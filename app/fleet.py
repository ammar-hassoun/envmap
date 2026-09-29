"""Fleet-wide health: every cluster the portal knows about, gathered concurrently.

Nothing here is configured — it walks the store, so a newly added cluster
appears on the dashboard automatically. Results are cached briefly because
each cluster costs several kubectl round-trips.
"""
import json
import re
import subprocess
import threading
import time

from . import history, repo, store
from .kube import base_args, reachable


def _pmap(fn, items: list, workers: int = 8) -> list:
    """Run fn over items on daemon threads, preserving order.

    Deliberately not ThreadPoolExecutor: its workers are non-daemon and are
    joined at interpreter exit, so a shutdown (uvicorn --reload, or a pod
    restart) blocks for as long as a kubectl call is still in flight. Daemon
    threads are abandoned instead, which is the right trade for a read-only
    dashboard fetch.
    """
    items = list(items)
    if not items:
        return []
    out: list = [None] * len(items)
    sem = threading.Semaphore(max(1, workers))

    def run(i, item):
        try:
            out[i] = fn(item)
        except Exception:                                     # noqa: BLE001
            out[i] = None
        finally:
            sem.release()

    threads = []
    for i, item in enumerate(items):
        sem.acquire()
        t = threading.Thread(target=run, args=(i, item), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return out

def _tokens(*parts: str) -> set:
    """Split on non-alphanumerics. Token equality — not substring matching —
    is what keeps 'preprod' from also matching 'prod'."""
    return {t for t in re.split(r"[^a-z0-9]+", " ".join(parts).lower()) if t}


def _infer_env(pid: str, project: dict, cluster: dict):
    """Guess (rgid, env) from a cluster's name and kubectl context.

    Explicit env_clusters mapping always wins; this only fills the gap so a
    cluster added today links straight to its environment instead of waiting
    for someone to wire the mapping by hand.
    """
    hay = _tokens(cluster.get("name", ""), cluster.get("context", ""))
    if not hay:
        return None
    best = None
    for rgid, rg in project.get("regions", {}).items():
        rname = (rg.get("name") or "").lower()
        if not rname or rname not in hay:
            continue
        # Only environments that actually exist in this region's repo. An
        # earlier version also guessed against a built-in list of common
        # environment names, which meant inventing links to pages that did not
        # exist — and hard-coded one team's vocabulary into the product.
        for env in sorted(repo.list_envs(pid, rgid, include_hidden=True),
                          key=len, reverse=True):
            if env.lower() in hay or env.lower().replace("-", "") in hay:
                rank = len(env)
                if best is None or rank > best[0]:
                    best = (rank, rgid, env)
                break
    return (best[1], best[2]) if best else None

TTL = 30.0
# HOW LONG A COLD READER WAITS before the page is drawn without the live parts.
# Not a timeout on the collection — that keeps running and lands in the cache a
# few seconds later; this is only how long a PERSON is made to look at nothing.
#
# Deliberately shorter than gather.Gatherer's 1.5s, because the two are being
# spent on different bets. A cluster tab's gather often DOES finish inside its
# deadline, so waiting buys the real page. A full-fleet collection measured
# 7.5s across 24 clusters, so waiting 1.5s there is 1.5s bought nothing — the
# skeleton is shown anyway. 0.4s is short enough to still read as immediate and
# long enough that a one- or two-cluster install (measured 0.3-0.5s) usually
# lands the real snapshot on the first paint and never sees the skeleton.
FIRST_PAINT = 0.4
_cache: dict = {"at": 0.0, "data": None}
_guard = threading.Lock()
_refreshing = False
# Set when a collection lands, so a cold reader can wait for one WITHOUT
# polling and without holding _guard while it does.
_arrived = threading.Event()


def _kubectl(cluster, *args, timeout=18):
    base = base_args(cluster)
    # the shared probe: one short answer per dead cluster per 30s, instead of
    # every fleet read waiting out its own timeout
    if not base or not reachable(cluster)[0]:
        return None
    try:
        r = subprocess.run(base + list(args) + ["-o", "json",
                                                f"--request-timeout={timeout - 3}s"],
                           capture_output=True, text=True, timeout=timeout)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:
        return None


def _cpu_to_milli(v: str) -> float:
    if not v:
        return 0.0
    v = str(v)
    try:
        if v.endswith("n"):
            return float(v[:-1]) / 1e6
        if v.endswith("u"):
            return float(v[:-1]) / 1e3
        if v.endswith("m"):
            return float(v[:-1])
        return float(v) * 1000
    except ValueError:
        return 0.0


def _mem_to_mib(v: str) -> float:
    if not v:
        return 0.0
    v = str(v)
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024,
             "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}
    for suf, mult in units.items():
        if v.endswith(suf):
            try:
                return float(v[: -len(suf)]) * mult
            except ValueError:
                return 0.0
    try:
        return float(v) / (1024 * 1024)
    except ValueError:
        return 0.0


def _cluster_health(pid: str, project: dict, cid: str, cluster: dict) -> dict:
    out = {
        "pid": pid, "project": project.get("name", ""),
        "icon": project.get("icon", "📦"), "cid": cid,
        "name": cluster.get("name", cid), "context": cluster.get("context", ""),
        "reachable": False, "error": "",
        "nodes": {"total": 0, "ready": 0},
        "pods": {"total": 0, "running": 0, "bad": 0, "pending": 0},
        "cpu": None, "mem": None, "problems": [], "used_by": [],
        "top_ns": [],
        "namespaces": 0,
    }
    out["used_by"] = store.serves({pid: project}, pid).get(cid, [])

    # Clicking the cluster's NAME opens THAT CLUSTER — its own overview, with
    # its nodes, pods, events and storage. It used to open the environment
    # mapped to it (or the project, or its settings), which meant the one thing
    # the card is about was the one thing its title did not lead to: somebody
    # reading "3/3 nodes, 2 unhealthy pods" and clicking the name landed on a
    # values-file listing. The environment badges below still go to the
    # environment pages, so nothing was lost by making the title literal.
    out["href"] = f"/clusters?project={pid}&cluster={cid}"
    out["href_kind"] = "cluster"
    # `guessed` still says which environment this cluster looks like it serves,
    # because "no environment matched" beside a name is a prompt to go and map
    # it — and the badge next to the title is what offers that.
    out["guessed"] = ""
    if not out["used_by"]:
        got = _infer_env(pid, project, cluster)
        if got:
            rgid, env = got
            rname = project.get("regions", {}).get(rgid, {}).get("name", "?")
            out["guess_href"] = f"/p/{pid}/{rgid}/{env}"
            out["guessed"] = f"{rname} / {env}"

    base = base_args(cluster)
    if not base:
        out["error"] = "no kubeconfig / context set"
        return out

    # These three reads are independent, and each one costs a full round trip
    # over the VPN — ~1.3s of latency, not of server work (a watch-cache read
    # measured no faster). Run together the cluster costs one round trip
    # instead of three.
    def _raw(path):
        try:
            r = subprocess.run(base + ["get", "--raw", path],
                               capture_output=True, text=True, timeout=15)
            return json.loads(r.stdout) if r.returncode == 0 else None
        except Exception:
            return None

    nodes, pods, raw = _pmap(lambda f: f(), [
        lambda: _kubectl(cluster, "get", "nodes"),
        lambda: _kubectl(cluster, "get", "pods", "-A"),
        lambda: _raw("/apis/metrics.k8s.io/v1beta1/nodes"),
    ], workers=3)

    if nodes is None:
        out["error"] = "unreachable"
        return out
    out["reachable"] = True

    cap_cpu = cap_mem = 0.0
    for n in nodes.get("items", []):
        out["nodes"]["total"] += 1
        if any(c["type"] == "Ready" and c["status"] == "True"
               for c in n.get("status", {}).get("conditions", [])):
            out["nodes"]["ready"] += 1
        alloc = n.get("status", {}).get("allocatable", {})
        cap_cpu += _cpu_to_milli(alloc.get("cpu"))
        cap_mem += _mem_to_mib(alloc.get("memory"))

    ns: dict = {}
    req_cpu = req_mem = 0.0
    if pods:
        for p in pods.get("items", []):
            meta, st = p["metadata"], p.get("status", {})
            ns[meta["namespace"]] = ns.get(meta["namespace"], 0) + 1
            phase = st.get("phase", "Unknown")
            cs = st.get("containerStatuses", []) or []
            reason = next((w["reason"] for c in cs
                           if (w := (c.get("state") or {}).get("waiting"))
                           and w.get("reason")), "")
            ready = sum(1 for c in cs if c.get("ready"))
            restarts = sum(c.get("restartCount", 0) for c in cs)
            out["pods"]["total"] += 1
            healthy = (phase == "Running" and cs and ready == len(cs) and not reason)
            if healthy:
                out["pods"]["running"] += 1
            elif phase in ("Succeeded",):
                out["pods"]["running"] += 1
            elif phase == "Pending":
                out["pods"]["pending"] += 1
                out["pods"]["bad"] += 1
            elif not meta.get("deletionTimestamp"):
                out["pods"]["bad"] += 1
            if not healthy and phase not in ("Succeeded",) and not meta.get("deletionTimestamp"):
                out["problems"].append({
                    "name": meta["name"], "namespace": meta["namespace"],
                    "status": reason or phase, "restarts": restarts})
            for c in p["spec"].get("containers", []):
                rq = (c.get("resources", {}) or {}).get("requests", {}) or {}
                req_cpu += _cpu_to_milli(rq.get("cpu"))
                req_mem += _mem_to_mib(rq.get("memory"))
    out["namespaces"] = len(ns)
    # busiest namespaces, for the distribution chart — free, we already have
    # every pod in hand
    out["top_ns"] = sorted(ns.items(), key=lambda kv: -kv[1])[:6]
    out["problems"] = sorted(out["problems"],
                             key=lambda x: -x["restarts"])[:6]

    # live usage from metrics-server when present, else fall back to requests
    # (`raw` was fetched alongside nodes and pods above)
    used_cpu = used_mem = None
    if raw:
        used_cpu = sum(_cpu_to_milli(i["usage"]["cpu"]) for i in raw.get("items", []))
        used_mem = sum(_mem_to_mib(i["usage"]["memory"]) for i in raw.get("items", []))
        source = "live"
    else:
        used_cpu, used_mem, source = req_cpu, req_mem, "requests"

    def pct(u, c):
        return round(min(100.0, (u / c) * 100), 1) if c else 0.0

    out["cpu"] = {"used": round(used_cpu), "cap": round(cap_cpu),
                  "pct": pct(used_cpu, cap_cpu), "source": source}
    out["mem"] = {"used": round(used_mem), "cap": round(cap_mem),
                  "pct": pct(used_mem, cap_mem), "source": source}
    return out


def overview(force: bool = False) -> dict:
    """Fleet snapshot.

    Serving policy: fresh cache → return it; stale cache → return the stale
    snapshot *immediately* and refresh in the background; no cache → wait
    FIRST_PAINT for one and draw the page without the live parts if it has not
    landed. `force` (the Refresh button) always waits for fresh data, because
    that is what the user asked for.

    WHY THE COLD PATH IS BOUNDED
        It used to be `_collect()`, and the docstring said "only the first load
        of a session ever waits" as though that settled it. Measured on a real
        estate of 24 clusters that wait was **ten seconds**, and "the first
        load" is every load after a deploy, a pod restart, or an upgrade — so
        the person who opens the portal first each morning paid all of it, and
        the warmer could not save them because it starts at the same moment
        they do.

        The collection is unchanged and still lands in the cache; what changed
        is that nobody is held behind it. A page drawn from `_skeleton()` knows
        every project and every cluster COUNT for free out of the database, and
        says in as many words that the live numbers are still being read.
    """
    now = time.monotonic()
    data = _cache["data"]
    if not force and data and now - _cache["at"] < TTL:
        return data
    if not force and data:
        _spawn_refresh()
        return {**data, "stale": True}
    if force:
        got = _collect()
        _cache.update(at=time.monotonic(), data=got)
        return got
    _spawn_refresh()
    _arrived.wait(FIRST_PAINT)
    data = _cache["data"]
    return data if data else _skeleton()


def peek() -> dict | None:
    """The snapshot if one has already been built, else None — and either way a
    collection is under way afterwards.

    For pages that want the snapshot but are not made of it: waiting out a
    first collection to draw one badge is a page that looks broken for three
    seconds. Asking still warms it, so the next look has it.
    """
    data = _cache["data"]
    if not data or time.monotonic() - _cache["at"] >= TTL:
        _spawn_refresh()
    return {**data, "stale": True} if data else None


def _spawn_refresh() -> None:
    """Kick off one background refresh, never a stampede of them."""
    global _refreshing
    with _guard:
        if _refreshing:
            return
        _refreshing = True

    def run():
        global _refreshing
        try:
            got = _collect()
            _cache.update(at=time.monotonic(), data=got)
            # Wake whoever is drawing a page right now. Set before _refreshing
            # is cleared so a waiter cannot see "not refreshing" with no data.
            _arrived.set()
        except Exception:
            pass
        finally:
            _refreshing = False

    threading.Thread(target=run, daemon=True).start()


def _projects() -> list:
    """The project roll-up, which is free: the database and the checked-out
    repositories on local disk, measured at about five milliseconds for a real
    estate. Shared with _skeleton() so a page drawn before the clusters have
    been read still knows what projects exist — without it the Overview shows
    "Nothing connected yet", which is the one thing worse than being slow.
    """
    out = []
    for pid, p in store.projects().items():
        envs = services = 0
        for rgid in p.get("regions", {}):
            e = repo.list_envs(pid, rgid, include_hidden=True)
            envs += len(e)
            services += sum(len(f) for f in e.values())
        out.append({
            "id": pid, "name": p.get("name", ""), "icon": p.get("icon", "📦"),
            "tagline": p.get("tagline", ""),
            "regions": len(p.get("regions", {})),
            "clusters": len(p.get("clusters", {})),
            "envs": envs, "services": services,
        })
    return out


def _skeleton() -> dict:
    """A drawable snapshot with the live parts still missing, and SAID to be.

    Everything here is read from local state, so it costs nothing: the
    projects, and how many clusters are configured. What it deliberately does
    NOT do is invent per-cluster health — an empty `clusters` list with
    `pending` set renders as "still collecting", whereas a list of clusters
    each marked unreachable would render as an estate that is down.
    """
    projects = _projects()
    return {
        "clusters": [],
        "projects": projects,
        "totals": {
            "clusters": sum(p["clusters"] for p in projects),
            "projects": len(projects),
            "services": sum(p["services"] for p in projects),
            # Unknown, not zero. `pending` is what the templates read to keep
            # these from being drawn as facts.
            "reachable": 0, "nodes": 0, "nodes_ready": 0,
            "pods": 0, "pods_running": 0, "pods_bad": 0,
        },
        "at": time.strftime("%H:%M:%S"),
        "stale": True, "pending": True,
    }


def _collect() -> dict:
    jobs = []
    for pid, p in store.projects().items():
        for cid, c in p.get("clusters", {}).items():
            jobs.append((pid, p, cid, c))

    clusters = [c for c in _pmap(lambda a: _cluster_health(*a), jobs, workers=8)
                if c]
    clusters.sort(key=lambda c: (c["project"], c["name"]))

    projects = _projects()

    totals = {
        "clusters": len(clusters),
        "reachable": sum(1 for c in clusters if c["reachable"]),
        "nodes": sum(c["nodes"]["total"] for c in clusters),
        "nodes_ready": sum(c["nodes"]["ready"] for c in clusters),
        "pods": sum(c["pods"]["total"] for c in clusters),
        "pods_running": sum(c["pods"]["running"] for c in clusters),
        "pods_bad": sum(c["pods"]["bad"] for c in clusters),
        "services": sum(p["services"] for p in projects),
        "projects": len(projects),
    }
    history.record(clusters, totals)

    # the caller owns the cache; _collect only builds
    return {"clusters": clusters, "projects": projects, "totals": totals,
            "at": time.strftime("%H:%M:%S"), "stale": False}


def invalidate():
    """Drop the snapshot: the next read rebuilds it, and waits.

    Right for a change in *shape* — a cluster added or removed — where showing
    the old snapshot would be showing something that no longer exists.
    """
    _cache.update(at=0.0, data=None)
    # The next cold reader must get its own FIRST_PAINT grace. Left set, the
    # wait would return instantly off the PREVIOUS collection's signal and the
    # page would fall back to the skeleton when a second of patience would have
    # produced the real thing.
    _arrived.clear()


def mark_stale():
    """Ask for fresh data without making anyone wait for it.

    Right for the Refresh button: the numbers are still true, just older, so the
    page returns the snapshot it has and the rebuild happens behind it. Clearing
    the cache instead would make Refresh take as long as a cold start, which is
    what it used to do.
    """
    if _cache["data"]:
        _cache["at"] = 0.0
    else:
        _cache.update(at=0.0, data=None)
