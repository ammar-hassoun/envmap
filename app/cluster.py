"""One cluster, read in depth — nodes, workloads, pods, events, storage, network.

WHY THIS IS SEPARATE FROM fleet.py
    fleet.py answers "is anything wrong anywhere", across every cluster, in as
    few round trips as possible. This answers "show me everything about this
    one", which is a different shape: many more reads, but only for the cluster
    someone is actually looking at.

HOW IT STAYS FAST
    Each tab fetches only what it needs, and each part is cached on its own for
    a few seconds. A kubectl call over a VPN costs about a second of pure
    latency, so the calls within a part run together on daemon threads — the
    tab costs one round trip rather than one per resource. Nothing is fetched
    speculatively for a tab nobody opened.

READ-ONLY, AND NOTHING ENUMERATED
    Every call is a get. No namespace list, workload kind or add-on name is
    written down here: the cluster is asked what it has. Resources that may not
    be installed (metrics-server, cert-manager, ArgoCD, Traefik) are probed and
    simply absent from the page when missing, never an error.
"""
import base64
import json
import re
import subprocess
from datetime import datetime, timezone

from . import kube
from . import fleet as _fleet
from .fleet import _cpu_to_milli, _mem_to_mib, _pmap
from .gather import Gatherer as _Gatherer
from .kube import base_args

TTL = 20.0
# Parts that cost more than a round trip get their own lifetime: the audit reads
# nine collections and every kubelet's configuration, which is seconds rather
# than milliseconds, and its answer does not change minute to minute.
# Disk is read from each kubelet, one call per node, and it is BOTH the
# slowest call in the node strip and the slowest-moving number in it: measured
# at ~1.8s against a real cluster, against ~1.0s for metrics-server, and a
# node's filesystem does not move percentage points in twenty seconds. Sharing
# the 20s default meant paying the slowest call every time the fastest one
# expired — half the strip's cold time, over and over.
PART_TTL = {"audit": 300.0, "nodedisk": 300.0}
CALL_TIMEOUT = 18

TABS = [
    # The third field names a line icon in app/logodata.py. It was an emoji,
    # which every desktop drew in its own font at its own weight — the tab strip
    # was the most visibly inconsistent thing on the page across machines.
    ("overview", "Overview", "activity"),
    # "Config" said nothing about where the values come from, and this tab is
    # entirely about ONE thing: the GitOps repository the environment declares.
    ("config", "GitOps repo", "git-branch"),
    ("diagram", "Diagram", "workflow"),
    ("nodes", "Nodes", "server"),
    ("workloads", "Workloads", "layers"),
    ("pods", "Pods", "boxes"),
    ("events", "Events", "history"),
    ("storage", "Storage", "hard-drive"),
    ("network", "Network", "globe"),
    ("crds", "CRDs", "package"),
    ("shell", "kubectl shell", "square-terminal"),
    ("access", "Access", "key-round"),
    ("scan", "Scan", "shield-check"),
]

# One line icon per workload kind, for the sub-tab strip. Unknown kinds are
# possible — a CRD-backed workload could appear here later — so the fallback is
# named rather than left to draw nothing.
KIND_GLYPH = {"Deployment": "layers", "StatefulSet": "database",
              "DaemonSet": "server", "CronJob": "hourglass"}


def kind_tabs(rows: list) -> list:
    """The Workloads sub-tabs: everything, then one tab per kind present.

    Counted here rather than in the template because the numbers have to be of
    the rows actually on screen. The dropdown this replaced counted every kind in
    the cluster while the table below it showed one namespace, so "Deployment
    (24)" sat above three rows.
    """
    seen: dict[str, int] = {}
    for row in rows:
        kind = row.get("kind") or ""
        seen[kind] = seen.get(kind, 0) + 1
    out = [{"key": "", "label": "All kinds", "count": len(rows),
            "icon": "layout-grid"}]
    for kind in sorted(seen):
        out.append({"key": kind, "label": kind, "count": seen[kind],
                    "icon": KIND_GLYPH.get(kind, "boxes")})
    return out


# What each tab needs, so a tab never pays for another tab's reads.
NEEDS = {
    "overview": ("nodes", "pods", "events", "storage", "argocd", "certs"),
    # the config tab reads the git working copy, not the cluster, so it asks the
    # cluster for nothing at all
    "config": (),
    # the diagram is built by topology.py, which does its own reads
    "diagram": (),
    "nodes": ("nodes", "pods"),
    # not "argocd" any more: the applications table left this tab for the GitOps
    # page, and a read nothing renders is a second or two of every page load
    "workloads": ("workloads",),
    "pods": ("pods",),
    "events": ("events",),
    "storage": ("storage",),
    "network": ("network", "certs"),
    "crds": ("crds",),
    # the console talks to the cluster only when a command is submitted
    "shell": (),
    # the access tab lists service accounts, which it fetches itself
    "access": (),
    # the audit does its own reads, and caches them under PART_TTL
    "scan": (),
}

_cache: dict[str, tuple[float, object]] = {}


def invalidate() -> None:
    _cache.clear()
    _gather.invalidate()


def forget(cid: str, *parts: str) -> None:
    """Drop only what an action could have changed.

    Deleting one pod used to clear every part of every cluster, which meant the
    page that came back had to collect the nodes, the namespaces and the pods
    again from cold — and showed "nothing matches" while it did, as though the
    cluster had emptied. What changed is what gets refetched.
    """
    for p in parts:
        _cache.pop(f"{cid}::{p}", None)
    _gather.invalidate()


def _now() -> float:
    import time
    return time.time()


# How long a part may be served while a fresh one is fetched behind the reader.
# Without this, every part expiring meant every page paying its full cost again
# — and the page people notice is the one they come back to, which is exactly
# the one whose parts have just gone stale while they were somewhere else.
STALE_MAX = 600.0
_refreshing: set = set()
_refresh_guard = __import__("threading").Lock()


def _refresh_behind(key: str, produce) -> None:
    import threading
    with _refresh_guard:
        if key in _refreshing:
            return                      # one refresh per part, not a stampede
        _refreshing.add(key)

    def run():
        try:
            _cache[key] = (_now(), produce())
        except Exception:                                     # noqa: BLE001
            pass
        finally:
            with _refresh_guard:
                _refreshing.discard(key)

    threading.Thread(target=run, name=f"cluster-{key}", daemon=True).start()


def _cached(cid: str, part: str, refresh: bool, produce):
    key = f"{cid}::{part}"
    # A part may carry what it is about — `bundle:<namespace>`, `nodedisk:<the
    # nodes>` — so the lifetime is looked up by the FAMILY, before the colon.
    # Keyed on the whole string, `nodedisk:talos-a,talos-b` simply missed
    # PART_TTL and silently took the 20s default, which is the opposite of why
    # it was given a longer one.
    family = part.split(":", 1)[0]
    hit = _cache.get(key)
    if hit and not refresh:
        age = _now() - hit[0]
        if age < PART_TTL.get(family, TTL):
            return hit[1]
        if age < STALE_MAX:
            _refresh_behind(key, produce)
            return hit[1]
    got = produce()
    _cache[key] = (_now(), got)
    return got


# ── raw kubectl ────────────────────────────────────────────────
def _get(cluster: dict, *args, timeout: int = CALL_TIMEOUT):
    """`kubectl get … -o json`, or None if the call failed.

    A None is not an error to show: many of these resources are optional, and a
    missing CRD looks exactly like a failed call at this level. The caller
    decides whether absence matters.
    """
    base = base_args(cluster)
    # One cached probe answers for the whole page: a tab reads a dozen
    # resources, and without this gate an unreachable cluster charges the full
    # timeout for each of them.
    if not base or not kube.reachable(cluster)[0]:
        return None
    try:
        r = subprocess.run(
            base + ["get", *args, "-o", "json",
                    f"--request-timeout={max(3, timeout - 3)}s"],
            capture_output=True, text=True, timeout=timeout)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:                                         # noqa: BLE001
        return None


def _get_why(cluster: dict, *args, timeout: int = CALL_TIMEOUT):
    """(document, reason). Like _get, but hands back WHY it failed.

    _get answers None for everything, which is right for the callers that treat
    an absent optional resource as absence. It is wrong for the service view: a
    namespace whose ConfigMaps are Forbidden and one that is empty look
    identical through _get, and the fix for those is a role binding versus
    nothing at all. kubectl already says which; this stops throwing it away.
    """
    base = base_args(cluster)
    if not base:
        return None, "this cluster has no kubeconfig or context set"
    alive, why = kube.reachable(cluster)
    if not alive:
        return None, why or "the cluster is not reachable"
    try:
        r = subprocess.run(
            base + ["get", *args, "-o", "json",
                    f"--request-timeout={max(3, timeout - 3)}s"],
            capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return json.loads(r.stdout), ""
        # kubectl's own sentence, with its prefix trimmed: it names the verb, the
        # resource and the identity, which is exactly what a person needs to fix
        # a role binding and is what the page used to swallow.
        said = (r.stderr or r.stdout).strip().splitlines()
        first = said[0] if said else f"kubectl exited {r.returncode}"
        return None, re.sub(r"^Error from server \(([^)]+)\): ", r"\1: ", first)
    except subprocess.TimeoutExpired:
        return None, f"no answer within {timeout}s"
    except Exception as e:                                    # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:120]}"


def _text(cluster: dict, *args, timeout: int = CALL_TIMEOUT) -> tuple:
    """`kubectl get …` with the caller's own output format: (text, error).

    Exists so a caller can ask for two fields instead of whole objects — see
    _part_tls, which must not pull private keys into this process just to read
    a date off the certificate beside them.

    IT RETURNS THE ERROR, and it did not. Every failure came back as an empty
    string, indistinguishable from a cluster that genuinely holds no matching
    object — so a denied `secrets -A` list, a wrong template or a timeout made
    `_part_tls` answer `{present: True, certs: [], manual: 0}`, and the Expiry
    radar rendered that cluster as CLEAN. A read-only kubeconfig without
    cluster-wide secret access is an ordinary thing to be handed, and this is
    the page whose whole job is to say what nobody is watching. The rule this
    codebase already states for the reachability case — "no certificates" and
    "could not ask" must not look the same — was being broken one call lower
    down.
    """
    base = base_args(cluster)
    if not base:
        return "", "no kubeconfig or context is set for this cluster"
    ok, why = kube.reachable(cluster)
    if not ok:
        return "", why or "unreachable"
    try:
        r = subprocess.run(
            base + ["get", *args, f"--request-timeout={max(3, timeout - 3)}s"],
            capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            # kubectl's own sentence, trimmed. "Error from server (Forbidden)"
            # is the whole diagnosis and it belongs on the page.
            said = " ".join((r.stderr or "").split())[:200]
            return "", said or f"kubectl exited {r.returncode}"
        return r.stdout, ""
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except Exception as e:                                    # noqa: BLE001
        return "", f"{type(e).__name__}"


def _raw(cluster: dict, path: str, timeout: int = 12):
    base = base_args(cluster)
    if not base or not kube.reachable(cluster)[0]:
        return None
    try:
        r = subprocess.run(base + ["get", "--raw", path],
                           capture_output=True, text=True, timeout=timeout)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:                                         # noqa: BLE001
        return None


def _items(doc) -> list:
    return (doc or {}).get("items") or []


def _age(ts: str) -> str:
    if not ts:
        return ""
    try:
        d = datetime.now(timezone.utc) - datetime.fromisoformat(
            ts.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if d.days >= 365:
        return f"{d.days // 365}y"
    if d.days:
        return f"{d.days}d"
    h = d.seconds // 3600
    return f"{h}h" if h else f"{max(1, d.seconds // 60)}m"


def _days_until(ts: str):
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00")) - datetime.now(
            timezone.utc)
    except ValueError:
        return None
    return d.days


def _pod_problem(pod: dict) -> str:
    """Why this pod is not simply fine, in the words the cluster used."""
    st = pod.get("status", {})
    meta = pod.get("metadata", {})
    if meta.get("deletionTimestamp"):
        return "Terminating"
    phase = st.get("phase", "Unknown")
    if phase in ("Succeeded",):
        return ""
    cs = (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or [])
    for c in cs:
        w = (c.get("state") or {}).get("waiting") or {}
        if w.get("reason") and w["reason"] not in ("ContainerCreating", "PodInitializing"):
            return w["reason"]
        t = (c.get("state") or {}).get("terminated") or {}
        if t.get("reason") and t["reason"] != "Completed":
            return t["reason"]
    if phase != "Running":
        # an unschedulable pod says why in its conditions, which is more useful
        # than the word "Pending" on its own
        for cond in st.get("conditions") or []:
            if cond.get("type") == "PodScheduled" and cond.get("status") != "True":
                return cond.get("reason") or phase
        return phase
    want = st.get("containerStatuses") or []
    if want and sum(1 for c in want if c.get("ready")) != len(want):
        return "NotReady"
    return ""


# ── parts ──────────────────────────────────────────────────────
def _node_disk(cluster: dict, names: list) -> dict:
    """Real filesystem usage per node, from each kubelet's own stats.

    metrics-server reports cpu and memory and nothing else, which is why the
    disk meter had a capacity and no fraction. The kubelet knows, and
    `nodes/proxy` is the way to ask it — one call per node, run together.
    Clusters that refuse that subresource simply report no usage rather than
    an error: a missing number is honest, a guessed one is not.
    """
    def one(name):
        got = _raw(cluster, f"/api/v1/nodes/{name}/proxy/stats/summary",
                   timeout=8)
        fs = ((got or {}).get("node") or {}).get("fs") or {}
        used, cap = fs.get("usedBytes"), fs.get("capacityBytes")
        if not used or not cap:
            return name, None
        return name, {"used_mib": used / 1048576, "cap_mib": cap / 1048576,
                      "pct": round(used / cap * 100)}
    return {n: d for n, d in
            (_pmap(one, list(names), workers=min(8, len(names))) or [])
            if d}


def _node_disk_cached(cluster: dict, names: list) -> dict:
    """The same, kept for PART_TTL["nodedisk"] rather than the nodes' own TTL.

    Cached under the node names it was asked about, so a cluster that gains or
    loses a machine reads fresh rather than serving a map that is missing one.
    """
    if not names:
        return {}
    cid = cluster.get("id") or cluster.get("context", "")
    key = "nodedisk:" + ",".join(sorted(names))
    return _cached(cid, key, False, lambda: _node_disk(cluster, names))


def _part_nodes(cluster: dict) -> dict:
    nodes, metrics = _pmap(lambda f: f(), [
        lambda: _get(cluster, "nodes"),
        lambda: _raw(cluster, "/apis/metrics.k8s.io/v1beta1/nodes"),
    ], workers=2)
    if nodes is None:
        return {"error": "unreachable", "nodes": []}
    use = {m["metadata"]["name"]: m.get("usage", {}) for m in _items(metrics)}
    disks = _node_disk_cached(
        cluster, [n["metadata"]["name"] for n in _items(nodes)])
    out, versions = [], set()
    for n in _items(nodes):
        meta, st = n["metadata"], n.get("status", {})
        info = st.get("nodeInfo", {})
        alloc, cap = st.get("allocatable", {}), st.get("capacity", {})
        conds = {c["type"]: c for c in st.get("conditions", [])}
        ready = conds.get("Ready", {}).get("status") == "True"
        # every condition that is true except Ready is a complaint: pressure,
        # network unavailable, whatever this distribution reports
        pressure = [t for t, c in conds.items()
                    if t != "Ready" and c.get("status") == "True"]
        u = use.get(meta["name"], {})
        cpu_cap = _cpu_to_milli(alloc.get("cpu")) or 0.0
        mem_cap = _mem_to_mib(alloc.get("memory")) or 0.0
        cpu_use = _cpu_to_milli(u.get("cpu")) if u else None
        mem_use = _mem_to_mib(u.get("memory")) if u else None
        # Disk, as far as the node object can tell us. metrics-server reports
        # cpu and memory and nothing else, so there is no *usage* figure here
        # without a per-node kubelet call — the node's own DiskPressure
        # condition is the honest signal, and it is already in `pressure`.
        disk_cap = _mem_to_mib(cap.get("ephemeral-storage")) or 0.0
        disk_alloc = _mem_to_mib(alloc.get("ephemeral-storage")) or 0.0
        seen = disks.get(meta["name"]) or {}
        versions.add(info.get("kubeletVersion", ""))
        roles = sorted(k.split("/", 1)[1] for k in meta.get("labels", {})
                       if k.startswith("node-role.kubernetes.io/"))
        out.append({
            "name": meta["name"], "ready": ready,
            "roles": roles or ["worker"],
            "schedulable": not n.get("spec", {}).get("unschedulable"),
            "taints": [f"{t.get('key')}={t.get('value','')}:{t.get('effect')}"
                       for t in n.get("spec", {}).get("taints", []) or []],
            "pressure": pressure,
            "version": info.get("kubeletVersion", ""),
            "os": info.get("osImage", ""), "kernel": info.get("kernelVersion", ""),
            "runtime": info.get("containerRuntimeVersion", ""),
            "arch": info.get("architecture", ""),
            "ip": next((a["address"] for a in st.get("addresses", [])
                        if a["type"] == "InternalIP"), ""),
            "age": _age(meta.get("creationTimestamp", "")),
            "cpu_cap": cpu_cap, "mem_cap": mem_cap,
            "cpu_use": cpu_use, "mem_use": mem_use,
            # the kubelet's own figure when it will give one, and the node
            # object's capacity either way
            "disk_cap": seen.get("cap_mib") or disk_cap,
            "disk_alloc": disk_alloc,
            "disk_use": seen.get("used_mib"),
            "disk_pct": seen.get("pct"),
            "disk_pressure": "DiskPressure" in pressure,
            "cpu_pct": round(cpu_use / cpu_cap * 100) if cpu_use and cpu_cap else None,
            "mem_pct": round(mem_use / mem_cap * 100) if mem_use and mem_cap else None,
            "pods_cap": int(cap.get("pods") or 0),
        })
    out.sort(key=lambda n: ("control-plane" not in n["roles"]
                            and "master" not in n["roles"], n["name"]))
    return {"error": "", "nodes": out, "metrics": metrics is not None,
            "versions": sorted(v for v in versions if v)}


def _workload_of(owners: list) -> str:
    """The workload a pod belongs to, from its ownerReferences.

    A ReplicaSet's name is its Deployment's plus `-<10 chars of hash>`; anything
    else owns its pods under its own name. Returns "" for a bare pod, which is
    then only ever matched by an exact "" — a filter that finds nothing rather
    than everything.
    """
    ref = next((o for o in owners if o.get("name")), None)
    if not ref:
        return ""
    name, kind = ref["name"], (ref.get("kind") or "")
    if kind == "ReplicaSet" and "-" in name:
        head, _, tail = name.rpartition("-")
        # a replica-set hash is 5-10 alphanumerics; a name ending in something
        # else is its own workload rather than a generated one
        if head and re.fullmatch(r"[a-z0-9]{5,10}", tail):
            return head
    return name


def _part_pods(cluster: dict) -> dict:
    pods, metrics = _pmap(lambda f: f(), [
        lambda: _get(cluster, "pods", "-A"),
        lambda: _raw(cluster, "/apis/metrics.k8s.io/v1beta1/pods"),
    ], workers=2)
    if pods is None:
        return {"error": "unreachable", "pods": []}
    use = {(m["metadata"]["namespace"], m["metadata"]["name"]):
           sum(_cpu_to_milli((c.get("usage") or {}).get("cpu"))
               for c in m.get("containers", []))
           for m in _items(metrics)}
    mem = {(m["metadata"]["namespace"], m["metadata"]["name"]):
           sum(_mem_to_mib((c.get("usage") or {}).get("memory"))
               for c in m.get("containers", []))
           for m in _items(metrics)}
    out = []
    for p in _items(pods):
        meta, st, spec = p["metadata"], p.get("status", {}), p.get("spec", {})
        cs = st.get("containerStatuses") or []
        key = (meta["namespace"], meta["name"])
        problem = _pod_problem(p)
        out.append({
            "namespace": meta["namespace"], "name": meta["name"],
            "node": spec.get("nodeName", ""),
            "phase": st.get("phase", "Unknown"),
            "problem": problem, "healthy": not problem,
            "ready": f"{sum(1 for c in cs if c.get('ready'))}/{len(cs)}",
            "restarts": sum(c.get("restartCount", 0) for c in cs),
            "age": _age(meta.get("creationTimestamp", "")),
            "images": sorted({(c.get("image") or "").split("/")[-1]
                              for c in spec.get("containers", [])}),
            "owner": next((o.get("kind", "") for o in
                           meta.get("ownerReferences", []) or []), ""),
            # Which workload this pod belongs to, by name. A pod's owner is a
            # ReplicaSet whose name is `<deployment>-<hash>`, so the deployment
            # is the name with that last segment removed; a StatefulSet, DaemonSet
            # or Job owns its pods directly and needs nothing removed.
            #
            # Worked out here because the alternative — filtering pods by "name
            # contains the workload's name" — is wrong in a way that is easy to
            # miss: `bo-frontend` matches every pod of `bo-frontend-v02` too.
            "workload": _workload_of(meta.get("ownerReferences") or []),
            "cpu": use.get(key), "mem": mem.get(key),
            "qos": st.get("qosClass", ""),
        })
    # worst first: a page that opens on the problems is the point
    out.sort(key=lambda p: (p["healthy"], -p["restarts"], p["namespace"], p["name"]))
    return {"error": "", "pods": out, "metrics": metrics is not None}


def _part_workloads(cluster: dict) -> dict:
    deps, sts, ds, cj = _pmap(lambda f: f(), [
        lambda: _get(cluster, "deployments", "-A"),
        lambda: _get(cluster, "statefulsets", "-A"),
        lambda: _get(cluster, "daemonsets", "-A"),
        lambda: _get(cluster, "cronjobs", "-A"),
    ], workers=4)
    if deps is None and sts is None and ds is None:
        return {"error": "unreachable", "workloads": []}
    rows = []

    def add(kind, doc, want_fn, have_fn):
        for w in _items(doc):
            meta, st = w["metadata"], w.get("status", {})
            want, have = want_fn(w, st), have_fn(w, st)
            images = sorted({c.get("image", "") for c in
                             w.get("spec", {}).get("template", {})
                             .get("spec", {}).get("containers", [])})
            rows.append({
                "kind": kind, "namespace": meta["namespace"], "name": meta["name"],
                "want": want, "have": have, "ok": want == have and want > 0,
                "empty": want == 0,
                "images": images,
                "tags": sorted({i.rsplit(":", 1)[-1] for i in images if ":" in i}),
                "age": _age(meta.get("creationTimestamp", "")),
                "suspended": False,
            })

    add("Deployment", deps,
        lambda w, s: int(w.get("spec", {}).get("replicas") or 0),
        lambda w, s: int(s.get("readyReplicas") or 0))
    add("StatefulSet", sts,
        lambda w, s: int(w.get("spec", {}).get("replicas") or 0),
        lambda w, s: int(s.get("readyReplicas") or 0))
    add("DaemonSet", ds,
        lambda w, s: int(s.get("desiredNumberScheduled") or 0),
        lambda w, s: int(s.get("numberReady") or 0))
    for c in _items(cj):
        meta, spec, st = c["metadata"], c.get("spec", {}), c.get("status", {})
        rows.append({
            "kind": "CronJob", "namespace": meta["namespace"], "name": meta["name"],
            "want": 0, "have": len(st.get("active") or []), "ok": True,
            "empty": False, "schedule": spec.get("schedule", ""),
            "last": _age(st.get("lastScheduleTime", "")),
            "suspended": bool(spec.get("suspend")),
            "images": [], "tags": [],
            "age": _age(meta.get("creationTimestamp", "")),
        })
    rows.sort(key=lambda r: (r["ok"] and not r["suspended"], r["namespace"],
                             r["kind"], r["name"]))
    return {"error": "", "workloads": rows}


def _part_events(cluster: dict) -> dict:
    doc = _get(cluster, "events", "-A")
    if doc is None:
        return {"error": "unreachable", "events": [], "groups": []}
    rows = []
    for e in _items(doc):
        meta = e["metadata"]
        obj = e.get("involvedObject") or e.get("regarding") or {}
        when = (e.get("lastTimestamp") or e.get("eventTime")
                or (e.get("series") or {}).get("lastObservedTime")
                or meta.get("creationTimestamp", ""))
        rows.append({
            "namespace": meta.get("namespace", ""),
            "type": e.get("type", ""),
            "reason": e.get("reason", ""),
            "object": f"{obj.get('kind','')}/{obj.get('name','')}".strip("/"),
            # split out as well as joined: the useful thing to open from an event
            # is the object it is about, and that needs the two of them apart
            "obj_kind": (obj.get("kind") or "").lower(),
            "obj_name": obj.get("name") or "",
            "message": (e.get("message") or "").strip(),
            "count": int(e.get("count") or (e.get("series") or {}).get("count") or 1),
            "when": when, "age": _age(when),
        })
    rows.sort(key=lambda r: (r["type"] != "Warning", r["when"]), reverse=False)
    rows.sort(key=lambda r: (r["type"] != "Warning", -(r["count"])))
    # the same reason firing across twenty pods is one problem, not twenty
    groups: dict = {}
    for r in rows:
        if r["type"] != "Warning":
            continue
        k = (r["reason"], r["namespace"])
        g = groups.setdefault(k, {"reason": r["reason"], "namespace": r["namespace"],
                                  "count": 0, "objects": set(), "sample": r["message"]})
        g["count"] += r["count"]
        g["objects"].add(r["object"])
    top = sorted(groups.values(), key=lambda g: -g["count"])
    for g in top:
        g["objects"] = sorted(g["objects"])
    return {"error": "", "events": rows, "groups": top,
            "warnings": sum(1 for r in rows if r["type"] == "Warning")}


def _part_crds(cluster: dict) -> dict:
    """Every CustomResourceDefinition, and what each one adds to the API.

    WHY THIS IS ITS OWN TAB
        A CRD is the difference between two clusters that otherwise look
        identical: what Traefik, cert-manager, ArgoCD, the sealing controller and
        every operator installed here can be asked about. Nothing else on this
        page says which of those exist — the other tabs probe for the handful the
        portal itself uses and stay quiet about the rest.

    Deliberately not counting instances. That would be one `kubectl get <plural>
    -A` per definition, which is fifty or more calls on a cluster with an
    operator or two, for a number nobody opened this tab to read.
    """
    doc, why = _get_why(cluster, "crd")
    if doc is None:
        return {"error": why or "unreachable", "crds": [], "groups": []}
    rows = []
    for c in _items(doc):
        meta, spec, st = c["metadata"], c.get("spec", {}), c.get("status", {})
        names = spec.get("names") or {}
        versions = spec.get("versions") or []
        served = [v["name"] for v in versions if v.get("served")]
        stored = next((v["name"] for v in versions if v.get("storage")), "")
        established = any(cond.get("type") == "Established"
                          and cond.get("status") == "True"
                          for cond in (st.get("conditions") or []))
        rows.append({
            "name": meta["name"], "group": spec.get("group", ""),
            "kind": names.get("kind", ""), "plural": names.get("plural", ""),
            "short": names.get("shortNames") or [],
            "scope": spec.get("scope", ""),
            "namespaced": spec.get("scope") == "Namespaced",
            "versions": served, "stored": stored,
            "established": established,
            # What put it here. An operator's chart labels its CRDs; a hand-applied
            # one has nothing, and saying "—" is more honest than guessing.
            "by": (meta.get("labels") or {}).get("app.kubernetes.io/name", "")
                  or (meta.get("labels") or {}).get("app", ""),
            "age": _age(meta.get("creationTimestamp", "")),
        })
    rows.sort(key=lambda r: (r["group"], r["kind"]))
    # Grouped by API group, because that is how they arrive: one operator brings
    # eight definitions under one group, and a flat list of sixty hides that.
    groups: dict = {}
    for r in rows:
        groups.setdefault(r["group"] or "(core)", []).append(r)
    return {"error": "", "crds": rows,
            "groups": [{"group": g, "rows": rs, "count": len(rs),
                        "by": next((x["by"] for x in rs if x["by"]), "")}
                       for g, rs in sorted(groups.items())]}


def _part_storage(cluster: dict) -> dict:
    pvcs, pvs, scs = _pmap(lambda f: f(), [
        lambda: _get(cluster, "pvc", "-A"),
        lambda: _get(cluster, "pv"),
        lambda: _get(cluster, "storageclass"),
    ], workers=3)
    if pvcs is None and pvs is None:
        return {"error": "unreachable", "claims": []}
    default_sc = next((s["metadata"]["name"] for s in _items(scs)
                       if (s["metadata"].get("annotations") or {})
                       .get("storageclass.kubernetes.io/is-default-class") == "true"),
                      "")
    claims, total_gib = [], 0.0
    for c in _items(pvcs):
        meta, spec, st = c["metadata"], c.get("spec", {}), c.get("status", {})
        size = (st.get("capacity") or spec.get("resources", {})
                .get("requests", {})).get("storage", "")
        gib = _mem_to_mib(size) / 1024 if size else 0.0
        total_gib += gib
        claims.append({
            "namespace": meta["namespace"], "name": meta["name"],
            "status": st.get("phase", ""), "bound": st.get("phase") == "Bound",
            "size": size, "gib": round(gib, 1),
            "sc": spec.get("storageClassName") or "",
            "volume": spec.get("volumeName", ""),
            "modes": spec.get("accessModes", []),
            "age": _age(meta.get("creationTimestamp", "")),
        })
    claims.sort(key=lambda c: (c["bound"], -c["gib"], c["namespace"]))

    # The volumes, as rows. A Released or Failed one used to be a name in a
    # warning strip under the table and nowhere else — so the thing holding disk
    # was the one object on this tab you could not open, describe or read the
    # class of. It is a row with a status like every other row now, sorted to the
    # top because it is the one that needs somebody.
    volumes = []
    for v in _items(pvs):
        meta, spec, st = v["metadata"], v.get("spec", {}), v.get("status", {})
        phase = st.get("phase", "")
        ref = spec.get("claimRef") or {}
        size = (spec.get("capacity") or {}).get("storage", "")
        volumes.append({
            "name": meta["name"], "status": phase,
            "bound": phase == "Bound",
            "stuck": phase in ("Released", "Failed"),
            "size": size, "gib": round(_mem_to_mib(size) / 1024 if size else 0, 1),
            "sc": spec.get("storageClassName") or "",
            "reclaim": spec.get("persistentVolumeReclaimPolicy", ""),
            "claim": f'{ref.get("namespace", "")}/{ref.get("name", "")}'.strip("/"),
            "modes": spec.get("accessModes", []),
            "reason": st.get("reason", "") or st.get("message", "")[:120],
            "age": _age(meta.get("creationTimestamp", "")),
        })
    volumes.sort(key=lambda v: (not v["stuck"], v["bound"], -v["gib"], v["name"]))
    released = [v["name"] for v in volumes if v["stuck"]]
    return {"error": "", "claims": claims, "total_gib": round(total_gib, 1),
            "volumes": len(volumes), "pvs": volumes, "released": released,
            "classes": [{"name": s["metadata"]["name"],
                         "provisioner": s.get("provisioner", ""),
                         "default": s["metadata"]["name"] == default_sc,
                         "reclaim": s.get("reclaimPolicy", "")}
                        for s in _items(scs)]}


def _part_network(cluster: dict) -> dict:
    """Every service, and the host names routed to them by whichever ingress this
    cluster uses.

    It used to keep only what was reachable from outside — a LoadBalancer or a
    NodePort — and drop every ClusterIP. That is most of a cluster: "which port
    is the API service on" and "what is traefik's cluster IP" are ordinary
    questions and the answer was simply not on the page. Published ones still
    sort first, and each row says which it is.
    """
    svcs, ings, troutes = _pmap(lambda f: f(), [
        lambda: _get(cluster, "svc", "-A"),
        lambda: _get(cluster, "ingress", "-A"),
        # Traefik's own CRD: on some clusters, absent on others
        lambda: _get(cluster, "ingressroute", "-A", timeout=12),
    ], workers=3)
    if svcs is None:
        return {"error": "unreachable", "services": [], "routes": []}

    services = []
    for s in _items(svcs):
        meta, spec, st = s["metadata"], s.get("spec", {}), s.get("status", {})
        kind = spec.get("type", "ClusterIP")
        ext = [i.get("ip") or i.get("hostname", "") for i in
               (st.get("loadBalancer") or {}).get("ingress", []) or []]
        ext = [e for e in ext if e]
        services.append({
            "namespace": meta["namespace"], "name": meta["name"], "type": kind,
            "cluster_ip": spec.get("clusterIP", ""),
            "external": ext,
            # What a reader means by "published": something outside the cluster
            # can reach it right now, without a port-forward. A NodePort qualifies
            # on every node's address; a LoadBalancer still waiting for one does
            # NOT — it is intended to be published and is not yet, which is a
            # different thing and the header counts "reachable from outside".
            "published": bool(ext) or kind == "NodePort",
            "pending": kind == "LoadBalancer" and not ext,
            "ports": [f"{p.get('port')}"
                      + (f"→{p['nodePort']}" if p.get("nodePort") else "")
                      + (f" {p['protocol']}" if p.get("protocol") not in
                         (None, "TCP") else "")
                      for p in spec.get("ports", []) or []],
        })
    # published first, then a pending load balancer (which somebody is probably
    # waiting on), then the internal ones by where they live
    services.sort(key=lambda s: (not s["published"], s["type"] != "LoadBalancer",
                                 s["pending"] is False, s["namespace"], s["name"]))

    routes = []
    for i in _items(ings):
        meta, spec = i["metadata"], i.get("spec", {})
        hosts = [r.get("host", "") for r in spec.get("rules", []) or []]
        tls_hosts = [h for t in spec.get("tls", []) or [] for h in t.get("hosts", [])]
        # Which Service each rule sends traffic to. The host is only half of what
        # an ingress says; "api.example.com is served by WHAT" is the other half,
        # and it was not on the page — you had to open the YAML to find out.
        backends = []
        for rule in spec.get("rules", []) or []:
            for path in ((rule.get("http") or {}).get("paths") or []):
                svc = ((path.get("backend") or {}).get("service") or {})
                name = svc.get("name") or ""
                port = ((svc.get("port") or {}).get("number")
                        or (svc.get("port") or {}).get("name") or "")
                if name and (name, port) not in backends:
                    backends.append((name, port))
        default = (((spec.get("defaultBackend") or {}).get("service")) or {})
        if default.get("name"):
            backends.append((default["name"], "default"))
        routes.append({
            # `api` is what kubectl is asked for; `kind` is what a person reads
            "kind": "Ingress", "api": "ingress", "namespace": meta["namespace"],
            "services": [f"{n}:{p}" if p else n for n, p in backends],
            "name": meta["name"], "hosts": [h for h in hosts if h],
            "tls": bool(spec.get("tls")), "tls_hosts": tls_hosts,
            "class": spec.get("ingressClassName", ""),
        })
    for r in _items(troutes):
        meta, spec = r["metadata"], r.get("spec", {})
        hosts = []
        for rule in spec.get("routes", []) or []:
            # a Traefik match expression, e.g. Host(`api.example.com`)
            for m in re.findall(r"Host\(([^)]*)\)", rule.get("match", "")):
                hosts += [h.strip().strip("`'\"") for h in m.split(",")]
        # Traefik keeps its backends in each route's `services` list.
        tsvcs = []
        for rule in spec.get("routes", []) or []:
            for svc in rule.get("services", []) or []:
                got = (f'{svc.get("name", "")}:{svc.get("port", "")}'
                       if svc.get("port") else svc.get("name", ""))
                if svc.get("name") and got not in tsvcs:
                    tsvcs.append(got)
        routes.append({
            "kind": "IngressRoute", "api": "ingressroute",
            "namespace": meta["namespace"], "services": tsvcs,
            "name": meta["name"], "hosts": [h for h in hosts if h],
            "tls": bool(spec.get("tls")), "tls_hosts": [],
            "class": ", ".join(spec.get("entryPoints", []) or []),
        })
    routes.sort(key=lambda r: (r["namespace"], r["name"]))
    return {"error": "", "services": services, "routes": routes,
            "hosts": sorted({h for r in routes for h in r["hosts"]})}


def _part_argocd(cluster: dict) -> dict:
    """ArgoCD applications, when ArgoCD is installed here. Absent otherwise."""
    doc = _get(cluster, "applications", "-A", timeout=14)
    if doc is None:
        return {"present": False, "apps": []}
    apps = []
    for a in _items(doc):
        meta, st = a["metadata"], a.get("status", {})
        sync = (st.get("sync") or {}).get("status", "")
        health = (st.get("health") or {}).get("status", "")
        op = st.get("operationState") or {}
        apps.append({
            "name": meta["name"], "namespace": meta.get("namespace", ""),
            "sync": sync, "health": health,
            "ok": sync == "Synced" and health == "Healthy",
            "revision": ((st.get("sync") or {}).get("revision") or "")[:7],
            "dest": (a.get("spec", {}).get("destination") or {}).get("namespace", ""),
            # When it last actually deployed, so a reader that puts changes on a
            # time axis does not have to ask Argo's own API for it — this is the
            # only sync record available on a cluster with no Argo credentials
            # registered. UTC with the offset dropped, as Argo writes it.
            "when": (op.get("finishedAt") or "")[:19].replace("T", " "),
            "phase": op.get("phase", ""),
        })
    apps.sort(key=lambda a: (a["ok"], a["name"]))
    return {"present": True, "apps": apps,
            "drifted": sum(1 for a in apps if a["sync"] not in ("Synced", "")),
            "unhealthy": sum(1 for a in apps
                             if a["health"] not in ("Healthy", "", "Progressing"))}


def _part_certs(cluster: dict) -> dict:
    """cert-manager certificates, when the CRD exists."""
    doc = _get(cluster, "certificates", "-A", timeout=14)
    if doc is None:
        return {"present": False, "certs": []}
    certs = []
    for c in _items(doc):
        meta, st, spec = c["metadata"], c.get("status", {}), c.get("spec", {})
        ready = next((x for x in st.get("conditions", []) or []
                      if x.get("type") == "Ready"), {})
        days = _days_until(st.get("notAfter", ""))
        certs.append({
            "namespace": meta["namespace"], "name": meta["name"],
            "ready": ready.get("status") == "True",
            "reason": ready.get("reason", ""),
            "dns": spec.get("dnsNames", []) or [],
            "issuer": (spec.get("issuerRef") or {}).get("name", ""),
            "not_after": st.get("notAfter", ""), "days": days,
        })
    certs.sort(key=lambda c: (c["days"] if c["days"] is not None else 9999))
    return {"present": True, "certs": certs,
            "expiring": sum(1 for c in certs
                            if c["days"] is not None and c["days"] <= 30),
            "failing": sum(1 for c in certs if not c["ready"])}


# One call, two fields. `-o json` over every TLS secret would hand this process
# every private key in the cluster to read a date off the certificate next to
# it; a key that is never fetched is a key that cannot leak, be logged, or end
# up in a cache. The jsonpath asks for the certificate and the cert-manager
# annotation, and nothing else.
# The two extra columns say WHO renews the cert, so a self-rotating one is not
# flagged as "needs a person": cert-manager stamps an annotation on the secret,
# CloudNativePG (Postgres) labels its own TLS secrets with cnpg.io/cluster and
# rotates them itself. Both are auto-renewing; anything with neither is manual.
# THE BLOB STAYS LAST, and the guard below counts these fields. Add a column
# before `.data.tls\.crt` and move both together, or every row fails the
# length check and the radar renders an empty — i.e. clean — cluster.
#
# Verified offline with `kubectl patch --local`: an ABSENT field emits an
# EMPTY column and the `{"\t"}` literals are separate template nodes that are
# always written, so nothing shifts left and the blob cannot be corrupted by
# a missing label. The escaping `{.metadata.labels.cnpg\.io/cluster}` is also
# correct — `\` escapes the next rune and `/` is not a terminator.
#
# WHY THE OWNER REFERENCE IS HERE. The `cnpg.io/cluster` label was the only
# CloudNativePG signal and **CNPG never puts it on a certificate secret**:
# `ensureCASecret`/`ensureLeafCertificate` call `utils.SetAsOwnedBy` and
# nothing else, in every release from v1.15.0 to today. So every CNPG
# certificate in every estate has been reading as "needs a person" since this
# feature shipped. The owner reference is the signal that is actually present,
# and it is a garbage-collection contract rather than decoration.
_TLS_PATH = ('jsonpath={range .items[*]}{.metadata.namespace}{"\\t"}'
             '{.metadata.name}{"\\t"}'
             '{.metadata.annotations.cert-manager\\.io/certificate-name}{"\\t"}'
             '{.metadata.labels.cnpg\\.io/cluster}{"\\t"}'
             '{.metadata.ownerReferences[*].apiVersion}{"\\t"}'
             '{.metadata.ownerReferences[*].kind}{"\\t"}'
             '{.metadata.ownerReferences[*].name}{"\\t"}'
             '{.data.tls\\.crt}{"\\n"}{end}')
_TLS_COLS = 8                      # keep in step with the template above

# Operators that mint AND RENEW their own TLS, by owner API GROUP, with the
# renewal policy each one publishes: (name, issued-for days, renews-at days).
#
# KEYED ON A KNOWN GROUP, NEVER ON "an owner exists". An owner reference is
# PROVENANCE — who created this object — and the tag on the page is a claim
# about LIVENESS: that something will renew it. A secret adopted by, say, a
# Helm-installed StatefulSet would flip to "renews itself" under a generic
# rule while nothing whatsoever renewed it, and that failure is silent until
# TLS breaks. An unrecognised group is therefore NOT auto.
RENEWERS = {
    # CertificateDuration=90, ExpiringCheckThreshold=7 (internal/configuration),
    # overridable per-install by CERTIFICATE_DURATION, so the numbers here are
    # the default and the certificate's own lifetime is what is measured.
    "postgresql.cnpg.io": ("CloudNativePG", 90, 7),
}


def _part_tls(cluster: dict) -> dict:
    """Every certificate the cluster is actually serving, with its expiry.

    WHY THIS IS NOT _part_certs
        That one reads cert-manager's Certificate objects — what cert-manager
        has been ASKED to manage. This reads the secrets themselves, which is
        what is actually presented on the wire. The difference is the whole
        point: a certificate somebody installed by hand, or one issued by a
        system that is no longer running, appears here and nowhere else, and
        it is exactly the kind that expires unnoticed because nothing renews
        it. `managed` marks which are cert-manager's problem and which are
        yours.
    """
    from . import certs as certlib
    # "no certificates" and "could not ask" must not look the same. A cluster
    # this portal cannot reach is the one most likely to be holding the expired
    # certificate nobody has looked at, so it says so instead of contributing
    # nothing and reading as clean.
    if not kube.reachable(cluster)[0]:
        return {"present": False, "certs": [], "error": "unreachable"}
    out, err = _text(cluster, "secrets", "-A",
                     "--field-selector", "type=kubernetes.io/tls",
                     "-o", _TLS_PATH, timeout=16)
    # A FAILED LIST IS NOT AN EMPTY CLUSTER. This used to fall through to the
    # empty answer below, so a kubeconfig without cluster-wide secret access
    # rendered as a cluster with nothing needing attention -- on the page whose
    # entire job is to say what nobody is watching.
    if err:
        return {"present": False, "certs": [], "error": err}
    if not out.strip():
        return {"present": True, "certs": [], "unreadable": 0,
                "manual": 0, "expiring": 0}
    rows, unreadable = [], 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < _TLS_COLS or not parts[_TLS_COLS - 1].strip():
            continue
        (namespace, name, cm, cnpg,
         own_api, own_kind, own_name, blob) = parts[:_TLS_COLS]
        try:
            pem = base64.b64decode(blob).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            unreadable += 1
            continue
        got = certlib.read_cert(pem)
        if got["not_after"] is None:
            unreadable += 1
            continue
        when = datetime.fromtimestamp(got["not_after"], timezone.utc)
        managed = bool(cm.strip())            # cert-manager Certificate object
        cnpg_owned = bool(cnpg.strip())       # the label, when it is there
        # `[*]` space-joins several owners; a controller owner is normally the
        # only one, and the first is the one that made the object.
        api = (own_api.split() or [""])[0]
        kind = (own_kind.split() or [""])[0]
        oname = (own_name.split() or [""])[0]
        group = api.split("/")[0] if "/" in api else ""
        known = RENEWERS.get(group)
        # LIFETIME AND AGE, from the certificate's own bytes. This is the
        # second witness that makes any renewer claim checkable: a certificate
        # whose renewer is alive is never observed below its own renewal
        # window, so one that is proves nothing is renewing it.
        life = age = None
        if got.get("not_before"):
            life = max(0, (got["not_after"] - got["not_before"]) // 86400)
            age = max(0, (int(datetime.now(timezone.utc).timestamp())
                          - got["not_before"]) // 86400)
        days = (when - datetime.now(timezone.utc)).days
        renewer = ("cert-manager" if managed
                   else known[0] if known
                   else "CloudNativePG" if cnpg_owned else "")
        auto = bool(managed or known or cnpg_owned)
        # OVERDUE IS ITS OWN STATE and must never be folded into either of the
        # other two. Something claims to renew this and the certificate says
        # it has not: louder than "needs a person", because a renewer nobody
        # is watching is worse than no renewer at all.
        overdue = False
        if known and life:
            # the operator's published window, scaled to this certificate's
            # actual lifetime rather than the documented default
            at = known[2] * life / known[1] if known[1] else known[2]
            overdue = days < at * 0.5
        rows.append({
            "namespace": namespace, "name": name,
            "managed": managed,
            # `auto` says something renews this; `renewer` names it; `owner`
            # is the EVIDENCE, so a reader can judge the claim rather than
            # take it. Provenance is a fact the API server recorded; renewal
            # is a prediction, and they are shown as different things.
            "auto": auto,
            "renewer": renewer,
            "owner": f"{kind}/{oname}" if kind and oname else "",
            "owner_group": group,
            "overdue": overdue,
            "lifetime_days": life, "age_days": age,
            "domains": got["domains"], "issuer": got["issuer"],
            "partial": got["partial"],
            "not_after": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": days,
        })
    rows.sort(key=lambda r: r["days"])
    return {"present": True, "certs": rows, "unreadable": unreadable,
            "manual": sum(1 for r in rows if not r["auto"]),
            "overdue": sum(1 for r in rows if r.get("overdue")),
            "expiring": sum(1 for r in rows if r["days"] <= 30)}


def _part_namespaces(cluster: dict) -> dict:
    """Every namespace, with how many pods are in it.

    Read directly rather than derived from the pod list: a namespace with
    nothing running is still somewhere you want to look, and deriving it from
    pods hides exactly the empty one you are investigating. One cheap call,
    cached like every other part.
    """
    doc = _get(cluster, "namespaces", timeout=10)
    if doc is None:
        return {"error": "unreachable", "namespaces": []}
    pods = _get(cluster, "pods", "-A",
                "--field-selector=status.phase!=Succeeded", timeout=12)
    counts: dict = {}
    for pod in _items(pods):
        n = pod["metadata"].get("namespace", "")
        counts[n] = counts.get(n, 0) + 1
    out = [{"name": n["metadata"]["name"],
            "phase": (n.get("status") or {}).get("phase", ""),
            "pods": counts.get(n["metadata"]["name"], 0)}
           for n in _items(doc)]
    # busiest first, then alphabetical: the one you want is usually the one
    # with something in it, and an alphabetical list of eighty puts kube-system
    # in the middle
    out.sort(key=lambda x: (-x["pods"], x["name"]))
    return {"error": "", "namespaces": out}


def node_strip(nodes: dict) -> dict:
    """The machines, shaped for the header that sits above every cluster tab.

    Built here rather than in the template because "what fraction is used" has
    three different honest answers depending on what the cluster can tell us:
    metrics-server gives real usage, its absence leaves only what the kubelet
    has reserved, and a node that is not Ready can report neither. A template
    cannot make that distinction readably, and guessing it produces a bar that
    looks like usage and is not.
    """
    # Where each meter turns yellow, then orange, then red. Only the last two
    # are round-ish numbers by accident: they follow what the kubelet itself
    # does, so an orange or red ring means something is about to happen rather
    # than that a number crossed a decade.
    #   yellow — filling. Nothing to do; the ring stops being green so a
    #            trend is visible before it is a problem.
    #   memory — the kubelet's default hard eviction is memory.available<100Mi,
    #            so real pressure begins in the high eighties
    #   disk   — nodefs.available<10% is the default, and disks fill one way,
    #            so its orange comes earlier than the others'
    #   cpu    — nothing is evicted for CPU; it is throttling, and a spike is
    #            normal, so only a sustained high number goes red
    BANDS = {"cpu": (60, 80, 92), "memory": (60, 85, 93), "disk": (60, 75, 88)}

    def tone(kind: str, pct: float) -> str:
        warn, high, bad = BANDS[kind]
        return ("bad" if pct >= bad else "high" if pct >= high
                else "warn" if pct >= warn else "")

    rows = nodes.get("nodes") or []
    if nodes.get("error") or not rows:
        return {"nodes": []}
    live = nodes.get("metrics")
    out = []
    for n in rows:
        meters = []
        for label, pct, used, cap, unit in (
            ("cpu", n.get("cpu_pct"), n.get("cpu_use"), n.get("cpu_cap"), "m"),
            ("memory", n.get("mem_pct"), n.get("mem_use"), n.get("mem_cap"), "Mi"),
        ):
            if pct is None:
                # No metrics-server: say what the machine HAS and draw no bar.
                # An empty track reads as "0% used", which is a measurement
                # nobody took — the same silence-as-data trap as everywhere
                # else in this codebase.
                meters.append({"label": label, "measured": False, "pct": 0,
                               "tone": "",
                               "text": (_si(cap, unit) if cap else "—")})
                continue
            meters.append({"label": label, "measured": True,
                           "pct": min(100, max(0, pct)),
                           "tone": tone(label, pct),
                           "text": f"{pct}% of {_si(cap, unit)}"})
        if n.get("disk_cap"):
            pct, pressed = n.get("disk_pct"), bool(n.get("disk_pressure"))
            if pct is None:
                # the kubelet would not answer; say the size and colour only
                # the condition the node itself reports
                meters.append({"label": "disk", "measured": False, "pct": 0,
                               "tone": "bad" if pressed else "",
                               "text": ("under pressure" if pressed
                                        else _si(n["disk_cap"], "Mi"))})
            else:
                meters.append({
                    "label": "disk", "measured": True,
                    "pct": min(100, max(0, pct)),
                    # A node the kubelet says is under disk pressure is red
                    # whatever the percentage reads: it is already evicting.
                    "tone": "bad" if pressed else tone("disk", pct),
                    "text": f"{pct}% of {_si(n['disk_cap'], 'Mi')}"})
        out.append({**n, "meters": meters})
    return {
        "nodes": out, "metrics": bool(live),
        "total": len(rows), "ready": sum(1 for n in rows if n.get("ready")),
        "unschedulable": sum(1 for n in rows if not n.get("schedulable")),
        "pressured": sum(1 for n in rows if n.get("pressure")),
        "cpu_cores": round(sum(n.get("cpu_cap") or 0 for n in rows) / 1000, 1),
        "mem_gib": round(sum(n.get("mem_cap") or 0 for n in rows) / 1024),
        "disk_gib": round(sum(n.get("disk_cap") or 0 for n in rows) / 1024),
    }


def _si(value, unit: str) -> str:
    """A capacity a person reads: millicores as cores, MiB as GiB."""
    try:
        v = float(value or 0)
    except (TypeError, ValueError):
        return "—"
    if unit == "m":
        return f"{v / 1000:.3g} cores"
    if v >= 1024:
        return f"{v / 1024:.3g} GiB"
    return f"{v:.3g} MiB"


def describe(cluster: dict, kind: str, name: str, namespace: str) -> dict:
    """`kubectl describe` for one object — the answer to "why is this unhappy"."""
    args = [kind, name] + (["-n", namespace] if namespace else [])
    base = base_args(cluster)
    if not base:
        return {"error": "this cluster has no kubeconfig set", "text": ""}
    try:
        r = subprocess.run(base + ["describe", *args],
                           capture_output=True, text=True, timeout=CALL_TIMEOUT)
        return {"error": "" if r.returncode == 0 else r.stderr.strip()[:400],
                "text": r.stdout[:120_000]}
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "text": ""}


def pod_logs(cluster: dict, namespace: str, name: str, container: str = "",
             tail: int = 400, previous: bool = False) -> dict:
    """The last N lines from a pod. Bounded and non-streaming on purpose: the
    Logs page streams, this is for a glance without leaving the table."""
    args = ["logs", name, "-n", namespace, f"--tail={max(1, min(tail, 5000))}"]
    if container:
        args += ["-c", container]
    if previous:
        # the crashed container's output, which is what you want after a restart
        args.append("--previous")
    else:
        args.append("--all-containers=true")
    base = base_args(cluster)
    if not base:
        return {"error": "this cluster has no kubeconfig set", "text": ""}
    try:
        r = subprocess.run(base + args, capture_output=True, text=True,
                           timeout=CALL_TIMEOUT)
        return {"error": "" if r.returncode == 0 else r.stderr.strip()[:400],
                "text": r.stdout[-120_000:]}
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "text": ""}


def _part_audit(cluster: dict) -> dict:
    """The API-only security audit. Lives in audit.py; cached here because it is
    the most expensive read the portal makes."""
    from . import audit
    return audit.report(cluster)


def _part_netshoots(cluster: dict) -> dict:
    """The troubleshooting pods this portal has left running.

    A cluster read like any other, and it was the last one still being made
    serially on every single render of the page — three quarters of a second,
    uncached, whether or not anybody was troubleshooting.
    """
    from . import kmanage        # a peer, imported here to keep the import flat
    return {"netshoots": kmanage.netshoot_list(cluster)}


_PARTS = {
    "audit": _part_audit,
    "nodes": _part_nodes, "pods": _part_pods, "workloads": _part_workloads,
    "events": _part_events, "storage": _part_storage, "network": _part_network,
    "crds": _part_crds,
    "argocd": _part_argocd, "certs": _part_certs,
    "tls": _part_tls, "namespaces": _part_namespaces,
    "netshoots": _part_netshoots,
}


def part(cluster: dict, name: str, refresh: bool = False) -> dict:
    fn = _PARTS[name]
    cid = cluster.get("id") or cluster.get("context", "")
    return _cached(cid, name, refresh, lambda: fn(cluster))


def view(cluster: dict, tab: str = "overview", refresh: bool = False) -> dict:
    """Everything the named tab needs, fetched together."""
    tab = tab if tab in NEEDS else "overview"
    names = NEEDS[tab]
    got = _pmap(lambda n: part(cluster, n, refresh), list(names),
                workers=min(6, len(names)))
    data = {n: (g or {"error": "unreachable"}) for n, g in zip(names, got)}
    if tab == "overview":
        data["summary"] = _summarise(data)
    return data


# The page asks for its tab's parts, the namespace list and the nodes in one
# breath. Gatherer is what the timeline and the expiry radar already use for
# the same problem — run them together, hand back whatever has arrived by the
# deadline, and name the rest — so the policy lives in one place rather than
# being written a third time here.
#
# ttl and hard are zero deliberately: the per-part cache above is the cache,
# and a second one over the top of it would be a second lifetime to reason
# about. What this is for is the deadline, and the joining of a second reader
# onto a collection already running.
_gather = _Gatherer("cluster", ttl=0.0, hard=0.0, first_paint=1.3, workers=8)

# A SECOND deadline, for reads that span the whole estate rather than one
# cluster. The number above is worth waiting out because a single cluster's
# parts usually arrive inside it; reading twenty-four clusters does not, so
# spending the same 1.3s on /nodes and /pods bought the skeleton anyway. There
# is one number for "reading the whole fleet" and it lives in fleet.py, next to
# the snapshot that shares the wait.
_gather_fleet = _Gatherer("cluster-fleet", ttl=0.0, hard=0.0,
                          first_paint=_fleet.FIRST_PAINT, workers=8)


def gathered(cluster: dict, names: list, refresh: bool = False) -> dict:
    """{"parts", "pending", "errors"} for these parts, without the wait."""
    cid = cluster.get("id") or cluster.get("context", "")
    if refresh:
        # An explicit Refresh is somebody asking to wait for fresh numbers.
        parts = {n: part(cluster, n, True) for n in names}
        return {"parts": parts, "pending": [], "errors": []}
    jobs = [(n, n, (lambda n=n: part(cluster, n))) for n in names]
    got = _gather.gather(cid, jobs)
    parts = {n: got["parts"].get(n) or {"collecting": True} for n in names}
    return {"parts": parts, "pending": got["pending"], "errors": got["errors"]}


def _summarise(d: dict) -> dict:
    """The headline state of the cluster, and what to look at first."""
    nodes = d.get("nodes", {}).get("nodes", []) or []
    pods = d.get("pods", {}).get("pods", []) or []
    ev = d.get("events", {})
    st = d.get("storage", {})
    argo, certs = d.get("argocd", {}), d.get("certs", {})

    ready = sum(1 for n in nodes if n["ready"])
    phases: dict = {}
    for p in pods:
        phases[p["phase"]] = phases.get(p["phase"], 0) + 1
    bad = [p for p in pods if not p["healthy"]]
    restarting = sorted((p for p in pods if p["restarts"]),
                        key=lambda p: -p["restarts"])[:8]
    ns: dict = {}
    for p in pods:
        ns[p["namespace"]] = ns.get(p["namespace"], 0) + 1

    cpu_cap = sum(n["cpu_cap"] for n in nodes)
    mem_cap = sum(n["mem_cap"] for n in nodes)
    cpu_use = sum(n["cpu_use"] or 0 for n in nodes) if any(
        n["cpu_use"] is not None for n in nodes) else None
    mem_use = sum(n["mem_use"] or 0 for n in nodes) if any(
        n["mem_use"] is not None for n in nodes) else None

    # what deserves attention, worst first — each one names the tab that shows it
    attention = []
    if nodes and ready < len(nodes):
        attention.append({"level": "critical", "tab": "nodes",
                          "text": f"{len(nodes) - ready} node(s) not Ready"})
    for n in nodes:
        if n["pressure"]:
            attention.append({"level": "warn", "tab": "nodes",
                              "text": f"{n['name']}: {', '.join(n['pressure'])}"})
        if not n["schedulable"]:
            attention.append({"level": "warn", "tab": "nodes",
                              "text": f"{n['name']} is cordoned"})
    if bad:
        attention.append({"level": "critical" if len(bad) > 2 else "warn",
                          "tab": "pods",
                          "text": f"{len(bad)} pod(s) not running cleanly"})
    if ev.get("warnings"):
        attention.append({"level": "warn", "tab": "events",
                          "text": f"{ev['warnings']} warning event(s)"})
    unbound = [c for c in st.get("claims", []) if not c["bound"]]
    if unbound:
        attention.append({"level": "warn", "tab": "storage",
                          "text": f"{len(unbound)} volume claim(s) not bound"})
    if st.get("released"):
        attention.append({"level": "info", "tab": "storage",
                          "text": f"{len(st['released'])} released volume(s) "
                                  "left behind"})
    if argo.get("drifted"):
        attention.append({"level": "warn", "tab": "workloads",
                          "text": f"{argo['drifted']} ArgoCD app(s) out of sync"})
    if argo.get("unhealthy"):
        attention.append({"level": "warn", "tab": "workloads",
                          "text": f"{argo['unhealthy']} ArgoCD app(s) unhealthy"})
    if certs.get("failing"):
        attention.append({"level": "critical", "tab": "network",
                          "text": f"{certs['failing']} certificate(s) not ready"})
    if certs.get("expiring"):
        soon = certs["certs"][0] if certs.get("certs") else {}
        attention.append({"level": "warn", "tab": "network",
                          "text": f"{certs['expiring']} certificate(s) expire "
                                  f"within 30 days (soonest: {soon.get('days')}d)"})
    versions = d.get("nodes", {}).get("versions") or []
    if len(versions) > 1:
        attention.append({"level": "info", "tab": "nodes",
                          "text": "nodes run different kubelet versions: "
                                  + ", ".join(versions)})
    order = {"critical": 0, "warn": 1, "info": 2}
    attention.sort(key=lambda a: order.get(a["level"], 9))

    return {
        "nodes_total": len(nodes), "nodes_ready": ready,
        "version": versions[0] if versions else "",
        "versions": versions,
        "pods_total": len(pods), "pods_bad": len(bad), "phases": phases,
        "restarting": restarting,
        "namespaces": sorted(ns.items(), key=lambda kv: -kv[1]),
        "cpu_cap": cpu_cap, "mem_cap": mem_cap,
        "cpu_use": cpu_use, "mem_use": mem_use,
        "cpu_pct": round(cpu_use / cpu_cap * 100) if cpu_use and cpu_cap else None,
        "mem_pct": round(mem_use / mem_cap * 100) if mem_use and mem_cap else None,
        "storage_gib": st.get("total_gib", 0), "claims": len(st.get("claims", [])),
        "attention": attention,
        "healthy": not any(a["level"] == "critical" for a in attention),
    }


# ── the whole fleet on one page ────────────────────────────────
def everywhere(part_name: str, refresh: bool = False) -> list:
    """One part — nodes or pods — read from every cluster in every project,
    in parallel, through the same per-cluster cache the tabs use. Each row is
    tagged with its project and cluster so one table can hold the fleet.

    Unreachable clusters cost the shared 30-second probe and come back as an
    error entry rather than being silently absent: on a fleet page, "this
    cluster could not be read" is data.

    BOUNDED, like every other slow read here. This used to _pmap over every
    cluster and join them all, so /nodes and /pods cost the slowest cluster in
    the estate on a cold cache — measured at fourteen seconds across
    twenty-four clusters. It now goes through the same gatherer the cluster
    tabs use: whatever has arrived by its first paint is returned, the rest
    keeps collecting behind the page, and the caller is told what is missing
    through `pending_clusters()` so the page can SAY so instead of quietly
    showing a short list.
    """
    from . import store
    jobs = []
    for pid, proj in store.projects().items():
        for cid, c in (proj.get("clusters") or {}).items():
            jobs.append((pid, proj.get("name", pid), cid,
                         {**c, "id": cid}))
    if not jobs:
        _PENDING.pop(part_name, None)
        return []

    def one(pid, pname, cid, c):
        got = part(c, part_name, refresh=refresh)
        return {"pid": pid, "project": pname, "cid": cid,
                "cluster": c.get("name", cid), **got}

    if refresh:
        # An explicit Refresh is somebody asking to wait for fresh numbers.
        _PENDING.pop(part_name, None)
        return [r for r in _pmap(lambda j: one(*j), jobs,
                                 workers=min(8, len(jobs))) if r]

    got = _gather_fleet.gather(
        f"everywhere:{part_name}",
        [(cid, c.get("name", cid), (lambda a=(pid, pname, cid, c): one(*a)))
         for pid, pname, cid, c in jobs])
    # Remembered per part rather than returned, so every existing caller of
    # everywhere() keeps working unchanged and only the pages that want to name
    # what is missing have to ask.
    _PENDING[part_name] = list(got["pending"])
    order = {cid: i for i, (_pid, _pname, cid, _c) in enumerate(jobs)}
    return sorted((v for v in got["parts"].values() if v),
                  key=lambda r: order.get(r["cid"], 0))


# What everywhere() could not read in time, by part. Read by the fleet pages
# through pending_clusters() so they can name it.
_PENDING: dict = {}


def pending_clusters(part_name: str) -> list:
    """Cluster names still being collected for this part, if any."""
    return list(_PENDING.get(part_name) or [])


# ── one service's resources, on the cluster ────────────────────
# WHY A BUNDLE AND NOT A PART PER KIND
#     The service view asks "what does this microservice consist of here", which
#     is six kinds in one namespace. Six kubectl calls to answer one page is six
#     round trips over somebody's VPN, so they go in one call — kubectl accepts a
#     comma-separated kind list and answers with one List of mixed items.
#
#     SealedSecret is asked for separately because it is a CRD: on a cluster
#     without sealed-secrets installed the combined call fails ENTIRELY, taking
#     the ConfigMaps down with it. Asked on its own, its absence costs nothing.
BUNDLE_KINDS = ("deployment", "statefulset", "service", "ingress",
                "configmap", "secret")


def _bundle_rows(cluster: dict, namespace: str) -> dict:
    """Every resource in one namespace, asked for ONE KIND AT A TIME.

    It was a single comma-separated call, which is all-or-nothing: on a real
    cluster whose credentials may not list configmaps or secrets, the whole read
    failed and the page said "could not read namespace" — hiding the Deployments,
    Services and Ingresses it was perfectly able to show, and hiding the reason.
    The same fragility was already noted for the SealedSecret CRD and then not
    applied to the rest of the list.

    Per kind in parallel, so a kind that is Forbidden or absent costs only
    itself and says so.
    """
    asked = list(BUNDLE_KINDS) + ["sealedsecret", "ingressroute"]
    got = _pmap(lambda kind: (kind, _get_why(cluster, kind, "-n", namespace,
                                             timeout=14)),
                asked, workers=min(8, len(asked)))
    items, refused, reached = [], [], 0
    for pair in got:
        if not pair:
            continue
        kind, (doc, why) = pair
        if doc is None:
            refused.append({"kind": kind, "why": why})
        else:
            reached += 1
            items += _items(doc)
    # Nothing answered at all: that is a cluster problem rather than a per-kind
    # one, and the first reason is the one worth repeating.
    if not reached:
        first = refused[0]["why"] if refused else "no answer"
        return {"error": first, "items": [], "refused": refused}
    return {"error": "", "items": items, "refused": refused}


def service_bundle(cluster: dict, namespace: str, refresh: bool = False) -> dict:
    """Every resource in one namespace that a service could be made of.

    Cached per namespace rather than per service: a namespace usually holds one
    service's worth of objects, and where it holds several they are one read
    between them instead of one each.
    """
    cid = cluster.get("id") or cluster.get("context", "")
    return _cached(cid, f"bundle:{namespace}", refresh,
                   lambda: _bundle_rows(cluster, namespace))


def data_keys(cluster: dict, kind: str, name: str, namespace: str) -> dict:
    """The data of one ConfigMap or Secret, read fresh and never cached.

    Not cached, and deliberately a separate call from the bundle: this is what
    the editor reads back after a write, and a cached answer there shows the
    person their change did not take.
    """
    if kind not in ("configmap", "secret"):
        raise ValueError(f"{kind} has no data section to read")
    got = _get(cluster, kind, name, "-n", namespace)
    if got is None:
        return {"error": f"could not read {kind}/{name}", "data": {}}
    data = got.get("data") or {}
    if kind == "secret":
        # Secret values are base64 on the wire. Decoded here so the editor is
        # writing the same thing a person reads, not an encoding of it.
        out = {}
        for k, v in data.items():
            try:
                out[k] = base64.b64decode(v).decode()
            except Exception:                                 # noqa: BLE001
                out[k] = ""      # binary, or not text — never shown, never sent
        data = out
    return {"error": "", "data": data, "type": got.get("type", ""),
            "immutable": bool(got.get("immutable"))}
