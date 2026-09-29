"""GitOps controllers: Argo CD, Flux, and anything that syncs a repo to a cluster.

WHY THIS SITS NEXT TO THE CLUSTER PAGES RATHER THAN INSIDE THEM
    The portal's whole model is that desired state lives in git and a controller
    applies it. That controller is the missing half of every "I pushed it, why is
    it not running" conversation: the repo says one thing, the cluster says
    another, and the answer is in the controller's sync status. So it gets its
    own page, listing applications across every connection with the two facts
    that matter — sync state and health — and a link into the tool itself.

WHAT IT READS, AND WHAT IT WILL DO
    Reading is everything Argo CD's own UI shows: applications, their resource
    tree, sync and health per resource, deployment history and conditions.

    Two operations are offered as well, and this is a deliberate reversal of
    the position this module used to take. Refresh only asks the controller to
    re-read git; it changes nothing in the cluster and needs no ceremony. Sync
    does change the cluster, so it is behind a dialog that names the
    application and the destination, it is written to the audit log with who
    asked for it, and pruning is off unless it is ticked. A dry run is offered
    first and costs nothing.

    Rollback, delete and editing an application are still not here. Those are
    rarer, more destructive, and belong where the full context is.

TWO PROVIDERS, TWO SHAPES
    * Argo CD has a REST API and its own auth (a project token, or an account's
      username and password exchanged for a session token). One connection sees
      every application the token's account may see.
    * Flux has no API — it is CRDs in the cluster. So a Flux "connection" is a
      cluster the portal already knows: it reads Kustomization and HelmRelease
      objects with kubectl, which means it needs no new credentials at all.
"""
import difflib
import json
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import yaml

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
CACHE_TTL = 45

PROVIDERS = {
    "argocd": {
        "label": "Argo CD",
        "icon": "🐙",
        "url_hint": "https://argocd.example.com",
        "needs": ["base_url"],
        "auth": "an API token (Settings → Accounts → Generate token), or a "
                "username and password which the portal exchanges for a "
                "session token",
        "note": "Every application the account can see, with its resource "
                "tree, health per resource, history and conditions. Refresh "
                "and Sync are offered from the portal, so give the account "
                "only what you want it able to do: a read-only account still "
                "shows everything, and Sync will simply be refused.",
        "fields": {"base_url": "Argo CD URL",
                   "username": "Username (blank if using an API token)",
                   "token": "API token, or the account password"},
    },
    "flux": {
        "label": "Flux",
        "icon": "🌀",
        "url_hint": "(none — pick a cluster below)",
        "needs": ["cluster"],
        "auth": "none: it reads the cluster's own CRDs with the kubeconfig you "
                "already registered",
        "note": "Flux has no API, so this reads Kustomization and HelmRelease "
                "objects from a cluster the portal already knows. Choose the "
                "cluster; no new credentials are involved.",
        "fields": {"cluster": "Cluster to read Flux objects from"},
    },
}


class GitOpsError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

_cache: dict = {}
_refreshing: set = set()
_guard = threading.Lock()


def invalidate() -> None:
    _cache.clear()


def _swr(key: str, ttl: float, produce):
    """Serve warm instantly, serve STALE instantly while ONE background thread
    refreshes (single-flight per key). Only the first-ever look blocks.

    This is what makes the app page open at once: Argo is usually a hop away,
    and the honest cost of "the application, its operation, its history and its
    resource tree" is two round-trips nobody should watch. An operator reading
    a tree three seconds old is right; a page that stalls is not — and every
    action here (refresh, sync, rollback, an edit) drops these keys, so a change
    somebody just made is never what they see stale."""
    hit = _cache.get(key)
    now = time.time()
    if hit and now - hit[0] < ttl:
        return hit[1]
    if hit:
        with _guard:
            spawn = key not in _refreshing
            if spawn:
                _refreshing.add(key)
        if spawn:
            def run():
                try:
                    _cache[key] = (time.time(), produce())
                except Exception:                             # noqa: BLE001
                    pass                # stale stays; the next look retries
                finally:
                    with _guard:
                        _refreshing.discard(key)
            threading.Thread(target=run, daemon=True).start()
        return hit[1]
    got = produce()
    _cache[key] = (time.time(), got)
    return got


def _ckey(conn: dict, *parts) -> str:
    return "::".join([str(conn.get("id") or conn.get("base_url", ""))]
                     + [str(p) for p in parts])


def drop(conn: dict, name: str) -> None:
    """Forget one application's cached reads — called by every action, so what
    a person just did is what they see next."""
    for part in ("view", "tree", "diff", "res", "actions", "events"):
        pre = _ckey(conn, part, name)
        for k in [k for k in list(_cache) if k.startswith(pre)]:
            _cache.pop(k, None)


# Argo answers errors as JSON with the same sentence in two fields, so the raw
# body reads as `HTTP 400 {"error":"…","code":9,"message":"…"}` — the message
# twice, wrapped in punctuation, in a red banner. Worth unwrapping: these are
# the errors an operator sees most, and the commonest of them is not a fault at
# all.
_ARGO_SAYS = {
    "another operation is already in progress":
        "Argo CD is already running an operation on this application — wait "
        "for the current sync to finish, then try again. On an app with "
        "auto-sync this usually means the controller got there first.",
    "application is deleting":
        "this application is being deleted, so it cannot be synced",
}


def _explain(code: int, detail: str) -> str:
    """Argo's own words, unwrapped — or the raw body when it is not JSON."""
    said = ""
    try:
        doc = json.loads(detail or "{}")
        said = str(doc.get("message") or doc.get("error") or "").strip()
    except (json.JSONDecodeError, AttributeError):
        said = ""
    for needle, plain in _ARGO_SAYS.items():
        if needle in said.lower():
            return plain
    if said:
        return said
    return f"HTTP {code} {detail}".strip()


def _req(url: str, headers: dict, verify: bool = True, body=None,
         method: str = ""):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Accept": "application/json", **headers}
    if data:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method=method or None)
    ctx = None if verify else _INSECURE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:                                     # noqa: BLE001
            pass
        if e.code in (401, 403):
            raise GitOpsError("authentication rejected — check the token or "
                              "account") from e
        if e.code == 404:
            raise GitOpsError("not found (404) — check the URL") from e
        raise GitOpsError(_explain(e.code, detail)) from e
    except urllib.error.URLError as e:
        raise GitOpsError(f"cannot reach the server: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise GitOpsError("the server answered, but not with JSON — is this "
                          "the API URL?") from e


# ── Argo CD ────────────────────────────────────────────────────
def _argo_token(c: dict) -> str:
    """The bearer token: either the stored one, or a session exchanged for the
    stored username and password. Sessions are cached for their lifetime so a
    page load does not log in again."""
    if c.get("token") and not c.get("username"):
        return c["token"]
    key = f"session::{c.get('id')}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    if not (c.get("username") and c.get("token")):
        raise GitOpsError("give either an API token, or a username and password")
    doc = _req(f"{c['base_url'].rstrip('/')}/api/v1/session", {},
               not c.get("skip_tls"),
               body={"username": c["username"], "password": c["token"]})
    tok = doc.get("token", "")
    if not tok:
        raise GitOpsError("Argo CD accepted the request but returned no token")
    _cache[key] = (time.time(), tok)
    return tok


def _argo(c: dict, path: str, body=None, method: str = ""):
    """One call to this Argo CD, authenticated."""
    tok = _argo_token(c)
    return _req(f"{c['base_url'].rstrip('/')}/api/v1{path}",
                {"Authorization": f"Bearer {tok}"}, not c.get("skip_tls"),
                body=body, method=method)


def _one_app(a: dict, c: dict) -> dict:
    """The shape every page here is written against, from Argo's own JSON."""
    meta, spec, st = a.get("metadata", {}), a.get("spec", {}), a.get("status", {})
    sync = st.get("sync") or {}
    health = st.get("health") or {}
    op = st.get("operationState") or {}
    dest = spec.get("destination") or {}
    src = spec.get("source") or (spec.get("sources") or [{}])[0]
    return {
        "name": meta.get("name", ""),
        "namespace": meta.get("namespace", ""),
        "labels": {k: str(v) for k, v in (meta.get("labels") or {}).items()},
        "project": spec.get("project", ""),
        "sync": sync.get("status") or "Unknown",
        "health": health.get("status") or "Unknown",
        "health_why": (health.get("message") or "")[:300],
        "revision": (sync.get("revision") or "")[:12],
        "target": src.get("targetRevision") or "",
        "repo": src.get("repoURL", ""),
        "path": src.get("path", "") or src.get("chart", ""),
        "dest": f"{dest.get('name') or dest.get('server', '')}"
                f"/{dest.get('namespace', '')}".strip("/"),
        "dest_server": dest.get("server", "") or dest.get("name", ""),
        "dest_ns": dest.get("namespace", ""),
        "when": (op.get("finishedAt") or "")[:19].replace("T", " "),
        "op_phase": op.get("phase", ""),
        "op_message": (op.get("message") or "")[:300],
        "auto": bool((spec.get("syncPolicy") or {}).get("automated")),
        "self_heal": bool(((spec.get("syncPolicy") or {}).get("automated")
                           or {}).get("selfHeal")),
        "auto_prune": bool(((spec.get("syncPolicy") or {}).get("automated")
                            or {}).get("prune")),
        "conditions": [{"type": x.get("type", ""),
                        "message": (x.get("message") or "")[:300]}
                       for x in st.get("conditions") or []],
        "url": f"{c['base_url'].rstrip('/')}/applications/{meta.get('name','')}",
    }


def _argo_apps(c: dict) -> list[dict]:
    doc = _argo(c, "/applications")
    out = [_one_app(a, c) for a in doc.get("items") or []]
    out.sort(key=lambda a: (a["health"] == "Healthy" and a["sync"] == "Synced",
                            a["name"]))
    return out


def app(conn: dict, name: str, refresh: str = "") -> dict:
    """One application. `refresh` asks the controller to re-read git first —
    "normal" compares against the cached manifests, "hard" re-renders them."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications have a detail view")
    q = f"?refresh={refresh}" if refresh in ("normal", "hard") else ""
    return _one_app(_argo(conn, f"/applications/{_esc(name)}{q}"), conn)


def app_and_operation(conn: dict, name: str) -> tuple[dict, dict]:
    """Both, from one request — the page needs each and Argo sends them
    together."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications have a detail view")
    doc = _argo(conn, f"/applications/{_esc(name)}")
    return _one_app(doc, conn), operation(conn, name, doc)


def _app_doc(conn: dict, name: str) -> dict:
    """The application document, SWR-cached once. Four readers want it — the
    view, the parameters, the per-resource sync status and the history — and
    each used to fetch its own copy."""
    return _swr(_ckey(conn, "doc", name), 12.0,
                lambda: _argo(conn, f"/applications/{_esc(name)}"))


def sync_map(conn: dict, name: str) -> dict:
    """(kind, namespace, name) -> Synced / OutOfSync, from the application's own
    status.resources. The resource TREE does not carry sync state — Argo's UI
    draws it from here, which is why our nodes never had it."""
    out = {}
    for r in ((_app_doc(conn, name).get("status") or {}).get("resources") or []):
        out[(r.get("kind", ""), r.get("namespace", "") or "",
             r.get("name", ""))] = {
                 "sync": r.get("status", ""),
                 "health": ((r.get("health") or {}).get("status") or "")}
    return out


def revision_meta(conn: dict, name: str, revision: str) -> dict:
    """Who wrote the commit a revision points at, and what they said — the
    author/comment line Argo CD puts on its Sync Status and Last Sync cards.
    Best-effort: a Helm chart revision has no commit, and that is not an error."""
    if conn.get("type") != "argocd" or not revision:
        return {}

    def produce():
        got = _argo(conn, f"/applications/{_esc(name)}/revisions/"
                          f"{urllib.parse.quote(str(revision), safe='')}/metadata")
        return {"author": got.get("author", ""),
                "date": (got.get("date") or "")[:19].replace("T", " "),
                "message": (got.get("message") or "").strip()[:300],
                "tags": list(got.get("tags") or [])}
    try:
        return _swr(_ckey(conn, "rev", name, revision), 300.0, produce)
    except GitOpsError:
        return {}


def app_view(conn: dict, name: str) -> tuple[dict, dict, list]:
    """The app page's document-derived parts — the application, its operation
    and its deploy history — from ONE request, served stale-while-revalidate.
    history() used to refetch the same document the page had just been handed;
    on a far-away Argo that was a whole round-trip for nothing."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications have a detail view")

    doc = _app_doc(conn, name)
    return (_one_app(doc, conn), operation(conn, name, doc),
            history(conn, name, doc))


def app_params(conn: dict, name: str) -> dict:
    """The rendered-from settings — Helm values/parameters, Kustomize images,
    directory options — which Argo CD shows and this page never did. Reads the
    same cached document app_view() just used, so it is free."""
    if conn.get("type") != "argocd":
        return {}

    return params(_app_doc(conn, name))


def params(doc: dict) -> dict:
    """What the source is rendered with. Empty dict when a plain directory app
    has nothing to say, so the page can leave the card out rather than draw an
    empty one."""
    spec = doc.get("spec") or {}
    src = spec.get("source") or (spec.get("sources") or [{}])[0]
    helm = src.get("helm") or {}
    kust = src.get("kustomize") or {}
    dirp = src.get("directory") or {}
    out = {
        "kind": ("Helm" if helm else "Kustomize" if kust
                 else "Directory" if dirp else ""),
        "helm_params": [{"name": p.get("name", ""),
                         "value": str(p.get("value", "")),
                         "forced": bool(p.get("forceString"))}
                        for p in (helm.get("parameters") or [])],
        "value_files": list(helm.get("valueFiles") or []),
        # `inline_values`, not `values`: Jinja resolves dict.values() before a
        # key of that name, so the template would render a bound method — the
        # same trap logstore's facet `vals` exists to avoid
        "inline_values": (helm.get("values") or "")[:4000],
        "release": helm.get("releaseName", ""),
        "version": helm.get("version", ""),
        "kust_images": list(kust.get("images") or []),
        "name_prefix": kust.get("namePrefix", ""),
        "name_suffix": kust.get("nameSuffix", ""),
        "recurse": bool(dirp.get("recurse")),
        "images": list(((doc.get("status") or {}).get("summary")
                        or {}).get("images") or []),
        "sources": len(spec.get("sources") or []) or 1,
        "ignore_diffs": len(spec.get("ignoreDifferences") or []),
        "sync_options": list((spec.get("syncPolicy") or {})
                             .get("syncOptions") or []),
    }
    return out


def _esc(name: str) -> str:
    return urllib.parse.quote(str(name or ""), safe="")


def tree(conn: dict, name: str) -> dict:
    """The resource tree, arranged for drawing.

    Argo returns a flat list of nodes, each naming its parents by uid. Turning
    that into the nesting the UI shows is this function's whole job; doing it
    in a template would be unreadable.

    Stale-while-revalidate (12s): opening a resource panel needs the tree only
    to find the node the page just drew from the very same tree, and paying a
    fresh round-trip to a far-away Argo per click is the whole reason the panel
    felt slow. `flat` is every node in one list, for the filter bar.
    """
    if conn.get("type") != "argocd":
        return {"roots": [], "count": 0, "by_health": {}, "by_sync": {},
                "by_kind": {}, "flat": []}
    return _swr(_ckey(conn, "tree", name), 12.0,
                lambda: _build_tree(conn, name))


def _build_tree(conn: dict, name: str) -> dict:
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_tree = pool.submit(_argo, conn,
                             f"/applications/{_esc(name)}/resource-tree")
        f_sync = pool.submit(sync_map, conn, name)
    doc = f_tree.result()
    try:
        smap = f_sync.result()
    except GitOpsError:
        smap = {}
    nodes, kids, parents = {}, {}, set()
    for n in doc.get("nodes") or []:
        uid = n.get("uid") or f"{n.get('kind')}/{n.get('name')}"
        nodes[uid] = {
            "uid": uid, "kind": n.get("kind", ""), "name": n.get("name", ""),
            "namespace": n.get("namespace", ""), "group": n.get("group", ""),
            "version": n.get("version", ""),
            "health": ((n.get("health") or {}).get("status") or ""),
            "health_why": ((n.get("health") or {}).get("message") or "")[:200],
            "images": n.get("images") or [],
            "created": (n.get("createdAt") or "")[:19].replace("T", " "),
            "age": _age(n.get("createdAt") or ""),
            "info": [f"{i.get('name')}: {i.get('value')}"
                     for i in n.get("info") or []
                     if i.get("name") not in ("Node", "Containers")],
            # What Kubernetes actually says about it — "ContainerCreating",
            # "Pending", "Running", "CrashLoopBackOff", "Terminating" — kept
            # apart from Argo's health word, because "progressing" is the word
            # that tells a reader the least: it is true of a pod that is
            # pulling an image, one waiting on a node, and one crash-looping.
            "phase": next((str(i.get("value")) for i in n.get("info") or []
                           if i.get("name") == "Status Reason"
                           and i.get("value")), ""),
            "ready": next((str(i.get("value")) for i in n.get("info") or []
                           if i.get("name") == "Containers"
                           and i.get("value")), ""),
            # what Argo prints ON the card when there is no phase: "rev:4"
            "chips": [str(i.get("value")) for i in n.get("info") or []
                      if i.get("name") in ("Revision", "Images")
                      and i.get("value")],
            "sync": "", "children": [],
        }
        for p in n.get("parentRefs") or []:
            pid = p.get("uid") or f"{p.get('kind')}/{p.get('name')}"
            kids.setdefault(pid, []).append(uid)
            parents.add(uid)
    for pid, cs in kids.items():
        if pid in nodes:
            nodes[pid]["children"] = [nodes[c] for c in cs if c in nodes]
    roots = [n for uid, n in nodes.items() if uid not in parents]
    order = {"Healthy": 0, "": 1, "Progressing": 2, "Missing": 3,
             "Suspended": 4, "Degraded": 5, "Unknown": 6}

    def rank(n):
        return (-order.get(n["health"], 1), n["kind"], n["name"])
    def sort_all(ns):
        ns.sort(key=rank)
        for n in ns:
            sort_all(n["children"])
    sort_all(roots)
    by_health: dict[str, int] = {}
    for n in nodes.values():
        by_health[n["health"] or "Unknown"] = by_health.get(
            n["health"] or "Unknown", 0) + 1
    by_sync: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for n in nodes.values():
        got = smap.get((n["kind"], n["namespace"], n["name"])) or {}
        n["sync"] = got.get("sync", "")
        if n["sync"]:
            by_sync[n["sync"]] = by_sync.get(n["sync"], 0) + 1
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    return {"roots": roots, "count": len(nodes), "by_health": by_health,
            "by_sync": by_sync, "by_kind": dict(sorted(by_kind.items())),
            "flat": sorted(nodes.values(),
                           key=lambda n: (n["kind"], n["name"]))}


def history(conn: dict, name: str, doc: dict | None = None) -> list[dict]:
    """What was deployed, and when. Argo keeps the last ten by default. A
    caller that already fetched the application hands it over (the operation()
    contract)."""
    if conn.get("type") != "argocd":
        return []
    if doc is None:
        doc = _argo(conn, f"/applications/{_esc(name)}")
    out = []
    for h in reversed((doc.get("status") or {}).get("history") or []):
        src = h.get("source") or {}
        out.append({"id": h.get("id", ""),
                    "revision": (h.get("revision") or "")[:12],
                    "at": (h.get("deployedAt") or "")[:19].replace("T", " "),
                    "target": src.get("targetRevision", ""),
                    "path": src.get("path", "")})
    return out[:12]


_TERMINAL = ("Succeeded", "Failed", "Error", "Terminated")


def operation(conn: dict, name: str, doc: dict | None = None) -> dict:
    """What the sync is doing right now, resource by resource.

    Argo CD's sync is asynchronous: the POST queues an operation and returns
    immediately, and the interesting part happens afterwards. This is that
    part — the same thing its own sync window shows — so watching a sync does
    not mean leaving the portal for the tool it just drove.
    """
    if conn.get("type") != "argocd":
        return {"phase": "", "resources": [], "running": False}
    # Argo returns the operation inside the application, so a caller that has
    # just fetched one can hand it over rather than asking again.
    if doc is None:
        doc = _argo(conn, f"/applications/{_esc(name)}")
    st = doc.get("status") or {}
    op = st.get("operationState") or {}
    sync = (op.get("operation") or {}).get("sync") or {}
    result = op.get("syncResult") or {}
    rows = []
    for r in result.get("resources") or []:
        rows.append({
            "kind": r.get("kind", ""), "name": r.get("name", ""),
            "namespace": r.get("namespace", ""),
            "group": r.get("group", ""), "version": r.get("version", ""),
            "status": r.get("status", "") or r.get("hookPhase", ""),
            "phase": r.get("syncPhase", "") or r.get("hookPhase", ""),
            "message": (r.get("message") or "")[:240],
        })
    bad = {"SyncFailed", "Failed", "Error", "ServerError", "Unknown"}
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"] or "pending"] = counts.get(r["status"] or "pending", 0) + 1
    phase = op.get("phase", "")
    # Ordered so the ones that need reading are at the top: a sync of ninety
    # resources where two failed should not make you hunt for the two.
    rows.sort(key=lambda r: (r["status"] not in bad, r["kind"], r["name"]))
    return {
        "phase": phase,
        "running": bool(phase) and phase not in _TERMINAL,
        "ok": phase == "Succeeded",
        "message": (op.get("message") or "")[:400],
        "started": (op.get("startedAt") or "")[:19].replace("T", " "),
        "finished": (op.get("finishedAt") or "")[:19].replace("T", " "),
        "revision": (result.get("revision") or sync.get("revision") or "")[:12],
        "dry_run": bool(sync.get("dryRun")),
        "prune": bool(sync.get("prune")),
        "resources": rows, "counts": counts,
        "failed": sum(n for s, n in counts.items() if s in bad),
        "sync": (st.get("sync") or {}).get("status", ""),
        "health": (st.get("health") or {}).get("status", ""),
    }


def refresh_app(conn: dict, name: str, hard: bool = False) -> str:
    """Ask the controller to re-read git. Changes nothing in the cluster."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD can be refreshed from here")
    got = app(conn, name, refresh="hard" if hard else "normal")
    invalidate()
    return (f"refreshed — {got['sync']}, {got['health']}"
            + (" (manifests re-rendered)" if hard else ""))


# The sync switches Argo CD's own dialog offers, and the wire form each takes.
# Kept as data so the panel can be built from it and a new one is one line.
SYNC_FLAGS = {
    "validate":    ("Skip schema validation", "Validate=false"),
    "createns":    ("Auto-create namespace", "CreateNamespace=true"),
    "prunelast":   ("Prune last", "PruneLast=true"),
    "applyoos":    ("Apply out of sync only", "ApplyOutOfSyncOnly=true"),
    "respectdiff": ("Respect ignore differences", "RespectIgnoreDifferences=true"),
    "ssa":         ("Server-side apply", "ServerSideApply=true"),
    "replace":     ("Replace", "Replace=true"),
}
PRUNE_POLICIES = ("foreground", "background", "orphan")


def sync_app(conn: dict, name: str, prune: bool = False,
             dry_run: bool = False, resources: list | None = None,
             revision: str = "", apply_only: bool = False,
             force: bool = False, flags: list | None = None,
             prune_policy: str = "", retry: bool = False) -> str:
    """Apply what is in git to the cluster.

    Pruning is separate and off by default: syncing a manifest is recoverable,
    deleting a resource the manifest no longer mentions frequently is not.

    Everything Argo CD's own Synchronize panel offers is here, in its wire
    form: `revision` to sync something other than the tracked target,
    apply-only vs hooks, force, the `syncOptions` list (see SYNC_FLAGS), the
    prune propagation policy, and a retry strategy. A caller that passes none
    of them sends exactly what this function always sent.
    """
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications can be synced from here")
    body = {"prune": bool(prune), "dryRun": bool(dry_run)}
    # apply-only skips the hooks; either way `force` rides inside the strategy,
    # which is where Argo reads it from — not the top level
    body["strategy"] = ({"apply": {"force": bool(force)}} if apply_only
                        else {"hook": {"force": bool(force)}})
    if revision:
        body["revision"] = revision
    opts = [SYNC_FLAGS[k][1] for k in (flags or []) if k in SYNC_FLAGS]
    if prune_policy in PRUNE_POLICIES:
        opts.append(f"PrunePropagationPolicy={prune_policy}")
    if opts:
        body["syncOptions"] = {"items": opts}
    if retry:
        # Argo's own defaults for the button: five tries, backing off
        body["retryStrategy"] = {"limit": 5, "backoff": {
            "duration": "5s", "factor": 2, "maxDuration": "3m"}}
    if resources:
        # a SELECTIVE sync: only these objects are applied. Argo wants each as
        # {group, kind, name, namespace}; anything else it silently syncs all,
        # which would be the opposite of what was asked.
        body["resources"] = [{"group": r.get("group", ""),
                              "kind": r.get("kind", ""),
                              "name": r.get("name", ""),
                              "namespace": r.get("namespace", "")}
                             for r in resources if r.get("kind") and r.get("name")]
    _argo(conn, f"/applications/{_esc(name)}/sync", body=body)
    invalidate()
    # Deliberately says "started", not whether it worked. The call only queues
    # the operation, and the reply carries whatever operationState was there
    # before — so reading a phase out of it announced the *previous* sync's
    # result as this one's, and said "succeeded" while the work had not begun.
    # What actually happened arrives from operation(), which the page watches.
    return (("dry run started" if dry_run else "sync started")
            + (f" for {len(body['resources'])} resource(s)"
               if body.get("resources") else "")
            + (f" at {revision}" if revision else "")
            + (", pruning" if prune and not dry_run else ""))


# ── Flux, read from a cluster the portal already knows ─────────
def _flux_apps(c: dict) -> list[dict]:
    from . import cluster as clusterview
    from . import store
    cid = c.get("cluster", "")
    found = None
    for pid, p in store.projects().items():
        if cid in (p.get("clusters") or {}):
            found = {**p["clusters"][cid], "id": cid}
            break
    if not found:
        raise GitOpsError("that cluster is no longer registered — pick another "
                          "in Settings")
    out = []
    for kind, label in (("kustomizations.kustomize.toolkit.fluxcd.io", "Kustomization"),
                        ("helmreleases.helm.toolkit.fluxcd.io", "HelmRelease")):
        doc = clusterview._get(found, kind, "-A")
        if doc is None:
            continue
        for it in doc.get("items") or []:
            meta, spec, st = it["metadata"], it.get("spec", {}), it.get("status", {})
            conds = {x.get("type"): x for x in st.get("conditions") or []}
            ready = conds.get("Ready", {})
            ok = ready.get("status") == "True"
            src = spec.get("sourceRef") or spec.get("chart", {}) \
                .get("spec", {}).get("sourceRef") or {}
            out.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "project": label,
                "sync": "Synced" if ok else "OutOfSync",
                "health": "Healthy" if ok else "Degraded",
                "health_why": (ready.get("message") or "")[:160],
                "revision": (st.get("lastAppliedRevision") or "")[:12],
                "target": spec.get("interval", ""),
                "repo": f"{src.get('kind', '')}/{src.get('name', '')}".strip("/"),
                "path": spec.get("path", "") or (spec.get("chart") or {})
                .get("spec", {}).get("chart", ""),
                "dest": f"{found.get('name', cid)}/{spec.get('targetNamespace')
                                                    or meta.get('namespace', '')}",
                "when": (ready.get("lastTransitionTime") or "")[:19].replace("T", " "),
                "url": "",
            })
    if not out:
        raise GitOpsError("no Flux Kustomizations or HelmReleases found — is "
                          "Flux installed in this cluster?")
    out.sort(key=lambda a: (a["health"] == "Healthy", a["namespace"], a["name"]))
    return out


_IMPL = {"argocd": _argo_apps, "flux": _flux_apps}


def apps(conn: dict, refresh: bool = False) -> list[dict]:
    fn = _IMPL.get(conn.get("type"))
    if not fn:
        raise GitOpsError(f"unknown GitOps tool '{conn.get('type')}'")
    key = f"apps::{conn.get('id')}"
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    got = fn(conn)
    _cache[key] = (time.time(), got)
    return got


def summarise(rows: list[dict]) -> dict:
    """Counts the page leads with: what is not Synced, and what is not Healthy."""
    out = {"total": len(rows), "synced": 0, "outofsync": 0,
           "healthy": 0, "degraded": 0, "progressing": 0, "missing": 0,
           # both at once, which is the state anybody means by "fine" — and
           # not derivable from the other two without knowing the overlap
           "ok": 0}
    for a in rows:
        out["synced" if a["sync"] == "Synced" else "outofsync"] += 1
        h = (a["health"] or "").lower()
        if h == "healthy":
            out["healthy"] += 1
        elif h == "progressing":
            out["progressing"] += 1
        elif h == "missing":
            out["missing"] += 1
        else:
            out["degraded"] += 1
        if a["sync"] == "Synced" and h == "healthy":
            out["ok"] += 1
    return out


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = apps(conn, refresh=True)
    except GitOpsError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    if not got:
        return True, "connected — no applications visible to this account yet"
    s = summarise(got)
    bits = [f"connected — {s['total']} application(s)"]
    if s["outofsync"]:
        bits.append(f"{s['outofsync']} out of sync")
    if s["degraded"]:
        bits.append(f"{s['degraded']} not healthy")
    if not s["outofsync"] and not s["degraded"]:
        bits.append("all synced and healthy")
    return True, ", ".join(bits)


# ── one resource, the way the tree's nodes deserve ─────────────────────────
# WHY THIS IS HERE AND NOT A LINK OUT
#     A tree you cannot open is a picture. The question after "which resource
#     is unhealthy" is always one of three: what does it actually look like,
#     what has happened to it, and — if it is a pod — what is it saying. Argo
#     CD answers all three; the portal was drawing the tree and then sending
#     people to Argo CD to ask.
#
# WHAT IS DIFFERENT HERE
#     Argo CD opens a panel with four tabs, all of them empty until clicked,
#     always starting on the same one. What you want first depends on the
#     resource: a pod that is crash-looping means logs, something OutOfSync
#     means the diff, and anything else means the manifest. So the useful tab
#     is chosen rather than defaulted to, and the events come with the summary
#     instead of hiding behind a click of their own.
LOG_LINES = 400


def _yaml(doc) -> str:
    """A manifest as YAML. Argo hands over JSON, which is the same information
    and materially harder to read."""
    if not isinstance(doc, (dict, list)):
        return str(doc or "")
    try:
        import io as _io
        from ruamel.yaml import YAML
        y = YAML()
        y.default_flow_style = False
        y.width = 200
        buf = _io.StringIO()
        y.dump(doc, buf)
        return buf.getvalue()
    except Exception:                                          # noqa: BLE001
        return json.dumps(doc, indent=2, sort_keys=True)


def _strip_noise(doc: dict) -> dict:
    """Drop what Kubernetes adds and nobody reads.

    managedFields alone is routinely longer than the object it is attached to
    and says nothing about what the object is.
    """
    if not isinstance(doc, dict):
        return doc
    meta = doc.get("metadata")
    if isinstance(meta, dict):
        for k in ("managedFields", "generation", "resourceVersion",
                  "selfLink", "creationTimestamp"):
            meta.pop(k, None)
        ann = meta.get("annotations")
        if isinstance(ann, dict):
            ann.pop("kubectl.kubernetes.io/last-applied-configuration", None)
            if not ann:
                meta.pop("annotations", None)
    return doc


def resource(conn: dict, app_name: str, node: dict, want: str = "") -> dict:
    """Everything worth showing about one node of the tree.

    `node` is what tree() produced — kind, name, namespace, group, version.
    Nothing here is cached: a manifest read from a page is being read because
    somebody suspects it changed.
    """
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD resources can be opened here")
    kind = node.get("kind", "")
    ns = node.get("namespace", "")
    name = node.get("name", "")
    out = {"kind": kind, "name": name, "namespace": ns, "tab": want,
           "group": node.get("group", ""), "version": node.get("version", ""),
           "manifest": "", "diff": "", "difftext": "", "events": [], "log": "",
           "containers": [], "container": "", "note": "", "synced": True}

    q = urllib.parse.urlencode({
        "appNamespace": "", "namespace": ns, "resourceName": name,
        "version": node.get("version") or "v1", "kind": kind,
        "group": node.get("group") or ""})

    # The live object, git's desire and the event history are three independent
    # questions to the same far-away Argo — asked TOGETHER. One after another
    # was most of why opening a resource felt slow.
    live = {}

    def _get_live():
        got = _argo(conn, f"/applications/{_esc(app_name)}/resource?{q}")
        raw = got.get("manifest") if isinstance(got, dict) else None
        return json.loads(raw) if isinstance(raw, str) else (raw or {})

    def _get_target():
        return _argo(conn, f"/applications/{_esc(app_name)}/managed-resources"
                           f"?namespace={urllib.parse.quote(ns)}"
                           f"&resourceName={urllib.parse.quote(name)}")

    def _get_events():
        return _argo(
            conn,
            f"/applications/{_esc(app_name)}/events"
            f"?resourceUID={urllib.parse.quote(node.get('uid') or '')}"
            f"&resourceNamespace={urllib.parse.quote(ns)}"
            f"&resourceName={urllib.parse.quote(name)}")

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_live = pool.submit(_get_live)
        f_target = pool.submit(_get_target)
        f_events = pool.submit(_get_events)

    try:
        live = f_live.result()
        out["manifest"] = _yaml(_strip_noise(live))
    except GitOpsError as e:
        out["note"] = str(e)
    except (json.JSONDecodeError, TypeError):
        out["note"] = "Argo CD returned a manifest that could not be read"

    # what git wants, and how it differs — only meaningful for a managed object
    try:
        doc = f_target.result()
        for item in (doc.get("items") or []):
            if item.get("kind") != kind or item.get("name") != name:
                continue
            target = item.get("targetState")
            if isinstance(target, str) and target.strip():
                try:
                    out["diff"] = _yaml(_strip_noise(json.loads(target)))
                except json.JSONDecodeError:
                    out["diff"] = target
            out["synced"] = not item.get("diff")
            break
    except GitOpsError:
        pass                    # a resource git does not manage has no target

    # what has happened to it
    try:
        ev = f_events.result()
        rows = []
        for e in (ev.get("items") or []):
            rows.append({
                "type": e.get("type", ""),
                "reason": e.get("reason", ""),
                "message": (e.get("message") or "")[:400],
                "count": e.get("count") or 1,
                "at": (e.get("lastTimestamp") or e.get("eventTime")
                       or "")[:19].replace("T", " "),
                "from": ((e.get("source") or {}).get("component") or ""),
            })
        rows.sort(key=lambda r: r["at"], reverse=True)
        # a warning is why you opened this, so it goes first whatever its age
        rows.sort(key=lambda r: r["type"] != "Warning")
        out["events"] = rows[:40]
    except GitOpsError:
        pass


    # the actual DIFF, not two documents to eyeball: git's normalised desire on
    # the left, the cluster's normalised reality on the right. Both sides went
    # through _strip_noise, so what remains differing is what actually differs.
    if out["manifest"] and out["diff"] and out["manifest"] != out["diff"]:
        out["difftext"] = "\n".join(difflib.unified_diff(
            out["diff"].splitlines(), out["manifest"].splitlines(),
            fromfile="git (desired)", tofile="cluster (live)", lineterm=""))

    # what has happened to it
    try:
        ev = _argo(conn, f"/applications/{_esc(app_name)}/events"
                         f"?resourceUID={urllib.parse.quote(node.get('uid') or '')}"
                         f"&resourceNamespace={urllib.parse.quote(ns)}"
                         f"&resourceName={urllib.parse.quote(name)}")
        rows = []
        for e in (ev.get("items") or []):
            rows.append({
                "type": e.get("type", ""),
                "reason": e.get("reason", ""),
                "message": (e.get("message") or "")[:400],
                "count": e.get("count") or 1,
                "at": (e.get("lastTimestamp") or e.get("eventTime")
                       or "")[:19].replace("T", " "),
                "from": ((e.get("source") or {}).get("component") or ""),
            })
        rows.sort(key=lambda r: r["at"], reverse=True)
        # a warning is why you opened this, so it goes first whatever its age
        rows.sort(key=lambda r: r["type"] != "Warning")
        out["events"] = rows[:40]
    except GitOpsError:
        pass

    # what Argo's SUMMARY tab shows: the facts, before any manifest
    meta = (live.get("metadata") or {}) if isinstance(live, dict) else {}
    lspec = (live.get("spec") or {}) if isinstance(live, dict) else {}
    lstat = (live.get("status") or {}) if isinstance(live, dict) else {}
    out["created"] = (meta.get("creationTimestamp") or "")[:19].replace("T", " ")
    out["uid_live"] = meta.get("uid", "")
    out["labels"] = {k: str(v) for k, v in (meta.get("labels") or {}).items()}
    out["images_live"] = [c.get("image", "") for c in
                          ((lspec.get("template") or {}).get("spec")
                           or lspec).get("containers", []) or []
                          if c.get("image")]
    out["svc_type"] = lspec.get("type", "") if kind == "Service" else ""
    out["hostnames"] = [i.get("hostname") or i.get("ip") or "" for i in
                        ((lstat.get("loadBalancer") or {}).get("ingress") or [])]
    out["node"] = lspec.get("nodeName", "") if kind == "Pod" else ""
    out["replicas"] = (f"{(lstat.get('readyReplicas') or 0)}"
                       f"/{(lspec.get('replicas') or 0)}"
                       if "replicas" in lspec else "")

    if kind == "Pod":
        spec = (live.get("spec") or {}) if isinstance(live, dict) else {}
        names = [c.get("name") for c in (spec.get("containers") or [])
                 if c.get("name")]
        out["containers"] = names
        # the container that is unhappy, not the first one declared: on a pod
        # with a sidecar the first is usually the one that is fine
        statuses = ((live.get("status") or {}).get("containerStatuses") or [])
        bad = next((c.get("name") for c in statuses
                    if not c.get("ready") or (c.get("restartCount") or 0) > 0), "")
        out["container"] = (node.get("container") or bad or
                            (names[0] if names else ""))
        try:
            out["log"] = pod_log(conn, app_name, name, ns, out["container"])
        except GitOpsError as e:
            out["log"] = ""
            out["note"] = out["note"] or str(e)

    if not want:
        # the tab worth opening on, per resource, rather than always the same
        out["tab"] = ("logs" if kind == "Pod" and out["log"]
                      else "diff" if not out["synced"] and out["diff"]
                      else "manifest")
    return out


def pod_log(conn: dict, app_name: str, pod: str, namespace: str,
            container: str = "", lines: int = LOG_LINES) -> str:
    """A pod's output, through Argo CD rather than through the cluster.

    Argo already has the credentials and the RBAC for it, so this needs no
    kubeconfig and obeys whatever the Argo account is allowed to see.
    """
    q = urllib.parse.urlencode({
        "namespace": namespace, "container": container,
        "tailLines": str(lines), "follow": "false"})
    tok = _argo_token(conn)
    url = (f"{conn['base_url'].rstrip('/')}/api/v1/applications/"
           f"{_esc(app_name)}/pods/{_esc(pod)}/logs?{q}")
    req = urllib.request.Request(
        urlguard.check(url),
        headers={"Authorization": f"Bearer {tok}", "Accept": "*/*"})
    ctx = _INSECURE if conn.get("skip_tls") else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT * 2, context=ctx) as r:
            raw = r.read(600_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise GitOpsError("Argo CD will not show this pod's log to that "
                              "account") from e
        raise GitOpsError(f"HTTP {e.code} reading the pod log") from e
    except Exception as e:                                     # noqa: BLE001
        raise GitOpsError(f"{type(e).__name__}: {e}"[:160]) from e
    # a stream of one JSON object per line, each holding a line of the log
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            out.append(line)
            continue
        res = doc.get("result") if isinstance(doc, dict) else None
        if isinstance(res, dict) and res.get("content") is not None:
            out.append(str(res["content"]))
        elif isinstance(doc, dict) and doc.get("content") is not None:
            out.append(str(doc["content"]))
    return "\n".join(out)


def find_node(resources: dict, uid: str) -> dict | None:
    """The node the page is asking about, out of the tree it already drew."""
    def walk(nodes):
        for n in nodes:
            if n.get("uid") == uid:
                return n
            got = walk(n.get("children") or [])
            if got:
                return got
        return None
    return walk(resources.get("roots") or [])


def find_by_ref(resources: dict, kind: str, name: str, namespace: str = "",
                group: str = "", version: str = "") -> dict:
    """The tree node matching a kind/name/namespace reference — or a pseudo-node
    when the tree no longer holds it. The sync-result table lists what an
    operation TOUCHED, which includes objects since pruned or replaced; their
    buttons must still open something rather than 404."""
    def walk(nodes):
        for n in nodes:
            if (n.get("kind") == kind and n.get("name") == name
                    and (n.get("namespace") or "") == (namespace or "")):
                return n
            got = walk(n.get("children") or [])
            if got:
                return got
        return None
    got = walk(resources.get("roots") or [])
    return got or {"uid": "", "kind": kind, "name": name,
                   "namespace": namespace or "", "group": group or "",
                   "version": version or "v1", "children": []}


def set_sync_policy(conn: dict, name: str, automated: bool, prune: bool,
                    self_heal: bool) -> str:
    """Turn an application's automated sync on or off, through Argo CD.

    A merge patch on the application's own spec — the same call Argo CD's own
    "Enable auto-sync" makes. `automated=False` sends null rather than an empty
    object, because an empty `automated: {}` is still automated to the
    controller: it would read as auto-sync ON with prune and self-heal off,
    which is the opposite of what somebody clicking "disable" means.
    """
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications can be changed here")
    policy = ({"automated": {"prune": bool(prune), "selfHeal": bool(self_heal)}}
              if automated else {"automated": None})
    body = {"name": name, "patchType": "merge",
            "patch": json.dumps({"spec": {"syncPolicy": policy}})}
    _argo(conn, f"/applications/{_esc(name)}", body=body, method="PATCH")
    drop(conn, name)
    invalidate()
    if not automated:
        return "auto-sync disabled — nothing will apply until somebody syncs"
    bits = [b for b, on in (("prune", prune), ("self-heal", self_heal)) if on]
    return "auto-sync enabled" + (" with " + " and ".join(bits) if bits else "")


# ── Argo CD's own settings: repositories, clusters, projects ────
# Reading these is what makes the applications list usable ("which repo is that
# app on, and does Argo even have credentials for it"); adding a repository is
# the one write, because it is the step that blocks a new application from
# syncing at all and the only place it can be done today is Argo's own UI.
def repos(conn: dict) -> list[dict]:
    """Every repository Argo CD holds credentials for, with its state."""
    doc = _argo(conn, "/repositories")
    out = []
    for r in doc.get("items") or []:
        out.append({
            "url": r.get("repo", ""), "name": r.get("name", ""),
            "type": r.get("type", "git"), "project": r.get("project", ""),
            "username": r.get("username", ""),
            "insecure": bool(r.get("insecure")),
            "state": (r.get("connectionState") or {}).get("status", ""),
            "why": (r.get("connectionState") or {}).get("message", "")[:200],
        })
    return sorted(out, key=lambda r: r["url"])


def add_repo(conn: dict, url: str, username: str = "", password: str = "",
             name: str = "", project: str = "", insecure: bool = False) -> str:
    """Register a repository with Argo CD.

    Argo validates the credentials as part of the call, so a wrong password
    comes back as a refusal here rather than as a mystery on the first sync.
    """
    url = (url or "").strip()
    if not url:
        raise GitOpsError("a repository URL is required")
    if url.startswith(("http://", "https://")):
        # re-raised as this module's own error so the route has one thing to
        # catch: a BlockedURL escaping would have been a 500 on a bad address,
        # which is the one case a guard exists to answer politely
        try:
            urlguard.check(url)
        except urlguard.BlockedURL as e:
            raise GitOpsError(f"that address is refused: {e}") from e
    body = {"repo": url, "insecure": bool(insecure)}
    for key, val in (("name", name), ("project", project),
                     ("username", username), ("password", password)):
        if (val or "").strip():
            body[key] = val.strip() if key != "password" else val
    _argo(conn, "/repositories", body=body)
    _cache.pop(_ckey(conn, "repos", ""), None)
    return f"{url} registered"


def remove_repo(conn: dict, url: str) -> str:
    """Drop a repository's credentials. Applications on it stop syncing, which
    is why the page asks for the URL to be typed."""
    if not (url or "").strip():
        raise GitOpsError("which repository?")
    _argo(conn, f"/repositories/{urllib.parse.quote(url, safe='')}",
          method="DELETE")
    _cache.pop(_ckey(conn, "repos", ""), None)
    return f"{url} removed"


def argo_clusters(conn: dict) -> list[dict]:
    """The clusters Argo CD can deploy to — its own list, not the portal's."""
    doc = _argo(conn, "/clusters")
    out = []
    for c in doc.get("items") or []:
        info = c.get("info") or {}
        out.append({
            "server": c.get("server", ""), "name": c.get("name", ""),
            "state": (info.get("connectionState") or {}).get("status", ""),
            "why": (info.get("connectionState") or {}).get("message", "")[:200],
            "version": info.get("serverVersion", ""),
            "apps": (info.get("applicationsCount") or 0),
        })
    return sorted(out, key=lambda c: c["name"] or c["server"])


def argo_projects(conn: dict) -> list[dict]:
    """Argo CD's AppProjects — the real ones, with what each permits."""
    doc = _argo(conn, "/projects")
    out = []
    for p in doc.get("items") or []:
        meta, spec = p.get("metadata") or {}, p.get("spec") or {}
        out.append({
            "name": meta.get("name", ""),
            "description": (spec.get("description") or "")[:200],
            "repos": list(spec.get("sourceRepos") or []),
            "destinations": [f"{d.get('server', d.get('name', ''))}"
                             f"/{d.get('namespace', '')}".strip("/")
                             for d in (spec.get("destinations") or [])],
        })
    return sorted(out, key=lambda p: p["name"])


def settings_view(conn: dict) -> dict:
    """Repositories, clusters and projects together — one SWR entry, because
    the rail that shows them is drawn on every applications list."""
    def produce():
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_r = pool.submit(repos, conn)
            f_c = pool.submit(argo_clusters, conn)
            f_p = pool.submit(argo_projects, conn)
            out = {}
            for key, fut in (("repos", f_r), ("clusters", f_c),
                             ("projects", f_p)):
                try:
                    out[key] = fut.result()
                except GitOpsError as e:
                    # one endpoint a token cannot reach must not blank the rail
                    out[key] = []
                    out[key + "_error"] = str(e)[:200]
            return out
    return _swr(_ckey(conn, "settings", ""), 60, produce)


def patch_resource(conn: dict, app_name: str, node: dict, text: str) -> str:
    """Apply an edited manifest to the live object, THROUGH Argo CD.

    A merge patch of exactly what the editor holds — the same call Argo CD's
    own Edit uses — so the change lands with the controller's identity and
    RBAC, not a kubeconfig this portal holds; and Argo sees its own write
    (an app with selfHeal will sync a drifting edit straight back, which is
    the honest behaviour, not a bug). The kind and name must match the node
    that was opened: an editor that can silently retarget is a footgun."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD resources can be edited here")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise GitOpsError(f"that is not valid YAML: {str(e)[:160]}") from e
    if not isinstance(doc, dict):
        raise GitOpsError("the editor must hold one YAML object")
    if ((doc.get("kind") or "") != node.get("kind")
            or ((doc.get("metadata") or {}).get("name") or "") != node.get("name")):
        raise GitOpsError("the manifest's kind and metadata.name must match "
                          "the resource being edited")
    api = str(doc.get("apiVersion") or "")
    q = urllib.parse.urlencode({
        "namespace": node.get("namespace") or "",
        "resourceName": node.get("name") or "",
        "version": node.get("version")
                   or (api.split("/")[-1] if api else "v1"),
        "kind": node.get("kind") or "",
        "group": node.get("group")
                 or (api.split("/")[0] if "/" in api else ""),
        "patchType": "application/merge-patch+json"})
    # the body is the patch AS A JSON STRING — _req json-encodes whatever it is
    # given, and Argo's API wants the patch double-encoded exactly so
    _argo(conn, f"/applications/{_esc(app_name)}/resource?{q}",
          body=json.dumps(doc), method="PATCH")
    return f"{node.get('kind')}/{node.get('name')} patched"


def _node_q(node: dict) -> str:
    """The query every per-resource Argo endpoint wants."""
    return urllib.parse.urlencode({
        "namespace": node.get("namespace") or "",
        "resourceName": node.get("name") or "",
        "version": node.get("version") or "v1",
        "kind": node.get("kind") or "",
        "group": node.get("group") or ""})


def resource_actions(conn: dict, app_name: str, node: dict) -> list[dict]:
    """What Argo CD can DO to this object, straight from the controller — a
    Deployment offers restart, a CronJob suspend/resume, a Rollout its promote
    and abort. These are Lua actions the controller ships and an operator can
    extend, so they are read rather than hardcoded here: a portal with a fixed
    list would be wrong the day somebody adds one."""
    if conn.get("type") != "argocd":
        return []

    def produce():
        got = _argo(conn, f"/applications/{_esc(app_name)}/resource/actions"
                          f"?{_node_q(node)}")
        return [{"name": a.get("name", ""),
                 "label": a.get("displayName") or a.get("name", ""),
                 "disabled": bool(a.get("disabled"))}
                for a in (got.get("actions") or []) if a.get("name")]
    try:
        return _swr(_ckey(conn, "actions", app_name, node.get("uid")
                          or node.get("name")), 20.0, produce)
    except GitOpsError:
        return []               # an Argo too old to offer them is not an error


def run_action(conn: dict, app_name: str, node: dict, action: str) -> str:
    """Run one of them. The body is the action NAME as a JSON string, which is
    what this endpoint takes — not an object."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD resources have actions")
    if not action:
        raise GitOpsError("no action was named")
    _argo(conn, f"/applications/{_esc(app_name)}/resource/actions"
                f"?{_node_q(node)}", body=str(action))
    drop(conn, app_name)
    return f"{action} run on {node.get('kind')}/{node.get('name')}"


def delete_resource(conn: dict, app_name: str, node: dict,
                    force: bool = False, orphan: bool = False) -> str:
    """Delete one object from the cluster.

    `orphan` leaves the children behind (Kubernetes' orphan cascade), `force`
    skips the graceful period. Both off by default: a delete is already the
    sharpest thing on this page.
    """
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD resources can be deleted from here")
    q = _node_q(node) + f"&force={'true' if force else 'false'}" \
                        f"&orphan={'true' if orphan else 'false'}"
    _argo(conn, f"/applications/{_esc(app_name)}/resource?{q}", method="DELETE")
    drop(conn, app_name)
    return (f"{node.get('kind')}/{node.get('name')} deleted"
            + (" (children orphaned)" if orphan else ""))


def rollback(conn: dict, name: str, hid, prune: bool = False,
             dry_run: bool = False) -> str:
    """Deploy a revision this application has already run.

    Argo rolls back by history id, not by revision string — the id is what its
    own history list carries, and two entries can share a revision.
    """
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications can be rolled back")
    try:
        hid = int(hid)
    except (TypeError, ValueError) as e:
        raise GitOpsError("that is not a history id") from e
    _argo(conn, f"/applications/{_esc(name)}/rollback",
          body={"name": name, "id": hid, "prune": bool(prune),
                "dryRun": bool(dry_run)})
    drop(conn, name)
    invalidate()
    return f"rollback to history #{hid} started"


def terminate(conn: dict, name: str) -> str:
    """Stop the operation that is running. Argo has no 'pause' — the sync stops
    where it is, and what it already applied stays applied, which is why this
    says so rather than implying a rewind."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD operations can be terminated")
    _argo(conn, f"/applications/{_esc(name)}/operation", method="DELETE")
    drop(conn, name)
    invalidate()
    return ("termination requested — whatever had already been applied stays "
            "applied")


def delete_app(conn: dict, name: str, cascade: bool = True) -> str:
    """Delete the application. `cascade` also deletes everything it deployed —
    which is what Argo CD's own dialog defaults to, and the reason this needs
    the sharpest confirmation on the page."""
    if conn.get("type") != "argocd":
        raise GitOpsError("only Argo CD applications can be deleted from here")
    _argo(conn, f"/applications/{_esc(name)}"
                f"?cascade={'true' if cascade else 'false'}", method="DELETE")
    invalidate()
    return (f"{name} deleted"
            + (" with everything it deployed" if cascade
               else " — its objects were left running"))


def app_diff(conn: dict, name: str) -> dict:
    """Every difference between git and the cluster, in one read.

    Argo CD's own UI makes you open resources one at a time to answer "what
    would this sync change" — the question anybody asks BEFORE syncing. One
    managed-resources call carries the target and live state of everything, so
    the whole answer is one round-trip and one page.
    """
    if conn.get("type") != "argocd":
        return {"rows": [], "count": 0}

    def produce():
        doc = _argo(conn, f"/applications/{_esc(name)}/managed-resources")
        rows = []
        for item in (doc.get("items") or []):
            if not item.get("diff") and item.get("liveState") \
                    and item.get("targetState"):
                continue
            def side(raw):
                if not raw:
                    return ""
                try:
                    return _yaml(_strip_noise(json.loads(raw)))
                except (json.JSONDecodeError, TypeError):
                    return str(raw)
            live, target = side(item.get("liveState")), side(item.get("targetState"))
            if live == target:
                continue
            kind = item.get("kind", "")
            rname = item.get("name", "")
            body = "\n".join(difflib.unified_diff(
                target.splitlines(), live.splitlines(),
                fromfile="git (desired)", tofile="cluster (live)", lineterm=""))
            rows.append({
                "kind": kind, "name": rname,
                "namespace": item.get("namespace", ""),
                "group": item.get("group", ""),
                "version": item.get("version", "") or "v1",
                # a target with no live object is about to be CREATED, and a
                # live one with no target is what prune would remove — naming
                # which is the whole point of reading a diff before syncing
                "state": ("missing" if not live else
                          "extra" if not target else "changed"),
                "added": sum(1 for l in body.splitlines()
                             if l.startswith("+") and not l.startswith("+++")),
                "removed": sum(1 for l in body.splitlines()
                               if l.startswith("-") and not l.startswith("---")),
                "diff": body,
            })
        rows.sort(key=lambda r: (r["state"] != "missing", r["kind"], r["name"]))
        return {"rows": rows, "count": len(rows)}
    return _swr(_ckey(conn, "diff", name), 15.0, produce)


def app_events(conn: dict, name: str) -> list[dict]:
    """What Kubernetes has recorded about the application object itself —
    Argo's own sync/health events, which the per-resource view cannot show."""
    if conn.get("type") != "argocd":
        return []

    def produce():
        got = _argo(conn, f"/applications/{_esc(name)}/events")
        rows = [{"type": e.get("type", ""), "reason": e.get("reason", ""),
                 "message": (e.get("message") or "")[:400],
                 "count": e.get("count") or 1,
                 "at": (e.get("lastTimestamp") or e.get("eventTime")
                        or "")[:19].replace("T", " ")}
                for e in (got.get("items") or [])]
        rows.sort(key=lambda r: r["at"], reverse=True)
        rows.sort(key=lambda r: r["type"] != "Warning")
        return rows[:40]
    try:
        return _swr(_ckey(conn, "events", name), 20.0, produce)
    except GitOpsError:
        return []


# ── the tree as a drawing ──────────────────────────────────────────────────
# WHY A DRAWING AND NOT A LIST
#     An indented list carries the same parent/child information and is easier
#     to build, which is why the first two attempts at this were one. It is not
#     what anybody means by a resource tree: you cannot see at a glance that one
#     Deployment fans out to four ReplicaSets while another has one, and a
#     failing pod three levels in reads as just another indented row.
#
#     So: columns by depth, boxes joined by elbows, laid out here rather than in
#     the template because the arithmetic is real and a template full of it is
#     unreadable and untestable.
GBOX_W, GBOX_H = 268, 68
GCOL_GAP, GROW_GAP = 80, 18
GPAD = 18


# Which family a kind belongs to — the diagram colours by this, so a reader
# navigates by hue before reading a word. Anything unlisted is "other" and
# takes the neutral colour rather than an invented one.
def _age(iso: str) -> str:
    """How old, in the shortest form that is still true — what Argo prints on
    every box. Empty when the timestamp is missing rather than a guessed "0s"."""
    if not iso:
        return ""
    try:
        born = datetime.fromisoformat(str(iso)[:19].replace(" ", "T"))
    except ValueError:
        return ""
    secs = (datetime.now(timezone.utc).replace(tzinfo=None) - born).total_seconds()
    if secs < 0:
        return ""
    for cut, unit, div in ((90, "s", 1), (5400, "m", 60),
                           (172800, "h", 3600), (10 ** 9, "d", 86400)):
        if secs < cut:
            return f"{int(secs // div)}{unit}"
    return ""


KIND_FAMILY = {
    "Deployment": "workload", "StatefulSet": "workload", "DaemonSet": "workload",
    "ReplicaSet": "replica", "Pod": "pod", "Job": "job", "CronJob": "job",
    "Rollout": "workload",
    "Service": "network", "Ingress": "network", "IngressRoute": "network",
    "Endpoints": "network", "EndpointSlice": "network", "Route": "network",
    "ConfigMap": "config", "Secret": "secret", "SealedSecret": "secret",
    "ServiceAccount": "rbac", "Role": "rbac", "RoleBinding": "rbac",
    "ClusterRole": "rbac", "ClusterRoleBinding": "rbac",
    "PersistentVolumeClaim": "storage", "PersistentVolume": "storage",
    "Cluster": "data", "Database": "data", "Pooler": "data",
    "HorizontalPodAutoscaler": "scale", "PodDisruptionBudget": "scale",
    "Certificate": "cert", "Issuer": "cert", "ClusterIssuer": "cert",
    "Namespace": "scope", "Application": "scope",
}

# The line icon each family wears on the diagram. Names from logos.GLYPHS —
# a box is recognised by its mark before its text at any zoom, which is the
# whole reason Argo's own nodes carry one.
FAMILY_ICON = {
    "workload": "rocket", "replica": "layers", "pod": "hexagon",
    "job": "hourglass", "network": "globe", "config": "settings",
    "secret": "lock", "rbac": "user-cog", "storage": "hard-drive",
    "data": "database", "scale": "chart-line", "cert": "shield-check",
    "scope": "package", "other": "boxes",
}

# Kinds Argo's own `restart` action applies to — the diagram offers it directly
# on those and nothing else, rather than a menu item that always fails.
RESTARTABLE = {"Deployment", "StatefulSet", "DaemonSet", "Rollout"}


def graph(resources: dict, app_name: str = "", app_health: str = "",
          app_sync: str = "") -> dict:
    """Positions for every node and the elbows between them.

    Laid out the way a tidy tree is: leaves take the next free row, and a
    parent sits at the average of its children, so a branch is centred against
    what it contains rather than pinned to its first child.

    `app_name` puts the APPLICATION itself at the root, with an arrow to every
    top-level object — which is how Argo CD draws it, and the thing a tree of
    four unconnected roots was missing: the map now says what it is a map OF.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    row = [0]                       # next free row, shared across the walk

    def place(n: dict, depth: int) -> dict:
        kids = n.get("children") or []
        if not kids:
            y = row[0]
            row[0] += 1
        else:
            placed = [place(k, depth + 1) for k in kids]
            y = sum(p["row"] for p in placed) / len(placed)
        me = {
            "uid": n.get("uid", ""), "kind": n.get("kind", ""),
            "name": n.get("name", ""), "namespace": n.get("namespace", ""),
            "health": n.get("health", ""), "info": (n.get("info") or [])[:1],
            "sync": n.get("sync", ""), "group": n.get("group", ""),
            "age": n.get("age", ""),
            "version": n.get("version", "") or "v1",
            "phase": n.get("phase", ""), "ready": n.get("ready", ""),
            # Argo reports a pod with a deletion timestamp as Terminating; that
            # is the half of a rolling update the reader is watching for, so it
            # is a state of its own on the box rather than a word in a tooltip
            "terminating": n.get("phase", "").lower().startswith("terminat"),
            "chips": (n.get("chips") or [])[:2],
            # the family a kind belongs to, for its colour on the diagram: a
            # reader scanning ninety boxes navigates by shape and hue long
            # before they read a word
            "family": KIND_FAMILY.get(n.get("kind", ""), "other"),
            "icon": FAMILY_ICON.get(
                KIND_FAMILY.get(n.get("kind", ""), "other"), "boxes"),
            "restartable": (n.get("kind", "") in RESTARTABLE
                            and n.get("uid", "") != "__app__"),
            "is_app": n.get("uid", "") == "__app__",
            "depth": depth, "row": y,
            "x": GPAD + depth * (GBOX_W + GCOL_GAP),
            "y": GPAD + y * (GBOX_H + GROW_GAP),
        }
        nodes.append(me)
        by_uid = {x["uid"]: x for x in nodes}
        for k in kids:
            child = by_uid.get(k.get("uid"))
            if not child:
                continue
            edges.append({
                "x1": me["x"] + GBOX_W, "y1": me["y"] + GBOX_H / 2,
                "x2": child["x"], "y2": child["y"] + GBOX_H / 2,
            })
        return me

    roots = resources.get("roots") or []
    if app_name and roots:
        # one synthetic root, so everything hangs off the application
        place({"uid": "__app__", "kind": "Application", "name": app_name,
               "namespace": "", "health": app_health, "sync": app_sync,
               "children": roots}, 0)
    else:
        for root in roots:
            place(root, 0)

    if not nodes:
        return {"nodes": [], "edges": [], "width": 0, "height": 0}
    width = max(n["x"] for n in nodes) + GBOX_W + GPAD
    height = max(n["y"] for n in nodes) + GBOX_H + GPAD
    # drawn parents first so an elbow never crosses over a box it leads to
    nodes.sort(key=lambda n: (n["depth"], n["row"]))
    return {"nodes": nodes, "edges": edges,
            "width": round(width), "height": round(height),
            "box_w": GBOX_W, "box_h": GBOX_H,
            "families": sorted({n["family"] for n in nodes})}
