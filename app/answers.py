"""Real answers to real questions, by querying the estate rather than describing it.

WHY THIS REPLACED "PUT A SUMMARY IN THE PROMPT"
    The first version of the assistant pasted a description of the estate into
    the model's system prompt and hoped. Ask it "which pods are running on the ZA
    preprod cluster" and it answered politely that it could not find that — correctly,
    because a summary of counts contains no pods. No larger model fixes that: the
    data was never there.

    So the assistant now *asks the portal*. Every question is matched to a query
    in the catalogue below, the query runs against live state, and the answer is
    the result — a real table, with a count, and a note saying which query ran.
    The model's job shrinks to two things it is genuinely good at: working out
    which query someone meant, and writing a sentence about the rows. It never
    has to hold the estate in its head.

WHAT THIS BUYS
    * Correctness. The numbers come from kubectl and the database, so they are
      right or they are an error — never plausible fiction.
    * It works with no GPU. The model sees a short question and a compact result,
      not a two-thousand-token dump, so prompt processing — the expensive part on
      a CPU — is small. A 3B model on a few cores is enough.
    * It works with no model at all. The matcher is ordinary code: keywords,
      live entity names, a score. With nothing configured the portal still
      answers; it just does not write prose around the table.
    * It is auditable. Every answer says which query ran with which arguments,
      so a wrong answer is a bug someone can find rather than a mystery.

ADDING A QUERY
    One entry in CATALOGUE: what it is called, the words that suggest it, which
    permission area governs it, and a function returning columns and rows. The
    matcher, the API, the table rendering and the model's tool list all read
    from that one place.
"""
import difflib
import re

# ── the vocabulary that resolves an entity in a question ───────
STOP = {"the", "a", "an", "in", "on", "of", "for", "is", "are", "what", "which",
        "show", "me", "list", "all", "and", "or", "to", "do", "does", "have",
        "has", "how", "many", "much", "there", "any", "please", "can", "you",
        "give", "tell", "about", "with", "that", "this", "it", "at", "from",
        "right", "now", "currently", "today"}


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9.:_-]+", (text or "").lower()) if w]


def close(word: str, candidates, cutoff: float = 0.76) -> str:
    """The candidate a misspelling most likely meant, or "".

    Typing is part of asking: "traefic", "ledgr dev", "clsuters" and "atention"
    are the same questions as their correct spellings, and a tool that answers
    only exact spellings makes the person adapt to it. Everything matched here
    comes from live data or the catalogue, so the vocabulary follows the estate.
    """
    if not word or not candidates:
        return ""
    hit = difflib.get_close_matches(word, list(candidates), n=1, cutoff=cutoff)
    return hit[0] if hit else ""


def cluster_index() -> dict:
    """Every way someone might name a cluster → its id.

    Built from live state, so "eu preprod", "eu-preprod", "payments eu" and the
    cluster's own name all land on the same cluster, and a cluster added a minute
    ago is addressable immediately.
    """
    from . import store
    out: dict = {}

    def add(key: str, cid: str):
        key = " ".join(_words(key))
        if key and key not in STOP:
            out.setdefault(key, cid)

    for pid, p in store.projects().items():
        pname = p.get("name", "")
        for cid, c in (p.get("clusters") or {}).items():
            name = c.get("name", cid)
            add(name, cid)
            add(name.replace("-", " "), cid)
            add(f"{pname} {name}", cid)
        for rgid, rg in (p.get("regions") or {}).items():
            rname = rg.get("name", "")
            for env, cid in (rg.get("env_clusters") or {}).items():
                if not cid:
                    continue
                add(f"{rname} {env}", cid)
                add(f"{env} {rname}", cid)
                add(f"{pname} {rname} {env}", cid)
                add(f"{pname} {env}", cid)
    return out


def find_cluster(question: str) -> tuple[str, str]:
    """(cluster id, the phrase that matched) — longest match wins, so "za
    preprod" beats "preprod" when both are present. Falls back to the nearest
    spelling, so "ledgr dev" finds the same cluster as "ledger dev"."""
    idx = cluster_index()
    words = _words(question)
    for n in (4, 3, 2, 1):
        for i in range(len(words) - n + 1):
            phrase = " ".join(words[i:i + n])
            if phrase in idx:
                return idx[phrase], phrase
    # nothing matched exactly; try the nearest spelling, longest phrases first
    for n in (3, 2, 1):
        for i in range(len(words) - n + 1):
            phrase = " ".join(words[i:i + n])
            if len(phrase) < 4:
                continue
            near = close(phrase, idx.keys())
            if near:
                return idx[near], near
    return "", ""


def _cluster_records(user, only: str = "") -> list:
    """The clusters this person may see, as records the reader functions want."""
    from . import rbac, store
    allowed = rbac.visible_clusters(user)
    out = []
    for pid, p in store.projects().items():
        for cid, c in (p.get("clusters") or {}).items():
            if only and cid != only:
                continue
            if allowed is not None and cid not in allowed:
                continue
            out.append({**c, "id": cid, "_pid": pid,
                        "_project": p.get("name", pid)})
    return out


def _flag(question: str, *words) -> bool:
    """Whether the question asks for the narrowed version of a query.

    "not" only counts when it precedes a health word — "not ready", "not
    healthy", "not running". On its own it appears in plenty of sentences that
    mean the opposite of a filter, and treating it as one silently dropped rows.
    """
    got = _words(question)
    have = set(got)
    for w in words:
        if w == "not":
            for i, token in enumerate(got):
                if token == "not" and i + 1 < len(got) and got[i + 1] in (
                        "ready", "healthy", "running", "synced", "working",
                        "reachable", "up", "ok", "good"):
                    return True
        elif w in have:
            return True
    return False


def _flagged(question: str, *words) -> list:
    """Which of these words the question actually used.

    _flag answers yes/no, which is all a query needs to narrow itself — but the
    generic value filter downstream then sees the SAME word still sitting in the
    question and applies it a second time, as a literal match against a column.
    "which clusters are unreachable" narrowed correctly here and was then
    emptied there, because the reachable column says yes and no rather than
    reachable and unreachable. A query reports what it consumed so nothing
    consumes it twice.
    """
    have = set(_words(question))
    return [w for w in words if w in have]


# ── the queries ────────────────────────────────────────────────
def q_pods(user, question: str, cid: str, focus: str = "") -> dict:
    from . import cluster as clusterview
    from . import fleet
    bad_only = _flag(question, "unhealthy", "failing", "failed", "problem",
                     "problems", "broken", "crash", "crashloop", "attention",
                     "restarting", "pending", "error", "errors", "not")
    recs = _cluster_records(user, cid)
    rows = []
    for r in fleet._pmap(lambda c: (c, clusterview.part(c, "pods")), recs,
                         workers=min(6, max(1, len(recs)))) or []:
        if not r:
            continue
        c, part = r
        if part.get("error"):
            rows.append({"cluster": c.get("name"), "namespace": "—",
                         "pod": f"(could not read: {part['error']})",
                         "status": "unknown", "ready": "", "restarts": "",
                         "node": "", "age": ""})
            continue
        for p in part.get("pods") or []:
            if bad_only and p["healthy"]:
                continue
            rows.append({"cluster": c.get("name"), "namespace": p["namespace"],
                         "pod": p["name"],
                         "status": p["problem"] or p["phase"],
                         "ready": p["ready"], "restarts": p["restarts"],
                         "node": p["node"], "age": p["age"]})
    ns = _namespace_in(question, rows)
    if ns:
        rows = [r for r in rows if r["namespace"] == ns]
    rows.sort(key=lambda r: (r["status"] in ("Running", "Succeeded"),
                            r["cluster"], r["namespace"], r["pod"]))
    what = "pods needing attention" if bad_only else "pods"
    return {"columns": ["cluster", "namespace", "pod", "status", "ready",
                        "restarts", "node", "age"],
            "rows": rows,
            "note": what + (f" in namespace {ns}" if ns else "")}


def _namespace_in(question: str, rows: list) -> str:
    """A namespace named in the question, but only one that actually exists in
    the result — so "payments" matches a real namespace and a stray word does
    not silently empty the table."""
    live = {r["namespace"] for r in rows}
    for w in _words(question):
        if w in live:
            return w
    return ""


def q_nodes(user, question: str, cid: str, focus: str = "") -> dict:
    from . import cluster as clusterview
    from . import fleet
    bad_only = _flag(question, "notready", "unhealthy", "down", "problem",
                     "problems", "cordoned", "pressure", "not")
    recs = _cluster_records(user, cid)
    rows = []
    for r in fleet._pmap(lambda c: (c, clusterview.part(c, "nodes")), recs,
                         workers=min(6, max(1, len(recs)))) or []:
        if not r:
            continue
        c, part = r
        for n in part.get("nodes") or []:
            if bad_only and n["ready"] and n["schedulable"] and not n["pressure"]:
                continue
            rows.append({
                "cluster": c.get("name"), "node": n["name"],
                "ready": "yes" if n["ready"] else "NO",
                "roles": ", ".join(n["roles"]),
                "version": n["version"],
                "cpu": (f"{n['cpu_use'] / 1000:.1f}/{n['cpu_cap'] / 1000:.0f} cores"
                        if n.get("cpu_use") is not None and n.get("cpu_cap")
                        else (f"{n['cpu_cap'] / 1000:.0f} cores" if n.get("cpu_cap") else "")),
                "memory": (f"{n['mem_use'] / 1024:.0f}/{n['mem_cap'] / 1024:.0f} GiB"
                           if n.get("mem_use") is not None and n.get("mem_cap")
                           else (f"{n['mem_cap'] / 1024:.0f} GiB" if n.get("mem_cap") else "")),
                "age": n.get("age", "")})
    rows.sort(key=lambda r: (r["ready"] == "yes", r["cluster"], r["node"]))
    return {"columns": ["cluster", "node", "ready", "roles", "version", "cpu",
                        "memory", "age"],
            "rows": rows,
            "note": "nodes that need attention" if bad_only else "nodes"}


def q_clusters(user, question: str, cid: str, focus: str = "") -> dict:
    from . import fleet, rbac
    # "Unreachable" is a specific claim about the API server answering, and it
    # was being treated as a synonym for "in any way unwell". Asked which
    # clusters are unreachable, the portal returned a cluster that answers fine
    # and merely has four unhealthy pods — a wrong answer to a precise question,
    # and the kind that costs somebody a call to the wrong team.
    REACH_WORDS = ("unreachable", "offline", "disconnected", "down")
    TROUBLE_WORDS = ("broken", "failing", "unhealthy", "problem", "problems",
                     "attention", "wrong", "not")
    reach_only = _flag(question, *REACH_WORDS)
    # Not "reach_only or trouble": every use below excludes reach_only again,
    # because an unreachable cluster is a different answer from an unhealthy one
    # — which is the distinction that made the first version unhelpful.
    bad_only = _flag(question, *TROUBLE_WORDS)
    allowed = rbac.visible_clusters(user)
    rows = []
    for c in fleet.overview().get("clusters") or []:
        if allowed is not None and c["cid"] not in allowed:
            continue
        if cid and c["cid"] != cid:
            continue
        nodes_now, pods_now = c.get("nodes") or {}, c.get("pods") or {}
        unhappy = (not c.get("reachable")
                   or (pods_now.get("bad") or 0) > 0
                   or (nodes_now.get("ready") != nodes_now.get("total")))
        if reach_only and c.get("reachable"):
            continue                     # asked about reachability, precisely
        if bad_only and not unhappy:
            continue
        cpu, mem = c.get("cpu") or {}, c.get("mem") or {}
        nodes, pods = c.get("nodes") or {}, c.get("pods") or {}
        rows.append({"cluster": c.get("name"), "project": c.get("project"),
                     "reachable": "yes" if c.get("reachable") else "NO",
                     "nodes": f"{nodes.get('ready', 0)}/{nodes.get('total', 0)}",
                     "pods": f"{pods.get('running', 0)}/{pods.get('total', 0)}",
                     "unhealthy pods": pods.get("bad", 0),
                     "pending pods": pods.get("pending", 0),
                     "cpu": f"{cpu.get('pct')}%" if cpu.get("pct") is not None else "",
                     "memory": f"{mem.get('pct')}%" if mem.get("pct") is not None else "",
                     "problem": (c.get("error") or "")[:90]})
    rows.sort(key=lambda r: (r["reachable"] == "yes", -int(r["unhealthy pods"] or 0),
                            r["cluster"]))
    return {"columns": ["cluster", "project", "reachable", "nodes", "pods",
                        "unhealthy pods", "pending pods", "cpu", "memory",
                        "problem"],
            "rows": rows,
            # The words this query has already acted on. Without this the
            # filter in shape() re-applies them against the reachable column and
            # empties a result that was already correct.
            "consumed": _flagged(question, *REACH_WORDS, *TROUBLE_WORDS,
                                 "reachable"),
            # What "none of them" means for the filter that was actually
            # applied. Without it every empty cluster result said the same
            # sentence, which answered a question nobody had asked.
            "empty": ("No cluster is unreachable — every one of them answers."
                      if reach_only else
                      "No cluster is unreachable, missing a node, or running "
                      "unhealthy pods." if bad_only else
                      "No clusters are configured yet."),
            "note": ("clusters that are unreachable" if reach_only else
                     "clusters that are unreachable, missing a node, or "
                     "running unhealthy pods" if bad_only else "clusters")}


def q_events(user, question: str, cid: str, focus: str = "") -> dict:
    from . import cluster as clusterview
    from . import fleet
    recs = _cluster_records(user, cid)
    rows = []
    for r in fleet._pmap(lambda c: (c, clusterview.part(c, "events")), recs,
                         workers=min(6, max(1, len(recs)))) or []:
        if not r:
            continue
        c, part = r
        for e in (part.get("events") or [])[:60]:
            rows.append({"cluster": c.get("name"), "namespace": e.get("namespace", ""),
                         "object": e.get("object", ""), "reason": e.get("reason", ""),
                         "message": (e.get("message") or "")[:140],
                         "count": e.get("count", ""), "age": e.get("age", "")})
    return {"columns": ["cluster", "namespace", "object", "reason", "message",
                        "count", "age"],
            "rows": rows, "note": "recent warning events"}


def q_workloads(user, question: str, cid: str, focus: str = "") -> dict:
    from . import cluster as clusterview
    from . import fleet
    recs = _cluster_records(user, cid)
    rows = []
    for r in fleet._pmap(lambda c: (c, clusterview.part(c, "workloads")), recs,
                         workers=min(6, max(1, len(recs)))) or []:
        if not r:
            continue
        c, part = r
        for w in part.get("workloads") or []:
            rows.append({"cluster": c.get("name"), "namespace": w.get("namespace", ""),
                         "kind": w.get("kind", ""), "name": w.get("name", ""),
                         "ready": w.get("ready", ""), "image": w.get("image", "")})
    return {"columns": ["cluster", "namespace", "kind", "name", "ready", "image"],
            "rows": rows, "note": "workloads"}


def q_pipelines(user, question: str, cid: str, focus: str = "") -> dict:
    from . import ci, fleet, store
    fail_only = _flag(question, "failing", "failed", "broken", "red", "not")
    rows = []
    for got in fleet._pmap(lambda c: (c, _safe(ci.jobs, c)), store.all_ci(),
                           workers=4) or []:
        if not got:
            continue
        c, jobs = got
        if isinstance(jobs, str):
            rows.append({"connection": c.get("name"), "pipeline": f"(error: {jobs})",
                         "status": "unknown", "health": "", "branch": "",
                         "last success": "", "last failure": ""})
            continue
        for j in jobs:
            if fail_only and j.get("status") != "failed":
                continue
            # The provider is on the connection, never in the job, so without
            # this a question naming one has nothing to match against — which
            # is how "bitbucket pipelines" came back holding a Jenkins job.
            rows.append({"connection": c.get("name"),
                         "provider": c.get("type", ""),
                         "pipeline": j.get("name"),
                         "status": j.get("status"),
                         "health": f"{j.get('health')}%" if j.get("health") is not None else "",
                         "branch": j.get("branch", ""),
                         "started": j.get("started", ""),
                         "build": j.get("number", ""),
                         "duration": j.get("duration", ""),
                         "folder": j.get("folder", ""),
                         "last success": (j.get("last_success") or {}).get("when", ""),
                         "last failure": (j.get("last_failure") or {}).get("when", ""),
                         "url": j.get("build_url") or j.get("url", ""),
                         "started_at": j.get("started_at", "")})
    rows.sort(key=lambda r: (r["status"] != "failed", r["connection"], r["pipeline"]))
    return {"columns": ["connection", "pipeline", "status", "health", "branch",
                        "started", "build", "duration",
                        "last success", "last failure"],
            "rows": rows, "note": "failing pipelines" if fail_only else "pipelines",
            "time_field": "started_at"}


def q_gitops(user, question: str, cid: str, focus: str = "") -> dict:
    from . import fleet, gitops, store
    bad_only = _flag(question, "outofsync", "unsynced", "degraded", "unhealthy",
                     "failing", "problem", "problems", "not")
    rows = []
    for got in fleet._pmap(lambda c: (c, _safe(gitops.apps, c)),
                           store.all_gitops(), workers=4) or []:
        if not got:
            continue
        c, apps = got
        if isinstance(apps, str):
            rows.append({"controller": c.get("name"), "application": f"(error: {apps})",
                         "sync": "", "health": "", "destination": "", "revision": ""})
            continue
        for a in apps:
            if bad_only and a["sync"] == "Synced" and a["health"] == "Healthy":
                continue
            rows.append({"controller": c.get("name"), "application": a["name"],
                         "sync": a["sync"], "health": a["health"],
                         "destination": a["dest"], "revision": a["revision"]})
    return {"columns": ["controller", "application", "sync", "health",
                        "destination", "revision"],
            "rows": rows,
            "note": "applications not synced or not healthy" if bad_only
                    else "GitOps applications"}


def q_workflows(user, question: str, cid: str, focus: str = "") -> dict:
    from . import fleet, store, workflows
    fail_only = _flag(question, "failed", "failing", "stuck", "problem", "not")
    rows = []
    for got in fleet._pmap(lambda c: (c, _safe(workflows.overview, c)),
                           store.all_wf(), workers=4) or []:
        if not got:
            continue
        c, ov = got
        if isinstance(ov, str):
            rows.append({"engine": c.get("name"), "group": "", "item": f"(error: {ov})",
                         "state": "", "when": ""})
            continue
        for g in ov.get("groups") or []:
            for r in g.get("rows") or []:
                if fail_only and r["state"] != "Failed":
                    continue
                rows.append({"engine": c.get("name"), "group": g["name"],
                             "item": r["name"], "state": r["state"],
                             "when": r["when"]})
    return {"columns": ["engine", "group", "item", "state", "when"],
            "rows": rows,
            "note": "failed workflows" if fail_only else "workflows"}


def q_ansible(user, question: str, cid: str, focus: str = "") -> dict:
    """Playbook runs: what ran, against what, and how it went.

    Runs rather than playbooks, because "did the node exporter play go out on the
    web group" is the question people actually ask, and a list of playbooks
    cannot answer it. A check run is marked as one: it changed nothing, and a
    reader told "it ran, it succeeded" about a dry run has been misled.
    """
    from . import ansible
    fail_only = _flag(question, "failed", "failing", "broken", "unreachable",
                      "problem", "not")
    rows = []
    for r in ansible.runs(200):
        if fail_only and r["status"] in ("ok", "running"):
            continue
        totals = (r.get("stats") or {}).get("totals") or {}
        rows.append({
            "playbook": r.get("pb_name") or "",
            "hosts": r.get("group_name") or "",
            "mode": "check (dry run)" if r.get("check_mode") else "real",
            "result": r.get("status") or "",
            "changed": totals.get("changed", ""),
            "failed": totals.get("failed", ""),
            "who": r.get("by") or "",
            "when": r.get("ago") or "",
        })
    return {"columns": ["playbook", "hosts", "mode", "result", "changed",
                        "failed", "who", "when"],
            "rows": rows,
            "note": "failed playbook runs" if fail_only else "playbook runs"}


def q_connections(user, question: str, cid: str, focus: str = "") -> dict:
    """Every integration and whether its last check passed. Cheap: reads stored
    status rather than re-testing, which is what makes this instant."""
    from . import rbac, store
    bad_only = _flag(question, "unhealthy", "failing", "failed", "broken",
                     "down", "problem", "problems", "not")
    kinds = [("ci", "CI/CD", store.all_ci, "pipelines"),
             ("sec", "security scanning", store.all_sec, "security"),
             ("log", "log store", store.all_log, "logs"),
             ("mon", "monitoring", store.all_mon, "monitoring"),
             ("cloud", "cloud account", store.all_cloud, "clouds"),
             ("stor", "storage device", store.all_stor, "storage"),
             ("gitops", "GitOps", store.all_gitops, "gitops"),
             ("wf", "workflow engine", store.all_wf, "workflows"),
             ("bmc", "server BMC", store.all_bmc, "bmc"),
             ("virt", "hypervisor", store.all_virt, "virt")]
    rows = []
    for _key, label, getter, area in kinds:
        if not rbac.may_area(user, area):
            continue
        for c in getter():
            st = c.get("status") or ""
            healthy = st.startswith("ok") or st.startswith("connected")
            if bad_only and healthy:
                continue
            rows.append({"kind": label, "name": c.get("name"),
                         "type": c.get("type"),
                         "address": c.get("base_url") or c.get("cluster") or "",
                         "healthy": "yes" if healthy else ("NO" if st else "not checked"),
                         "last check": st[:110]})
    rows.sort(key=lambda r: (r["healthy"] == "yes", r["kind"], r["name"]))
    return {"columns": ["kind", "name", "type", "address", "healthy", "last check"],
            "rows": rows,
            "note": "integrations that are not healthy" if bad_only
                    else "connected integrations"}


IDENTIFIER = re.compile(
    r"^(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}"          # an IP address
    r"|[a-z0-9][a-z0-9-]*\.[a-z0-9.-]+"   # a host name with a dot
    r"|(?=[a-z0-9-]*\d)[a-z0-9-]{5,}"     # a serial or tag: has a digit, 5+ chars
    r")$", re.I)


def q_assets(user, question: str, cid: str, focus: str = "") -> dict:
    """The inventory, narrowed by any identifier in the question.

    "give me the ip for C7KG414" and "idrac ip for esx01.dc1" both work: the
    identifier is recognised by shape and handed to the same search the Assets
    page uses, so serials, host names and IP addresses all resolve. Management
    IP is included because "the iDRAC address" is inventory data, not something
    the BMC can be asked for before you know where it is.
    """
    from . import assets, store
    terms = [w for w in _words(question)
             if w not in STOP and IDENTIFIER.match(w)]
    raw, seen = [], set()
    for term in terms or [""]:
        for a in assets.search(term, None, "hostname", limit=1000)["rows"]:
            if a["id"] not in seen:
                seen.add(a["id"])
                raw.append(a)

    # Scope from the words in the question, matched against the values that are
    # actually in the inventory — so "physical servers in uae acme prod"
    # narrows by kind, project, region and environment without any of those
    # being written down here. A word that matches nothing is ignored rather
    # than emptying the table.
    project_names = {pid: (p.get("name") or "").lower()
                     for pid, p in store.projects().items()}
    asked = [w for w in _words(question) if w not in STOP]
    scopes, unknown_kind = [], 0

    getters = {
        "kind": lambda a: (a.get("kind") or "").lower(),
        "placement": lambda a: (a.get("placement") or "").lower(),
        "environment": lambda a: (a.get("env") or "").lower(),
        "region": lambda a: (a.get("region") or "").lower(),
        "status": lambda a: (a.get("status") or "").lower(),
        "location": lambda a: (a.get("location") or "").lower(),
        "provider": lambda a: (a.get("provider") or "").lower(),
        "project": lambda a: project_names.get(a.get("pid") or "", ""),
    }
    # Every scope is decided against the FULL set, then all of them are applied
    # together. Deciding one field at a time against the already-narrowed set
    # lost constraints silently: "uae acme prod" filtered by environment
    # first and then found no "uae" left to match, so the region was dropped
    # without a word.
    filters = []
    for field, get in getters.items():
        live = {get(a) for a in raw if get(a)}
        for w in asked:
            hit = next((v for v in live
                        if w == v or w in v.split()
                        or w.rstrip("s") == v.rstrip("s")
                        or w.rstrip("s") in [x.rstrip("s") for x in v.split()]),
                       "")
            if hit:
                filters.append((field, hit, get))
                break

    # "physical" and "vm" are not values in anybody's inventory — they are
    # groups over whatever words a team uses for kind ("blade", "rack server",
    # "virtual machine"). Asked literally, "physical" matched nothing here and
    # would have answered a question about 65 machines with 0.
    VIRTUAL = ("virtual", "vm", "container", "lxc", "guest")
    want_physical = any(w in ("physical", "baremetal", "bare-metal", "metal",
                              "hardware") for w in asked)
    want_virtual = any(w in ("vm", "vms", "virtual", "guest", "guests")
                       for w in asked)
    if want_physical or want_virtual:
        filters = [f for f in filters if f[0] != "kind"]

    for field, hit, get in filters:
        raw = [a for a in raw if get(a) == hit]
        scopes.append(f"{field} {hit}")
    if want_physical:
        unknown_kind = sum(1 for a in raw if not (a.get("kind") or "").strip())
        raw = [a for a in raw
               if (a.get("kind") or "").strip()
               and not any(v in (a.get("kind") or "").lower() for v in VIRTUAL)]
        scopes.append("physical (any non-virtual kind)")
    elif want_virtual:
        raw = [a for a in raw
               if any(v in (a.get("kind") or "").lower() for v in VIRTUAL)]
        scopes.append("virtual machines")

    rows = [{
        "hostname": a.get("hostname"), "serial": a.get("serial", ""),
        "ip": a.get("ip", ""), "idrac / ilo ip": a.get("mgmt_ip", ""),
        "model": a.get("model", ""), "environment": a.get("env", ""),
        "kind": a.get("kind", "") or a.get("placement", ""),
        "location": a.get("location", ""), "status": a.get("status", "")}
        for a in raw]
    note = "inventory"
    if terms:
        note += " matching " + ", ".join(f"“{t}”" for t in terms)
    if scopes:
        note += " — " + ", ".join(scopes)
    if unknown_kind:
        note += (f" (plus {unknown_kind} with no kind recorded, "
                 "not counted either way)")
    return {"columns": ["hostname", "serial", "ip", "idrac / ilo ip", "model",
                        "environment", "kind", "location", "status"],
            "rows": rows, "note": note}


def q_servers(user, question: str, cid: str, focus: str = "") -> dict:
    from . import bmc, fleet, store
    rows = []
    for got in fleet._pmap(lambda c: (c, _safe(bmc.read, c)), store.all_bmc(),
                           workers=4) or []:
        if not got:
            continue
        c, info = got
        if isinstance(info, str):
            rows.append({"bmc": c.get("name"),
                         "address": (c.get("base_url") or "").replace("https://", "")
                                    .replace("http://", ""),
                         "model": f"(error: {info})",
                         "serial": "", "power": "", "health": "", "hottest": ""})
            continue
        rows.append({"bmc": c.get("name"),
                     "address": (c.get("base_url") or "").replace("https://", "")
                                .replace("http://", ""),
                     "model": f"{info.get('vendor','')} {info.get('model','')}".strip(),
                     "serial": info.get("serial", ""),
                     "power": info.get("power", ""),
                     "health": info.get("health", ""),
                     "hottest": (f"{info['hottest']} °C"
                                 if info.get("hottest") is not None else "")})
    return {"columns": ["bmc", "address", "model", "serial", "power", "health",
                        "hottest"],
            "rows": rows, "note": "server hardware"}


def q_vms(user, question: str, cid: str, focus: str = "") -> dict:
    from . import fleet, store, virt
    off_only = _flag(question, "stopped", "off", "down", "not")
    rows = []
    for got in fleet._pmap(lambda c: (c, _safe(virt.read, c)), store.all_virt(),
                           workers=4) or []:
        if not got:
            continue
        c, data = got
        if isinstance(data, str):
            rows.append({"hypervisor": c.get("name"), "guest": f"(error: {data})",
                         "kind": "", "state": "", "host": "", "cpu": "", "memory": ""})
            continue
        for g in data.get("guests") or []:
            live = (g["state"] or "").lower() in ("running", "on", "poweredon")
            if off_only and live:
                continue
            rows.append({"hypervisor": c.get("name"), "guest": g["name"],
                         "kind": g["kind"], "state": g["state"], "host": g["host"],
                         "cpu": f"{g['cores']} vCPU" if g.get("cores") else "",
                         "memory": f"{g['mem_gib']} GiB" if g.get("mem_gib") else ""})
    return {"columns": ["hypervisor", "guest", "kind", "state", "host", "cpu",
                        "memory"],
            "rows": rows,
            "note": ("virtual machines not running, from the connected "
                     "hypervisors") if off_only
                    else "virtual machines, from the connected hypervisors"}


# ── addresses: the questions that start with "what is the IP of…" ──
def _generic_words() -> set:
    """Words that describe what kind of thing is wanted, not which one."""
    return {w for spec in CATALOGUE.values() for w in spec["words"]}


# Words that describe an attribute of a thing rather than naming one. They can
# never be the subject of a search, however unfamiliar they look to the routing
# vocabulary, because no estate contains a certificate called "expiry".
META = {
    "date", "dates", "time", "times", "expiry", "expiration", "expire",
    "expires", "expired", "expiring", "renewal", "renew", "days", "week",
    "weeks", "month", "months", "year", "years", "status", "state", "states",
    "name", "names", "number", "numbers", "count", "value", "values", "detail",
    "details", "info", "information", "version", "versions", "type", "types",
    "kind", "kinds", "first", "last", "latest", "next", "previous", "soonest",
    "newest", "oldest", "current", "currently", "used", "using", "total",
    "amount", "each", "every", "which", "whose", "there", "their", "these",
    "those", "same", "other", "another", "left", "remaining", "soon",
}

# How much a word must resemble a real name here before its absence is worth
# reporting. Tuned so that a genuine but absent subject ("traefik" on a cluster
# using nginx) still earns an honest "not here", while a stray English word does
# not become a failed search.
NAME_FLOOR = 0.5


def _name_likeness(word: str, live_tokens: set) -> float:
    """Best similarity between a word and any name present in these rows."""
    return max((difflib.SequenceMatcher(None, word, t).ratio()
                for t in live_tokens), default=0.0)


def _name_filter(question: str, rows: list, fields: tuple,
                 focus: str = "") -> tuple[list, str, list]:
    """(rows, the subject they were narrowed by, suggestions if it was absent).

    The subject is identified as a subject — a word that names a *particular*
    thing — rather than by trying every word and keeping whichever happens to
    filter. That fallback is what turned "what is the traefik ip for ledger
    dev" into sixteen ledger services: traefik was absent, so the code quietly
    answered a different question. Now an absent subject returns nothing and
    says so, with the nearest live names as suggestions.

    Spelling is forgiven: a subject that does not match exactly is matched
    against the names actually present, so "traefic" and "ingres" resolve.
    """
    def hits_for(term):
        return [r for r in rows
                if any(term in str(r.get(f, "")).lower() for f in fields)]

    # every token of every live name, for exact and fuzzy resolution
    live_tokens = set()
    for r in rows:
        for f in fields:
            val = str(r.get(f, "")).lower()
            live_tokens.add(val)
            live_tokens.update(t for t in re.split(r"[^a-z0-9]+", val) if t)

    if focus:
        hits = hits_for(focus.lower())
        if hits:
            return hits, focus, []
        near = close(focus.lower(), live_tokens)
        if near:
            return hits_for(near), near, []
        return [], focus, sorted(t for t in live_tokens if len(t) > 3)[:6]

    generic = _generic_words()
    scope = set(_words(find_cluster(question)[1]))
    # a column name is a field, not a subject: "the expiry DATE for the
    # certificate" was read as a search for something called "date"
    field_words = set()
    for r in rows[:1]:
        for key in r:
            field_words.update(t for t in re.split(r"[^a-z0-9]+", key.lower()) if t)
    candidates = [w for w in _words(question)
                  if w not in STOP and w not in generic and w not in scope
                  and w not in field_words and w not in META
                  and len(w) > 3 and not w.isdigit()]

    # Every candidate is tried, and the most specific hit wins — the narrowest
    # match is the one that names a thing. Stopping at the first candidate meant
    # an incidental word ("direct", "please") decided the answer.
    best = None
    for w in candidates:
        hits = hits_for(w)
        if not hits:
            near = close(w, live_tokens)
            if near:
                hits, w = hits_for(near), near
        if hits and (best is None or len(hits) < len(best[0])):
            best = (hits, w)
    if best:
        return best[0], best[1], []

    if candidates:
        # nothing named in the question exists here. Report the candidate that
        # came closest to a real name, so the message is about the word the
        # person meant rather than the first one they typed.
        ranked = sorted(
            candidates,
            key=lambda w: _name_likeness(w, live_tokens), reverse=True)
        # …but only if it could be a name at all. "the expiry DATE" and "which
        # one expires FIRST" are questions about a column, not searches for a
        # thing called date, and answering them with "no certificate matching
        # date" was worse than useless.
        if _name_likeness(ranked[0], live_tokens) >= NAME_FLOOR:
            return [], ranked[0], sorted(t for t in live_tokens if len(t) > 3)[:6]
    return rows, "", []


def q_services(user, question: str, cid: str, focus: str = "") -> dict:
    """Every service and its addresses, across every cluster this role can see.

    Reads services directly rather than through the network part: that one is
    scoped to a single cluster, and "what is the traefik IP" is usually asked
    without naming one. (It used to hide internal ClusterIP services as well,
    which was the original reason for reading around it; it no longer does.)
    """
    from . import cluster as clusterview
    from . import fleet
    recs = _cluster_records(user, cid)
    rows = []
    for got in fleet._pmap(
            lambda c: (c, clusterview._get(c, "svc", "-A")), recs,
            workers=min(6, max(1, len(recs)))) or []:
        if not got:
            continue
        c, doc = got
        if doc is None:
            rows.append({"cluster": c.get("name"), "namespace": "—",
                         "service": "(could not read this cluster)", "type": "",
                         "cluster ip": "", "external ip": "", "ports": ""})
            continue
        for sv in doc.get("items") or []:
            meta, spec = sv["metadata"], sv.get("spec", {})
            st = sv.get("status", {})
            ext = [i.get("ip") or i.get("hostname", "") for i in
                   (st.get("loadBalancer") or {}).get("ingress", []) or []]
            rows.append({
                "cluster": c.get("name"), "namespace": meta["namespace"],
                "service": meta["name"], "type": spec.get("type", "ClusterIP"),
                "cluster ip": spec.get("clusterIP", ""),
                "external ip": ", ".join(e for e in ext if e)
                               or ", ".join(spec.get("externalIPs", []) or []),
                "ports": ", ".join(
                    f"{p.get('port')}" + (f":{p['nodePort']}" if p.get("nodePort") else "")
                    for p in spec.get("ports", []) or [])})
    everything = list(rows)
    rows, term, suggestions = _name_filter(question, rows,
                                           ("service", "namespace"), focus)
    note = "services and their addresses"
    if term and rows:
        note = f"services matching “{term}”"
    elif term and not rows:
        # The named thing is not here. Answer the question behind the question:
        # someone asking for "the traefik ip" wants the way in, and this cluster
        # may simply use a different ingress controller. Show what is actually
        # exposed and say plainly that it is a substitution.
        note = f"no service named “{term}” in this cluster"
        exposed = [r for r in everything
                   if r["type"] in ("LoadBalancer", "NodePort")]
        wants_entry = any(w in _words(question) for w in
                          ("ip", "ips", "address", "addresses", "entry",
                           "ingress", "external", "endpoint", "url"))
        if exposed and wants_entry:
            rows = exposed
            note += " — showing the services it exposes externally instead"
        elif suggestions:
            note += " — closest names here: " + ", ".join(suggestions)

    low = (term or "").lower()
    rows.sort(key=lambda r: (
        0 if low and low in r["service"].lower() else 1,
        {"LoadBalancer": 0, "NodePort": 1}.get(r["type"], 2),
        r["cluster"], r["namespace"], r["service"]))
    return {"columns": ["cluster", "namespace", "service", "type", "cluster ip",
                        "external ip", "ports"],
            "rows": rows, "note": note, "focus": term}


def q_ingress(user, question: str, cid: str, focus: str = "") -> dict:
    """Host names served by a cluster, and the address they resolve to.

    Reads three shapes, because a cluster uses whichever its ingress controller
    speaks: the standard Ingress, Traefik's IngressRoute, and Gateway API's
    HTTPRoute. Asking only about Ingress returned nothing on a Traefik cluster
    that was in fact serving eighteen host names — an empty table that looked
    like an answer.
    """
    from . import cluster as clusterview
    from . import fleet
    recs = _cluster_records(user, cid)
    rows = []

    def read(c):
        return (c,
                clusterview._get(c, "ingress", "-A"),
                clusterview._get(c, "ingressroute", "-A", timeout=12),
                clusterview._get(c, "httproute", "-A", timeout=12))

    for got in fleet._pmap(read, recs, workers=min(6, max(1, len(recs)))) or []:
        if not got:
            continue
        c, doc, troutes, hroutes = got
        # Traefik IngressRoute: hosts live inside a match expression
        for r in ((troutes or {}).get("items") or []):
            meta, spec = r["metadata"], r.get("spec", {})
            for rule in spec.get("routes", []) or []:
                hosts = []
                for m in re.findall(r"Host\(([^)]*)\)", rule.get("match", "")):
                    hosts += [h.strip().strip("`'\"") for h in m.split(",")]
                svc = ", ".join(sv.get("name", "")
                                for sv in rule.get("services", []) or [])
                for h in hosts or [""]:
                    rows.append({
                        "cluster": c.get("name"), "namespace": meta["namespace"],
                        "ingress": meta["name"], "host": h, "address": "",
                        "service": svc,
                        "class": ", ".join(spec.get("entryPoints", []) or [])
                                 or "IngressRoute",
                        "tls": "yes" if spec.get("tls") else "no"})
        # Gateway API HTTPRoute
        for r in ((hroutes or {}).get("items") or []):
            meta, spec = r["metadata"], r.get("spec", {})
            svc = ", ".join(
                b.get("name", "")
                for rule in spec.get("rules", []) or []
                for b in rule.get("backendRefs", []) or [])
            for h in spec.get("hostnames", []) or [""]:
                rows.append({
                    "cluster": c.get("name"), "namespace": meta["namespace"],
                    "ingress": meta["name"], "host": h, "address": "",
                    "service": svc, "class": "HTTPRoute", "tls": ""})
        if doc is None:
            continue
        for ing in doc.get("items") or []:
            meta, spec = ing["metadata"], ing.get("spec", {})
            st = ing.get("status", {})
            addrs = [i.get("ip") or i.get("hostname", "") for i in
                     (st.get("loadBalancer") or {}).get("ingress", []) or []]
            tls_hosts = {h for t in spec.get("tls", []) or []
                         for h in t.get("hosts", []) or []}
            for rule in spec.get("rules", []) or [{}]:
                host = rule.get("host", "")
                paths = (rule.get("http") or {}).get("paths") or []
                backend = ", ".join(
                    ((pa.get("backend") or {}).get("service") or {}).get("name", "")
                    for pa in paths) or ""
                rows.append({
                    "cluster": c.get("name"), "namespace": meta["namespace"],
                    "ingress": meta["name"], "host": host,
                    "address": ", ".join(a for a in addrs if a),
                    "service": backend,
                    "class": spec.get("ingressClassName", ""),
                    "tls": "yes" if host in tls_hosts or spec.get("tls") else "no"})
    rows, term, suggestions = _name_filter(
        question, rows, ("host", "ingress", "service", "namespace"), focus)
    low = (term or "").lower()
    rows.sort(key=lambda r: (0 if low and low in r["host"].lower() else 1,
                            r["cluster"], r["host"], r["ingress"]))
    note = "host names served by this cluster"
    if term and rows:
        note = f"host names matching “{term}”"
    elif term:
        note = f"no host name matching “{term}”"
        if suggestions:
            note += " — closest here: " + ", ".join(suggestions)
    elif not rows:
        # An empty table with no explanation reads as a broken answer. Say what
        # was looked for, so "nothing here" is a fact rather than a shrug.
        note = ("no Ingress, IngressRoute or HTTPRoute objects — this cluster "
                "may publish services directly; ask for its services instead")
    return {"columns": ["cluster", "namespace", "ingress", "host", "address",
                        "service", "class", "tls"],
            "rows": rows, "note": note, "focus": term}


def _safe(fn, *a):
    """Run a reader, returning its error as a string instead of raising: one
    broken connection must not empty the whole answer."""
    try:
        return fn(*a)
    except Exception as e:                                    # noqa: BLE001
        return f"{type(e).__name__}: {e}"[:160]


CATALOGUE = {
    "pods": {
        "unit": "pods",
        "label": "pods", "area": "clusters", "run": q_pods, "cluster": True,
        "words": ["pod", "pods", "container", "containers", "crashloop",
                  "restarting", "restarts", "pending", "evicted", "attention",
                  "crashloopbackoff", "crashing"],
        "help": "pods across clusters, filterable by cluster, namespace, or "
                "only the unhealthy ones",
    },
    "nodes": {
        "unit": "nodes",
        "label": "nodes", "area": "clusters", "run": q_nodes, "cluster": True,
        "words": ["node", "nodes", "worker", "workers", "kubelet", "notready",
                  "cordoned", "capacity", "ready"],
        "help": "nodes, their readiness, versions and utilisation",
    },
    "clusters": {
        "unit": "clusters",
        "label": "clusters", "area": "clusters", "run": q_clusters, "cluster": True,
        "words": ["cluster", "clusters", "unreachable", "fleet", "reachable",
                  "kubernetes", "k8s"],
        "help": "every cluster with reachability, node and pod health",
    },
    "events": {
        "unit": "events",
        "label": "events", "area": "clusters", "run": q_events, "cluster": True,
        "words": ["event", "events", "warning", "warnings", "why", "oom",
                  "killed", "evicted", "failedmount"],
        "help": "recent warning events from a cluster",
    },
    "workloads": {
        "unit": "workloads",
        "label": "workloads", "area": "clusters", "run": q_workloads, "cluster": True,
        "words": ["deployment", "deployments", "statefulset", "statefulsets",
                  "daemonset", "cronjob", "workload", "workloads", "replicas"],
        "help": "deployments, statefulsets, daemonsets and cronjobs",
    },
    "services": {
        "unit": "services",
        "label": "services and addresses", "area": "clusters", "run": q_services,
        "cluster": True,
        "words": ["ip", "ips", "address", "addresses", "service", "services",
                  "svc", "loadbalancer", "clusterip", "nodeport", "endpoint",
                  "port", "ports", "vip"],
        "help": "services in a cluster with their cluster IP, external IP and "
                "ports — ask for one by name, e.g. “traefik ip on tz preprod”",
    },
    "ingress": {
        "unit": "host names",
        "label": "ingress host names", "area": "clusters", "run": q_ingress,
        "cluster": True,
        # "certificate"/"tls" deliberately absent: they belong to the
        # certificates query, and having them here answered "list the
        # certificates" with a table of host names.
        "words": ["ingress", "ingresses", "host", "hosts", "hostname", "dns",
                  "domain", "url", "route", "routes", "published", "exposed"],
        "help": "host names a cluster serves, the address they point at, and "
                "which service is behind each",
    },
    "pipelines": {
        "unit": "pipelines",
        "label": "pipelines", "area": "pipelines", "run": q_pipelines,
        "words": ["pipeline", "pipelines", "build", "builds", "ci", "jenkins",
                  "bitbucket", "gitlab", "actions", "job", "jobs"],
        "help": "CI builds and their outcomes",
    },
    "gitops": {
        "unit": "applications",
        "label": "GitOps applications", "area": "gitops", "run": q_gitops,
        "words": ["argo", "argocd", "gitops", "sync", "synced", "outofsync",
                  "flux", "application", "applications", "app", "apps"],
        "help": "Argo CD and Flux applications with sync and health",
    },
    "workflows": {
        "unit": "workflows",
        "label": "workflows", "area": "workflows", "run": q_workflows,
        "words": ["workflow", "workflows", "temporal", "airflow", "dag", "dags"],
        "help": "running and recently failed workflows",
    },
    "ansible": {
        "unit": "runs",
        "label": "playbook runs", "area": "ansible", "run": q_ansible,
        # deliberately NOT "inventory": that word belongs to the server
        # inventory, and claiming it here sent "what is in the inventory" to
        # playbook runs — caught by tests/test_routing.py, not by reading.
        "words": ["ansible", "playbook", "playbooks", "play", "plays", "ran",
                  "run", "runs", "task", "tasks", "become"],
        "help": "playbook runs, what they targeted and how they ended",
    },
    "connections": {
        "unit": "integrations",
        "label": "integrations", "area": "overview", "run": q_connections,
        "words": ["connection", "connections", "integration", "integrations",
                  "connected", "configured", "setup", "health", "healthy",
                  "unhealthy", "broken", "status"],
        "help": "every integration and whether its last check passed",
    },
    "assets": {
        "unit": "machines",
        "label": "inventory", "area": "assets", "run": q_assets,
        # a serial, host name or IP address in the question means this one
        "identifier": True,
        "words": ["asset", "assets", "inventory", "warranty", "rack",
                  "serial", "serials", "serialnumber", "sn", "servicetag",
                  "location", "owner", "procurement", "idrac", "ilo", "mgmt",
                  "management", "physical", "machine", "machines", "box",
                  "boxes", "baremetal", "hostname", "hostnames"],
        "help": "the inventory — look a machine up by serial, host name or IP "
                "and get its address and its iDRAC/iLO address",
    },
    "servers": {
        "unit": "servers",
        "label": "server hardware", "area": "bmc", "run": q_servers,
        "words": ["idrac", "ilo", "bmc", "redfish", "temperature", "temperatures",
                  "thermal", "fan", "fans", "psu", "psus", "watt", "watts",
                  "power", "firmware", "bios", "overheating", "hot"],
        "help": "BMC health: power, temperature, firmware",
    },
    "vms": {
        "unit": "virtual machines",
        "label": "virtual machines", "area": "virt", "run": q_vms,
        "words": ["vm", "vms", "virtual", "proxmox", "esxi", "vcenter",
                  "hypervisor", "guest", "guests", "lxc"],
        "help": "virtual machines and their hosts",
    },
}


def match(user, question: str) -> tuple[str, float]:
    """(query name, confidence 0-1). Ordinary code, no model involved.

    Confidence is the share of the question's meaningful words that the winning
    query claims. It is used to decide whether to trust the match or ask a model
    to route instead, so it needs to be a number, not a feeling.
    """
    from . import rbac
    words = [w for w in _words(question) if w not in STOP]
    if not words:
        return "", 0.0
    # A word shared by several queries says little; one that belongs to a single
    # query says a lot. Without this, "temperature of the servers" scored a tie
    # between the inventory (which owns "servers") and the BMC page (which owns
    # "temperature") and the winner was whichever came first in the catalogue.
    owners: dict = {}
    for spec in CATALOGUE.values():
        for w in spec["words"]:
            owners[w] = owners.get(w, 0) + 1

    # Words that qualify a request rather than name its subject. "connected"
    # appears in every connection query, so "list the connected clusters" and
    # "connected repos" were both decided by it instead of by the noun that
    # followed — which is the word that actually says what is wanted.
    MODIFIERS = {"connected", "connection", "connections", "integration",
                 "integrations", "configured", "setup", "status", "health",
                 "healthy", "unhealthy", "broken", "down", "available",
                 "existing", "current"}

    def weight(w: str) -> float:
        base = 1.0 / owners.get(w, 1)
        return base * 0.3 if w in MODIFIERS else base

    # Evidence from the question's *entities*, not just its vocabulary. "ip" is
    # claimed by services and by the inventory, and the tie-breaker is what else
    # is in the sentence: a serial or an address means a machine is being looked
    # up; a cluster name means the question is about a cluster.
    cid_hit, phrase = find_cluster(question)
    cluster_hit = bool(cid_hit)
    identifier = any(IDENTIFIER.match(w) for w in words)

    # Words spent naming the cluster must not also vote for a query. In
    # "traefik ip for ledger prod cluster" the trailing "cluster" belongs to
    # the cluster's name, but it also happens to be the clusters query's own
    # keyword — so that question started answering with a list of clusters.
    if phrase:
        spent = set(_words(phrase))
        raw = _words(question)
        for i, w in enumerate(raw):
            if w in ("cluster", "clusters", "k8s", "kubernetes") and (
                    (i and raw[i - 1] in spent)
                    or (i + 1 < len(raw) and raw[i + 1] in spent)):
                spent.add(w)
        words = [w for w in words if w not in spent]
        if not words:
            words = [w for w in _words(question) if w not in STOP]

    best, best_score = "", 0.0
    for name, spec in CATALOGUE.items():
        if not rbac.may_area(user, spec["area"]):
            continue
        score = 0.0
        for w in words:
            if w in spec["words"]:
                score += weight(w)
            elif any(w.rstrip("s") == v.rstrip("s") for v in spec["words"]):
                score += 0.5 * weight(w.rstrip("s") + "s")
            elif len(w) > 3:
                # a misspelling should still route: "pdos" and "clsuters" mean
                # what they obviously mean. Scored below an exact hit so a
                # correctly spelled word always wins a contest against a
                # near-miss.
                near = close(w, spec["words"], cutoff=0.72)
                if near:
                    score += 0.7 * weight(near)
        if cluster_hit and spec.get("cluster"):
            score += 0.8
        if identifier and spec.get("identifier"):
            score += 1.6
        if score > best_score:
            best, best_score = name, score
    return best, min(1.0, best_score / max(1.0, 0.6 * len(words)))


def _flat(rows: list, columns: list) -> list:
    """Every cell a string or number, never a container.

    A reader that returns a nested structure by mistake would otherwise render a
    Python dict into the table — which is exactly what happened with the fleet
    snapshot's {'total': 91, 'running': 91} pod counts. Catching it here means
    the next reader with the same slip produces something readable rather than
    something embarrassing.
    """
    out = []
    for r in rows:
        clean = {}
        for col in columns:
            v = r.get(col, "")
            if isinstance(v, dict):
                v = ", ".join(f"{k}={x}" for k, x in v.items())
            elif isinstance(v, (list, tuple, set)):
                v = ", ".join(str(x) for x in v)
            clean[col] = v
        out.append(clean)
    return out


def run(user, name: str, question: str, focus: str = "") -> dict:
    """Execute a query and return everything the page and the model need."""
    from . import rbac
    spec = CATALOGUE.get(name)
    if not spec:
        raise KeyError(name)
    if not rbac.may_area(user, spec["area"]):
        raise PermissionError(spec["area"])
    cid, phrase = find_cluster(question) if spec.get("cluster") else ("", "")
    got = spec["run"](user, question, cid, focus)
    scope = f" in cluster “{phrase}”" if phrase else ""
    return shape({"query": name, "label": spec["label"], "cluster": cid,
                  "cluster_phrase": phrase, "focus": got.get("focus", ""),
                  "time_field": got.get("time_field", ""),
                  "columns": got["columns"],
                  "rows": _flat(got["rows"], list(got["rows"][0].keys())
                                if got["rows"] else got["columns"]),
                  "count": len(got["rows"]),
                  # Whatever the query says it has already acted on, and what
                  # "none of them" means for the filter it applied. Both were
                  # being dropped here, which left shape() re-applying a word the
                  # query had consumed and every empty result reciting the same
                  # sentence — the two things setting them was meant to prevent.
                  "consumed": got.get("consumed") or [],
                  "empty": got.get("empty", ""),
                  "note": got["note"] + scope},
                 question)


def as_text(result: dict, limit: int = 40) -> str:
    """The result as compact text for a model to summarise. Deliberately small:
    this is what keeps the assistant usable without a GPU."""
    rows = result["rows"][:limit]
    lines = [f"Query: {result['query']} — {result['note']} "
             f"({result['count']} row(s)"
             + (f", showing {len(rows)}" if len(rows) < result["count"] else "")
             + ")"]
    if not rows:
        lines.append("(no rows matched)")
        return "\n".join(lines)
    lines.append(" | ".join(result["columns"]))
    for r in rows:
        lines.append(" | ".join(str(r.get(c, "")) for c in result["columns"]))
    return "\n".join(lines)


def capabilities(user) -> list[dict]:
    """What the assistant can answer, for the page and for a model's routing."""
    from . import rbac
    return [{"name": k, "label": v["label"], "help": v["help"]}
            for k, v in CATALOGUE.items() if rbac.may_area(user, v["area"])]


# ── the one-line answer, written by code ───────────────────────
# A model is not needed to say "traefik in ledger prod: cluster IP x, external
# y". Generating that sentence here makes it instant, always correct, and
# identical every time — and it means the assistant answers a direct question
# properly with no model configured at all. The model, when present, is left to
# do the thing code cannot: characterise a large result.
def _pick(row: dict, *cols) -> list:
    return [(c, str(row.get(c, "")).strip()) for c in cols
            if str(row.get(c, "")).strip()]


def headline(result: dict) -> str:
    """A short factual sentence about the rows, or "" when a table says it
    better."""
    rows, q, n = result["rows"], result["query"], result["count"]
    where = (f" in {result['cluster_phrase']}" if result.get("cluster_phrase")
             else "")
    if result.get("count_only") and rows:
        # "how many …" is answered with a number; the table is right there for
        # the detail
        thing = (CATALOGUE.get(q, {}).get("unit")
                 or result.get("label") or q)
        return f"{n} {thing}{where}."
    if not rows:
        # when the query explained the absence, that explanation IS the answer:
        # "nothing with status running — the values present are …" says more
        # than a generic "no pipeline is failing", which was simply wrong here
        # A query that knows what it filtered on knows what "none" means.
        if result.get("empty"):
            return result["empty"]
        note = result.get("note", "")
        # Any "nothing…" note, not just "nothing with": the provider filter
        # writes "nothing here is bitbucket — what is connected: jenkins", and
        # matching only the narrower prefix sent that straight past to the
        # canned line below, which then said "No pipeline is failing." — a
        # different claim, and a false one.
        if note.startswith(("nothing", "no ")):
            return note[0].upper() + note[1:] + "."
        # "nothing matched" is an answer and should be said as one
        return {
            "clusters": "No cluster is unreachable, missing a node, or running "
                        "unhealthy pods.",
            "pods": f"No pod needs attention{where}.",
            "repos": "No repository is configured yet.",
            "config": "No config file matches that.",
            "nodes": f"Every node is ready{where}.",
            "connections": "Every integration passed its last check.",
            "pipelines": "No pipeline is failing.",
            "gitops": "Every application is synced and healthy.",
            "workflows": "Nothing has failed recently.",
            "vms": "Every guest is running.",
        }.get(q, "")

    if q == "services":
        focus = (result.get("focus") or "").lower()

        def describe(r):
            bits = []
            if r.get("external ip"):
                bits.append(f"external {r['external ip']}")
            if r.get("cluster ip"):
                bits.append(f"cluster IP {r['cluster ip']}")
            ports = [x.strip() for x in str(r.get("ports", "")).split(",") if x.strip()]
            if ports:
                # a service can publish a dozen ports; three and a count is
                # readable, the full list is not
                shown = ", ".join(ports[:3])
                bits.append(f"ports {shown}"
                            + (f" and {len(ports) - 3} more" if len(ports) > 3 else ""))
            return f"{r['service']} ({r['type']}) — " + ", ".join(bits)

        # what was actually asked for: the service whose NAME matches, else
        # whatever is exposed outside, else the first rows
        primary = [r for r in rows if focus and focus in r["service"].lower()]
        if not primary:
            primary = [r for r in rows
                       if r["type"] in ("LoadBalancer", "NodePort")] or rows
        head = "; ".join(describe(r) for r in primary[:2])
        rest = n - len(primary[:2])
        if rest > 0:
            head += (f"; and {rest} more"
                     + (f" matching “{focus}”" if focus else " service"
                        + ("s" if rest != 1 else "")))
        return head + "."

    if q == "timeline":
        # "110 rows." is true and useless. What a reader wants from a change
        # stream is the mix and the newest thing in it.
        mix: dict = {}
        for r in rows:
            mix[r.get("kind", "?")] = mix.get(r.get("kind", "?"), 0) + 1
        parts = ", ".join(f"{c} {k}{'s' if c != 1 else ''}"
                          for k, c in sorted(mix.items(), key=lambda kv: -kv[1]))
        first = rows[0]
        latest = (f" Most recent: {first.get('what', '')}"
                  f"{' — ' + first['where'] if first.get('where') else ''}"
                  f", {first.get('ago', '')} ago.")
        return f"{n} change{'s' if n != 1 else ''} — {parts}.{latest}"

    if q == "databases":
        head = "; ".join(f"{r['server']} ({r['engine']}) at {r['address']}"
                         for r in rows[:3])
        rest = n - len(rows[:3])
        return (head + (f"; and {rest} more" if rest > 0 else "")
                + ". Reading them needs your own database login.")

    if q == "vpn":
        up = [r for r in rows if str(r.get("state", "")).startswith("up")]
        peers = sum(int(r.get("connected") or 0) for r in rows if r.get("peer") == "")
        portals = len({r.get("portal") for r in rows})
        return (f"{portals} VPN portal{'s' if portals != 1 else ''}, "
                f"{len(up)} up, {peers} peer{'s' if peers != 1 else ''} "
                f"connected.")

    if q == "certificates":
        def one(r):
            when = (f"expires {r['expires']}" if r["expires"] else "no expiry recorded")
            left = (f" ({r['days left']} days)"
                    if isinstance(r["days left"], int) else "")
            issued = f", issued by {r['issuer']}" if r["issuer"] else ""
            bad = "" if r["ready"] == "yes" else f", NOT ready — {r['reason'] or 'see the cluster'}"
            return f"{r['certificate']} {when}{left}{issued}{bad}"
        # sorted soonest-first, so the first rows are the ones that matter
        head = "; ".join(one(r) for r in rows[:3])
        rest = n - len(rows[:3])
        if rest > 0:
            head += f"; and {rest} more certificate" + ("s" if rest != 1 else "")
        return head + "."

    if q == "ingress":
        if n <= 6:
            return "; ".join(
                f"{r['host'] or r['ingress']}"
                + (f" → {r['service']}" if r.get("service") else "")
                + (f" at {r['address']}" if r.get("address") else "")
                for r in rows[:6]) + "."
        shown = ", ".join(r["host"] for r in rows[:5] if r.get("host"))
        return f"{n} host names{where}, including {shown}."

    if q == "assets" and n <= 4:
        out = []
        for r in rows[:4]:
            bits = _pick(r, "ip", "idrac / ilo ip", "serial", "model", "location")
            out.append(f"{r['hostname']}: "
                       + ", ".join(f"{k} {v}" for k, v in bits))
        return "; ".join(out) + "."
    if q == "assets":
        return f"{n} machines{where}."

    if q == "clusters":
        bad = [r for r in rows if r["reachable"] != "yes"
               or str(r.get("unhealthy pods", "0")) not in ("0", "")]
        head = f"{n} cluster{'s' if n != 1 else ''}: " + ", ".join(
            r["cluster"] for r in rows[:8])
        if len(rows) > 8:
            head += f" and {len(rows) - 8} more"
        if bad:
            head += " — needing attention: " + ", ".join(r["cluster"] for r in bad)
        return head + "."

    if q == "repos":
        return "; ".join(
            f"{r['project']} / {r['region']}: {r['repository']} ({r['branch']})"
            + (f", {r['services']} services" if r.get("services") else "")
            for r in rows[:4]) + ("." if n <= 4 else f"; and {n - 4} more.")

    if q == "config":
        if n <= 5:
            return "; ".join(f"{r['service']} in {r['environment']} → {r['link']}"
                             for r in rows) + "."
        return (f"{n} config files{where}; the closest are: "
                + ", ".join(f"{r['service']} ({r['environment']}) {r['link']}"
                            for r in rows[:3]) + ".")

    if q in {k for k, *_ in CONNECTION_KINDS}:
        unit = CATALOGUE[q]["unit"]
        bad = [r for r in rows if r["healthy"] != "yes"]
        head = f"{n} {unit}: " + ", ".join(
            f"{r['name']} ({r['type']})" for r in rows[:6])
        if n > 6:
            head += f" and {n - 6} more"
        if bad:
            head += " — not healthy: " + ", ".join(r["name"] for r in bad)
        return head + "."

    if q == "connections":
        bad = [r for r in rows if r["healthy"] != "yes"]
        head = f"{n} integration{'s' if n != 1 else ''}"
        if bad:
            head += ", " + str(len(bad)) + " not healthy: " + ", ".join(
                f"{r['name']} ({r['kind']})" for r in bad[:6])
        else:
            head += ", all healthy"
        return head + "."

    if q in ("pods", "nodes"):
        key = "pod" if q == "pods" else "node"
        bad = [r for r in rows
               if (q == "pods" and r["status"] not in ("Running", "Succeeded"))
               or (q == "nodes" and r.get("ready") != "yes")]
        head = f"{n} {key}{'s' if n != 1 else ''}{where}"
        if bad:
            head += f", {len(bad)} needing attention: " + ", ".join(
                f"{r.get('namespace', '')}/{r[key]}".strip("/") for r in bad[:6])
        else:
            head += ", all healthy"
        return head + "."

    if q in ("pipelines", "gitops", "workflows"):
        label = {"pipelines": "pipeline", "gitops": "application",
                 "workflows": "item"}[q]
        name_col = {"pipelines": "pipeline", "gitops": "application",
                    "workflows": "item"}[q]
        if n <= 3:
            out = []
            for r in rows[:3]:
                bits = [v for v in (r.get("status"), r.get("health"),
                                    (f"build {r['build']}" if r.get("build") else ""),
                                    r.get("started"), r.get("duration"),
                                    r.get("sync"), r.get("destination"),
                                    r.get("state"), r.get("when")) if v]
                out.append(f"{r.get(name_col, '')} — " + ", ".join(str(b) for b in bits))
            return "; ".join(out) + "."
        bad = [r for r in rows if str(r.get("status", r.get("health", ""))).lower()
               in ("failed", "failing", "degraded", "outofsync")]
        head = f"{n} {label}{'s' if n != 1 else ''}"
        if bad:
            head += f", {len(bad)} failing: " + ", ".join(
                str(r.get(name_col, "")) for r in bad[:5])
            if len(bad) > 5:
                head += f" and {len(bad) - 5} more"
        return head + "."

    if n <= 4:
        first = result["columns"][1] if len(result["columns"]) > 1 else result["columns"][0]
        return ", ".join(str(r.get(first, "")) for r in rows) + "."
    return f"{n} rows{where}."


# ── shaping an answer to the question that was asked ───────────
# The queries above decide WHICH data. This decides what to do with it, from the
# words in the question: which fields to show, how to order, whether one row is
# wanted rather than all of them, and whether the answer is a count.
#
# It exists because a fixed set of columns cannot anticipate the questions. Asked
# for "the last running pipeline", the assistant used to reply that the result
# did not include that detail — true, and useless, when the data was one sort
# away. Everything here is driven by the field names in the rows, so a
# deployment with different data answers different questions without a change.
# "just" is deliberately absent. It reads as a superlative in "it just ran" and
# as a narrowing word in "just the bitbucket pipelines" — and the second is far
# commoner in a question. Treating it as "most recent" silently reduced a
# forty-row answer to one row, which looked like a confident answer to a
# question nobody asked. "just now" still lands, on "now".
SUPERLATIVE_NEW = ("last", "latest", "newest", "recent", "recently", "current",
                   "currently", "now")
SUPERLATIVE_OLD = ("oldest", "first", "earliest", "longest")
COUNT_WORDS = ("how", "many", "count", "number", "total", "much")


def _requested_fields(question: str, keys: list) -> list:
    """Field names the question actually mentions, in the row's own vocabulary —
    so "build number", "duration" and "branch" pull those columns in, and a
    deployment whose data has other fields answers about those instead."""
    asked = [w for w in _words(question) if w not in STOP and len(w) > 2]
    hits = []
    for key in keys:
        tokens = [t for t in re.split(r"[^a-z0-9]+", key.lower()) if t]
        for w in asked:
            if w in tokens or close(w, tokens, cutoff=0.85):
                hits.append(key)
                break
    return hits


# Columns that hold a category rather than a measurement or a free-text name:
# which tool, which cluster, which namespace. A word in the question that is one
# of these values narrows to it.
CATEGORY_COLUMNS = ("provider", "connection", "platform", "engine", "tool",
                    "kind", "type", "cluster", "project", "namespace", "ca",
                    "source", "environment", "region")

# ── the vocabulary of things the portal integrates WITH ────────
# These are the words that must never be quietly ignored: each names a product,
# so a question containing one is asking about that product specifically. Asked
# for "bitbucket pipelines" against an estate whose only CI connection is
# Jenkins, the honest answer is "no Bitbucket connection is registered" — the
# answer that came back instead was a Jenkins pipeline, which is worse than
# none.
#
# WHY THIS IS READ OFF THE MODULES INSTEAD OF LISTED HERE
#     It was a hand-written list, and a hand-written list is wrong the day
#     somebody adds an integration. Measured against the real registries it was
#     already missing nine products a customer could name — pritunl, netmaker,
#     wg_easy, openvpn_as, vsphere, nfs, smb, s3 — so a site running Pritunl
#     would have hit the exact fault this mechanism exists to prevent, under a
#     different product name. Every provider table in the codebase is now the
#     source, so a new integration teaches the assistant about itself.
#
#     `assistant` is deliberately not read: its providers are the models the
#     portal calls, not systems it holds data about.
_VOCAB_MODULES = ("ci", "security", "logstore", "monitoring", "gitops",
                  "workflows", "virt", "bmc", "cloud", "stordev", "edge",
                  "dbconn", "vpn", "cbase", "sso")
_VOCAB_ATTRS = ("_IMPL", "_READERS", "_OVERVIEW", "PROVIDERS", "_PROVIDERS")

# Words that are a provider id somewhere but mean nothing as a filter. "http"
# and "other" are real storage and cloud types; treated as product names they
# would refuse perfectly good questions ("which http ingress…") on the grounds
# that no connection is called that.
_VOCAB_SKIP = {"other", "http", "https", "custom", "generic", "none", "manual",
               "file", "api", "default", "auto", "raw", "plain", "local"}

# Short forms and second names people type, mapped to the id the data holds.
# A MAPPING and not just extra words: "esxi" and "vsphere" are the same
# connection, so listing "esxi" as a bare product name would refuse "the esxi
# hosts" on an estate that has exactly that, on the grounds that every row says
# vsphere. An alias has to resolve, not merely be recognised.
PROVIDER_ALIASES = {
    "esxi": "vsphere", "vcenter": "vsphere", "vmware": "vsphere",
    "opensearch": "elasticsearch", "elastic": "elasticsearch",
    "postgresql": "postgres", "psql": "postgres",
    "argo": "argocd", "dojo": "defectdojo", "sonar": "sonarqube",
    "idrac": "redfish", "ilo": "redfish",
    # no alias: it names a protocol two different connection types speak, so
    # the honest reply is "what is connected: netmaker" rather than a guess
    "wireguard": "wireguard",
}


def _canonical(word: str) -> str:
    return PROVIDER_ALIASES.get(word, word)

_vocab: frozenset | None = None


def provider_words() -> frozenset:
    """Every product the portal can talk to, in the words a question uses.

    Computed once: the registries are module constants, and a connection can
    only ever hold a type one of them defines, so the live database adds
    nothing this does not already have.
    """
    global _vocab
    if _vocab is not None:
        return _vocab
    import importlib
    words = set(PROVIDER_ALIASES)
    for name in _VOCAB_MODULES:
        try:
            mod = importlib.import_module(f".{name}", __package__)
        except Exception:                                      # noqa: BLE001
            continue                       # a module that will not import here
        for attr in _VOCAB_ATTRS:                              # is not fatal
            table = getattr(mod, attr, None)
            keys: list = []
            if isinstance(table, dict):
                keys = list(table)
            elif isinstance(table, (list, tuple)):
                keys = [it.get("id") or it.get("key") or it.get("type")
                        for it in table if isinstance(it, dict)]
            for key in keys:
                if not isinstance(key, str) or not key.strip():
                    continue
                key = key.strip().lower()
                words.add(key)
                words.add(re.sub(r"[^a-z0-9]", "", key))
                # "openvpn_as" is asked about as "openvpn". Only the first
                # token, and only when it is long enough to be a name: the
                # second half of "wg_easy" is the word "easy", which would
                # refuse every question containing it.
                head = re.split(r"[^a-z0-9]", key)[0]
                if len(head) >= 4:
                    words.add(head)
    _vocab = frozenset(w for w in words
                       if len(w) > 2 and w not in _VOCAB_SKIP)
    return _vocab


def _narrow_category(result: dict, rows: list, question: str) -> tuple:
    """Narrow to a product or place the question named, or say it is not here.

    Matching is EXACT against values actually present, never fuzzy: a categorical
    filter that guesses is worse than one that does not fire, because "prod"
    quietly matching a namespace called "production" is indistinguishable from a
    real answer. The provider vocabulary is the exception that must always be
    resolved one way or the other — see PROVIDER_WORDS.
    """
    if not rows:
        return result, rows
    asked = [w for w in _words(question) if len(w) > 2]
    if not asked:
        return result, rows
    keys = list(rows[0].keys())
    cols = [c for c in keys if c.lower() in CATEGORY_COLUMNS]
    satisfied = set()

    # What each asked word could legitimately match: itself, the id it is an
    # alias for, and the singular of either — "builds" should match a kind
    # recorded as "build". Still an exact match against a value that is really
    # there; only the plural and the alias are folded, never the meaning.
    forms: dict = {}
    for w in asked:
        cands = {w, _canonical(w)}
        for c in list(cands):
            if len(c) > 3 and c.endswith("s"):
                cands.add(c[:-1])
        forms[w] = cands

    for col in cols:
        live = {str(r.get(col, "")).strip().lower() for r in rows}
        live.discard("")
        word, hit = "", ""
        for w in asked:
            found = next((c for c in forms[w] if c in live), "")
            if found:
                word, hit = w, found
                break
        if not hit:
            continue
        # The word IS one of this column's values, so the constraint is met —
        # even when it selects everything. Treating "all of them match" as "no
        # match" is what made "jenkins pipelines" answer "nothing here is
        # jenkins" on an estate where every pipeline is Jenkins.
        satisfied.add(word)
        narrowed = [r for r in rows
                    if str(r.get(col, "")).strip().lower() == hit]
        if narrowed and len(narrowed) < len(rows):
            rows = narrowed
            result = {**result, "note": f"{result.get('note', '')}, {hit}"}

    # A product was named, and nothing here is it. Do not fall through to the
    # unfiltered answer — that is the failure this whole function exists for.
    vocab = provider_words()
    missing = [w for w in asked if w in vocab and w not in satisfied]
    if missing and cols:
        # what IS here, named in the vocabulary the question used: the provider
        # column if there is one, because "jenkins" answers "why not bitbucket"
        # and a connection's display name does not
        prefer = [c for c in cols if c.lower() in ("provider", "platform",
                                                   "engine", "type", "kind")]
        present = sorted({str(r.get(c, "")).strip()
                          for c in (prefer or cols) for r in rows
                          if str(r.get(c, "")).strip()})
        return ({**result,
                 "note": f"nothing here is {missing[0]} — what is connected: "
                         + ", ".join(present[:8])}, [])
    return result, rows


# A state named in the question narrows to it: "running", "failed",
# "succeeded", "pending". Only columns that hold a state are considered, so
# "prod" cannot accidentally filter a branch name, and the values come from
# the data — a provider with its own vocabulary works without changes here.
STATE_COLUMNS = ("status", "state", "healthy", "health", "reachable",
                 "ready", "sync", "power", "phase")
# Words that name a state wherever they appear. Listed because a state the
# data does not currently contain still has to be recognised: asked for "the
# last RUNNING pipeline" when none is running, the honest answer is "none
# is", not the most recent successful one — which is what it used to give.
STATE_WORDS = {"running", "failed", "failing", "success", "successful",
               "succeeded", "passing", "pending", "queued", "cancelled",
               "canceled", "aborted", "unknown", "healthy", "unhealthy",
               "degraded", "missing", "unreachable", "reachable", "ready",
               "notready", "stopped", "off", "on", "synced", "outofsync",
               "progressing", "terminating", "crashloopbackoff"}
# Some columns answer yes/no, and the word people use is the CONDITION
# rather than the value: "unreachable" means reachable=no. No amount of
# prefix or fuzzy matching bridges that — "unre" against "yes" is not a near
# miss, it is a different question — so the pairing is written down.
BOOL_VALUES = {"yes", "no", "true", "false"}
BOOL_WORDS = {"unreachable": "no", "reachable": "yes",
              "notready": "no", "ready": "yes",
              "unhealthy": "no", "healthy": "yes",
              "off": "no", "on": "yes", "stopped": "no"}


def shape(result: dict, question: str) -> dict:
    """Order, narrow and re-column a result according to the question."""
    rows = result.get("rows") or []
    if not rows:
        return result
    # Split once. This used to be recomputed at four points in the function,
    # including inside a per-column loop.
    qwords = _words(question)
    asked = set(qwords)
    keys = list(rows[0].keys())
    time_field = result.get("time_field") or ""

    done = {str(w).lower() for w in (result.get("consumed") or ())}
    for col in [c for c in keys if c.lower() in STATE_COLUMNS]:
        live = {str(r.get(col, "")).strip().lower() for r in rows}
        live.discard("")
        wanted = [w for w in qwords
                  if w in STATE_WORDS and len(w) > 2 and w not in done]
        if live <= BOOL_VALUES:
            wanted = [BOOL_WORDS.get(w, w) for w in wanted]
        if not wanted:
            continue
        for w in wanted:
            hit = w if w in live else ""
            if not hit and len(w) >= 4:
                hit = next((v for v in sorted(live) if v[:4] == w[:4]), "")
            if not hit:
                hit = close(w, live, cutoff=0.72)
            if hit:
                narrowed = [r for r in rows
                            if str(r.get(col, "")).strip().lower() == hit]
                if narrowed and len(narrowed) < len(rows):
                    rows = narrowed
                    result = {**result, "note": f"{result['note']}, {hit}"}
                break
            # a state that exists nowhere in this result
            rows = []
            result = {**result,
                      "note": f"nothing with {col} “{w}” — the values present "
                              f"are: " + ", ".join(sorted(live)[:6])}
            break
        break

    # Which product, which cluster, which namespace — applied before any
    # superlative, so "the last bitbucket build" means the last of the
    # Bitbucket ones rather than the last of all of them.
    result, rows = _narrow_category(result, rows, question)
    if not rows:
        return {**result, "rows": [], "count": 0,
                "columns": list(result.get("columns") or keys)}

    # "the last one that ran", "the most recent build"
    newest = bool(asked & set(SUPERLATIVE_NEW))
    oldest = bool(asked & set(SUPERLATIVE_OLD))
    if time_field and time_field in keys and (newest or oldest):
        have = [r for r in rows if str(r.get(time_field) or "").strip()]
        if have:
            have.sort(key=lambda r: str(r.get(time_field)), reverse=newest)
            # "the last" means one; "the last 5" means five
            n = 1
            for w in qwords:
                if w.isdigit() and 1 < int(w) <= 50:
                    n = int(w)
                    break
            rows = have[:n]
            result = {**result,
                      "note": result["note"] + (" — most recent" if newest
                                                else " — oldest")}

    # a count is an answer, not a table
    wants_count = len(asked & set(COUNT_WORDS)) >= 1 and "many" in asked
    columns = list(result.get("columns") or keys)
    extra = [k for k in _requested_fields(question, keys)
             if k not in columns and not k.endswith("_at")]
    if extra:
        columns = columns[:2] + extra + [c for c in columns[2:] if c not in extra]
    columns = [c for c in columns if not c.endswith("_at")]

    return {**result, "rows": rows, "count": len(rows), "columns": columns,
            "count_only": wants_count}


# ── the things the portal is connected TO, per kind ────────────
# "give me the list of connected repos / clouds / gitops tools" all fell through
# to one combined integrations table, because the catalogue had no entry for any
# of them. These are generated from one table: a new integration kind becomes
# answerable by adding a row, not by writing a query.
CONNECTION_KINDS = [
    ("cloud_accounts", "cloud accounts", "clouds", "all_cloud",
     ["cloud", "clouds", "aws", "azure", "gcp", "alibaba", "account",
      "accounts", "subscription", "tenant"]),
    ("storage_devices", "storage devices", "storage", "all_stor",
     ["storage", "nas", "synology", "truenas", "minio", "backup", "backups",
      "share", "shares", "s3", "nfs", "smb"]),
    ("gitops_tools", "GitOps controllers", "gitops", "all_gitops",
     ["argocd", "argo", "flux", "controller", "controllers", "tool", "tools"]),
    ("workflow_engines", "workflow engines", "workflows", "all_wf",
     ["temporal", "airflow", "engine", "engines"]),
    ("bmcs", "server BMCs", "bmc", "all_bmc",
     ["idrac", "ilo", "bmc", "bmcs", "redfish", "outofband"]),
    ("hypervisors", "hypervisors", "virt", "all_virt",
     ["proxmox", "esxi", "vcenter", "vsphere", "hypervisor", "hypervisors"]),
    ("ci_servers", "CI servers", "pipelines", "all_ci",
     ["jenkins", "bitbucket", "gitlab", "cicd", "ci"]),
    ("log_stores", "log stores", "logs", "all_log",
     ["elk", "elasticsearch", "opensearch", "loki", "logstore", "logstores",
      "log", "logs", "logging"]),
    ("monitoring_systems", "monitoring systems", "monitoring", "all_mon",
     ["prometheus", "grafana", "zabbix", "alertmanager", "monitoring",
      "monitor", "alerting", "system", "systems"]),
    ("scanners", "scan platforms", "security", "all_sec",
     ["defectdojo", "sonarqube", "sonar", "dependencytrack", "scanner",
      "scanners", "scanning", "vulnerability", "vulnerabilities",
      "wazuh", "siem", "agent", "agents", "xdr"]),
]


def _connection_query(unit: str, getter: str):
    """One query over one kind of connection, honest when none is configured."""
    def run(user, question: str, cid: str, focus: str = "") -> dict:
        from . import store
        rows = []
        for c in getattr(store, getter)():
            st = c.get("status") or ""
            healthy = st.startswith("ok") or st.startswith("connected")
            rows.append({
                "name": c.get("name"), "type": c.get("type"),
                "address": c.get("base_url") or c.get("cluster") or "",
                "healthy": "yes" if healthy else ("NO" if st else "not checked"),
                "last check": st[:120]})
        rows.sort(key=lambda r: (r["healthy"] == "yes", str(r["name"])))
        note = unit
        if not rows:
            # the difference between "none of them are healthy" and "none are
            # configured" matters, and conflating them produced a cheerful
            # "every application is synced and healthy" when nothing was set up
            note = f"no {unit} are connected — add one in Settings"
        return {"columns": ["name", "type", "address", "healthy", "last check"],
                "rows": rows, "note": note}
    return run


for _key, _unit, _area, _getter, _words_ in CONNECTION_KINDS:
    CATALOGUE[_key] = {
        "unit": _unit, "label": _unit, "area": _area,
        "run": _connection_query(_unit, _getter),
        "words": _words_ + ["connected", "connection", "connections",
                            "integration", "integrations", "configured"],
        "help": f"the {_unit} this portal is connected to, and whether each "
                "answered its last check",
    }


# ── the GitOps repositories the portal edits ───────────────────
def q_repos(user, question: str, cid: str, focus: str = "") -> dict:
    """The git repositories behind each region's environments — the ones
    config edits land in.

    A repository is not an "integration": it is an environment's source of
    truth, with a branch, a path and a working copy that can be behind. It had
    no query at all, so "the list of connected repos" answered with
    integrations.

    Grouped by (region, resolved repository, branch) rather than one row per
    region: an environment may declare its own repository and branch, so a
    region with no default of its own still shows up here through whichever
    environment carries one, and one whose environments split across two
    repositories reports both rather than only the region's.
    """
    from . import git_ops, rbac, repo as repolib
    from . import store
    visible = rbac.visible_projects(user)
    groups: dict[tuple, dict] = {}
    for pid, p in store.projects().items():
        if visible is not None and pid not in visible:
            continue
        for rgid, rg in (p.get("regions") or {}).items():
            try:
                envs = repolib.list_envs(pid, rgid)
            except Exception:                                 # noqa: BLE001
                envs = {}
            for env, files in envs.items():
                b = repolib.binding(pid, rgid, env)
                if not b["url"]:
                    continue
                key = (rgid, b["url"], b["branch"])
                g = groups.setdefault(key, {
                    "project": p.get("name", pid), "region": rg.get("name", rgid),
                    "repository": b["url"], "branch": b["branch"],
                    "own_credentials": b["has_own_auth"], "envs": [],
                    "services": 0, "pid": pid, "rgid": rgid})
                g["envs"].append(env)
                g["services"] += len(files)
    rows = []
    for g in groups.values():
        try:
            st = git_ops.region_status(g["pid"], g["rgid"], check_remote=False,
                                       env=g["envs"][0]) or {}
        except Exception:                                     # noqa: BLE001
            st = {}
        rows.append({
            "project": g["project"], "region": g["region"],
            "repository": g["repository"], "branch": g["branch"] or st.get("branch") or "",
            "environments": ", ".join(sorted(g["envs"])),
            "services": g["services"],
            "own credentials": "yes" if g["own_credentials"] else "region's",
            "uncommitted": st.get("dirty") if st.get("dirty") is not None else ""})
    rows.sort(key=lambda r: (r["project"], r["region"], r["repository"]))
    note = "GitOps repositories, by what each environment actually reads from"
    if not rows:
        note = ("no environment is declared anywhere — declare one from a "
                "cluster's own form in Settings → Kubernetes clusters")
    return {"columns": ["project", "region", "repository", "branch",
                        "environments", "services", "own credentials",
                        "uncommitted"],
            "rows": rows, "note": note}


# ── the config files themselves, with a link to edit each ──────
def q_config(user, question: str, cid: str, focus: str = "") -> dict:
    """Every service's values file, and the link that opens it for editing.

    "give me a direct link to edit the config for payments in eu staging" is the
    portal's own core feature, and it had no query — the question was answered
    with a pod list. Environments and file names come from the working copies,
    so any repository layout works.
    """
    from . import rbac, repo as repolib
    from . import store
    visible = rbac.visible_projects(user)
    wanted_env = ""
    rows = []
    for pid, p in store.projects().items():
        if visible is not None and pid not in visible:
            continue
        for rgid, rg in (p.get("regions") or {}).items():
            try:
                envs = repolib.list_envs(pid, rgid)
            except Exception:                                 # noqa: BLE001
                continue
            for env, files in envs.items():
                for fname in files:
                    rows.append({
                        "project": p.get("name", pid),
                        "region": rg.get("name", rgid),
                        "environment": env,
                        "service": repolib.service_display(fname),
                        "file": fname,
                        "link": f"/p/{pid}/{rgid}/{env}/s/{fname}"})

    # scope by environment or region words that exist in the rows, the same way
    # the inventory scopes itself
    asked = [w for w in _words(question) if w not in STOP]
    for field in ("environment", "region", "project"):
        live = {str(r[field]).lower() for r in rows if r[field]}
        for w in asked:
            hit = w if w in live else next(
                (v for v in sorted(live) if w in v.split() or v.startswith(w)), "")
            if hit:
                narrowed = [r for r in rows if str(r[field]).lower() == hit]
                if narrowed:
                    rows = narrowed
                    wanted_env = f"{field} {hit}" if not wanted_env else \
                        f"{wanted_env}, {field} {hit}"
                break

    rows, term, suggestions = _name_filter(question, rows,
                                          ("service", "file"), focus)
    note = "config files"
    if term and rows:
        note = f"config for “{term}”"
    elif term:
        note = f"no config file matching “{term}”"
        if suggestions:
            note += " — closest: " + ", ".join(suggestions[:5])
    if wanted_env:
        note += f" — {wanted_env}"
    rows.sort(key=lambda r: (r["project"], r["region"], r["environment"],
                            r["service"]))
    return {"columns": ["project", "region", "environment", "service", "file",
                        "link"],
            "rows": rows, "note": note, "focus": term}


CATALOGUE["repos"] = {
    "unit": "repositories", "label": "GitOps repositories", "area": "config",
    "run": q_repos,
    "words": ["repo", "repos", "repository", "repositories", "git", "bitbucket",
              "github", "gitlab", "branch", "branches", "clone", "checkout"],
    "help": "the git repositories behind each region, their branch and whether "
            "the working copy has uncommitted changes",
}
CATALOGUE["config"] = {
    "unit": "config files", "label": "service configuration", "area": "config",
    "run": q_config, "identifier": False,
    "words": ["config", "configs", "configuration", "values", "valuesfile",
              "yaml", "edit", "editing", "link", "url", "chart", "helm",
              "service", "services", "microservice", "microservices"],
    "help": "the values file for each service in each environment, with a link "
            "that opens it for editing",
}


# ── certificates and their expiry ──────────────────────────────
def q_certs(user, question: str, cid: str, focus: str = "") -> dict:
    """cert-manager certificates: what they cover, who issued them, when they
    expire. The data was already read for the cluster pages; there was simply no
    query, so "list the certificates" was answered with ingress host names."""
    from . import cluster as clusterview
    from . import fleet
    recs = _cluster_records(user, cid)
    rows, missing = [], []
    for got in fleet._pmap(lambda c: (c, clusterview.part(c, "certs")), recs,
                           workers=min(6, max(1, len(recs)))) or []:
        if not got:
            continue
        c, part = got
        if not part.get("present"):
            missing.append(c.get("name", ""))
            continue
        for cert in part.get("certs") or []:
            days = cert.get("days")
            rows.append({
                "cluster": c.get("name"), "namespace": cert["namespace"],
                "certificate": cert["name"],
                "expires": (cert.get("not_after") or "")[:10],
                "days left": days if days is not None else "",
                "ready": "yes" if cert["ready"] else "NO",
                "issuer": cert.get("issuer", ""),
                "covers": ", ".join(cert.get("dns") or []),
                "reason": cert.get("reason", ""),
                "not_after": cert.get("not_after", "")})
    rows, term, suggestions = _name_filter(
        question, rows, ("certificate", "covers", "namespace", "issuer"), focus)
    # soonest to expire first: that is the only ordering anyone wants here
    rows.sort(key=lambda r: (r["days left"] if isinstance(r["days left"], int)
                             else 99999))
    # "expiring in the next 30 days" is a threshold, and answering it with every
    # certificate sorted by date is not the same answer.
    window = re.search(r"(?:next|within|under|less than|in)\s+(\d{1,4})\s*"
                       r"(day|days|week|weeks|month|months)", question.lower())
    horizon = ""
    if window:
        n = int(window.group(1))
        days = n * {"day": 1, "week": 7, "month": 30}[window.group(2).rstrip("s")]
        rows = [r for r in rows
                if isinstance(r["days left"], int) and r["days left"] <= days]
        horizon = f" expiring within {days} days"
    note = "certificates" + horizon
    if term and rows:
        note = f"certificates matching “{term}”"
    elif term:
        note = f"no certificate matching “{term}”"
        if suggestions:
            note += " — closest: " + ", ".join(suggestions[:5])
    elif not rows and missing:
        note = ("cert-manager is not installed on "
                + ", ".join(missing[:4])
                + " — nothing issues certificates there")
    soon = [r for r in rows if isinstance(r["days left"], int) and r["days left"] <= 30]
    if soon and not term and not horizon:
        note += f" — {len(soon)} expiring within 30 days"
    return {"columns": ["cluster", "namespace", "certificate", "expires",
                        "days left", "ready", "issuer", "covers"],
            "rows": rows, "note": note, "focus": term,
            "time_field": "not_after"}


# ── what changed recently, from every system at once ───────────
def q_timeline(user, question: str, cid: str, focus: str = "") -> dict:
    """The change stream behind /timeline, as a table.

    Deliberately reuses timeline.collect rather than re-reading the sources: a
    second implementation of "what changed" would drift from the page, and the
    clock normalisation there is the hard part.
    """
    from . import timeline as tl
    hours = 24
    for w in _words(question):
        if w.isdigit() and 0 < int(w) <= tl.MAX_HOURS:
            hours = int(w)
            break
    if _flag(question, "week"):
        hours = 24 * 7
    elif _flag(question, "hour", "now", "just"):
        hours = 1
    got = tl.collect(user, hours=hours)
    rows = [{"when": f"{e['day']} {e['time']}", "ago": e["ago"],
             "kind": e["kind"], "what": e["what"], "where": e["where"],
             "who": e["who"], "status": e["status"], "detail": e["detail"],
             "changed_at": e["at"].strftime("%Y-%m-%d %H:%M:%S")}
            for e in got["events"]]
    note = f"changes in the last {hours} hour{'s' if hours != 1 else ''}"
    if got["idle"]:
        note += f" (not connected: {', '.join(got['idle'])})"
    return {"columns": ["when", "ago", "kind", "what", "where", "who", "status"],
            "rows": rows, "note": note, "time_field": "changed_at"}


CATALOGUE["timeline"] = {
    "unit": "changes",
    "label": "recent changes", "area": "timeline", "run": q_timeline,
    "words": ["change", "changes", "changed", "timeline", "history",
              "happened", "recently", "activity", "who", "when", "broke",
              "before", "deployed", "pushed"],
    "help": "everything that changed recently — commits, deployments, builds, "
            "cluster events, alerts and portal actions on one clock",
}


# ── what runs out, and when ────────────────────────────────────
def q_expiry(user, question: str, cid: str, focus: str = "") -> dict:
    """The radar behind /expiry, as a table.

    Reuses expiry.collect rather than re-reading the sources: a second answer
    to "what expires" that disagreed with the page would be worse than none.
    """
    from . import expiry as radar
    horizon = 0
    for w in _words(question):
        if w.isdigit() and 0 < int(w) <= 3650:
            horizon = int(w)
            break
    if _flag(question, "week"):
        horizon = 7
    elif _flag(question, "month"):
        horizon = 30
    # "what needs renewing" is a question about work, not about dates
    manual = _flag(question, "manual", "renew", "renewing", "renewal",
                   "action", "do", "need", "needs")
    got = radar.collect(user, horizon=horizon,
                        renewal=radar.MANUAL if manual else "")
    rows = [{"expires": r["on"], "when": radar.days_word(r["days"]),
             "what": r["name"], "kind": r["kind"], "where": r["where"],
             "renews": ("itself" if r["renewal"] == radar.AUTOMATIC
                        else "needs a person" if r["renewal"] == radar.MANUAL
                        else "unknown"),
             "detail": r["detail"], "expires_at": r["on"]}
            for r in got["rows"]]
    note = "everything with an expiry date"
    if horizon:
        note = f"expiring within {horizon} day{'s' if horizon != 1 else ''}"
    if manual:
        note += ", needing a person"
    s = got["summary"]
    if s["expired"]:
        note += f" — {s['expired']} already expired"
    return {"columns": ["expires", "when", "what", "kind", "where", "renews"],
            "rows": rows, "note": note, "time_field": "expires_at"}


CATALOGUE["expiry"] = {
    "unit": "things",
    "label": "expiring things", "area": "expiry", "run": q_expiry,
    "words": ["expire", "expires", "expiring", "expiry", "expired", "renew",
              "renewal", "renewals", "renewing", "warranty", "warranties",
              "overdue", "lapsed", "due", "runs", "out", "soon"],
    "help": "everything that runs out — certificates, warranties, "
            "subscriptions and licences — and which of them nothing renews",
}


# ── who did what in the portal itself ──────────────────────────
def q_audit(user, question: str, cid: str, focus: str = "") -> dict:
    from . import auth
    rows = [{"when": r.get("at", "").replace("T", " "),
             "who": r.get("user", ""), "action": r.get("action", ""),
             "target": r.get("target", ""), "detail": r.get("detail", ""),
             "from": r.get("ip", ""), "when_at": r.get("at", "")}
            for r in auth.read_audit(300)]
    return {"columns": ["when", "who", "action", "target", "detail", "from"],
            "rows": rows, "note": "portal audit trail",
            "time_field": "when_at"}


CATALOGUE["audit"] = {
    "unit": "entries",
    "label": "audit trail", "area": "audit", "run": q_audit,
    "words": ["audit", "who", "did", "sealed", "pushed", "signin", "signed",
              "trail", "log", "logged", "action", "actions", "changed"],
    "help": "who did what in the portal, and from where",
}


# ── subscriptions, renewals and what IT costs ──────────────────
def q_spend(user, question: str, cid: str, focus: str = "") -> dict:
    from . import spend
    soon_only = _flag(question, "renew", "renewing", "renewal", "renewals",
                      "expiring", "expires", "due", "soon")
    rows = []
    for s in spend.search(status="all", sort="renews"):
        state = spend.renewal_state(s.get("renews"), s.get("status", ""),
                                    s.get("cycle", ""))
        if soon_only and state["state"] not in ("soon", "expired"):
            continue
        rows.append({"item": s.get("name", ""), "vendor": s.get("vendor", ""),
                     "category": s.get("category", ""),
                     "cycle": s.get("cycle", ""),
                     "cost": f"{s.get('currency', '')} {s.get('amount', '')}".strip(),
                     "per year": f"{spend.display_currency()} "
                                 f"{round(s.get('base_yearly') or 0):,}",
                     "renews": s.get("renews", "") or "",
                     "state": state["label"], "status": s.get("status", ""),
                     "renews_at": s.get("renews") or ""})
    if not rows and not soon_only:
        return {"columns": ["item"], "rows": [],
                "note": "no subscriptions or licences have been recorded"}
    return {"columns": ["item", "vendor", "category", "cost", "per year",
                        "renews", "state"],
            "rows": rows,
            "note": ("no renewal is due soon" if soon_only and not rows
                     else "renewals due" if soon_only
                     else "subscriptions and licences"),
            "time_field": "renews_at"}


CATALOGUE["spend"] = {
    "unit": "subscriptions",
    "label": "IT spend", "area": "spend", "run": q_spend,
    "words": ["spend", "cost", "costs", "subscription", "subscriptions",
              "licence", "licences", "license", "renewal", "renewals",
              "renew", "renewing", "invoice", "vendor", "vendors", "billing",
              "expensive", "budget"],
    "help": "subscriptions and licences, what they cost and when they renew",
}


# ── VPN tunnels and who is on them ─────────────────────────────
def q_vpn(user, question: str, cid: str, focus: str = "") -> dict:
    from . import store, vpn
    conns = store.all_vpn()
    # "none are connected" and "none are up" are different answers, and only
    # one of them is about the tunnels
    if not conns:
        return {"columns": ["portal"], "rows": [],
                "note": "no VPN portal is connected to this portal yet"}
    rows = []
    for got in vpn.read_all(conns):
        c, data, err = got["conn"], got["data"], got["error"]
        if err or data is None:
            rows.append({"portal": c.get("name", ""),
                         "type": c.get("type", ""), "state": f"error: {err}",
                         "tunnels": "", "connected": "", "peer": ""})
            continue
        peers = data.get("peers") or []
        if not peers:
            rows.append({"portal": c.get("name", ""), "type": c.get("type", ""),
                         "state": "up", "tunnels": len(data.get("tunnels") or []),
                         "connected": data.get("connected", 0), "peer": ""})
        for p in peers:
            rows.append({"portal": c.get("name", ""), "type": c.get("type", ""),
                         "state": "up", "tunnels": len(data.get("tunnels") or []),
                         "connected": data.get("connected", 0),
                         "peer": p.get("name") or p.get("user")
                                 or p.get("id") or ""})
    return {"columns": ["portal", "type", "state", "tunnels", "connected",
                        "peer"],
            "rows": rows, "note": "VPN portals"}


CATALOGUE["vpn"] = {
    "unit": "VPN portals",
    "label": "VPN", "area": "vpn", "run": q_vpn,
    "words": ["vpn", "tunnel", "tunnels", "wireguard", "ipsec", "openvpn",
              "fortigate", "connected", "remote", "dialup"],
    "help": "VPN portals, which tunnels are up and who is connected",
}


# ── database servers the portal knows about ────────────────────
def q_databases(user, question: str, cid: str, focus: str = "") -> dict:
    """The registered servers, not their contents. The console asks for
    credentials per session and stores none, so there is nothing here to read
    without them — and an assistant must not be the thing that prompts for a
    database password."""
    from . import dbconn, store
    servers = store.all_db()
    if not servers:
        return {"columns": ["server"], "rows": [],
                "note": "no database server is registered"}
    rows = [{"server": c.get("name", ""), "engine": c.get("type", ""),
             "address": f"{c.get('host', '')}:{dbconn.port_of(c)}",
             "environment": c.get("env", "") or c.get("environment", ""),
             "note": c.get("note", "")}
            for c in servers]
    return {"columns": ["server", "engine", "address", "environment", "note"],
            "rows": rows,
            "note": "registered database servers — contents need your own "
                    "database login, which the portal never stores"}


CATALOGUE["databases"] = {
    "unit": "database servers",
    "label": "databases", "area": "db", "run": q_databases,
    "words": ["database", "databases", "db", "postgres", "postgresql",
              "mysql", "mariadb", "couchbase", "sql", "schema", "server"],
    "help": "which database servers are registered and where they are",
}


CATALOGUE["certificates"] = {
    "unit": "certificates", "label": "certificates", "area": "clusters",
    "run": q_certs, "cluster": True,
    "words": ["certificate", "certificates", "cert", "certs", "tls", "ssl",
              "expiry", "expires", "expiring", "expiration", "issuer",
              "letsencrypt", "certmanager", "renewal", "renew"],
    "help": "cert-manager certificates with their expiry date, issuer and the "
            "host names they cover",
}


# ── coverage: a new page must not be invisible to the assistant ──
# Every area in rbac.AREAS is either answerable here or listed below with the
# reason it is not. Nothing may be merely forgotten, which is what happened to
# the Timeline: it shipped as a page the assistant had never heard of, so
# "what changed today" fell through to whichever query claimed the most words.
# tests/test_answers.py fails when an area is in neither set, so adding a page
# forces the decision rather than deferring it indefinitely.
NOT_ANSWERABLE = {
    "settings": "holds credentials and connection secrets — a question must "
                "never be a way to read them back out",
    "users": "accounts and personal data; the audit trail answers "
             "“who did what” without listing people",
    "manage": "an action surface, not data — the assistant reads, it does not "
              "restart or drain anything",
    "ansible_run": "an action surface, not data. The runs themselves ARE "
                   "answerable (see the ansible entry) — starting one is not "
                   "something a question may do",
    "pam": "the privileged-access catalogue and its session recordings — which "
           "machines are reachable, who connected, and what a screen showed. "
           "Sensitive by nature; a question must not be a way to enumerate "
           "targets or read a recording back",
    # The token register is a list of this portal's own machine credentials —
    # who could be asking, from where, with which door still open. Letting a
    # model enumerate that is letting a model case the building, and the
    # question is answered perfectly well by a page a person has to open.
    "mcp": "the register of AI-client tokens — who holds a machine credential "
           "for this portal and when it was last used. A question must not be "
           "a way to enumerate the doors into it; Settings → AI clients shows "
           "it to a person",
    "pam_connect": "an action surface, not data — opening a live shell or "
                   "desktop, or deleting a recording, is not something a "
                   "question may do",
    "terraform": "the Terraform stacks and their runs — the .tf can reference "
                 "secrets and a stack holds a sealed provider credential; "
                 "answerable coverage still needs a shape of its own, so it is "
                 "out for now",
    "terraform_apply": "an action surface, not data — running init, plan, apply "
                       "or destroy is not something a question may do",
    "assistant": "the assistant's own settings — which provider it calls and "
                 "what it may read. Answerable from here it would be a way to "
                 "ask what it is allowed to be asked",
    "edge": "not yet — zones, DNS records and cache state are read per "
            "connection and need a shape that spans providers",
    "certs": "not yet — the certificates query answers cert-manager, and the "
             "portal's own ACME orders still need an entry of their own",
}


def coverage() -> dict:
    """Which areas the assistant can answer, and which are declared out.

    -> {"covered": {...}, "declared": {...}, "missing": {...}}
    `missing` must always be empty; the test is what keeps it that way.
    """
    from . import rbac
    covered = {v.get("area") for v in CATALOGUE.values() if v.get("area")}
    declared = set(NOT_ANSWERABLE)
    every = set(rbac.AREAS)
    return {"covered": covered & every, "declared": declared & every,
            "missing": every - covered - declared}
