"""Workflow engines: Temporal, Airflow, and anything else that runs long jobs.

WHY THESE BELONG IN A PLATFORM CONSOLE
    A workflow engine is where the business logic that outlives a request goes —
    payment retries, reconciliations, nightly batches. When one is stuck, the
    symptom shows up in a support queue rather than in a cluster metric, so the
    portal reads the two facts that matter: what is running, and what has failed
    recently.

READ-ONLY, INCLUDING NO TERMINATE BUTTON
    Cancelling or terminating a workflow is a business action with consequences
    the portal cannot see (a half-finished payment is not a half-finished pod).
    Both tools have their own UI for that, one click from every row here.

TEMPORAL'S API, HONESTLY
    Temporal's own protocol is gRPC, which the standard library cannot speak. But
    every Temporal deployment that has a web UI also runs the UI server, and that
    serves a plain HTTP/JSON API — the same one the UI itself calls. So the
    connection points at the UI's address, and the note in PROVIDERS says so
    rather than letting someone paste the gRPC port and wonder why it fails.
"""
import json
import ssl
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
CACHE_TTL = 45

PROVIDERS = {
    "temporal": {
        "label": "Temporal",
        "icon": "⏱",
        "url_hint": "https://temporal-ui.example.com  (the web UI address)",
        "needs": ["base_url"],
        "auth": "usually none inside a cluster; a bearer token if the UI sits "
                "behind an authenticating proxy",
        "note": "Point this at the Temporal **UI server**, not the gRPC "
                "frontend (7233): the UI serves the JSON API this reads. Lists "
                "namespaces, and the running and recently-failed workflows in "
                "each.",
        "unit": "namespace",
        "fields": {"base_url": "Temporal UI URL",
                   "token": "Bearer token (only if behind a proxy)"},
    },
    "airflow": {
        "label": "Apache Airflow",
        "icon": "🌬",
        "url_hint": "https://airflow.example.com",
        "needs": ["base_url", "username"],
        "auth": "a username and password with the Viewer role",
        "note": "Reads the stable REST API (/api/v1): DAGs, whether each is "
                "paused, and the outcome of recent runs.",
        "unit": "DAG",
        "fields": {"base_url": "Airflow URL", "username": "Username",
                   "token": "Password"},
    },
}


class WorkflowError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

_cache: dict = {}


def invalidate() -> None:
    _cache.clear()


def _req(url: str, c: dict):
    h = {"Accept": "application/json"}
    if c.get("username"):
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(
            f"{c['username']}:{c.get('token', '')}".encode()).decode()
    elif c.get("token"):
        h["Authorization"] = f"Bearer {c['token']}"
    req = urllib.request.Request(urlguard.check(url), headers=h)
    ctx = None if not c.get("skip_tls") else _INSECURE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise WorkflowError("authentication rejected — check the "
                                "credentials and the account's role") from e
        if e.code == 404:
            raise WorkflowError("not found (404) — check the URL; for Temporal "
                                "this must be the UI server, not port 7233") from e
        # Temporal explains a rejected visibility query precisely — which
        # attribute is unknown, which operator its index cannot do. Reporting
        # only "HTTP 400" throws away the one thing the operator needs, and
        # makes a mistyped filter look like a broken portal.
        detail = ""
        try:
            body = json.loads(e.read().decode("utf-8", "replace") or "{}")
            detail = str(body.get("message") or body.get("error") or "")[:400]
        except Exception:                                      # noqa: BLE001
            pass
        raise WorkflowError(f"HTTP {e.code}"
                            + (f" — {detail}" if detail else "")) from e
    except urllib.error.URLError as e:
        raise WorkflowError(f"cannot reach the server: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise WorkflowError("answered, but not with JSON — for Temporal, point "
                            "this at the UI server rather than the gRPC "
                            "frontend") from e


def _ago(iso: str) -> str:
    if not iso:
        return ""
    from datetime import datetime, timezone
    try:
        then = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return ""
    d = datetime.now(timezone.utc) - then
    if d.days:
        return f"{d.days}d ago"
    h = d.seconds // 3600
    if h:
        return f"{h}h ago"
    return f"{max(1, d.seconds // 60)}m ago"


# ── Temporal ───────────────────────────────────────────────────
def _temporal(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    doc = _req(f"{base}/api/v1/namespaces?pageSize=100", c)
    groups = []
    for ns in doc.get("namespaces") or []:
        info = ns.get("namespaceInfo") or {}
        name = info.get("name", "")
        if not name:
            continue
        rows = []
        for label, query in (("running", "ExecutionStatus='Running'"),
                             ("failed", "ExecutionStatus='Failed'")):
            try:
                w = _req(f"{base}/api/v1/namespaces/{urllib.parse.quote(name)}"
                         f"/workflows?query={urllib.parse.quote(query)}"
                         "&pageSize=25", c)
            except WorkflowError:
                continue
            for ex in w.get("executions") or []:
                wf = ex.get("execution") or {}
                wid = wf.get("workflowId", "")
                rid = wf.get("runId", "")
                rows.append({
                    "name": wid[:70],
                    "kind": (ex.get("type") or {}).get("name", ""),
                    "state": ex.get("status", label).replace(
                        "WORKFLOW_EXECUTION_STATUS_", "").title(),
                    "when": _ago(ex.get("startTime", "")),
                    # the raw instant as well as the phrase: "3h" cannot be
                    # placed on a shared axis, and re-deriving it from the
                    # wording would be guessing
                    "at": ex.get("startTime", ""),
                    "extra": (ex.get("taskQueue") or ""),
                    # Where the portal shows it, and where Temporal does. The
                    # first is the point of this page; the second stays because
                    # anything not built here is one click away.
                    "href": (f"/workflows/{c.get('id', '')}/"
                             f"{urllib.parse.quote(name, safe='')}/run"
                             f"?id={urllib.parse.quote(wid, safe='')}"
                             f"&run={urllib.parse.quote(rid, safe='')}"),
                    "url": f"{base}/namespaces/{name}/workflows/"
                           f"{urllib.parse.quote(wid)}",
                })
        groups.append({"name": name, "note": info.get("description", ""),
                       "href": (f"/workflows/{c.get('id', '')}/"
                                f"{urllib.parse.quote(name, safe='')}"),
                       "rows": rows,
                       "running": sum(1 for r in rows if r["state"] == "Running"),
                       "failed": sum(1 for r in rows if r["state"] == "Failed")})
    return {"groups": groups, "unit": "namespace"}


# ── Airflow ────────────────────────────────────────────────────
def _airflow(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    doc = _req(f"{base}/api/v1/dags?limit=100", c)
    rows = []
    for d in doc.get("dags") or []:
        dag_id = d.get("dag_id", "")
        state, when, started = "", "", ""
        try:
            runs = _req(f"{base}/api/v1/dags/{urllib.parse.quote(dag_id)}"
                        "/dagRuns?limit=1&order_by=-start_date", c)
            first = (runs.get("dag_runs") or [{}])[0]
            state = (first.get("state") or "").title()
            started = first.get("start_date") or ""
            when = _ago(started)
        except WorkflowError:
            pass
        tags = ", ".join(t.get("name", "") for t in (d.get("tags") or []))
        schedule = (d.get("schedule_interval") or {}).get("value", "")
        rows.append({
            "name": dag_id, "kind": tags,
            "state": "Paused" if d.get("is_paused") else (state or "—"),
            "when": when, "at": started, "extra": schedule,
            "url": f"{base}/dags/{urllib.parse.quote(dag_id)}/grid",
        })
    rows.sort(key=lambda r: (r["state"] not in ("Failed",), r["name"]))
    return {"groups": [{"name": "DAGs", "note": "", "rows": rows,
                        "running": sum(1 for r in rows if r["state"] == "Running"),
                        "failed": sum(1 for r in rows if r["state"] == "Failed")}],
            "unit": "DAG"}


_IMPL = {"temporal": _temporal, "airflow": _airflow}


def overview(conn: dict, refresh: bool = False) -> dict:
    fn = _IMPL.get(conn.get("type"))
    if not fn:
        raise WorkflowError(f"unknown engine '{conn.get('type')}'")
    key = f"ov::{conn.get('id')}"
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    got = fn(conn)
    got["total"] = sum(len(g["rows"]) for g in got["groups"])
    got["failed"] = sum(g["failed"] for g in got["groups"])
    got["running"] = sum(g["running"] for g in got["groups"])
    _cache[key] = (time.time(), got)
    return got


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = overview(conn, refresh=True)
    except WorkflowError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    unit = got.get("unit", "group")
    n = len(got["groups"])
    bits = [f"connected — {n} {unit}{'s' if n != 1 else ''}"]
    if got["running"]:
        bits.append(f"{got['running']} running")
    if got["failed"]:
        bits.append(f"{got['failed']} failed recently")
    return True, ", ".join(bits)


# ══ Temporal, in detail ════════════════════════════════════════
# The page above answers "is anything wrong". This section answers the questions
# you would otherwise open Temporal's own UI for: which executions match, what
# happened inside one, and why it failed. It is the same JSON API the UI itself
# calls, so nothing here is reverse-engineered from a screen.
#
# TWO URL SHAPES, BECAUSE THE UI SERVER CHANGED ITS ROUTES
#     ui-server 2.42 addresses one execution as
#         /workflows/{id}?runId={run}
#     and newer builds as
#         /workflows/{id}/runs/{run}
#     Neither is a redirect to the other: the wrong one is a flat 404, which
#     reads as "that workflow does not exist" rather than "this server spells it
#     differently". So both are tried and the one that answers is remembered per
#     connection. This was found by asking a real 2.42 server, not by reading
#     current documentation — which describes only the newer form.

MAX_EVENTS = 400            # events rendered for one execution
PAYLOAD_CAP = 4000          # characters of one decoded payload
_shape: dict[str, str] = {}          # connection id -> "query" | "path"

STATUSES = ("Running", "Completed", "Failed", "Canceled", "Terminated",
            "ContinuedAsNew", "TimedOut")


def _short(s: str, prefix: str) -> str:
    return (s or "").replace(prefix, "").replace("_", " ").strip().title()


def status_of(raw: str) -> str:
    """WORKFLOW_EXECUTION_STATUS_TIMED_OUT -> TimedOut."""
    return _short(raw, "WORKFLOW_EXECUTION_STATUS_").replace(" ", "")


def _base(c: dict) -> str:
    return c["base_url"].rstrip("/")


def _ns_path(c: dict, ns: str) -> str:
    return f"{_base(c)}/api/v1/namespaces/{urllib.parse.quote(ns, safe='')}"


def _exec_url(c: dict, ns: str, wid: str, rid: str, tail: str = "") -> list[str]:
    """Both spellings, in the order to try them."""
    w = urllib.parse.quote(wid, safe="")
    r = urllib.parse.quote(rid or "", safe="")
    root = f"{_ns_path(c, ns)}/workflows/{w}"
    q = f"{root}{tail}" + (f"?runId={r}" if r else "")
    p = f"{root}/runs/{r}{tail}" if r else f"{root}{tail}"
    known = _shape.get(str(c.get("id") or ""))
    order = [q, p] if known != "path" else [p, q]
    return order


def _exec_get(c: dict, ns: str, wid: str, rid: str, tail: str = ""):
    """Ask for one execution, learning which URL shape this server speaks."""
    urls = _exec_url(c, ns, wid, rid, tail)
    last: Exception | None = None
    for i, u in enumerate(urls):
        try:
            got = _req(u, c)
            # Remembered so the second request onward costs one call, not two.
            _shape[str(c.get("id") or "")] = "query" if "?runId=" in u else "path"
            return got
        except WorkflowError as e:
            last = e
            if "not found" not in str(e).lower() and "404" not in str(e):
                raise                       # a real error, not the wrong spelling
    raise last or WorkflowError("could not read that execution")


# ── payloads ───────────────────────────────────────────────────
def _payload(p: dict) -> str:
    """One Temporal payload as text.

    data is base64 and metadata.encoding is base64 of something like
    "json/plain". A payload can also be binary or encrypted by a codec the
    portal does not have, and guessing produces mojibake — so anything that is
    not decodable text is described rather than shown.
    """
    import base64
    if not isinstance(p, dict):
        return str(p)[:PAYLOAD_CAP]
    meta = p.get("metadata") or {}
    enc = ""
    try:
        enc = base64.b64decode(meta.get("encoding") or "").decode("utf-8", "replace")
    except Exception:                                          # noqa: BLE001
        pass
    raw = p.get("data")
    if raw is None:
        return f"<{enc or 'no data'}>"
    try:
        blob = base64.b64decode(raw)
    except Exception:                                          # noqa: BLE001
        return "<undecodable>"
    if enc.startswith("binary") or "encrypted" in enc:
        return f"<{enc}, {len(blob)} bytes — not decoded here>"
    text = blob.decode("utf-8", "replace")
    try:                                    # pretty-print JSON, which most are
        text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except ValueError:
        pass
    return text[:PAYLOAD_CAP] + ("\n… truncated" if len(text) > PAYLOAD_CAP else "")


def _payloads(node) -> list[str]:
    if not isinstance(node, dict):
        return []
    return [_payload(p) for p in (node.get("payloads") or [])]


def _failure(f: dict, depth: int = 0) -> list[dict]:
    """A failure and everything that caused it, outermost first.

    Temporal nests the real reason inside `cause`, sometimes three deep — an
    activity failure wrapping an application error wrapping a timeout. Showing
    only the top one is how "activity task failed" becomes the whole diagnosis.
    """
    out = []
    # `and f`, not just isinstance: the chain ends with cause == {}, and an empty
    # dict is still a dict — without this every failure grew four blank "?:"
    # rows, which read as unparsed causes rather than the end of the chain.
    while isinstance(f, dict) and f and depth < 6:
        kind = ""
        for k in f:
            if k.endswith("FailureInfo"):
                kind = _short(k.replace("FailureInfo", ""), "")
                break
        out.append({
            "message": f.get("message") or "",
            "type": (f.get("applicationFailureInfo") or {}).get("type") or kind,
            "stack": (f.get("stackTrace") or "")[:PAYLOAD_CAP],
            "source": f.get("source") or "",
            "depth": depth,
        })
        f = f.get("cause") or {}
        depth += 1
    return out


# ── the list, with filters ─────────────────────────────────────
def namespaces(conn: dict) -> list[dict]:
    doc = _req(f"{_base(conn)}/api/v1/namespaces?pageSize=100", conn)
    out = []
    for ns in doc.get("namespaces") or []:
        i = ns.get("namespaceInfo") or {}
        if not i.get("name"):
            continue
        out.append({"name": i["name"], "note": i.get("description") or "",
                    "retention": (ns.get("config") or {}).get(
                        "workflowExecutionRetentionTtl", "")})
    return sorted(out, key=lambda n: (n["name"].startswith("temporal-"),
                                      n["name"]))


def _q(value: str) -> str:
    """A value inside a visibility query. Double quotes are the delimiter, so a
    value containing one would otherwise end the clause and change its meaning."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_query(f: dict) -> str:
    """Filters to a Temporal visibility query.

    Deliberately conservative. `ORDER BY` and `STARTS_WITH` need advanced
    visibility (Elasticsearch); on a cluster using the database's own index they
    are rejected outright, and a filter that works on one deployment and errors
    on another is worse than a narrower one that always works. The raw box is
    there for anyone who knows which they have.
    """
    if (f.get("raw") or "").strip():
        return f["raw"].strip()
    parts = []
    picked = [s for s in (f.get("status") or []) if s in STATUSES]
    if len(picked) == 1:
        parts.append(f"ExecutionStatus = {_q(picked[0])}")
    elif picked:
        parts.append("ExecutionStatus IN ("
                     + ", ".join(_q(s) for s in picked) + ")")
    for field, key in (("WorkflowType", "type"), ("WorkflowId", "wid"),
                       ("TaskQueue", "queue")):
        v = (f.get(key) or "").strip()
        if v:
            parts.append(f"{field} = {_q(v)}")
    since = (f.get("since") or "").strip()
    if since:
        parts.append(f'StartTime >= "{since}"')
    # Attribute filters, typed. This is what makes a namespace's own indexed
    # fields — phoneNumber, partnerId — usable: "every workflow for this
    # customer" is not a question a status filter can answer.
    for a in (f.get("attrs") or []):
        clause = attr_clause(a.get("name", ""), a.get("op", "="),
                             a.get("value", ""), a.get("type", "KEYWORD"))
        if clause:
            parts.append(clause)
    return " AND ".join(parts)


def search(conn: dict, ns: str, f: dict | None = None, token: str = "",
           size: int = 50) -> dict:
    """One page of executions matching the filters."""
    f = f or {}
    query = build_query(f)
    url = f"{_ns_path(conn, ns)}/workflows?pageSize={max(1, min(size, 100))}"
    if query:
        url += "&query=" + urllib.parse.quote(query)
    if token:
        url += "&nextPageToken=" + urllib.parse.quote(token, safe="")
    try:
        doc = _req(url, conn)
    except WorkflowError as e:
        # A rejected query is the operator's own words being wrong, not a broken
        # portal, so it is handed back rather than raised past the page.
        return {"rows": [], "token": "", "query": query, "error": str(e)}
    rows = []
    for ex in doc.get("executions") or []:
        w = ex.get("execution") or {}
        rows.append({
            "wid": w.get("workflowId") or "",
            "rid": w.get("runId") or "",
            "type": (ex.get("type") or {}).get("name") or "",
            "status": status_of(ex.get("status") or ""),
            "start": ex.get("startTime") or "",
            "close": ex.get("closeTime") or "",
            "ago": _ago(ex.get("startTime") or ""),
            "took": _duration(ex.get("executionDuration") or ""),
            "queue": (ex.get("taskQueue") or ""),
            "events": _int(ex.get("historyLength")),
        })
    return {"rows": rows, "token": doc.get("nextPageToken") or "",
            "query": query, "error": ""}


def _int(v) -> int:
    """Temporal serialises int64 as a JSON *string*, so historySizeBytes arrives
    as "2048" and thousands-formatting it raises. Coerced here rather than in
    each template, because it is the API's quirk and not the page's problem."""
    try:
        return int(str(v or 0))
    except ValueError:
        return 0


def _duration(v: str) -> str:
    """Temporal sends durations as "3.5s" or "120s"; make it readable."""
    s = str(v or "").strip()
    if not s.endswith("s"):
        return s
    try:
        n = float(s[:-1])
    except ValueError:
        return s
    if n < 1:
        return f"{int(n * 1000)}ms"
    if n < 90:
        return f"{n:.1f}s".replace(".0s", "s")
    if n < 3600:
        return f"{int(n // 60)}m {int(n % 60)}s"
    return f"{int(n // 3600)}h {int((n % 3600) // 60)}m"


# ── one execution ──────────────────────────────────────────────
def describe(conn: dict, ns: str, wid: str, rid: str = "") -> dict:
    doc = _exec_get(conn, ns, wid, rid)
    wei = doc.get("workflowExecutionInfo") or {}
    cfg = doc.get("executionConfig") or {}
    w = wei.get("execution") or {}
    # Pending activities moved between the top level and the execution info
    # across versions; both are read rather than one being assumed.
    pending = doc.get("pendingActivities") or wei.get("pendingActivities") or []
    acts = []
    for a in pending:
        acts.append({
            "id": a.get("activityId") or "",
            "type": (a.get("activityType") or {}).get("name") or "",
            "state": _short(a.get("state") or "", "PENDING_ACTIVITY_STATE_"),
            "attempt": _int(a.get("attempt")),
            "max": (a.get("maximumAttempts") if "maximumAttempts" in a
                    else None),
            "scheduled": a.get("scheduledTime") or "",
            "started": a.get("lastStartedTime") or "",
            "retry": a.get("scheduledTime") or "",
            "worker": a.get("lastWorkerIdentity") or "",
            # The reason it keeps retrying, which is the whole point of looking.
            "failure": _failure(a.get("lastFailure") or {}),
        })
    children = []
    for ch in (doc.get("pendingChildren") or []):
        children.append({"wid": ch.get("workflowId") or "",
                         "rid": ch.get("runId") or "",
                         "type": (ch.get("workflowTypeName")
                                  or (ch.get("workflowType") or {}).get("name") or "")})
    return {
        "wid": w.get("workflowId") or wid,
        "rid": w.get("runId") or rid,
        "type": (wei.get("type") or {}).get("name") or "",
        "status": status_of(wei.get("status") or ""),
        "start": wei.get("startTime") or "",
        "close": wei.get("closeTime") or "",
        "took": _duration(wei.get("executionDuration") or ""),
        "ago": _ago(wei.get("startTime") or ""),
        "queue": (cfg.get("taskQueue") or {}).get("name")
                 or (wei.get("taskQueue") or ""),
        "events": _int(wei.get("historyLength")),
        "bytes": _int(wei.get("historySizeBytes")),
        "transitions": _int(wei.get("stateTransitionCount")),
        "first_run": wei.get("firstRunId") or "",
        "root": (wei.get("rootExecution") or {}).get("workflowId") or "",
        "timeouts": {"execution": cfg.get("workflowExecutionTimeout") or "",
                     "run": cfg.get("workflowRunTimeout") or "",
                     "task": cfg.get("defaultWorkflowTaskTimeout") or ""},
        "search_attrs": {k: _payload(v) for k, v in
                         ((wei.get("searchAttributes") or {})
                          .get("indexedFields") or {}).items()},
        "memo": {k: _payload(v) for k, v in
                 ((wei.get("memo") or {}).get("fields") or {}).items()},
        "pending": acts,
        "children": children,
    }


# ── the event history, which is what "the logs" means here ─────
# A Temporal workflow has no log file. Its history IS the record: every decision,
# every activity attempt, every timer and every failure, in order. Rendering it
# raw is unreadable — one event is a nested proto with a dozen fields — so each
# is reduced to a line an operator can scan, keeping the parts that answer "what
# happened" and "why did it stop".

_CATEGORY = (
    ("ACTIVITY_TASK", "activity"),
    ("WORKFLOW_TASK", "task"),
    ("TIMER", "timer"),
    ("CHILD_WORKFLOW", "child"),
    ("SIGNAL", "signal"),
    ("MARKER", "marker"),
    ("WORKFLOW_EXECUTION", "workflow"),
    ("UPSERT_WORKFLOW", "attrs"),
    ("REQUEST_CANCEL", "cancel"),
)


def _category(kind: str) -> str:
    for prefix, name in _CATEGORY:
        if kind.startswith(prefix):
            return name
    return "other"


def history(conn: dict, ns: str, wid: str, rid: str = "",
            newest_first: bool = False) -> dict:
    tail = "/history-reverse" if newest_first else "/history"
    doc = _exec_get(conn, ns, wid, rid, tail)
    raw = (doc.get("history") or {}).get("events") or doc.get("events") or []
    events, failures = [], []
    for e in raw[:MAX_EVENTS]:
        kind = (e.get("eventType") or "").replace("EVENT_TYPE_", "")
        attrs = {}
        for k, v in e.items():
            if k.endswith("EventAttributes") and isinstance(v, dict):
                attrs = v
                break
        row = {
            "id": e.get("eventId") or "",
            "time": e.get("eventTime") or "",
            "kind": kind.replace("_", " ").title(),
            "raw_kind": kind,
            "cat": _category(kind),
            "detail": [],
            "failure": [],
            "payloads": [],
            # The whole event, as Temporal's JSON view shows it. Capped: a
            # history of 400 events each carrying a base64 payload would put
            # megabytes into one page.
            "json": json.dumps(e, indent=2, ensure_ascii=False)[:EVENT_JSON_CAP],
        }
        # Only the fields that say something. A generic dump of the attributes
        # is what makes Temporal's own JSON view hard to read.
        for label, path in (
                ("activity", ("activityType", "name")),
                ("activity id", ("activityId",)),
                ("workflow", ("workflowType", "name")),
                ("child", ("workflowExecution", "workflowId")),
                ("task queue", ("taskQueue", "name")),
                ("timer", ("timerId",)),
                ("signal", ("signalName",)),
                ("marker", ("markerName",)),
                ("identity", ("identity",)),
                ("attempt", ("attempt",)),
                ("retry state", ("retryState",)),
                ("timeout type", ("timeoutType",)),
                ("started event", ("scheduledEventId",)),
                ("new run", ("newExecutionRunId",)),
        ):
            node = attrs
            for step in path:
                node = (node or {}).get(step) if isinstance(node, dict) else None
            if node not in (None, "", 0, {}):
                text = str(node)
                if label in ("retry state", "timeout type"):
                    text = _short(text, "RETRY_STATE_").strip() or text
                row["detail"].append((label, text[:160]))
        for key in ("input", "result", "lastCompletionResult", "details"):
            for p in _payloads(attrs.get(key)):
                row["payloads"].append((key, p))
        if attrs.get("failure"):
            row["failure"] = _failure(attrs["failure"])
            failures.append({"event": row["id"], "kind": row["kind"],
                             "time": row["time"], "chain": row["failure"]})
        events.append(row)
    # Temporal's own page shows the workflow's Input and Result above the
    # history, and both live inside events — Input on the started event, Result
    # on whichever event closed it. Pulled out here so the page does not fetch
    # the history twice or make the reader hunt for them.
    started = next((e for e in raw
                    if "WORKFLOW_EXECUTION_STARTED" in (e.get("eventType") or "")), {})
    sa = started.get("workflowExecutionStartedEventAttributes") or {}
    closing = next((e for e in reversed(raw)
                    if (e.get("eventType") or "").startswith(
                        "EVENT_TYPE_WORKFLOW_EXECUTION_")
                    and "STARTED" not in (e.get("eventType") or "")), {})
    ca = {}
    for k, v in closing.items():
        if k.endswith("EventAttributes") and isinstance(v, dict):
            ca = v
            break
    result = _payloads(ca.get("result"))
    if not result and ca.get("failure"):
        chain = _failure(ca["failure"])
        result = [chain[-1]["message"]] if chain else []
    parent = sa.get("parentWorkflowExecution") or {}
    return {"events": events, "failures": failures,
            "total": len(raw),
            "truncated": len(raw) > MAX_EVENTS,
            "shown": len(events),
            "input": _payloads(sa.get("input")),
            "result": result,
            "closed_by": _short(closing.get("eventType") or "",
                                "EVENT_TYPE_WORKFLOW_EXECUTION_"),
            "parent": {"wid": parent.get("workflowId") or "",
                       "rid": parent.get("runId") or ""},
            "attempt": _int(sa.get("attempt")) or 1,
            "cron": sa.get("cronSchedule") or ""}


# ── counts, for the status pills ───────────────────────────────
# One request gives the total and the split by status, which is what the header
# is made of. It is optional: a cluster whose visibility store cannot group, or
# whose UI server predates the endpoint, gets pills that filter but do not count.
# That degrades to something still useful, which is the point of asking.
_count_shape: dict[str, str] = {}      # connection id -> "count" | "hyphen"


def _scalar(p: dict) -> str:
    """A grouped value: base64 JSON, usually a bare string like "Completed"."""
    text = _payload(p)
    return text.strip().strip('"')


def counts(conn: dict, ns: str, base: str = "") -> dict:
    """{"total": int, "by_status": {...}, "available": bool}.

    GROUP BY is only meaningful here; it is not offered in the filter box because
    a grouped list is not a list of executions. `base` narrows the counts to the
    same filters the page is showing, so the pills describe what is on screen
    rather than the whole namespace.
    """
    query = ("(" + base + ") AND " if base else "") + "GROUP BY ExecutionStatus"
    root = _ns_path(conn, ns)
    # 2.42 spells it workflow-count; newer builds spell it workflows/count.
    known = _count_shape.get(str(conn.get("id") or ""))
    tries = ["/workflow-count", "/workflows/count"]
    if known == "count":
        tries.reverse()
    for tail in tries:
        try:
            doc = _req(f"{root}{tail}?query=" + urllib.parse.quote(query), conn)
        except WorkflowError as e:
            if "not found" in str(e).lower() or "404" in str(e):
                continue
            return {"total": 0, "by_status": {}, "available": False,
                    "why": str(e)}
        _count_shape[str(conn.get("id") or "")] = (
            "hyphen" if tail == "/workflow-count" else "count")
        by = {}
        for g in doc.get("groups") or []:
            vals = g.get("groupValues") or []
            if not vals:
                continue
            by[_scalar(vals[0])] = int(g.get("count") or 0)
        return {"total": int(doc.get("count") or 0), "by_status": by,
                "available": True, "why": ""}
    return {"total": 0, "by_status": {}, "available": False,
            "why": "this Temporal UI server does not report counts"}


# ── saved views ────────────────────────────────────────────────
# The same shortcuts Temporal offers. Each is a query this portal has confirmed
# a database-backed visibility store accepts — no ORDER BY, no STARTS_WITH.
def views(now_iso: str) -> list[dict]:
    day = now_iso[:10]
    return [
        {"key": "", "label": "All workflows", "query": ""},
        {"key": "running", "label": "Running",
         "query": 'ExecutionStatus = "Running"'},
        {"key": "failed", "label": "Failed and timed out",
         "query": 'ExecutionStatus IN ("Failed", "TimedOut", "Terminated")'},
        {"key": "today", "label": "Today",
         "query": f'StartTime >= "{day}T00:00:00Z"'},
        {"key": "hour", "label": "Last hour",
         "query": f'StartTime >= "{now_iso}"'},
    ]


# ══ what Temporal shows that the pages above did not ═══════════
# Three things, and each needed a different part of the API:
#   the attributes a namespace can be filtered by  — /search-attributes
#   who is polling a task queue right now          — /task-queues/{name}
#   the timeline of activities inside one run       — derived from the history
EVENT_JSON_CAP = 2500       # characters of one event's raw JSON

# Temporal's own operator set, and what each one is allowed on. An operator the
# store cannot do is refused with a message about the query, so offering only
# what fits the attribute's type is the difference between a filter that works
# and one that has to be debugged.
OPS = {
    "KEYWORD": ["=", "!=", "IN", "IS NULL", "IS NOT NULL"],
    "KEYWORD_LIST": ["=", "!=", "IN"],
    "TEXT": ["=", "!="],
    "INT": ["=", "!=", ">", ">=", "<", "<="],
    "DOUBLE": ["=", "!=", ">", ">=", "<", "<="],
    "BOOL": ["=", "!="],
    "DATETIME": [">=", "<=", ">", "<", "="],
}


def _attr_type(raw: str) -> str:
    return (raw or "").replace("INDEXED_VALUE_TYPE_", "").upper() or "KEYWORD"


def search_attributes(conn: dict, ns: str) -> dict:
    """Everything this namespace can be filtered by, custom attributes included.

    The custom ones are the point: a namespace that indexes phoneNumber or
    partnerId can answer "every workflow for this customer", and that question is
    unanswerable from a status filter. They are per namespace and per cluster, so
    they have to be read rather than assumed.
    """
    try:
        doc = _req(f"{_ns_path(conn, ns)}/search-attributes", conn)
    except WorkflowError as e:
        return {"custom": [], "system": [], "why": str(e)}
    out = {"custom": [], "system": [], "why": ""}
    for key, where in (("customAttributes", "custom"),
                       ("systemAttributes", "system")):
        for name, raw in sorted((doc.get(key) or {}).items()):
            t = _attr_type(raw)
            out[where].append({"name": name, "type": t,
                               "ops": OPS.get(t, OPS["KEYWORD"])})
    return out


def attr_clause(name: str, op: str, value: str, kind: str) -> str:
    """One typed clause. Quoting is decided by the attribute's type, not guessed.

    Getting this wrong is silent: `HistoryLength = "5"` is rejected as a type
    mismatch, while `WorkflowId = 5` matches nothing at all rather than erroring.
    """
    name = (name or "").strip()
    op = (op or "=").strip().upper() if op.upper().startswith("IS") else (op or "=").strip()
    if not name:
        return ""
    if op in ("IS NULL", "IS NOT NULL"):
        return f"{name} {op}"
    value = (value or "").strip()
    if not value:
        return ""
    kind = (kind or "KEYWORD").upper()
    if op == "IN":
        parts = [p.strip() for p in value.split(",") if p.strip()]
        if not parts:
            return ""
        if kind in ("INT", "DOUBLE", "BOOL"):
            return f"{name} IN ({', '.join(parts)})"
        return f"{name} IN ({', '.join(_q(p) for p in parts)})"
    if kind in ("INT", "DOUBLE"):
        return f"{name} {op} {value}"
    if kind == "BOOL":
        return f"{name} {op} {'true' if value.lower() in ('1', 'true', 'yes') else 'false'}"
    return f"{name} {op} {_q(value)}"


# ── who is polling a task queue ────────────────────────────────
def pollers(conn: dict, ns: str, queue: str) -> dict:
    """The workers currently polling this queue.

    Different question from "which worker handled this execution", and both are
    worth having: a task queue with no pollers is why a workflow is stuck at
    Scheduled, and no amount of reading its history will say so.
    """
    if not queue:
        return {"rows": [], "why": "", "rate": 0}
    try:
        doc = _req(f"{_ns_path(conn, ns)}/task-queues/"
                   f"{urllib.parse.quote(queue, safe='')}", conn)
    except WorkflowError as e:
        return {"rows": [], "why": str(e), "rate": 0}
    rows = []
    for p in (doc.get("pollers") or []):
        rows.append({"identity": p.get("identity") or "?",
                     "last": p.get("lastAccessTime") or "",
                     "ago": _ago(p.get("lastAccessTime") or ""),
                     "rate": _int(p.get("ratePerSecond"))})
    return {"rows": sorted(rows, key=lambda r: r["identity"]),
            "why": "" if rows else "no worker is polling this queue",
            "rate": ((doc.get("effectiveRateLimit") or {})
                     .get("requestsPerSecond") or 0)}


# ── the timeline ───────────────────────────────────────────────
# Temporal draws one bar per activity, timer and child, coloured by how it ended
# and positioned by when it ran. That is not in the API — it is the history,
# stitched by the ids events use to refer to one another:
#   ACTIVITY_TASK_SCHEDULED is event S; STARTED and the closing event both carry
#   scheduledEventId = S. TIMER_FIRED carries startedEventId. A child carries
#   initiatedEventId. Stitching by those is what turns 29 flat events into the
#   five bars an operator actually reads.
_END = {"COMPLETED": "completed", "FAILED": "failed", "TIMED_OUT": "timedout",
        "CANCELED": "canceled", "CANCEL_REQUESTED": "canceled",
        "TERMINATED": "terminated", "FIRED": "completed"}


def timeline(events: list[dict], raw: list[dict] | None = None) -> list[dict]:
    """Lifecycles, oldest first: {kind, name, start, end, outcome, events}."""
    by_id = {e.get("id"): e for e in events}
    lanes: dict[str, dict] = {}
    order: list[str] = []

    def lane(key: str, kind: str, name: str, ev: dict) -> dict:
        if key not in lanes:
            lanes[key] = {"kind": kind, "name": name, "start": ev.get("time"),
                          "end": "", "outcome": "pending", "attempt": 0,
                          "events": [], "detail": []}
            order.append(key)
        lanes[key]["events"].append(ev.get("id"))
        if name and not lanes[key]["name"]:
            lanes[key]["name"] = name
        return lanes[key]

    for e in events:
        kind = e.get("raw_kind") or ""
        det = dict(e.get("detail") or [])
        anchor = det.get("started event") or ""      # scheduledEventId, mostly
        if kind.startswith("ACTIVITY_TASK"):
            key = f"a{anchor or e.get('id')}"
            ln = lane(key, "activity", det.get("activity", ""), e)
            if kind.endswith("SCHEDULED"):
                ln["start"] = e.get("time")
                ln["name"] = ln["name"] or det.get("activity", "")
            if det.get("attempt"):
                ln["attempt"] = max(ln["attempt"], _int(det["attempt"]))
            tail = kind.rsplit("ACTIVITY_TASK_", 1)[-1]
            if tail in _END:
                ln["outcome"] = _END[tail]
                ln["end"] = e.get("time")
            if e.get("failure"):
                ln["detail"] = e["failure"]
        elif kind.startswith("TIMER"):
            key = f"t{anchor or det.get('timer') or e.get('id')}"
            ln = lane(key, "timer", "timer " + str(det.get("timer", "")), e)
            tail = kind.rsplit("TIMER_", 1)[-1]
            if tail in _END:
                ln["outcome"] = _END[tail]
                ln["end"] = e.get("time")
        elif "CHILD_WORKFLOW" in kind:
            key = f"c{anchor or e.get('id')}"
            ln = lane(key, "child", det.get("child") or det.get("workflow", ""), e)
            tail = kind.rsplit("_", 1)[-1]
            if tail in _END:
                ln["outcome"] = _END[tail]
                ln["end"] = e.get("time")
            if e.get("failure"):
                ln["detail"] = e["failure"]
    out = []
    for key in order:
        ln = lanes[key]
        if ln["name"] or ln["kind"] != "activity" or ln["outcome"] != "pending":
            out.append({**ln, "key": key})
    return out


def epoch(iso: str) -> float:
    """An ISO timestamp as seconds, for positioning a bar. 0 when unparsable —
    a bar at the origin is wrong but visible, which is better than a template
    raising halfway through a page."""
    if not iso:
        return 0.0
    from datetime import datetime
    try:
        return datetime.fromisoformat(
            str(iso).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def span(events: list[dict]) -> tuple[str, str]:
    """The window the timeline is drawn against: first and last event time."""
    times = [e.get("time") for e in events if e.get("time")]
    return (min(times), max(times)) if times else ("", "")
