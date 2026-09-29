"""Log platforms — Elasticsearch/OpenSearch and Grafana Loki.

Same contract as ci.py and security.py: each platform is reduced to one shape so
the UI never learns which one answered, and adding a third means one registry
entry plus two functions.

Read-only. Every call is a search or a metadata read; nothing here writes,
deletes or manages indices.

WHY FIELD NAMES ARE NOT ASSUMED
    Log documents have no standard shape. One cluster ships ECS
    (`@timestamp`, `log.level`, `message`), another ships bare Fluent Bit
    (`time`, `severity`, `log`), another has whatever the app logger emitted.
    Guessing wrongly means a table of empty cells, so a connection may state its
    field names and, when it does not, they are detected from a real document.

Normalised entry:
    {ts, level, service, message, source}
"""
import base64
import json
import re
import ssl
import threading
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

TIMEOUT = 25            # a real search: the user asked for it and will wait
PROBE_TIMEOUT = 6       # the health figures on the hub: nobody asked, so be brief
CACHE_TTL = 60
PAGE_DEFAULT = 100

# How long a connection that could not be reached is left alone. A store whose
# port is not open yet — a firewall change still in someone's queue — otherwise
# costs a full timeout on *every* page load, which makes the whole page feel
# broken rather than the one connection. Backoff doubles per consecutive failure
# so a store that is down for a day is tried a few times an hour, not constantly.
FAIL_COOLDOWN = 60
FAIL_COOLDOWN_MAX = 900

# Candidate field names, most standard first. Generic logging conventions (ECS,
# Fluent Bit, Docker, plain syslog) — not any one deployment's mapping, and any
# connection can override them.
_TIME_FIELDS = ("@timestamp", "timestamp", "time", "ts", "date", "eventTime")
_LEVEL_FIELDS = ("log.level", "level", "severity", "log_level", "loglevel",
                 "syslog.severity", "stream")
_MSG_FIELDS = ("message", "msg", "log", "short_message", "event.original", "line")
_SVC_FIELDS = ("service.name", "kubernetes.container_name", "container_name",
               "kubernetes.labels.app", "app", "service", "container", "logger_name")

# What counts as a problem. This is the union of the syslog severities (RFC 5424:
# emerg, alert, crit, err) and the level names the mainstream logging libraries
# emit — fatal (log4j, logrus, zap), panic (Go, logrus), severe (java.util
# .logging). It is a vocabulary of the ecosystem, not of any one deployment.
ERROR_LEVELS = ("error", "err", "critical", "crit", "fatal", "alert", "emerg",
                "emergency", "severe", "panic")
LEVELS = ("error", "warn", "info", "debug")

PROVIDERS = {
    "elasticsearch": {
        "label": "Elasticsearch / OpenSearch",
        "icon": "🔶",
        "url_hint": "https://elk.example.com:9200",
        "needs": ["base_url", "token"],
        "scope_label": "index pattern",
        "scope_hint": "e.g. logs-* — blank searches every index",
        "note": "An API key (paste it alone) or a username plus password. "
                "Works with Elasticsearch and OpenSearch alike; the portal only "
                "ever issues searches.",
    },
    "loki": {
        "label": "Grafana Loki",
        "icon": "🟠",
        "url_hint": "https://loki.example.com:3100",
        "needs": ["base_url"],
        "scope_label": "stream selector",
        "scope_hint": 'LogQL selector, e.g. {namespace=~".+"}',
        "note": "Loki needs no credentials by default; add a username and "
                "password if it sits behind basic auth, and a tenant if it runs "
                "multi-tenant.",
    },
}


class LogError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _req(url: str, headers: dict, verify: bool = True, body=None,
         timeout: float | None = None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Accept": "application/json", **headers}
    if data:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT,
                                    context=None if verify else _INSECURE) as r:
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        if e.code in (401, 403):
            raise LogError(f"authentication rejected ({e.code}) — check the API "
                           "key or credentials and their index privileges") from e
        if e.code == 404:
            raise LogError("not found (404) — check the base URL and the index "
                           "pattern") from e
        raise LogError(f"HTTP {e.code} {detail}".strip()) from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason or "SSLCertVerification" in reason:
            raise LogError(
                f"TLS certificate rejected: {reason}. If this is an internal "
                "server with a self-signed certificate, tick 'skip TLS "
                "verification' on the connection.") from e
        raise LogError(f"cannot reach the server: {reason}") from e
    except json.JSONDecodeError:
        raise LogError("the server did not return JSON — is the base URL the "
                       "API endpoint rather than a dashboard page?")
    except Exception as e:                                    # noqa: BLE001
        raise LogError(f"{type(e).__name__}: {e}".strip()[:200]
                       or "unexpected transport error") from e


# ── shared helpers ─────────────────────────────────────────────
_CACHE: dict[str, tuple[float, object]] = {}
# connection id -> (when it failed, message, how many times in a row)
_FAILED: dict[str, tuple[float, str, int]] = {}


def invalidate() -> None:
    _CACHE.clear()
    _FAILED.clear()


def _key(conn: dict) -> str:
    return conn.get("id") or conn.get("base_url", "")


def cooling(conn: dict) -> tuple[str, int]:
    """The remembered failure for this connection, and the seconds left of its
    cooldown. ("", 0) when it is due another attempt."""
    hit = _FAILED.get(_key(conn))
    if not hit:
        return "", 0
    when, message, strikes = hit
    wait = min(FAIL_COOLDOWN * 2 ** (strikes - 1), FAIL_COOLDOWN_MAX)
    left = int(when + wait - time.time())
    return (message, left) if left > 0 else ("", 0)


def _note_failure(conn: dict, message: str) -> None:
    k = _key(conn)
    strikes = (_FAILED.get(k) or (0, "", 0))[2] + 1
    _FAILED[k] = (time.time(), message, strikes)


def _note_success(conn: dict) -> None:
    _FAILED.pop(_key(conn), None)


def _probing(conn: dict, refresh: bool, produce):
    """Run a health probe, unless this connection is in its cooldown.

    Raises the remembered error instead of waiting for the same timeout again,
    which is what keeps one unreachable store from slowing down the page for
    every other one. A refresh always tries for real.
    """
    if not refresh:
        message, left = cooling(conn)
        if message:
            raise LogError(f"{message} (not retried for another "
                           f"{left}s — use Refresh to try now)")
    try:
        got = produce()
    except LogError as e:
        _note_failure(conn, str(e)[:200])
        raise
    _note_success(conn)
    return got


# ── the warmer: the page never pays for the network ───────────
# The hub used to fetch each store's overview on the request that happened to
# arrive after the cache expired — so every minute, someone's page load paid
# the probe (six seconds per slow store). The trade is wrong: a dashboard
# should show slightly-old numbers instantly, not fresh numbers slowly.
#
# So a daemon thread now owns ALL overview fetching. It re-reads the connection
# list each cycle (a store added in Settings is picked up on the next pass,
# nothing to signal), refreshes every overview under the same cooldown rules,
# and the request path reads only the cache — peek() never touches the network.
# An unreachable store costs the warmer its timeout, in the background, once
# per cooldown; the page it costs nothing.
WARM_EVERY = 45.0        # under CACHE_TTL, so a warmed entry never expires

_warm_started = False
_warm_lock = threading.Lock()


def warm_start() -> None:
    """Start the background warmer once. Called at app startup and defensively
    from the page, so a hot-reloaded process warms itself back up."""
    global _warm_started
    with _warm_lock:
        if _warm_started:
            return
        _warm_started = True
    threading.Thread(target=_warm_loop, name="logstore-warmer",
                     daemon=True).start()


def _warm_loop() -> None:
    from . import store
    while True:
        try:
            conns = store.all_log()
        except Exception:                                     # noqa: BLE001
            conns = []
        for c in conns:
            try:
                overview(c)
            except Exception:                                 # noqa: BLE001
                pass    # the cooldown remembers it; peek() reports it
        time.sleep(WARM_EVERY)


def warm_now() -> None:
    """One forced pass, off-thread — the Refresh button. The page serves what
    it has and picks the fresh numbers up on its reload; nobody waits on a
    socket for a dashboard."""
    def run():
        from . import store
        try:
            conns = store.all_log()
        except Exception:                                     # noqa: BLE001
            return
        for c in conns:
            try:
                overview(c, refresh=True)
            except Exception:                                 # noqa: BLE001
                pass
    threading.Thread(target=run, name="logstore-refresh", daemon=True).start()


def peek(conn: dict) -> tuple[dict | None, str, int]:
    """(overview-or-None, remembered-error, age-seconds) — cache only, and a
    stale entry is served rather than dropped: the warmer replaces it, the
    page never waits for it. None with no error means the warmer has not
    reached this connection yet."""
    hit = _CACHE.get(f"{_key(conn)}::overview::")
    message, _left = cooling(conn)
    if hit:
        return hit[1], message, int(time.time() - hit[0])
    return None, message, -1


def _cached(conn: dict, part: str, extra: str, refresh: bool, produce):
    key = f"{conn.get('id') or conn.get('base_url','')}::{part}::{extra}"
    hit = _CACHE.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    got = produce()
    _CACHE[key] = (time.time(), got)
    return got


def _dig(doc: dict, path: str):
    """Read `a.b.c`, tolerating both nested objects and literal dotted keys —
    log shippers produce either."""
    if path in doc:
        return doc[path]
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first_present(doc: dict, candidates, configured: str = ""):
    """The configured field if given, else the first candidate the document has."""
    if configured:
        return configured
    for c in candidates:
        if _dig(doc, c) not in (None, ""):
            return c
    return ""


def _norm_level(raw) -> str:
    v = str(raw or "").strip().lower()
    if not v:
        return ""
    if v in ERROR_LEVELS or any(v.startswith(e) for e in ERROR_LEVELS):
        return "error"
    if v.startswith("warn"):
        return "warn"
    if v.startswith("debug") or v.startswith("trace"):
        return "debug"
    if v.startswith("info") or v in ("stdout", "notice"):
        return "info"
    return v[:12]


def _ago(iso) -> str:
    if not iso:
        return ""
    try:
        s = str(iso).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        d = datetime.now(timezone.utc) - dt
        # A shipper whose clock runs ahead produces timestamps in the future.
        # Subtracting gives a negative delta, which rendered as "-1d ago"; say
        # what is actually happening instead, since clock skew is worth noticing.
        if d.total_seconds() < 0:
            ahead = -d
            mins = int(ahead.total_seconds() // 60)
            return f"{mins}m ahead" if mins else "just now"
        if d.days:
            return f"{d.days}d ago"
        h, m = d.seconds // 3600, (d.seconds % 3600) // 60
        if h:
            return f"{h}h {m}m ago"
        return f"{m}m ago" if m else "just now"
    except Exception:
        return ""


def _window(minutes: int) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return (now - timedelta(minutes=max(1, minutes))).isoformat(), now.isoformat()


def fields_of(conn: dict) -> dict:
    """The connection's field mapping; empty values mean auto-detect."""
    return {"time": (conn.get("f_time") or "").strip(),
            "level": (conn.get("f_level") or "").strip(),
            "message": (conn.get("f_message") or "").strip(),
            "service": (conn.get("f_service") or "").strip()}


# ── Elasticsearch / OpenSearch ─────────────────────────────────
def _es_ctx(c: dict) -> tuple[str, dict, bool]:
    base = c["base_url"].rstrip("/")
    user, token = (c.get("username") or "").strip(), c.get("token") or ""
    if user:
        auth = base64.b64encode(f"{user}:{token}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
    else:
        # a bare key is an Elasticsearch API key, sent as ApiKey not Bearer
        headers = {"Authorization": f"ApiKey {token}"}
    return base, headers, not c.get("skip_tls")


def _es_index(c: dict) -> str:
    idx = (c.get("scope") or "").strip().strip("/")
    return urllib.parse.quote(idx, safe="*,-_.") if idx else "_all"


def _es_indices(c: dict, timeout: float | None = None) -> list[dict]:
    base, h, v = _es_ctx(c)
    pat = (c.get("scope") or "").strip() or "*"
    got = _req(f"{base}/_cat/indices/{urllib.parse.quote(pat, safe='*,-_.')}"
               f"?format=json&h=index,docs.count,store.size&s=index", h, v,
               timeout=timeout)
    rows = got if isinstance(got, list) else []
    out = []
    for r in rows:
        if str(r.get("index", "")).startswith("."):     # system indices
            continue
        try:
            docs = int(r.get("docs.count") or 0)
        except ValueError:
            docs = 0
        out.append({"name": r.get("index", "?"), "docs": docs,
                    "size": r.get("store.size", "")})
    return sorted(out, key=lambda x: -x["docs"])


def _es_search(c: dict, q: str, level: str, minutes: int, limit: int,
               timeout: float | None = None) -> dict:
    base, h, v = _es_ctx(c)
    f = fields_of(c)
    tfield = f["time"] or _TIME_FIELDS[0]
    start, end = _window(minutes)

    must: list = [{"range": {tfield: {"gte": start, "lte": end}}}]
    if q:
        must.append({"query_string": {"query": q, "lenient": True,
                                      "default_operator": "AND"}})
    if level:
        # the level field name is unknown until a document is seen, so match the
        # value across the usual candidates rather than guessing one
        names = [f["level"]] if f["level"] else list(_LEVEL_FIELDS)
        vals = list(ERROR_LEVELS) if level == "error" else [level, level + "ing"]
        must.append({"bool": {"minimum_should_match": 1, "should": [
            {"match": {n: {"query": " ".join(vals), "operator": "or"}}}
            for n in names]}})

    body = {"size": limit, "track_total_hits": True,
            "sort": [{tfield: {"order": "desc", "unmapped_type": "date"}}],
            "query": {"bool": {"must": must}}}
    try:
        got = _req(f"{base}/{_es_index(c)}/_search", h, v, body, timeout=timeout)
    except LogError as e:
        # a wrong time field is the most common cause and the message from
        # Elasticsearch is unreadable, so say what to change
        if "400" in str(e) and not f["time"]:
            raise LogError(
                f"the search was rejected — this index may not use '{tfield}' as "
                "its time field. Set the time field on the connection.") from e
        raise

    hits = ((got.get("hits") or {}).get("hits") or [])
    total = ((got.get("hits") or {}).get("total") or {})
    sample = hits[0].get("_source", {}) if hits else {}
    fm = {
        "time": _first_present(sample, _TIME_FIELDS, f["time"]) or tfield,
        "level": _first_present(sample, _LEVEL_FIELDS, f["level"]),
        "message": _first_present(sample, _MSG_FIELDS, f["message"]),
        "service": _first_present(sample, _SVC_FIELDS, f["service"]),
    }
    entries = []
    for hit in hits:
        src = hit.get("_source") or {}
        msg = _dig(src, fm["message"]) if fm["message"] else None
        if msg is None:                       # nothing recognisable — show the doc
            msg = json.dumps({k: v for k, v in src.items()
                              if k not in (fm["time"],)})[:400]
        ts = _dig(src, fm["time"]) if fm["time"] else ""
        entries.append({
            "ts": str(ts or ""), "when": _ago(ts),
            "level": _norm_level(_dig(src, fm["level"]) if fm["level"] else ""),
            "service": str(_dig(src, fm["service"]) or "" if fm["service"] else ""),
            "message": str(msg)[:2000], "source": hit.get("_index", ""),
        })
    return {"entries": entries,
            "total": total.get("value") if isinstance(total, dict) else total or 0,
            "took_ms": got.get("took") or 0, "fields": fm, "note": ""}


def _es_overview(c: dict) -> dict:
    # a health figure, not a search someone is waiting on: short timeout
    idx = _es_indices(c, timeout=PROBE_TIMEOUT)
    try:
        errs = _es_search(c, "", "error", 60, 1, timeout=PROBE_TIMEOUT)
        recent_errors, err_note = errs["total"], ""
    except LogError as e:
        recent_errors, err_note = None, str(e)
    return {"streams": len(idx), "docs": sum(i["docs"] for i in idx),
            "top": idx[:6], "recent_errors": recent_errors, "note": err_note,
            "unit": "index"}


# ── Grafana Loki ───────────────────────────────────────────────
def _loki_ctx(c: dict) -> tuple[str, dict, bool]:
    base = c["base_url"].rstrip("/")
    headers = {}
    user, token = (c.get("username") or "").strip(), c.get("token") or ""
    if user:
        auth = base64.b64encode(f"{user}:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {auth}"
    if (c.get("tenant") or "").strip():
        headers["X-Scope-OrgID"] = c["tenant"].strip()
    return base, headers, not c.get("skip_tls")


def _loki_labels(c: dict, timeout: float | None = None) -> list[str]:
    base, h, v = _loki_ctx(c)
    got = _req(f"{base}/loki/api/v1/labels", h, v, timeout=timeout)
    return sorted(got.get("data") or [])


def _loki_selector(c: dict, labels=None) -> str:
    """LogQL needs at least one matcher, so fall back to a label the server
    actually reports rather than a hard-coded guess."""
    sel = (c.get("scope") or "").strip()
    if sel:
        return sel if sel.startswith("{") else "{" + sel + "}"
    for pref in ("namespace", "job", "app", "container", "service_name"):
        if labels and pref in labels:
            return "{%s=~\".+\"}" % pref
    if labels:
        return "{%s=~\".+\"}" % labels[0]
    raise LogError("Loki needs a stream selector and this server reports no "
                   "labels — set one on the connection, e.g. {namespace=~\".+\"}")


def _loki_search(c: dict, q: str, level: str, minutes: int, limit: int,
                 timeout: float | None = None) -> dict:
    base, h, v = _loki_ctx(c)
    try:
        labels = _loki_labels(c)
    except LogError:
        labels = []
    query = _loki_selector(c, labels)
    if level == "error":
        query += " |~ `(?i)(" + "|".join(ERROR_LEVELS) + ")`"
    elif level:
        query += f" |~ `(?i){level}`"
    if q:
        query += f" |= `{q}`"
    start, end = _window(minutes)
    params = urllib.parse.urlencode({
        "query": query, "limit": limit, "direction": "backward",
        "start": str(int(datetime.fromisoformat(start).timestamp() * 1e9)),
        "end": str(int(datetime.fromisoformat(end).timestamp() * 1e9))})
    got = _req(f"{base}/loki/api/v1/query_range?{params}", h, v, timeout=timeout)
    entries = []
    for stream in ((got.get("data") or {}).get("result") or []):
        lbl = stream.get("stream") or {}
        # conventional labels first; failing that, any label the stream carries,
        # so an unfamiliar naming scheme still fills the column
        svc = next((lbl[k] for k in ("container", "app", "job", "service_name",
                                     "pod", "namespace") if lbl.get(k)),
                   next((v for k, v in sorted(lbl.items()) if v), ""))
        for ns, line in (stream.get("values") or []):
            try:
                ts = datetime.fromtimestamp(int(ns) / 1e9, timezone.utc).isoformat()
            except Exception:
                ts = ""
            entries.append({
                "ts": ts, "when": _ago(ts),
                "level": _norm_level(lbl.get("level")
                                     or _sniff_level(line)),
                "service": svc, "message": str(line)[:2000],
                "source": lbl.get("namespace", "")})
    entries.sort(key=lambda e: e["ts"], reverse=True)
    return {"entries": entries[:limit], "total": len(entries),
            "took_ms": 0, "fields": {"query": query}, "note": ""}


# built from the vocabulary above rather than repeating it, so the two can never
# drift apart — a level the search can filter on must also be readable in a line
_LEVEL_IN_LINE = re.compile(
    r"\b(" + "|".join(sorted(set(ERROR_LEVELS) | {"warn", "warning", "info",
                                                   "debug", "trace", "notice"},
                              key=len, reverse=True)) + r")\b", re.I)


def _sniff_level(line: str) -> str:
    """Loki keeps the line opaque, so read the level out of the text itself."""
    m = _LEVEL_IN_LINE.search(str(line)[:200])
    return m.group(1) if m else ""


def _loki_overview(c: dict) -> dict:
    # a labels call that fails means the API is not answering, which the hub
    # should report as unreachable rather than as "zero labels"
    labels = _loki_labels(c, timeout=PROBE_TIMEOUT)
    try:
        errs = _loki_search(c, "", "error", 60, 200, timeout=PROBE_TIMEOUT)
        recent, note = errs["total"], ""
    except LogError as e:
        recent, note = None, str(e)
    return {"streams": len(labels), "docs": 0,
            "top": [{"name": l, "docs": 0, "size": ""} for l in labels[:6]],
            "recent_errors": recent, "note": note, "unit": "label"}


# ── public API ─────────────────────────────────────────────────
_SEARCH = {"elasticsearch": _es_search, "loki": _loki_search}
_OVERVIEW = {"elasticsearch": _es_overview, "loki": _loki_overview}


def search(conn: dict, q: str = "", level: str = "", minutes: int = 60,
           limit: int = PAGE_DEFAULT, refresh: bool = False) -> dict:
    fn = _SEARCH.get(conn.get("type"))
    if not fn:
        raise LogError(f"unknown log platform '{conn.get('type')}'")
    return _cached(conn, "search", f"{q}:{level}:{minutes}:{limit}", refresh,
                   lambda: fn(conn, q, level, minutes, limit))


def overview(conn: dict, refresh: bool = False) -> dict:
    fn = _OVERVIEW.get(conn.get("type"))
    if not fn:
        raise LogError(f"unknown log platform '{conn.get('type')}'")
    return _cached(conn, "overview", "", refresh,
                   lambda: _probing(conn, refresh, lambda: fn(conn)))


def test(conn: dict) -> tuple[bool, str]:
    try:
        o = overview(conn, refresh=True)
    except LogError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    # Reaching the API is not the same as being able to read logs from it. A
    # connection with nothing visible and a failed search is not "connected" in
    # any sense the user cares about, so say so rather than reassuring them.
    if not o.get("streams") and o.get("recent_errors") is None:
        return False, (o.get("note")
                       or "reachable, but no indices or labels are visible to "
                          "these credentials and no search succeeded")
    unit = o.get("unit", "stream")
    bits = [f"connected — {o['streams']} {unit}{'es' if unit == 'index' else 's'}"]
    if o.get("docs"):
        bits.append(f"{o['docs']:,} documents")
    if o.get("recent_errors") is not None:
        bits.append(f"{o['recent_errors']:,} error-level entries in the last hour")
    detail = ", ".join(bits)
    return True, detail + (f" · {o['note'][:80]}" if o.get("note") else "")


def page_size(conn: dict) -> int:
    try:
        n = int(conn.get("limit") or PAGE_DEFAULT)
    except (TypeError, ValueError):
        return PAGE_DEFAULT
    return max(10, min(n, 1000))


# ── exploration: what turns a search box into an investigation ──
# Everything below is derived from the data. No field names are assumed: facets
# are chosen by how the values behave (a field with one value tells you nothing,
# a field with a distinct value per document is an identifier, and the useful
# ones sit in between), and the histogram uses whichever time field was
# detected. The same code therefore works on an index it has never seen.
FACET_MIN_COVERAGE = 0.20      # must appear in this share of the sampled docs
FACET_MIN_DISTINCT = 2         # one value everywhere explains nothing
FACET_MAX_DISTINCT = 40        # beyond this it is an identifier, not a facet
FACET_MAX_LEN = 120            # a long identifier is still a category
FACET_MAX_WORDS = 8            # …but a sentence is not
FACET_LIMIT = 8


def _flatten(doc, prefix=""):
    """Every scalar leaf as a dotted path, so nested documents facet too."""
    for k, v in (doc or {}).items():
        p = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from _flatten(v, p + ".")
        elif isinstance(v, list):
            if v and all(isinstance(i, (str, int, float, bool)) for i in v):
                for i in v[:5]:
                    yield p, i
        elif isinstance(v, bool) or isinstance(v, (int, float)) or \
                (isinstance(v, str) and v.strip()):
            yield p, v


def _facet_candidates(docs: list, skip: set) -> list:
    """Fields worth offering as filters, judged only by their value pattern."""
    from collections import Counter, defaultdict
    present, values = Counter(), defaultdict(set)
    for d in docs:
        seen = set()
        for path, val in _flatten(d):
            if path in skip or path.startswith("_"):
                continue
            if path not in seen:
                seen.add(path)
                present[path] += 1
            if len(values[path]) <= FACET_MAX_DISTINCT + 1:
                values[path].add(str(val)[:FACET_MAX_LEN + 1])
    n = max(1, len(docs))
    out = []
    for path, cnt in present.items():
        vals = values[path]
        if len(vals) < FACET_MIN_DISTINCT or len(vals) > FACET_MAX_DISTINCT:
            continue
        if cnt / n < FACET_MIN_COVERAGE:
            continue
        if max((len(x) for x in vals), default=0) > FACET_MAX_LEN:
            continue
        # prose reads as a category by every other measure, so reject on shape
        if max((x.count(" ") for x in vals), default=0) >= FACET_MAX_WORDS:
            continue
        # prefer broad coverage, then few distinct values — the most explanatory
        out.append((-(cnt / n), len(vals), path))
    out.sort()
    return [p for _c, _d, p in out[:FACET_LIMIT]]


_SIG_RULES = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<hash>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<time>"),
    (re.compile(r'"[^"]{1,80}"'), '"<str>"'),
    (re.compile(r"\b\d+\b"), "<n>"),
)


def signature(message: str) -> str:
    """Collapse a log line to its shape so repeats of the same event group.

    Identifiers, timestamps and numbers are what make otherwise identical lines
    unique, so replacing them reveals that ten thousand entries are really one
    problem repeated.
    """
    s = str(message or "")[:300]
    for rx, repl in _SIG_RULES:
        s = rx.sub(repl, s)
    return re.sub(r"\s+", " ", s).strip()


def _es_explore(c: dict, q: str, level: str, minutes: int, limit: int) -> dict:
    """One page of entries plus everything needed to explore them."""
    base, h, verify = _es_ctx(c)
    f = fields_of(c)
    tfield = f["time"] or _TIME_FIELDS[0]
    start, end = _window(minutes)
    idx = _es_index(c)

    must: list = [{"range": {tfield: {"gte": start, "lte": end}}}]
    if q:
        must.append({"query_string": {"query": q, "lenient": True,
                                      "default_operator": "AND"}})
    if level:
        names = [f["level"]] if f["level"] else list(_LEVEL_FIELDS)
        vals = list(ERROR_LEVELS) if level == "error" else [level, level + "ing"]
        must.append({"bool": {"minimum_should_match": 1, "should": [
            {"match": {n: {"query": " ".join(vals), "operator": "or"}}}
            for n in names]}})
    query = {"bool": {"must": must}}

    # bucket width chosen so the chart always has a readable number of bars
    buckets = 60
    secs = max(1, (minutes * 60) // buckets)
    interval = (f"{secs}s" if secs < 60 else
                f"{max(1, secs // 60)}m" if secs < 3600 else f"{max(1, secs // 3600)}h")

    body = {
        "size": limit, "track_total_hits": True,
        "sort": [{tfield: {"order": "desc", "unmapped_type": "date"}}],
        "query": query,
        "aggs": {
            "over_time": {"date_histogram": {
                "field": tfield, "fixed_interval": interval, "min_doc_count": 0}},
            # an error overlay drawn without knowing which field holds the level:
            # a lenient text match across the document is enough for a shape
            "errors": {"filter": {"query_string": {
                "query": " OR ".join(ERROR_LEVELS), "lenient": True}},
                "aggs": {"over_time": {"date_histogram": {
                    "field": tfield, "fixed_interval": interval,
                    "min_doc_count": 0}}}},
        },
    }
    # the sample used for facet discovery does not depend on the main result,
    # so pay for one round trip rather than two
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_main = pool.submit(_req, f"{base}/{idx}/_search", h, verify, body)
        f_samp = pool.submit(_es_random_sample, c, query, idx)
        got, rand = f_main.result(), f_samp.result()

    hits = ((got.get("hits") or {}).get("hits") or [])
    total = ((got.get("hits") or {}).get("total") or {})
    sample = hits[0].get("_source", {}) if hits else {}
    fm = {
        "time": _first_present(sample, _TIME_FIELDS, f["time"]) or tfield,
        "level": _first_present(sample, _LEVEL_FIELDS, f["level"]),
        "message": _first_present(sample, _MSG_FIELDS, f["message"]),
        "service": _first_present(sample, _SVC_FIELDS, f["service"]),
    }
    entries = []
    for hit in hits:
        src = hit.get("_source") or {}
        msg = _dig(src, fm["message"]) if fm["message"] else None
        if msg is None:
            msg = json.dumps({k: v for k, v in src.items() if k != fm["time"]})[:400]
        ts = _dig(src, fm["time"]) if fm["time"] else ""
        entries.append({
            "ts": str(ts or ""), "when": _ago(ts),
            "level": _norm_level(_dig(src, fm["level"]) if fm["level"] else ""),
            "service": str(_dig(src, fm["service"]) or "" if fm["service"] else ""),
            "message": str(msg)[:2000], "source": hit.get("_index", ""),
            "raw": src,
        })

    aggs = got.get("aggregations") or {}
    tot_b = ((aggs.get("over_time") or {}).get("buckets") or [])
    err_b = {b["key"]: b["doc_count"]
             for b in (((aggs.get("errors") or {}).get("over_time") or {})
                       .get("buckets") or [])}
    histogram = [{"t": b.get("key_as_string", ""), "total": b["doc_count"],
                  "errors": err_b.get(b["key"], 0)} for b in tot_b]

    # Facets are discovered from a RANDOM sample of the window, never from the
    # newest N documents: during a burst the newest are all one service, so
    # every field looks single-valued and nothing is offered exactly when the
    # user most needs to know who is shouting.
    skip = {fm["time"], fm["message"]}
    cand = _facet_candidates(rand, skip)
    facets = _es_facet_counts(c, query, cand, idx) if cand else []

    sigs = _signatures(entries)
    return {"entries": [{k: v for k, v in e.items() if k != "raw"} for e in entries],
            "total": total.get("value") if isinstance(total, dict) else total or 0,
            "took_ms": got.get("took") or 0, "fields": fm, "note": "",
            "histogram": histogram, "interval": interval,
            "facets": facets, "signatures": sigs}


def _es_random_sample(c: dict, query: dict, idx: str, size: int = 300) -> list:
    """A random slice of the matching documents, for judging field shape."""
    base, h, verify = _es_ctx(c)
    try:
        got = _req(f"{base}/{idx}/_search", h, verify, {
            "size": size, "_source": True,
            "query": {"function_score": {"query": query, "random_score": {}}}})
    except LogError:
        return []
    return [x.get("_source") or {} for x in ((got.get("hits") or {}).get("hits") or [])]


def _es_facet_counts(c: dict, query: dict, paths: list, idx: str) -> list:
    """Exact top values for the discovered fields.

    A text field cannot be aggregated, so the mapping decides whether to use the
    field itself or its `.keyword` sub-field — asking the cluster rather than
    guessing at the naming convention.
    """
    base, h, verify = _es_ctx(c)
    try:
        caps = _req(f"{base}/{idx}/_field_caps?fields="
                    + urllib.parse.quote(",".join(p + "*" for p in paths)), h, verify)
        known = caps.get("fields", {})
    except LogError:
        known = {}

    def aggregatable(p):
        types = known.get(p, {})
        if any(t in types for t in ("keyword", "ip", "boolean")) or \
           any(t.startswith(("long", "integer", "short", "double", "float"))
               for t in types):
            return p
        return p + ".keyword" if p + ".keyword" in known else None

    use = {p: aggregatable(p) for p in paths}
    use = {p: a for p, a in use.items() if a}
    if not use:
        return []
    body = {"size": 0, "query": query,
            "aggs": {f"f{i}": {"terms": {"field": a, "size": 6}}
                     for i, (_p, a) in enumerate(use.items())}}
    try:
        got = _req(f"{base}/{idx}/_search", h, verify, body)
    except LogError:
        return []
    out = []
    for i, (path, _a) in enumerate(use.items()):
        buckets = ((got.get("aggregations") or {}).get(f"f{i}") or {}).get("buckets") or []
        if len(buckets) < 2:
            continue
        top = sum(b["doc_count"] for b in buckets) or 1
        # NB: not "values" — Jinja resolves dict.values() before a key of that
        # name, so the template would iterate a bound method.
        out.append({"field": path,
                    "label": path.split(".")[-1].replace("_", " "),
                    "vals": [{"v": str(b["key"]), "n": b["doc_count"],
                                "pct": round(b["doc_count"] / top * 100)}
                               for b in buckets]})
    return out


def _signatures(entries: list, top: int = 6) -> list:
    """The handful of message shapes that account for most of the noise."""
    from collections import Counter
    errs = [e for e in entries if e["level"] == "error"] or entries
    if not errs:
        return []
    counts = Counter(signature(e["message"]) for e in errs)
    samples = {}
    for e in errs:
        samples.setdefault(signature(e["message"]), e["message"])
    total = sum(counts.values()) or 1
    return [{"pattern": p[:180], "n": n, "pct": round(n / total * 100),
             "sample": samples.get(p, "")[:220],
             "of": "error entries" if any(e["level"] == "error" for e in entries)
                   else "entries"}
            for p, n in counts.most_common(top) if n > 1]


def explore(conn: dict, q: str = "", level: str = "", minutes: int = 60,
            limit: int = PAGE_DEFAULT, refresh: bool = False) -> dict:
    """Search plus the context that makes it an investigation."""
    def produce():
        if conn.get("type") == "elasticsearch":
            return _es_explore(conn, q, level, minutes, limit)
        got = _loki_search(conn, q, level, minutes, limit)
        got.setdefault("histogram", [])
        got["facets"] = []
        got["signatures"] = _signatures(got["entries"])
        return got
    return _cached(conn, "explore", f"{q}:{level}:{minutes}:{limit}", refresh, produce)
