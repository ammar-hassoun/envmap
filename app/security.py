"""Security scan platforms — DefectDojo, Dependency-Track, SonarQube.

Same contract as ci.py: every platform is reduced to one shape so the UI never
learns which tool produced the data, and adding a scanner means adding one
provider entry plus its part functions.

Read-only. Every call is a GET — the portal reports findings, it never triages,
suppresses or re-scans. That belongs in the scanner's own UI.

WHY THIS IS SPLIT INTO "PARTS"
    A real DefectDojo here holds ~87k findings across 75 products. Pulling all
    of it for one page took 28s, almost entirely serial pagination. The API also
    gets *slower* under concurrency (it is database-bound, not connection-bound),
    so fanning out does not rescue a design that asks for too much.
    So each screen asks only for what it shows:
        overview(conn)        5 severity counts            → the hub boxes
        products(conn)        products + engagements       → the product table
        findings(conn)        one worst-first page         → the findings table
        scans(conn)           newest tests                 → the scan feed
        product(conn, id)     counts scoped to one product → per-product detail
    Each part is cached independently, so switching tabs never re-pulls a part
    that is already warm.

Normalised shapes:
    product : {id, name, group, total, sev{}, engagements, last, url, ...}
    finding : {title, severity, product, component, cve, when, status, url}
severity is always one of SEVERITIES.
"""
import base64
import json
import ssl
import threading
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

TIMEOUT = 25
CACHE_TTL = 120
# DefectDojo degrades under parallel load: per-request latency roughly triples
# from 4 workers upward while throughput barely moves. Keep fan-out modest.
WORKERS = 5
SEVERITIES = ("critical", "high", "medium", "low", "info")
PAGE_DEFAULT = 200

PROVIDERS = {
    "defectdojo": {
        "label": "DefectDojo",
        "icon": "🛡",
        "url_hint": "https://defectdojo.example.com",
        "needs": ["base_url", "token"],
        "scope_label": "product type (optional)",
        "scope_hint": "blank = every product type",
        "note": "An API v2 key from your DefectDojo profile "
                "(User → API v2 Key). A read-only role is enough.",
    },
    "dependencytrack": {
        "label": "Dependency-Track",
        "icon": "📦",
        "url_hint": "https://dependency-track.example.com",
        "needs": ["base_url", "token"],
        "scope_label": "project tag (optional)",
        "scope_hint": "blank = every project",
        "note": "An API key from a team with VIEW_PORTFOLIO and "
                "VIEW_VULNERABILITY permissions.",
    },
    "wazuh": {
        "label": "Wazuh",
        "icon": "🛰",
        "url_hint": "https://wazuh.example.com:55000",
        "needs": ["base_url", "username", "token"],
        "scope_label": "agent group (optional)",
        "scope_hint": "blank = every agent",
        "note": "The Wazuh API, not the dashboard — port 55000 by default. A "
                "read-only user is enough: it needs agent:read, and "
                "vulnerability:read if this version still serves "
                "vulnerabilities from the API. The password is exchanged for a "
                "short-lived JWT on every fetch and never stored beyond the "
                "connection itself.",
    },
    "sonarqube": {
        "label": "SonarQube",
        "icon": "🔎",
        "url_hint": "https://sonarqube.example.com",
        "needs": ["base_url", "token"],
        "scope_label": "project key filter (optional)",
        "scope_hint": "blank = every project",
        "note": "A user token (My Account → Security). Reports the quality "
                "gate, the ratings and the measures behind them; the severity "
                "totals on the security hub count vulnerabilities only, since "
                "a code smell is not one.",
    },
}


class SecError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _get(url: str, headers: dict, verify: bool = True):
    req = urllib.request.Request(
        urlguard.check(url), headers={"Accept": "application/json",
                                               **headers})
    ctx = None if verify else _INSECURE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read().decode("utf-8", "replace")
        return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise SecError(f"authentication rejected ({e.code}) — check the API "
                           "key and its permissions") from e
        if e.code == 404:
            raise SecError("not found (404) — check the base URL") from e
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:160]
        except Exception:
            pass
        raise SecError(f"HTTP {e.code} {detail}".strip()) from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason or "SSLCertVerification" in reason:
            raise SecError(
                f"TLS certificate rejected: {reason}. If this is an internal "
                "server with an expired or self-signed certificate, tick "
                "'skip TLS verification' on the connection.") from e
        raise SecError(f"cannot reach the server: {reason}") from e
    except json.JSONDecodeError:
        raise SecError("the server did not return JSON — is the base URL right? "
                       "It should be the root, not a page inside the UI.")
    except Exception as e:                          # noqa: BLE001
        raise SecError(f"{type(e).__name__}: {e}".strip()[:200]
                       or "unexpected transport error") from e


def _basic(user: str, secret: str) -> dict:
    tok = base64.b64encode(f"{user}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {tok}"}


def _blank() -> dict:
    return {s: 0 for s in SEVERITIES}


def _weight(sev: dict) -> int:
    return (sev["critical"] * 100000 + sev["high"] * 1000
            + sev["medium"] * 10 + sev["low"])


def _ago(iso) -> str:
    if not iso:
        return ""
    try:
        s = str(iso).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        d = datetime.now(timezone.utc) - dt
        if d.days > 730:
            return f"{d.days // 365}y ago"
        if d.days > 60:
            return f"{d.days // 30}mo ago"
        if d.days:
            return f"{d.days}d ago"
        h = d.seconds // 3600
        if h:
            return f"{h}h ago"
        m = d.seconds // 60
        return f"{m}m ago" if m else "just now"
    except Exception:
        return ""


def _epoch_ago(ms) -> str:
    if not ms:
        return ""
    try:
        return _ago(datetime.fromtimestamp(int(ms) / 1000, timezone.utc).isoformat())
    except Exception:
        return ""


def _iso_of(v) -> str:
    if not v:
        return ""
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / 1000, timezone.utc).isoformat()
        except Exception:
            return ""
    return str(v)


# ── part cache ─────────────────────────────────────────────────
_CACHE: dict[str, tuple[float, object]] = {}
_REFRESHING: set[str] = set()
_REFRESH_GUARD = threading.Lock()


def invalidate() -> None:
    _CACHE.clear()


def _cached(conn: dict, part: str, extra: str, refresh: bool, produce):
    """Serve warm instantly; serve STALE instantly while one background thread
    refreshes it (single-flight per key). This cache used to block on expiry,
    which meant that every CACHE_TTL somebody's click paid the whole cold cost
    of this DefectDojo — a findings view is ~35 count/page calls, and this
    instance has been measured at ~15s for a products pull. A read-only console
    two minutes old is right; a page that hangs half a minute is not.

    Blocking remains in exactly two cases, both deliberate: the FIRST look at a
    part (there is nothing to serve yet), and `refresh=True` (the Refresh
    button is a person asking for now, so it waits for now). A background
    refresh that fails keeps the stale value and will be retried on the next
    stale hit."""
    key = f"{conn.get('id') or conn.get('base_url','')}::{part}::{extra}"
    hit = _CACHE.get(key)
    now = time.time()
    if hit and not refresh:
        if now - hit[0] < CACHE_TTL:
            return hit[1]
        with _REFRESH_GUARD:
            spawn = key not in _REFRESHING
            if spawn:
                _REFRESHING.add(key)
        if spawn:
            def run():
                try:
                    _CACHE[key] = (time.time(), produce())
                except Exception:                              # noqa: BLE001
                    pass                 # stale stays; the next hit retries
                finally:
                    with _REFRESH_GUARD:
                        _REFRESHING.discard(key)
            threading.Thread(target=run, daemon=True).start()
        return hit[1]
    got = produce()
    _CACHE[key] = (time.time(), got)
    return got


# ── DefectDojo ─────────────────────────────────────────────────
def _dd_ctx(c: dict) -> tuple[str, dict, bool]:
    return (c["base_url"].rstrip("/"),
            {"Authorization": f"Token {c['token']}"},
            not c.get("skip_tls"))


_DD_OPEN = {"active": "true", "duplicate": "false"}

# The finding STATUS dimension — DefectDojo's whole lifecycle, not only the
# open slice the page always showed. key -> (label, param overrides on top of
# _DD_OPEN; None REMOVES a default, so "all" can drop the active filter).
# Duplicates stay excluded everywhere: a duplicate is bookkeeping, not a state.
STATUSES = {
    "": ("Open", {}),
    "closed": ("Closed", {"active": "false"}),
    "mitigated": ("Mitigated", {"active": None, "is_mitigated": "true"}),
    "accepted": ("Risk accepted", {"active": None, "risk_accepted": "true"}),
    "false": ("False positives", {"active": None, "false_p": "true"}),
    "out": ("Out of scope", {"active": None, "out_of_scope": "true"}),
    "all": ("All", {"active": None}),
}

# how a non-DefectDojo row's status TEXT maps into the same keys, so the filter
# means the same thing on every platform that reports a status at all
_STATUS_TEXT = {
    "": ("active", "verified"),
    "closed": ("mitigated", "risk accepted", "false positive", "out of scope"),
    "mitigated": ("mitigated",),
    "accepted": ("risk accepted",),
    "false": ("false positive",),
    "out": ("out of scope",),
}


def _dd_page(base: str, path: str, h: dict, verify: bool, **params):
    q = urllib.parse.urlencode(params)
    return _get(f"{base}/api/v2/{path}?{q}", h, verify)


def _dd_all(base: str, path: str, h: dict, verify: bool, cap: int = 1000,
            page: int = 200, **params) -> list:
    """Page through a cheap collection endpoint, fetching pages 2..N in
    parallel once page 1 has told us the total."""
    first = _dd_page(base, path, h, verify, limit=page, offset=0, **params)
    rows = list(first.get("results") or [])
    total = min(first.get("count") or len(rows), cap)
    offsets = list(range(len(rows), total, page))
    if offsets:
        def grab(off):
            return (_dd_page(base, path, h, verify, limit=page,
                             offset=off, **params).get("results") or [])
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(offsets))) as pool:
            for got in pool.map(grab, offsets):
                rows += got
    return rows[:cap]


def _dd_count(base: str, h: dict, verify: bool, **params) -> int:
    # a None value REMOVES an open-default (the status dimension needs to be
    # able to ask about inactive findings); everything else merges over it
    merged = {k: v for k, v in {**_DD_OPEN, **params}.items() if v is not None}
    return _dd_page(base, "findings/", h, verify, limit=1,
                    **merged).get("count") or 0


def _dd_sev_counts(base: str, h: dict, verify: bool, **scope) -> tuple[dict, list]:
    """Exact per-severity counts. Five count-only queries, run together.

    Returns (counts, failed). A failed query must never be reported as a count
    of zero: "0 high-severity findings" and "we could not ask" mean opposite
    things on a security dashboard. One retry absorbs the transient failures
    this API occasionally returns under concurrent load; anything still failing
    is named so the UI can say so.
    """
    def one(sev):
        for attempt in (1, 2):
            try:
                return sev, _dd_count(base, h, verify,
                                      severity=sev.capitalize(), **scope), True
            except SecError:
                if attempt == 2:
                    return sev, 0, False
                time.sleep(0.4)
        return sev, 0, False

    counts, failed = {}, []
    with ThreadPoolExecutor(max_workers=5) as pool:
        for sev, n, ok in pool.map(one, SEVERITIES):
            counts[sev] = n
            if not ok:
                failed.append(sev)
    return {s: counts.get(s, 0) for s in SEVERITIES}, failed


def _dd_overview(c: dict) -> dict:
    base, h, verify = _dd_ctx(c)
    totals, failed = _dd_sev_counts(base, h, verify)
    try:
        n = _dd_page(base, "products/", h, verify, limit=1).get("count") or 0
    except SecError:
        n = 0
    return {"totals": totals, "products": n, "open": sum(totals.values()),
            "incomplete": failed}


def _dd_products(c: dict) -> list:
    """Product rows. `findings_count` on the product payload is already the
    open (active, non-duplicate) count — verified against scoped count queries —
    so per-product totals cost nothing extra. The severity split is deliberately
    not here: it would be 5 queries per product, and this instance needs ~15s
    for 75 products. It lives on the product page instead, where it is exact."""
    base, h, verify = _dd_ctx(c)
    scope = (c.get("scope") or "").strip().lower()

    def pull():
        ptypes = {p["id"]: p.get("name") or "?"
                  for p in _dd_all(base, "product_types/", h, verify, cap=500)}
        prods = _dd_all(base, "products/", h, verify, cap=2000)
        engs = _dd_all(base, "engagements/", h, verify, cap=3000)
        return ptypes, prods, engs

    ptypes, prods, engs = pull()

    last, count = {}, {}
    for e in engs:
        pid = e.get("product")
        count[pid] = count.get(pid, 0) + 1
        when = e.get("target_end") or e.get("updated") or e.get("created") or ""
        if when > last.get(pid, ""):
            last[pid] = when

    rows = []
    for p in prods:
        group = ptypes.get(p.get("prod_type"), "")
        if scope and scope not in group.lower():
            continue
        pid = p["id"]
        rows.append({
            "id": pid, "name": p.get("name") or "?", "group": group,
            "url": f"{base}/product/{pid}", "total": p.get("findings_count") or 0,
            "sev": _blank(), "sev_known": False,
            "engagements": count.get(pid, 0),
            "last": _ago(last.get(pid, "")), "last_iso": last.get(pid, ""),
            "grade": p.get("prod_numeric_grade"),
            "criticality": (p.get("business_criticality") or "").replace("_", " "),
            "tags": [str(t) for t in (p.get("tags") or [])],
        })
    rows.sort(key=lambda r: (-r["total"], r["name"].lower()))
    return rows


def _dd_status(f: dict) -> str:
    if f.get("false_p"):
        return "false positive"
    if f.get("risk_accepted"):
        return "risk accepted"
    if f.get("out_of_scope"):
        return "out of scope"
    if f.get("is_mitigated") or f.get("mitigated"):
        return "mitigated"
    return "verified" if f.get("verified") else "active"


def _dd_cve(f: dict) -> str:
    if f.get("cve"):
        return str(f["cve"])
    for v in (f.get("vulnerability_ids") or []):
        got = (v or {}).get("vulnerability_id") if isinstance(v, dict) else v
        if got:
            return str(got)
    cwe = f.get("cwe")
    return f"CWE-{cwe}" if cwe else ""


def _dd_row(f: dict, base: str) -> dict:
    """One finding. related_fields embeds test → engagement → product, which
    removes the need to pull every test and engagement just to name the product
    — and the API answers it faster than the plain call."""
    sev = (f.get("severity") or "info").lower()
    rf = (f.get("related_fields") or {})
    test = rf.get("test") or {}
    eng = test.get("engagement") or {}
    prod = eng.get("product") or {}
    ttype = test.get("test_type") or {}
    comp = f.get("component_name") or ""
    if comp and f.get("component_version"):
        comp += f" {f['component_version']}"
    return {
        "id": f.get("id"), "title": f.get("title") or "?",
        "severity": sev if sev in SEVERITIES else "info",
        "product": prod.get("name") or "", "product_id": prod.get("id"),
        "group": ((prod.get("prod_type") or {}) or {}).get("name") or "",
        "engagement": eng.get("name") or "", "component": comp,
        "cve": _dd_cve(f), "when": _ago(f.get("date")), "status": _dd_status(f),
        "tool": (ttype.get("name") if isinstance(ttype, dict) else "")
                or test.get("title") or "",
        "branch": test.get("branch_tag") or "",
        "sla": f.get("sla_days_remaining"),
        "url": f"{base}/finding/{f.get('id')}",
    }


def _dd_findings(c: dict, limit: int, offset: int, **scope) -> dict:
    """One page of findings, worst severity first. numerical_severity ascending
    puts S0 (critical) at the top."""
    base, h, verify = _dd_ctx(c)
    merged = {k: v for k, v in {**_DD_OPEN, **scope}.items() if v is not None}
    d = _dd_page(base, "findings/", h, verify, limit=limit, offset=offset,
                 o="numerical_severity", related_fields="true", **merged)
    rows = [_dd_row(f, base) for f in (d.get("results") or [])]
    return {"rows": rows, "total": d.get("count") or len(rows),
            "limit": limit, "offset": offset}


def _vuln_url(vid: str) -> str:
    """Where a reference id is documented — NVD for CVEs, GitHub for GHSAs,
    MITRE for CWEs. Empty when the shape is not recognised, and the template
    renders a plain chip rather than a link to nowhere."""
    v = (vid or "").strip().upper()
    if v.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{v}"
    if v.startswith("GHSA-"):
        return f"https://github.com/advisories/{v}"
    if v.startswith("CWE-") and v[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{v[4:]}.html"
    return ""


def _dd_finding(c: dict, fid: int) -> dict:
    """One finding, whole — everything DefectDojo holds about it, so the CVE
    can be read here instead of in the DefectDojo UI. The list row's fields
    come from _dd_row so the header of the detail always agrees with the row
    that was clicked; the long texts (description, mitigation, impact,
    references) are the platform's own words, rendered as text."""
    base, h, verify = _dd_ctx(c)
    f = _get(f"{base}/api/v2/findings/{int(fid)}/?related_fields=true",
             h, verify)
    row = _dd_row(f, base)
    # every reference id, not only the first the row shows
    vulns = [str(f["cve"])] if f.get("cve") else []
    for v in (f.get("vulnerability_ids") or []):
        got = (v or {}).get("vulnerability_id") if isinstance(v, dict) else v
        if got and str(got) not in vulns:
            vulns.append(str(got))
    if f.get("cwe") and f"CWE-{f['cwe']}" not in vulns:
        vulns.append(f"CWE-{f['cwe']}")
    refs = [{"id": v, "url": _vuln_url(v)} for v in vulns]
    flags = [label for cond, label in (
        (f.get("active"), "active"),
        (f.get("verified"), "verified"),
        (f.get("duplicate"), "duplicate"),
        (f.get("false_p"), "false positive"),
        (f.get("risk_accepted"), "risk accepted"),
        (f.get("out_of_scope"), "out of scope"),
        (f.get("is_mitigated") or f.get("mitigated"), "mitigated"),
        (f.get("under_review"), "under review"),
    ) if cond]
    # notes are a separate endpoint and strictly optional — a finding must
    # render whole even when the key may not read notes
    notes = []
    try:
        for n in (_dd_page(base, f"findings/{int(fid)}/notes/", h, verify)
                  .get("results") or []):
            notes.append({
                "who": ((n.get("author") or {}).get("username")) or "?",
                "when": _iso_of(n.get("date"))[:16].replace("T", " "),
                "text": n.get("entry") or ""})
    except Exception:                                          # noqa: BLE001
        pass
    return {
        **row,
        "refs": refs, "flags": flags,
        "description": f.get("description") or "",
        "mitigation": f.get("mitigation") or "",
        "impact": f.get("impact") or "",
        "references": f.get("references") or "",
        "steps": f.get("steps_to_reproduce") or "",
        "justification": f.get("severity_justification") or "",
        "cvss": f.get("cvssv3") or "",
        "cvss_score": f.get("cvssv3_score"),
        "epss": f.get("epss_score"),
        "file": f.get("file_path") or "", "line": f.get("line"),
        "date": _iso_of(f.get("date"))[:10],
        "mitigated_on": (_iso_of((f.get("mitigated") or {}).get("date")
                                 if isinstance(f.get("mitigated"), dict)
                                 else f.get("mitigated"))[:10]
                         if f.get("mitigated") else ""),
        "tags": f.get("tags") or [],
        "notes": notes,
    }


def _dd_scans(c: dict) -> list:
    base, h, verify = _dd_ctx(c)
    tests = (_dd_page(base, "tests/", h, verify, limit=60, o="-created")
             .get("results") or [])
    engs = {e["id"]: e for e in _dd_all(base, "engagements/", h, verify, cap=3000)}
    names = {p["id"]: p["name"] for p in products(c)}
    ttypes = {t["id"]: t.get("name") or "?"
              for t in _dd_all(base, "test_types/", h, verify, cap=1000)}
    out = []
    for t in tests:
        eng = engs.get(t.get("engagement")) or {}
        when = t.get("target_end") or t.get("created") or ""
        out.append({
            "name": t.get("scan_type") or ttypes.get(t.get("test_type")) or "test",
            "product": names.get(eng.get("product"), ""),
            "engagement": eng.get("name") or "",
            "when": _ago(when), "iso": _iso_of(when),
            "url": f"{base}/test/{t['id']}",
        })
    out.sort(key=lambda s: s["iso"], reverse=True)
    return out


def _dd_product(c: dict, pid) -> dict:
    """One product, exactly: severity counts scoped to it plus its worst
    findings. Cheap because the product filter is indexed — note it must be
    test__engagement__product; a bare `product=` is silently ignored by the
    API and would return portfolio-wide numbers."""
    base, h, verify = _dd_ctx(c)
    scope = {"test__engagement__product": pid}
    sev, failed = _dd_sev_counts(base, h, verify, **scope)
    page = _dd_findings(c, PAGE_DEFAULT, 0, **scope)
    row = next((p for p in products(c) if str(p["id"]) == str(pid)), None)
    return {"product": row, "sev": sev, "total": sum(sev.values()),
            "findings": page["rows"], "findings_total": page["total"],
            "incomplete": failed}


# ── Dependency-Track ───────────────────────────────────────────
def _dependencytrack(c: dict) -> dict:
    """Small enough to pull whole: the project list carries its own metrics."""
    base = c["base_url"].rstrip("/")
    verify = not c.get("skip_tls")
    h = {"X-Api-Key": c["token"]}
    scope = (c.get("scope") or "").strip().lower()

    projects: list = []
    page = 1
    while len(projects) < 500:
        got = _get(f"{base}/api/v1/project?pageSize=100&pageNumber={page}"
                   f"&excludeInactive=true", h, verify)
        if not isinstance(got, list) or not got:
            break
        projects += got
        page += 1
        if len(got) < 100:
            break

    rows, totals = [], _blank()
    for p in projects:
        tags = [str((t or {}).get("name", t)) for t in (p.get("tags") or [])]
        if scope and not any(scope in t.lower() for t in tags):
            continue
        m = p.get("metrics") or {}
        sev = {"critical": m.get("critical") or 0, "high": m.get("high") or 0,
               "medium": m.get("medium") or 0, "low": m.get("low") or 0,
               "info": m.get("unassigned") or 0}
        for s in SEVERITIES:
            totals[s] += sev[s]
        name = p.get("name") or "?"
        if p.get("version"):
            name += f" {p['version']}"
        last = p.get("lastBomImport")
        rows.append({
            "id": p.get("uuid", ""), "name": name,
            "group": tags[0] if tags else "untagged",
            "url": f"{base}/projects/{p.get('uuid','')}", "sev": sev,
            "sev_known": True, "total": sum(sev.values()), "engagements": 0,
            "last": _epoch_ago(last), "last_iso": _iso_of(last),
            "grade": m.get("inheritedRiskScore"), "criticality": "", "tags": tags,
        })
    rows.sort(key=lambda r: (-_weight(r["sev"]), r["name"].lower()))

    worst = [r for r in rows if r["total"]][:8]
    findings: list = []

    def detail(r):
        try:
            return r, _get(f"{base}/api/v1/finding/project/{r['id']}", h, verify)
        except SecError:
            return r, []

    if worst:
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(worst))) as pool:
            for r, got in pool.map(detail, worst):
                for f in (got if isinstance(got, list) else []):
                    v = f.get("vulnerability") or {}
                    comp = f.get("component") or {}
                    an = f.get("analysis") or {}
                    if an.get("isSuppressed"):
                        continue
                    sev = (v.get("severity") or "info").lower()
                    findings.append({
                        "id": v.get("vulnId"),
                        "title": v.get("title") or v.get("vulnId") or "?",
                        "severity": sev if sev in SEVERITIES else "info",
                        "product": r["name"], "product_id": r["id"],
                        "group": r["group"], "engagement": "",
                        "component": " ".join(x for x in (comp.get("name"),
                                                          comp.get("version")) if x),
                        "cve": v.get("vulnId") or "",
                        "when": _epoch_ago((f.get("attribution") or {}).get("attributedOn")),
                        "status": (an.get("state") or "not set").lower().replace("_", " "),
                        "tool": v.get("source") or "", "branch": "", "sla": None,
                        "url": f"{base}/vulnerabilities/{v.get('source','')}/{v.get('vulnId','')}",
                    })
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))

    scans = sorted([{"name": "BOM import", "product": r["name"], "engagement": "",
                     "when": r["last"], "iso": r["last_iso"], "url": r["url"]}
                    for r in rows if r["last_iso"]],
                   key=lambda s: s["iso"], reverse=True)
    return {"products": rows, "findings": findings, "scans": scans,
            "totals": totals,
            "note": "component detail covers the 8 highest-risk projects; "
                    "the counts come from every project"}


# ── SonarQube ──────────────────────────────────────────────────
_SONAR_SEV = {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium",
              "MINOR": "low", "INFO": "info"}

# What the portal reads for every project in one bulk call. The split matters:
# the first group is what Sonar is *for* — a gate that passes or fails and the
# ratings behind it — and the second is the raw counts people ask about.
_SONAR_METRICS = ("alert_status,bugs,vulnerabilities,code_smells,"
                  "security_hotspots,coverage,duplicated_lines_density,ncloc,"
                  "sqale_index,reliability_rating,security_rating,sqale_rating,"
                  "security_review_rating")

# Sonar reports its ratings as 1.0–5.0 and shows them as letters everywhere in
# its own UI, so a portal showing "3.0" would be a worse copy of it.
_RATINGS = {1: "A", 2: "B", 3: "C", 4: "D", 5: "E"}

# The gate conditions in the language people use, so a failing gate reads as a
# sentence rather than as a metric key nobody outside Sonar recognises.
_METRIC_WORDS = {
    "new_coverage": "coverage on new code",
    "coverage": "coverage",
    "new_duplicated_lines_density": "duplicated lines on new code",
    "duplicated_lines_density": "duplicated lines",
    "new_violations": "new issues",
    "new_bugs": "new bugs", "bugs": "bugs",
    "new_vulnerabilities": "new vulnerabilities", "vulnerabilities": "vulnerabilities",
    "new_code_smells": "new code smells", "code_smells": "code smells",
    "new_security_hotspots_reviewed": "hotspots reviewed on new code",
    "new_reliability_rating": "reliability on new code",
    "new_security_rating": "security on new code",
    "new_maintainability_rating": "maintainability on new code",
    "reliability_rating": "reliability", "security_rating": "security",
    "sqale_rating": "maintainability",
}


def _rating(value) -> str:
    try:
        return _RATINGS.get(int(float(value)), "")
    except (TypeError, ValueError):
        return ""


def _num(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _tidy(value) -> str:
    """A measured value as somebody would write it, not as JSON returned it.

    Sonar reports a duplication of 16.64746 and a coverage of 0.0. Printing
    those verbatim reads as machine output and makes two numbers of different
    precision impossible to compare at a glance.
    """
    n = _num(value)
    if n is None:
        return "" if value is None else str(value)
    return str(int(n)) if float(n).is_integer() else f"{n:.1f}"


def _plural(word: str, n: int) -> str:
    """Sonar's issue types are singular nouns; one of them ends in y."""
    if n == 1:
        return word
    return word[:-1] + "ies" if word.endswith("y") else word + "s"


def _debt(minutes) -> str:
    """Sonar's technical debt is a count of minutes; nobody reads it that way."""
    m = _num(minutes)
    if m is None:
        return ""
    if m < 60:
        return f"{int(m)}min"
    hours = m / 60
    if hours < 8:
        return f"{hours:.0f}h"
    days = hours / 8            # Sonar's own working day
    return f"{days:.0f}d" if days < 365 else f"{days / 365:.1f}y"


def _sonar_measures(base: str, h: dict, verify: bool, keys: list) -> dict:
    """{project key: {metric: value}} for many projects in as few calls as
    possible — one request per 100 keys rather than one per project."""
    out: dict = {}
    for i in range(0, len(keys), 100):
        chunk = keys[i:i + 100]
        q = urllib.parse.urlencode({"projectKeys": ",".join(chunk),
                                    "metricKeys": _SONAR_METRICS})
        try:
            d = _get(f"{base}/api/measures/search?{q}", h, verify)
        except SecError:
            continue
        for m in (d.get("measures") or []):
            out.setdefault(m.get("component", ""), {})[m.get("metric", "")] = \
                m.get("value")
    return out


def _sonar_gate(base: str, h: dict, verify: bool, key: str) -> dict:
    """The quality gate and, when it is failing, exactly which conditions."""
    q = urllib.parse.urlencode({"projectKey": key})
    try:
        d = _get(f"{base}/api/qualitygates/project_status?{q}", h, verify)
    except SecError:
        return {"status": "", "conditions": []}
    ps = d.get("projectStatus") or {}
    conds = []
    for c in (ps.get("conditions") or []):
        metric = c.get("metricKey", "")
        actual, want = c.get("actualValue"), c.get("errorThreshold")
        # a rating condition compares 1–5, so its numbers have to be letters
        if metric.endswith("_rating"):
            actual, want = _rating(actual), _rating(want)
        else:
            actual, want = _tidy(actual), _tidy(want)
        conds.append({
            "metric": metric,
            "label": _METRIC_WORDS.get(metric, metric.replace("_", " ")),
            "ok": (c.get("status") or "").upper() == "OK",
            "actual": actual, "want": want,
            "op": "must not exceed" if c.get("comparator") == "GT"
                  else "must be at least",
        })
    return {"status": (ps.get("status") or "").upper(),
            "conditions": conds,
            "period": ((ps.get("period") or {}).get("date") or "")[:10]}


def _sonar_quality(measures: dict) -> dict:
    """The measure block the pages read, already in display form."""
    g = measures.get
    return {
        "gate": (g("alert_status") or "").upper(),
        "bugs": int(_num(g("bugs"), 0)),
        "vulnerabilities": int(_num(g("vulnerabilities"), 0)),
        "smells": int(_num(g("code_smells"), 0)),
        "hotspots": int(_num(g("security_hotspots"), 0)),
        "coverage": _num(g("coverage")),
        "duplication": _num(g("duplicated_lines_density")),
        "ncloc": int(_num(g("ncloc"), 0)),
        "debt": _debt(g("sqale_index")),
        "reliability": _rating(g("reliability_rating")),
        "security": _rating(g("security_rating")),
        "maintainability": _rating(g("sqale_rating")),
        "review": _rating(g("security_review_rating")),
    }


def _sonar_facets(base: str, h: dict, verify: bool, key: str) -> dict:
    """Unresolved issues for one project, counted by type and by severity."""
    q = urllib.parse.urlencode({"componentKeys": key, "resolved": "false",
                                "ps": 1, "facets": "types,severities"})
    try:
        d = _get(f"{base}/api/issues/search?{q}", h, verify)
    except SecError:
        return {"total": 0, "types": {}, "sev": _blank()}
    out = {"total": d.get("total") or 0, "types": {}, "sev": _blank()}
    for fc in (d.get("facets") or []):
        for v in (fc.get("values") or []):
            n = v.get("count") or 0
            if not n:
                continue
            if fc.get("property") == "types":
                kind = (v.get("val") or "").lower().replace("_", " ")
                out["types"][_plural(kind, n)] = n
            elif fc.get("property") == "severities":
                key_ = _SONAR_SEV.get((v.get("val") or "").upper())
                if key_:
                    out["sev"][key_] += n
    return out


def _sonarqube(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    verify = not c.get("skip_tls")
    h = _basic(c["token"], "")       # token as username works on every version
    scope = (c.get("scope") or "").strip().lower()

    comps: list = []
    page = 1
    while len(comps) < 400:
        d = _get(f"{base}/api/components/search?qualifiers=TRK&ps=200&p={page}",
                 h, verify)
        got = d.get("components") or []
        comps += got
        total = (d.get("paging") or {}).get("total") or len(comps)
        page += 1
        if not got or len(comps) >= total:
            break
    if scope:
        comps = [x for x in comps
                 if scope in (x.get("key", "") + x.get("name", "")).lower()]

    LIMIT = 40
    probed, dropped = comps[:LIMIT], max(0, len(comps) - LIMIT)

    # one call for every project's measures, rather than one call each
    measures = _sonar_measures(base, h, verify, [x.get("key", "") for x in probed])

    def per_project(comp):
        key = comp.get("key", "")
        # The severity buckets stay VULNERABILITY-only on purpose. They feed the
        # security hub, where they are added to DefectDojo's findings — and a
        # code smell is not a vulnerability. Bugs, smells and coverage are real
        # and are reported, but as quality measures beside the gate rather than
        # folded into a security total that other pages then quote.
        q = urllib.parse.urlencode({"componentKeys": key,
                                    "types": "VULNERABILITY", "resolved": "false",
                                    "ps": 1, "facets": "severities"})
        sev = _blank()
        try:
            d = _get(f"{base}/api/issues/search?{q}", h, verify)
            for fc in (d.get("facets") or []):
                if fc.get("property") != "severities":
                    continue
                for v in (fc.get("values") or []):
                    k = _SONAR_SEV.get((v.get("val") or "").upper())
                    if k:
                        sev[k] += v.get("count") or 0
        except SecError:
            pass
        return comp, sev, _sonar_gate(base, h, verify, key)

    rows, totals = [], _blank()
    failing = 0
    if probed:
        with ThreadPoolExecutor(max_workers=min(8, len(probed))) as pool:
            for comp, sev, gate in pool.map(per_project, probed):
                key = comp.get("key", "")
                for s in SEVERITIES:
                    totals[s] += sev[s]
                quality = _sonar_quality(measures.get(key, {}))
                quality["gate"] = gate["status"] or quality["gate"]
                if quality["gate"] == "ERROR":
                    failing += 1
                rows.append({
                    "id": key,
                    "name": comp.get("name") or key or "?",
                    "group": "", "sev": sev, "sev_known": True,
                    "total": sum(sev.values()), "engagements": 0,
                    "last": "", "last_iso": "", "grade": None,
                    "criticality": "", "tags": [],
                    "quality": quality, "gate_why": [c for c in gate["conditions"]
                                                     if not c["ok"]],
                    "url": f"{base}/dashboard?id={urllib.parse.quote(key)}",
                })
    # a failing gate is the thing to look at first; after that, the worst issues
    rows.sort(key=lambda r: (r["quality"]["gate"] != "ERROR",
                             -_weight(r["sev"]), r["name"].lower()))

    q = urllib.parse.urlencode({"types": "VULNERABILITY", "resolved": "false",
                                "ps": 100, "s": "SEVERITY", "asc": "false"})
    findings: list = []
    try:
        d = _get(f"{base}/api/issues/search?{q}", h, verify)
    except SecError:
        d = {}
    names = {r["id"]: r["name"] for r in rows}
    for i in (d.get("issues") or []):
        proj = i.get("project", "")
        findings.append({
            "id": i.get("key"), "title": i.get("message") or "?",
            "severity": _SONAR_SEV.get((i.get("severity") or "").upper(), "info"),
            "product": names.get(proj, proj), "product_id": proj, "group": "",
            "engagement": "", "component": (i.get("component") or "").split(":")[-1],
            "cve": i.get("rule") or "", "when": _ago(i.get("creationDate")),
            "status": (i.get("status") or "open").lower(), "tool": "sonarqube",
            "branch": "", "sla": None,
            "url": f"{base}/project/issues?id={urllib.parse.quote(proj)}"
                   f"&open={urllib.parse.quote(i.get('key',''))}",
        })
    return {"products": rows, "findings": findings, "scans": [], "totals": totals,
            "gates": {"failing": failing, "total": len(rows)},
            "note": (f"{dropped} more project(s) not counted — narrow the project "
                     "key filter on this connection" if dropped else "")}


def sonar_detail(conn: dict, key: str, refresh: bool = False) -> dict:
    """Everything Sonar knows about one project, so its own UI is not needed.

    Hotspots are counted from the measure rather than listed: the hotspots API
    refuses a plain user token on some installs, and a page that half-works is
    worse than one that says what it cannot show.
    """
    def produce():
        base = conn["base_url"].rstrip("/")
        verify = not conn.get("skip_tls")
        h = _basic(conn["token"], "")
        quality = _sonar_quality(_sonar_measures(base, h, verify, [key]).get(key, {}))
        gate = _sonar_gate(base, h, verify, key)
        quality["gate"] = gate["status"] or quality["gate"]
        facets = _sonar_facets(base, h, verify, key)

        issues = []
        q = urllib.parse.urlencode({"componentKeys": key, "resolved": "false",
                                    "ps": 100, "s": "SEVERITY", "asc": "false"})
        try:
            d = _get(f"{base}/api/issues/search?{q}", h, verify)
        except SecError:
            d = {}
        for i in (d.get("issues") or []):
            issues.append({
                "id": i.get("key"),
                "title": i.get("message") or "?",
                "severity": _SONAR_SEV.get((i.get("severity") or "").upper(), "info"),
                "type": (i.get("type") or "").replace("_", " ").lower(),
                "rule": i.get("rule") or "",
                "component": (i.get("component") or "").split(":")[-1],
                "line": i.get("line") or "",
                "effort": i.get("effort") or "",
                "when": _ago(i.get("creationDate")),
                "url": f"{base}/project/issues?id={urllib.parse.quote(key)}"
                       f"&open={urllib.parse.quote(i.get('key', ''))}",
            })
        return {"key": key, "quality": quality, "gate": gate, "facets": facets,
                "issues": issues, "shown": len(issues),
                "url": f"{base}/dashboard?id={urllib.parse.quote(key)}"}
    return _cached(conn, "sonar_detail", key, refresh, produce)


# ── public, part-wise API ──────────────────────────────────────
# Platforms that are cheap to pull whole go through _FULL and are sliced;
# DefectDojo has a native implementation for each part.
# ── Wazuh ──────────────────────────────────────────────────────────────────
# WHY WAZUH SITS UNDER SECURITY AND NOT LOGS
#     It is tempting to file a SIEM under Logs, and wrong here. Logs in this
#     portal means "search raw log lines", which is what the Elasticsearch
#     connections do — and Wazuh's own alert store IS an Elasticsearch, so if
#     that is what somebody wants they can add the Indexer as a log connection
#     and get a better experience than a SIEM API would give them.
#
#     What the Wazuh API is good for is posture: which hosts are reporting,
#     which have stopped, and what is outstanding on each. That is the same
#     question DefectDojo and SonarQube answer, in the same shape — a list of
#     things with severity counts — so it belongs beside them on the security
#     hub, where its numbers add to a total that means something.
WZ_SEV = {"critical": "critical", "high": "high", "medium": "medium",
          "low": "low", "untriaged": "info", "none": "info", "": "info"}
WZ_AGENTS = 500          # one page is plenty; a bigger estate gets a note
WZ_DETAIL = 40           # agents probed for vulnerabilities, worst-connected first


def _wz_items(d: dict) -> list:
    """Wazuh wraps everything in data.affected_items."""
    return ((d or {}).get("data") or {}).get("affected_items") or []


def _wz_token(base: str, user: str, secret: str, verify: bool) -> dict:
    """Exchange the password for a JWT.

    Wazuh has no long-lived API key: you authenticate with a user and get a
    token that expires in 15 minutes by default. So this happens on every
    fetch, which is also why the result is never cached — a stale JWT looks
    exactly like a wrong password.
    """
    d = _get(f"{base}/security/user/authenticate", _basic(user, secret), verify)
    tok = ((d or {}).get("data") or {}).get("token") or ""
    if not tok:
        raise SecError("Wazuh accepted the request but returned no token — "
                       "check the user has the authenticate permission")
    return {"Authorization": f"Bearer {tok}"}


def _wazuh(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    verify = not c.get("skip_tls")
    scope = (c.get("scope") or "").strip().lower()
    h = _wz_token(base, c.get("username") or "wazuh", c.get("token") or "", verify)

    version = ""
    try:
        info = _wz_items(_get(f"{base}/manager/info", h, verify))
        version = (info[0] or {}).get("version", "") if info else ""
    except SecError:
        pass                                  # cosmetic; never fail the fetch

    raw = _get(f"{base}/agents?limit={WZ_AGENTS}&sort=-lastKeepAlive", h, verify)
    agents = _wz_items(raw)
    total_agents = (((raw or {}).get("data") or {}).get("total_affected_items")
                    or len(agents))
    if scope:
        agents = [a for a in agents
                  if scope in " ".join(str(g).lower()
                                       for g in (a.get("group") or []))]

    # The manager itself is agent 000 and has no vulnerability surface of its
    # own worth reporting next to real hosts.
    agents = [a for a in agents if str(a.get("id")) != "000"]

    # Worst connection state first: a host that stopped reporting is the finding
    # here, and it is also the one whose vulnerability data is least current.
    order = {"never_connected": 0, "disconnected": 1, "pending": 2, "active": 3}
    agents.sort(key=lambda a: (order.get(a.get("status", ""), 9),
                               (a.get("name") or "").lower()))
    probed, dropped = agents[:WZ_DETAIL], max(0, len(agents) - WZ_DETAIL)

    vuln_gone = False
    rows, findings = [], []
    for a in probed:
        aid = str(a.get("id") or "")
        name = a.get("name") or aid or "?"
        sev = _blank()
        sev_known = False
        if not vuln_gone:
            try:
                items = _wz_items(_get(
                    f"{base}/vulnerability/{aid}?limit=500", h, verify))
                sev_known = True
                for v in items:
                    key = WZ_SEV.get(str(v.get("severity") or "").lower(), "info")
                    sev[key] += 1
                    if len(findings) < 400:
                        findings.append({
                            "id": f"{aid}:{v.get('cve') or v.get('title') or ''}",
                            "title": v.get("title") or v.get("cve") or "vulnerability",
                            "severity": key, "product": name, "product_id": aid,
                            "group": (a.get("group") or ["ungrouped"])[0],
                            "engagement": "", "component": v.get("name") or "",
                            "cve": v.get("cve") or "", "when": _ago(v.get("detection_time")),
                            "status": str(v.get("condition") or "open").lower(),
                            "tool": "Wazuh", "branch": "", "sla": "",
                            "url": f"{base}/vulnerability/{aid}",
                        })
            except SecError:
                # 4.8 moved vulnerabilities out of the API and into the indexer.
                # One 404 is enough to know; asking 40 times is just slower.
                vuln_gone = True

        rows.append({
            "id": aid, "name": name,
            "group": (a.get("group") or ["ungrouped"])[0],
            "url": f"{base}/agents?agents_list={aid}", "sev": sev,
            "sev_known": sev_known, "total": sum(sev.values()), "engagements": 0,
            "last": _ago(a.get("lastKeepAlive")),
            "last_iso": _iso_of(a.get("lastKeepAlive")),
            "grade": None,
            # the status is the point for an agent, so it is what shows as the
            # criticality chip rather than being buried in a tooltip
            "criticality": a.get("status") or "",
            "tags": [t for t in [a.get("status"),
                                 (a.get("os") or {}).get("name"),
                                 a.get("version")] if t],
        })

    totals = _blank()
    for r in rows:
        for k, n in r["sev"].items():
            totals[k] += n

    down = [r["name"] for r in rows
            if r["criticality"] in ("disconnected", "never_connected")]
    notes = []
    if version:
        notes.append(f"Wazuh {version}")
    notes.append(f"{len(agents)} agent{'s' if len(agents) != 1 else ''} in scope"
                 + (f" of {total_agents}" if total_agents > len(agents) else ""))
    if down:
        notes.append(f"{len(down)} not reporting: "
                     + ", ".join(down[:6]) + ("…" if len(down) > 6 else ""))
    if vuln_gone:
        notes.append("this version serves vulnerabilities from the indexer "
                     "rather than the API, so severity counts are unavailable "
                     "here — add the Wazuh indexer as a log connection to "
                     "search them")
    if dropped:
        notes.append(f"{dropped} further agents listed without vulnerability "
                     f"detail")

    scans = sorted(({"product": r["name"], "product_id": r["id"],
                     "tool": "Wazuh agent", "when": r["last"],
                     "iso": r["last_iso"], "url": r["url"]}
                    for r in rows if r["last_iso"]),
                   key=lambda s: s["iso"], reverse=True)
    return {"products": rows, "findings": findings, "scans": scans,
            "totals": totals, "note": " · ".join(notes)}


_FULL = {"dependencytrack": _dependencytrack, "sonarqube": _sonarqube,
         "wazuh": _wazuh}


def _full(conn: dict, refresh: bool = False) -> dict:
    fn = _FULL.get(conn.get("type"))
    if not fn:
        raise SecError(f"unknown security platform '{conn.get('type')}'")
    return _cached(conn, "full", "", refresh, lambda: fn(conn))


def _is_dd(conn: dict) -> bool:
    return conn.get("type") == "defectdojo"


def overview(conn: dict, refresh: bool = False) -> dict:
    """Portfolio counts only — what the hub and connection boxes need."""
    def produce():
        if _is_dd(conn):
            return _dd_overview(conn)
        got = _full(conn, refresh)
        return {"totals": got["totals"], "products": len(got["products"]),
                "open": sum(got["totals"].values()), "note": got.get("note", ""),
                "incomplete": []}
    return _cached(conn, "overview", "", refresh, produce)


def products(conn: dict, refresh: bool = False) -> list:
    def produce():
        return (_dd_products(conn) if _is_dd(conn)
                else _full(conn, refresh)["products"])
    return _cached(conn, "products", "", refresh, produce)


def sev_counts(conn: dict, refresh: bool = False, q: str = "",
               group: str = "", status: str = "") -> dict:
    """Per-severity counts IN A SCOPE — the numbers behind the severity tiles
    on a connection's findings view. The tiles used to show the connection-wide
    open counts whatever the page below them was filtered to, so "CRITICAL
    15,113" sat directly above a list of 109 — two universes on one page.
    Same scope contract as status_counts(): group, title search, and the
    lifecycle status being viewed (tiles above a Closed list count CLOSED)."""
    status = status if status in STATUSES else ""

    def produce():
        if not _is_dd(conn):
            rows = _full(conn, refresh)["findings"]
            if status and status != "all":
                want = _STATUS_TEXT.get(status, ())
                rows = [r for r in rows if (r.get("status") or "") in want]
            if group:
                rows = [r for r in rows if r.get("group") == group]
            if q:
                ql = q.lower()
                rows = [r for r in rows if ql in r["title"].lower()
                        or ql in (r.get("component") or "").lower()
                        or ql in (r.get("cve") or "").lower()]
            return {s: sum(1 for r in rows if r["severity"] == s)
                    for s in SEVERITIES}
        base, h, verify = _dd_ctx(conn)
        extra = dict(STATUSES[status][1])
        if q:
            extra["title"] = q
        if group:
            gid = group_ids(conn).get(group)
            if gid is not None:
                extra["test__engagement__product__prod_type"] = gid
        counts, _failed = _dd_sev_counts(base, h, verify, **extra)
        return counts
    return _cached(conn, "sevs", f"{q}:{group}:{status}", refresh, produce)


def group_ids(conn: dict, refresh: bool = False) -> dict:
    """Group name → id, for platforms whose findings can be filtered by group.
    DefectDojo product types qualify; nothing else needs it."""
    def produce():
        if not _is_dd(conn):
            return {}
        base, h, verify = _dd_ctx(conn)
        return {p.get("name") or "?": p["id"]
                for p in _dd_all(base, "product_types/", h, verify, cap=500)}
    return _cached(conn, "group_ids", "", refresh, produce)


def findings(conn: dict, refresh: bool = False, limit: int = PAGE_DEFAULT,
             offset: int = 0, sev: str = "", q: str = "", pid=None,
             group: str = "", status: str = "") -> dict:
    """One page of findings, worst severity first.

    Severity and text filters are pushed into the API, not applied to the page
    we happened to fetch. With 5,746 criticals here, a worst-first page is *all*
    criticals — filtering it client-side for "low" would correctly return
    nothing, which looks like a bug. Verified server-side: `severity` is exact
    and `title` is a substring match. `component_name__icontains` and
    `title__icontains` are silently ignored by this API, so they are not used.

    `status` opens the lifecycle beyond the open slice (see STATUSES): "" is
    open — exactly what this always returned — "closed"/"mitigated"/"accepted"/
    "false"/"out" are the inactive worlds, "all" is everything non-duplicate."""
    status = status if status in STATUSES else ""

    def produce():
        if _is_dd(conn):
            scope = dict(STATUSES[status][1])
            if sev:
                scope["severity"] = sev.capitalize()
            if q:
                scope["title"] = q
            if pid is not None:
                scope["test__engagement__product"] = pid
            if group:
                gid = group_ids(conn).get(group)
                if gid is not None:
                    # note the full path: prod_type and …prod_type__id are both
                    # silently ignored by this API and would return everything
                    scope["test__engagement__product__prod_type"] = gid
            return _dd_findings(conn, limit, offset, **scope)
        rows = _full(conn, refresh)["findings"]
        if status and status != "all":
            want = _STATUS_TEXT.get(status, ())
            rows = [r for r in rows if (r.get("status") or "") in want]
        if sev:
            rows = [r for r in rows if r["severity"] == sev]
        if group:
            rows = [r for r in rows if r.get("group") == group]
        if pid is not None:
            rows = [r for r in rows if str(r.get("product_id")) == str(pid)]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in r["title"].lower()
                    or ql in (r.get("component") or "").lower()
                    or ql in (r.get("cve") or "").lower()]
        return {"rows": rows[offset:offset + limit], "total": len(rows),
                "limit": limit, "offset": offset}
    return _cached(conn, "findings",
                   f"{limit}:{offset}:{sev}:{q}:{pid}:{group}:{status}",
                   refresh, produce)


def status_counts(conn: dict, refresh: bool = False, sev: str = "",
                  q: str = "", group: str = "") -> dict:
    """How the findings stand, across the whole lifecycle: one exact count per
    STATUSES key (duplicates excluded throughout). A count that could not be
    asked is None — "0 mitigated" and "we could not ask" mean different things.
    Non-DefectDojo platforms are counted from the rows they report.

    `sev`/`q`/`group` are the SAME scope the findings list applies, because the
    strip's numbers are links into that list — a "Risk accepted 3" whose click
    opens an empty page (the 3 live in another product type) is exactly the bug
    this parameterisation exists to prevent."""
    def produce():
        if not _is_dd(conn):
            rows = _full(conn, refresh)["findings"]
            if sev:
                rows = [r for r in rows if r["severity"] == sev]
            if group:
                rows = [r for r in rows if r.get("group") == group]
            if q:
                ql = q.lower()
                rows = [r for r in rows if ql in r["title"].lower()
                        or ql in (r.get("component") or "").lower()
                        or ql in (r.get("cve") or "").lower()]
            out = {k: sum(1 for r in rows
                          if (r.get("status") or "") in _STATUS_TEXT.get(k, ()))
                   for k in STATUSES if k != "all"}
            out["all"] = len(rows)
            return out
        base, h, verify = _dd_ctx(conn)
        extra = {}
        if sev:
            extra["severity"] = sev.capitalize()
        if q:
            extra["title"] = q
        if group:
            gid = group_ids(conn).get(group)
            if gid is not None:
                extra["test__engagement__product__prod_type"] = gid

        def one(key):
            for attempt in (1, 2):
                try:
                    return key, _dd_count(base, h, verify,
                                          **{**STATUSES[key][1], **extra})
                except SecError:
                    if attempt == 2:
                        return key, None
                    time.sleep(0.4)
            return key, None
        with ThreadPoolExecutor(max_workers=4) as pool:
            return dict(pool.map(one, list(STATUSES)))
    return _cached(conn, "statuses", f"{sev}:{q}:{group}", refresh, produce)


def finding(conn: dict, fid, refresh: bool = False) -> dict | None:
    """One finding in full — description, mitigation, impact, references,
    CVSS, every CVE/GHSA/CWE id, flags and notes — so the detail is readable
    in the portal rather than in the platform's own UI.

    DefectDojo only: the other platforms' list rows already carry everything
    their APIs offer, so they return None and the page keeps linking out."""
    if not _is_dd(conn):
        return None

    def produce():
        return _dd_finding(conn, int(fid))
    return _cached(conn, "finding", str(fid), refresh, produce)


def scans(conn: dict, refresh: bool = False) -> list:
    def produce():
        return (_dd_scans(conn) if _is_dd(conn)
                else _full(conn, refresh)["scans"])
    return _cached(conn, "scans", "", refresh, produce)


def product(conn: dict, pid, refresh: bool = False) -> dict:
    """One product in full detail, with an exact severity split."""
    def produce():
        if _is_dd(conn):
            return _dd_product(conn, pid)
        got = _full(conn, refresh)
        row = next((p for p in got["products"] if str(p["id"]) == str(pid)), None)
        mine = [f for f in got["findings"] if str(f.get("product_id")) == str(pid)]
        sev = (row or {}).get("sev") or _blank()
        return {"product": row, "sev": sev, "total": sum(sev.values()),
                "findings": mine, "findings_total": len(mine)}
    return _cached(conn, "product", str(pid), refresh, produce)


def groups(conn: dict, refresh: bool = False) -> list:
    """Tab strip values, straight from the platform's own grouping."""
    return sorted({p["group"] for p in products(conn, refresh) if p.get("group")})


def page_size(conn: dict) -> int:
    try:
        n = int(conn.get("max_findings") or PAGE_DEFAULT)
    except (TypeError, ValueError):
        return PAGE_DEFAULT
    return max(25, min(n, 1000))


def test(conn: dict) -> tuple[bool, str]:
    """Validate a connection with the cheap part only — never the whole pull."""
    try:
        got = overview(conn, refresh=True)
    except SecError as e:
        return False, str(e)
    except Exception as e:                          # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    t, n = got["totals"], got["products"]
    if not n and not got["open"]:
        return True, "connected — nothing visible to this key yet"
    return True, (f"connected — {n} product(s), {got['open']} open finding(s)"
                  + (f", {t['critical']} critical" if t["critical"] else ""))


def merge_totals(parts: list[dict]) -> dict:
    out = _blank()
    for p in parts:
        for s in SEVERITIES:
            out[s] += (p.get("totals") or {}).get(s, 0)
    return out


def risk_grade(sev: dict) -> tuple[str, str]:
    if sev["critical"]:
        return "critical", f"{sev['critical']} critical open"
    if sev["high"]:
        return "high", f"{sev['high']} high open"
    if sev["medium"]:
        return "medium", f"{sev['medium']} medium open"
    if sev["low"] or sev["info"]:
        return "low", "low severity only"
    return "clean", "no open findings"
