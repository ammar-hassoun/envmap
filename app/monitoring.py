"""Monitoring platforms — Prometheus-compatible, Alertmanager, Grafana, Zabbix.

Same contract as ci.py, security.py and logstore.py: every platform is reduced to
one shape so the UI never learns which one answered, and adding another means one
registry entry plus one fetch function.

Read-only. Alerts are read, never acknowledged or silenced; dashboards are listed,
never modified. Silencing an alert belongs in Alertmanager, where the audit trail
and the expiry handling already exist.

WHY ALERTS RATHER THAN EMBEDDED DASHBOARDS
    A monitoring stack is usually deployed per cluster, so a fleet of ten clusters
    means ten Grafanas holding near-identical dashboards. Embedding panels from
    each would multiply maintenance and fight Grafana's own auth (its session
    cookie is SameSite=Lax, so a cross-origin iframe shows a login screen unless
    anonymous access is enabled — a security downgrade). What no single Grafana
    can answer is "what is firing right now, everywhere". That is what this
    module collects; Grafana stays the place to explore, reached by a deep link
    that already knows the cluster, namespace and time range.

Normalised alert:
    {name, severity, state, summary, since, source, labels, url}
severity is one of SEVERITIES.
"""
import base64
import json
import ssl
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

TIMEOUT = 20
CACHE_TTL = 45           # alerts are the point of this page; keep them fresh
SEVERITIES = ("critical", "warning", "info")

PROVIDERS = {
    "prometheus": {
        "label": "Prometheus",
        "icon": "🔥",
        "url_hint": "https://prometheus.example.com:9090",
        "needs": ["base_url"],
        "note": "Also works with Thanos, Mimir, Cortex and VictoriaMetrics — "
                "anything serving the Prometheus HTTP API. Reads firing alerts "
                "and scrape-target health. Add a token or basic auth only if it "
                "sits behind one.",
        "reads": "firing alerts, target health",
    },
    "alertmanager": {
        "label": "Alertmanager",
        "icon": "🔔",
        "url_hint": "https://alertmanager.example.com:9093",
        "needs": ["base_url"],
        "note": "The clearest source of what is firing right now, already "
                "deduplicated and grouped. Existing silences are honoured — a "
                "silenced alert is not reported as firing.",
        "reads": "active alerts, silences",
    },
    "grafana": {
        "label": "Grafana",
        "icon": "📈",
        "url_hint": "https://grafana.example.com",
        "needs": ["base_url"],
        "note": "A service-account token with the Viewer role. Lists dashboards "
                "so the portal can deep-link into the right one; it does not "
                "embed panels — see this module's header for why.",
        "reads": "dashboard inventory, unified-alerting alerts",
    },
    "zabbix": {
        "label": "Zabbix",
        "icon": "🟥",
        "url_hint": "https://zabbix.example.com/api_jsonrpc.php",
        "needs": ["base_url", "token"],
        "note": "An API token from Users → API tokens (Zabbix 5.4+). Reads "
                "current problems. Point the URL at api_jsonrpc.php.",
        "reads": "current problems",
    },
}


class MonError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _req(url: str, headers: dict, verify: bool = True, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Accept": "application/json", **headers}
    if data:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT,
                                    context=None if verify else _INSECURE) as r:
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:180]
        except Exception:
            pass
        if e.code in (401, 403):
            raise MonError(f"authentication rejected ({e.code}) — check the token "
                           "and its permissions") from e
        if e.code == 404:
            raise MonError("not found (404) — check the base URL. Prometheus and "
                           "Alertmanager want the API root, Zabbix wants "
                           "api_jsonrpc.php") from e
        raise MonError(f"HTTP {e.code} {detail}".strip()) from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason or "SSLCertVerification" in reason:
            raise MonError(
                f"TLS certificate rejected: {reason}. If this is an internal "
                "server with a self-signed certificate, tick 'skip TLS "
                "verification' on the connection.") from e
        raise MonError(f"cannot reach the server: {reason}") from e
    except json.JSONDecodeError:
        raise MonError("the server did not return JSON — is the base URL the API "
                       "endpoint rather than a browser page?")
    except Exception as e:                                    # noqa: BLE001
        raise MonError(f"{type(e).__name__}: {e}".strip()[:200]
                       or "unexpected transport error") from e


def _auth(c: dict) -> dict:
    """Bearer when only a token is given, basic when a username is too."""
    user, token = (c.get("username") or "").strip(), c.get("token") or ""
    if user:
        enc = base64.b64encode(f"{user}:{token}".encode()).decode()
        return {"Authorization": f"Basic {enc}"}
    return {"Authorization": f"Bearer {token}"} if token else {}


def _norm_sev(raw) -> str:
    v = str(raw or "").strip().lower()
    if v in ("critical", "crit", "fatal", "disaster", "emergency", "page", "p1"):
        return "critical"
    if v in ("warning", "warn", "high", "average", "major", "p2"):
        return "warning"
    if v in ("info", "information", "informational", "none", "low", "minor", "p3"):
        return "info"
    return "warning" if v else "info"     # an unlabelled alert is still worth seeing


def _ago(iso) -> str:
    if not iso:
        return ""
    try:
        s = str(iso).replace("Z", "+00:00")
        s = s[:26] + "+00:00" if len(s) > 32 and "+" not in s[19:] else s
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        d = datetime.now(timezone.utc) - dt
        if d.total_seconds() < 0:
            return "just now"
        if d.days > 1:
            return f"{d.days}d"
        h, m = (d.days * 24) + d.seconds // 3600, (d.seconds % 3600) // 60
        return f"{h}h {m}m" if h else f"{m}m"
    except Exception:
        return ""


def _blank() -> dict:
    return {s: 0 for s in SEVERITIES}


# ── cache ──────────────────────────────────────────────────────
_CACHE: dict[str, tuple[float, object]] = {}


def invalidate() -> None:
    _CACHE.clear()


def _cached(conn: dict, part: str, refresh: bool, produce):
    key = f"{conn.get('id') or conn.get('base_url','')}::{part}"
    hit = _CACHE.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    got = produce()
    _CACHE[key] = (time.time(), got)
    return got


# ── Prometheus (and anything serving its API) ──────────────────
def _prom_alerts(c: dict) -> list:
    base = c["base_url"].rstrip("/")
    got = _req(f"{base}/api/v1/alerts", _auth(c), not c.get("skip_tls"))
    out = []
    for a in ((got.get("data") or {}).get("alerts") or []):
        # "pending" means the condition is true but has not yet held for the
        # rule's `for:` duration. It is not firing, so it belongs in neither the
        # count nor the list — showing it in one but not the other made the
        # tiles disagree with the table.
        if a.get("state") == "pending":
            continue
        lbl = a.get("labels") or {}
        ann = a.get("annotations") or {}
        out.append({
            "name": lbl.get("alertname", "?"),
            "severity": _norm_sev(lbl.get("severity")),
            "state": a.get("state", "firing"),
            "summary": ann.get("summary") or ann.get("description") or "",
            "since": _ago(a.get("activeAt")), "at": a.get("activeAt", ""),
            "source": lbl.get("namespace") or lbl.get("job") or lbl.get("instance") or "",
            "labels": lbl,
            "url": f"{base}/alerts",
        })
    return out


def _prom_overview(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    verify, h = not c.get("skip_tls"), _auth(c)
    alerts = _prom_alerts(c)
    counts = _blank()
    for a in alerts:
        counts[a["severity"]] += 1
    up = down = 0
    try:
        t = _req(f"{base}/api/v1/targets?state=any", h, verify)
        for tg in ((t.get("data") or {}).get("activeTargets") or []):
            if tg.get("health") == "up":
                up += 1
            else:
                down += 1
    except MonError:
        pass
    note = f"{down} scrape target(s) down" if down else ""
    return {"counts": counts, "alerts": alerts, "item_count": up + down,
            "unit": "scrape target", "healthy": up, "unhealthy": down,
            "note": note, "dashboards": []}


# ── Alertmanager ───────────────────────────────────────────────
def _am_alerts(c: dict) -> list:
    base = c["base_url"].rstrip("/")
    # silenced and inhibited alerts are deliberately excluded: someone already
    # decided they are not actionable, and repeating them here undoes that
    got = _req(f"{base}/api/v2/alerts?active=true&silenced=false&inhibited=false",
               _auth(c), not c.get("skip_tls"))
    out = []
    for a in (got if isinstance(got, list) else []):
        lbl = a.get("labels") or {}
        ann = a.get("annotations") or {}
        out.append({
            "name": lbl.get("alertname", "?"),
            "severity": _norm_sev(lbl.get("severity")),
            "state": ((a.get("status") or {}).get("state") or "active"),
            "summary": ann.get("summary") or ann.get("description") or "",
            "since": _ago(a.get("startsAt")), "at": a.get("startsAt", ""),
            "source": lbl.get("namespace") or lbl.get("job") or lbl.get("instance") or "",
            "labels": lbl,
            "url": a.get("generatorURL") or f"{base}/#/alerts",
        })
    return out


def _am_overview(c: dict) -> dict:
    alerts = _am_alerts(c)
    counts = _blank()
    for a in alerts:
        counts[a["severity"]] += 1
    silenced = 0
    try:
        base = c["base_url"].rstrip("/")
        sil = _req(f"{base}/api/v2/silences", _auth(c), not c.get("skip_tls"))
        silenced = sum(1 for s in (sil if isinstance(sil, list) else [])
                       if ((s.get("status") or {}).get("state") == "active"))
    except MonError:
        pass
    return {"counts": counts, "alerts": alerts, "item_count": silenced,
            "unit": "active silence", "healthy": 0, "unhealthy": 0,
            "note": f"{silenced} active silence(s) — those alerts are hidden here"
                    if silenced else "", "dashboards": []}


# ── Grafana ────────────────────────────────────────────────────
def _grafana_dashboards(c: dict) -> list:
    base = c["base_url"].rstrip("/")
    got = _req(f"{base}/api/search?type=dash-db&limit=500", _auth(c),
               not c.get("skip_tls"))
    out = []
    for d in (got if isinstance(got, list) else []):
        out.append({"title": d.get("title", "?"),
                    "folder": d.get("folderTitle") or "General",
                    "tags": d.get("tags") or [],
                    # the uid is how the dashboard is opened IN the portal; the
                    # search result carried it all along and it was dropped, so
                    # every dashboard could only ever be a link back to Grafana
                    "uid": d.get("uid") or "",
                    "url": base + (d.get("url") or "")})
    return sorted(out, key=lambda x: (x["folder"].lower(), x["title"].lower()))


def _grafana_overview(c: dict) -> dict:
    dash = _grafana_dashboards(c)
    alerts, counts = [], _blank()
    # Grafana 8+ unified alerting exposes an Alertmanager-compatible endpoint;
    # absent on older versions, which is not an error worth surfacing
    try:
        base = c["base_url"].rstrip("/")
        got = _req(f"{base}/api/alertmanager/grafana/api/v2/alerts",
                   _auth(c), not c.get("skip_tls"))
        for a in (got if isinstance(got, list) else []):
            lbl = a.get("labels") or {}
            ann = a.get("annotations") or {}
            sev = _norm_sev(lbl.get("severity"))
            counts[sev] += 1
            alerts.append({"name": lbl.get("alertname", "?"), "severity": sev,
                           "state": ((a.get("status") or {}).get("state") or "active"),
                           "summary": ann.get("summary") or "",
                           "since": _ago(a.get("startsAt")), "at": a.get("startsAt", ""),
                           "source": lbl.get("grafana_folder") or "", "labels": lbl,
                           "url": a.get("generatorURL") or f"{base}/alerting/list"})
    except MonError:
        pass
    folders = len({d["folder"] for d in dash})
    return {"counts": counts, "alerts": alerts, "item_count": len(dash),
            "unit": "dashboard", "healthy": 0, "unhealthy": 0,
            "note": f"{folders} folder(s)" if dash else "", "dashboards": dash}


# ── Zabbix (JSON-RPC) ──────────────────────────────────────────
_ZBX_SEV = {"5": "critical", "4": "critical", "3": "warning",
            "2": "warning", "1": "info", "0": "info"}


def _zbx_call(c: dict, method: str, params: dict) -> list:
    url = c["base_url"].rstrip("/")
    if not url.endswith(".php"):
        url += "/api_jsonrpc.php"
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    got = _req(url, {"Authorization": f"Bearer {c.get('token') or ''}"},
               not c.get("skip_tls"), body)
    if isinstance(got, dict) and got.get("error"):
        err = got["error"]
        raise MonError(f"{err.get('message','error')}: {err.get('data','')}"[:180])
    return (got or {}).get("result") or []


def _zbx_overview(c: dict) -> dict:
    problems = _zbx_call(c, "problem.get", {
        "output": "extend", "recent": False, "sortfield": ["eventid"],
        "sortorder": "DESC", "limit": 300})
    hosts = {}
    try:
        for h in _zbx_call(c, "host.get", {"output": ["hostid", "name"]}):
            hosts[h["hostid"]] = h.get("name", "")
    except MonError:
        pass
    # problem.get returns the trigger's objectid, not the host, so map through
    # the event when the API gives it
    counts, alerts = _blank(), []
    for p in problems:
        sev = _ZBX_SEV.get(str(p.get("severity", "0")), "info")
        counts[sev] += 1
        ts = p.get("clock")
        at = (datetime.fromtimestamp(int(ts), timezone.utc).isoformat()
              if str(ts).isdigit() else "")
        alerts.append({
            "name": p.get("name", "?"), "severity": sev,
            "state": "acknowledged" if str(p.get("acknowledged")) == "1" else "active",
            "summary": p.get("opdata") or "", "since": _ago(at), "at": at,
            "source": hosts.get(p.get("hostid"), ""), "labels": {},
            "url": c["base_url"].rstrip("/").replace("/api_jsonrpc.php", "")
                   + "/zabbix.php?action=problem.view"})
    return {"counts": counts, "alerts": alerts, "item_count": len(hosts),
            "unit": "host", "healthy": 0, "unhealthy": 0,
            "note": "", "dashboards": []}


# ── public API ─────────────────────────────────────────────────
_OVERVIEW = {"prometheus": _prom_overview, "alertmanager": _am_overview,
             "grafana": _grafana_overview, "zabbix": _zbx_overview}


def overview(conn: dict, refresh: bool = False) -> dict:
    fn = _OVERVIEW.get(conn.get("type"))
    if not fn:
        raise MonError(f"unknown monitoring platform '{conn.get('type')}'")
    return _cached(conn, "overview", refresh, lambda: fn(conn))


def alerts(conn: dict, refresh: bool = False) -> list:
    return overview(conn, refresh)["alerts"]


def dashboards(conn: dict, refresh: bool = False) -> list:
    return overview(conn, refresh)["dashboards"]


def test(conn: dict) -> tuple[bool, str]:
    try:
        o = overview(conn, refresh=True)
    except MonError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    total = sum(o["counts"].values())
    bits = [f"connected — {total} alert(s) firing" if total
            else "connected — nothing firing"]
    if o["item_count"]:
        n = o["item_count"]
        bits.append(f"{n} {o['unit']}{'s' if n != 1 else ''}")
    if o.get("note"):
        bits.append(o["note"])
    return True, ", ".join(bits)


def merge_counts(parts: list[dict]) -> dict:
    out = _blank()
    for p in parts:
        for s in SEVERITIES:
            out[s] += (p.get("counts") or {}).get(s, 0)
    return out


def deep_link(conn: dict, namespace: str = "", cluster: str = "",
              minutes: int = 60) -> str:
    """A Grafana URL with the context the portal already knows filled in.

    This is the alternative to embedding: the operator lands in Grafana already
    scoped to the right namespace and time range instead of setting it by hand
    across a fleet of per-cluster Grafanas.
    """
    if conn.get("type") != "grafana":
        return conn.get("base_url", "")
    base = conn["base_url"].rstrip("/")
    q = {"from": f"now-{max(5, minutes)}m", "to": "now"}
    if namespace:
        q["var-namespace"] = namespace
    if cluster:
        q["var-cluster"] = cluster
    return f"{base}/dashboards?{urllib.parse.urlencode(q)}"
