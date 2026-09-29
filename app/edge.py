"""Edge and DNS: Cloudflare, and the others that sit in front of everything.

WHY THIS DESERVES ITS OWN PAGE
    Every request to every service in this portal arrives through something the
    portal could not see. A domain resolves somewhere, terminates TLS somewhere,
    is cached somewhere, and is filtered somewhere — and when a deploy is fine but
    the site is not, that layer is usually the answer. "Is the record proxied?",
    "is development mode still on?", "which certificate is serving this?" and
    "what did the cache do" are the questions, and they were all a browser tab
    away in somebody else's console.

WHAT IT READS
    Zones with their plan and status, every DNS record with whether it is proxied,
    the TLS position (mode, minimum version, always-use-HTTPS, HSTS), certificate
    packs with their expiry, cache posture including whether development mode is
    on, Zero Trust tunnels, Workers and R2 buckets. Anything a provider does not
    have is simply absent rather than faked.

WHAT IT WILL CHANGE, AND WHAT IT WILL NOT
    Purging a cache, toggling development mode, adding or removing a DNS record
    and blocking an address are all things done at three in the morning under
    pressure, so they are here, each behind a typed confirmation and recorded
    before it runs. Changing a plan, moving a domain between accounts and deleting
    a zone are not: they are rare, expensive and irreversible, and the console can
    keep them.

FOUR PROVIDERS, ONE SHAPE
    Cloudflare is the deep one. Fastly, Bunny and NS1 each cover part of the same
    ground with a different API, and are read for what they do have — a service
    list, a pull zone, a DNS zone — rather than being pushed into Cloudflare's
    shape.
"""
from __future__ import annotations

import json
import ssl
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
CACHE_TTL = 60

PROVIDERS = {
    "cloudflare": {
        "label": "Cloudflare",
        "icon": "🟠",
        "url_hint": "(none — the API is api.cloudflare.com)",
        "needs": ["token"],
        "auth": "an API token, which is what Cloudflare recommends over the "
                "global key: My Profile → API Tokens → Create Token",
        "note": "Reads zones, DNS records, TLS position, certificates, cache "
                "state, tunnels, Workers and R2. A token with Zone.Zone:Read and "
                "Zone.DNS:Read is enough to look; purging a cache needs "
                "Zone.Cache Purge, and editing records needs Zone.DNS:Edit. Add "
                "Account.Cloudflare Tunnel:Read and Account.Workers R2 "
                "Storage:Read if you want those listed too.",
        "fields": {"token": "API token",
                   "username": "Account id (optional — for tunnels, Workers, R2)"},
    },
    "fastly": {
        "label": "Fastly",
        "icon": "🔺",
        "url_hint": "(none — the API is api.fastly.com)",
        "needs": ["token"],
        "auth": "an API token with global:read",
        "note": "Reads services, their active version and the domains and "
                "backends on it. Purging is per service and per surrogate key, "
                "which is a decision the portal does not make for you.",
        "fields": {"token": "API token"},
    },
    "bunny": {
        "label": "Bunny.net",
        "icon": "🐰",
        "url_hint": "(none — the API is api.bunny.net)",
        "needs": ["token"],
        "auth": "the account API key, from Account → API",
        "note": "Reads pull zones with their origin and hostnames, and storage "
                "zones. Purging a pull zone is offered.",
        "fields": {"token": "API key"},
    },
    "ns1": {
        "label": "NS1",
        "icon": "1️⃣",
        "url_hint": "(none — the API is api.nsone.net)",
        "needs": ["token"],
        "auth": "an API key with data:view",
        "note": "Reads zones and their records. NS1 is DNS only — there is no "
                "cache or TLS layer to report.",
        "fields": {"token": "API key"},
    },
    "other": {
        "label": "Something else",
        "icon": "🌐",
        "url_hint": "https://api.example.com/health",
        "needs": ["base_url"],
        "auth": "a bearer token, if the endpoint wants one",
        "note": "Registers an endpoint and reports whether it answers. The portal "
                "has no schema for it, so it reports reachability and nothing "
                "more — which is honest rather than a page of empty tables.",
        "fields": {"base_url": "Endpoint", "token": "Bearer token (optional)"},
    },
}


class EdgeError(Exception):
    pass


def _ctx(skip_tls: bool):
    if not skip_tls:
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _call(url: str, headers: dict, skip_tls: bool = False, method: str = "GET",
          body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    head = {"Accept": "application/json", **headers}
    if data:
        head["Content-Type"] = "application/json"
    req = urllib.request.Request(
        urlguard.check(url), data=data, headers=head, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT,
                                    context=_ctx(skip_tls)) as r:
            raw = r.read().decode(errors="replace")
            code = r.getcode()
    except urllib.error.HTTPError as e:
        raw, code = e.read().decode(errors="replace"), e.code
    except Exception as e:                                    # noqa: BLE001
        raise EdgeError(str(e)) from e
    try:
        return code, json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return code, {"_raw": raw[:400]}


def _cf(c: dict, path: str, method: str = "GET",
        body: dict | None = None) -> tuple[int, dict]:
    return _call(f"https://api.cloudflare.com/client/v4{path}",
                 {"Authorization": f"Bearer {c['token']}"},
                 bool(c.get("skip_tls")), method, body)


def _cf_why(doc: dict, code: int) -> str:
    """Cloudflare's own message, plus the permission it is really about.

    Its errors are a list of objects, and a token missing one permission answers
    the same 403 as a token that is wrong — so the message says which.
    """
    errors = doc.get("errors") or []
    why = "; ".join(str(e.get("message", "")) for e in errors if e.get("message"))
    why = why or f"HTTP {code}"
    low = why.lower()
    if code == 403 or "authentication" in low or "permission" in low:
        why += (" — the token is missing a permission for that call, or is scoped "
                "to different zones")
    elif code == 429:
        why += " — Cloudflare is rate limiting; it clears on its own"
    return why


# ── verifying a connection ────────────────────────────────────────────────
def test(c: dict) -> tuple[bool, str]:
    kind = c.get("type")
    try:
        if kind == "cloudflare":
            code, doc = _cf(c, "/user/tokens/verify")
            if code == 200 and (doc.get("result") or {}).get("status") == "active":
                zc, zdoc = _cf(c, "/zones?per_page=1")
                zones = (zdoc.get("result_info") or {}).get("total_count", "?")
                return True, f"token active · {zones} zone(s) visible"
            return False, _cf_why(doc, code)
        if kind == "fastly":
            code, doc = _call("https://api.fastly.com/current_user",
                              {"Fastly-Key": c["token"]}, bool(c.get("skip_tls")))
            if code == 200:
                return True, f"signed in as {doc.get('login', 'this token')}"
            return False, f"HTTP {code} {str(doc)[:120]}"
        if kind == "bunny":
            code, doc = _call("https://api.bunny.net/pullzone?page=1&perPage=1",
                              {"AccessKey": c["token"]}, bool(c.get("skip_tls")))
            if code == 200:
                return True, "API key accepted"
            return False, f"HTTP {code} {str(doc)[:120]}"
        if kind == "ns1":
            code, doc = _call("https://api.nsone.net/v1/zones",
                              {"X-NSONE-Key": c["token"]}, bool(c.get("skip_tls")))
            if code == 200:
                n = len(doc) if isinstance(doc, list) else "?"
                return True, f"{n} zone(s) visible"
            return False, f"HTTP {code} {str(doc)[:120]}"
        base = (c.get("base_url") or "").rstrip("/")
        if not base:
            return False, "an endpoint is required"
        head = {"Authorization": f"Bearer {c['token']}"} if c.get("token") else {}
        code, _doc = _call(base, head, bool(c.get("skip_tls")))
        return (200 <= code < 400), f"HTTP {code}"
    except EdgeError as e:
        return False, str(e)


# ── what is out there ─────────────────────────────────────────────────────
_cache: dict = {}


def invalidate() -> None:
    _cache.clear()


def inventory(c: dict, refresh: bool = False) -> dict:
    """{groups, notes, zones, error} for one connection, briefly cached."""
    key = c.get("id") or c.get("name", "")
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    fn = {"cloudflare": _cf_inventory, "fastly": _fastly_inventory,
          "bunny": _bunny_inventory, "ns1": _ns1_inventory}.get(c.get("type"))
    if not fn:
        got = {"groups": [], "zones": [], "error": "",
               "notes": ["registered, but the portal has no schema for this "
                         "provider — it reports reachability only"]}
    else:
        try:
            got = {**fn(c), "error": ""}
        except EdgeError as e:
            got = {"groups": [], "zones": [], "notes": [], "error": str(e)}
        except Exception as e:                                # noqa: BLE001
            got = {"groups": [], "zones": [], "notes": [],
                   "error": f"{type(e).__name__}: {e}"}
    got["total"] = sum(len(g["rows"]) for g in got.get("groups") or [])
    _cache[key] = (time.time(), got)
    return got


def _cf_inventory(c: dict) -> dict:
    from .fleet import _pmap
    notes, groups = [], []
    code, doc = _cf(c, "/zones?per_page=50")
    if code != 200:
        raise EdgeError(_cf_why(doc, code))
    zones = []
    for z in doc.get("result") or []:
        zones.append({
            "id": z.get("id", ""), "name": z.get("name", ""),
            "status": z.get("status", ""),
            "plan": ((z.get("plan") or {}).get("name", "")),
            "paused": bool(z.get("paused")),
            "type": z.get("type", ""),
            "nameservers": ", ".join(z.get("name_servers") or []),
            "modified": (z.get("modified_on") or "")[:10]})
    groups.append({"key": "zones", "label": "Zones", "icon": "🌍",
                   "rows": [{"name": z["name"], "id": z["id"],
                             "kind": f"{z['plan']} · {z['type']}",
                             "state": "paused" if z["paused"] else z["status"],
                             "extra": z["nameservers"][:60],
                             "zone": z["modified"]} for z in zones],
                   "columns": ["domain", "plan", "status", "name servers",
                               "changed"]})

    # DNS records, TLS position and cache state, per zone and in parallel
    def per_zone(z):
        out = {"records": [], "tls": None, "certs": [], "note": ""}
        rc, rdoc = _cf(c, f"/zones/{z['id']}/dns_records?per_page=200")
        if rc != 200:
            out["note"] = f"{z['name']}: records — {_cf_why(rdoc, rc)}"
            return (z, out)
        for r in rdoc.get("result") or []:
            # the generic six fields for the table and the CSV, plus everything an
            # edit form needs — otherwise every change means going and finding the
            # zone id and the record id by hand, which is what made this
            # unusable at fifty-seven records
            out["records"].append({
                "name": r.get("name", ""), "id": r.get("id", ""),
                "kind": r.get("type", ""),
                "state": "proxied" if r.get("proxied") else "dns only",
                "extra": str(r.get("content", ""))[:70],
                "zone": z["name"],
                "zone_id": z["id"], "type": r.get("type", ""),
                "content": r.get("content", ""),
                "ttl": r.get("ttl", 1), "proxied": bool(r.get("proxied")),
                "proxiable": bool(r.get("proxiable")),
                "comment": r.get("comment") or "",
                "short": (r.get("name", "").removesuffix("." + z["name"])
                          if r.get("name", "") != z["name"] else "@")})
        sc, sdoc = _cf(c, f"/zones/{z['id']}/settings")
        if sc == 200:
            got = {s.get("id"): s.get("value")
                   for s in sdoc.get("result") or []}
            out["tls"] = {
                "zone": z["name"], "ssl": got.get("ssl", ""),
                "min_tls": got.get("min_tls_version", ""),
                "https": got.get("always_use_https", ""),
                "hsts": ((got.get("security_header") or {})
                         .get("strict_transport_security", {}) or {}).get("enabled"),
                "cache": got.get("cache_level", ""),
                "dev_mode": got.get("development_mode", ""),
                "under_attack": got.get("security_level", "")}
        cc, cdoc = _cf(c, f"/zones/{z['id']}/ssl/certificate_packs?status=all")
        if cc == 200:
            for p in cdoc.get("result") or []:
                for cert in p.get("certificates") or [{}]:
                    out["certs"].append({
                        "name": ", ".join(p.get("hosts") or [])[:50] or z["name"],
                        "id": p.get("id", ""),
                        "kind": f"{p.get('type', '')} · {p.get('certificate_authority', '')}",
                        "state": p.get("status", ""),
                        "extra": (cert.get("expires_on") or "")[:10],
                        "zone": z["name"]})
        return (z, out)

    records, tls, certs = [], [], []
    for got in _pmap(per_zone, zones, workers=min(6, max(1, len(zones)))) or []:
        if not got:
            continue
        _z, part = got
        records += part["records"]
        certs += part["certs"]
        if part["tls"]:
            tls.append(part["tls"])
        if part["note"]:
            notes.append(part["note"])

    groups.append({"key": "dns", "label": "DNS records", "icon": "🧭",
                   "rows": records,
                   "columns": ["record", "type", "proxy", "value", "zone"]})
    if certs:
        groups.append({"key": "certs", "label": "Certificates", "icon": "🔐",
                       "rows": certs,
                       "columns": ["hosts", "type", "status", "expires", "zone"]})

    # account-wide things, when an account id was given
    account = (c.get("username") or "").strip()
    if account:
        for key, label, icon, path, reader in (
                ("tunnels", "Zero Trust tunnels", "🚇",
                 f"/accounts/{account}/cfd_tunnel?is_deleted=false",
                 lambda r: {"name": r.get("name", ""), "id": r.get("id", ""),
                            "kind": "tunnel", "state": r.get("status", ""),
                            "extra": ", ".join(
                                cx.get("origin_ip", "")
                                for cx in (r.get("connections") or [])[:2]),
                            "zone": (r.get("created_at") or "")[:10]}),
                ("workers", "Workers", "⚙", f"/accounts/{account}/workers/scripts",
                 lambda r: {"name": r.get("id", ""), "id": r.get("id", ""),
                            "kind": "worker", "state": "",
                            "extra": ", ".join(
                                str(x.get("name", "")) for x in
                                (r.get("routes") or [])[:2]),
                            "zone": (r.get("modified_on") or "")[:10]}),
                ("r2", "R2 buckets", "🪣", f"/accounts/{account}/r2/buckets",
                 lambda r: {"name": r.get("name", ""), "id": r.get("name", ""),
                            "kind": r.get("location", "") or "bucket",
                            "state": "", "extra": r.get("storage_class", ""),
                            "zone": (r.get("creation_date") or "")[:10]})):
            ac, adoc = _cf(c, path)
            if ac != 200:
                notes.append(f"{label}: {_cf_why(adoc, ac)}")
                continue
            result = adoc.get("result")
            rows = result.get("buckets") if isinstance(result, dict) else result
            groups.append({"key": key, "label": label, "icon": icon,
                           "rows": [reader(r) for r in (rows or [])]})
    else:
        notes.append("tunnels, Workers and R2 are account-wide rather than "
                     "per zone — add the account id to the connection to see them")
    return {"groups": groups, "zones": zones, "tls": tls, "notes": notes}


def _fastly_inventory(c: dict) -> dict:
    code, doc = _call("https://api.fastly.com/service?per_page=100",
                      {"Fastly-Key": c["token"]}, bool(c.get("skip_tls")))
    if code != 200:
        raise EdgeError(f"HTTP {code} {str(doc)[:160]}")
    rows = []
    for s in (doc if isinstance(doc, list) else []):
        rows.append({"name": s.get("name", ""), "id": s.get("id", ""),
                     "kind": s.get("type", "vcl"),
                     "state": f"v{s.get('version', '?')}",
                     "extra": ", ".join(
                         str(v.get("number")) for v in (s.get("versions") or [])[-1:]),
                     "zone": (s.get("updated_at") or "")[:10]})
    return {"groups": [{"key": "services", "label": "Services", "icon": "🔺",
                        "rows": rows}], "zones": [], "tls": [], "notes": []}


def _bunny_inventory(c: dict) -> dict:
    code, doc = _call("https://api.bunny.net/pullzone?page=1&perPage=100",
                      {"AccessKey": c["token"]}, bool(c.get("skip_tls")))
    if code != 200:
        raise EdgeError(f"HTTP {code} {str(doc)[:160]}")
    items = doc.get("Items") if isinstance(doc, dict) else doc
    rows = []
    for z in items or []:
        rows.append({"name": z.get("Name", ""), "id": str(z.get("Id", "")),
                     "kind": "pull zone",
                     "state": "enabled" if z.get("Enabled") else "disabled",
                     "extra": z.get("OriginUrl", ""),
                     "zone": ", ".join(h.get("Value", "")
                                       for h in (z.get("Hostnames") or [])[:2])})
    return {"groups": [{"key": "pullzones", "label": "Pull zones", "icon": "🐰",
                        "rows": rows}], "zones": [], "tls": [], "notes": []}


def _ns1_inventory(c: dict) -> dict:
    code, doc = _call("https://api.nsone.net/v1/zones",
                      {"X-NSONE-Key": c["token"]}, bool(c.get("skip_tls")))
    if code != 200:
        raise EdgeError(f"HTTP {code} {str(doc)[:160]}")
    rows = [{"name": z.get("zone", ""), "id": z.get("zone", ""), "kind": "zone",
             "state": "", "extra": f"{z.get('records', '?')} records",
             "zone": z.get("ttl", "")}
            for z in (doc if isinstance(doc, list) else [])]
    return {"groups": [{"key": "zones", "label": "Zones", "icon": "🌍",
                        "rows": rows}], "zones": [], "tls": [], "notes": []}


# ── the things worth doing from here ──────────────────────────────────────
# Each one is a call, the parameters it needs, and how badly it goes if it is
# wrong — the same declaration the cloud actions use, so the form, the
# confirmation and the audit entry all read from one place.
def _p(name, label, required=True, hint="", kind="text", options=None):
    return {"name": name, "label": label, "required": required, "hint": hint,
            "kind": kind, "options": options or []}


ACTIONS = {
    "cf.purge_all": {
        "label": "Purge everything", "group": "zones", "icon": "🧹",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id")],
        "note": "Empties the whole cache for the zone. Every next request goes to "
                "the origin, so on a busy site expect a spike there.",
    },
    "cf.purge_urls": {
        "label": "Purge specific URLs", "group": "zones", "icon": "🧽",
        "danger": "safe", "provider": "cloudflare",
        "params": [_p("zone", "zone id"),
                   _p("files", "URLs", True,
                      "full URLs, comma separated: https://x/a.js, https://x/b.css")],
        "note": "Almost always the right purge: the origin only sees traffic for "
                "what actually changed.",
    },
    "cf.dev_mode": {
        "label": "Development mode", "group": "zones", "icon": "🚧",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id"),
                   _p("value", "state", True, "", "select", ["on", "off"])],
        "note": "Bypasses the cache entirely for three hours, then turns itself "
                "off. Useful while debugging and expensive to leave on.",
    },
    "cf.ssl_mode": {
        "label": "Set the TLS mode", "group": "zones", "icon": "🔒",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id"),
                   _p("value", "mode", True,
                      "full_strict is the only one that verifies the origin "
                      "certificate", "select",
                      ["full_strict", "full", "flexible", "off"])],
        "note": "flexible leaves the connection to your origin unencrypted, and "
                "off disables TLS. Moving down from full_strict is worth a "
                "second thought.",
    },
    "cf.record_create": {
        "label": "Add a DNS record", "group": "dns", "icon": "＋",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id"),
                   _p("type", "type", True, "", "select",
                      ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"]),
                   _p("name", "name", True, "the host, or @ for the domain itself"),
                   _p("content", "value", True, "an address, a hostname, or text"),
                   _p("ttl", "TTL", False, "1 means automatic"),
                   _p("proxied", "through Cloudflare", False, "", "select",
                      ["true", "false"]),
                   _p("comment", "why", False,
                      "the next person will want to know")],
        "note": "DNS changes take effect in seconds. A proxied record hides the "
                "origin address; an unproxied one publishes it.",
    },
    "cf.record_update": {
        "label": "Change a DNS record", "group": "dns", "icon": "✎",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id"), _p("record", "record id"),
                   _p("type", "type", True, "", "select",
                      ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"]),
                   _p("name", "name"), _p("content", "value"),
                   _p("ttl", "TTL", False, "1 means automatic"),
                   _p("proxied", "through Cloudflare", False, "", "select",
                      ["true", "false"])],
        "note": "Replaces the record. Whatever resolves through it changes with it.",
    },
    "cf.record_delete": {
        "label": "Delete a DNS record", "group": "dns", "icon": "🗑",
        "danger": "removal", "provider": "cloudflare",
        "params": [_p("zone", "zone id"), _p("record", "record id"),
                   _p("name", "record name", False,
                      "carried for the confirmation and the audit entry")],
        "note": "Irreversible from here, and whatever depended on that name stops "
                "resolving immediately.",
    },
    "cf.block_ip": {
        "label": "Block an address", "group": "zones", "icon": "🚫",
        "danger": "care", "provider": "cloudflare",
        "params": [_p("zone", "zone id"),
                   _p("value", "address or range", True,
                      "an IP, or a CIDR like 203.0.113.0/24"),
                   _p("mode", "what to do", True, "", "select",
                      ["block", "challenge", "js_challenge", "whitelist"]),
                   _p("notes", "why", False, "future you, again")],
        "note": "Applies to this zone only. Challenge is usually the better first "
                "move than an outright block.",
    },
    "bunny.purge": {
        "label": "Purge a pull zone", "group": "pullzones", "icon": "🧹",
        "danger": "care", "provider": "bunny",
        "params": [_p("zone", "pull zone id")],
        "note": "Empties the cache for the whole pull zone.",
    },
}


def for_group(key: str, provider: str) -> list[dict]:
    return [{**spec, "key": k} for k, spec in ACTIONS.items()
            if spec["group"] == key and spec["provider"] == provider]


def confirm_word(key: str, params: dict) -> str:
    """What has to be typed to go ahead.

    "Delete" for a removal, which is what the rest of the portal already asks for
    when removing a config key or a whole section — one convention across the
    product beats a different ritual per page. The record's name is shown in the
    dialog beside it, so what is about to go is read even though it is not typed.
    """
    spec = ACTIONS.get(key) or {}
    return "Delete" if spec.get("danger") == "removal" else "CONFIRM"


def preview(key: str, params: dict) -> str:
    spec = ACTIONS.get(key)
    if not spec:
        return ""
    given = ", ".join(f"{k}={v}" for k, v in params.items() if v != "")
    return f"{key}({given})"


def run(c: dict, key: str, params: dict) -> dict:
    """Make the change. Confirmation and the audit entry are the caller's job."""
    spec = ACTIONS.get(key)
    if not spec:
        raise EdgeError(f"unknown action '{key}'")
    if spec["provider"] != c.get("type"):
        raise EdgeError(f"{key} is a {spec['provider']} action, and this "
                        f"connection is {c.get('type')}")
    missing = [p["label"] for p in spec["params"]
               if p["required"] and not str(params.get(p["name"], "")).strip()]
    if missing:
        raise EdgeError("missing: " + ", ".join(missing))

    def val(name, default=""):
        return str(params.get(name, default)).strip()

    zone = val("zone")
    if key == "cf.purge_all":
        code, doc = _cf(c, f"/zones/{zone}/purge_cache", "POST",
                        {"purge_everything": True})
        done = "the whole cache is purged"
    elif key == "cf.purge_urls":
        files = [u.strip() for u in val("files").split(",") if u.strip()]
        code, doc = _cf(c, f"/zones/{zone}/purge_cache", "POST", {"files": files})
        done = f"{len(files)} URL(s) purged"
    elif key == "cf.dev_mode":
        code, doc = _cf(c, f"/zones/{zone}/settings/development_mode", "PATCH",
                        {"value": val("value")})
        done = f"development mode {val('value')}"
    elif key == "cf.ssl_mode":
        code, doc = _cf(c, f"/zones/{zone}/settings/ssl", "PATCH",
                        {"value": val("value")})
        done = f"TLS mode set to {val('value')}"
    elif key in ("cf.record_create", "cf.record_update"):
        body = {"type": val("type"), "name": val("name"),
                "content": val("content")}
        if val("ttl"):
            body["ttl"] = int(val("ttl"))
        if val("proxied"):
            body["proxied"] = val("proxied") == "true"
        if val("comment"):
            body["comment"] = val("comment")
        if key == "cf.record_create":
            code, doc = _cf(c, f"/zones/{zone}/dns_records", "POST", body)
            done = f"{body['type']} record for {body['name']} created"
        else:
            code, doc = _cf(c, f"/zones/{zone}/dns_records/{val('record')}",
                            "PUT", body)
            done = f"{body['type']} record for {body['name']} updated"
    elif key == "cf.record_delete":
        code, doc = _cf(c, f"/zones/{zone}/dns_records/{val('record')}", "DELETE")
        done = "record deleted"
    elif key == "cf.block_ip":
        code, doc = _cf(c, f"/zones/{zone}/firewall/access_rules/rules", "POST",
                        {"mode": val("mode"),
                         "configuration": {"target": ("ip_range"
                                                      if "/" in val("value")
                                                      else "ip"),
                                           "value": val("value")},
                         "notes": val("notes")})
        done = f"{val('value')} set to {val('mode')}"
    elif key == "bunny.purge":
        code, doc = _call(f"https://api.bunny.net/pullzone/{zone}/purgeCache",
                          {"AccessKey": c["token"]}, bool(c.get("skip_tls")),
                          "POST", {})
        done = "pull zone purged"
    else:
        raise EdgeError(f"'{key}' has no implementation")

    if c.get("type") == "cloudflare":
        if code >= 300 or (doc and doc.get("success") is False):
            raise EdgeError(_cf_why(doc, code))
    elif code >= 300:
        raise EdgeError(f"HTTP {code} {str(doc)[:160]}")
    invalidate()
    return {"ok": True, "message": done, "data": {}}


def prefill_for(group: str, ident: str, zones: list) -> dict:
    """What an action form already knows when opened from a row."""
    if group == "zones":
        return {"zone": ident}
    if group == "dns":
        # a record row knows its own id; its zone comes from the zone list
        return {"record": ident}
    return {}
