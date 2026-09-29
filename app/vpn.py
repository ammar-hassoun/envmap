"""VPN portals: Pritunl, OpenVPN Access Server, wg-easy and Netmaker.

WHY THIS BELONGS NEXT TO THE CLUSTERS
    Almost every internal endpoint in this portal — a BMC, a hypervisor, a
    database, a cluster API — is reachable only from inside the network, and
    the VPN is how people get inside it. When something is unreachable, "is the
    tunnel up, and who is on it" is the first question, and today it is
    answered in a different tool with a different login.

READ-ONLY, AS EVERYWHERE ELSE
    Servers, users and who is connected right now. No enabling or disabling a
    user, no restarting a server, no revoking a certificate. Those are account
    decisions with consequences the portal cannot see, and each of these tools
    has its own console with its own audit trail.

AUTH, PER TOOL
    * Pritunl signs each request: an API token identifies the caller and an API
      secret signs "token&timestamp&nonce&method&path" with HMAC-SHA256. The
      secret is never sent, which is why Pritunl is the pleasant one here.
    * OpenVPN Access Server has no REST API for this in the free build. Its
      XML-RPC endpoint (/RPC2) answers to an admin account over basic auth,
      which means a real password is stored — said plainly on the settings page.
    * wg-easy exposes a small JSON API behind a session cookie obtained from
      its password login. WireGuard itself has no API at all; without a
      management layer there is nothing here to connect to.
    * Netmaker issues a JWT from a username and password, or takes a
      long-lived API key, which is the better choice.

Normalised shapes:
    server  {name, status, online, port, protocol, network, users, detail}
    peer    {user, server, address, since, bytes_in, bytes_out, client}
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import urlguard
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 15
CACHE_TTL = 45

PROVIDERS = {
    "pritunl": {
        "label": "Pritunl",
        "icon": "🔒",
        "url_hint": "https://vpn.example.com",
        "needs": ["base_url", "username", "token"],
        "auth": "an API token and its secret, both 32 characters, from the "
                "Administrators section of the Pritunl console. Needs a "
                "Pritunl Enterprise subscription — the free edition has no "
                "admin API, and no credential will make this work without "
                "one. Not the username and password you sign in with",
        "fields": {"base_url": "Pritunl URL",
                   "username": "API token (32 characters)",
                   "token": "API secret (32 characters)"},
        "note": "Reads organisations, servers, users and who is connected. "
                "Each request is signed with the secret rather than carrying "
                "it, so the secret never crosses the network. Pritunl often "
                "runs with its own certificate — expect to tick “skip TLS "
                "verification”.",
        "reads": "servers, organisations, users, live sessions",
    },
    "openvpn_as": {
        "label": "OpenVPN Access Server",
        "icon": "🛡",
        "url_hint": "https://vpn.example.com:943",
        "needs": ["base_url", "username", "token"],
        "auth": "an Access Server admin account (username and password)",
        "fields": {"base_url": "Access Server URL (port 943)",
                   "username": "Admin username", "token": "Admin password"},
        "note": "Uses the XML-RPC admin API at /RPC2 — the only interface "
                "Access Server offers for this. It takes a real admin password "
                "rather than a token, so that password is stored in the portal "
                "database; give it an account with as little as the API allows. "
                "Reads the user list and current sessions.",
        "reads": "users, current sessions",
    },
    "wg_easy": {
        "label": "wg-easy",
        "icon": "⚡",
        "url_hint": "https://wg.example.com:51821",
        "needs": ["base_url", "token"],
        "auth": "the wg-easy web password",
        "fields": {"base_url": "wg-easy URL (port 51821)",
                   "token": "Web password"},
        "note": "The small WireGuard front-end. Reads every configured peer "
                "with its address and last handshake, which is how wg-easy "
                "reports who is connected. Plain WireGuard with no front-end "
                "has no API and cannot be added here.",
        "reads": "peers, last handshake, transfer",
    },
    "netmaker": {
        "label": "Netmaker",
        "icon": "🕸",
        "url_hint": "https://api.netmaker.example.com",
        "needs": ["base_url", "token"],
        "auth": "an API key (or a master key) sent as a bearer token",
        "fields": {"base_url": "Netmaker API URL", "token": "API key"},
        "note": "Reads networks and their hosts, with the last check-in for "
                "each. Prefer an API key over a username and password: the key "
                "can be revoked on its own without changing anyone's login.",
        "reads": "networks, hosts, last check-in",
    },
}


class VPNError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

_cache: dict[str, tuple[float, dict]] = {}


def invalidate() -> None:
    _cache.clear()


def _req(url: str, c: dict, headers: dict | None = None,
         data: bytes | None = None, method: str = "",
         want_json: bool = True):
    h = {"Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
        method=method or ("POST" if data is not None else "GET"))
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read().decode("utf-8", "replace")
            got_headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:                                      # noqa: BLE001
            pass
        if e.code in (401, 403):
            # The server's own words, not just ours. Pritunl answers "401
            # Missing token" when the Auth-Token header never arrived and
            # something else when it arrived and was wrong — two different
            # problems that our generic sentence made look identical, and the
            # difference is most of the diagnosis.
            said = " ".join(detail.split())[:120]
            raise VPNError("credentials refused"
                           + (f" — it said: {said}" if said else "")
                           + " — check the token and that the account is "
                             "still enabled") from e
        if e.code == 404:
            raise VPNError(f"{url} is not there — check the URL") from e
        raise VPNError(f"HTTP {e.code}{': ' + detail if detail else ''}") from e
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError):
            raise VPNError("TLS failed — a private certificate usually means "
                           "ticking “skip TLS verification”") from e
        raise VPNError(f"cannot reach it: {reason}") from e
    except TimeoutError as e:
        raise VPNError(f"no answer within {TIMEOUT}s") from e
    if not want_json:
        return raw, got_headers
    try:
        return (json.loads(raw) if raw.strip() else {}), got_headers
    except json.JSONDecodeError as e:
        raise VPNError("that URL answered with something that is not JSON — "
                       "it is usually the web UI rather than the API") from e


def _base(c: dict) -> str:
    return (c.get("base_url") or "").rstrip("/")


# ── Pritunl ────────────────────────────────────────────────────
# Pritunl generates both of these itself, and both are 32 characters. A short
# value in either box is almost always a console username and password typed
# in by hand — an easy mistake, because the fields ask for a "token" and a
# "secret" and a login has two boxes too.
#
# The other reason the boxes end up wrong is that there is nothing to put in
# them: Pritunl's admin API is an Enterprise feature, so on the free edition
# the Administrators section has no token to copy. Both possibilities are
# named below, because "credentials refused" sent somebody hunting through a
# console for a checkbox that does nothing here.
PRITUNL_KEY_LEN = 32


def _pritunl_credentials_problem(c: dict) -> str:
    token = (c.get("username") or "").strip()
    secret = (c.get("token") or "").strip()
    if not token or not secret:
        return "Pritunl needs both an API token and its secret"
    wrong = [name for name, v in (("token", token), ("secret", secret))
             if len(v) != PRITUNL_KEY_LEN]
    if wrong:
        return (f"that does not look like a Pritunl API "
                f"{' or '.join(wrong)}: both are {PRITUNL_KEY_LEN} characters "
                f"and these are {len(token)} and {len(secret)}. They are not "
                f"the username and password you sign in with: the real ones "
                f"are in the Administrators section of the Pritunl console, "
                f"which needs a Pritunl Enterprise subscription — the free "
                f"edition has no admin API at all")
    return ""


def _pritunl(c: dict, path: str) -> object:
    """Signed request. The secret signs the line; it is never transmitted."""
    token = (c.get("username") or "").strip()
    secret = (c.get("token") or "").strip()
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    line = "&".join([token, ts, nonce, "GET", path])
    sig = base64.b64encode(
        hmac.new(secret.encode(), line.encode(), hashlib.sha256).digest()).decode()
    body, _ = _req(f"{_base(c)}{path}", c, {
        "Auth-Token": token, "Auth-Timestamp": ts, "Auth-Nonce": nonce,
        "Auth-Signature": sig})
    return body


def _read_pritunl(c: dict) -> dict:
    if (why := _pritunl_credentials_problem(c)):
        raise VPNError(why)
    servers = _pritunl(c, "/server")
    orgs = _pritunl(c, "/organization")
    out_servers, peers = [], []
    users = 0
    for org in orgs if isinstance(orgs, list) else []:
        users += int(org.get("user_count") or 0)
    for s in servers if isinstance(servers, list) else []:
        sid = s.get("id", "")
        online = s.get("status") == "online"
        out_servers.append({
            "name": s.get("name", sid), "status": s.get("status", "unknown"),
            "online": online, "port": s.get("port", ""),
            "protocol": (s.get("protocol") or "").upper(),
            "network": s.get("network", ""),
            "users": int(s.get("users_online") or 0),
            "detail": f"{s.get('cipher', '')} {s.get('hash', '')}".strip(),
        })
        if not online:
            continue
        # Connected devices are per server. Pritunl has moved this endpoint
        # between versions, so a failure here costs the session list for that
        # server and nothing else — the server row is already known good.
        try:
            conns = _pritunl(c, f"/server/{sid}/device")
        except VPNError:
            conns = []
        for d in conns if isinstance(conns, list) else []:
            peers.append({
                "user": d.get("name") or d.get("user_id", ""),
                "server": s.get("name", sid),
                "address": d.get("virt_address") or d.get("real_address", ""),
                "since": _ago(d.get("connected_since")),
                "bytes_in": int(d.get("bytes_received") or 0),
                "bytes_out": int(d.get("bytes_sent") or 0),
                "client": d.get("platform") or d.get("device_name", ""),
            })
    return {"servers": out_servers, "peers": peers, "users": users,
            "orgs": len(orgs) if isinstance(orgs, list) else 0}


# ── OpenVPN Access Server (XML-RPC) ────────────────────────────
_XMLRPC = ('<?xml version="1.0"?><methodCall><methodName>{m}</methodName>'
           '<params></params></methodCall>')


def _openvpn(c: dict, method: str) -> str:
    auth = base64.b64encode(
        f"{c.get('username', '')}:{c.get('token', '')}".encode()).decode()
    raw, _ = _req(f"{_base(c)}/RPC2", c,
                  {"Authorization": f"Basic {auth}",
                   "Content-Type": "text/xml", "Accept": "text/xml"},
                  data=_XMLRPC.format(m=method).encode(), want_json=False)
    if "<fault>" in raw:
        raise VPNError("Access Server refused that call — the account may not "
                       "have admin rights")
    return raw


def _xml_values(raw: str, name: str) -> list[str]:
    """Access Server's XML-RPC replies are deeply nested and vary by version.
    Pulling the fields by name is uglier than a parser and far more durable
    than assuming a shape that changes between 2.7 and 2.13."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise VPNError("Access Server sent a reply that could not be read") from e
    out = []
    for member in root.iter("member"):
        n = member.find("name")
        v = member.find("value")
        if n is not None and n.text == name and v is not None:
            out.append("".join(v.itertext()).strip())
    return out


def _read_openvpn(c: dict) -> dict:
    users = _xml_values(_openvpn(c, "EnumClients"), "")
    try:
        raw = _openvpn(c, "VPNStatus")
    except VPNError:
        raw = ""
    names = _xml_values(raw, "common_name")
    addrs = _xml_values(raw, "virtual_addr")
    since = _xml_values(raw, "connected_since")
    peers = [{"user": n, "server": "Access Server",
              "address": addrs[i] if i < len(addrs) else "",
              "since": _ago(since[i] if i < len(since) else ""),
              "bytes_in": 0, "bytes_out": 0, "client": ""}
             for i, n in enumerate(names)]
    return {"servers": [{"name": "Access Server", "status": "online",
                         "online": True, "port": "", "protocol": "",
                         "network": "", "users": len(peers),
                         "detail": "XML-RPC"}],
            "peers": peers, "users": len(users) or len(peers), "orgs": 0}


# ── wg-easy ────────────────────────────────────────────────────
def _read_wg_easy(c: dict) -> dict:
    body, headers = _req(f"{_base(c)}/api/session", c,
                         {"Content-Type": "application/json"},
                         data=json.dumps({"password": c.get("token", "")}).encode())
    cookie = (headers.get("Set-Cookie") or "").split(";")[0]
    if not cookie:
        raise VPNError("wg-easy accepted the password but sent no session "
                       "cookie — check the version")
    clients, _ = _req(f"{_base(c)}/api/wireguard/client", c, {"Cookie": cookie})
    peers, online = [], 0
    for w in clients if isinstance(clients, list) else []:
        fresh = _fresh(w.get("latestHandshakeAt"))
        if fresh:
            online += 1
        peers.append({"user": w.get("name", ""), "server": "WireGuard",
                      "address": w.get("address", ""),
                      "since": _ago(w.get("latestHandshakeAt")),
                      "bytes_in": int(w.get("transferRx") or 0),
                      "bytes_out": int(w.get("transferTx") or 0),
                      "client": "connected" if fresh else "idle"})
    return {"servers": [{"name": "WireGuard", "status": "online", "online": True,
                         "port": "", "protocol": "WireGuard", "network": "",
                         "users": online, "detail": f"{len(peers)} peer(s)"}],
            "peers": [p for p in peers if p["client"] == "connected"] or peers,
            "users": len(peers), "orgs": 0}


# ── Netmaker ───────────────────────────────────────────────────
def _read_netmaker(c: dict) -> dict:
    head = {"Authorization": f"Bearer {c.get('token', '')}"}
    nets, _ = _req(f"{_base(c)}/api/networks", c, head)
    hosts, _ = _req(f"{_base(c)}/api/hosts", c, head)
    servers = [{"name": n.get("netid", ""), "status": "online", "online": True,
                "port": "", "protocol": "WireGuard",
                "network": n.get("addressrange", ""), "users": 0,
                "detail": n.get("defaultinterface", "")}
               for n in (nets if isinstance(nets, list) else [])]
    peers = []
    for h in hosts if isinstance(hosts, list) else []:
        peers.append({"user": h.get("name", ""), "server": "",
                      "address": h.get("endpointip", ""),
                      "since": _ago(h.get("lastcheckin")),
                      "bytes_in": 0, "bytes_out": 0,
                      "client": h.get("os", "")})
    for s in servers:
        s["users"] = len(peers)
    return {"servers": servers, "peers": peers, "users": len(peers),
            "orgs": len(servers)}


# ── shared ─────────────────────────────────────────────────────
_READERS = {"pritunl": _read_pritunl, "openvpn_as": _read_openvpn,
            "wg_easy": _read_wg_easy, "netmaker": _read_netmaker}


def _epoch(v) -> float:
    """These four tools report time in four ways: ISO strings, seconds and
    milliseconds since the epoch."""
    if not v:
        return 0.0
    if isinstance(v, (int, float)):
        return float(v) / 1000 if float(v) > 1e11 else float(v)
    text = str(v).strip().replace("Z", "+00:00")
    try:
        from datetime import datetime
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        try:
            n = float(text)
            return n / 1000 if n > 1e11 else n
        except ValueError:
            return 0.0


def _fresh(v, within: int = 180) -> bool:
    t = _epoch(v)
    return bool(t) and (time.time() - t) < within


def _ago(v) -> str:
    t = _epoch(v)
    if not t:
        return ""
    secs = int(time.time() - t)
    if secs < 0:
        return "just now"
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return f"{secs}s ago"


def read(conn: dict, refresh: bool = False) -> dict:
    key = f"{conn.get('id', '')}:{conn.get('type', '')}"
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    reader = _READERS.get(conn.get("type", ""))
    if not reader:
        raise VPNError("unknown VPN type")
    got = reader(conn)
    got["connected"] = len(got.get("peers", []))
    _cache[key] = (time.time(), got)
    return got


def read_all(conns: list[dict]) -> list[dict]:
    """Every portal at once. One that is down must not hold up the others, so
    a failure becomes a row with an error on it rather than an exception."""
    def one(c: dict) -> dict:
        try:
            return {"conn": c, "data": read(c), "error": ""}
        except VPNError as e:
            return {"conn": c, "data": None, "error": str(e)}
        except Exception as e:                                 # noqa: BLE001
            return {"conn": c, "data": None, "error": f"{type(e).__name__}: {e}"}
    if not conns:
        return []
    with ThreadPoolExecutor(max_workers=min(6, len(conns))) as pool:
        return list(pool.map(one, conns))


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = read(conn, refresh=True)
    except VPNError as e:
        return False, str(e)
    except Exception as e:                                     # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    bits = [f"connected — {len(got['servers'])} server(s)"]
    if got.get("users"):
        bits.append(f"{got['users']} user(s)")
    bits.append(f"{got['connected']} connected now")
    return True, ", ".join(bits)
