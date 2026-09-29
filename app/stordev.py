"""Storage devices: the boxes backups land on, registered and health-checked.

WHY THIS PAGE EXISTS
    Backup targets are the piece of infrastructure nobody watches until a
    restore fails. Registering them here gives them the same treatment as CI
    or monitoring: a named connection, a Test button that proves the thing
    answers, and a status line that says when it last did.

WHAT IT IS, AND IS NOT
    This is an inventory with health checks — it does not browse shares, read
    backup catalogues or move data. Checks are protocol-appropriate and shallow
    on purpose: a DSM login proves a Synology is up and the credentials work; a
    TCP handshake proves an NFS or SMB endpoint is listening. Deeper (are last
    night's backups actually there?) belongs to the backup software's own
    reporting, which can be connected through the monitoring page.

    Nothing here is Synology-specific by design: a provider is an entry in
    PROVIDERS with a check function, exactly like ci.py and monitoring.py, so
    the next kind of box is a dict entry and a function.
"""
import json
import socket
import ssl

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10

PROVIDERS = {
    "synology": {
        "label": "Synology DSM",
        "icon": "🗄",
        "url_hint": "https://nas.example.com:5001",
        "needs": ["base_url"],
        "auth": "account + password (a dedicated read-only DSM user is enough)",
        "note": "Talks to the DSM web API: confirms the box answers and, when "
                "an account is given, that a login actually works. Create a "
                "dedicated portal user in DSM with no share access — the check "
                "needs nothing but the ability to sign in.",
    },
    "truenas": {
        "label": "TrueNAS",
        "icon": "🐟",
        "url_hint": "https://truenas.example.com",
        "needs": ["base_url", "token"],
        "auth": "API key (System Settings → API Keys)",
        "note": "Reads /api/v2.0/system/info with the API key and reports the "
                "version it finds.",
    },
    "minio": {
        "label": "MinIO",
        "icon": "🪣",
        "url_hint": "https://minio.example.com:9000",
        "needs": ["base_url"],
        "auth": "none needed — the health endpoint is unauthenticated",
        "note": "Checks /minio/health/live, the endpoint MinIO itself exposes "
                "for exactly this purpose.",
    },
    "s3": {
        "label": "S3-compatible endpoint",
        "icon": "☁️",
        "url_hint": "https://s3.example.com",
        "needs": ["base_url"],
        "auth": "none for the check — it proves the endpoint speaks S3",
        "note": "Any S3-compatible service (Ceph RGW, Wasabi, Backblaze B2…). "
                "The check makes an unsigned request and accepts the signed "
                "XML refusal as proof of life — S3 saying 'AccessDenied' is "
                "S3 answering.",
    },
    "nfs": {
        "label": "NFS server",
        "icon": "📁",
        "url_hint": "nas.example.com  or  nas.example.com:2049",
        "needs": ["base_url"],
        "auth": "none — NFS authorises by export list, not login",
        "note": "A TCP handshake on the NFS port (2049 unless the host says "
                "otherwise). Proves the server is listening; whether an export "
                "mounts is decided by its export list.",
    },
    "smb": {
        "label": "SMB / CIFS share",
        "icon": "🗂",
        "url_hint": "nas.example.com  or  nas.example.com:445",
        "needs": ["base_url"],
        "auth": "none for the check — a TCP handshake on the SMB port",
        "note": "Proves the server is listening on 445. Verifying a specific "
                "share and credentials needs an SMB client, which the check "
                "deliberately does not carry.",
    },
    "http": {
        "label": "Anything with a URL",
        "icon": "🌐",
        "url_hint": "https://backups.example.com/health",
        "needs": ["base_url"],
        "auth": "optional bearer token or basic auth",
        "note": "A plain HTTP check for any other box: 2xx or 3xx is healthy. "
                "Point it at a health endpoint if the device has one.",
    },
}


class StorError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _http(url: str, c: dict, headers: dict | None = None):
    """GET with this device's auth and TLS choices; returns (code, body)."""
    h = {"Accept": "application/json", **(headers or {})}
    if c.get("token") and not c.get("username"):
        h["Authorization"] = f"Bearer {c['token']}"
    elif c.get("username"):
        import base64
        cred = base64.b64encode(
            f"{c['username']}:{c.get('token', '')}".encode()).decode()
        h["Authorization"] = f"Basic {cred}"
    req = urllib.request.Request(urlguard.check(url), headers=h)
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.getcode(), r.read(65536).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode(errors="replace")


def _tcp(hostport: str, default_port: int) -> tuple[bool, str]:
    host, _, port = hostport.replace("nfs://", "").replace("smb://", "") \
        .replace("//", "").partition(":")
    host = host.strip("/")
    try:
        p = int(port) if port else default_port
    except ValueError:
        p = default_port
    try:
        with socket.create_connection((host, p), timeout=TIMEOUT):
            return True, f"{host} is listening on {p}"
    except OSError as e:
        return False, f"{host}:{p} — {e}"


# ── per-provider checks ────────────────────────────────────────
def _check_synology(c: dict) -> tuple[bool, str]:
    base = c["base_url"].rstrip("/")
    code, body = _http(f"{base}/webapi/entry.cgi?api=SYNO.API.Info&version=1"
                       "&method=query&query=SYNO.API.Auth", {**c, "token": "",
                                                             "username": ""})
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        return False, f"answered HTTP {code} but not with the DSM API — " \
                      "is the port the DSM one (5000/5001)?"
    if not doc.get("success"):
        return False, "the DSM API refused the info query"
    if not (c.get("username") and c.get("token")):
        return True, "DSM answers (no account given, so login not tested)"
    q = urllib.parse.urlencode({
        "api": "SYNO.API.Auth", "version": "3", "method": "login",
        "account": c["username"], "passwd": c["token"],
        "session": "portal", "format": "sid"})
    code, body = _http(f"{base}/webapi/entry.cgi?{q}",
                       {**c, "token": "", "username": ""})
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        return False, "login endpoint gave a non-JSON answer"
    if not doc.get("success"):
        err = (doc.get("error") or {}).get("code")
        return False, {400: "wrong account or password",
                       403: "2-step verification is on for this account — "
                            "use one without it for the check",
                       }.get(err, f"DSM refused the login (code {err})")
    sid = (doc.get("data") or {}).get("sid", "")
    if sid:      # be a good citizen: close the session we opened
        _http(f"{base}/webapi/entry.cgi?api=SYNO.API.Auth&version=3"
              f"&method=logout&session=portal&_sid={urllib.parse.quote(sid)}",
              {**c, "token": "", "username": ""})
    return True, "DSM answers and the account signs in"


def _check_truenas(c: dict) -> tuple[bool, str]:
    code, body = _http(f"{c['base_url'].rstrip('/')}/api/v2.0/system/info", c)
    if code == 401:
        return False, "the API key was refused"
    if code != 200:
        return False, f"HTTP {code} from the TrueNAS API"
    try:
        info = json.loads(body)
        return True, f"{info.get('version', 'TrueNAS')} on " \
                     f"{info.get('hostname', '?')}"
    except json.JSONDecodeError:
        return False, "answered, but not with the TrueNAS API"


def _check_minio(c: dict) -> tuple[bool, str]:
    code, _ = _http(f"{c['base_url'].rstrip('/')}/minio/health/live", c)
    return (True, "ok: MinIO reports itself live") if code == 200 \
        else (False, f"health endpoint answered HTTP {code}")


def _check_s3(c: dict) -> tuple[bool, str]:
    code, body = _http(c["base_url"].rstrip("/"), c)
    if code in (200, 403) and ("<Error>" in body or "ListAllMyBuckets" in body
                               or "AccessDenied" in body):
        return True, "the endpoint speaks S3"
    if code < 500:
        return True, f"endpoint answers (HTTP {code}), " \
                     "though it did not identify itself as S3"
    return False, f"HTTP {code}"


def _check_http(c: dict) -> tuple[bool, str]:
    code, _ = _http(c["base_url"], c)
    return (True, f"ok: HTTP {code}") if code < 400 else (False, f"HTTP {code}")


CHECKS = {
    "synology": _check_synology,
    "truenas": _check_truenas,
    "minio": _check_minio,
    "s3": _check_s3,
    "nfs": lambda c: _tcp(c["base_url"], 2049),
    "smb": lambda c: _tcp(c["base_url"], 445),
    "http": _check_http,
}


def test(conn: dict) -> tuple[bool, str]:
    kind = conn.get("type", "")
    if kind not in CHECKS:
        return False, f"unknown device type '{kind}'"
    if not (conn.get("base_url") or "").strip():
        return False, "an address is required"
    try:
        return CHECKS[kind](conn)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
