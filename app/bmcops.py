"""Managing a server through its BMC (Dell iDRAC, HPE iLO, Lenovo XCC,
Supermicro) over Redfish: power, the identify light, one-time boot, virtual
media, the event logs, the hardware inventory, a BMC reset, and on a Dell
iDRAC its console.

SAME GATES AS THE HYPERVISORS (see virtops)
    1. The connection opts in: "allow management from EnvMap" (`manage`) in
       Settings → Server hardware, off by default.
    2. The person holds the area: `bmc_console`, `bmc_power` (power and the
       identify light) or `bmc_admin` (everything else; includes the other
       two). All three escalate.
    3. A connection marked `production` wants the server's name typed —
       checked on the server.
    Refusals are audited `<action>_refused`.

STANDARD REDFISH FIRST
    Every action is the DMTF one (ComputerSystem.Reset, Boot override,
    VirtualMedia.InsertMedia, LogService.ClearLog, Manager.Reset), and a
    power action is offered only when the BMC lists it among its allowable
    values. Read from a real iDRAC9 7.00.60 on 24 November 2026.

THE CONSOLE (Dell iDRAC)
    An iDRAC's own HTML5 console is a proprietary protocol behind its web
    application. It also has a VNC server, off by default. Enabling the
    console from EnvMap turns that server on with TLS ("256-Bit or higher")
    and a random 8-character password (the iDRAC requires exactly 8) that is
    kept sealed in the connection and never sent to a browser: the relay
    connects, answers the VNC challenge itself, and presents the browser a
    session that needs no password (rfb_proxy_handshake). Disabling turns
    the server off and forgets the password.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import string
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import bmc, rbac, urlguard
from .bmc import BmcError

AREAS = {"console": "bmc_console", "power": "bmc_power", "admin": "bmc_admin"}
POWER = {"power.on": "On", "power.shutdown": "GracefulShutdown",
         "power.restart": "GracefulRestart", "power.off": "ForceOff",
         "power.reset": "ForceRestart", "power.cycle": "PowerCycle"}
ACTIONS = {
    "power.on": ("power", "power on"),
    "power.shutdown": ("power", "shut down"),
    "power.restart": ("power", "restart"),
    "power.off": ("power", "power off"),
    "power.reset": ("power", "reset"),
    "power.cycle": ("power", "power cycle"),
    "identify.on": ("power", "turn the identify light on"),
    "identify.off": ("power", "turn the identify light off"),
    "boot.once": ("admin", "set a one-time boot device"),
    "boot.clear": ("admin", "clear the boot override"),
    "media.insert": ("admin", "insert virtual media"),
    "media.eject": ("admin", "eject virtual media"),
    "log.clear": ("admin", "clear the hardware event log"),
    "bmc.reset": ("admin", "restart the BMC"),
    "console.enable": ("admin", "turn the console on"),
    "console.disable": ("admin", "turn the console off"),
    "console.open": ("console", "open the console"),
}
NOT_RUN = {"console.open"}
TIMEOUT = 20
_cache: dict = {}
_guard = threading.Lock()
_consoles: dict = {}
CONSOLE_TTL = 60
VNC_PORT = 5901


class Refused(BmcError):
    pass


def audit_name(action: str) -> str:
    return "bmc_" + action.replace(".", "_")


# ── transport ──────────────────────────────────────────────────
def call(conn: dict, method: str, path: str, body: dict | None = None):
    """One Redfish request: (status, the JSON answer or {}). A refusal raises
    BmcError with the BMC's own message (@Message.ExtendedInfo)."""
    if not path.startswith("/redfish/v1"):
        raise BmcError("not a Redfish path")
    url = conn["base_url"].rstrip("/") + path
    h = {"Accept": "application/json", "Content-Type": "application/json",
         "Authorization": "Basic " + base64.b64encode(
             f"{conn.get('username', '')}:{conn.get('token', '')}".encode()).decode()}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method=method)
    ctx = bmc._INSECURE if conn.get("skip_tls") else None
    try:
        with urlguard.urlopen(req, timeout=TIMEOUT, context=ctx, cross_host="refuse") as r:
            raw = r.read(4 * 1024 * 1024)
            try:
                return r.status, json.loads(raw.decode("utf-8", "replace") or "{}")
            except json.JSONDecodeError:
                return r.status, {}
    except urllib.error.HTTPError as e:
        msg = _redfish_error(e)
        if e.code == 401:
            raise BmcError("the BMC rejected these credentials") from e
        if e.code == 403:
            raise BmcError(f"the BMC account may not do this — {msg or 'it needs a higher role'}") from e
        raise BmcError(f"the BMC refused: {msg or f'HTTP {e.code}'}") from e
    except urllib.error.URLError as e:
        raise BmcError(f"cannot reach the BMC: {e.reason}") from e


def _redfish_error(e) -> str:
    try:
        doc = json.loads(e.read(65536).decode("utf-8", "replace") or "{}")
    except (ValueError, OSError):
        return ""
    err = doc.get("error") or {}
    infos = err.get("@Message.ExtendedInfo") or []
    msgs = [i.get("Message", "") for i in infos if isinstance(i, dict) and i.get("Message")]
    return ("; ".join(msgs) or err.get("message") or "")[:300]


def get(conn: dict, path: str) -> dict:
    return call(conn, "GET", path)[1]


# ── where things are ───────────────────────────────────────────
def paths(conn: dict) -> dict:
    """{system, chassis, manager, vendor}. The manager is the one the system
    names (Links.ManagedBy), else the first; remembered like bmc's paths."""
    key = bmc._where(conn) + "::mgr"
    hit = _cache.get(key)
    if hit:
        return hit
    vendor, system, chassis = bmc._paths.get(bmc._where(conn)) or bmc._discover(conn)
    sysd = get(conn, system)
    mgr = ((sysd.get("Links") or {}).get("ManagedBy") or [{}])[0].get("@odata.id", "")
    if not mgr:
        mgr = bmc._members(get(conn, "/redfish/v1/Managers"))[:1]
        mgr = mgr[0] if mgr else ""
    out = {"vendor": vendor, "system": system, "chassis": chassis, "manager": mgr}
    _cache[key] = out
    return out


def _member_docs(conn: dict, coll_path: str, limit: int = 64) -> list[dict]:
    """A collection's members as documents: one $expand request where the
    BMC can, else the members a few at a time."""
    try:
        doc = get(conn, coll_path + "?$expand=*($levels=1)")
        mem = doc.get("Members") or []
        if mem and all(len(m) > 1 for m in mem):
            return mem[:limit]
        refs = bmc._members(doc)
    except BmcError:
        refs = bmc._members(get(conn, coll_path))
    refs = refs[:limit]
    out: list = []
    for i in range(0, len(refs), 4):
        got = bmc._together({r: (lambda r=r: get(conn, r)) for r in refs[i:i + 4]})
        out += [got[r] for r in refs[i:i + 4] if isinstance(got[r], dict)]
    return out


def _health(d) -> str:
    st = (d or {}).get("Status") or {}
    return st.get("Health") or st.get("HealthRollup") or ""


# ── reading ────────────────────────────────────────────────────
def state(conn: dict) -> dict:
    """What the action bar needs: power, the identify light, the boot
    override and which resets the BMC allows."""
    p = paths(conn)
    sysd = get(conn, p["system"])
    boot = sysd.get("Boot") or {}
    reset = ((sysd.get("Actions") or {}).get("#ComputerSystem.Reset") or {})
    allowed = reset.get("ResetType@Redfish.AllowableValues") or list(POWER.values())
    led = sysd.get("LocationIndicatorActive")
    if led is None:
        led = (sysd.get("IndicatorLED") or "Off") in ("Lit", "Blinking")
    return {
        "power": sysd.get("PowerState", ""), "health": _health(sysd),
        "identify": bool(led), "led_style": "location" if "LocationIndicatorActive" in sysd else "indicator",
        "reset_allowed": allowed, "reset_target": reset.get("target", ""),
        "boot_target": boot.get("BootSourceOverrideTarget", "None"),
        "boot_enabled": boot.get("BootSourceOverrideEnabled", "Disabled"),
        "boot_targets": [t for t in (boot.get("BootSourceOverrideTarget@Redfish.AllowableValues")
                                     or ["None", "Pxe", "Cd", "Hdd", "BiosSetup"]) if t],
        "vendor": p["vendor"], "dell": "dell" in (p["vendor"] or "").lower(),
    }


def inventory(conn: dict) -> dict:
    """Processors, memory, storage (controllers, drives, volumes) and network
    adapters, read together and kept for five minutes."""
    key = bmc._where(conn) + "::inv"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    p = paths(conn)
    sys_ = p["system"]
    got = bmc._together({
        "cpu": lambda: _member_docs(conn, sys_ + "/Processors"),
        "mem": lambda: _member_docs(conn, sys_ + "/Memory"),
        "storage": lambda: bmc._members(get(conn, sys_ + "/Storage")),
        "nics": lambda: _member_docs(conn, sys_ + "/EthernetInterfaces"),
    })
    cpus = [{"id": c.get("Id", ""), "model": (c.get("Model") or "").strip(),
             "cores": c.get("TotalCores"), "threads": c.get("TotalThreads"),
             "mhz": c.get("MaxSpeedMHz"), "health": _health(c)}
            for c in (got["cpu"] if isinstance(got["cpu"], list) else [])
            if c.get("ProcessorType", "CPU") == "CPU"]
    dimms = [{"id": m.get("Id", ""), "gib": round((m.get("CapacityMiB") or 0) / 1024, 1),
              "speed": m.get("OperatingSpeedMhz"), "type": m.get("MemoryDeviceType", ""),
              "maker": m.get("Manufacturer", ""), "health": _health(m),
              "state": (m.get("Status") or {}).get("State", "")}
             for m in (got["mem"] if isinstance(got["mem"], list) else [])
             if (m.get("CapacityMiB") or 0) > 0]
    controllers = []
    for sp in (got["storage"] if isinstance(got["storage"], list) else [])[:8]:
        try:
            s = get(conn, sp)
        except BmcError:
            continue
        drives = []
        drefs = [d.get("@odata.id") for d in (s.get("Drives") or []) if d.get("@odata.id")][:32]
        dgot = bmc._together({r: (lambda r=r: get(conn, r)) for r in drefs[:16]})
        for r in drefs[:16]:
            d = dgot.get(r)
            if isinstance(d, dict):
                drives.append({"id": d.get("Id", ""), "model": (d.get("Model") or "").strip(),
                               "gib": round((d.get("CapacityBytes") or 0) / 1024 ** 3),
                               "media": d.get("MediaType", ""), "protocol": d.get("Protocol", ""),
                               "life": d.get("PredictedMediaLifeLeftPercent"),
                               "health": _health(d)})
        vols = []
        if (s.get("Volumes") or {}).get("@odata.id"):
            try:
                for v in _member_docs(conn, s["Volumes"]["@odata.id"], 16):
                    vols.append({"id": v.get("Id", ""), "name": v.get("Name", ""),
                                 "gib": round((v.get("CapacityBytes") or 0) / 1024 ** 3),
                                 "raid": v.get("RAIDType") or v.get("VolumeType", ""),
                                 "health": _health(v)})
            except BmcError:
                pass
        if drives or vols:
            controllers.append({"id": s.get("Id", ""), "name": s.get("Name", ""),
                                "health": _health(s), "drives": drives, "volumes": vols})
    nics = [{"id": n.get("Id", ""), "mac": n.get("MACAddress", ""),
             "speed": n.get("SpeedMbps"), "link": n.get("LinkStatus", ""),
             "health": _health(n)}
            for n in (got["nics"] if isinstance(got["nics"], list) else [])]
    out = {"cpus": cpus, "dimms": dimms, "controllers": controllers, "nics": nics,
           "mem_gib": round(sum(d["gib"] for d in dimms), 1)}
    _cache[key] = (time.time(), out)
    return out


def logs(conn: dict, which: str = "sel", top: int = 50) -> list[dict]:
    """The newest entries of a log service: sel (hardware events), lclog
    (Dell's Lifecycle log) or faultlist."""
    p = paths(conn)
    svc = {"sel": "Sel", "lclog": "Lclog", "faultlist": "FaultList"}.get(which, "Sel")
    base = f"{p['manager']}/LogServices/{svc}/Entries"
    try:
        doc = get(conn, f"{base}?$top={int(top)}")
    except BmcError:
        try:
            doc = get(conn, f"{p['system']}/LogServices/{svc}/Entries?$top={int(top)}")
        except BmcError:
            return []
    out = []
    for e in (doc.get("Members") or [])[:top]:
        out.append({"id": e.get("Id", ""), "when": e.get("Created", ""),
                    "severity": e.get("Severity", ""), "message": e.get("Message", ""),
                    "sensor": e.get("SensorType", ""), "code": e.get("MessageId", "")})
    return out


def media(conn: dict) -> list[dict]:
    p = paths(conn)
    out = []
    for d in _member_docs(conn, p["manager"] + "/VirtualMedia", 8):
        acts = d.get("Actions") or {}
        out.append({"id": d.get("Id", ""), "types": d.get("MediaTypes") or [],
                    "inserted": bool(d.get("Inserted")),
                    # never a password, however it was inserted
                    "image": re.sub(r"^([a-z]+://)[^/@\s]*@", r"\1", str(d.get("Image") or ""), flags=re.I),
                    "insert": (acts.get("#VirtualMedia.InsertMedia") or {}).get("target", ""),
                    "eject": (acts.get("#VirtualMedia.EjectMedia") or {}).get("target", "")})
    return out


def console_state(conn: dict) -> dict:
    """Dell iDRAC only: {available, enabled, port, tls, why}."""
    p = paths(conn)
    if "dell" not in (p["vendor"] or "").lower():
        return {"available": False, "enabled": False,
                "why": "the in-EnvMap console is for Dell iDRAC; use the BMC's own console"}
    try:
        a = get(conn, p["manager"] + "/Attributes").get("Attributes") or {}
    except BmcError as e:
        return {"available": False, "enabled": False, "why": str(e)}
    enabled = a.get("VNCServer.1.Enable") == "Enabled"
    return {"available": True, "enabled": enabled and bool(conn.get("vnc_password")),
            "server_on": enabled, "port": int(a.get("VNCServer.1.Port") or VNC_PORT),
            "tls": (a.get("VNCServer.1.SSLEncryptionBitLength") or "Disabled") != "Disabled",
            "why": "" if (enabled and conn.get("vnc_password")) else
            ("the iDRAC's VNC server was turned on outside EnvMap; turn the console on "
             "here so EnvMap holds its password" if enabled else "the console is off")}


# ── the gates ──────────────────────────────────────────────────
def manage_why(conn: dict) -> str:
    if not conn.get("manage"):
        return ("this server is read-only in EnvMap. To manage it, tick “Allow "
                "management from EnvMap” on it in Settings → Server hardware")
    return ""


def may(user, need: str, pid: str | None = None) -> bool:
    """Whether this person holds the area for `need`; with `pid`, for a
    server of that project too (see virtops.may)."""
    if not user:
        return False

    def holds(area):
        return rbac.may_area(user, area) and (pid is None or rbac.may_project(user, pid, area))
    return holds(AREAS[need]) or (need in ("console", "power") and holds("bmc_admin"))


def capabilities(user, conn: dict) -> dict:
    gate = manage_why(conn)
    pid = conn.get("pid") or ""
    out = {}
    for need in AREAS:
        label = rbac.AREAS[AREAS[need]][0]
        out[need] = gate or ("" if may(user, need, pid) else
                             f"your roles grant “{label}” for other projects, not this server's"
                             if may(user, need) else f"your roles do not include “{label}”")
    return out


def gate(user, conn: dict, action: str, confirm: str) -> None:
    if action not in ACTIONS:
        raise Refused("unknown action")
    why = capabilities(user, conn)[ACTIONS[action][0]]
    if why:
        raise Refused(why)
    if conn.get("production") and (confirm or "").strip() != conn.get("name", "").strip():
        raise Refused(f"this is a production server: type {conn.get('name', '')} to confirm")


def find_conn(cid: str) -> dict | None:
    from . import store
    return next((c for c in store.all_bmc() if c.get("id") == cid), None)


def forget(conn: dict) -> None:
    for k in [k for k in list(_cache) if k.startswith(bmc._where(conn))]:
        _cache.pop(k, None)
    bmc._cache.pop(bmc._key(conn), None)


# ── actions ────────────────────────────────────────────────────
def _new_password() -> str:
    """Exactly 8 characters (the iDRAC's rule), mixed classes."""
    pools = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    while True:
        pw = "".join(secrets.choice("".join(pools)) for _ in range(8))
        if all(any(ch in pool for ch in pw) for pool in pools):
            return pw


# What a BMC may be told to fetch: an http(s) URL, an NFS share
# (host:/path, never host://…, which is a URL scheme such as file://) or a
# CIFS share (//host/share/…). Nothing else — no file:, no ftp:, no spaces.
_USERINFO = re.compile(r"^[a-z]+://[^/@\s]*@", re.I)
_IMAGE = re.compile(r"^(https?://[^/\s]\S*"
                    r"|//[A-Za-z0-9][A-Za-z0-9.-]*/\S+"
                    r"|(?!(?:file|ftps?|tftp|smb|cifs|nfs|data|javascript|vbscript|"
                    r"gopher|ldaps?|dict|sftp|scp|https?):)"
                    r"[A-Za-z0-9][A-Za-z0-9.-]*:/(?!/)\S+)$", re.I)


def run(conn: dict, action: str, p: dict) -> dict:
    """Do one action; {"done": True, ...}. Raises BmcError with the BMC's
    own reason."""
    if action in NOT_RUN or action not in ACTIONS:
        raise BmcError("that action has its own route")
    pa = paths(conn)
    out: dict = {"done": True}
    if action in POWER:
        st = state(conn)
        rt = POWER[action]
        if rt not in st["reset_allowed"]:
            raise BmcError(f"this BMC does not offer {rt}")
        call(conn, "POST", st["reset_target"] or f"{pa['system']}/Actions/ComputerSystem.Reset",
             {"ResetType": rt})
    elif action in ("identify.on", "identify.off"):
        on = action == "identify.on"
        if state(conn)["led_style"] == "location":
            call(conn, "PATCH", pa["system"], {"LocationIndicatorActive": on})
        else:
            call(conn, "PATCH", pa["system"], {"IndicatorLED": "Lit" if on else "Off"})
    elif action == "boot.once":
        target = p.get("target", "")
        if target not in state(conn)["boot_targets"] or target == "None":
            raise BmcError("choose a boot device this BMC offers")
        call(conn, "PATCH", pa["system"], {"Boot": {"BootSourceOverrideTarget": target,
                                                    "BootSourceOverrideEnabled": "Once"}})
    elif action == "boot.clear":
        call(conn, "PATCH", pa["system"], {"Boot": {"BootSourceOverrideTarget": "None",
                                                    "BootSourceOverrideEnabled": "Disabled"}})
    elif action == "media.insert":
        dev = next((m for m in media(conn) if m["id"] == p.get("device")), None)
        if not dev or not dev["insert"]:
            raise BmcError("unknown virtual media device")
        image = str(p.get("image") or "").strip()
        if not _IMAGE.match(image) or len(image) > 1000 \
                or any(ch in image for ch in "\"'<>\\`"):
            raise BmcError("an image the BMC can fetch: an http(s) URL, an NFS share "
                           "(host:/path/file.iso) or a CIFS share (//host/share/file.iso)")
        if _USERINFO.search(image):
            # a password in the address would be in the audit and on the page
            # for every reader: it goes in its own fields instead
            raise BmcError("put the share's username and password in their own fields, "
                           "not in the address")
        body = {"Image": image, "Inserted": True, "WriteProtected": True}
        user, pw = str(p.get("username") or "").strip(), str(p.get("password") or "")
        if user:
            if len(user) > 128 or len(pw) > 256 or any(ord(ch) < 32 for ch in user + pw):
                raise BmcError("a username and password of printable characters")
            body.update(UserName=user, Password=pw)
        call(conn, "POST", dev["insert"], body)
    elif action == "media.eject":
        dev = next((m for m in media(conn) if m["id"] == p.get("device")), None)
        if not dev or not dev["eject"]:
            raise BmcError("unknown virtual media device")
        call(conn, "POST", dev["eject"], {})
    elif action == "log.clear":
        call(conn, "POST", f"{pa['manager']}/LogServices/Sel/Actions/LogService.ClearLog", {})
    elif action == "bmc.reset":
        call(conn, "POST", f"{pa['manager']}/Actions/Manager.Reset", {"ResetType": "GracefulRestart"})
    elif action == "console.enable":
        if not console_state(conn)["available"]:
            raise BmcError("the in-EnvMap console is for Dell iDRAC")
        pw = _new_password()
        call(conn, "PATCH", f"{pa['manager']}/Attributes", {"Attributes": {
            "VNCServer.1.Enable": "Enabled", "VNCServer.1.Password": pw,
            "VNCServer.1.SSLEncryptionBitLength": "256-Bit or higher",
            "VNCServer.1.Timeout": 1800}})
        out["vnc_password"] = pw
    elif action == "console.disable":
        call(conn, "PATCH", f"{pa['manager']}/Attributes", {"Attributes": {
            "VNCServer.1.Enable": "Disabled"}})
        out["vnc_password"] = ""
    forget(conn)
    return out


# ── the console ────────────────────────────────────────────────
def console_open(user: dict, conn: dict) -> str:
    cs = console_state(conn)
    if not cs.get("enabled"):
        raise BmcError(cs.get("why") or "the console is off")
    if not cs.get("tls"):
        # without TLS the VNC challenge and its answer cross the network in
        # the clear, and eight characters fall to an offline search
        raise BmcError("the iDRAC's VNC server is running without TLS. Turn the console "
                       "off and on again here, which turns TLS back on")
    host = urllib.parse.urlsplit(conn["base_url"]).hostname or ""
    urlguard.check(f"https://{host}:{cs['port']}/")
    sid = secrets.token_urlsafe(24)
    now = time.time()
    with _guard:
        for k in [k for k, v in _consoles.items() if v["expires"] < now]:
            _consoles.pop(k, None)
        _consoles[sid] = {"uid": user.get("id"), "conn": conn.get("id"),
                          "name": conn.get("name", ""), "host": host,
                          "port": cs["port"], "tls": cs["tls"],
                          "insecure": bool(conn.get("skip_tls")),
                          "expires": now + CONSOLE_TTL}
    return sid


def console_take(sid: str, user: dict) -> dict | None:
    with _guard:
        s = _consoles.pop(sid or "", None)
    if not s or s["expires"] < time.time() or s["uid"] != (user or {}).get("id"):
        return None
    conn = find_conn(s["conn"])
    # the connection may have been closed to management, or its console
    # turned off, in the minute since the session was opened
    if not conn or not console_still(s, user):
        return None
    s["password"] = conn["vnc_password"]
    return s


def console_still(s: dict, user: dict) -> bool:
    """Whether an open console may go on: asked when it starts and every
    half-minute after (a role removed, management switched off, the console
    turned off or the connection deleted all end it)."""
    conn = find_conn(s.get("conn", ""))
    return bool(conn) and bool(conn.get("vnc_password")) \
        and not capabilities(user, conn)["console"]


def _vnc_des(password: str, challenge: bytes) -> bytes:
    """VNC authentication: the challenge DES-encrypted with the password as
    the key, each key byte's bits reversed (RFB 6.2.2)."""
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:                                       # older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in password.encode()[:8].ljust(8, b"\0"))
    # key three times = single DES (8-byte TripleDES keys are deprecated)
    enc = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
    return enc.update(challenge) + enc.finalize()


async def rfb_proxy_handshake(srv_read, srv_write, br_read, br_write,
                              password: str) -> None:
    """Stand between the browser and a VNC server that wants a password: do
    the server's VNC authentication here, and offer the browser "None". After
    this returns, both sides are at ClientInit and bytes pass straight
    through. srv_read(n) -> exactly n bytes; br_read() -> one message."""
    ver = await srv_read(12)
    if not re.match(rb"^RFB 003\.\d{3}\n$", ver):
        raise BmcError("the console did not answer as VNC")
    minor = int(ver[8:11])
    await br_write(b"RFB 003.008\n")
    bb = bytearray()                       # what the browser has sent, unread
    while len(bb) < 12:
        bb += await br_read()
    del bb[:12]
    await srv_write(b"RFB 003.008\n" if minor >= 8 else ver)
    if minor >= 7:
        n = (await srv_read(1))[0]
        if n == 0:
            ln = min(struct.unpack(">I", await srv_read(4))[0], 1024)
            raise BmcError("the console refused: " + (await srv_read(ln)).decode("utf-8", "replace")[:200])
        types = list(await srv_read(n))
        if 2 in types:
            await srv_write(b"\x02")
            chosen = 2
        elif 1 in types:
            await srv_write(b"\x01")
            chosen = 1
        else:
            raise BmcError(f"the console offers no security type EnvMap speaks ({types})")
    else:
        chosen = struct.unpack(">I", await srv_read(4))[0]
    if chosen == 2:
        await srv_write(_vnc_des(password, await srv_read(16)))
    if chosen == 2 or minor >= 8:
        res = struct.unpack(">I", await srv_read(4))[0]
        if res != 0:
            reason = ""
            if minor >= 8:
                # a reason is a sentence: never buffer what a hostile BMC
                # announces as four gigabytes of one
                ln = min(struct.unpack(">I", await srv_read(4))[0], 1024)
                reason = (await srv_read(ln)).decode("utf-8", "replace")[:200]
            raise BmcError("the console refused the password" + (f": {reason}" if reason else ""))
    # the browser: one security type, None, accepted
    await br_write(b"\x01\x01")
    while not bb:
        bb += await br_read()
    del bb[:1]                             # its choice: None, the only one offered
    await br_write(struct.pack(">I", 0))
    if bb:                                 # ClientInit, if it came early
        await srv_write(bytes(bb))
