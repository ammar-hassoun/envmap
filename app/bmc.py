"""Server hardware, through Redfish: iDRAC, iLO, XCC, Supermicro — one protocol.

WHY REDFISH AND NOT VENDOR APIS
    Dell iDRAC, HPE iLO, Lenovo XCC and Supermicro BMCs all implement Redfish,
    the DMTF standard, and have done for years (iDRAC 7+ / iLO 4+). So there is
    one implementation here rather than four, the vendor is *detected* rather
    than configured, and a BMC from a vendor nobody thought about works on the
    day it is plugged in. Vendor-specific endpoints would have meant a new module
    per manufacturer and a portal that silently lags the estate.

WHAT IT READS
    Model and serial, power state, the BMC's own health roll-up, temperatures and
    fans, and firmware versions — the answers to "is this box unhappy, and which
    box is it". Enough to triage from a desk instead of walking to a rack.

    And the operating system, where the BMC knows it: the OS's own agent (Dell's
    iDRAC Service Module, HPE's Agentless Management Service) writes its name,
    version and host name into the BMC of the box it runs on. That is the box
    telling on itself, not a name matched across systems, so it is shown as
    fact. Without the agent the BMC has no idea, and EnvMap says so.

WHAT IT WILL NOT DO
    No power actions. Redfish exposes reset, power off and virtual media, and a
    web page that can power-cycle a production database by mis-click is a worse
    trade than walking to the BMC's own UI — which every row links to. This is
    the same line the cluster pages draw between reading and managing.

CERTIFICATES
    BMCs ship with self-signed certificates and almost nobody replaces them, so
    "skip TLS verification" is expected here rather than a red flag — but it is
    still per-device and explicit, never assumed.
"""
import base64
import hashlib
import json
import re
import ssl
import threading
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 12
CACHE_TTL = 90        # sensors move slowly; a BMC is also slow to answer

PROVIDERS = {
    "redfish": {
        "label": "Redfish BMC",
        "icon": "🔌",
        "url_hint": "https://10.0.0.10  (the BMC's address, not the server's)",
        "needs": ["base_url", "username"],
        "auth": "a BMC account with the read-only role",
        "fields": {"base_url": "BMC address (https://…)",
                   "username": "BMC username", "token": "BMC password",
                   "asset": "Linked inventory asset (optional)"},
        "note": "Works with Dell iDRAC 7+, HPE iLO 4+, Lenovo XCC, Supermicro "
                "and anything else implementing Redfish — the vendor and model "
                "are read from the BMC, not configured here. Most BMCs use a "
                "self-signed certificate, so ticking “skip TLS verification” is "
                "normal for these.",
    },
}


class BmcError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

_cache: dict = {}
_os_seen: dict = {}  # _key(conn) -> (when, _dell_os(conn)), {} = none reported
OS_TTL = 1800        # an operating system changes on a reinstall, not between looks


def invalidate() -> None:
    # not _paths: where a BMC keeps its system never changes, and a path that
    # stops answering (404) is looked up again by _fresh on its own
    _cache.clear()
    _os_seen.clear()


def _get(c: dict, path: str):
    url = c["base_url"].rstrip("/") + path
    h = {"Accept": "application/json",
         "Authorization": "Basic " + base64.b64encode(
             f"{c.get('username','')}:{c.get('token','')}".encode()).decode()}
    req = urllib.request.Request(urlguard.check(url), headers=h)
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urlguard.urlopen(req, timeout=TIMEOUT, context=ctx, cross_host="refuse") as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise BmcError("the BMC rejected these credentials") from e
        if e.code == 404:
            raise BmcError(f"{path} not found — an unusually old or partial "
                           "Redfish implementation") from e
        raise BmcError(f"HTTP {e.code} from {path}") from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason:
            raise BmcError("the certificate is not trusted — BMCs ship with "
                           "self-signed certificates, so tick “skip TLS "
                           "verification” for this device") from e
        raise BmcError(f"cannot reach the BMC: {reason}") from e
    except json.JSONDecodeError as e:
        raise BmcError("answered, but not with JSON — is this the BMC address "
                       "rather than the server's own?") from e


def _members(doc) -> list[str]:
    return [m.get("@odata.id", "") for m in (doc or {}).get("Members") or []
            if m.get("@odata.id")]


def _health(raw: dict) -> str:
    st = (raw or {}).get("Status") or {}
    return (st.get("Health") or st.get("HealthRollup") or "").strip()


def _text(v, most: int = 120) -> str:
    """A BMC field as one short line: the OS agent writes these, not the BMC."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(v or ""))
    return " ".join(s.split())[:most]


def os_label(name: str, version: str = "") -> str:
    """"Ubuntu 22.04.4 LTS", "ESXi 8.0 U3", "Red Hat Enterprise Linux 8.6":
    the name and the release, without the kernel, build and image tags an
    agent adds ("22.04.4 LTS (Jammy Jellyfish) Kernel 5.15.0-91-generic",
    "Version 8.6 (Ootpa) (x86_64)").

    ESXi reads the same however its image says it. Real iDRACs answered, for
    one release, "VMware ESXi" "8.0 Update 3 build-25595708", "VMware ESXi"
    "8.0.3 25595708 U3 P102" and "Dell-VMware ESXi" "8.0 Update 2
    Build-22380479 (A00)" (16 iDRACs, 25 November 2026): all of it is
    "ESXi 8.0 U<n>", as EnvMap names the hypervisor everywhere else."""
    name = _text(name, 80)
    if not name:
        return ""

    def release(text: str) -> str:
        r = re.split(r"\s*\(|\s+(?:kernel|build)\b|\s+\d{5,}\b", _text(text, 120),
                     maxsplit=1, flags=re.I)[0]
        r = re.sub(r"^(?:version|ver\.?|v)\s*", "", r, flags=re.I).strip(" ,;-")
        return re.sub(r"\bUpdate\s*(\d+)", r"U\1", r)
    v = release(version)
    if re.search(r"\besxi\b", name, re.I):
        # an iLO puts the release in the name: "VMware ESXi 8.0.2"
        inname = re.search(r"\d+\.\d+.*$", name)
        v = v or (release(inname.group(0)) if inname else "")
        name = "ESXi"
        m = re.fullmatch(r"(\d+\.\d+)\.(\d+)(.*)", v)
        if m:                                   # 8.0.3 is 8.0 Update 3
            v = m.group(1) + (f" U{int(m.group(2))}" if int(m.group(2)) else "") + m.group(3)
    if not v or v.lower() in name.lower():
        return name
    return f"{name} {v}"[:80]


def is_hypervisor_os(label: str) -> bool:
    """An OS that is itself a hypervisor EnvMap can connect to."""
    low = (label or "").lower()
    return "esxi" in low or "proxmox" in low


def agent(vendor: str) -> tuple[str, str]:
    """(what the BMC is called, the agent that tells it the OS) for a vendor."""
    low = (vendor or "").lower()
    if "dell" in low:
        return "iDRAC", "the iDRAC Service Module (iSM)"
    if low.startswith("hp"):
        return "iLO", "the Agentless Management Service (AMS)"
    return "BMC", ""


# Where an iDRAC keeps the System attribute set, ServerOS.1.* among it: the
# Managers path from iDRAC9 4.x, the Dell OEM one before it.
_DELL_OS_PATHS = ("/redfish/v1/Managers/System.Embedded.1/Attributes",
                  "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/System.Embedded.1")


def _dell_os(conn: dict) -> dict:
    """What the iDRAC Service Module told the iDRAC: blank without it."""
    for path in _DELL_OS_PATHS:
        try:
            attrs = (_get(conn, path) or {}).get("Attributes") or {}
        except BmcError as e:
            if "not found" in str(e):
                continue
            raise
        name, version = attrs.get("ServerOS.1.OSName"), attrs.get("ServerOS.1.OSVersion")
        return {"name": _text(name, 80), "version": _text(version),
                "hostname": _text(attrs.get("ServerOS.1.HostName"), 253),
                "label": os_label(name, version)}
    return {}


def _hpe_os(sysd: dict) -> dict:
    """An iLO carries what its agent reported in the system itself. Its OsName
    already holds the release ("Ubuntu 22.04.1 LTS"); OsVersion is the kernel."""
    oem = sysd.get("Oem") or {}
    h = (oem.get("Hpe") or oem.get("Hp") or {}).get("HostOS") or {}
    name = _text(h.get("OsName"), 80)
    return {"name": name, "version": _text(h.get("OsVersion")), "hostname": "",
            "label": os_label(name)} if name else {}


STALE_MAX = 900      # past CACHE_TTL, served at once while a fresh read runs
FW_WORKERS = 4       # a BMC is one small CPU: a few requests at once, not 25
_refreshing: set = set()
_guard = threading.Lock()


def _key(conn: dict) -> str:
    """The connection AND what it reads with: an edited address or password
    is never answered from what the old one returned."""
    raw = "\0".join(str(conn.get(k) or "") for k in
                    ("id", "base_url", "username", "token", "skip_tls"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _together(calls: dict) -> dict:
    """Run {name: zero-argument callable} at once on daemon threads ->
    {name: result or the exception it raised}. A BMC answers each request in
    0.2-1s and the old read made up to 32 of them one after another, so one
    iDRAC took 9-11s and a page of 16 took half a minute (measured on a real
    estate, 24 November 2026)."""
    out: dict = {}

    def run(name, fn):
        try:
            out[name] = fn()
        except Exception as e:                                # noqa: BLE001
            out[name] = e

    threads = [threading.Thread(target=run, args=(n, f), daemon=True)
               for n, f in calls.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(TIMEOUT * 2 + 5)
    return {n: out.get(n, BmcError("the BMC did not answer in time"))
            for n in calls}


def read(conn: dict, refresh: bool = False, detail: bool = True) -> dict:
    """Everything the page shows for one BMC.

    `detail` adds the firmware inventory, which only a device's own page
    shows and which costs one request per component; the list, the Overview
    and the assistant read without it.

    Cached for CACHE_TTL; after that, for up to STALE_MAX, the last answer is
    returned at once and a fresh one is read behind the caller, so opening the
    page never waits on a BMC it has read recently. Refresh reads now."""
    key = _key(conn)
    if refresh:
        _os_seen.pop(key, None)
    hit = _cache.get(key)
    if hit and not refresh and (hit[2] or not detail):
        age = time.time() - hit[0]
        if age < CACHE_TTL:
            return hit[1]
        if age < STALE_MAX:
            _behind(conn, key, hit[2])
            return hit[1]
    return _fresh(conn, key, detail)


def _behind(conn: dict, key: str, detail: bool) -> None:
    with _guard:
        if key in _refreshing:
            return
        _refreshing.add(key)

    def run():
        try:
            _fresh(conn, key, detail)
        except Exception:                                     # noqa: BLE001
            pass
        finally:
            with _guard:
                _refreshing.discard(key)

    threading.Thread(target=run, name="bmc-refresh", daemon=True).start()


_paths: dict = {}


def _where(conn: dict) -> str:
    return f"{conn.get('id')}::{conn.get('base_url')}"


def _discover(conn: dict) -> tuple[str, str, str]:
    """(vendor, the first system's path, the first chassis' path or "").
    Three requests that answer the same thing every time, so remembered per
    connection: after the first read a BMC is read in one round, not two."""
    got = _together({"root": lambda: _get(conn, "/redfish/v1"),
                     "systems": lambda: _get(conn, "/redfish/v1/Systems"),
                     "chassis": lambda: _get(conn, "/redfish/v1/Chassis")})
    for name in ("root", "systems"):
        if isinstance(got[name], Exception):
            raise got[name]
    root = got["root"]
    vendor = root.get("Vendor") or root.get("Oem") and list(
        (root.get("Oem") or {}).keys())[:1] or ""
    if isinstance(vendor, list):
        vendor = vendor[0] if vendor else ""
    systems = _members(got["systems"])
    if not systems:
        raise BmcError("the BMC exposes no computer systems")
    chassis = [] if isinstance(got["chassis"], Exception) \
        else _members(got["chassis"])
    found = (vendor, systems[0], chassis[0] if chassis else "")
    _paths[_where(conn)] = found
    return found


def _fresh(conn: dict, key: str, detail: bool) -> dict:
    known = _paths.get(_where(conn))
    if known:
        try:
            return _read(conn, key, detail, *known)
        except BmcError as e:
            # only a path that is gone is looked up again: anything else (a
            # refused password, a BMC that does not answer) would only be met
            # a second time, and an unreachable box waited out twice
            if "not found" not in str(e):
                raise
            _paths.pop(_where(conn), None)
    return _read(conn, key, detail, *_discover(conn))


def _read(conn: dict, key: str, detail: bool, vendor: str, system: str,
          chassis: str) -> dict:
    calls = {"system": lambda: _get(conn, system)}
    if chassis:
        calls["thermal"] = lambda: _get(conn, chassis + "/Thermal")
        calls["power"] = lambda: _get(conn, chassis + "/Power")
    if detail:
        calls["fw"] = lambda: _firmware_list(conn)
    dell = "dell" in (vendor or "").lower()
    seen = _os_seen.get(key)
    if dell and not (seen and time.time() - seen[0] < OS_TTL):
        calls["os"] = lambda: _dell_os(conn)
    more = _together(calls)
    if isinstance(more["system"], Exception):
        raise more["system"]
    sysd = more["system"]
    got = more
    if isinstance(more.get("os"), dict):
        seen = _os_seen[key] = (time.time(), more["os"])
    # an OS read that failed keeps what the last one found
    host_os = (seen[1] if seen else {}) if dell else _hpe_os(sysd)

    out = {
        "vendor": vendor or sysd.get("Manufacturer", ""),
        "model": sysd.get("Model", ""),
        "serial": sysd.get("SerialNumber", ""),
        "sku": sysd.get("SKU", ""),
        # the SMBIOS UUID: what the hypervisor installed on this box reports
        # as its own, and how app/chain.py knows which host runs here
        "uuid": sysd.get("UUID", ""),
        "hostname": _text(sysd.get("HostName"), 253) or host_os.get("hostname", ""),
        # what the OS's agent told the BMC (see the module note); "" = unknown
        "os": host_os.get("label", ""), "os_name": host_os.get("name", ""),
        "os_version": host_os.get("version", ""),
        "power": sysd.get("PowerState", ""),
        "health": _health(sysd) or "",
        "bios": sysd.get("BiosVersion", ""),
        "cpu_count": ((sysd.get("ProcessorSummary") or {}).get("Count")),
        "cpu_model": ((sysd.get("ProcessorSummary") or {}).get("Model") or ""),
        "memory_gib": ((sysd.get("MemorySummary") or {})
                       .get("TotalSystemMemoryGiB")),
        "leds": sysd.get("IndicatorLED", ""),
        "sensors": [], "fans": [], "psus": [], "firmware": [],
        "url": conn["base_url"].rstrip("/"),
    }

    # thermals and power: optional in the standard, so absence is not an error
    if chassis:
        th = more.get("thermal")
        if isinstance(th, dict):
            out["sensors"] = [
                {"name": t.get("Name", ""), "reading": t.get("ReadingCelsius"),
                 "limit": t.get("UpperThresholdCritical"),
                 "health": _health(t)}
                for t in th.get("Temperatures") or []
                if t.get("ReadingCelsius") is not None]
            out["fans"] = [
                {"name": f.get("Name", ""),
                 "reading": f.get("Reading"), "units": f.get("ReadingUnits", ""),
                 "health": _health(f)}
                for f in th.get("Fans") or []]
        pw = more.get("power")
        if isinstance(pw, dict):
            out["psus"] = [
                {"name": p.get("Name", ""), "state": (p.get("Status") or {})
                 .get("State", ""), "health": _health(p),
                 "watts": p.get("LastPowerOutputWatts"),
                 "model": p.get("Model", "")}
                for p in pw.get("PowerSupplies") or []]
            out["watts"] = ((pw.get("PowerControl") or [{}])[0]
                            .get("PowerConsumedWatts"))
    if detail and isinstance(got.get("fw"), list):
        out["firmware"] = got["fw"]

    hottest = max((s["reading"] for s in out["sensors"]
                   if isinstance(s["reading"], (int, float))), default=None)
    out["hottest"] = hottest
    out["ok"] = (out["health"] or "OK").upper() in ("OK", "")
    _cache[key] = (time.time(), out, detail)
    return out


def _firmware_list(conn: dict) -> list[dict]:
    """The firmware inventory: one request when the BMC can expand the
    collection (Redfish $expand, which iDRAC 9 serves), otherwise the members
    a few at a time. Never raises: firmware is optional, as before."""
    path = "/redfish/v1/UpdateService/FirmwareInventory"
    docs: list = []
    try:
        expanded = _get(conn, path + "?$expand=*($levels=1)")
        docs = [m for m in expanded.get("Members") or [] if "Version" in m]
        refs = [] if docs else _members(expanded)
    except BmcError:
        try:
            refs = _members(_get(conn, path))
        except BmcError:
            return []
    refs = refs[:25]
    for i in range(0, len(refs), FW_WORKERS):
        batch = _together({r: (lambda r=r: _get(conn, r))
                           for r in refs[i:i + FW_WORKERS]})
        docs += [batch[r] for r in refs[i:i + FW_WORKERS]
                 if isinstance(batch[r], dict)]
    return [{"name": d.get("Name", ""), "version": d.get("Version", "")}
            for d in docs[:25] if d.get("Version")]


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = read(conn, refresh=True)
    except BmcError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    bits = [f"ok: {got['vendor']} {got['model']}".strip()]
    if got["serial"]:
        bits.append(f"serial {got['serial']}")
    if got["power"]:
        bits.append(got["power"].lower())
    if got["health"]:
        bits.append(f"health {got['health']}")
    return True, " · ".join(bits)
