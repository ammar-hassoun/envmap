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
import json
import ssl
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


def invalidate() -> None:
    _cache.clear()


def _get(c: dict, path: str):
    url = c["base_url"].rstrip("/") + path
    h = {"Accept": "application/json",
         "Authorization": "Basic " + base64.b64encode(
             f"{c.get('username','')}:{c.get('token','')}".encode()).decode()}
    req = urllib.request.Request(urlguard.check(url), headers=h)
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
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


def read(conn: dict, refresh: bool = False) -> dict:
    """Everything the page shows for one BMC, in as few round trips as a BMC
    allows (they are slow, so this is cached for CACHE_TTL)."""
    key = conn.get("id") or conn.get("base_url", "")
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]

    root = _get(conn, "/redfish/v1")
    vendor = root.get("Vendor") or root.get("Oem") and list(
        (root.get("Oem") or {}).keys())[:1] or ""
    if isinstance(vendor, list):
        vendor = vendor[0] if vendor else ""

    systems = _members(_get(conn, "/redfish/v1/Systems"))
    if not systems:
        raise BmcError("the BMC exposes no computer systems")
    sysd = _get(conn, systems[0].replace("/redfish/v1", "/redfish/v1"))

    out = {
        "vendor": vendor or sysd.get("Manufacturer", ""),
        "model": sysd.get("Model", ""),
        "serial": sysd.get("SerialNumber", ""),
        "sku": sysd.get("SKU", ""),
        "hostname": sysd.get("HostName", ""),
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
    chassis = _members(_get(conn, "/redfish/v1/Chassis"))
    if chassis:
        try:
            th = _get(conn, chassis[0] + "/Thermal")
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
        except BmcError:
            pass
        try:
            pw = _get(conn, chassis[0] + "/Power")
            out["psus"] = [
                {"name": p.get("Name", ""), "state": (p.get("Status") or {})
                 .get("State", ""), "health": _health(p),
                 "watts": p.get("LastPowerOutputWatts"),
                 "model": p.get("Model", "")}
                for p in pw.get("PowerSupplies") or []]
            out["watts"] = ((pw.get("PowerControl") or [{}])[0]
                            .get("PowerConsumedWatts"))
        except BmcError:
            pass
    try:
        fw = _get(conn, "/redfish/v1/UpdateService/FirmwareInventory")
        for ref in _members(fw)[:25]:
            d = _get(conn, ref)
            if d.get("Version"):
                out["firmware"].append({"name": d.get("Name", ""),
                                        "version": d.get("Version", "")})
    except BmcError:
        pass

    hottest = max((s["reading"] for s in out["sensors"]
                   if isinstance(s["reading"], (int, float))), default=None)
    out["hottest"] = hottest
    out["ok"] = (out["health"] or "OK").upper() in ("OK", "")
    _cache[key] = (time.time(), out)
    return out


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
