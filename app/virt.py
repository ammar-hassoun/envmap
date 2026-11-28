"""Hypervisors: Proxmox VE, vCenter and standalone ESXi.

WHY IT MATTERS TO A KUBERNETES PORTAL
    Almost every cluster in a self-hosted estate runs on virtual machines
    somebody has to manage, and the layer underneath is where "the node went
    away" is explained. The portal already knows the clusters and the inventory;
    this closes the gap between a Kubernetes node and the host it actually lives
    on.

READ-ONLY, AND FOR THE SAME REASON AS EVERYTHING ELSE
    No start, stop, migrate or snapshot. Both tools have their own consoles with
    their own permissions and audit trails; a stop button here would be a second
    unaudited path to shutting down production.

AUTH, PER TOOL
    * Proxmox: an API token (User → API Tokens) sent as a PVEAPIToken header. No
      session, no ticket, no CSRF dance — which is why a token is preferred over
      a password here.
    * vCenter: the REST API (/api) issues a session id for basic credentials,
      which this then reuses until it expires.
    * Standalone ESXi: the same URL field, but a different API. ESXi does not
      serve the REST API at all — its /api answers 400 "Unsupported content
      type" to the login and 503 "upstream connect error" with a JSON one,
      whatever the password — so it is read through the vSphere Web Services
      (SOAP) API at /sdk, the one the ESXi Host Client and every vSphere SDK
      use. /sdk answers without logging in to say which kind of server it is
      (about.apiType: "HostAgent" for ESXi, "VirtualCenter" for vCenter), and
      that decides the path. Until 0.7.63 the page promised standalone ESXi
      and the code only spoke vCenter, so every ESXi connection showed
      "HTTP 400" with the right password.
"""
import base64
import hashlib
import json
import ssl
import threading
import time
from xml.sax.saxutils import escape as _xml

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
CACHE_TTL = 60

PROVIDERS = {
    "proxmox": {
        "label": "Proxmox VE",
        "icon": "🧱",
        "url_hint": "https://pve.example.com:8006",
        "needs": ["base_url", "username", "token"],
        "auth": "an API token: username is user@realm!tokenid, secret is the "
                "token's value (Datacenter → Permissions → API Tokens)",
        "fields": {"base_url": "Proxmox URL (port 8006)",
                   "username": "user@realm!tokenid",
                   "token": "Token secret"},
        "note": "Reads the cluster's nodes and every VM and container on them, "
                "with CPU, memory and uptime. A token with PVEAuditor is "
                "enough. Proxmox certificates are usually self-signed, so "
                "expect to tick “skip TLS verification”.",
    },
    "vsphere": {
        "label": "vCenter / ESXi",
        "icon": "🟦",
        "url_hint": "https://vcenter.example.com",
        "needs": ["base_url", "username", "token"],
        "auth": "a read-only vSphere account (username and password)",
        "fields": {"base_url": "vCenter / ESXi URL",
                   "username": "Username", "token": "Password"},
        "note": "Works against vCenter (its REST API: hosts, VMs, power state "
                "and assigned resources) and against a standalone ESXi host "
                "(its own API at /sdk: the host with CPU, memory and uptime, "
                "and its VMs with power state, usage and disk). The URL is "
                "the host's own address, e.g. https://10.0.0.5; root or a "
                "local user with the Read-only role is enough.",
    },
}


class VirtError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

_cache: dict = {}


def invalidate() -> None:
    _cache.clear()


def forget(conn: dict) -> None:
    """Drop one connection's cached read, so the next look after a change
    shows the change rather than the minute-old answer."""
    _cache.pop(f"read::{_who(conn)}", None)


def store_all() -> list[dict]:
    from . import store
    return store.all_virt()


def _req(url: str, c: dict, headers: dict | None = None, data: bytes | None = None,
         method: str = ""):
    h = {"Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method=method or ("POST" if data is not None
                                                   else "GET"))
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urlguard.urlopen(req, timeout=TIMEOUT, context=ctx, cross_host="refuse") as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise VirtError("authentication rejected — check the credentials "
                            "and the account's role") from e
        if e.code == 404:
            raise VirtError("not found (404) — check the URL and port") from e
        raise VirtError(f"HTTP {e.code}") from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason:
            raise VirtError("the certificate is not trusted — tick “skip TLS "
                            "verification” if this host uses a self-signed "
                            "certificate") from e
        raise VirtError(f"cannot reach the host: {reason}") from e
    except json.JSONDecodeError as e:
        raise VirtError("answered, but not with JSON — check the URL and port "
                        "(Proxmox is 8006)") from e


def _pct(used, total) -> float | None:
    try:
        return round(float(used) / float(total) * 100, 1) if total else None
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _secs(seconds) -> int:
    """Uptime as a number, for sorting the guest list: the text is "3d 4h"."""
    try:
        return max(int(seconds or 0), 0)
    except (TypeError, ValueError):
        return 0


def _uptime(seconds) -> str:
    try:
        s = int(seconds or 0)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    d, rem = divmod(s, 86400)
    h = rem // 3600
    return f"{d}d {h}h" if d else f"{h}h"


# ── Proxmox ────────────────────────────────────────────────────
def _proxmox(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    h = {"Authorization": f"PVEAPIToken={c['username']}={c['token']}"}
    nodes_doc = _req(f"{base}/api2/json/nodes", c, h)
    hosts, guests = [], []
    for n in nodes_doc.get("data") or []:
        name = n.get("node", "")
        hosts.append({
            "name": name,
            "state": n.get("status", ""),
            "cpu_pct": round((n.get("cpu") or 0) * 100, 1),
            "cores": n.get("maxcpu"),
            "mem_pct": _pct(n.get("mem"), n.get("maxmem")),
            "mem_gib": round((n.get("maxmem") or 0) / 1024**3, 1),
            "uptime": _uptime(n.get("uptime")),
            "extra": n.get("level", "") or "",
            "url": f"{base}/#v1:0:=node%2F{urllib.parse.quote(name)}",
        })
        for kind, path in (("qemu", "qemu"), ("lxc", "lxc")):
            try:
                doc = _req(f"{base}/api2/json/nodes/{urllib.parse.quote(name)}"
                           f"/{path}", c, h)
            except VirtError:
                continue
            for g in doc.get("data") or []:
                guests.append({
                    # an unnamed guest reads as the VM page names it, and as
                    # a production change must be confirmed (virtops.vm_name)
                    "name": g.get("name") or f"{kind}-{g.get('vmid', '')}",
                    "id": str(g.get("vmid", "")),
                    "host": name,
                    "kind": "VM" if kind == "qemu" else "container",
                    "state": g.get("status", ""),
                    "cpu_pct": round((g.get("cpu") or 0) * 100, 1),
                    "cores": g.get("cpus"),
                    "mem_gib": round((g.get("maxmem") or 0) / 1024**3, 1),
                    "mem_pct": _pct(g.get("mem"), g.get("maxmem")),
                    "disk_gib": round((g.get("maxdisk") or 0) / 1024**3, 1),
                    "uptime": _uptime(g.get("uptime")),
                    "uptime_s": _secs(g.get("uptime")),
                    "url": f"{base}/#v1:0:={kind}%2F{g.get('vmid', '')}",
                })
    return {"hosts": hosts, "guests": guests, "kind": "Proxmox"}


# ── vCenter / ESXi ─────────────────────────────────────────────
SESSION_TTL = 1500


def _who(c: dict) -> str:
    """The cache key for a login: the connection AND what it logs in with, so
    an edited URL, username or password is never answered from the session
    the old ones opened. Hashed, so no password sits in the key."""
    raw = "\0".join(str(c.get(k) or "") for k in
                    ("id", "base_url", "username", "token", "skip_tls"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _vsphere_session(c: dict) -> str:
    key = f"vsession::{_who(c)}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < SESSION_TTL:
        return hit[1]
    base = c["base_url"].rstrip("/")
    cred = base64.b64encode(f"{c['username']}:{c['token']}".encode()).decode()
    # an explicit JSON type: with a body and no type, urllib sends
    # application/x-www-form-urlencoded, which the vSphere API front end is
    # entitled to refuse (ESXi's does, with a 400)
    doc = _req(f"{base}/api/session", c, {"Authorization": f"Basic {cred}",
                                          "Content-Type": "application/json"},
               data=b"")
    sid = doc if isinstance(doc, str) else (doc.get("value") or "")
    if not sid:
        raise VirtError("vCenter accepted the login but returned no session id")
    _cache[key] = (time.time(), sid)
    return sid


# ── standalone ESXi: the vSphere Web Services (SOAP) API at /sdk ──
SOAP_MAX = 32 * 1024 * 1024
_NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
_HOST_PATHS = ("name", "runtime.connectionState", "runtime.powerState",
               "summary.hardware.numCpuCores", "summary.hardware.cpuMhz",
               "summary.hardware.memorySize",
               "summary.quickStats.overallCpuUsage",
               "summary.quickStats.overallMemoryUsage",
               "summary.quickStats.uptime", "summary.config.product.fullName")
# Identity, for app/chain.py: which physical server a host is, and which
# Kubernetes node a VM is (config.uuid is the SMBIOS UUID its kernel reports).
# Asked for in the same read; a host too old to know one of them (the serial
# arrived in 6.7) answers InvalidProperty, and the read is made again without.
_HOST_ID = ("hardware.systemInfo.uuid", "hardware.systemInfo.serialNumber",
            "summary.hardware.vendor", "summary.hardware.model")
_VM_ID = ("config.uuid", "guest.ipAddress", "guest.hostName")
_NO_ID: set = set()
_VM_PATHS = ("name", "runtime.powerState", "runtime.host",
             "summary.config.numCpu", "summary.config.memorySizeMB",
             "summary.config.template", "summary.runtime.maxCpuUsage",
             "summary.quickStats.overallCpuUsage",
             "summary.quickStats.guestMemoryUsage",
             "summary.quickStats.uptimeSeconds", "summary.storage.committed")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _kids(el, name: str) -> list:
    return [k for k in list(el) if _local(k.tag) == name]


def _kid(el, name: str):
    found = _kids(el, name) if el is not None else []
    return found[0] if found else None


def _text(el, name: str) -> str:
    k = _kid(el, name)
    return (k.text or "").strip() if k is not None else ""


def _num(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _parse_xml(raw: bytes):
    """defusedxml, because the answer comes from whatever the URL points at:
    a DTD or entity in it is refused rather than expanded."""
    import defusedxml.ElementTree as ET
    try:
        return ET.fromstring(raw)
    except Exception as e:                                    # noqa: BLE001
        raise VirtError("answered, but not with the vSphere API — check the "
                        "URL (the ESXi host or vCenter address, no path)") from e


def _soap_fault(root) -> tuple[str, str, str]:
    """(the fault's type, its message, the privilege a NoPermission names)."""
    body = _kid(root, "Body")
    fault = _kid(body, "Fault") if body is not None else None
    if fault is None:
        return "", "", ""
    detail = _kid(fault, "detail")
    kind = _local(list(detail)[0].tag) if detail is not None and len(detail) else ""
    priv = next(((x.text or "").strip() for x in fault.iter()
                 if _local(x.tag) == "privilegeId"), "")
    return kind, _text(fault, "faultstring"), priv


def _soap(c: dict, ver: str, inner: str, cookie: str = "",
          timeout: float = 0) -> tuple:
    """One SOAP call to <base>/sdk: (the response's returnval parent, the
    session cookie the server set, if any)."""
    url = c["base_url"].rstrip("/") + "/sdk"
    env = ('<?xml version="1.0" encoding="UTF-8"?>'
           f'<soapenv:Envelope xmlns:soapenv="{_NS_SOAP}" '
           'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
           'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
           f'<soapenv:Body>{inner}</soapenv:Body></soapenv:Envelope>')
    h = {"Content-Type": "text/xml; charset=utf-8",
         "SOAPAction": f'"urn:vim25/{ver}"'}
    if cookie:
        h["Cookie"] = cookie
    req = urllib.request.Request(urlguard.check(url), data=env.encode(),
                                 headers=h, method="POST")
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urlguard.urlopen(req, timeout=timeout or TIMEOUT,
                                    context=ctx, cross_host="refuse") as r:
            raw, set_cookie = r.read(SOAP_MAX), r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        raw = e.read(SOAP_MAX) if e.code == 500 else b""
        if not raw:
            if e.code in (401, 403):
                raise VirtError("authentication rejected — check the "
                                "credentials and the account's role") from e
            if e.code == 404:
                raise VirtError("not found (404) — check the URL and port") from e
            raise VirtError(f"HTTP {e.code}") from e
        kind, msg, priv = _soap_fault(_parse_xml(raw))
        raise _fault_error(kind, msg or f"HTTP {e.code}", priv) from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason:
            raise VirtError("the certificate is not trusted — tick “skip TLS "
                            "verification” if this host uses a self-signed "
                            "certificate") from e
        raise VirtError(f"cannot reach the host: {reason}") from e
    root = _parse_xml(raw)
    kind, msg, priv = _soap_fault(root)
    if kind or msg:
        raise _fault_error(kind, msg, priv)
    body = _kid(root, "Body")
    resp = list(body)[0] if body is not None and len(body) else None
    if resp is None:
        raise VirtError("answered, but not with the vSphere API — check the URL")
    return resp, set_cookie.split(";", 1)[0].strip()


class _NotAuthenticated(VirtError):
    pass


class _NoPermission(VirtError):
    pass


def _fault_error(kind: str, msg: str, priv: str = "") -> VirtError:
    if kind.startswith("InvalidLogin"):
        err = VirtError("authentication rejected — check the credentials and "
                        "the account's role")
    elif kind.startswith("NotAuthenticated"):
        err = _NotAuthenticated("the session expired")
    elif kind.startswith("NoPermission") and priv and priv != "System.View":
        # a change the account may not make: name the privilege it lacks, which
        # is what the ESXi administrator needs to grant
        err = _NoPermission(f"the account is not allowed to do this on the "
                            f"host (it lacks the vSphere privilege {priv})")
    elif kind.startswith("NoPermission"):
        err = _NoPermission("the account has no permission to read this host "
                            "— give it the Read-only role (Host Client: Host "
                            "→ Actions → Permissions)")
    else:
        err = VirtError(f"vSphere refused the request: {(msg or kind)[:240]}")
    err.fault = kind.removesuffix("Fault")
    return err


def _moref(el, name: str, kind: str) -> str:
    return f'<{name} type="{kind}">{_xml(el)}</{name}>'


def _service(c: dict) -> dict:
    """What /sdk says it is, asked without logging in, and remembered for an
    hour per URL: apiType, version and the managed-object ids every later
    call is addressed to. {} when /sdk is not a vSphere SOAP endpoint."""
    key = f"vservice::{c.get('base_url')}::{bool(c.get('skip_tls'))}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    try:
        resp, _ = _soap(c, "6.5", '<RetrieveServiceContent xmlns="urn:vim25">'
                        '<_this type="ServiceInstance">ServiceInstance</_this>'
                        '</RetrieveServiceContent>')
    except VirtError as e:
        if str(e).startswith(("cannot reach", "the certificate")):
            raise
        _cache[key] = (time.time(), {})
        return {}
    rv = _kid(resp, "returnval")
    about = _kid(rv, "about")
    got = {"apiType": _text(about, "apiType"),
           "version": _text(about, "apiVersion") or "6.5",
           "fullName": _text(about, "fullName"),
           "rootFolder": _text(rv, "rootFolder"),
           "propertyCollector": _text(rv, "propertyCollector"),
           "viewManager": _text(rv, "viewManager"),
           "sessionManager": _text(rv, "sessionManager")}
    _cache[key] = (time.time(), got)
    return got


def _esxi_login(c: dict, svc: dict) -> str:
    key = f"vsoap::{_who(c)}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < SESSION_TTL:
        return hit[1]
    try:
        _, cookie = _soap(c, svc["version"],
                          '<Login xmlns="urn:vim25">'
                          + _moref(svc["sessionManager"], "_this",
                                   "SessionManager")
                          + f"<userName>{_xml(c.get('username') or '')}"
                          "</userName>"
                          + f"<password>{_xml(c.get('token') or '')}</password>"
                          + "</Login>")
    except _NoPermission as e:
        # ESXi's answer when the password is right but the account may not
        # sign in: it has no role on the host ("No access"), or the host is
        # in lockdown mode and the account is not an exception user. Seen on
        # the first real host this ran against, 24 November 2026.
        raise VirtError("ESXi accepted the password but refused this account: "
                        "it has no role on the host, or the host is in "
                        "lockdown mode — give it the Read-only role (Host "
                        "Client: Host → Actions → Permissions) or use root"
                        ) from e
    if not cookie:
        raise VirtError("ESXi accepted the login but set no session cookie")
    _cache[key] = (time.time(), cookie)
    return cookie


def _esxi_objects(c: dict, svc: dict, cookie: str, host_paths=None,
                  vm_paths=None) -> list[tuple]:
    """Every HostSystem and VirtualMachine under the root folder with the
    properties above, as (type, moid, {path: text})."""
    host_paths = _HOST_PATHS if host_paths is None else host_paths
    vm_paths = _VM_PATHS if vm_paths is None else vm_paths
    ver = svc["version"]
    resp, _ = _soap(c, ver, '<CreateContainerView xmlns="urn:vim25">'
                    + _moref(svc["viewManager"], "_this", "ViewManager")
                    + _moref(svc["rootFolder"], "container", "Folder")
                    + "<type>HostSystem</type><type>VirtualMachine</type>"
                    "<recursive>true</recursive></CreateContainerView>", cookie)
    view = _text(resp, "returnval")
    pc = _moref(svc["propertyCollector"], "_this", "PropertyCollector")
    spec = ("<specSet>"
            + "<propSet><type>HostSystem</type>"
            + "".join(f"<pathSet>{p}</pathSet>" for p in host_paths)
            + "</propSet><propSet><type>VirtualMachine</type>"
            + "".join(f"<pathSet>{p}</pathSet>" for p in vm_paths)
            + "</propSet><objectSet>" + _moref(view, "obj", "ContainerView")
            + "<skip>true</skip><selectSet xsi:type=\"TraversalSpec\">"
            "<name>view</name><type>ContainerView</type><path>view</path>"
            "<skip>false</skip></selectSet></objectSet></specSet>")
    out: list[tuple] = []
    try:
        resp, _ = _soap(c, ver, '<RetrievePropertiesEx xmlns="urn:vim25">' + pc
                        + spec + "<options><maxObjects>500</maxObjects>"
                        "</options></RetrievePropertiesEx>", cookie)
        for _page in range(200):
            rv = _kid(resp, "returnval")
            if rv is None:
                break
            for o in _kids(rv, "objects"):
                obj = _kid(o, "obj")
                props = {_text(p, "name"): _text(p, "val")
                         for p in _kids(o, "propSet")}
                out.append((obj.get("type", "") if obj is not None else "",
                            (obj.text or "").strip() if obj is not None else "",
                            props))
            token = _text(rv, "token")
            if not token:
                break
            resp, _ = _soap(c, ver, '<ContinueRetrievePropertiesEx '
                            'xmlns="urn:vim25">' + pc
                            + f"<token>{_xml(token)}</token>"
                            "</ContinueRetrievePropertiesEx>", cookie)
    finally:
        try:
            _soap(c, ver, '<DestroyView xmlns="urn:vim25">'
                  + _moref(view, "_this", "ContainerView") + "</DestroyView>",
                  cookie)
        except VirtError:
            pass
    return out


def _esxi(c: dict, svc: dict) -> dict:
    base = c["base_url"].rstrip("/")
    cookie = _esxi_login(c, svc)
    who = _who(c)

    def objects(ck):
        if who not in _NO_ID:
            try:
                return _esxi_objects(c, svc, ck, _HOST_PATHS + _HOST_ID, _VM_PATHS + _VM_ID)
            except VirtError as e:
                if not str(getattr(e, "fault", "")).startswith("InvalidProperty"):
                    raise
                _NO_ID.add(who)          # an older host: never ask it again
        return _esxi_objects(c, svc, ck)
    try:
        objs = objects(cookie)
    except _NotAuthenticated:
        # the host forgot the session (restart, idle timeout): log in again once
        _cache.pop(f"vsoap::{who}", None)
        objs = objects(_esxi_login(c, svc))
    hosts, guests, names = [], [], {}
    for kind, moid, p in objs:
        if kind != "HostSystem":
            continue
        cores, mhz = _num(p.get("summary.hardware.numCpuCores")), \
            _num(p.get("summary.hardware.cpuMhz"))
        mem = _num(p.get("summary.hardware.memorySize"))
        used_mb = _num(p.get("summary.quickStats.overallMemoryUsage"))
        names[moid] = p.get("name", "") or moid
        hosts.append({
            "name": names[moid],
            "state": p.get("runtime.connectionState", ""),
            "cpu_pct": _pct(p.get("summary.quickStats.overallCpuUsage"),
                            (cores or 0) * (mhz or 0)),
            "cores": cores,
            "mem_pct": _pct((used_mb or 0) * 1024**2, mem) if used_mb is not None
            else None,
            "mem_gib": round((mem or 0) / 1024**3, 1),
            "uptime": _uptime(p.get("summary.quickStats.uptime")),
            "extra": p.get("summary.config.product.fullName", "")
            or svc.get("fullName", ""),
            "url": f"{base}/ui/#/host",
            "uuid": p.get("hardware.systemInfo.uuid", ""),
            "serial": p.get("hardware.systemInfo.serialNumber", ""),
            "vendor": p.get("summary.hardware.vendor", ""),
            "model": p.get("summary.hardware.model", ""),
        })
    for kind, moid, p in objs:
        if kind != "VirtualMachine":
            continue
        mem_mb = _num(p.get("summary.config.memorySizeMB"))
        state = {"poweredon": "On", "poweredoff": "Off",
                 "suspended": "Suspended"}.get(
            (p.get("runtime.powerState") or "").lower(),
            p.get("runtime.powerState", ""))
        committed = _num(p.get("summary.storage.committed"))
        guests.append({
            "name": p.get("name", "") or moid, "id": moid,
            "host": names.get(p.get("runtime.host", ""), ""),
            "kind": "template" if p.get("summary.config.template") == "true"
            else "VM",
            "state": state,
            "cpu_pct": _pct(p.get("summary.quickStats.overallCpuUsage"),
                            p.get("summary.runtime.maxCpuUsage"))
            if state == "On" else None,
            "cores": _num(p.get("summary.config.numCpu")),
            "mem_gib": round((mem_mb or 0) / 1024, 1),
            "mem_pct": _pct(p.get("summary.quickStats.guestMemoryUsage"), mem_mb)
            if state == "On" else None,
            "disk_gib": round(committed / 1024**3, 1) if committed else None,
            "uptime": _uptime(p.get("summary.quickStats.uptimeSeconds")),
            "uptime_s": _secs(p.get("summary.quickStats.uptimeSeconds")),
            "url": f"{base}/ui/#/host/vms/{urllib.parse.quote(moid)}",
            "uuid": p.get("config.uuid", ""),
            "ip": p.get("guest.ipAddress", ""),
            "guest_host": p.get("guest.hostName", ""),
        })
    return {"hosts": hosts, "guests": guests, "kind": "ESXi"}


def _vsphere(c: dict) -> dict:
    svc = _service(c)
    if svc.get("apiType") == "HostAgent":
        return _esxi(c, svc)
    return _vcenter(c)


def _vcenter(c: dict) -> dict:
    base = c["base_url"].rstrip("/")
    sid = _vsphere_session(c)
    h = {"vmware-api-session-id": sid}
    hosts, guests = [], []
    try:
        for host in _req(f"{base}/api/vcenter/host", c, h) or []:
            hosts.append({"name": host.get("name", ""),
                          "state": host.get("connection_state", ""),
                          "cpu_pct": None, "cores": None, "mem_pct": None,
                          "mem_gib": None,
                          "uptime": "", "extra": host.get("power_state", ""),
                          "url": base})
    except VirtError:
        # a standalone ESXi host does not serve /vcenter/host; its VMs still list
        pass
    for vm in _req(f"{base}/api/vcenter/vm", c, h) or []:
        guests.append({
            "name": vm.get("name", ""), "id": vm.get("vm", ""),
            "host": "", "kind": "VM",
            "state": (vm.get("power_state") or "").replace("POWERED_", "").title(),
            "cpu_pct": None, "cores": vm.get("cpu_count"),
            "mem_gib": round((vm.get("memory_size_MiB") or 0) / 1024, 1),
            "mem_pct": None, "disk_gib": None, "uptime": "",
            "url": f"{base}/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:"
                   f"{vm.get('vm', '')}/summary",
        })
    return {"hosts": hosts, "guests": guests, "kind": "vSphere"}


# ── identity, for app/chain.py ─────────────────────────────────
# A standalone ESXi host's list read already carries it (_HOST_ID, _VM_ID).
# Two kinds do not: a vCenter, whose list comes from the REST API, and
# Proxmox, where a VM's SMBIOS UUID sits in its config. Read on their own,
# slowly changing, kept IDENT_TTL.
IDENT_TTL = 600
_ident: dict = {}


def identities(conn: dict) -> dict:
    """{"hosts": {name: {uuid, serial, vendor, model}},
        "vms": {id: {uuid, ip, guest_host, host}}} — what is known, empty where
    nothing is. Never raises: identity only adds links, it never breaks a
    page. A failed read is kept for half a minute, not ten: a vCenter that
    blinked must not leave its VMs unjoined, or joined by weaker clues, for
    the next ten minutes."""
    key = f"ident::{_who(conn)}"
    hit = _ident.get(key)
    if hit and time.time() - hit[0] < hit[2]:
        return hit[1]
    out: dict = {"hosts": {}, "vms": {}}
    ttl = IDENT_TTL
    try:
        if conn.get("type") == "vsphere":
            svc = _service(conn)
            if svc.get("apiType") == "VirtualCenter":
                paths = (("name",) + _HOST_ID, ("name", "runtime.host") + _VM_ID)
                try:
                    objs = _esxi_objects(conn, svc, _esxi_login(conn, svc), *paths)
                except _NotAuthenticated:
                    _cache.pop(f"vsoap::{_who(conn)}", None)
                    objs = _esxi_objects(conn, svc, _esxi_login(conn, svc), *paths)
                names = {moid: p.get("name", "") or moid
                         for kind, moid, p in objs if kind == "HostSystem"}
                for kind, moid, p in objs:
                    if kind == "HostSystem":
                        out["hosts"][names[moid]] = {
                            "uuid": p.get("hardware.systemInfo.uuid", ""),
                            "serial": p.get("hardware.systemInfo.serialNumber", ""),
                            "vendor": p.get("summary.hardware.vendor", ""),
                            "model": p.get("summary.hardware.model", "")}
                    elif kind == "VirtualMachine":
                        # which host runs it: the REST list a vCenter page
                        # is read from does not say
                        out["vms"][moid] = {"uuid": p.get("config.uuid", ""),
                                            "ip": p.get("guest.ipAddress", ""),
                                            "guest_host": p.get("guest.hostName", ""),
                                            "host": names.get(p.get("runtime.host", ""), "")}
        elif conn.get("type") == "proxmox":
            out["vms"] = _pve_uuids(conn)
    except Exception:                                         # noqa: BLE001
        out, ttl = {"hosts": {}, "vms": {}}, 30
    _ident[key] = (time.time(), out, ttl)
    return out


def _pve_uuids(conn: dict) -> dict:
    """Each QEMU VM's SMBIOS UUID, from `smbios1: uuid=…` in its config: one
    request per VM, a few at a time, at most 400. A container has none."""
    base = conn["base_url"].rstrip("/")
    h = {"Authorization": f"PVEAPIToken={conn['username']}={conn['token']}"}
    vms = [(g["host"], g["id"]) for g in read(conn).get("guests") or []
           if g.get("kind") == "VM"][:400]

    def one(item):
        node, vmid = item
        try:
            cfg = (_req(f"{base}/api2/json/nodes/{urllib.parse.quote(node)}"
                        f"/qemu/{urllib.parse.quote(str(vmid))}/config", conn, h)
                   or {}).get("data") or {}
        except VirtError:
            return vmid, None
        smb = str(cfg.get("smbios1") or "")
        uuid = next((kv.split("=", 1)[1] for kv in smb.split(",")
                     if kv.startswith("uuid=")), "")
        return vmid, {"uuid": uuid, "ip": "", "guest_host": ""}
    from .fleet import _pmap
    return {vmid: got for vmid, got in (_pmap(one, vms, workers=6) or []) if got}


_IMPL = {"proxmox": _proxmox, "vsphere": _vsphere}


STALE_MAX = 900
_refreshing: set = set()
_guard = threading.Lock()


def read(conn: dict, refresh: bool = False) -> dict:
    """One connection's hosts and guests.

    Cached for CACHE_TTL; after that, for up to STALE_MAX, the last answer is
    returned at once and a fresh one is read behind the caller. Before this
    every look after the first minute read every hypervisor again, and with
    eight hosts the page outran its own first-paint deadline and reloaded to
    fill in (24 November 2026). Refresh reads now."""
    fn = _IMPL.get(conn.get("type"))
    if not fn:
        raise VirtError(f"unknown hypervisor '{conn.get('type')}'")
    key = f"read::{_who(conn)}"
    hit = _cache.get(key)
    if hit and not refresh:
        age = time.time() - hit[0]
        if age < CACHE_TTL:
            return hit[1]
        if age < STALE_MAX:
            _behind(key, fn, conn)
            return hit[1]
    return _fresh(key, fn, conn)


def _behind(key: str, fn, conn: dict) -> None:
    with _guard:
        if key in _refreshing:
            return
        _refreshing.add(key)

    def run():
        try:
            _fresh(key, fn, conn)
        except Exception:                                     # noqa: BLE001
            pass
        finally:
            with _guard:
                _refreshing.discard(key)

    threading.Thread(target=run, name="virt-refresh", daemon=True).start()


def _fresh(key: str, fn, conn: dict) -> dict:
    got = fn(conn)
    got["running"] = sum(1 for g in got["guests"]
                         if (g["state"] or "").lower() in ("running", "on", "poweredon"))
    got["stopped"] = len(got["guests"]) - got["running"]
    _cache[key] = (time.time(), got)
    return got


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = read(conn, refresh=True)
    except VirtError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    bits = [f"connected — {len(got['hosts'])} host(s)",
            f"{len(got['guests'])} guest(s)"]
    if got["stopped"]:
        bits.append(f"{got['stopped']} not running")
    return True, ", ".join(bits)
