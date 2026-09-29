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
    * vCenter / ESXi: the REST API issues a session id for basic credentials,
      which this then reuses until it expires. Standalone ESXi 7.0+ serves enough
      of the same API for the host and its VMs.
"""
import base64
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
        "note": "Uses the vSphere REST API: hosts, VMs, power state and "
                "assigned resources. Works against vCenter, and against a "
                "standalone ESXi 7.0+ host for that host's own VMs.",
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


def _req(url: str, c: dict, headers: dict | None = None, data: bytes | None = None,
         method: str = ""):
    h = {"Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(urlguard.check(url), data=data, headers=h,
                                 method=method or ("POST" if data is not None
                                                   else "GET"))
    ctx = _INSECURE if c.get("skip_tls") else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
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
                    "name": g.get("name") or str(g.get("vmid", "")),
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
                    "url": f"{base}/#v1:0:={kind}%2F{g.get('vmid', '')}",
                })
    return {"hosts": hosts, "guests": guests, "kind": "Proxmox"}


# ── vCenter / ESXi ─────────────────────────────────────────────
def _vsphere_session(c: dict) -> str:
    key = f"vsession::{c.get('id')}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 1500:
        return hit[1]
    base = c["base_url"].rstrip("/")
    cred = base64.b64encode(f"{c['username']}:{c['token']}".encode()).decode()
    doc = _req(f"{base}/api/session", c, {"Authorization": f"Basic {cred}"},
               data=b"")
    sid = doc if isinstance(doc, str) else (doc.get("value") or "")
    if not sid:
        raise VirtError("vCenter accepted the login but returned no session id")
    _cache[key] = (time.time(), sid)
    return sid


def _vsphere(c: dict) -> dict:
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


_IMPL = {"proxmox": _proxmox, "vsphere": _vsphere}


def read(conn: dict, refresh: bool = False) -> dict:
    fn = _IMPL.get(conn.get("type"))
    if not fn:
        raise VirtError(f"unknown hypervisor '{conn.get('type')}'")
    key = f"read::{conn.get('id')}"
    hit = _cache.get(key)
    if hit and not refresh and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
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
