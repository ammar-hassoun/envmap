"""Hypervisor management: the one place that decides who may change what on
which hypervisor, and then hands the change to the engine that speaks it
(esxiops for a standalone ESXi host, pveops for Proxmox VE).

THREE GATES, ALL OF THEM, EVERY TIME
    1. The connection opts in. A hypervisor connection is read-only until
       somebody with Settings ticks "Allow management from EnvMap" on it
       (`manage`). Existing connections stay as they were.
    2. The person holds the area. `virt_console` opens consoles, `virt_power`
       powers VMs and takes, reverts and deletes snapshots, `virt_admin` does
       everything else (and includes the other two). All three escalate, so
       only an administrator hands them out.
    3. Production asks for the name. On a connection marked `production`,
       every change and every console needs the VM's (or host's) name typed —
       checked here, on the server, not only in the page.
    A refusal at any gate is audited as `<action>_refused`.

WHY ONE DISPATCH TABLE
    Every action has an area, a target and an audit name. Writing them once,
    next to each other, is how a new action cannot ship without a permission:
    `ACTIONS` is the whole surface, and tests/test_virt_manage.py walks it.
"""
from __future__ import annotations

import secrets
import threading
import time

from . import esxiops, pveops, rbac, virt
from .virt import VirtError

AREAS = {"console": "virt_console", "power": "virt_power", "admin": "virt_admin"}
CONSOLE_TTL = 60
_consoles: dict = {}
_console_guard = threading.Lock()


class Refused(VirtError):
    """A gate said no; the message says which and how to open it."""


# ── what a connection is, and whether it may be managed ────────
def flavor(conn: dict) -> str:
    """esxi | proxmox | vcenter | "" (unknown or unreachable)."""
    if conn.get("type") == "proxmox":
        return "proxmox"
    if conn.get("type") == "vsphere":
        try:
            api = virt._service(conn).get("apiType")
        except VirtError:
            return ""
        return {"HostAgent": "esxi", "VirtualCenter": "vcenter"}.get(api, "")
    return ""


def manage_why(conn: dict) -> str:
    """"" when this connection may be managed at all, else why not."""
    if not conn.get("manage"):
        return ("this connection is read-only in EnvMap. To manage it, tick "
                "“Allow management from EnvMap” on it in Settings → Hypervisors")
    f = flavor(conn)
    if f == "vcenter":
        return ("management is for standalone ESXi hosts and Proxmox; this is "
                "a vCenter, which stays read-only")
    if f not in ("esxi", "proxmox"):
        return "the hypervisor is not answering, so it cannot be managed now"
    return ""


def may(user, need: str, pid: str | None = None) -> bool:
    """Whether this person holds the area for `need`; with `pid`, for a
    connection of that project too (a role confined to some projects
    manages only their connections, and a global one only when unconfined)."""
    if not user:
        return False

    def holds(area):
        return rbac.may_area(user, area) and (pid is None or rbac.may_project(user, pid, area))
    return holds(AREAS[need]) or (need in ("console", "power") and holds("virt_admin"))


def may_why(user, need: str, pid: str | None = None) -> str:
    if may(user, need, pid):
        return ""
    label = rbac.AREAS[AREAS[need]][0]
    if pid is not None and may(user, need):
        return f"your roles grant “{label}” for other projects, not this connection's"
    return f"your roles do not include “{label}”"


def capabilities(user, conn: dict) -> dict:
    """What the page may offer for this connection: {need: "" or why not}."""
    gate = manage_why(conn)
    pid = conn.get("pid") or ""
    return {need: gate or may_why(user, need, pid) for need in AREAS}


def find_conn(cid: str) -> dict | None:
    return next((c for c in virt.store_all() if c.get("id") == cid), None)


# ── the actions ────────────────────────────────────────────────
# name: (need, target, label for the audit and the page)
ACTIONS = {
    "vm.start": ("power", "vm", "start"),
    "vm.shutdown": ("power", "vm", "shut down"),
    "vm.reboot": ("power", "vm", "restart"),
    "vm.stop": ("power", "vm", "power off"),
    "vm.reset": ("power", "vm", "reset"),
    "vm.suspend": ("power", "vm", "suspend"),
    "vm.resume": ("power", "vm", "resume"),
    "vm.snapshot": ("power", "vm", "take a snapshot"),
    "vm.revert": ("power", "vm", "revert to a snapshot"),
    "vm.snapshot_delete": ("power", "vm", "delete a snapshot"),
    "vm.snapshot_delete_all": ("power", "vm", "delete every snapshot"),
    "vm.snapshot_rename": ("power", "vm", "rename a snapshot"),
    "vm.resources": ("admin", "vm", "change CPU, memory or notes"),
    "vm.boot": ("admin", "vm", "change boot options"),
    "vm.rename": ("admin", "vm", "rename"),
    "vm.disk_add": ("admin", "vm", "add a disk"),
    "vm.disk_extend": ("admin", "vm", "grow a disk"),
    "vm.device_remove": ("admin", "vm", "remove a device"),
    "vm.nic_add": ("admin", "vm", "add a network adapter"),
    "vm.nic_set": ("admin", "vm", "change a network adapter"),
    "vm.cd": ("admin", "vm", "insert or eject an ISO"),
    "vm.cd_add": ("admin", "vm", "add a CD/DVD drive"),
    "vm.clone": ("admin", "vm", "clone"),
    "vm.migrate": ("admin", "vm", "migrate to another node"),
    "vm.unregister": ("admin", "vm", "remove from inventory"),
    "vm.delete": ("admin", "vm", "delete"),
    "vm.create": ("admin", "host", "create a VM"),
    "host.maintenance_enter": ("admin", "host", "enter maintenance mode"),
    "host.maintenance_exit": ("admin", "host", "exit maintenance mode"),
    "host.reboot": ("admin", "host", "reboot the host"),
    "host.shutdown": ("admin", "host", "shut down the host"),
    "host.service": ("admin", "host", "start, stop or restart a service"),
    "host.service_policy": ("admin", "host", "change a service's start policy"),
    "host.portgroup_add": ("admin", "host", "add a port group"),
    "host.portgroup_update": ("admin", "host", "change a port group"),
    "host.portgroup_remove": ("admin", "host", "remove a port group"),
    "ds.mkdir": ("admin", "host", "create a folder"),
    "ds.delete": ("admin", "host", "delete a file"),
    "ds.upload": ("admin", "host", "upload a file"),
    "console.open": ("console", "vm", "open the console"),
}
# gated and audited here, but carried out by their own routes (a stream, a socket)
NOT_RUN = {"ds.upload", "console.open"}
ESXI_ONLY = {"vm.unregister", "vm.boot", "vm.snapshot_delete_all",
             "vm.snapshot_rename", "host.maintenance_enter",
             "host.maintenance_exit", "host.service_policy",
             "host.portgroup_add", "host.portgroup_update",
             "host.portgroup_remove", "ds.mkdir"}
PVE_ONLY = {"vm.resume", "vm.clone", "vm.migrate", "vm.cd_add"}


def audit_name(action: str) -> str:
    return "virt_" + action.replace(".", "_")


def gate(user, conn: dict, action: str, confirm: str, target_name: str) -> None:
    """Raise Refused unless every gate is open for this action."""
    if action not in ACTIONS:
        raise Refused("unknown action")
    need = ACTIONS[action][0]
    why = manage_why(conn) or may_why(user, need, conn.get("pid") or "")
    if why:
        raise Refused(why)
    f = flavor(conn)
    if (f == "esxi" and action in PVE_ONLY) or (f == "proxmox" and action in ESXI_ONLY):
        raise Refused("this hypervisor cannot do that")
    if conn.get("production"):
        # an empty name is no confirmation: a VM that could not be looked
        # up (or a request naming none) must not pass by sending nothing
        if not (target_name or "").strip():
            raise Refused("this is a production hypervisor, and the VM could not be "
                          "found to confirm its name")
        if (confirm or "").strip() != target_name.strip():
            raise Refused(f"this is a production hypervisor: type {target_name} to confirm")


def _i(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _bool(v) -> bool:
    return str(v).lower() in ("1", "true", "on", "yes")


def run(conn: dict, action: str, p: dict) -> dict:
    """Do one action. `p` holds the request's own fields (vm, node, kind,
    key, name, ...). Returns {"task": id} for something to poll, or
    {"done": True}; raises VirtError with the hypervisor's own reason."""
    if action in NOT_RUN:
        raise VirtError("that action has its own route")
    f = flavor(conn)
    out = _run_esxi(conn, action, p) if f == "esxi" else _run_pve(conn, action, p)
    virt.forget(conn)
    return out


def _run_esxi(conn: dict, action: str, p: dict) -> dict:
    E = esxiops
    es = E.Esxi(conn)
    vm = p.get("vm", "")
    a = action.split(".", 1)[1]
    power = {"start": "on", "stop": "off", "reset": "reset", "suspend": "suspend",
             "shutdown": "shutdown", "reboot": "reboot"}
    if action.startswith("vm.") and a in power:
        return E.power(es, vm, power[a])
    if action == "vm.snapshot":
        return E.snapshot_create(es, vm, p.get("name", ""), p.get("description", ""),
                                 _bool(p.get("memory")), _bool(p.get("quiesce")))
    if action in ("vm.revert", "vm.snapshot_delete", "vm.snapshot_rename"):
        # a snapshot id names its own VM: it must be one of THIS VM's, the
        # one whose name was confirmed and goes in the audit
        snap = str(p.get("snapshot", ""))
        if snap not in {s["id"] for s in E.vm_detail(es, vm).get("snapshots") or []}:
            raise VirtError("that snapshot is not one of this VM's")
        if action == "vm.revert":
            return E.snapshot_revert(es, snap)
        if action == "vm.snapshot_delete":
            return E.snapshot_remove(es, snap, _bool(p.get("children")))
        return E.snapshot_rename(es, snap, p.get("name", ""), p.get("description", ""))
    if action == "vm.snapshot_delete_all":
        return E.snapshot_remove_all(es, vm)
    if action == "vm.resources":
        return E.set_resources(es, vm, _i(p.get("cpus")), _i(p.get("cores_per_socket")),
                               _i(p.get("memory_mb")),
                               p.get("notes") if "notes" in p else None)
    if action == "vm.boot":
        return E.set_boot(es, vm,
                          _bool(p["enter_setup"]) if "enter_setup" in p else None,
                          _bool(p["secure_boot"]) if "secure_boot" in p else None,
                          p.get("firmware") or None)
    if action == "vm.rename":
        return E.rename(es, vm, p.get("name", ""))
    if action == "vm.disk_add":
        return E.disk_add(es, vm, float(p.get("gib") or 0), p.get("datastore", ""),
                          p.get("thin", True) not in (False, "0", "false"))
    if action == "vm.disk_extend":
        return E.disk_extend(es, vm, _i(p.get("key")), float(p.get("gib") or 0))
    if action == "vm.device_remove":
        return E.device_remove(es, vm, _i(p.get("key")), _bool(p.get("delete_file")))
    if action == "vm.nic_add":
        return E.nic_add(es, vm, p.get("network", ""), p.get("adapter") or "vmxnet3")
    if action == "vm.nic_set":
        return E.nic_set(es, vm, _i(p.get("key")),
                         p.get("network") or None,
                         _bool(p["connected"]) if "connected" in p else None)
    if action == "vm.cd":
        return E.cd_set(es, vm, _i(p.get("key")), p.get("iso", ""))
    if action == "vm.unregister":
        return E.unregister(es, vm)
    if action == "vm.delete":
        return E.destroy(es, vm)
    if action == "vm.create":
        return E.create_vm(es, p)
    if action == "host.maintenance_enter":
        return E.maintenance(es, True)
    if action == "host.maintenance_exit":
        return E.maintenance(es, False)
    if action in ("host.reboot", "host.shutdown"):
        return E.host_power(es, a, _bool(p.get("force")))
    if action == "host.service":
        return E.service(es, p.get("op", ""), p.get("key", ""))
    if action == "host.service_policy":
        return E.service_policy(es, p.get("key", ""), p.get("policy", ""))
    if action == "host.portgroup_add":
        return E.portgroup_add(es, p.get("name", ""), _i(p.get("vlan"), 0),
                               p.get("vswitch", ""))
    if action == "host.portgroup_update":
        return E.portgroup_update(es, p.get("name", ""), _i(p.get("vlan"), 0),
                                  p.get("vswitch", ""))
    if action == "host.portgroup_remove":
        return E.portgroup_remove(es, p.get("name", ""))
    if action == "ds.mkdir":
        return E.mkdir(es, p.get("datastore", ""), p.get("path", ""))
    if action == "ds.delete":
        return E.delete_file(es, p.get("datastore", ""), p.get("path", ""))
    raise VirtError("this hypervisor cannot do that")


def _run_pve(conn: dict, action: str, p: dict) -> dict:
    P = pveops
    node, kind, vm = p.get("node", ""), p.get("kind") or "qemu", p.get("vm", "")
    a = action.split(".", 1)[1]
    with P.client(conn) as px:
        if action.startswith("vm.") and a in ("start", "shutdown", "reboot", "stop",
                                              "reset", "suspend", "resume"):
            return P.power(px, node, kind, vm, a)
        if action == "vm.snapshot":
            return P.snapshot_create(px, node, kind, vm, p.get("name", ""),
                                     p.get("description", ""), _bool(p.get("memory")))
        if action == "vm.revert":
            return P.snapshot_revert(px, node, kind, vm, p.get("snapshot", ""))
        if action == "vm.snapshot_delete":
            return P.snapshot_remove(px, node, kind, vm, p.get("snapshot", ""))
        if action == "vm.resources":
            return P.set_resources(px, node, kind, vm, _i(p.get("cpus")),
                                   _i(p.get("sockets")), _i(p.get("memory_mb")),
                                   p.get("notes") if "notes" in p else None,
                                   _bool(p["onboot"]) if "onboot" in p else None)
        if action == "vm.rename":
            return P.rename(px, node, kind, vm, p.get("name", ""))
        if action == "vm.disk_add":
            return P.disk_add(px, node, kind, vm, float(p.get("gib") or 0),
                              p.get("datastore", ""))
        if action == "vm.disk_extend":
            return P.disk_extend(px, node, kind, vm, p.get("key", ""),
                                 float(p.get("gib") or 0))
        if action == "vm.device_remove":
            return P.device_remove(px, node, kind, vm, p.get("key", ""))
        if action == "vm.nic_add":
            return P.nic_add(px, node, kind, vm, p.get("network", ""),
                             p.get("vlan", ""), p.get("adapter") or "virtio")
        if action == "vm.nic_set":
            return P.nic_set(px, node, kind, vm, p.get("key", ""),
                             p.get("network") or None,
                             p.get("vlan") if "vlan" in p else None,
                             _bool(p["connected"]) if "connected" in p else None)
        if action == "vm.cd":
            return P.cd_set(px, node, kind, vm, p.get("key", ""), p.get("iso", ""))
        if action == "vm.cd_add":
            return P.cd_add(px, node, kind, vm)
        if action == "vm.clone":
            return P.clone(px, node, vm, p.get("name", ""), p.get("target", ""),
                           p.get("full", True) not in (False, "0", "false"),
                           p.get("datastore", ""))
        if action == "vm.migrate":
            return P.migrate(px, node, kind, vm, p.get("target", ""),
                             p.get("online", True) not in (False, "0", "false"))
        if action == "vm.delete":
            return P.destroy(px, node, kind, vm)
        if action == "vm.create":
            return P.create_vm(px, node, p)
        if action in ("host.reboot", "host.shutdown"):
            return P.node_power(px, node, a)
        if action == "host.service":
            return P.service(px, node, p.get("op", ""), p.get("key", ""))
        if action == "ds.delete":
            return P.delete_content(px, node, p.get("datastore", ""), p.get("path", ""))
    raise VirtError("this hypervisor cannot do that")


def task(conn: dict, task_id: str, node: str = "") -> dict:
    if _engine(conn) == "esxi":
        es = esxiops.Esxi(conn)
        if not task_id or len(task_id) > 80:
            raise VirtError("unknown task")
        info = es.task_info(task_id)
    else:
        with pveops.client(conn) as px:
            info = pveops.task_info(px, node, task_id)
    if info["state"] not in ("queued", "running"):
        virt.forget(conn)
    return info


# ── reads for the pages ────────────────────────────────────────
def _engine(conn: dict) -> str:
    """esxi or proxmox, or VirtError for anything the detail pages cannot
    read (a vCenter, an unreachable host)."""
    f = flavor(conn)
    if f in ("esxi", "proxmox"):
        return f
    if f == "vcenter":
        raise VirtError("the detail pages are for standalone ESXi hosts and "
                        "Proxmox; a vCenter is shown on the Hypervisors page only")
    raise VirtError("the hypervisor is not answering")


def vm_name(conn: dict, vmid: str, node: str = "", kind: str = "qemu") -> str:
    """The VM's name as the hypervisor has it — what a production change is
    confirmed with and what the audit names. One small read."""
    _engine(conn)
    if flavor(conn) == "esxi":
        return esxiops.Esxi(conn).props("VirtualMachine", vmid, ["name"]).get("name", "")
    with pveops.client(conn) as px:
        cfg = pveops.call(px, "GET", f"{pveops._base(node, kind or 'qemu', vmid)}/config") or {}
    # the same fallback the VM page shows (pveops.vm_detail), so an unnamed
    # guest on a production node can still be confirmed
    return cfg.get("name") or cfg.get("hostname") or f"{kind or 'qemu'}-{vmid}"


def vm(conn: dict, vmid: str, node: str = "", kind: str = "qemu") -> dict:
    _engine(conn)
    if flavor(conn) == "esxi":
        es = esxiops.Esxi(conn)
        d = esxiops.vm_detail(es, vmid)
        d["tasks"] = esxiops.recent_tasks(es, d["tasks"]) if d["tasks"] else []
        d["flavor"] = "esxi"
        return d
    with pveops.client(conn) as px:
        d = pveops.vm_detail(px, node, kind, vmid)
        try:
            d["tasks"] = pveops.tasks(px, node, vmid)
        except VirtError:
            d["tasks"] = []
    d["flavor"] = "proxmox"
    return d


def host(conn: dict, node: str = "") -> dict:
    _engine(conn)
    if flavor(conn) == "esxi":
        es = esxiops.Esxi(conn)
        d = esxiops.host_detail(es)
        try:
            d["tasks"] = esxiops.recent_tasks(es)
        except VirtError:
            d["tasks"] = []
        d["flavor"] = "esxi"
        return d
    with pveops.client(conn) as px:
        d = pveops.node_detail(px, node)
        try:
            d["tasks"] = pveops.tasks(px, node)
        except VirtError:
            d["tasks"] = []
    d["flavor"] = "proxmox"
    return d


def choices(conn: dict, node: str = "") -> dict:
    """What the VM forms offer: networks, datastores, ISOs, guest OS types."""
    _engine(conn)
    if flavor(conn) == "esxi":
        es = esxiops.Esxi(conn)
        return {"networks": esxiops.networks(es),
                "datastores": [d for d in esxiops.datastores(es) if d["accessible"]],
                "isos": esxiops.isos(es),
                "guest_os": esxiops.guest_os(es), "flavor": "esxi"}
    with pveops.client(conn) as px:
        st = pveops.storages(px, node)
        return {"networks": pveops.bridges(px, node),
                "datastores": [s for s in st if "images" in s["content"] and s["accessible"]],
                "iso_storages": [s for s in st if "iso" in s["content"] and s["accessible"]],
                "isos": pveops.isos(px, node),
                "guest_os": [(k, v, "") for k, v in pveops.OS_TYPES],
                "nodes": [h["name"] for h in (virt.read(conn).get("hosts") or [])],
                "flavor": "proxmox"}


def browse(conn: dict, datastore: str, path: str = "", node: str = "") -> dict:
    _engine(conn)
    if flavor(conn) == "esxi":
        return esxiops.browse(esxiops.Esxi(conn), datastore, path)
    with pveops.client(conn) as px:
        files = [{"name": c["name"], "kind": c["content"], "size": c["size"],
                  "modified": c["created"], "volid": c["volid"]}
                 for c in pveops.content(px, node, datastore)]
    return {"datastore": datastore, "path": "", "files": files}


# ── consoles ───────────────────────────────────────────────────
def console_open(user: dict, conn: dict, vmid: str, node: str, kind: str,
                 name: str) -> tuple[str, str]:
    """A one-time console session for this person, good for CONSOLE_TTL:
    (session id, the VNC password the browser must answer with — Proxmox's
    ticket; empty for ESXi, whose ticket is in the websocket URL). The
    hypervisor is asked now, so a refusal shows on the page, not as a
    dropped socket."""
    up = _upstream(conn, vmid, node, kind or "qemu")
    sid = secrets.token_urlsafe(24)
    now = time.time()
    with _console_guard:
        for k in [k for k, v in _consoles.items() if v["expires"] < now]:
            _consoles.pop(k, None)
        _consoles[sid] = {"uid": user.get("id"), "conn": conn.get("id"),
                          "conn_name": conn.get("name", ""), "vm": vmid,
                          "node": node, "kind": kind or "qemu", "name": name,
                          "up": up, "expires": now + CONSOLE_TTL}
    return sid, up.get("password", "")


def console_take(sid: str, user: dict) -> dict | None:
    """The session, once, and only for the person it was minted for — and
    only while the connection still exists, still allows management and the
    person may still open its console."""
    with _console_guard:
        s = _consoles.pop(sid or "", None)
    if not s or s["expires"] < time.time() or s["uid"] != (user or {}).get("id"):
        return None
    return s if console_still(s, user) else None


def console_still(s: dict, user: dict) -> bool:
    """Whether an open console may go on: asked when it starts and every
    half-minute after (a role removed, management switched off, the
    connection deleted all end it)."""
    conn = find_conn(s.get("conn", ""))
    return bool(conn) and not manage_why(conn) and may(user, "console", conn.get("pid") or "")


def _upstream(conn: dict, vmid: str, node: str, kind: str) -> dict:
    """{url, headers, insecure, password, flavor} for the relay to dial."""
    if flavor(conn) == "esxi":
        t = esxiops.console_ticket(esxiops.Esxi(conn), vmid)
        return {**t, "headers": {}, "password": "", "flavor": "esxi"}
    with pveops.client(conn) as px:
        t = pveops.console_ticket(px, conn, node, kind, vmid)
    return {**t, "flavor": "proxmox"}


def strip_zlib(first: bytes) -> bytes:
    """The ESXi console stalls when a client offers Zlib (encoding 6): it sends
    the cursor and never the screen (measured against ESXi 8.0.3, 24 November
    2026). This rewrites a SetEncodings message without it; anything else is
    returned unchanged."""
    import struct
    if len(first) < 4 or first[0] != 2:
        return first
    n = struct.unpack(">H", first[2:4])[0]
    if len(first) < 4 + 4 * n:
        return first
    encs = [struct.unpack(">i", first[4 + 4 * k:8 + 4 * k])[0] for k in range(n)]
    keep = [e for e in encs if e != 6]
    if len(keep) == len(encs):
        return first
    return (struct.pack(">BxH", 2, len(keep))
            + b"".join(struct.pack(">i", e) for e in keep) + first[4 + 4 * n:])
