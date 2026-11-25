"""Managing a standalone ESXi host from EnvMap: its virtual machines, their
snapshots and hardware, the host's maintenance, services, port groups and
datastores.

WHY HAND-WRITTEN SOAP AND NOT A LIBRARY
    The read side (virt.py) already speaks the vSphere Web Services API at /sdk
    with urllib and defusedxml, through urlguard, with no third-party package.
    A management client is the same API with more methods, so it reuses that
    transport rather than adding pyVmomi (a large dependency whose own client
    would bypass the URL guard). Every call here is one SOAP body built from
    escaped values.

EDITS KEEP THE HOST'S OWN DEVICE XML
    vSphere data objects are XML sequences: elements must arrive in schema
    order, and a device carries a dozen fields a form never shows (its uuid,
    its slot, its shares). Rebuilding a device from a few known fields would
    silently reset the rest. So an edit reads the device as the host returned
    it, changes the one field asked for in place, and sends that element back.

WHAT IS CHECKED AGAINST A REAL HOST
    Every request body here was sent to a real ESXi 8.0.3 with a managed
    object id that does not exist: the host parses the whole body before it
    looks the object up, so a malformed body answers InvalidRequest and a
    well-formed one ManagedObjectNotFound (tests/test_virt_manage.py replays
    the same shapes against a fake host). Nothing was changed on that host.

WHAT THIS DOES NOT DO
    vCenter. Its VMs are reachable through the same API, but a vCenter adds
    clusters, DRS and permissions this was never tested against, so a vCenter
    connection stays read-only (virtops.can_manage says why).
"""
from __future__ import annotations

import re
import threading
import time
import urllib.parse
from xml.sax.saxutils import escape as _x

from . import virt
from .virt import VirtError, _kid, _kids, _local, _moref, _text

XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"
# a CD/DVD drive takes an ISO image on a datastore, never another VM's disk
# (a -flat.vmdk attached as a CD is that VM's data, readable from this guest)
_ISO = re.compile(r"^\[[^\]]+\] \S.*\.iso$", re.I)
TASK_WAIT = 60          # seconds a short task is waited for before polling
_REFS: dict = {}        # base_url -> the managed object ids this host uses
_GUEST_OS: dict = {}    # base_url -> (time, [(id, name, family)])
_REFS_GUARD = threading.Lock()


# ── vSphere data objects as Python ─────────────────────────────
def obj(el):
    """A data object as Python: text for a leaf, a dict for a complex value
    (a repeated child becomes a list), `_type` from xsi:type."""
    if el is None:
        return None
    kids = list(el)
    if not kids:
        return (el.text or "").strip()
    out: dict = {}
    t = el.get(XSI_TYPE)
    if t:
        out["_type"] = t
    multi: set = set()
    for k in kids:
        name = _local(k.tag)
        v = obj(k)
        if name in out:
            if name not in multi:
                out[name] = [out[name]]
                multi.add(name)
            out[name].append(v)
        else:
            out[name] = v
    return out


def lst(v) -> list:
    if v is None or v == "":
        return []
    return v if isinstance(v, list) else [v]


def dig(d, *path, default=""):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
        if d is None:
            return default
    return d


def num(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def flag(v) -> bool:
    return str(v).strip().lower() == "true"


def to_xml(el, name: str | None = None) -> str:
    """An element as the host sent it, back as request XML in the vim25
    namespace: same children, same order, same xsi:type."""
    tag = name or _local(el.tag)
    attrs = ""
    t = el.get(XSI_TYPE)
    if t:
        attrs += f' xsi:type="{_x(t)}"'
    if el.get("type"):
        attrs += f' type="{_x(el.get("type"))}"'
    kids = list(el)
    if not kids:
        return f"<{tag}{attrs}>{_x(el.text or '')}</{tag}>"
    return f"<{tag}{attrs}>" + "".join(to_xml(k) for k in kids) + f"</{tag}>"


def _b(v) -> str:
    return "true" if v else "false"


def ds_path(datastore: str, path: str = "") -> str:
    """`[datastore] folder/file`, the way vSphere names a datastore file."""
    path = (path or "").strip().strip("/")
    return f"[{datastore}] {path}" if path else f"[{datastore}]"


_SAFE_NAME = re.compile(r"^[^\x00-\x1f%\\/<>&\"]{1,80}$")


def check_name(name: str, what: str = "name") -> str:
    name = (name or "").strip()
    if not name or not _SAFE_NAME.match(name):
        raise VirtError(f"a {what} of 1-80 characters, without / \\ % < > & "
                        "or quotes")
    return name


def check_path(path: str) -> str:
    """A datastore-relative path: no climbing out, no control characters."""
    path = (path or "").strip().strip("/")
    if any(p in ("..", ".") for p in path.split("/")) or re.search(
            r"[\x00-\x1f\\]", path):
        raise VirtError("that datastore path is not allowed")
    return path


# ── one signed-in session to one host ──────────────────────────
class Esxi:
    """A SOAP session to one standalone ESXi host, sharing the read side's
    cached login. Built per request; cheap, because the login is cached."""

    def __init__(self, conn: dict):
        self.c = conn
        self.svc = virt._service(conn)
        if self.svc.get("apiType") != "HostAgent":
            raise VirtError("this connection is not a standalone ESXi host")
        self.cookie = virt._esxi_login(conn, self.svc)

    # transport
    def call(self, inner: str, timeout: float = 0):
        try:
            resp, _ = virt._soap(self.c, self.svc["version"], inner,
                                 self.cookie, timeout)
        except virt._NotAuthenticated:
            virt._cache.pop(f"vsoap::{virt._who(self.c)}", None)
            self.cookie = virt._esxi_login(self.c, self.svc)
            resp, _ = virt._soap(self.c, self.svc["version"], inner,
                                 self.cookie, timeout)
        return resp

    def returnval(self, inner: str, timeout: float = 0) -> str:
        return _text(self.call(inner, timeout), "returnval")

    def _retrieve(self, kind: str, moids: list[str], paths: list[str]) -> dict:
        if not moids:
            return {}
        body = ('<RetrievePropertiesEx xmlns="urn:vim25">'
                + _moref(self.svc["propertyCollector"], "_this",
                         "PropertyCollector")
                + f"<specSet><propSet><type>{kind}</type>"
                + "".join(f"<pathSet>{_x(p)}</pathSet>" for p in paths)
                + "</propSet>"
                + "".join(f"<objectSet>{_moref(m, 'obj', kind)}"
                          "<skip>false</skip></objectSet>" for m in moids)
                + "</specSet><options/></RetrievePropertiesEx>")
        out: dict = {}
        resp = self.call(body)
        rv = _kid(resp, "returnval")
        for o in _kids(rv, "objects") if rv is not None else []:
            moid = _text(o, "obj")
            out[moid] = {_text(p, "name"): _kid(p, "val")
                         for p in _kids(o, "propSet")}
        return out

    def raw(self, kind: str, moid: str, paths: list[str]) -> dict:
        """{path: the val element} for one object."""
        return self._retrieve(kind, [moid], paths).get(moid, {})

    def props(self, kind: str, moid: str, paths: list[str]) -> dict:
        return {k: obj(v) for k, v in self.raw(kind, moid, paths).items()}

    def many(self, kind: str, moids: list[str], paths: list[str]) -> dict:
        return {m: {k: obj(v) for k, v in got.items()}
                for m, got in self._retrieve(kind, moids, paths).items()}

    # the ids a standalone host uses for its folder, pool and managers
    @property
    def refs(self) -> dict:
        key = self.c.get("base_url", "")
        with _REFS_GUARD:
            hit = _REFS.get(key)
        if hit and time.time() - hit["_at"] < 3600:
            return hit
        rv = _kid(self.call('<RetrieveServiceContent xmlns="urn:vim25">'
                            '<_this type="ServiceInstance">ServiceInstance'
                            '</_this></RetrieveServiceContent>'), "returnval")
        r = {k: _text(rv, k) for k in ("rootFolder", "fileManager",
                                       "taskManager", "propertyCollector")}
        dc = lst(dig(self.props("Folder", r["rootFolder"], ["childEntity"]),
                     "childEntity", "ManagedObjectReference"))
        r["datacenter"] = dc[0] if dc else "ha-datacenter"
        d = self.props("Datacenter", r["datacenter"],
                       ["vmFolder", "hostFolder", "name"])
        r["vmFolder"], r["dcName"] = d.get("vmFolder", ""), d.get("name", "")
        hosts = lst(dig(self.props("Folder", d.get("hostFolder", ""),
                                   ["childEntity"]),
                        "childEntity", "ManagedObjectReference"))
        cr = hosts[0] if hosts else ""
        c = self.props("ComputeResource", cr,
                       ["resourcePool", "host", "environmentBrowser"])
        r["pool"] = c.get("resourcePool", "")
        r["envBrowser"] = c.get("environmentBrowser", "")
        hs = lst(dig(c, "host", "ManagedObjectReference"))
        r["host"] = hs[0] if hs else "ha-host"
        h = self.props("HostSystem", r["host"],
                       ["datastoreBrowser", "configManager.serviceSystem",
                        "configManager.networkSystem"])
        r["browser"] = h.get("datastoreBrowser", "")
        r["serviceSystem"] = h.get("configManager.serviceSystem", "")
        r["networkSystem"] = h.get("configManager.networkSystem", "")
        r["_at"] = time.time()
        with _REFS_GUARD:
            _REFS[key] = r
        return r

    # tasks
    def task(self, inner: str) -> str:
        t = self.returnval(inner)
        if not t:
            raise VirtError("the host accepted the request but returned no task")
        return t

    def task_info(self, task: str) -> dict:
        info = self.props("Task", task, ["info"]).get("info") or {}
        err = info.get("error") if isinstance(info, dict) else None
        msg = ""
        if isinstance(err, dict):
            msg = err.get("localizedMessage") or dig(err, "fault", "_type") or "failed"
        return {"task": task, "state": dig(info, "state"),
                "progress": num(dig(info, "progress")),
                "error": msg, "what": dig(info, "descriptionId"),
                "entity": dig(info, "entityName"),
                "started": dig(info, "startTime"),
                "finished": dig(info, "completeTime"),
                "result": dig(info, "result") if not isinstance(
                    dig(info, "result"), dict) else ""}

    def wait(self, task: str, timeout: float = TASK_WAIT) -> dict:
        end = time.time() + timeout
        info = self.task_info(task)
        while info["state"] in ("queued", "running") and time.time() < end:
            time.sleep(0.6)
            info = self.task_info(task)
        return info


# ── reading a VM ───────────────────────────────────────────────
VM_PATHS = [
    "name", "runtime.powerState", "runtime.host", "runtime.bootTime",
    "runtime.connectionState", "config.guestFullName", "config.guestId",
    "config.annotation", "config.hardware.numCPU",
    "config.hardware.numCoresPerSocket", "config.hardware.memoryMB",
    "config.firmware", "config.bootOptions", "config.files.vmPathName",
    "config.version", "config.uuid", "config.template",
    "guest.toolsRunningStatus", "guest.toolsVersionStatus2",
    "guest.ipAddress", "guest.hostName", "guest.guestFullName", "guest.net",
    "summary.quickStats.overallCpuUsage", "summary.runtime.maxCpuUsage",
    "summary.quickStats.guestMemoryUsage", "summary.quickStats.uptimeSeconds",
    "summary.storage.committed", "summary.storage.uncommitted",
    "snapshot", "recentTask"]


def _device(el) -> dict:
    """One device, summarised for the page; `kind` says what it is."""
    d = obj(el) or {}
    t = d.get("_type", "")
    label = dig(d, "deviceInfo", "label")
    con = d.get("connectable") if isinstance(d.get("connectable"), dict) else {}
    out = {"key": num(d.get("key")), "type": t, "label": label,
           "summary": dig(d, "deviceInfo", "summary"),
           "controller": num(d.get("controllerKey")),
           "unit": num(d.get("unitNumber")),
           "connected": flag(con.get("connected")) if con else None,
           "start_connected": flag(con.get("startConnected")) if con else None}
    backing = d.get("backing") if isinstance(d.get("backing"), dict) else {}
    if t == "VirtualDisk":
        kb = num(d.get("capacityInKB"), 0)
        out.update(kind="disk", gib=round(kb / 1048576, 1), kb=kb,
                   file=backing.get("fileName", ""),
                   thin=flag(backing.get("thinProvisioned")),
                   mode=backing.get("diskMode", ""))
    elif t in ("VirtualVmxnet3", "VirtualVmxnet2", "VirtualE1000",
               "VirtualE1000e", "VirtualPCNet32", "VirtualVmxnet",
               "VirtualSriovEthernetCard"):
        out.update(kind="nic", adapter=t.removeprefix("Virtual").lower(),
                   mac=d.get("macAddress", ""),
                   network=backing.get("deviceName", "")
                   or dig(backing, "port", "portgroupKey"))
    elif t == "VirtualCdrom":
        iso = backing.get("fileName", "") if backing.get(
            "_type") == "VirtualCdromIsoBackingInfo" else ""
        out.update(kind="cdrom", iso=iso)
    elif t.endswith("Controller") and t not in (
            "VirtualPCIController", "VirtualPS2Controller",
            "VirtualSIOController", "VirtualUSBController",
            "VirtualUSBXHCIController"):
        out.update(kind="controller", bus=num(d.get("busNumber")),
                   devices=[num(x) for x in lst(d.get("device"))],
                   scsi=t in ("ParaVirtualSCSIController",
                              "VirtualLsiLogicSASController",
                              "VirtualLsiLogicController",
                              "VirtualBusLogicController"))
    else:
        out["kind"] = "other"
    return out


def _snapshots(tree, current: str, depth: int = 0) -> list[dict]:
    out = []
    for s in lst(tree):
        if not isinstance(s, dict):
            continue
        moid = s.get("snapshot", "")
        out.append({"id": moid, "name": s.get("name", ""),
                    "description": s.get("description", ""),
                    "created": s.get("createTime", ""),
                    "state": s.get("state", ""),
                    "quiesced": flag(s.get("quiesced")),
                    "current": moid == current, "depth": depth})
        out += _snapshots(s.get("childSnapshotList"), current, depth + 1)
    return out


def vm_detail(es: Esxi, moid: str) -> dict:
    raw = es.raw("VirtualMachine", moid, VM_PATHS + ["config.hardware.device"])
    if not raw:
        raise VirtError("that virtual machine is no longer on this host")
    p = {k: obj(v) for k, v in raw.items() if k != "config.hardware.device"}
    devs = [_device(el) for el in list(raw.get("config.hardware.device") or [])]
    power = p.get("runtime.powerState", "")
    snap = p.get("snapshot") if isinstance(p.get("snapshot"), dict) else {}
    nets = []
    for n in lst(dig(p, "guest.net", "GuestNicInfo")):
        if isinstance(n, dict):
            nets.append({"network": n.get("network", ""),
                         "mac": n.get("macAddress", ""),
                         "ips": [i for i in lst(n.get("ipAddress")) if i],
                         "connected": flag(n.get("connected"))})
    host_name = ""
    if p.get("runtime.host"):
        host_name = es.props("HostSystem", p["runtime.host"], ["name"]).get(
            "name", "")
    tasks = [t for t in lst(dig(p, "recentTask", "ManagedObjectReference"))]
    boot = p.get("config.bootOptions") if isinstance(
        p.get("config.bootOptions"), dict) else {}
    return {
        "id": moid, "name": p.get("name", moid), "power": power,
        "state": {"poweredOn": "On", "poweredOff": "Off",
                  "suspended": "Suspended"}.get(power, power),
        "host": host_name, "guest_os": p.get("config.guestFullName", ""),
        "guest_id": p.get("config.guestId", ""),
        "guest_running_os": p.get("guest.guestFullName", ""),
        "notes": p.get("config.annotation", ""),
        "cpus": num(p.get("config.hardware.numCPU")),
        "cores_per_socket": num(p.get("config.hardware.numCoresPerSocket")),
        "memory_mb": num(p.get("config.hardware.memoryMB")),
        "firmware": p.get("config.firmware", ""),
        "secure_boot": flag(boot.get("efiSecureBootEnabled")),
        "enter_setup": flag(boot.get("enterBIOSSetup")),
        "vmx": p.get("config.files.vmPathName", ""),
        "hw_version": p.get("config.version", ""),
        "uuid": p.get("config.uuid", ""),
        "template": flag(p.get("config.template")),
        "tools": p.get("guest.toolsRunningStatus", ""),
        "tools_version": p.get("guest.toolsVersionStatus2", ""),
        "ip": p.get("guest.ipAddress", ""),
        "hostname": p.get("guest.hostName", ""),
        "nets": nets,
        "cpu_pct": virt._pct(p.get("summary.quickStats.overallCpuUsage"),
                             p.get("summary.runtime.maxCpuUsage"))
        if power == "poweredOn" else None,
        "mem_pct": virt._pct(p.get("summary.quickStats.guestMemoryUsage"),
                             p.get("config.hardware.memoryMB"))
        if power == "poweredOn" else None,
        "uptime": virt._uptime(p.get("summary.quickStats.uptimeSeconds")),
        "booted": p.get("runtime.bootTime", ""),
        "committed_gib": round(num(p.get("summary.storage.committed"), 0)
                               / 1024 ** 3, 1),
        "devices": devs,
        "disks": [d for d in devs if d["kind"] == "disk"],
        "nics": [d for d in devs if d["kind"] == "nic"],
        "cdroms": [d for d in devs if d["kind"] == "cdrom"],
        "controllers": [d for d in devs if d["kind"] == "controller"],
        "snapshots": _snapshots(snap.get("rootSnapshotList"),
                                snap.get("currentSnapshot", "")),
        "tasks": tasks,
    }


def recent_tasks(es: Esxi, moids: list[str] | None = None,
                 limit: int = 25) -> list[dict]:
    """The host's recent tasks (or these ones), newest first."""
    if moids is None:
        moids = lst(dig(es.props("TaskManager", es.refs["taskManager"],
                                 ["recentTask"]),
                        "recentTask", "ManagedObjectReference"))
    if not moids:
        return []
    got = es.many("Task", moids[-limit:], ["info"])
    out = []
    for m, p in got.items():
        info = p.get("info") if isinstance(p.get("info"), dict) else {}
        err = info.get("error")
        out.append({"task": m, "what": _task_label(info.get("descriptionId", "")),
                    "entity": info.get("entityName", ""),
                    "state": info.get("state", ""),
                    "progress": num(info.get("progress")),
                    "error": (err.get("localizedMessage") if isinstance(err, dict)
                              else "") or "",
                    "who": dig(info, "reason", "userName"),
                    "queued": info.get("queueTime", ""),
                    "started": info.get("startTime", ""),
                    "finished": info.get("completeTime", "")})
    out.sort(key=lambda t: t.get("queued") or "", reverse=True)
    return out


def _task_label(desc: str) -> str:
    """`VirtualMachine.powerOn` -> `Power on`: the task's own id, readable."""
    tail = desc.rsplit(".", 1)[-1] if desc else ""
    words = re.sub(r"(?<!^)([A-Z])", r" \1", tail).lower().strip()
    return (words[:1].upper() + words[1:]) if words else desc


# ── VM actions ─────────────────────────────────────────────────
POWER = {"on": "PowerOnVM_Task", "off": "PowerOffVM_Task",
         "reset": "ResetVM_Task", "suspend": "SuspendVM_Task"}
GUEST = {"shutdown": "ShutdownGuest", "reboot": "RebootGuest"}


def power(es: Esxi, moid: str, op: str) -> dict:
    if op in POWER:
        return {"task": es.task(f'<{POWER[op]} xmlns="urn:vim25">'
                                + _moref(moid, "_this", "VirtualMachine")
                                + f"</{POWER[op]}>")}
    if op in GUEST:
        es.call(f'<{GUEST[op]} xmlns="urn:vim25">'
                + _moref(moid, "_this", "VirtualMachine") + f"</{GUEST[op]}>")
        return {"done": True}
    raise VirtError(f"unknown power action {op!r}")


def snapshot_create(es: Esxi, moid: str, name: str, description: str = "",
                    memory: bool = False, quiesce: bool = False) -> dict:
    return {"task": es.task(
        '<CreateSnapshot_Task xmlns="urn:vim25">'
        + _moref(moid, "_this", "VirtualMachine")
        + f"<name>{_x(check_name(name, 'snapshot name'))}</name>"
        + f"<description>{_x(description or '')}</description>"
        + f"<memory>{_b(memory)}</memory><quiesce>{_b(quiesce)}</quiesce>"
        + "</CreateSnapshot_Task>")}


def snapshot_revert(es: Esxi, snap: str) -> dict:
    return {"task": es.task('<RevertToSnapshot_Task xmlns="urn:vim25">'
                            + _moref(snap, "_this", "VirtualMachineSnapshot")
                            + "</RevertToSnapshot_Task>")}


def snapshot_remove(es: Esxi, snap: str, children: bool = False) -> dict:
    return {"task": es.task('<RemoveSnapshot_Task xmlns="urn:vim25">'
                            + _moref(snap, "_this", "VirtualMachineSnapshot")
                            + f"<removeChildren>{_b(children)}</removeChildren>"
                            "<consolidate>true</consolidate>"
                            "</RemoveSnapshot_Task>")}


def snapshot_remove_all(es: Esxi, moid: str) -> dict:
    return {"task": es.task('<RemoveAllSnapshots_Task xmlns="urn:vim25">'
                            + _moref(moid, "_this", "VirtualMachine")
                            + "<consolidate>true</consolidate>"
                            "</RemoveAllSnapshots_Task>")}


def snapshot_rename(es: Esxi, snap: str, name: str, description: str) -> dict:
    es.call('<RenameSnapshot xmlns="urn:vim25">'
            + _moref(snap, "_this", "VirtualMachineSnapshot")
            + f"<name>{_x(check_name(name, 'snapshot name'))}</name>"
            + f"<description>{_x(description or '')}</description>"
            "</RenameSnapshot>")
    return {"done": True}


def _reconfig(es: Esxi, moid: str, spec: str) -> dict:
    return {"task": es.task('<ReconfigVM_Task xmlns="urn:vim25">'
                            + _moref(moid, "_this", "VirtualMachine")
                            + f"<spec>{spec}</spec></ReconfigVM_Task>")}


def set_resources(es: Esxi, moid: str, cpus: int | None = None,
                  cores_per_socket: int | None = None,
                  memory_mb: int | None = None,
                  notes: str | None = None) -> dict:
    """CPU, memory and notes in one reconfigure, fields in schema order:
    annotation, numCPUs, numCoresPerSocket, memoryMB."""
    spec = ""
    if notes is not None:
        spec += f"<annotation>{_x(notes[:4000])}</annotation>"
    if cpus is not None:
        if not 1 <= cpus <= 768:
            raise VirtError("between 1 and 768 vCPUs")
        spec += f"<numCPUs>{cpus}</numCPUs>"
    if cores_per_socket is not None:
        if cores_per_socket < 1 or (cpus and cpus % cores_per_socket):
            raise VirtError("cores per socket must divide the vCPU count")
        spec += f"<numCoresPerSocket>{cores_per_socket}</numCoresPerSocket>"
    if memory_mb is not None:
        if memory_mb < 4 or memory_mb % 4:
            raise VirtError("memory in MB, a multiple of 4")
        spec += f"<memoryMB>{memory_mb}</memoryMB>"
    if not spec:
        raise VirtError("nothing to change")
    return _reconfig(es, moid, spec)


def set_boot(es: Esxi, moid: str, enter_setup: bool | None = None,
             secure_boot: bool | None = None,
             firmware: str | None = None) -> dict:
    """bootOptions (enterBIOSSetup, efiSecureBootEnabled) and firmware, in
    schema order: bootOptions before firmware."""
    opts = ""
    if enter_setup is not None:
        opts += f"<enterBIOSSetup>{_b(enter_setup)}</enterBIOSSetup>"
    if secure_boot is not None:
        opts += f"<efiSecureBootEnabled>{_b(secure_boot)}</efiSecureBootEnabled>"
    spec = f"<bootOptions>{opts}</bootOptions>" if opts else ""
    if firmware is not None:
        if firmware not in ("bios", "efi"):
            raise VirtError("firmware is bios or efi")
        spec += f"<firmware>{firmware}</firmware>"
    if not spec:
        raise VirtError("nothing to change")
    return _reconfig(es, moid, spec)


def rename(es: Esxi, moid: str, name: str) -> dict:
    return {"task": es.task('<Rename_Task xmlns="urn:vim25">'
                            + _moref(moid, "_this", "VirtualMachine")
                            + f"<newName>{_x(check_name(name, 'VM name'))}"
                            "</newName></Rename_Task>")}


def destroy(es: Esxi, moid: str) -> dict:
    """Delete the VM and its files from the datastore."""
    return {"task": es.task('<Destroy_Task xmlns="urn:vim25">'
                            + _moref(moid, "_this", "VirtualMachine")
                            + "</Destroy_Task>")}


def unregister(es: Esxi, moid: str) -> dict:
    """Remove the VM from the inventory, leaving its files."""
    es.call('<UnregisterVM xmlns="urn:vim25">'
            + _moref(moid, "_this", "VirtualMachine") + "</UnregisterVM>")
    return {"done": True}


def _device_el(es: Esxi, moid: str, key: int):
    raw = es.raw("VirtualMachine", moid, ["config.hardware.device"])
    for el in list(raw.get("config.hardware.device") or []):
        if num(_text(el, "key")) == key:
            return el
    raise VirtError("that device is no longer on the VM")


def _set(el, name: str, value: str) -> None:
    k = _kid(el, name)
    if k is None:
        raise VirtError(f"the device has no {name} to change")
    for c in list(k):
        k.remove(c)
    k.text = value


def _change(op: str, device_xml: str, file_op: str = "") -> str:
    fo = f"<fileOperation>{file_op}</fileOperation>" if file_op else ""
    return (f"<deviceChange><operation>{op}</operation>{fo}"
            f"{device_xml}</deviceChange>")


def disk_extend(es: Esxi, moid: str, key: int, gib: float) -> dict:
    el = _device_el(es, moid, key)
    if obj(el).get("_type") != "VirtualDisk":
        raise VirtError("that device is not a disk")
    old = num(_text(el, "capacityInKB"), 0)
    new = int(round(float(gib) * 1048576))
    if new <= old:
        raise VirtError("a disk can only grow: give a size larger than "
                        f"{round(old / 1048576, 1)} GiB")
    _set(el, "capacityInKB", str(new))
    if _kid(el, "capacityInBytes") is not None:
        _set(el, "capacityInBytes", str(new * 1024))
    return _reconfig(es, moid, _change("edit", to_xml(el, "device")))


def _free_unit(vm: dict, ctrl: dict) -> int:
    used = {d["unit"] for d in vm["devices"] if d.get("controller") == ctrl["key"]}
    for u in range(0, 64 if not ctrl.get("scsi") else 16):
        if ctrl.get("scsi") and u == 7:
            continue
        if u not in used:
            return u
    raise VirtError("that controller has no free slot")


def disk_add(es: Esxi, moid: str, gib: float, datastore: str = "",
             thin: bool = True) -> dict:
    vm = vm_detail(es, moid)
    ctrl = next((c for c in vm["controllers"] if c.get("scsi")), None) or \
        next((c for c in vm["controllers"]
              if c["type"] in ("VirtualAHCIController", "VirtualNVMEController")),
             None)
    if not ctrl:
        raise VirtError("the VM has no disk controller to attach a disk to")
    unit = _free_unit(vm, ctrl)
    kb = int(round(float(gib) * 1048576))
    if kb < 1048576:
        raise VirtError("at least 1 GiB")
    ds = datastore or re.sub(r"^\[([^\]]+)\].*$", r"\1", vm["vmx"])
    dev = ('<device xsi:type="VirtualDisk"><key>-1</key>'
           '<backing xsi:type="VirtualDiskFlatVer2BackingInfo">'
           f"<fileName>{_x(ds_path(ds))}</fileName>"
           f"<diskMode>persistent</diskMode><thinProvisioned>{_b(thin)}"
           "</thinProvisioned></backing>"
           f"<controllerKey>{ctrl['key']}</controllerKey>"
           f"<unitNumber>{unit}</unitNumber>"
           f"<capacityInKB>{kb}</capacityInKB></device>")
    return _reconfig(es, moid, _change("add", dev, "create"))


def device_remove(es: Esxi, moid: str, key: int,
                  delete_file: bool = False) -> dict:
    el = _device_el(es, moid, key)
    kind = obj(el).get("_type", "")
    fo = "destroy" if (delete_file and kind == "VirtualDisk") else ""
    return _reconfig(es, moid, _change("remove", to_xml(el, "device"), fo))


def _net_backing(network: str) -> str:
    return ('<backing xsi:type="VirtualEthernetCardNetworkBackingInfo">'
            f"<deviceName>{_x(network)}</deviceName>"
            f'<network type="Network">{_x("HaNetwork-" + network)}</network>'
            "</backing>")


NIC_TYPES = {"vmxnet3": "VirtualVmxnet3", "e1000e": "VirtualE1000e",
             "e1000": "VirtualE1000"}


def nic_add(es: Esxi, moid: str, network: str, adapter: str = "vmxnet3") -> dict:
    t = NIC_TYPES.get(adapter)
    if not t:
        raise VirtError("adapter is vmxnet3, e1000e or e1000")
    dev = (f'<device xsi:type="{t}"><key>-1</key>' + _net_backing(network)
           + "<connectable><startConnected>true</startConnected>"
           "<allowGuestControl>true</allowGuestControl>"
           "<connected>true</connected></connectable>"
           "<addressType>generated</addressType></device>")
    return _reconfig(es, moid, _change("add", dev))


def nic_set(es: Esxi, moid: str, key: int, network: str | None = None,
            connected: bool | None = None) -> dict:
    el = _device_el(es, moid, key)
    if network is not None:
        b = _kid(el, "backing")
        idx = list(el).index(b)
        el.remove(b)
        from defusedxml.ElementTree import fromstring
        nb = fromstring(_net_backing(network).replace(
            'xsi:type="', 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:type="', 1))
        el.insert(idx, nb)
    if connected is not None:
        con = _kid(el, "connectable")
        if con is None:
            raise VirtError("that adapter cannot be connected or disconnected")
        _set(con, "connected", _b(connected))
        _set(con, "startConnected", _b(connected))
    return _reconfig(es, moid, _change("edit", to_xml(el, "device")))


def cd_set(es: Esxi, moid: str, key: int, iso: str = "") -> dict:
    """Insert a datastore ISO (`[ds] path.iso`), or eject when iso is empty."""
    el = _device_el(es, moid, key)
    if obj(el).get("_type") != "VirtualCdrom":
        raise VirtError("that device is not a CD/DVD drive")
    b = _kid(el, "backing")
    idx = list(el).index(b) if b is not None else 1
    if b is not None:
        el.remove(b)
    if iso:
        if not _ISO.match(iso) or ".." in iso:
            raise VirtError("choose an ISO on a datastore")
        nb_xml = ('<backing xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                  ' xsi:type="VirtualCdromIsoBackingInfo">'
                  f"<fileName>{_x(iso)}</fileName></backing>")
    else:
        nb_xml = ('<backing xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                  ' xsi:type="VirtualCdromRemotePassthroughBackingInfo">'
                  "<deviceName></deviceName><useAutoDetect>false</useAutoDetect>"
                  "<exclusive>false</exclusive></backing>")
    from defusedxml.ElementTree import fromstring
    el.insert(idx, fromstring(nb_xml))
    con = _kid(el, "connectable")
    if con is not None:
        powered = es.props("VirtualMachine", moid, ["runtime.powerState"]).get(
            "runtime.powerState") == "poweredOn"
        _set(con, "startConnected", _b(bool(iso)))
        _set(con, "connected", _b(bool(iso) and powered))
    return _reconfig(es, moid, _change("edit", to_xml(el, "device")))


# ── creating a VM ──────────────────────────────────────────────
FALLBACK_OS = [
    ("otherLinux64Guest", "Other Linux (64-bit)", "linuxGuest"),
    ("rhel9_64Guest", "Red Hat Enterprise Linux 9 (64-bit)", "linuxGuest"),
    ("rhel8_64Guest", "Red Hat Enterprise Linux 8 (64-bit)", "linuxGuest"),
    ("ubuntu64Guest", "Ubuntu Linux (64-bit)", "linuxGuest"),
    ("debian12_64Guest", "Debian GNU/Linux 12 (64-bit)", "linuxGuest"),
    ("windows2019srvNext_64Guest", "Microsoft Windows Server 2022 (64-bit)",
     "windowsGuest"),
    ("windows2019srv_64Guest", "Microsoft Windows Server 2019 (64-bit)",
     "windowsGuest"),
    ("windows11_64Guest", "Microsoft Windows 11 (64-bit)", "windowsGuest"),
    ("otherGuest64", "Other (64-bit)", "otherGuestFamily")]


def guest_os(es: Esxi) -> list[tuple]:
    """Every guest OS this host can create, newest first within a family —
    asked of the host, because the list changes with each ESXi release."""
    key = es.c.get("base_url", "")
    hit = _GUEST_OS.get(key)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    out = []
    try:
        resp = es.call('<QueryConfigOption xmlns="urn:vim25">'
                       + _moref(es.refs["envBrowser"], "_this",
                                "EnvironmentBrowser")
                       + "</QueryConfigOption>", timeout=40)
        rv = _kid(resp, "returnval")
        for g in _kids(rv, "guestOSDescriptor") if rv is not None else []:
            gid, name = _text(g, "id"), _text(g, "fullName")
            if gid and name and _text(g, "supportLevel") not in (
                    "deprecated", "unsupported", "techPreview"):
                out.append((gid, name, _text(g, "family")))
    except VirtError:
        out = []
    out = out or list(FALLBACK_OS)
    out.sort(key=lambda g: (g[2] != "linuxGuest", g[2], g[1]))
    _GUEST_OS[key] = (time.time(), out)
    return out


def create_vm(es: Esxi, spec: dict) -> dict:
    """A new VM: name, guest OS, CPUs, memory, one thin disk on a paravirtual
    SCSI controller, one VMXNET3 adapter, a SATA CD drive (with an ISO when
    one is chosen), UEFI or BIOS. Power-on is a separate step."""
    name = check_name(spec.get("name", ""), "VM name")
    ds = check_name(spec.get("datastore", ""), "datastore")
    cpus = num(spec.get("cpus"), 0)
    cps = num(spec.get("cores_per_socket"), 0) or cpus
    mem = num(spec.get("memory_mb"), 0)
    gib = float(spec.get("disk_gib") or 0)
    if not (1 <= cpus <= 128) or cps < 1 or cpus % cps:
        raise VirtError("vCPUs between 1 and 128; cores per socket must divide them")
    if mem < 256 or mem % 4:
        raise VirtError("at least 256 MB of memory, a multiple of 4")
    if gib < 1:
        raise VirtError("a disk of at least 1 GiB")
    guest = (spec.get("guest_id") or "otherLinux64Guest").strip()
    if not re.match(r"^[A-Za-z0-9_]{3,60}$", guest):
        raise VirtError("choose a guest OS from the list")
    firmware = "efi" if spec.get("firmware", "efi") == "efi" else "bios"
    network = (spec.get("network") or "").strip()
    iso = (spec.get("iso") or "").strip()
    if iso and (not _ISO.match(iso) or ".." in iso):
        raise VirtError("choose an ISO on a datastore")
    changes = [
        _change("add", '<device xsi:type="ParaVirtualSCSIController">'
                "<key>-100</key><busNumber>0</busNumber>"
                "<sharedBus>noSharing</sharedBus></device>"),
        _change("add", '<device xsi:type="VirtualDisk"><key>-101</key>'
                '<backing xsi:type="VirtualDiskFlatVer2BackingInfo">'
                f"<fileName>{_x(ds_path(ds))}</fileName>"
                "<diskMode>persistent</diskMode>"
                f"<thinProvisioned>{_b(spec.get('thin', True))}</thinProvisioned>"
                "</backing><controllerKey>-100</controllerKey>"
                f"<unitNumber>0</unitNumber><capacityInKB>{int(gib * 1048576)}"
                "</capacityInKB></device>", "create"),
        _change("add", '<device xsi:type="VirtualAHCIController"><key>-102</key>'
                "<busNumber>0</busNumber></device>"),
        _change("add", '<device xsi:type="VirtualCdrom"><key>-103</key>'
                + (('<backing xsi:type="VirtualCdromIsoBackingInfo">'
                    f"<fileName>{_x(iso)}</fileName></backing>") if iso else
                   ('<backing xsi:type="VirtualCdromRemotePassthroughBackingInfo">'
                    "<deviceName></deviceName><useAutoDetect>false</useAutoDetect>"
                    "<exclusive>false</exclusive></backing>"))
                + f"<connectable><startConnected>{_b(bool(iso))}</startConnected>"
                "<allowGuestControl>true</allowGuestControl>"
                "<connected>false</connected></connectable>"
                "<controllerKey>-102</controllerKey><unitNumber>0</unitNumber>"
                "</device>"),
    ]
    if network:
        changes.append(_change(
            "add", '<device xsi:type="VirtualVmxnet3"><key>-104</key>'
            + _net_backing(network)
            + "<connectable><startConnected>true</startConnected>"
            "<allowGuestControl>true</allowGuestControl>"
            "<connected>false</connected></connectable>"
            "<addressType>generated</addressType></device>"))
    cfg = (f"<name>{_x(name)}</name><guestId>{guest}</guestId>"
           + (f"<annotation>{_x(spec['notes'][:4000])}</annotation>"
              if spec.get("notes") else "")
           + f"<files><vmPathName>{_x(ds_path(ds))}</vmPathName></files>"
           + f"<numCPUs>{cpus}</numCPUs><numCoresPerSocket>{cps}"
           f"</numCoresPerSocket><memoryMB>{mem}</memoryMB>"
           + "".join(changes)
           + (f"<bootOptions><efiSecureBootEnabled>"
              f"{_b(bool(spec.get('secure_boot')) and firmware == 'efi')}"
              "</efiSecureBootEnabled></bootOptions>")
           + f"<firmware>{firmware}</firmware>")
    r = es.refs
    return {"task": es.task('<CreateVM_Task xmlns="urn:vim25">'
                            + _moref(r["vmFolder"], "_this", "Folder")
                            + f"<config>{cfg}</config>"
                            + _moref(r["pool"], "pool", "ResourcePool")
                            + "</CreateVM_Task>"), "name": name}


# ── the host ───────────────────────────────────────────────────
HOST_PATHS = [
    "name", "runtime.connectionState", "runtime.powerState",
    "runtime.inMaintenanceMode", "runtime.bootTime", "summary.hardware",
    "summary.quickStats.overallCpuUsage",
    "summary.quickStats.overallMemoryUsage", "summary.quickStats.uptime",
    "config.product", "config.network.portgroup", "config.network.vswitch",
    "config.network.pnic", "config.service", "datastore", "vm"]


def host_detail(es: Esxi) -> dict:
    hid = es.refs["host"]
    p = es.props("HostSystem", hid, HOST_PATHS)
    hw = p.get("summary.hardware") if isinstance(p.get("summary.hardware"), dict) else {}
    prod = p.get("config.product") if isinstance(p.get("config.product"), dict) else {}
    cores, mhz = num(hw.get("numCpuCores"), 0), num(hw.get("cpuMhz"), 0)
    mem = num(hw.get("memorySize"), 0)
    used = num(p.get("summary.quickStats.overallMemoryUsage"), 0)
    pgs = []
    for g in lst(dig(p, "config.network.portgroup", "HostPortGroup")):
        if isinstance(g, dict):
            pgs.append({"name": dig(g, "spec", "name"),
                        "vlan": num(dig(g, "spec", "vlanId"), 0),
                        "vswitch": dig(g, "spec", "vswitchName"),
                        "ports": len(lst(g.get("port"))),
                        "vm_ports": sum(1 for x in lst(g.get("port"))
                                        if isinstance(x, dict)
                                        and x.get("type") == "virtualMachine")})
    switches = []
    for s in lst(dig(p, "config.network.vswitch", "HostVirtualSwitch")):
        if isinstance(s, dict):
            switches.append({"name": s.get("name", ""),
                             "mtu": num(s.get("mtu")),
                             "ports": num(s.get("numPorts")),
                             "uplinks": [u.rsplit("-", 1)[-1]
                                         for u in lst(s.get("pnic"))]})
    nics = []
    for n in lst(dig(p, "config.network.pnic", "PhysicalNic")):
        if isinstance(n, dict):
            nics.append({"name": n.get("device", ""), "mac": n.get("mac", ""),
                         "speed": num(dig(n, "linkSpeed", "speedMb")),
                         "driver": n.get("driver", "")})
    services = []
    for s in lst(dig(p, "config.service", "service")):
        if isinstance(s, dict):
            services.append({"key": s.get("key", ""), "label": s.get("label", ""),
                             "running": flag(s.get("running")),
                             "policy": s.get("policy", ""),
                             "required": flag(s.get("required"))})
    dss = datastores(es, lst(dig(p, "datastore", "ManagedObjectReference")))
    return {
        "id": hid, "name": p.get("name", ""),
        "state": p.get("runtime.connectionState", ""),
        "power": p.get("runtime.powerState", ""),
        "maintenance": flag(p.get("runtime.inMaintenanceMode")),
        "booted": p.get("runtime.bootTime", ""),
        "uptime": virt._uptime(p.get("summary.quickStats.uptime")),
        "vendor": hw.get("vendor", ""), "model": hw.get("model", ""),
        "cpu_model": hw.get("cpuModel", ""), "sockets": num(hw.get("numCpuPkgs")),
        "cores": cores, "threads": num(hw.get("numCpuThreads")), "mhz": mhz,
        "cpu_pct": virt._pct(p.get("summary.quickStats.overallCpuUsage"),
                             cores * mhz),
        "mem_gib": round(mem / 1024 ** 3, 1),
        "mem_pct": virt._pct(used * 1024 ** 2, mem) if mem else None,
        "product": prod.get("fullName", ""), "version": prod.get("version", ""),
        "build": prod.get("build", ""),
        "portgroups": sorted(pgs, key=lambda g: g["name"].lower()),
        "vswitches": switches, "pnics": nics,
        "services": sorted(services, key=lambda s: s["label"].lower()),
        "datastores": dss,
        "vm_count": len(lst(dig(p, "vm", "ManagedObjectReference"))),
    }


def datastores(es: Esxi, moids: list[str] | None = None) -> list[dict]:
    if moids is None:
        moids = lst(dig(es.props("HostSystem", es.refs["host"], ["datastore"]),
                        "datastore", "ManagedObjectReference"))
    out = []
    for m, p in es.many("Datastore", moids, ["summary"]).items():
        s = p.get("summary") if isinstance(p.get("summary"), dict) else {}
        cap, free = num(s.get("capacity"), 0), num(s.get("freeSpace"), 0)
        out.append({"id": m, "name": s.get("name", ""), "type": s.get("type", ""),
                    "capacity_gib": round(cap / 1024 ** 3, 1),
                    "free_gib": round(free / 1024 ** 3, 1),
                    "used_pct": virt._pct(cap - free, cap),
                    "accessible": flag(s.get("accessible"))})
    return sorted(out, key=lambda d: d["name"].lower())


def networks(es: Esxi) -> list[str]:
    """Port group names a VM adapter can be put on."""
    p = es.props("HostSystem", es.refs["host"], ["config.network.portgroup"])
    return sorted({dig(g, "spec", "name") for g in
                   lst(dig(p, "config.network.portgroup", "HostPortGroup"))
                   if isinstance(g, dict) and dig(g, "spec", "name")},
                  key=str.lower)


def maintenance(es: Esxi, enter: bool) -> dict:
    hid = es.refs["host"]
    if enter:
        body = ('<EnterMaintenanceMode_Task xmlns="urn:vim25">'
                + _moref(hid, "_this", "HostSystem")
                + "<timeout>0</timeout></EnterMaintenanceMode_Task>")
    else:
        body = ('<ExitMaintenanceMode_Task xmlns="urn:vim25">'
                + _moref(hid, "_this", "HostSystem")
                + "<timeout>0</timeout></ExitMaintenanceMode_Task>")
    return {"task": es.task(body)}


def host_power(es: Esxi, op: str, force: bool = False) -> dict:
    m = {"reboot": "RebootHost_Task", "shutdown": "ShutdownHost_Task"}.get(op)
    if not m:
        raise VirtError(f"unknown host action {op!r}")
    return {"task": es.task(f'<{m} xmlns="urn:vim25">'
                            + _moref(es.refs["host"], "_this", "HostSystem")
                            + f"<force>{_b(force)}</force></{m}>")}


SERVICE_OPS = {"start": "StartService", "stop": "StopService",
               "restart": "RestartService"}


def service(es: Esxi, op: str, key: str) -> dict:
    m = SERVICE_OPS.get(op)
    if not m or not re.match(r"^[A-Za-z0-9_.-]{1,40}$", key or ""):
        raise VirtError("unknown service action")
    es.call(f'<{m} xmlns="urn:vim25">'
            + _moref(es.refs["serviceSystem"], "_this", "HostServiceSystem")
            + f"<id>{_x(key)}</id></{m}>")
    return {"done": True}


def service_policy(es: Esxi, key: str, policy: str) -> dict:
    if policy not in ("on", "off", "automatic") or not re.match(
            r"^[A-Za-z0-9_.-]{1,40}$", key or ""):
        raise VirtError("policy is on, off or automatic")
    es.call('<UpdateServicePolicy xmlns="urn:vim25">'
            + _moref(es.refs["serviceSystem"], "_this", "HostServiceSystem")
            + f"<id>{_x(key)}</id><policy>{policy}</policy>"
            "</UpdateServicePolicy>")
    return {"done": True}


def _pg_spec(name: str, vlan: int, vswitch: str) -> str:
    if not 0 <= vlan <= 4095:
        raise VirtError("a VLAN id between 0 and 4095 (4095 = all VLANs)")
    return (f"<portgrp><name>{_x(check_name(name, 'port group name'))}</name>"
            f"<vlanId>{vlan}</vlanId>"
            f"<vswitchName>{_x(check_name(vswitch, 'virtual switch'))}"
            "</vswitchName><policy/></portgrp>")


def portgroup_add(es: Esxi, name: str, vlan: int, vswitch: str) -> dict:
    es.call('<AddPortGroup xmlns="urn:vim25">'
            + _moref(es.refs["networkSystem"], "_this", "HostNetworkSystem")
            + _pg_spec(name, vlan, vswitch) + "</AddPortGroup>")
    return {"done": True}


def portgroup_update(es: Esxi, name: str, vlan: int, vswitch: str) -> dict:
    es.call('<UpdatePortGroup xmlns="urn:vim25">'
            + _moref(es.refs["networkSystem"], "_this", "HostNetworkSystem")
            + f"<pgName>{_x(check_name(name, 'port group name'))}</pgName>"
            + _pg_spec(name, vlan, vswitch) + "</UpdatePortGroup>")
    return {"done": True}


def portgroup_remove(es: Esxi, name: str) -> dict:
    es.call('<RemovePortGroup xmlns="urn:vim25">'
            + _moref(es.refs["networkSystem"], "_this", "HostNetworkSystem")
            + f"<pgName>{_x(check_name(name, 'port group name'))}</pgName>"
            "</RemovePortGroup>")
    return {"done": True}


# ── datastore files ────────────────────────────────────────────
def browse(es: Esxi, datastore: str, path: str = "") -> dict:
    """One folder of a datastore: sub-folders first, then files, with size and
    date. A search task, waited for (folders answer in well under a second)."""
    datastore = check_name(datastore, "datastore")
    path = check_path(path)
    t = es.task('<SearchDatastore_Task xmlns="urn:vim25">'
                + _moref(es.refs["browser"], "_this", "HostDatastoreBrowser")
                + f"<datastorePath>{_x(ds_path(datastore, path))}</datastorePath>"
                "<searchSpec><details><fileType>true</fileType>"
                "<fileSize>true</fileSize><modification>true</modification>"
                "<fileOwner>false</fileOwner></details>"
                "<sortFoldersFirst>true</sortFoldersFirst></searchSpec>"
                "</SearchDatastore_Task>")
    info = es.wait(t, 30)
    if info["state"] != "success":
        raise VirtError(info["error"] or "the datastore could not be read")
    raw = es.raw("Task", t, ["info.result"]).get("info.result")
    res = obj(raw) if raw is not None else {}
    files = []
    for f in lst(res.get("file") if isinstance(res, dict) else None):
        if not isinstance(f, dict):
            continue
        t_ = f.get("_type", "FileInfo")
        files.append({"name": f.get("path", ""),
                      "kind": {"FolderFileInfo": "folder",
                               "IsoImageFileInfo": "iso",
                               "VmDiskFileInfo": "disk",
                               "VmConfigFileInfo": "config",
                               "VmLogFileInfo": "log",
                               "VmNvramFileInfo": "nvram",
                               "VmSnapshotFileInfo": "snapshot"}.get(t_, "file"),
                      "size": num(f.get("fileSize"), 0),
                      "modified": f.get("modification", "")})
    files.sort(key=lambda f: (f["kind"] != "folder", f["name"].lower()))
    return {"datastore": datastore, "path": path, "files": files}


def isos(es: Esxi) -> list[str]:
    """Every .iso on every datastore, `[ds] path` — what a CD drive can take.
    Searched with the browser's recursive search, one task per datastore."""
    out = []
    for d in datastores(es):
        if not d["accessible"]:
            continue
        try:
            t = es.task('<SearchDatastoreSubFolders_Task xmlns="urn:vim25">'
                        + _moref(es.refs["browser"], "_this",
                                 "HostDatastoreBrowser")
                        + f"<datastorePath>{_x(ds_path(d['name']))}</datastorePath>"
                        "<searchSpec><query xsi:type=\"IsoImageFileQuery\"/>"
                        "<details><fileType>true</fileType><fileSize>false</fileSize>"
                        "<modification>false</modification>"
                        "<fileOwner>false</fileOwner></details>"
                        "<matchPattern>*.iso</matchPattern></searchSpec>"
                        "</SearchDatastoreSubFolders_Task>")
            info = es.wait(t, 30)
            if info["state"] != "success":
                continue
            raw = es.raw("Task", t, ["info.result"]).get("info.result")
            for res in lst(dig(obj(raw), "HostDatastoreBrowserSearchResults")
                           if raw is not None else None):
                folder = res.get("folderPath", "") if isinstance(res, dict) else ""
                for f in lst(res.get("file") if isinstance(res, dict) else None):
                    if isinstance(f, dict) and f.get("path", "").lower().endswith(".iso"):
                        out.append(_join(folder, f["path"]))
        except VirtError:
            continue
    return sorted(set(out), key=str.lower)


def _join(folder: str, name: str) -> str:
    """`[ds]` + `a.iso` -> `[ds] a.iso`; `[ds] ISO/` + `a.iso` -> `[ds] ISO/a.iso`."""
    folder = folder.rstrip()
    if folder.endswith("]"):
        return f"{folder} {name}"
    return f"{folder}{'' if folder.endswith('/') else '/'}{name}"


def mkdir(es: Esxi, datastore: str, path: str) -> dict:
    path = check_path(path)
    if not path:
        raise VirtError("name the folder")
    es.call('<MakeDirectory xmlns="urn:vim25">'
            + _moref(es.refs["fileManager"], "_this", "FileManager")
            + f"<name>{_x(ds_path(check_name(datastore, 'datastore'), path))}</name>"
            + _moref(es.refs["datacenter"], "datacenter", "Datacenter")
            + "<createParentDirectories>true</createParentDirectories>"
            "</MakeDirectory>")
    return {"done": True}


def delete_file(es: Esxi, datastore: str, path: str) -> dict:
    path = check_path(path)
    if not path:
        raise VirtError("refusing to delete a whole datastore")
    return {"task": es.task(
        '<DeleteDatastoreFile_Task xmlns="urn:vim25">'
        + _moref(es.refs["fileManager"], "_this", "FileManager")
        + f"<name>{_x(ds_path(check_name(datastore, 'datastore'), path))}</name>"
        + _moref(es.refs["datacenter"], "datacenter", "Datacenter")
        + "</DeleteDatastoreFile_Task>")}


def upload_target(es: Esxi, datastore: str, path: str) -> tuple[str, dict]:
    """(URL, headers) for an HTTP PUT of one file into a datastore: the host's
    /folder file service, authorised by this session's cookie."""
    path = check_path(path)
    if not path:
        raise VirtError("name the file")
    base = es.c["base_url"].rstrip("/")
    q = urllib.parse.urlencode({"dcPath": es.refs["dcName"] or "ha-datacenter",
                                "dsName": check_name(datastore, "datastore")})
    url = f"{base}/folder/{urllib.parse.quote(path)}?{q}"
    return url, {"Cookie": es.cookie, "Content-Type": "application/octet-stream"}


# ── console ────────────────────────────────────────────────────
def console_ticket(es: Esxi, moid: str) -> dict:
    """A one-use WebMKS ticket and the websocket it opens. The host answers
    with its own name (often localhost.localdomain), so the address is the
    connection's own."""
    resp = es.call('<AcquireTicket xmlns="urn:vim25">'
                   + _moref(moid, "_this", "VirtualMachine")
                   + "<ticketType>webmks</ticketType></AcquireTicket>")
    rv = _kid(resp, "returnval")
    ticket = _text(rv, "ticket")
    if not ticket:
        raise VirtError("the host gave no console ticket")
    u = urllib.parse.urlsplit(es.c["base_url"])
    # a number, never text: "443@elsewhere" would move the relay's target
    try:
        port = int(_text(rv, "port") or 443)
    except ValueError as e:
        raise VirtError("the host gave a console port that is not a number") from e
    if not 0 < port < 65536:
        raise VirtError("the host gave a console port that is not a port")
    scheme = "ws" if u.scheme == "http" else "wss"
    return {"url": f"{scheme}://{u.hostname}:{port}/ticket/{ticket}",
            "insecure": bool(es.c.get("skip_tls"))}
