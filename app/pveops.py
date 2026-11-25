"""Managing Proxmox VE from EnvMap: VMs and containers, their snapshots and
hardware, nodes, storage and ISOs, consoles.

The transport is provision.Proxmox (httpx through urlguard), built from the
hypervisor connection's API token: `PVEAPIToken=<user@realm!tokenid>=<secret>`.
Every write is a POST/PUT/DELETE the Proxmox API documents; long ones return a
task id (UPID) that virtops polls. Nothing here shells into a node.

TESTED AGAINST
    A fake Proxmox in tests/test_virt_manage.py that answers the documented
    shapes. No real Proxmox was reachable while this was written: the console's
    vncwebsocket is the one call known to differ between token and ticket
    auth, and the console page says so when it is refused.
"""
from __future__ import annotations

import re
import urllib.parse

import httpx

from . import provision
from .virt import VirtError

_NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SNAP = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")
_VOLID = re.compile(r"^[A-Za-z0-9_.-]{1,64}:[A-Za-z0-9_./ -]{1,240}$")
# what a CD/DVD drive may take: an ISO image on a storage, never another
# guest's disk volume (which a guest could then read)
_ISO = re.compile(r"^[A-Za-z0-9_.-]{1,64}:iso/[A-Za-z0-9_./ -]{1,236}\.iso$", re.I)
KINDS = ("qemu", "lxc")
QEMU_POWER = ("start", "shutdown", "stop", "reboot", "reset", "suspend", "resume")
LXC_POWER = ("start", "shutdown", "stop", "reboot", "suspend", "resume")
OS_TYPES = [("l26", "Linux 2.6 - 6.x kernel"), ("win11", "Windows 11 / Server 2022/2025"),
            ("win10", "Windows 10 / Server 2016/2019"), ("win8", "Windows 8 / Server 2012"),
            ("solaris", "Solaris"), ("other", "Other")]


def client(conn: dict) -> provision.Proxmox:
    if not (conn.get("username") and conn.get("token")):
        raise VirtError("this Proxmox connection has no API token")
    return provision.Proxmox(conn["base_url"],
                             token=f"{conn['username']}={conn['token']}",
                             insecure=bool(conn.get("skip_tls")))


def node_ok(node: str) -> str:
    if not _NODE.match(node or ""):
        raise VirtError("unknown node")
    return node


def vmid_ok(vmid) -> int:
    try:
        v = int(str(vmid))
    except ValueError:
        raise VirtError("unknown VM id") from None
    if not 100 <= v <= 999999999:
        raise VirtError("a VM id between 100 and 999999999")
    return v


def kind_ok(kind: str) -> str:
    if kind not in KINDS:
        raise VirtError("unknown guest type")
    return kind


def id_ok(v: str, what: str) -> str:
    if not _ID.match(v or ""):
        raise VirtError(f"unknown {what}")
    return v


def call(px: provision.Proxmox, method: str, path: str, data: dict | None = None,
         params: dict | None = None, timeout: float | None = None):
    """One API call; Proxmox's own message on failure."""
    px._login()
    try:
        r = px._c.request(method, path, data=data, params=params,
                          timeout=timeout or provision.HTTP_TIMEOUT)
    except httpx.HTTPError as e:
        raise VirtError(f"Proxmox did not answer: {provision._httperr(e)}") from e
    if r.status_code >= 400:
        msg = ""
        try:
            body = r.json() or {}
            errs = body.get("errors") or {}
            msg = body.get("message") or "; ".join(f"{k}: {v}" for k, v in errs.items())
        except ValueError:
            pass
        msg = (msg or r.reason_phrase or f"HTTP {r.status_code}").strip()
        if r.status_code in (401, 403) and "permission" not in msg.lower():
            msg = f"permission denied — {msg}"
        raise VirtError(f"Proxmox refused: {msg[:300]}")
    try:
        return (r.json() or {}).get("data")
    except ValueError:
        return None


def _base(node: str, kind: str, vmid) -> str:
    return f"/nodes/{node_ok(node)}/{kind_ok(kind)}/{vmid_ok(vmid)}"


def _opts(s: str) -> dict:
    """`virtio=AA:BB,bridge=vmbr0,tag=10` -> {"virtio": "AA:BB", ...}; a bare
    first item (a volume id) lands under "_"."""
    out: dict = {}
    for i, part in enumerate(str(s or "").split(",")):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
        elif i == 0:
            out["_"] = part
    return out


def _unopts(d: dict) -> str:
    first = [d["_"]] if d.get("_") else []
    return ",".join(first + [f"{k}={v}" for k, v in d.items() if k != "_"])


def _size_gib(s: str) -> float:
    m = re.match(r"^(\d+(?:\.\d+)?)([KMGT]?)$", str(s or ""))
    if not m:
        return 0.0
    n, u = float(m.group(1)), m.group(2)
    return round(n * {"K": 1 / 1048576, "M": 1 / 1024, "G": 1, "T": 1024, "": 1 / 1024 ** 3}[u], 1)


DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide|efidisk|tpmstate|rootfs|mp)\d*$")


# ── reading ────────────────────────────────────────────────────
def vm_detail(px, node: str, kind: str, vmid) -> dict:
    base = _base(node, kind, vmid)
    st = call(px, "GET", f"{base}/status/current") or {}
    cfg = call(px, "GET", f"{base}/config") or {}
    try:
        snaps = call(px, "GET", f"{base}/snapshot") or []
    except VirtError:
        snaps = []
    disks, nics, cds = [], [], []
    for k, v in sorted(cfg.items()):
        if not isinstance(v, str):
            continue
        if re.match(r"^net\d+$", k):
            o = _opts(v)
            model = next((m for m in ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3")
                          if m in o), kind == "lxc" and "veth" or "")
            nics.append({"key": k, "adapter": model, "mac": o.get(model) or o.get("hwaddr", ""),
                         "network": o.get("bridge", ""), "vlan": o.get("tag", ""),
                         "connected": o.get("link_down") != "1", "raw": v,
                         "name": o.get("name", "")})
        elif DISK_KEY.match(k) and "media=cdrom" in v:
            o = _opts(v)
            cds.append({"key": k, "iso": "" if o.get("_") in ("none", "cdrom") else o.get("_", "")})
        elif DISK_KEY.match(k):
            o = _opts(v)
            disks.append({"key": k, "file": o.get("_", ""), "gib": _size_gib(o.get("size", "")),
                          "mount": o.get("mp", "/" if k == "rootfs" else ""),
                          "resizable": not k.startswith(("efidisk", "tpmstate"))})
    ips = []
    if kind == "qemu" and st.get("status") == "running" and str(cfg.get("agent", "")).startswith("1"):
        try:
            got = call(px, "GET", f"{base}/agent/network-get-interfaces", timeout=6) or {}
            for i in (got.get("result") or []):
                for a in i.get("ip-addresses") or []:
                    ip = a.get("ip-address", "")
                    if ip and not ip.startswith(("127.", "::1", "fe80")):
                        ips.append(ip)
        except VirtError:
            pass
    elif kind == "lxc" and st.get("status") == "running":
        try:
            for i in call(px, "GET", f"{base}/interfaces") or []:
                ip = (i.get("inet") or "").split("/")[0]
                if ip and not ip.startswith("127."):
                    ips.append(ip)
        except VirtError:
            pass
    maxmem = st.get("maxmem") or 0
    snaplist = [{"id": s.get("name", ""), "name": s.get("name", ""),
                 "description": (s.get("description") or "").strip(),
                 "created": s.get("snaptime", ""), "parent": s.get("parent", ""),
                 "state": "with RAM" if s.get("vmstate") else ""}
                for s in snaps if s.get("name") and s.get("name") != "current"]
    current = next((s.get("parent", "") for s in snaps if s.get("name") == "current"), "")
    for s in snaplist:
        s["current"] = s["name"] == current
    return {
        "id": str(vmid), "node": node, "kind": kind,
        "name": cfg.get("name") or cfg.get("hostname") or f"{kind}-{vmid}",
        "power": st.get("status", ""),
        "state": {"running": "running", "stopped": "stopped",
                  "paused": "paused"}.get(st.get("qmpstatus") or st.get("status"),
                                          st.get("status", "")),
        "cpus": cfg.get("cores"), "sockets": cfg.get("sockets", 1),
        "memory_mb": cfg.get("memory"), "ostype": cfg.get("ostype", ""),
        "guest_os": dict(OS_TYPES).get(cfg.get("ostype", ""), {"debian": "Debian", "ubuntu": "Ubuntu",
                                       "centos": "CentOS", "alpine": "Alpine", "archlinux": "Arch Linux",
                                       "fedora": "Fedora", "opensuse": "openSUSE"}.get(cfg.get("ostype", ""),
                                                                                       cfg.get("ostype", ""))),
        "notes": cfg.get("description", ""), "onboot": str(cfg.get("onboot", "0")) == "1",
        "bios": cfg.get("bios", "seabios"), "agent": str(cfg.get("agent", "")).startswith("1"),
        "cpu_pct": round((st.get("cpu") or 0) * 100, 1) if st.get("status") == "running" else None,
        "mem_pct": round((st.get("mem") or 0) / maxmem * 100, 1) if maxmem and st.get("status") == "running" else None,
        "uptime": _uptime(st.get("uptime")), "ips": ips, "lock": cfg.get("lock", ""),
        "template": str(cfg.get("template", "0")) == "1",
        "disks": disks, "nics": nics, "cdroms": cds, "snapshots": snaplist,
    }


def _uptime(s) -> str:
    from .virt import _uptime as u
    return u(s)


def node_detail(px, node: str) -> dict:
    node = node_ok(node)
    st = call(px, "GET", f"/nodes/{node}/status") or {}
    cpu = st.get("cpuinfo") or {}
    mem = st.get("memory") or {}
    try:
        services = call(px, "GET", f"/nodes/{node}/services") or []
    except VirtError:
        services = []
    try:
        nets = call(px, "GET", f"/nodes/{node}/network") or []
    except VirtError:
        nets = []
    return {
        "name": node, "uptime": _uptime(st.get("uptime")),
        "cpu_pct": round((st.get("cpu") or 0) * 100, 1),
        "cpu_model": cpu.get("model", ""), "cores": cpu.get("cpus"),
        "sockets": cpu.get("sockets"),
        "mem_gib": round((mem.get("total") or 0) / 1024 ** 3, 1),
        "mem_pct": round((mem.get("used") or 0) / mem["total"] * 100, 1) if mem.get("total") else None,
        "product": st.get("pveversion", ""), "kernel": st.get("kversion", ""),
        "load": st.get("loadavg") or [],
        "services": sorted([{"key": s.get("service", s.get("name", "")),
                             "label": s.get("desc") or s.get("name", ""),
                             "running": s.get("state") == "running",
                             "policy": s.get("unit-state", "")}
                            for s in services], key=lambda s: s["key"]),
        "bridges": [{"name": n.get("iface", ""), "type": n.get("type", ""),
                     "active": bool(n.get("active")), "cidr": n.get("cidr", ""),
                     "ports": n.get("bridge_ports", ""),
                     "vlan_aware": bool(n.get("bridge_vlan_aware"))}
                    for n in nets if n.get("type") in ("bridge", "OVSBridge")],
        "storage": storages(px, node),
    }


def storages(px, node: str) -> list[dict]:
    out = []
    for s in call(px, "GET", f"/nodes/{node_ok(node)}/storage") or []:
        total = s.get("total") or 0
        out.append({"name": s.get("storage", ""), "type": s.get("type", ""),
                    "content": [c for c in (s.get("content") or "").split(",") if c],
                    "capacity_gib": round(total / 1024 ** 3, 1),
                    "free_gib": round((s.get("avail") or 0) / 1024 ** 3, 1),
                    "used_pct": round((s.get("used") or 0) / total * 100, 1) if total else None,
                    "accessible": bool(s.get("active", 1)) and bool(s.get("enabled", 1))})
    return sorted(out, key=lambda s: s["name"].lower())


def content(px, node: str, storage: str) -> list[dict]:
    out = []
    for c in call(px, "GET", f"/nodes/{node_ok(node)}/storage/{id_ok(storage, 'storage')}/content") or []:
        out.append({"volid": c.get("volid", ""), "name": c.get("volid", "").split("/", 1)[-1],
                    "content": c.get("content", ""), "size": c.get("size") or 0,
                    "format": c.get("format", ""), "created": c.get("ctime", "")})
    return sorted(out, key=lambda c: (c["content"], c["name"].lower()))


def isos(px, node: str) -> list[str]:
    out = []
    for s in storages(px, node):
        if "iso" in s["content"] and s["accessible"]:
            try:
                out += [c["volid"] for c in content(px, node, s["name"]) if c["content"] == "iso"]
            except VirtError:
                continue
    return sorted(out, key=str.lower)


def bridges(px, node: str) -> list[str]:
    try:
        return sorted(n.get("iface", "") for n in call(px, "GET", f"/nodes/{node_ok(node)}/network") or []
                      if n.get("type") in ("bridge", "OVSBridge"))
    except VirtError:
        return []


def tasks(px, node: str, vmid=None, limit: int = 25) -> list[dict]:
    params = {"limit": limit}
    if vmid:
        params["vmid"] = vmid_ok(vmid)
    out = []
    for t in call(px, "GET", f"/nodes/{node_ok(node)}/tasks", params=params) or []:
        out.append({"task": t.get("upid", ""), "what": (t.get("type") or "").replace("qm", "VM ").replace("vz", "CT "),
                    "entity": t.get("id", ""), "who": t.get("user", ""),
                    "state": "running" if not t.get("endtime") else ("success" if t.get("status") == "OK" else "error"),
                    "error": "" if t.get("status") in (None, "OK") else t.get("status", ""),
                    "started": t.get("starttime", ""), "finished": t.get("endtime", "")})
    return out


def task_info(px, node: str, upid: str) -> dict:
    if not re.match(r"^UPID:[A-Za-z0-9.:@!_-]+$", upid or ""):
        raise VirtError("unknown task")
    st = call(px, "GET", f"/nodes/{node_ok(node)}/tasks/{urllib.parse.quote(upid, safe='')}/status") or {}
    running = st.get("status") == "running"
    ok = st.get("exitstatus") == "OK"
    return {"task": upid, "state": "running" if running else ("success" if ok else "error"),
            "progress": None, "error": "" if running or ok else (st.get("exitstatus") or "failed"),
            "what": st.get("type", ""), "entity": st.get("id", "")}


def next_id(px) -> int:
    return int(call(px, "GET", "/cluster/nextid"))


# ── actions ────────────────────────────────────────────────────
def power(px, node, kind, vmid, op: str) -> dict:
    allowed = QEMU_POWER if kind == "qemu" else LXC_POWER
    if op not in allowed:
        raise VirtError(f"{op} is not available for this guest")
    return {"task": call(px, "POST", f"{_base(node, kind, vmid)}/status/{op}")}


def snapshot_create(px, node, kind, vmid, name: str, description: str = "",
                    memory: bool = False) -> dict:
    if not _SNAP.match(name or ""):
        raise VirtError("a snapshot name starts with a letter: letters, digits, - and _, up to 40")
    data = {"snapname": name, "description": description or ""}
    if memory and kind == "qemu":
        data["vmstate"] = 1
    return {"task": call(px, "POST", f"{_base(node, kind, vmid)}/snapshot", data)}


def snapshot_revert(px, node, kind, vmid, name: str) -> dict:
    if not _SNAP.match(name or ""):
        raise VirtError("unknown snapshot")
    return {"task": call(px, "POST", f"{_base(node, kind, vmid)}/snapshot/{name}/rollback")}


def snapshot_remove(px, node, kind, vmid, name: str) -> dict:
    if not _SNAP.match(name or ""):
        raise VirtError("unknown snapshot")
    return {"task": call(px, "DELETE", f"{_base(node, kind, vmid)}/snapshot/{name}")}


def _set_config(px, node, kind, vmid, data: dict) -> dict:
    method = "POST" if kind == "qemu" else "PUT"
    res = call(px, method, f"{_base(node, kind, vmid)}/config", data)
    return {"task": res} if isinstance(res, str) and res.startswith("UPID:") else {"done": True}


def set_resources(px, node, kind, vmid, cpus=None, sockets=None, memory_mb=None,
                  notes=None, onboot=None) -> dict:
    data: dict = {}
    if cpus is not None:
        if not 1 <= int(cpus) <= 512:
            raise VirtError("between 1 and 512 cores")
        data["cores"] = int(cpus)
    if sockets is not None and kind == "qemu":
        data["sockets"] = max(1, int(sockets))
    if memory_mb is not None:
        if int(memory_mb) < 16:
            raise VirtError("at least 16 MB of memory")
        data["memory"] = int(memory_mb)
    if notes is not None:
        data["description"] = notes[:8000]
    if onboot is not None:
        data["onboot"] = 1 if onboot else 0
    if not data:
        raise VirtError("nothing to change")
    return _set_config(px, node, kind, vmid, data)


def rename(px, node, kind, vmid, name: str) -> dict:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$", name or ""):
        raise VirtError("a name of letters, digits, dots and dashes (a DNS name)")
    return _set_config(px, node, kind, vmid, {"name" if kind == "qemu" else "hostname": name})


def disk_extend(px, node, kind, vmid, key: str, gib: float) -> dict:
    if not DISK_KEY.match(key or ""):
        raise VirtError("unknown disk")
    res = call(px, "PUT", f"{_base(node, kind, vmid)}/resize", {"disk": key, "size": f"{float(gib):g}G"})
    return {"task": res} if isinstance(res, str) and res.startswith("UPID:") else {"done": True}


def disk_add(px, node, kind, vmid, gib: float, storage: str) -> dict:
    if kind != "qemu":
        raise VirtError("add a mount point to a container in Proxmox's own form")
    id_ok(storage, "storage")
    cfg = call(px, "GET", f"{_base(node, kind, vmid)}/config") or {}
    slot = next(i for i in range(31) if f"scsi{i}" not in cfg)
    if float(gib) < 1:
        raise VirtError("at least 1 GiB")
    return _set_config(px, node, kind, vmid, {f"scsi{slot}": f"{storage}:{float(gib):g},discard=on"})


def device_remove(px, node, kind, vmid, key: str) -> dict:
    if not (re.match(r"^net\d+$", key or "") or DISK_KEY.match(key or "")):
        raise VirtError("unknown device")
    return _set_config(px, node, kind, vmid, {"delete": key})


def nic_add(px, node, kind, vmid, bridge: str, vlan: str = "", adapter: str = "virtio") -> dict:
    id_ok(bridge, "bridge")
    cfg = call(px, "GET", f"{_base(node, kind, vmid)}/config") or {}
    slot = next(i for i in range(32) if f"net{i}" not in cfg)
    if kind == "qemu":
        if adapter not in ("virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"):
            raise VirtError("unknown adapter model")
        val = f"{adapter},bridge={bridge}"
    else:
        val = f"name=eth{slot},bridge={bridge},ip=dhcp"
    if vlan:
        if not str(vlan).isdigit() or not 1 <= int(vlan) <= 4094:
            raise VirtError("a VLAN tag between 1 and 4094")
        val += f",tag={int(vlan)}"
    return _set_config(px, node, kind, vmid, {f"net{slot}": val})


def nic_set(px, node, kind, vmid, key: str, bridge: str | None = None,
            vlan: str | None = None, connected: bool | None = None) -> dict:
    if not re.match(r"^net\d+$", key or ""):
        raise VirtError("unknown adapter")
    cfg = call(px, "GET", f"{_base(node, kind, vmid)}/config") or {}
    if key not in cfg:
        raise VirtError("that adapter is no longer on the guest")
    o = _opts(cfg[key])
    if bridge is not None:
        o["bridge"] = id_ok(bridge, "bridge")
    if vlan is not None:
        if vlan in ("", "0"):
            o.pop("tag", None)
        elif str(vlan).isdigit() and 1 <= int(vlan) <= 4094:
            o["tag"] = str(int(vlan))
        else:
            raise VirtError("a VLAN tag between 1 and 4094, or none")
    if connected is not None:
        if connected:
            o.pop("link_down", None)
        else:
            o["link_down"] = "1"
    return _set_config(px, node, kind, vmid, {key: _unopts(o)})


def cd_set(px, node, kind, vmid, key: str, iso: str = "") -> dict:
    if kind != "qemu" or not DISK_KEY.match(key or ""):
        raise VirtError("unknown CD/DVD drive")
    if iso and not (_VOLID.match(iso) and _ISO.match(iso) and ".." not in iso):
        raise VirtError("choose an ISO from a storage")
    return _set_config(px, node, kind, vmid, {key: f"{iso or 'none'},media=cdrom"})


def cd_add(px, node, kind, vmid) -> dict:
    cfg = call(px, "GET", f"{_base(node, kind, vmid)}/config") or {}
    slot = next((f"ide{i}" for i in (2, 0, 1, 3) if f"ide{i}" not in cfg), None)
    if not slot:
        raise VirtError("no free IDE slot for a CD/DVD drive")
    return _set_config(px, node, kind, vmid, {slot: "none,media=cdrom"})


def destroy(px, node, kind, vmid) -> dict:
    return {"task": call(px, "DELETE", _base(node, kind, vmid),
                         params={"purge": 1, "destroy-unreferenced-disks": 1})}


def clone(px, node, vmid, name: str, target: str = "", full: bool = True,
          storage: str = "") -> dict:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$", name or ""):
        raise VirtError("a name of letters, digits, dots and dashes (a DNS name)")
    data: dict = {"newid": next_id(px), "name": name, "full": 1 if full else 0}
    if target:
        data["target"] = node_ok(target)
    if storage:
        data["storage"] = id_ok(storage, "storage")
    return {"task": call(px, "POST", f"{_base(node, 'qemu', vmid)}/clone", data),
            "new_id": data["newid"]}


def migrate(px, node, kind, vmid, target: str, online: bool = True) -> dict:
    data: dict = {"target": node_ok(target)}
    if kind == "qemu":
        if online:
            data["online"] = 1
        data["with-local-disks"] = 1
    else:
        data["restart"] = 1 if online else 0
    return {"task": call(px, "POST", f"{_base(node, kind, vmid)}/migrate", data)}


def create_vm(px, node: str, spec: dict) -> dict:
    node = node_ok(node)
    name = (spec.get("name") or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$", name):
        raise VirtError("a name of letters, digits, dots and dashes (a DNS name)")
    cores, sockets = int(spec.get("cpus") or 0), int(spec.get("sockets") or 1)
    mem, gib = int(spec.get("memory_mb") or 0), float(spec.get("disk_gib") or 0)
    if not 1 <= cores <= 512 or mem < 256 or gib < 1:
        raise VirtError("at least 1 core, 256 MB of memory and a 1 GiB disk")
    storage = id_ok(spec.get("storage", ""), "storage")
    bridge = (spec.get("network") or "").strip()
    ostype = spec.get("ostype") or "l26"
    if ostype not in dict(OS_TYPES):
        raise VirtError("choose an OS type from the list")
    iso = (spec.get("iso") or "").strip()
    if iso and not (_VOLID.match(iso) and _ISO.match(iso) and ".." not in iso):
        raise VirtError("choose an ISO from a storage")
    vmid = vmid_ok(spec.get("vmid") or next_id(px))
    data: dict = {"vmid": vmid, "name": name, "cores": cores, "sockets": sockets,
                  "memory": mem, "ostype": ostype, "scsihw": "virtio-scsi-single",
                  "scsi0": f"{storage}:{gib:g},iothread=1,discard=on",
                  "ide2": f"{iso or 'none'},media=cdrom", "agent": "1",
                  "boot": "order=scsi0;ide2" + (";net0" if bridge else "")}
    if bridge:
        data["net0"] = f"virtio,bridge={id_ok(bridge, 'bridge')}"
        if spec.get("vlan"):
            data["net0"] += f",tag={int(spec['vlan'])}"
    if spec.get("firmware", "efi") == "efi":
        data.update(bios="ovmf", machine="q35",
                    efidisk0=f"{storage}:1,efitype=4m,pre-enrolled-keys="
                             f"{1 if spec.get('secure_boot') else 0}")
    if spec.get("notes"):
        data["description"] = spec["notes"][:8000]
    if spec.get("onboot"):
        data["onboot"] = 1
    return {"task": call(px, "POST", f"/nodes/{node}/qemu", data), "new_id": vmid,
            "name": name}


def node_power(px, node: str, op: str) -> dict:
    if op not in ("reboot", "shutdown"):
        raise VirtError("unknown node action")
    call(px, "POST", f"/nodes/{node_ok(node)}/status", {"command": op})
    return {"done": True}


def service(px, node: str, op: str, key: str) -> dict:
    if op not in ("start", "stop", "restart") or not re.match(r"^[A-Za-z0-9_.@-]{1,60}$", key or ""):
        raise VirtError("unknown service action")
    return {"task": call(px, "POST", f"/nodes/{node_ok(node)}/services/{key}/{op}")}


def delete_content(px, node: str, storage: str, volid: str) -> dict:
    if not _VOLID.match(volid or ""):
        raise VirtError("unknown file")
    res = call(px, "DELETE", f"/nodes/{node_ok(node)}/storage/{id_ok(storage, 'storage')}"
                             f"/content/{urllib.parse.quote(volid, safe='')}")
    return {"task": res} if isinstance(res, str) and res.startswith("UPID:") else {"done": True}


def upload_target(conn: dict, node: str, storage: str) -> tuple[str, dict]:
    """(URL, headers) for a multipart POST of one ISO into a storage."""
    base = conn["base_url"].rstrip("/")
    if not base.endswith("/api2/json"):
        base += "/api2/json"
    url = f"{base}/nodes/{node_ok(node)}/storage/{id_ok(storage, 'storage')}/upload"
    return url, {"Authorization": f"PVEAPIToken={conn['username']}={conn['token']}"}


def console_ticket(px, conn: dict, node: str, kind: str, vmid) -> dict:
    """vncproxy -> the vncwebsocket URL, its headers, and the password noVNC
    sends (the ticket itself)."""
    base = _base(node, kind, vmid)
    got = call(px, "POST", f"{base}/vncproxy", {"websocket": 1}) or {}
    port, ticket = got.get("port"), got.get("ticket")
    if not (port and ticket):
        raise VirtError("Proxmox gave no console ticket")
    u = urllib.parse.urlsplit(conn["base_url"])
    q = urllib.parse.urlencode({"port": port, "vncticket": ticket})
    scheme = "ws" if u.scheme == "http" else "wss"
    return {"url": f"{scheme}://{u.hostname}:{u.port or 8006}/api2/json{base}/vncwebsocket?{q}",
            "headers": {"Authorization": f"PVEAPIToken={conn['username']}={conn['token']}"},
            "password": ticket, "insecure": bool(conn.get("skip_tls"))}
