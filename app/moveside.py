"""The two kinds of hypervisor as EnvMap Move sees them (vmmove drives them).

A side is one VM's place: a Proxmox node or a standalone ESXi host.

For the VM that moves (the source) a side reads what the VM is, reaches into
the guest, and adds and removes the transfer card. Into the guest means the
QEMU guest agent on Proxmox, and VMware Tools on ESXi with the guest's own
sign-in, typed for this move and kept in memory only for as long as it runs.

For the new VM (the target) it uploads this move's receiver CD, creates the VM
in the source's image (the same processors, memory, firmware, disk sizes and
network cards with their own addresses, plus a transfer card and the CD), starts
it, and once the system has arrived makes it an ordinary VM again: CD out,
transfer card out, its own disk first to start from.

THE SAME HYPERVISOR ON BOTH SIDES
    The target is laid out like the source device for device (Proxmox: the same
    configuration keys, so the same PCI addresses; ESXi: the same controllers in
    the same PCI slots and the same hardware version). The disk controllers can
    then stay attached through the move (`-keep auto`), whatever the root
    filesystem sits on. The engine's own pre-flight checks each kept
    controller is the same device at the same address before anything freezes.

ACROSS HYPERVISORS
    The controllers change type, so the engine holds the storage mappings and
    re-points them (`-repoint`): every mounted filesystem must then sit on
    device-mapper (LVM). vmmove checks that in the guest before it starts.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import math
import re
import secrets
import time
import urllib.parse
from xml.sax.saxutils import escape as _x

import httpx

from . import esxiops, pveops, urlguard, virt
from .virt import VirtError, _kid, _moref, _text

E = esxiops
P = pveops
CHUNK = 45 * 1024          # the guest agent writes at most 60 KiB of base64 per call
DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide)\d+$")
NET_KEY = re.compile(r"^net\d+$")
PVE_MODELS = ("virtio", "e1000", "e1000e", "vmxnet3", "rtl8139")
# what a Proxmox target copies from a Proxmox source as it is
PVE_COPY = ("cores", "sockets", "cpu", "memory", "balloon", "shares", "numa", "vcpus",
            "cpulimit", "cpuunits", "bios", "machine", "ostype", "scsihw",
            "vga", "serial0", "serial1", "serial2", "serial3", "agent", "tablet", "acpi",
            "kvm", "localtime", "smbios1", "vmgenid", "hotplug", "rng0", "watchdog",
            "keyboard", "tags", "startup", "onboot", "ciuser", "citype",
            "cicustom", "sshkeys", "nameserver", "searchdomain", "ipconfig0", "ipconfig1",
            "ipconfig2", "ipconfig3", "audio0", "spice_enhancements")
# not copied: cipassword (Proxmox shows it as asterisks), affinity and
# hugepages (they name what one host has), hookscript and args (host files)
DISK_OPTS = ("iothread", "discard", "ssd", "cache", "aio", "backup", "replicate",
             "serial", "wwn", "ro", "shared", "snapshot", "detect_zeroes", "queues",
             "product", "vendor", "rotational")
NIC_OPTS = ("queues", "mtu", "rate", "link_down", "firewall")
ESXI_NICS = ("VirtualVmxnet3", "VirtualE1000e", "VirtualE1000", "VirtualVmxnet2",
             "VirtualVmxnet", "VirtualPCNet32")
ESXI_CTRLS = ("ParaVirtualSCSIController", "VirtualLsiLogicSASController",
              "VirtualLsiLogicController", "VirtualBusLogicController",
              "VirtualAHCIController", "VirtualNVMEController")


def mac_ok(mac: str) -> str:
    m = (mac or "").strip().lower()
    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", m):
        raise VirtError(f"not a network card address: {mac!r}")
    return m


def new_mac(flavor: str) -> str:
    """An address for a transfer card. ESXi accepts a manual address only in
    VMware's own range (00:50:56:00-3F); Proxmox takes a locally administered
    one."""
    b = secrets.token_bytes(3)
    if flavor == "esxi":
        return "00:50:56:%02x:%02x:%02x" % (b[0] & 0x3F, b[1], b[2])
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(secrets.token_bytes(2) + b)


def sh_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


# ── Proxmox ────────────────────────────────────────────────────
class Pve:
    flavor = "proxmox"

    def __init__(self, conn: dict, node: str, vmid=None):
        self.conn, self.node = conn, P.node_ok(node)
        self.vmid = P.vmid_ok(vmid) if vmid not in (None, "") else None

    def api(self, method: str, path: str, data: dict | None = None,
            params: dict | None = None, timeout: float | None = None):
        with P.client(self.conn) as px:
            return P.call(px, method, path, data, params, timeout)

    @property
    def base(self) -> str:
        return f"/nodes/{self.node}/qemu/{self.vmid}"

    def wait(self, upid, limit: float = 1800) -> None:
        if not (isinstance(upid, str) and upid.startswith("UPID:")):
            return
        t0 = time.time()
        while time.time() - t0 < limit:
            st = self.api("GET", f"/nodes/{self.node}/tasks/{urllib.parse.quote(upid, safe='')}/status") or {}
            if st.get("status") == "stopped":
                if st.get("exitstatus") != "OK":
                    raise VirtError(f"Proxmox: {st.get('exitstatus') or 'the task failed'}")
                return
            time.sleep(1.5)
        raise VirtError("Proxmox did not finish the task in time")

    # what the VM is
    def config(self) -> dict:
        return self.api("GET", f"{self.base}/config") or {}

    def status(self) -> str:
        return (self.api("GET", f"{self.base}/status/current") or {}).get("status", "")

    def exists(self) -> bool:
        """Whether the node still has this VM, from the node's own list. A
        node that does not answer raises: that is not a no."""
        if self.vmid in (None, ""):
            return False
        return any(str(v.get("vmid")) == str(self.vmid) for v in self.api("GET", f"/nodes/{self.node}/qemu") or [])

    def facts(self) -> dict:
        cfg = self.config()
        st = self.api("GET", f"{self.base}/status/current") or {}
        disks, cds, nics, why = [], [], [], []
        off, off_notes = [], []                 # the same for a VM that is powered off
        for k, v in sorted(cfg.items()):
            if DISK_KEY.match(k):
                o = P._opts(v)
                if o.get("media") == "cdrom":
                    cds.append({"key": k, "volume": o.get("_", "")})
                    continue
                gib = P._size_gib(o.get("size", ""))
                disks.append({"key": k, "bytes": int(round(gib * 1024 ** 3)), "gib": gib,
                              "volume": o.get("_", ""),
                              "opts": {x: o[x] for x in DISK_OPTS if x in o}})
            elif NET_KEY.match(k):
                o = P._opts(v)
                model = next((m for m in PVE_MODELS if m in o), "")
                nics.append({"key": k, "mac": (o.get(model) or "").lower(), "model": model,
                             "network": o.get("bridge", ""), "vlan": o.get("tag", ""),
                             "opts": {x: o[x] for x in NIC_OPTS if x in o}})
            elif re.match(r"^(hostpci|usb|parallel)\d+$", k):
                why.append(f"{k} ({v[:60]}) is a device of this host that cannot move with it")
                off_notes.append(f"{k} ({v[:60]}) is a device of this host: the new VM is built without it")
        if cfg.get("template"):
            why.append("this is a template, not a running VM")
            off.append("this is a template, not a VM")
        if cfg.get("lock"):
            why.append(f"Proxmox has the VM locked ({cfg['lock']}): wait for that to finish")
            off.append(why[-1])
        if "tpmstate0" in cfg:
            why.append("its TPM holds keys that cannot be copied (a disk sealed to it would not open on the new VM)")
            off.append(why[-1])
        hot = (cfg.get("hotplug") or "network,disk,usb").split(",")
        if "network" not in hot and cfg.get("hotplug") != "1":
            why.append("network hot-plug is off for this VM (Options → Hotplug), so a transfer card cannot be added while it runs")
        sockets, cores = int(cfg.get("sockets") or 1), int(cfg.get("cores") or 1)
        return {"flavor": "proxmox", "name": cfg.get("name") or f"vm-{self.vmid}",
                "power": st.get("status", ""), "agent_on": str(cfg.get("agent", "0")).split(",")[0] in ("1", "enabled=1"),
                "cpus": int(cfg.get("vcpus") or sockets * cores), "sockets": sockets, "cores": cores,
                "memory_mb": int(cfg.get("memory") or 512),
                "firmware": "efi" if cfg.get("bios") == "ovmf" else "bios",
                "disks": disks, "cdroms": cds, "nics": nics, "blockers": why,
                "blockers_off": off, "notes_off": off_notes, "config": cfg}

    # into the guest: the QEMU guest agent
    def agent_ok(self) -> bool:
        try:
            self.api("POST", f"{self.base}/agent/ping", timeout=8)
            return True
        except VirtError:
            return False

    def exec(self, script: str, timeout: float = 300) -> tuple[int, str]:
        r = self.api("POST", f"{self.base}/agent/exec",
                     {"command": ["/bin/sh", "-c", script]}, timeout=30) or {}
        pid = r.get("pid")
        if pid is None:
            raise VirtError("the guest agent did not start the command")
        t0 = time.time()
        while time.time() - t0 < timeout:
            st = self.api("GET", f"{self.base}/agent/exec-status", params={"pid": pid}, timeout=20) or {}
            if st.get("exited"):
                out = (st.get("out-data") or "") + (st.get("err-data") or "")
                if st.get("signal"):                  # killed: never a success
                    return 128 + int(st.get("signal") or 9), out
                return int(st.get("exitcode") or 0), out
            time.sleep(0.7)
        raise VirtError("the guest command did not finish in time")

    def put(self, path: str, data: bytes) -> None:
        # pieces of an earlier, broken copy would be joined into this one
        self.exec(f"rm -f {path}.part*", 60)
        for i in range(0, len(data), CHUNK):
            self.api("POST", f"{self.base}/agent/file-write",
                     {"file": f"{path}.part{i // CHUNK:05d}",
                      "content": base64.b64encode(data[i:i + CHUNK]).decode(), "encode": 0}, timeout=60)
        code, out = self.exec(f"cat {path}.part* > {path} && rm -f {path}.part*", 120)
        if code:
            raise VirtError(f"could not put {path} in the guest: {out[-200:]}")

    # the transfer card on a running source
    def add_card(self, mac: str, network: str, vlan: str = "", model: str = "virtio") -> str:
        cfg = self.config()
        key = next(f"net{i}" for i in range(31, 0, -1) if f"net{i}" not in cfg)
        val = f"{model}={mac_ok(mac).upper()},bridge={P.id_ok(network, 'bridge')}"
        if str(vlan or "").strip():
            val += f",tag={int(vlan)}"
        self.wait(self.api("POST", f"{self.base}/config", {key: val}))
        now = self.api("GET", f"{self.base}/config", params={"current": 1}) or {}
        if key not in now:
            # left pending (not hot-plugged): take it back rather than leave a
            # change waiting for the VM's next start
            try:
                self.api("POST", f"{self.base}/config", {"revert": key})
            except VirtError:
                pass
            raise VirtError("Proxmox could not add the transfer card while the VM runs (hot-plug)")
        return key

    def remove_card(self, key: str) -> None:
        if NET_KEY.match(key or ""):
            self.wait(self.api("POST", f"{self.base}/config", {"delete": key}))

    def ha_managed(self) -> bool:
        for r in self.api("GET", "/cluster/ha/resources") or []:
            if str(r.get("sid", "")) in (f"vm:{self.vmid}", str(self.vmid)):
                return True
        return False

    def disconnect_cards(self) -> None:
        """Every network card's link down, so whatever starts this VM again
        finds it off the network."""
        cfg = self.api("GET", f"{self.base}/config", params={"current": 1}) or {}
        upd = {}
        for k, v in cfg.items():
            if NET_KEY.match(k) and "link_down=1" not in str(v):
                upd[k] = f"{v},link_down=1"
        if upd:
            self.wait(self.api("POST", f"{self.base}/config", upd))

    def set(self, values: dict) -> None:
        self.wait(self.api("POST", f"{self.base}/config", values))

    def stop(self) -> None:
        self.wait(self.api("POST", f"{self.base}/status/stop"), 300)

    def start(self) -> None:
        self.wait(self.api("POST", f"{self.base}/status/start"), 300)

    def reset(self) -> None:
        self.api("POST", f"{self.base}/status/reset")

    def destroy(self) -> None:
        if self.status() == "running":
            self.stop()
        self.wait(self.api("DELETE", self.base, params={"purge": 1, "destroy-unreferenced-disks": 1}))

    # the target
    def choices(self) -> dict:
        with P.client(self.conn) as px:
            st = P.storages(px, self.node)
            return {"networks": P.bridges(px, self.node),
                    "storages": [s for s in st if "images" in s["content"] and s["accessible"]],
                    "iso_storages": [s for s in st if "iso" in s["content"] and s["accessible"]]}

    def room(self) -> dict:
        n = self.api("GET", f"/nodes/{self.node}/status") or {}
        mem = n.get("memory") or {}
        return {"free_mb": int((mem.get("free") or 0) / 1048576), "cpus": int((n.get("cpuinfo") or {}).get("cpus") or 0)}

    def upload_iso(self, storage: str, name: str, data: bytes) -> str:
        url, headers = P.upload_target(self.conn, self.node, storage)
        r = httpx.post(urlguard.check(url), headers=headers, data={"content": "iso"},
                       files={"filename": (name, data, "application/octet-stream")},
                       verify=not self.conn.get("skip_tls"), timeout=600)
        if r.status_code >= 300:
            raise VirtError(f"Proxmox refused the receiver CD (HTTP {r.status_code}) {r.text[:160]}")
        try:
            self.wait((r.json() or {}).get("data"))
        except ValueError:
            pass
        return f"{storage}:iso/{name}"

    def delete_iso(self, volid: str) -> None:
        storage = volid.split(":", 1)[0]
        self.wait(self.api("DELETE", f"/nodes/{self.node}/storage/{P.id_ok(storage, 'storage')}"
                                     f"/content/{urllib.parse.quote(volid, safe='')}"))

    def create(self, spec: dict) -> str:
        """spec: the full configuration (vmmove.pve_spec); returns the VM id."""
        vmid = int(self.api("GET", "/cluster/nextid"))
        data = {"vmid": vmid, **spec}
        self.wait(self.api("POST", f"/nodes/{self.node}/qemu", data, timeout=120), 1800)
        self.vmid = vmid
        return str(vmid)


def pve_spec(src: dict, dst_flavor_from: str, *, name: str, storage: str, nets: list[dict],
             transfer: dict | None, iso: str | None) -> tuple[dict, dict]:
    """The new VM's Proxmox configuration, and where its CD and transfer card
    went ({"cd": key, "transfer": key, "boot": the order to restore}).

    With `iso` None the VM gets no receiver CD and no transfer card: the new
    VM of a powered-off move, which EnvMap never starts (coldside)."""
    spec: dict = {"name": name}
    disks = src["disks"]
    if dst_flavor_from == "proxmox":
        cfg = src["config"]
        for k in PVE_COPY:
            if k in cfg:
                spec[k] = cfg[k]
        if cfg.get("description"):
            spec["description"] = cfg["description"]
        if cfg.get("bios") == "ovmf":
            ef = P._opts(cfg.get("efidisk0", ""))
            # Secure Boot off: the receiver CD's boot loader is not signed for it.
            # A VM that never starts from that CD keeps what the source had.
            keys = "0" if iso is not None else ("1" if str(ef.get("pre-enrolled-keys", "0")) == "1" else "0")
            spec["efidisk0"] = f"{storage}:1,efitype={ef.get('efitype', '4m')},pre-enrolled-keys={keys}"
        for d in disks:
            spec[d["key"]] = _pve_disk(storage, d)
        for c in src["cdroms"]:
            # a cloud-init drive is made again on the new storage, so the guest
            # finds the same settings when it next starts; other drives empty
            spec[c["key"]] = f"{storage}:cloudinit" if "cloudinit" in (c.get("volume") or "") \
                else "none,media=cdrom"
        cd = next(k for k in ("ide2", "ide0", "ide1", "ide3", "sata0", "sata1", "sata2", "sata3", "sata4", "sata5")
                  if k not in spec and k not in cfg)
        for n, m in zip(src["nics"], nets):
            spec[n["key"]] = _pve_nic(n["model"] or "virtio", n["mac"], m, n.get("opts"))
        boot_after = cfg.get("boot") or "order=" + ";".join(d["key"] for d in disks)
    else:
        sockets = max(1, src["cpus"] // max(1, src["cores"]))
        spec.update(cores=max(1, src["cores"]), sockets=sockets, memory=src["memory_mb"],
                    ostype="l26", scsihw="virtio-scsi-single", machine="q35", cpu="host",
                    agent="1", balloon=0)
        if src["firmware"] == "efi":
            spec.update(bios="ovmf", efidisk0=f"{storage}:1,efitype=4m,pre-enrolled-keys=0")
        for i, d in enumerate(disks):
            spec[f"scsi{i}"] = _pve_disk(storage, {"bytes": d["bytes"], "opts": {"iothread": "1", "discard": "on"}})
        cd = "ide2"
        for i, (n, m) in enumerate(zip(src["nics"], nets)):
            spec[f"net{i}"] = _pve_nic("virtio", n["mac"], m, {})
        boot_after = "order=" + ";".join(f"scsi{i}" for i in range(len(disks)))
    if iso is None:
        spec["boot"] = boot_after
        spec["onboot"] = 0                   # set as the source had it once the copy is confirmed
        return spec, {"cd": "", "transfer": "", "boot": boot_after,
                      "onboot": (src.get("config") or {}).get("onboot", 0)}
    if dst_flavor_from != "proxmox" and cd in spec:
        cd = "ide0"
    spec[cd] = f"{iso},media=cdrom"
    tkey = next(f"net{i}" for i in range(31, 0, -1) if f"net{i}" not in spec)
    spec[tkey] = _pve_nic("virtio", transfer["dst_mac"],
                          {"network": transfer["dst_net"], "vlan": transfer.get("dst_vlan", "")}, {})
    spec["boot"] = f"order={cd}"
    spec["onboot"] = 0                       # set as the source had it once the move is done
    return spec, {"cd": cd, "transfer": tkey, "boot": boot_after,
                  "onboot": (src.get("config") or {}).get("onboot", 0)}


def _pve_disk(storage: str, d: dict) -> str:
    gib = d["bytes"] / 1024 ** 3
    size = f"{gib:g}" if abs(gib - round(gib)) < 1e-9 else f"{math.ceil(gib * 1024) / 1024:.4f}".rstrip("0")
    opts = "".join(f",{k}={v}" for k, v in (d.get("opts") or {}).items())
    return f"{P.id_ok(storage, 'storage')}:{size}{opts}"


def _pve_nic(model: str, mac: str, m: dict, opts: dict | None) -> str:
    if model not in PVE_MODELS:
        model = "virtio"
    val = f"{model}={mac_ok(mac).upper()},bridge={P.id_ok(m['network'], 'bridge')}"
    if str(m.get("vlan") or "").strip():
        v = int(m["vlan"])
        if not 1 <= v <= 4094:
            raise VirtError("a VLAN tag between 1 and 4094")
        val += f",tag={v}"
    for k, v in (opts or {}).items():
        if k != "link_down":
            val += f",{k}={v}"
    return val


# ── ESXi ───────────────────────────────────────────────────────
class Esxi:
    """An ESXi host with a licence whose API takes changes. A host on the free
    licence, where the API only reads, is esxshell.EsxiShell: the same
    interface, through the host's shell and SSH to the guest."""
    flavor = "esxi"
    road = "api"

    def __init__(self, conn: dict, moid: str | None = None, guest_user: str = "",
                 guest_password: str = ""):
        self.conn = conn
        self.moid = moid
        self.user, self.password = guest_user, guest_password
        self._es = None
        self._gom: dict = {}

    @property
    def es(self) -> E.Esxi:
        if self._es is None:
            self._es = E.Esxi(self.conn)
        return self._es

    def status(self) -> str:
        p = self.es.props("VirtualMachine", self.moid, ["runtime.powerState"])
        return {"poweredOn": "running", "poweredOff": "stopped",
                "suspended": "suspended"}.get(p.get("runtime.powerState", ""), "")

    def exists(self) -> bool:
        """Whether the host still has this VM. A host that cannot be read
        raises: that is not a no."""
        if not self.moid:
            return False
        try:
            self.es.props("VirtualMachine", self.moid, ["runtime.powerState"])
        except VirtError as e:
            if getattr(e, "fault", "") == "ManagedObjectNotFound":
                return False
            raise
        return True

    def raw_devices(self) -> list:
        return list(self.es.raw("VirtualMachine", self.moid, ["config.hardware.device"])
                    .get("config.hardware.device") or [])

    def facts(self) -> dict:
        d = E.vm_detail(self.es, self.moid)
        raw = {E.num(_text(el, "key")): E.obj(el) for el in self.raw_devices()}
        ctrls = {c["key"]: c for c in d["controllers"]}
        disks, nics, why = [], [], []
        off, off_notes = [], []                 # the same for a VM that is powered off
        for x in d["disks"]:
            c = ctrls.get(x["controller"]) or {}
            disks.append({"key": x["key"], "bytes": int(x.get("kb") or 0) * 1024,
                          "gib": x["gib"], "ctrl": c.get("type", ""), "bus": c.get("bus"),
                          "unit": x.get("unit"), "ctrl_key": x["controller"], "file": x.get("file") or ""})
            if (x.get("mode") or "").startswith("independent") or "rdm" in (x.get("file") or "").lower():
                why.append(f"{x['label']} is an independent or raw disk")
            if "rdm" in (x.get("file") or "").lower():
                off.append(f"{x['label']} is a raw device of this host, not a disk file that can be copied")
        for n in d["nics"]:
            r = raw.get(n["key"]) or {}
            nics.append({"key": n["key"], "mac": (n.get("mac") or "").lower(),
                         "model": n["type"], "network": n.get("network", ""), "vlan": "",
                         "slot": E.num(E.dig(r, "slotInfo", "pciSlotNumber"))})
        for k, r in raw.items():
            t = r.get("_type", "") if isinstance(r, dict) else ""
            if t in ("VirtualPCIPassthrough", "VirtualUSB", "VirtualParallelPort"):
                why.append(f"{t.removeprefix('Virtual')} cannot move with the VM")
                off_notes.append(f"{t.removeprefix('Virtual')} is a device of this host: the new VM is built without it")
        if d.get("template"):
            why.append("this is a template, not a running VM")
            off.append("this is a template, not a VM")
        if d.get("snapshots"):
            why.append("it has snapshots: remove them first (their disks would not move)")
            off_notes.append("it has snapshots: the new VM gets the disks as they are now; the snapshots stay "
                             "with the old copy")
        cpus = d.get("cpus") or 1
        return {"flavor": "esxi", "name": d.get("name", ""),
                "power": {"poweredOn": "running", "poweredOff": "stopped"}.get(d.get("power"), d.get("power")),
                "tools": d.get("tools", ""), "cpus": cpus,
                "cores": d.get("cores_per_socket") or cpus, "sockets": cpus // max(1, d.get("cores_per_socket") or cpus),
                "memory_mb": d.get("memory_mb") or 512, "firmware": d.get("firmware") or "bios",
                "guest_id": d.get("guest_id", ""), "hw_version": d.get("hw_version", ""),
                "datastore": re.sub(r"^\[([^\]]+)\].*$", r"\1", d.get("vmx", "")),
                "disks": disks, "cdroms": d["cdroms"], "nics": nics, "blockers": why,
                "blockers_off": off, "notes_off": off_notes,
                "controllers": [{"key": c["key"], "type": c["type"], "bus": c.get("bus"),
                                 "slot": E.num(E.dig(raw.get(c["key"]) or {}, "slotInfo", "pciSlotNumber")),
                                 "shared": E.dig(raw.get(c["key"]) or {}, "sharedBus") or "noSharing"}
                                for c in d["controllers"] if c["type"] in ESXI_CTRLS]}

    # into the guest: VMware Tools guest operations, with the guest's sign-in
    def _gops(self) -> dict:
        if not self._gom:
            rv = _kid(self.es.call('<RetrieveServiceContent xmlns="urn:vim25">'
                                   '<_this type="ServiceInstance">ServiceInstance</_this>'
                                   '</RetrieveServiceContent>'), "returnval")
            gom = _text(rv, "guestOperationsManager")
            if not gom:
                raise VirtError("this host offers no guest operations")
            p = self.es.props("GuestOperationsManager", gom, ["processManager", "fileManager"])
            self._gom = {"proc": p.get("processManager", ""), "file": p.get("fileManager", "")}
        return self._gom

    def _auth(self) -> str:
        if not self.user:
            raise VirtError("the guest's own sign-in is needed to reach into an ESXi guest")
        return ('<auth xsi:type="NamePasswordAuthentication"><interactiveSession>false'
                f"</interactiveSession><username>{_x(self.user)}</username>"
                f"<password>{_x(self.password)}</password></auth>")

    def agent_ok(self) -> bool:
        try:
            p = self.es.props("VirtualMachine", self.moid, ["guest.toolsRunningStatus", "guestHeartbeatStatus"])
        except VirtError:
            return False
        return p.get("guest.toolsRunningStatus") == "guestToolsRunning" and \
            p.get("guestHeartbeatStatus") in ("green", "yellow")

    def _fixhost(self, url: str) -> str:
        """ESXi names the guest-file URL's host as `*` (or by its own name):
        it is always sent to the connection's own host and port."""
        base = urllib.parse.urlsplit(self.conn["base_url"])
        got = urllib.parse.urlsplit(url)
        if not got.path.startswith("/guestFile"):
            raise VirtError("the host answered with an unexpected file address")
        return urlguard.check(urllib.parse.urlunsplit(
            (base.scheme or "https", base.netloc, got.path, got.query, "")))

    def put(self, path: str, data: bytes) -> None:
        g = self._gops()
        url = self.es.returnval(
            '<InitiateFileTransferToGuest xmlns="urn:vim25">'
            + _moref(g["file"], "_this", "GuestFileManager")
            + _moref(self.moid, "vm", "VirtualMachine") + self._auth()
            + f"<guestFilePath>{_x(path)}</guestFilePath>"
            '<fileAttributes xsi:type="GuestPosixFileAttributes"/>'
            f"<fileSize>{len(data)}</fileSize><overwrite>true</overwrite>"
            "</InitiateFileTransferToGuest>")
        r = httpx.put(urlguard.check(self._fixhost(url)), content=data, verify=not self.conn.get("skip_tls"), timeout=600)
        if r.status_code >= 300:
            raise VirtError(f"the guest refused the file (HTTP {r.status_code})")

    def get(self, path: str, limit: int = 1 << 20) -> bytes:
        g = self._gops()
        rv = _kid(self.es.call(
            '<InitiateFileTransferFromGuest xmlns="urn:vim25">'
            + _moref(g["file"], "_this", "GuestFileManager")
            + _moref(self.moid, "vm", "VirtualMachine") + self._auth()
            + f"<guestFilePath>{_x(path)}</guestFilePath></InitiateFileTransferFromGuest>"), "returnval")
        url = _text(rv, "url")
        if not url:
            raise VirtError("the guest did not hand the file over")
        r = httpx.get(urlguard.check(self._fixhost(url)), verify=not self.conn.get("skip_tls"), timeout=120)
        if r.status_code >= 300:
            raise VirtError(f"the guest did not hand the file over (HTTP {r.status_code})")
        return r.content[:limit]

    def exec(self, script: str, timeout: float = 300) -> tuple[int, str]:
        """The script runs as root: directly when signed in as root, otherwise
        through sudo without a password (which the user must have)."""
        g = self._gops()
        tag = secrets.token_hex(6)
        sp, op = f"/tmp/envmove-{tag}.sh", f"/tmp/envmove-{tag}.out"
        self.put(sp, f"exec > {op} 2>&1\n{script}\n".encode())
        prog, args = ("/bin/sh", sp) if self.user == "root" else ("/usr/bin/sudo", f"-n /bin/sh {sp}")
        pid = self.es.returnval(
            '<StartProgramInGuest xmlns="urn:vim25">'
            + _moref(g["proc"], "_this", "GuestProcessManager")
            + _moref(self.moid, "vm", "VirtualMachine") + self._auth()
            + f'<spec xsi:type="GuestProgramSpec"><programPath>{prog}</programPath>'
            f"<arguments>{_x(args)}</arguments></spec></StartProgramInGuest>")
        t0, code = time.time(), None
        while time.time() - t0 < timeout:
            rv = _kid(self.es.call(
                '<ListProcessesInGuest xmlns="urn:vim25">'
                + _moref(g["proc"], "_this", "GuestProcessManager")
                + _moref(self.moid, "vm", "VirtualMachine") + self._auth()
                + f"<pids>{_x(pid)}</pids></ListProcessesInGuest>"), "returnval")
            if rv is not None and _text(rv, "endTime"):
                code = E.num(_text(rv, "exitCode"), 1)
                break
            time.sleep(1)
        if code is None:
            raise VirtError("the guest command did not finish in time")
        try:
            out = self.get(op).decode(errors="replace")
        except VirtError:
            out = ""
        self._start_quiet(f"rm -f {sp} {op}")
        return code, out

    def _start_quiet(self, cmd: str) -> None:
        try:
            g = self._gops()
            prog, args = ("/bin/sh", f"-c {sh_quote(cmd)}") if self.user == "root" else \
                ("/usr/bin/sudo", f"-n /bin/sh -c {sh_quote(cmd)}")
            self.es.returnval('<StartProgramInGuest xmlns="urn:vim25">'
                              + _moref(g["proc"], "_this", "GuestProcessManager")
                              + _moref(self.moid, "vm", "VirtualMachine") + self._auth()
                              + f'<spec xsi:type="GuestProgramSpec"><programPath>{prog}</programPath>'
                              f"<arguments>{_x(args)}</arguments></spec></StartProgramInGuest>")
        except VirtError:
            pass

    # the transfer card on a running source
    def add_card(self, mac: str, network: str, vlan: str = "", model: str = "vmxnet3") -> str:
        before = {d["key"] for d in E.vm_detail(self.es, self.moid)["nics"]}
        dev = ('<device xsi:type="VirtualVmxnet3"><key>-1</key>' + E._net_backing(E.check_name(network, "network"))
               + "<connectable><startConnected>true</startConnected><allowGuestControl>true</allowGuestControl>"
               f"<connected>true</connected></connectable><addressType>manual</addressType>"
               f"<macAddress>{mac_ok(mac)}</macAddress></device>")
        self._wait(E._reconfig(self.es, self.moid, E._change("add", dev)))
        after = [d for d in E.vm_detail(self.es, self.moid)["nics"] if d["key"] not in before]
        if not after:
            raise VirtError("the host did not add the transfer card")
        return str(after[0]["key"])

    def remove_card(self, key) -> None:
        self._wait(E.device_remove(self.es, self.moid, int(key)))

    def _wait(self, out: dict, limit: float = 600) -> None:
        t = (out or {}).get("task")
        if not t:
            return
        info = self.es.wait(t, limit)
        if info["state"] != "success":
            raise VirtError(f"ESXi: {info.get('error') or info['state']}")

    def stop(self) -> None:
        self._wait(E.power(self.es, self.moid, "off"))

    def start(self) -> None:
        self._wait(E.power(self.es, self.moid, "on"))

    def reset(self) -> None:
        E.power(self.es, self.moid, "reset")

    def rename(self, name: str) -> None:
        self._wait(E.rename(self.es, self.moid, name))

    def disconnect_cards(self) -> None:
        """Every network card disconnected and not connected at power-on, so
        whatever starts this VM again (the host's autostart list, a person)
        finds it off the network."""
        for n in E.vm_detail(self.es, self.moid)["nics"]:
            self._wait(E.nic_set(self.es, self.moid, n["key"], connected=False))

    def boot_disk_first(self) -> None:
        disks = E.vm_detail(self.es, self.moid)["disks"]
        if not disks:
            return
        spec = ('<spec><bootOptions><bootOrder xsi:type="VirtualMachineBootOptionsBootableDiskDevice">'
                f"<deviceKey>{int(disks[0]['key'])}</deviceKey></bootOrder></bootOptions></spec>")
        self._wait({"task": self.es.task('<ReconfigVM_Task xmlns="urn:vim25">'
                                         + _moref(self.moid, "_this", "VirtualMachine") + spec
                                         + "</ReconfigVM_Task>")})

    def destroy(self) -> None:
        if self.status() == "running":
            self.stop()
        self._wait(E.destroy(self.es, self.moid))

    # the target
    def choices(self) -> dict:
        return {"networks": E.networks(self.es),
                "storages": [{"name": d["name"], "free_gib": d.get("free_gib"),
                              "capacity_gib": d.get("capacity_gib")}
                             for d in E.datastores(self.es) if d["accessible"]]}

    def room(self) -> dict:
        h = E.host_detail(self.es)
        total = float(h.get("mem_gib") or 0) * 1024
        return {"free_mb": int(total * (1 - float(h.get("mem_pct") or 0) / 100)),
                "cpus": int(h.get("cores") or 0)}

    def upload_iso(self, datastore: str, name: str, data: bytes) -> str:
        url, headers = E.upload_target(self.es, datastore, f"envmove/{name}")
        headers["Content-Length"] = str(len(data))
        r = httpx.put(urlguard.check(url), headers=headers, content=data,
                      verify=not self.conn.get("skip_tls"), timeout=600)
        if r.status_code >= 300:
            raise VirtError(f"the host refused the receiver CD (HTTP {r.status_code})")
        return E.ds_path(datastore, f"envmove/{name}")

    def delete_iso(self, path: str) -> None:
        m = re.match(r"^\[([^\]]+)\] (.+)$", path or "")
        if m:
            self._wait(E.delete_file(self.es, m.group(1), m.group(2)))

    def create(self, cfg_xml: str) -> str:
        r = self.es.refs
        task = self.es.task('<CreateVM_Task xmlns="urn:vim25">'
                            + _moref(r["vmFolder"], "_this", "Folder")
                            + f"<config>{cfg_xml}</config>"
                            + _moref(r["pool"], "pool", "ResourcePool") + "</CreateVM_Task>")
        info = self.es.wait(task, 600)
        if info["state"] != "success":
            raise VirtError(f"ESXi did not create the VM: {info.get('error') or info['state']}")
        moid = info.get("result") or ""
        if not moid:
            raise VirtError("ESXi created the VM but did not say which")
        self.moid = moid
        return moid

    def device_keys(self) -> dict:
        d = E.vm_detail(self.es, self.moid)
        return {"cdroms": [c["key"] for c in d["cdroms"]],
                "nics": {n["mac"].lower(): n["key"] for n in d["nics"]}}

    def build(self, src: dict, *, name: str, datastore: str, nets: list[dict], transfer: dict,
              iso: str) -> dict:
        """The new VM, in the source's image: {"vm", "cd", "tcard"}."""
        self.create(esxi_spec(src, name=name, datastore=datastore, nets=nets, transfer=transfer, iso=iso))
        try:
            keys = self.device_keys()
        except Exception:
            try:
                self.destroy()
            except VirtError:
                pass
            raise
        return {"vm": self.moid, "cd": (keys["cdroms"] or [""])[0],
                "tcard": keys["nics"].get(mac_ok(transfer["dst_mac"]), "")}

    def cd_out(self, key) -> None:
        if str(key or "").strip():
            self._wait(E.cd_set(self.es, self.moid, int(key), ""))


def esxi_spec(src: dict, *, name: str, datastore: str, nets: list[dict], transfer: dict | None,
              iso: str | None) -> str:
    """The new VM's ESXi configuration (ConfigSpec XML). From an ESXi source:
    the same controllers in the same PCI slots, the same hardware version.
    From Proxmox: one paravirtual SCSI controller and VMXNET3 cards.

    With `iso` None the VM gets an empty CD drive, no transfer card, and
    starts from its disk: the new VM of a powered-off move, which EnvMap
    never starts (coldside)."""
    ds = E.check_name(datastore, "datastore")
    cps = max(1, int(src.get("cores") or src["cpus"]))
    cpus = int(src["cpus"])
    if cpus % cps:
        cps = 1
    changes, key = [], -200
    if src["flavor"] == "esxi":
        ctrl_keys = {}
        for c in src["controllers"]:
            key -= 1
            ctrl_keys[c["key"]] = key
            slot = f"<slotInfo xsi:type=\"VirtualDevicePciBusSlotInfo\"><pciSlotNumber>{c['slot']}</pciSlotNumber></slotInfo>" \
                if c.get("slot") is not None else ""
            shared = f"<sharedBus>{_x(c['shared'])}</sharedBus>" if c["type"] not in ("VirtualAHCIController", "VirtualNVMEController") else ""
            changes.append(E._change("add", f'<device xsi:type="{c["type"]}"><key>{key}</key>{slot}'
                                            f"<busNumber>{int(c.get('bus') or 0)}</busNumber>{shared}</device>"))
        disk_where = [(ctrl_keys.get(d["ctrl_key"]), d.get("unit") or 0) for d in src["disks"]]
        if any(k is None for k, _ in disk_where):
            raise VirtError("a disk of the VM sits on a controller that cannot be built on the new VM")
        cd_ctrl = next((ctrl_keys[c["key"]] for c in src["controllers"] if c["type"] == "VirtualAHCIController"), None)
        guest = src.get("guest_id") or "otherLinux64Guest"
    else:
        key -= 1
        scsi = key
        changes.append(E._change("add", f'<device xsi:type="ParaVirtualSCSIController"><key>{scsi}</key>'
                                        "<busNumber>0</busNumber><sharedBus>noSharing</sharedBus></device>"))
        units = [u for u in range(16) if u != 7]
        if len(src["disks"]) > len(units):
            raise VirtError("more disks than one controller holds")
        disk_where = [(scsi, units[i]) for i in range(len(src["disks"]))]
        cd_ctrl = None
        guest = "otherLinux64Guest"
    for d, (ck, unit) in zip(src["disks"], disk_where):
        key -= 1
        kb = int(math.ceil(d["bytes"] / 1024))
        changes.append(E._change("add", f'<device xsi:type="VirtualDisk"><key>{key}</key>'
                                        '<backing xsi:type="VirtualDiskFlatVer2BackingInfo">'
                                        f"<fileName>{_x(E.ds_path(ds))}</fileName><diskMode>persistent</diskMode>"
                                        "<thinProvisioned>true</thinProvisioned></backing>"
                                        f"<controllerKey>{ck}</controllerKey><unitNumber>{unit}</unitNumber>"
                                        f"<capacityInKB>{kb}</capacityInKB></device>", "create"))
    if cd_ctrl is None:
        key -= 1
        cd_ctrl = key
        changes.append(E._change("add", f'<device xsi:type="VirtualAHCIController"><key>{cd_ctrl}</key>'
                                        "<busNumber>3</busNumber></device>"))
    key -= 1
    cd_backing = (f'<backing xsi:type="VirtualCdromIsoBackingInfo"><fileName>{_x(iso)}</fileName></backing>'
                  if iso is not None else
                  '<backing xsi:type="VirtualCdromRemotePassthroughBackingInfo"><deviceName></deviceName>'
                  "<useAutoDetect>false</useAutoDetect><exclusive>false</exclusive></backing>")
    changes.append(E._change("add", f'<device xsi:type="VirtualCdrom"><key>{key}</key>' + cd_backing
                                    + f"<connectable><startConnected>{'true' if iso is not None else 'false'}</startConnected>"
                                    "<allowGuestControl>true</allowGuestControl>"
                                    "<connected>false</connected></connectable>"
                                    f"<controllerKey>{cd_ctrl}</controllerKey><unitNumber>29</unitNumber></device>"))
    extra = []
    for i, (n, m) in enumerate(zip(src["nics"], nets)):
        key -= 1
        t = n["model"] if n["model"] in ESXI_NICS else "VirtualVmxnet3"
        slot = f"<slotInfo xsi:type=\"VirtualDevicePciBusSlotInfo\"><pciSlotNumber>{n['slot']}</pciSlotNumber></slotInfo>" \
            if src["flavor"] == "esxi" and n.get("slot") is not None else ""
        changes.append(E._change("add", f'<device xsi:type="{t}"><key>{key}</key>'
                                        + E._net_backing(E.check_name(m["network"], "network"))
                                        + "<connectable><startConnected>true</startConnected><allowGuestControl>true"
                                        "</allowGuestControl><connected>false</connected></connectable>" + slot
                                        + f"<addressType>manual</addressType><macAddress>{mac_ok(n['mac'])}</macAddress></device>"))
        if not mac_ok(n["mac"]).startswith("00:50:56"):
            # an address from another hypervisor: ESXi checks manual addresses
            # against VMware's range unless told not to, card by card
            extra.append(("ethernet%d.checkMACAddress" % i, "FALSE"))
    if transfer is not None:
        key -= 1
        changes.append(E._change("add", f'<device xsi:type="VirtualVmxnet3"><key>{key}</key>'
                                        + E._net_backing(E.check_name(transfer["dst_net"], "network"))
                                        + "<connectable><startConnected>true</startConnected><allowGuestControl>true"
                                        "</allowGuestControl><connected>false</connected></connectable>"
                                        f"<addressType>manual</addressType><macAddress>{mac_ok(transfer['dst_mac'])}"
                                        "</macAddress></device>"))
    ver = src.get("hw_version") if src["flavor"] == "esxi" and re.match(r"^vmx-\d+$", src.get("hw_version") or "") else ""
    opts = "".join(f"<extraConfig><key>{_x(k)}</key><value xsi:type=\"xsd:string\">{_x(v)}</value></extraConfig>"
                   for k, v in extra)
    return (f"<name>{_x(E.check_name(name, 'VM name'))}</name>"
            + (f"<version>{ver}</version>" if ver else "")
            + f"<guestId>{_x(guest)}</guestId>"
            + f"<files><vmPathName>{_x(E.ds_path(ds))}</vmPathName></files>"
            + f"<numCPUs>{cpus}</numCPUs><numCoresPerSocket>{cps}</numCoresPerSocket>"
            + f"<memoryMB>{int(src['memory_mb'])}</memoryMB>"
            + "".join(changes) + opts
            + "<bootOptions><efiSecureBootEnabled>false</efiSecureBootEnabled>"
            + ("<bootOrder xsi:type=\"VirtualMachineBootOptionsBootableCdromDevice\"/>" if iso is not None else "")
            + "</bootOptions>"
            + f"<firmware>{'efi' if src['firmware'] == 'efi' else 'bios'}</firmware>")


def gz(data: bytes) -> tuple[bytes, str]:
    """The engine, compressed for the trip into the guest, and its hash."""
    return gzip.compress(data, 6, mtime=0), hashlib.sha256(data).hexdigest()
