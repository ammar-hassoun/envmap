"""The two helper machines of a powered-off move (EnvMap Move for a VM that
is not running), and its new VM.

A VM that is off has no system that could copy itself. EnvMap does not start
it to get one: starting somebody's VM is a decision, its firmware may refuse
EnvMap's CD (Secure Boot), and it would need all of the VM's memory. Instead
it makes two small machines of its own and starts those from its CD
(moveiso, envmove/cold_linux.go):

    the giver   on the old host, with the VM's disks attached to it, read-only
                where the hypervisor can say so
    the taker   on the new host, with the new VM's blank disks

The giver reads, the taker writes and reads every byte back. Neither VM, the
old one or the new one, is started by EnvMap at any point.

RULES
    A HELPER IS NEVER DESTROYED WITH A DISK ON IT. "Delete this VM" on ESXi
    deletes every disk attached to it, wherever the disk's file is. A helper
    holds disks that are not its own: the VM's. So a helper is taken apart in
    this order, each step read back before the next: powered off; every disk
    detached, without touching its file; looked at again, and it must hold no
    disk; only then removed. If a disk is still on it, nothing is removed and
    the helper stays for a person.

    A HELPER IS REMOVED ONLY IF IT IS STILL THE HELPER. A host gives a VM's
    number out again; the name (or, through the shell, the settings file)
    EnvMap gave the helper is read from the host first.

    WHERE A DISK IS ATTACHED IS WRITTEN DOWN, NOT WORKED OUT. `slots` names a
    place for every disk; the same list goes into the helper's configuration
    and into its CD's settings, and the helper takes each disk by its place.

    A HELPER THAT IS OFF HAS SAID NOTHING. Done is what a helper says while it
    runs (`says`). The helpers never power themselves off.

HOW A HELPER IS HEARD
    Proxmox     the QEMU guest agent's port: `agent/exec` answers with the
                helper's status line (the helper runs nothing).
    ESXi        the helper's serial port is a file on the datastore, and its
                console is what it writes there: read over the host's file
                service, or with `tail` through the shell on the free licence.
"""
from __future__ import annotations

import json
import re
import secrets
from xml.sax.saxutils import escape as _x

import httpx

from . import esxiops, esxshell, moveside, pveops, urlguard, virt
from .virt import VirtError

E = esxiops
P = pveops
q = moveside.sh_quote
HELPER_MB = 1024
ESXI_UNITS = [u for u in range(16) if u != 7]      # the places on one SCSI controller
PVE_UNITS = 31
_VOLUME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._/-]*$")
_FILE = re.compile(r"^\[[^\]\r\n]+\] [^\r\n\"]+\.vmdk$")
_NAME = re.compile(r"^envmap-helper-[0-9a-f]{6,32}-(give|take)$")
_MARK = re.compile(r"^\.envmap-[0-9a-f]{16}$")
SERIAL = "serial.log"


def helper_name(jid: str, role: str) -> str:
    name = f"envmap-helper-{jid}-{role}"
    if not _NAME.match(name):
        raise VirtError("not a helper's name")
    return name


def most(flavor: str) -> int:
    return len(ESXI_UNITS) if flavor == "esxi" else PVE_UNITS


def slots(flavor: str, sizes: list[int]) -> list[dict]:
    """Where each disk goes in a helper on this kind of hypervisor, in the
    words the helper's CD uses: SCSI target, unit, and the bytes it must hold."""
    if len(sizes) > most(flavor):
        raise VirtError(f"the VM has {len(sizes)} disks; a helper on "
                        f"{'ESXi' if flavor == 'esxi' else 'Proxmox'} holds {most(flavor)}")
    if flavor == "esxi":
        return [{"t": ESXI_UNITS[i], "l": 0, "bytes": int(n)} for i, n in enumerate(sizes)]
    return [{"t": 0, "l": i, "bytes": int(n)} for i, n in enumerate(sizes)]


def parse_says(text: str) -> tuple[dict | None, str]:
    """A helper's status out of what it wrote, and its last plain lines.

    Through the agent the answer is the status line itself, then the helper's
    plain lines. On a console every line of the helper's starts `envcold: `,
    among the kernel's own; the last whole status line stands, so a line cut
    short by the read leaves the one before it."""
    lines = (text or "").replace("\r", "").split("\n")
    agent = bool(lines) and lines[0].lstrip().startswith("{")
    state, plain = None, []
    for i, line in enumerate(lines):
        t = line.strip()
        if not t:
            continue
        if agent:
            if i:
                plain.append(t)
                continue
            body = t
        else:
            k = t.find("envcold: ")
            if k < 0:
                continue
            body = t[k + 9:].strip()
            if not body.startswith("{"):
                plain.append(body)
                continue
        try:
            got = json.loads(body)
        except ValueError:
            continue
        if isinstance(got, dict) and got.get("state"):
            state = got
    return state, "\n".join(plain[-8:])


def find_by_name(conn: dict, name: str, node: str = "") -> str:
    """The id of the VM called `name` on this host, read afresh, or "". For a
    helper whose making was cut off before its id was written down."""
    virt.forget(conn)
    for g in (virt.read(conn, refresh=True) or {}).get("guests") or []:
        if g.get("name") == name and (not node or g.get("host") == node):
            return str(g.get("id") or "")
    return ""


# ── the new VM: built, never started ───────────────────────────
def target(dst, facts: dict, *, name: str, storage: str, nets: list[dict], plan: dict | None = None) -> dict:
    """The new VM of a powered-off move: the source's shape, blank disks, no
    receiver CD, no transfer card, stopped. {"vm", "wheres": where each disk
    is kept, in the order of facts["disks"], ...}."""
    if dst.flavor == "proxmox":
        if facts["flavor"] == "proxmox":
            spec, where = moveside.pve_spec(facts, "proxmox", name=re.sub(r"[^A-Za-z0-9.-]", "-", name),
                                            storage=storage, nets=nets, transfer=None, iso=None)
            keys = [d["key"] for d in facts["disks"]]
        else:
            spec, where, keys = pve_like_esxi(facts, name=re.sub(r"[^A-Za-z0-9.-]", "-", name),
                                              storage=storage, nets=nets)
        vm = dst.create(spec)
        try:
            cfg = dst.config()
            wheres = [P._opts(cfg.get(k, "")).get("_", "") for k in keys]
            if not all(wheres):
                raise VirtError("Proxmox made the new VM without one of its disks")
        except Exception:
            # made, and not yet on the move's record: taken away here, or nobody would
            try:
                dst.destroy()
            except VirtError:
                pass
            raise
        return {"vm": vm, "wheres": wheres, "boot": where["boot"], "onboot": where["onboot"]}
    if getattr(dst, "road", "") == "shell":
        made = dst.build(facts, name=name, datastore=storage, nets=nets, transfer=None, iso=None, plan=plan)
        folder = (plan or {}).get("folder", "")
        wheres = [E.ds_path(plan["datastore"], f"{folder}/{f}") for f in plan["disks"]]
        return {"vm": made["vm"], "vmx": made["vmx"], "wheres": wheres}
    dst.create(moveside.esxi_spec(facts, name=name, datastore=storage, nets=nets, transfer=None, iso=None))
    try:
        d = E.vm_detail(dst.es, dst.moid)
        ctrl = {c["key"]: (c["type"], int(c.get("bus") or 0)) for c in d["controllers"]}
        have = {(*ctrl.get(x["controller"], ("", 0)), int(x.get("unit") or 0)): x.get("file") or "" for x in d["disks"]}
        wheres = []
        for i, s in enumerate(facts["disks"]):
            at = (s.get("ctrl", ""), int(s.get("bus") or 0), int(s.get("unit") or 0)) if facts["flavor"] == "esxi" \
                else ("ParaVirtualSCSIController", 0, ESXI_UNITS[i])
            if not have.get(at):
                raise VirtError(f"the host made the new VM without its disk {i + 1}")
            wheres.append(have[at])
    except Exception:
        # made, and not yet on the move's record: taken away here, or nobody would
        try:
            dst.destroy()
        except VirtError:
            pass
        raise
    return {"vm": dst.moid, "wheres": wheres}


PVE_NIC_LIKE = {"VirtualVmxnet3": "vmxnet3", "VirtualE1000e": "e1000e", "VirtualE1000": "e1000"}


def pve_like_esxi(src: dict, *, name: str, storage: str, nets: list[dict]) -> tuple[dict, dict, list[str]]:
    """A Proxmox VM for a system that was installed on ESXi and will start
    cold on it: the device types it already drives, where Proxmox has them.

    A system that starts cold finds its disk with the drivers in its start-up
    image, and a start-up image built on ESXi often carries VMware's and no
    others. Proxmox can present VMware's own: the paravirtual SCSI controller
    and the VMXNET3, E1000 and E1000e cards. A disk on a controller Proxmox
    has no like of (LSI Logic, NVMe) goes on SATA, the driver most start-up
    images carry. (A running move does not need this: its kernel is already
    up and takes the new devices as they are.)
    Returns (configuration, what to restore, the disks' keys in order)."""
    sockets = max(1, src["cpus"] // max(1, src["cores"]))
    windows = "win" in (src.get("guest_id") or "").lower()
    spec: dict = {"name": name, "cores": max(1, src["cores"]), "sockets": sockets, "memory": src["memory_mb"],
                  "ostype": "win10" if windows else "l26", "cpu": "host", "balloon": 0, "onboot": 0}
    if src["firmware"] == "efi":
        spec.update(bios="ovmf", machine="q35", efidisk0=f"{storage}:1,efitype=4m,pre-enrolled-keys=0")
    keys, n = [], {"scsi": 0, "sata": 0, "ide": 0}
    for d in src["disks"]:
        bus = {"ParaVirtualSCSIController": "scsi", "VirtualIDEController": "ide"}.get(d.get("ctrl", ""), "sata")
        if bus == "ide" and n["ide"] >= 4:
            bus = "sata"
        if bus == "sata" and n["sata"] >= 6:
            bus = "scsi"
        key = f"{bus}{n[bus]}"
        n[bus] += 1
        spec[key] = moveside._pve_disk(storage, {"bytes": d["bytes"], "opts": {}})
        keys.append(key)
    if n["scsi"]:
        spec["scsihw"] = "pvscsi"
    for i, (c, m) in enumerate(zip(src["nics"], nets)):
        spec[f"net{i}"] = moveside._pve_nic(PVE_NIC_LIKE.get(c.get("model", ""), "virtio"), c["mac"], m, {})
    spec["boot"] = "order=" + ";".join(keys)
    return spec, {"boot": spec["boot"], "onboot": 0}, keys


# ── the helpers ────────────────────────────────────────────────
class PveHelper:
    """A helper on a Proxmox node."""

    def __init__(self, side, rec: dict | None = None):
        self.rec = dict(rec or {})
        self.h = moveside.Pve(side.conn, side.node, self.rec.get("vm") or None)

    def plan(self, name: str, store: str) -> dict:
        return {"name": name, "store": store}

    def make(self, rec: dict, *, iso: str, net: str, vlan: str, mac: str, disks: list[str],
             places: list[dict], readonly: bool) -> dict:
        spec = {"name": rec["name"], "memory": HELPER_MB, "cores": 2, "sockets": 1, "ostype": "l26",
                "scsihw": "virtio-scsi-pci", "agent": "1", "onboot": 0, "boot": "order=ide2",
                "ide2": f"{iso},media=cdrom",
                "net0": moveside._pve_nic("virtio", mac, {"network": net, "vlan": vlan}, {}),
                "description": "EnvMap Move helper. It copies the disks of a powered-off VM and is removed "
                               "when the move ends. Do not delete it with its disks: they belong to that VM."}
        for where, at in zip(disks, places):
            if not _VOLUME.match(where or ""):
                raise VirtError("a disk of the VM is not a volume Proxmox names")
            spec[f"scsi{int(at['l'])}"] = where + (",ro=1" if readonly else "")
        self.rec = {**rec, "vm": self.h.create(spec)}
        return self.rec

    def start(self) -> None:
        self.h.start()

    def power(self) -> str:
        if not self.h.vmid or not self.h.exists():
            return ""
        return self.h.status()

    def says(self) -> tuple[dict | None, str]:
        try:
            code, out = self.h.exec("status", 25)
        except VirtError:
            return None, ""
        return parse_says(out) if not code else (None, "")

    def _mine(self) -> dict:
        cfg = self.h.config()
        if cfg.get("name") != self.rec.get("name"):
            raise VirtError(f"VM {self.h.vmid} on {self.h.node} is no longer the helper EnvMap made there "
                            f"(it is called {cfg.get('name') or '?'}): it is left alone")
        return cfg

    @staticmethod
    def _held(cfg: dict) -> list[str]:
        return sorted(k for k, v in cfg.items()
                      if (moveside.DISK_KEY.match(k) and P._opts(v).get("media") != "cdrom")
                      or re.match(r"^unused\d+$", k))

    def drop(self) -> str:
        if not self.rec.get("name"):
            return "no helper had been made"
        if not self.h.vmid:
            found = find_by_name(self.h.conn, self.rec["name"], self.h.node)
            if not found:
                return "no helper had been made"
            self.h.vmid = P.vmid_ok(found)
        if not self.h.exists():
            return "the helper was already gone"
        cfg = self._mine()
        if self.h.status() != "stopped":
            self.h.stop()
        held = [k for k in self._held(cfg) if not k.startswith("unused")]
        why = ""
        if held:
            # detached, not deleted: Proxmox frees a volume only for the VM that owns it
            try:
                self.h.api("PUT", f"{self.h.base}/config", {"delete": ",".join(held)})
            except VirtError as e:
                why = f" ({e})"
        left = self._held(self._mine())
        if left:
            raise VirtError(f"the helper {self.rec.get('name')} (VM {self.h.vmid}) still holds {', '.join(left)}{why}: "
                            "it was not removed, so that no disk goes with it. Detach them from it, without "
                            "deleting them, then delete the helper")
        self.h.wait(self.h.api("DELETE", self.h.base))
        return "the helper removed"


def _esxi_helper_spec(name: str, datastore: str, *, iso: str, net: str, mac: str, disks: list[tuple[str, int]],
                      places: list[dict], serial: str) -> str:
    ds = E.check_name(datastore, "datastore")
    ch = [E._change("add", '<device xsi:type="ParaVirtualSCSIController"><key>-201</key>'
                           "<busNumber>0</busNumber><sharedBus>noSharing</sharedBus></device>")]
    key = -300
    for (file, kib), at in zip(disks, places):
        if not _FILE.match(file or ""):
            raise VirtError("a disk of the VM is not a disk file on a datastore")
        key -= 1
        # an existing file, added with no file operation: nothing is created and nothing is deleted
        ch.append(E._change("add", f'<device xsi:type="VirtualDisk"><key>{key}</key>'
                                   '<backing xsi:type="VirtualDiskFlatVer2BackingInfo">'
                                   f"<fileName>{_x(file)}</fileName><diskMode>persistent</diskMode></backing>"
                                   f"<controllerKey>-201</controllerKey><unitNumber>{int(at['t'])}</unitNumber>"
                                   f"<capacityInKB>{int(kib)}</capacityInKB></device>"))
    ch.append(E._change("add", '<device xsi:type="VirtualAHCIController"><key>-210</key><busNumber>0</busNumber></device>'))
    ch.append(E._change("add", '<device xsi:type="VirtualCdrom"><key>-211</key>'
                               f'<backing xsi:type="VirtualCdromIsoBackingInfo"><fileName>{_x(iso)}</fileName></backing>'
                               "<connectable><startConnected>true</startConnected><allowGuestControl>false</allowGuestControl>"
                               "<connected>false</connected></connectable>"
                               "<controllerKey>-210</controllerKey><unitNumber>0</unitNumber></device>"))
    ch.append(E._change("add", '<device xsi:type="VirtualVmxnet3"><key>-220</key>'
                               + E._net_backing(E.check_name(net, "network"))
                               + "<connectable><startConnected>true</startConnected><allowGuestControl>false"
                               "</allowGuestControl><connected>false</connected></connectable>"
                               f"<addressType>manual</addressType><macAddress>{moveside.mac_ok(mac)}</macAddress></device>"))
    ch.append(E._change("add", '<device xsi:type="VirtualSerialPort"><key>-230</key>'
                               f'<backing xsi:type="VirtualSerialPortFileBackingInfo"><fileName>{_x(serial)}</fileName></backing>'
                               "<connectable><startConnected>true</startConnected><allowGuestControl>false"
                               "</allowGuestControl><connected>false</connected></connectable>"
                               "<yieldOnPoll>true</yieldOnPoll></device>"))
    extra = [("answer.msg.serial.file.overwrite", "APPEND")]
    if not moveside.mac_ok(mac).startswith("00:50:56"):
        extra.append(("ethernet0.checkMACAddress", "FALSE"))
    opts = "".join(f"<extraConfig><key>{_x(k)}</key><value xsi:type=\"xsd:string\">{_x(v)}</value></extraConfig>"
                   for k, v in extra)
    return (f"<name>{_x(E.check_name(name, 'VM name'))}</name><guestId>otherLinux64Guest</guestId>"
            f"<files><vmPathName>{_x(E.ds_path(ds))}</vmPathName></files>"
            f"<numCPUs>2</numCPUs><memoryMB>{HELPER_MB}</memoryMB>"
            "<annotation>EnvMap Move helper. It copies the disks of a powered-off VM and is removed when the "
            "move ends. Do not delete it: deleting it would delete the disks attached to it, and they belong "
            "to that VM.</annotation>"
            + "".join(ch) + opts
            + "<bootOptions><bootOrder xsi:type=\"VirtualMachineBootOptionsBootableCdromDevice\"/></bootOptions>"
            + "<firmware>bios</firmware>")


class EsxiHelper:
    """A helper on an ESXi host whose API takes changes."""

    def __init__(self, side, rec: dict | None = None):
        self.rec = dict(rec or {})
        self.h = moveside.Esxi(side.conn, self.rec.get("vm") or None)

    def plan(self, name: str, store: str) -> dict:
        return {"name": name, "store": E.check_name(store, "datastore"),
                "serial": E.ds_path(E.check_name(store, "datastore"), f"envmove/{name}.log")}

    def make(self, rec: dict, *, iso: str, net: str, vlan: str, mac: str, disks: list[str],
             places: list[dict], readonly: bool) -> dict:
        sized = [(f, max(1, int(at["bytes"]) // 1024)) for f, at in zip(disks, places)]
        self.h.create(_esxi_helper_spec(rec["name"], rec["store"], iso=iso, net=net, mac=mac, disks=sized,
                                        places=places, serial=rec["serial"]))
        self.rec = {**rec, "vm": self.h.moid}
        return self.rec

    def start(self) -> None:
        self.h.start()

    def power(self) -> str:
        return self.h.status() if self.h.exists() else ""

    def says(self) -> tuple[dict | None, str]:
        m = re.match(r"^\[([^\]]+)\] (.+)$", self.rec.get("serial") or "")
        if not m:
            return None, ""
        try:
            url, headers = E.upload_target(self.h.es, m.group(1), m.group(2))
            headers = {"Cookie": headers["Cookie"], "Range": "bytes=-65536"}
            r = httpx.get(urlguard.check(url), headers=headers, verify=not self.h.conn.get("skip_tls"), timeout=30)
        except (VirtError, httpx.HTTPError):
            return None, ""
        if r.status_code not in (200, 206):
            return None, ""
        return parse_says(r.content[-65536:].decode(errors="replace"))

    def _mine(self) -> dict:
        d = E.vm_detail(self.h.es, self.h.moid)
        if d.get("name") != self.rec.get("name"):
            raise VirtError(f"VM {self.h.moid} on {self.h.conn.get('name', 'the host')} is no longer the helper "
                            f"EnvMap made there (it is called {d.get('name') or '?'}): it is left alone")
        return d

    def drop(self) -> str:
        if not self.rec.get("name"):
            return "no helper had been made"
        if not self.h.moid:
            self.h.moid = find_by_name(self.h.conn, self.rec["name"]) or None
            if not self.h.moid:
                return "no helper had been made"
        if not self.h.exists():
            return "the helper was already gone"
        d = self._mine()
        if self.h.status() != "stopped":
            self.h.stop()
        why = ""
        for x in d["disks"]:
            # taken off the helper; the disk's file is not touched
            try:
                self.h._wait(E.device_remove(self.h.es, self.h.moid, int(x["key"]), delete_file=False))
            except VirtError as e:
                why = f" ({e})"
        left = self._mine()["disks"]
        if left:
            raise VirtError(f"the helper {self.rec.get('name')} still holds {len(left)} disk(s) that are not its "
                            f"own{why}: it was not removed, because deleting a VM on ESXi deletes the disks attached "
                            "to it. Remove them from it in the host's client (Remove, not Delete files), then "
                            "delete the helper")
        self.h._wait(E.destroy(self.h.es, self.h.moid))
        m = re.match(r"^\[([^\]]+)\] (.+)$", self.rec.get("serial") or "")
        if m:
            try:
                self.h._wait(E.delete_file(self.h.es, m.group(1), m.group(2)))
            except VirtError:
                pass                            # the console's file: nothing depends on it
        return "the helper removed"


def helper_vmx(name: str, *, hw: str, iso_file: str, net: str, mac: str, disks: list[str],
               places: list[dict]) -> str:
    """A helper as a .vmx file: its own folder holds only this file, its
    serial console and what the host writes beside them; the disks are the
    VM's, named by their full paths."""
    lines: list[str] = []

    def put(key: str, value) -> None:
        v = str(value)
        if '"' in v or "\n" in v or "\r" in v:
            raise VirtError("a value that cannot be written into a .vmx file")
        lines.append(f'{key} = "{v}"')

    put(".encoding", "UTF-8")
    put("config.version", "8")
    put("virtualHW.version", int(hw))
    put("displayName", E.check_name(name, "VM name"))
    put("guestOS", "otherlinux-64")
    put("memSize", HELPER_MB)
    put("numvcpus", 2)
    put("firmware", "bios")
    put("bios.bootOrder", "cdrom")
    put("nvram", "helper.nvram")
    put("uuid.action", "create")
    put("annotation", "EnvMap Move helper. Do not delete it: deleting it would delete the disks attached to it, "
                      "and they belong to another VM.")
    put("pciBridge0.present", "TRUE")
    for b in (4, 5, 6, 7):
        put(f"pciBridge{b}.present", "TRUE")
        put(f"pciBridge{b}.virtualDev", "pcieRootPort")
        put(f"pciBridge{b}.functions", "8")
    put("vmci0.present", "TRUE")
    put("hpet0.present", "TRUE")
    put("svga.present", "TRUE")
    put("floppy0.present", "FALSE")
    put("scsi0.present", "TRUE")
    put("scsi0.virtualDev", "pvscsi")
    put("scsi0.sharedBus", "none")
    for path, at in zip(disks, places):
        if not re.match(r"^/vmfs/volumes/[^/]+/.+\.vmdk$", path or ""):
            raise VirtError("a disk of the VM is not a disk file on a datastore")
        p = f"scsi0:{int(at['t'])}"
        put(f"{p}.present", "TRUE")
        put(f"{p}.fileName", path)
        put(f"{p}.deviceType", "scsi-hardDisk")
    put("sata0.present", "TRUE")
    put("sata0:0.present", "TRUE")
    put("sata0:0.deviceType", "cdrom-image")
    put("sata0:0.fileName", iso_file)
    put("sata0:0.startConnected", "TRUE")
    put("ethernet0.present", "TRUE")
    put("ethernet0.virtualDev", "vmxnet3")
    put("ethernet0.networkName", E.check_name(net, "network"))
    put("ethernet0.addressType", "static")
    put("ethernet0.address", moveside.mac_ok(mac))
    if not esxshell._manual_range(mac):
        put("ethernet0.checkMACAddress", "FALSE")
    put("ethernet0.startConnected", "TRUE")
    put("serial0.present", "TRUE")
    put("serial0.fileType", "file")
    put("serial0.fileName", SERIAL)
    put("serial0.yieldOnMsrRead", "TRUE")
    put("answer.msg.serial.file.overwrite", "APPEND")
    return "\n".join(lines) + "\n"


class ShellHelper:
    """A helper on an ESXi host with the free licence: made and removed
    through the host's shell."""
    OWN = ("helper.vmx", "helper.vmx.envmap", "helper.nvram", "helper.vmsd", "helper.vmxf", SERIAL)

    def __init__(self, side, rec: dict | None = None):
        self.rec = dict(rec or {})
        self.h = esxshell.EsxiShell(side.conn, self.rec.get("vm") or None, who=getattr(side, "who", ""))
        self.h.made_vmx = self.rec.get("vmx", "")

    def plan(self, name: str, store: str) -> dict:
        ds = E.check_name(store, "datastore")
        return {"name": name, "store": ds, "folder": name, "mark": f".envmap-{secrets.token_hex(8)}",
                "vmx": E.ds_path(ds, f"{name}/helper.vmx")}

    def _base(self) -> str:
        if not _NAME.match(self.rec.get("folder") or ""):
            raise VirtError("this move's record of its helper is not complete, so nothing of it was touched")
        return self.h._vol(E.ds_path(self.rec["store"], self.rec["folder"]))

    def make(self, rec: dict, *, iso: str, net: str, vlan: str, mac: str, disks: list[str],
             places: list[dict], readonly: bool) -> dict:
        self.rec = dict(rec)
        base = self._base()
        if not _MARK.match(rec.get("mark") or ""):
            raise VirtError("this move's record of its helper is not complete")
        text = helper_vmx(rec["name"], hw=self.h._hw({"flavor": "helper"}), iso_file=self.h._vol(iso), net=net,
                          mac=mac, disks=[self.h._vol(f) for f in disks], places=places)
        # a plain mkdir: it fails if the folder is there, and then nothing of it is EnvMap's
        self.h.sh(f"mkdir {q(base)} && : > {q(base + '/' + rec['mark'])}")
        self.h._write(f"{base}/helper.vmx", text.encode())
        out = self.h.sh(f"vim-cmd solo/registervm {q(base + '/helper.vmx')}", timeout=120)
        m = re.search(r"^\s*(\d+)\s*$", out, re.M)
        vm = m.group(1) if m else self.h._registered(rec["vmx"])
        if not vm:
            raise VirtError(f"the host did not register the helper: {out.strip()[-160:]}")
        self.h.moid, self.h.made_vmx = vm, rec["vmx"]
        self.rec = {**rec, "vm": vm}
        return self.rec

    def start(self) -> None:
        self.h._is_mine()
        self.h.sh(f"vim-cmd vmsvc/power.on {self.h._vmid}", timeout=150)
        self.h._until(lambda: self.h.status() == "running", "the helper did not power on")

    def power(self) -> str:
        return self.h.status() if self.h.moid else ""

    def says(self) -> tuple[dict | None, str]:
        try:
            out = self.h.sh(f"tail -c 65536 {q(self._base() + '/' + SERIAL)} 2>/dev/null || true", timeout=30)
        except VirtError:
            return None, ""
        return parse_says(out)

    def drop(self) -> str:
        """Taken off the host's list (never "destroy": that deletes attached
        disks), then the files this helper made, by name, out of its own folder."""
        if not self.rec.get("folder"):
            return "no helper had been made"
        base = self._base()
        mark = self.rec.get("mark") or ""
        if not _MARK.match(mark):
            raise VirtError("this move's record of its helper is not complete, so nothing of it was touched")
        mine = self.h._look(f"{base}/{mark}")
        vm = self.h._registered(self.rec["vmx"]) if mine else str(self.rec.get("vm") or "")
        did = "the helper was already gone"
        if vm:
            self.h.moid, self.h.made_vmx = vm, self.rec["vmx"]
            if self.h.status() != "":
                self.h._is_mine()
                if self.h.status() != "stopped":
                    self.h.stop()
                self.h.sh(f"vim-cmd vmsvc/unregister {self.h._vmid}", timeout=120)
                self.h._until(lambda: self.h.status() == "", "the helper is still on the host's list", 30)
                did = "the helper removed"
        if not mine:
            return did
        for f in self.OWN + (mark,):
            self.h.sh(f"rm -f {q(base + '/' + f)}")
        self.h.sh(f"rm -f {q(base)}/vmware*.log {q(base)}/*.vswp {q(base)}/*.vswp.lck {q(base)}/vmx-*.vswp 2>/dev/null; true")
        try:
            self.h.sh(f"rmdir {q(base)}")
        except VirtError:
            return did + "; its folder stays, because something that is not EnvMap's is in it"
        return "the helper removed"


def helper(side, rec: dict | None = None):
    """The helper on `side`'s host, by the road that host is worked through."""
    if side.flavor == "proxmox":
        return PveHelper(side, rec)
    if getattr(side, "road", "") == "shell":
        return ShellHelper(side, rec)
    return EsxiHelper(side, rec)


# ── what only Proxmox needs asking ─────────────────────────────
def pve_may_attach(side, volumes: list[str]) -> list[str]:
    """The storages on which EnvMap's Proxmox user may not attach a volume to
    another VM than its owner (Datastore.Allocate), which is what a helper
    does. Empty when it may, or when Proxmox would not say."""
    missing = []
    for sid in sorted({v.split(":", 1)[0] for v in volumes if ":" in v}):
        try:
            got = side.api("GET", "/access/permissions", params={"path": f"/storage/{sid}"}) or {}
        except VirtError:
            return []
        privs = got.get(f"/storage/{sid}") or {}
        if not privs.get("Datastore.Allocate"):
            missing.append(sid)
    return missing


def pve_started_since(side, since: float) -> bool | None:
    """Whether the VM was started since `since`, from the node's own task
    list. None when the node would not say."""
    try:
        tasks = side.api("GET", f"/nodes/{side.node}/tasks",
                         params={"vmid": side.vmid, "since": int(since), "typefilter": "qmstart", "source": "all"}) or []
    except VirtError:
        return None
    return any(str(t.get("id")) == str(side.vmid) and t.get("type") == "qmstart" for t in tasks)

