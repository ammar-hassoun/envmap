"""Stand-in hosts for a powered-off move (tests/test_coldmove.py, and the docs
demo of the migration page).

They are harsh where a real hypervisor is harsh, so that a wrong order of
steps fails a test instead of passing by the stand-in's kindness:

    DELETING A VM DELETES EVERY DISK ATTACHED TO IT, whoever owns it. That is
    what "Destroy" does on ESXi. Proxmox is kinder in fact; here it is not.
    What was deleted is kept in `gone` for the tests to look at.

    A VM CANNOT START WHILE ANOTHER RUNNING VM HOLDS ITS DISK (ESXi's lock).

    A HELPER SAYS NOTHING unless it runs. What the two helpers say comes from
    one ColdLab, by the clock, and a test turns its knobs.
"""
from __future__ import annotations

import json
import re
import shlex
import time

from _fake_esxi import XSI, Fault, FakeEsxi, _k, _l, _t, _vm
from _fake_esxshell import EsxiShell
from _fake_pve_agent import AgentPve

HELPER = re.compile(r"^envmap-helper-[0-9a-f]{6,32}-(give|take)$")
NEW_DISK = re.compile(r"^([A-Za-z0-9._-]+):(\d+(?:\.\d+)?)((?:,.*)?)$")


def role_of(name: str) -> str:
    m = HELPER.match(name or "")
    return m.group(1) if m else ""


class ColdLab:
    """What the two helpers of one move say. Both started: they copy for
    `copy_s`, the taker reads back for `check_s`, then both say done."""

    def __init__(self, copy_s: float = 1.0, check_s: float = 0.6, total: int = 64 << 30):
        self.copy_s, self.check_s, self.total = copy_s, check_s, total
        self.on: dict = {}               # role -> when its helper was started
        self.disks: dict = {}            # role -> how many disks it holds
        self.fail: dict = {}             # role -> why it stops, once the copy runs
        self.mute: set = set()           # roles that run and cannot be heard
        self.hold = None                 # seconds into the copy at which the numbers stop moving
        self.apart = False               # the two run on networks that do not reach each other
        self.digests: dict = {}          # role -> what it names instead of the real digests
        self.asked: list = []            # (role, how) every time a helper was listened to
        self.starts: list = []           # every helper start, in order

    def start(self, role: str, disks: int) -> None:
        self.on[role], self.disks[role] = time.time(), disks
        self.starts.append(role)

    def stop(self, role: str) -> None:
        self.on.pop(role, None)

    def state(self, role: str) -> dict | None:
        if role not in self.on or role in self.mute:
            return None
        n = self.disks.get(role, 1)
        s = {"role": role, "state": "waiting", "disk": 0, "disks": n, "done": 0, "total": 0, "sent": 0,
             "checked": 0, "breaks": 0, "beat": int(time.time() * 10) % 100000}
        if len(self.on) < 2 or self.apart:
            return s
        t = time.time() - max(self.on.values())
        if self.hold is not None:
            t = min(t, self.hold)
        s["total"] = self.total
        if role in self.fail and t > 0.15:
            return {**s, "state": "failed", "why": self.fail[role]}
        if t < self.copy_s:
            done = int(self.total * t / self.copy_s)
            return {**s, "state": "copying", "disk": 1, "done": done, "sent": done // 3, "digests": [""] * n}
        if t < self.copy_s + self.check_s:
            return {**s, "state": "checking", "disk": n, "done": self.total, "sent": self.total // 3,
                    "checked": int(self.total * (t - self.copy_s) / self.check_s) if role == "take" else 0,
                    "digests": [""] * n}
        return {**s, "state": "done", "disk": n, "done": self.total, "sent": self.total // 3,
                "checked": self.total if role == "take" else 0,
                "digests": self.digests.get(role) or [f"{0xC01D0000 + i:016x}" for i in range(n)]}

    def text(self, role: str, console: bool) -> str | None:
        """The helper's words: on its console (among the kernel's own lines),
        or as its answer through the guest agent."""
        s = self.state(role)
        self.asked.append((role, "console" if console else "agent"))
        if s is None:
            return None
        plain = [f"helper ({role}) on eth0 169.254.77.{1 if role == 'give' else 2}/16"]
        if s["state"] in ("checking", "done"):
            plain.append("disk 1: read back from the device, the same as the original" if role == "take"
                         else "disk 1: the new disk was read back and is the same")
        if console:
            return ("[    0.000000] Linux version 6.12.51-0-lts\n[    1.204311] sd 0:0:0:0: [sda] Attached SCSI disk\n"
                    + "".join(f"envcold: {p}\n" for p in plain) + f"envcold: {json.dumps(s)}\n"
                    + 'envcold: {"role":"' + role + '","state":"do')          # a line the read cut short
        return json.dumps(s) + "\n" + "\n".join(plain) + "\n"


# ── Proxmox ────────────────────────────────────────────────────
class ColdPve(AgentPve):
    def __init__(self, lab: ColdLab | None = None):
        super().__init__()
        self.lab = lab or ColdLab()
        self.gone: list = []             # volumes that were freed
        self.no_allocate = False         # EnvMap's user lacks Datastore.Allocate
        self.stuck_disks = False         # a disk cannot be detached from a helper
        self.volumes: dict = {}          # volume -> the VM that owns it
        for vmid, g in self.guests.items():
            for k, v in g["config"].items():
                if re.match(r"^(scsi|virtio|sata|ide|efidisk)\d+$", k) and "media=cdrom" not in str(v):
                    self.volumes[str(v).split(",")[0]] = vmid

    def _disks(self, cfg: dict) -> dict:
        return {k: str(v).split(",")[0] for k, v in cfg.items()
                if (re.match(r"^(scsi|virtio|sata|ide)\d+$", k) and "media=cdrom" not in str(v) and str(v) != "none")
                or re.match(r"^(unused|efidisk)\d+$", k)}

    def route(self, m, path, p, raw, headers):
        parts = [x for x in path.split("/") if x]
        if path == "/access/permissions":
            return 200, {p.get("path", "/"): ({} if self.no_allocate else
                                               {"Datastore.Allocate": 1, "Datastore.AllocateSpace": 1, "Datastore.Audit": 1})}
        if len(parts) == 3 and parts[0] == "nodes" and parts[2] == "qemu" and m == "POST":
            vmid, n = int(p["vmid"]), 0
            for k in sorted(p):
                v = str(p[k])
                if not re.match(r"^(scsi|virtio|sata|ide|efidisk)\d+$", k) or "media=cdrom" in v:
                    continue
                new = NEW_DISK.match(v)
                if new:
                    # a new disk: Proxmox allocates a volume and writes its name down
                    vol = f"{new.group(1)}:vm-{vmid}-disk-{n}"
                    n += 1
                    size = "4M" if k.startswith("efidisk") else f"{new.group(2)}G"
                    p[k] = f"{vol}{new.group(3)},size={size}"
                    self.volumes[vol] = vmid
                elif v.split(",")[0] in self.volumes:
                    # another VM's volume: only for who may allocate on that storage
                    if self.no_allocate:
                        return 500, {"data": None, "message": "Permission check failed (/storage/"
                                                              f"{v.split(':')[0]}, Datastore.Allocate)"}
                else:
                    return 500, {"data": None, "message": f"volume '{v.split(',')[0]}' does not exist"}
        return super().route(m, path, p, raw, headers)

    def has_agent(self, vmid) -> bool:
        g = self.guests.get(vmid)
        role = role_of((g or {}).get("config", {}).get("name", ""))
        if role:
            return bool(g["status"] == "running" and str(g["config"].get("agent", "0"))[:1] == "1"
                        and self.lab.state(role) is not None)
        return super().has_agent(vmid)

    def run_script(self, vmid, script) -> tuple[int, str]:
        role = role_of(self.guests[vmid]["config"].get("name", ""))
        if role:
            return 0, self.lab.text(role, console=False) or ""
        return super().run_script(vmid, script)

    def guest(self, m, node, kind, vmid, rest, p):
        g = self.guests.get(vmid)
        role = role_of((g or {}).get("config", {}).get("name", ""))
        if g and rest == [] and m == "DELETE" and g["status"] == "stopped":
            for vol in self._disks(g["config"]).values():
                self.gone.append(vol)
                self.volumes.pop(vol, None)
        if g and rest == ["config"] and m in ("POST", "PUT") and self.stuck_disks and "delete" in p and role:
            return 500, {"data": None, "message": "can't lock file '/var/lock/qemu-server/lock.conf' - got timeout"}
        out = super().guest(m, node, kind, vmid, rest, p)
        if role and len(rest) == 2 and rest[0] == "status" and m == "POST":
            if g["status"] == "running":
                self.lab.start(role, len([k for k in self._disks(g["config"]) if k.startswith("scsi")]))
            else:
                self.lab.stop(role)
        return out


# ── ESXi, through its API ──────────────────────────────────────
class ColdEsxi(FakeEsxi):
    def __init__(self, *a, lab: ColdLab | None = None, **k):
        super().__init__(*a, **k)
        self.lab = lab or ColdLab()
        self.gone: list = []             # disk files that were deleted
        self.stuck_disks = False         # a disk cannot be removed from a helper
        self.serials: dict = {}          # VM number -> its serial port's file

    def _files_of(self, vm: dict) -> list:
        return [d["file"] for d in vm["devices"] if d["type"] == "VirtualDisk"]

    def _held(self, moid: str) -> str:
        """The name of another running VM that holds one of this VM's disks."""
        mine = set(self._files_of(self.vms[moid]))
        for k, vm in self.vms.items():
            if k != moid and vm["power"] == "poweredOn" and mine & set(self._files_of(vm)):
                return vm["name"]
        return ""

    def read_file(self, ds: str, path: str):
        for moid, f in self.serials.items():
            vm = self.vms.get(moid)
            if f == f"[{ds}] {path}" and vm:
                text = self.lab.text(role_of(vm["name"]), console=True)
                return text.encode() if text is not None else None
        return None

    def op_PowerOnVM_Task(self, req, this):
        vm = self._vm(this)
        held = self._held(this)
        if held:
            return self._task(vm["name"], "powerOn", error=f"Failed to lock the file: a disk of this virtual machine "
                                                            f"is in use by {held}")
        out = super().op_PowerOnVM_Task(req, this)
        if role_of(vm["name"]) and vm["power"] == "poweredOn":
            self.lab.start(role_of(vm["name"]), len(self._files_of(vm)))
        return out

    def op_PowerOffVM_Task(self, req, this):
        vm = self._vm(this)
        out = super().op_PowerOffVM_Task(req, this)
        if role_of(vm["name"]) and vm["power"] == "poweredOff":
            self.lab.stop(role_of(vm["name"]))
        return out

    def _device_change(self, vm, ch):
        if _t(ch, "operation") == "remove" and self.stuck_disks and role_of(vm["name"]):
            raise Fault("GenericVmConfigFault", "The device could not be removed: the virtual machine is busy")
        return super()._device_change(vm, ch)

    def op_Destroy_Task(self, req, this):
        vm = self._vm(this)
        if vm["power"] == "poweredOff":
            # ESXi deletes every disk attached to the VM, wherever its file is
            for f in self._files_of(vm):
                self.gone.append(f)
                m = re.match(r"^\[([^\]]+)\] (.+)$", f)
                self.files.get(m.group(1), {}).pop(m.group(2), None)
            self.serials.pop(this, None)
        return super().op_Destroy_Task(req, this)

    def op_CreateVM_Task(self, req, this):
        if this != "ha-folder-vm":
            raise Fault("ManagedObjectNotFound", "no such folder")
        cfg = _k(req, "config")
        moid = str(next(self._ids))
        name = _t(cfg, "name")
        vm = _vm(name, _t(cfg, "guestId"), _t(cfg, "guestId"), int(_t(cfg, "numCPUs")),
                 int(_t(cfg, "memoryMB")) / 1024, 1, "", power="poweredOff")
        vm["devices"] = [{"type": "VirtualPCIController", "key": 100}]
        vm["firmware"] = _t(cfg, "firmware") or "bios"
        vm["notes"] = _t(cfg, "annotation")
        known = {f for x in self.vms.values() for f in self._files_of(x)}
        made = 0
        for ch in cfg:
            if _l(ch.tag) != "deviceChange":
                continue
            dev = _k(ch, "device")
            t, k = dev.get(XSI), int(_t(dev, "key"))
            back, con = _k(dev, "backing"), _k(dev, "connectable")
            d = {"type": t, "key": abs(k) * 10}
            if t.endswith("Controller"):
                d["bus"] = int(_t(dev, "busNumber") or 0)
            elif t == "VirtualDisk":
                given = _t(back, "fileName")
                if _t(ch, "fileOperation") == "create":
                    file = f"[datastore1] {name}/{name}{'' if not made else f'_{made}'}.vmdk"
                    made += 1
                    self.files.setdefault("datastore1", {})[file.split("] ", 1)[1]] = int(_t(dev, "capacityInKB"))
                elif given in known:
                    file = given                     # an existing disk, used where it is
                else:
                    return self._task(name, "createVm", error=f"File {given} was not found")
                d.update(controller=abs(int(_t(dev, "controllerKey"))) * 10, unit=int(_t(dev, "unitNumber")),
                         kb=int(_t(dev, "capacityInKB")), thin=True, file=file)
            elif t == "VirtualCdrom":
                d.update(controller=abs(int(_t(dev, "controllerKey"))) * 10, unit=int(_t(dev, "unitNumber") or 0),
                         connected=False, start_connected=_t(con, "startConnected") == "true",
                         iso=_t(back, "fileName") if back.get(XSI) == "VirtualCdromIsoBackingInfo" else "")
            elif t == "VirtualSerialPort":
                self.serials[moid] = _t(back, "fileName")
                continue
            else:
                d.update(network=_t(back, "deviceName"), connected=False, mac=_t(dev, "macAddress").lower(),
                         address_type="manual", controller=100, unit=7 + len(vm["devices"]))
            vm["devices"].append(d)
        vm["vmx"] = f"[datastore1] {name}/{name}.vmx"
        self.vms[moid] = vm
        self.files.setdefault("datastore1", {})[f"{name}/{name}.vmx"] = 3200
        return self._task(name, "createVm", result=moid)


# ── ESXi on the free licence, through its shell ────────────────
class ColdShell(EsxiShell):
    def __init__(self, fake, host: str, password: str = "lab-password"):
        super().__init__(fake, host, password)
        self.lab = getattr(fake, "lab", None) or ColdLab()
        self.gone: list = []             # disk files that were deleted
        self.keep_on_list = False        # the host does not take a helper off its list

    def boot(self, moid: str) -> None:
        # a helper starts from its CD and says so itself: nothing to work out here
        if not role_of(self.fake.vms[moid]["name"]):
            super().boot(moid)

    def _run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        vms = self.fake.vms
        m = re.match(r"^tail -c \d+ (\S+|'[^']*') 2>/dev/null \|\| true$", command)
        if m:
            path = shlex.split(m.group(1))[0]
            folder = path.rsplit("/", 1)[0]
            vm = next((x for x in vms.values() if self.vmx_path(x).rsplit("/", 1)[0] == folder), None)
            text = self.lab.text(role_of(vm["name"]), console=True) if vm and vm["power"] == "poweredOn" else None
            return 0, (text or "").encode(), ""
        if command.startswith("rm -f ") and command.endswith(" 2>/dev/null; true"):
            # the host's own files beside a helper's settings file, by pattern
            pats = shlex.split(command[len("rm -f "):-len(" 2>/dev/null; true")])
            for pat in pats:
                rx = re.compile("^" + re.escape(pat).replace(r"\*", "[^/]*") + "$")
                for k in [k for k in self.files if rx.match(k)]:
                    del self.files[k]
            return 0, b"", ""
        a = shlex.split(command)
        if a[:1] == ["vim-cmd"] and len(a) == 3 and a[1] in ("vmsvc/power.on", "vmsvc/power.off", "vmsvc/destroy",
                                                              "vmsvc/unregister"):
            vm = vms[a[2]]
            role, op = role_of(vm["name"]), a[1]
            if op == "vmsvc/power.on":
                mine = {d["file"] for d in vm["devices"] if d["type"] == "VirtualDisk"}
                for k, x in vms.items():
                    if k != a[2] and x["power"] == "poweredOn" and mine & {
                            d["file"] for d in x["devices"] if d["type"] == "VirtualDisk"}:
                        raise ValueError(f"Failed to lock the file: a disk of this virtual machine is in use by {x['name']}")
            if op == "vmsvc/unregister" and self.keep_on_list and role:
                raise ValueError("The operation is not allowed in the current state")
            if op == "vmsvc/destroy" and vm["power"] != "poweredOn":
                # ESXi deletes every disk attached to the VM, wherever its file is
                for d in vm["devices"]:
                    if d["type"] == "VirtualDisk":
                        self.gone.append(d["file"])
                        dm = re.match(r"^\[([^\]]+)\] (.+)$", d["file"])
                        full = f"/vmfs/volumes/{dm.group(1)}/{dm.group(2)}"
                        self.files.pop(full, None)
                        self.files.pop(full[:-5] + "-flat.vmdk", None)
            out = super()._run(command, stdin)
            if role and out[0] == 0:
                if op == "vmsvc/power.on":
                    self.lab.start(role, len([d for d in vm["devices"] if d["type"] == "VirtualDisk"]))
                elif op != "vmsvc/power.on":
                    self.lab.stop(role)
            return out
        return super()._run(command, stdin)
