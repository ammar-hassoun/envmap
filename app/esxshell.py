"""EnvMap Move on an ESXi host whose licence keeps VMware's API read-only.

WHY THIS EXISTS
    The free ESXi licence ("vSphere Hypervisor") lets a program read the host
    through VMware's API and refuses every change, and every guest operation,
    with "Current license or ESXi version prohibits execution of the requested
    operation". A move needs changes on both hosts and commands in the guest,
    so on 27 November 2026 a move between two free hosts stopped at its first
    step, and would have stopped at every later one.

    The host has a second management door that the licence leaves open: its
    own shell over SSH, with VMware's own commands (vim-cmd, vmkfstools). That
    is the door used here. EnvMap does not dress up as VMware's own client to
    get past the API's licence check; that would be working around the
    licence, and this is not.

WHAT GOES WHERE
    reading   still the API (moveside.Esxi): the VM's hardware, its power
              state, VMware Tools, the host's networks and datastores.
    changing  the host's shell. The new VM is a .vmx file written here, with
              disks from vmkfstools, registered and powered with vim-cmd. The
              transfer card on the running source is vim-cmd's createnic.
    the guest SSH to the guest itself, with the sign-in typed for the move.
              (Reaching into a guest through VMware Tools is an API change.)

WHAT THE SHELL CANNOT DO, AND WHAT IS DONE INSTEAD
    vim-cmd cannot rename a running VM, cannot take a network card out of one,
    and cannot change whether a device connects at power-on. So:
    - the new VM carries the VM's name from the start (two hosts, no clash);
    - the new VM's transfer card is written as "not connected at power-on" and
      connected by hand after each start, so that once it is disconnected at
      the end it stays so;
    - a transfer card hot-added to a source that then keeps running (a move
      called off) can only be disconnected: it comes back at that VM's next
      power-on until a person removes it, and the log says exactly that;
    - the receiver CD must connect at power-on (the firmware starts from it),
      so it stays; its image is emptied rather than deleted, because a CD
      whose image is gone makes ESXi ask a question at the next power-on, and
      a question nobody sees is a VM that does not start;
    - the old VM, powered off at the end, has its .vmx edited (cards not
      connected at power-on, transfer card out, renamed) and is reloaded.

THE NEW VM STARTS FROM THE CD, EVERY TIME, UNTIL THE SYSTEM HAS ARRIVED
    `bios.bootOrder = "cdrom,hdd"`. VMware's firmware tries the disk first by
    itself, and the first start only reaches the CD because the disks are
    blank. After the copy they are not: a reset (which is what "Bring it
    back" does, so that the receiver tells the frozen system to carry on)
    would start the COPY, and two copies of one system would be on the
    network. An independent review found this before any real run.

WHAT IS MADE IS WRITTEN DOWN FIRST
    A folder, disks, a registered VM: `plan_build` says what will be made and
    vmmove records it in the job before `build` makes any of it, so a move
    that dies half-way (EnvMap restarted, SSH dropped) can still be undone
    (`unmake`). A VM is only ever destroyed if the number the host knows it by
    still names the settings file EnvMap wrote.

FILES ARE VERIFIED BEFORE THEY REPLACE ANYTHING
    `cat > x && mv x y` calls a half-received file a success when the
    connection drops: the remote `cat` just sees the end of its input. Every
    file sent to a host goes to a temporary name, is hashed there, and only
    then takes its place (`_write`).

SECRETS
    The password reaches ssh through its askpass hook, from the environment of
    that one ssh process, and is never written to disk: move threads are
    daemon threads, a `finally` does not run when the process is stopped, and
    a watcher signs in to the guest every two seconds. One sign-in method is
    tried per call, so a mistyped password costs one failed attempt in the
    guest, not two (a guest with `faillock deny=3` would lock on the second
    check otherwise).

HOST KEYS
    The same pins Privileged Access uses (pam.seed_known_hosts): the key seen
    at the first contact is written down and audited, and a different one is
    refused. The check tells the person which key was written down.

NOT YET RUN AGAINST A REAL HOST
    Written on 27 November 2026 with no free-licence host reachable over SSH
    (the service was off or port 22 filtered on all nine). The vim-cmd forms
    are from VMware's documentation and its knowledge base, not from a run;
    least certain are `device.connection` on a CD drive (the vendor shows it
    for network cards) and whether a .vmx-written VM lands every device in
    the slot claimed. Each change is read back through the API, so a command
    that does not do what it says fails here instead of passing unseen.
    tests/test_esxshell.py drives it against a stand-in shell.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.parse

from . import ansible, env, esxiops, moveside, pam, urlguard
from .virt import VirtError

E = esxiops
q = moveside.sh_quote
CONNECT = 8                                    # seconds for the TCP connection
STUB = 64 * 1024                               # what is left of a receiver CD still attached
CD_GRACE = 5                                   # seconds a restarted receiver's CD is given to read as connected:
#                                                far less than a system needs to come up from a disk
CD_GRACE_BLANK = 30                            # the same on the first start: the disks are blank, nothing hurries
SECRET = "ENVMAP_SSH_SECRET"                   # the password, in the environment of one ssh process
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_IP6 = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
_ISO = re.compile(r"^envmove-[0-9a-f]{6,32}\.iso$")
_DENIED = re.compile(r"(?i)permission denied|authentication failed|too many authentication failures")
_OFFERED = re.compile(r"(?i)permission denied \(([^)]*)\)")
HOST_METHODS = ("keyboard-interactive", "password")       # ESXi's sshd asks through PAM
GUEST_METHODS = ("password", "keyboard-interactive")

VMX_SCSI = {"ParaVirtualSCSIController": "pvscsi", "VirtualLsiLogicSASController": "lsisas1068",
            "VirtualLsiLogicController": "lsilogic", "VirtualBusLogicController": "buslogic"}
VMX_NIC = {"VirtualVmxnet3": "vmxnet3", "VirtualE1000e": "e1000e", "VirtualE1000": "e1000",
           "VirtualVmxnet2": "vmxnet", "VirtualVmxnet": "vmxnet", "VirtualPCNet32": "vlance"}
VMX_SHARE = {"noSharing": "none", "virtualSharing": "virtual", "physicalSharing": "physical"}
# guest types whose .vmx spelling does not follow from the API's
VMX_GUEST = {"vmwarePhoton64Guest": "vmware-photon-64"}
# the newest virtual hardware every build of a release runs, for a VM that
# arrives from Proxmox and so brings no version of its own
HW_FOR = (("9.", "21"), ("8.", "20"), ("7.", "17"), ("6.7", "14"), ("6.5", "13"))


class ShellError(VirtError):
    """The host's shell, or the guest, could not be reached or refused."""


# ── which road ─────────────────────────────────────────────────
_lic: dict = {}


def licence(conn: dict) -> dict:
    """{"name", "edition"} of the host's licence, read through the API (which
    the free licence still allows) and remembered for ten minutes.

    A read that fails raises, and is not remembered: which road a host is
    worked through must never be a guess. (It was `{}`, cached, at first: one
    failed read and a free host was handed to the API for ten minutes, where
    every change of a move's clean-up is refused.)"""
    key = f"{conn.get('id')}::{conn.get('base_url')}"
    hit = _lic.get(key)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        es = E.Esxi(conn)
        raw = es.raw("LicenseManager", "ha-license-manager", ["licenses"]).get("licenses")
    except VirtError as e:
        raise VirtError(f"{conn.get('name', 'the host')}: its licence could not be read ({e})") from e
    items = E.lst(E.dig(E.obj(raw), "LicenseManagerLicenseInfo", default=[])) if raw is not None else []
    got = next(({"name": str(it.get("name", "")), "edition": str(it.get("editionKey", ""))}
                for it in items if isinstance(it, dict) and it.get("editionKey")), None)
    if got is None:
        raise VirtError(f"{conn.get('name', 'the host')}: it shows no licence to the account EnvMap signs in with. "
                        "EnvMap reads the licence to know whether VMware's API accepts changes on this host; the "
                        "account may lack the right to read licences (Global.Licenses on vSphere)")
    _lic[key] = (time.time(), got)
    return got


def restricted(conn: dict) -> bool:
    """Whether this host's licence makes VMware's API read-only: the free one,
    whose edition key starts esx.hypervisor (measured on ESXi 7.0 and 8.0;
    Enterprise Plus reads esx.enterprisePlus.cpuPackage)."""
    return licence(conn).get("edition", "").lower().startswith("esx.hypervisor")


# ── one command over SSH ───────────────────────────────────────
_worked: dict = {}            # (host, port, user) -> the way of signing in that worked there last


def _dest(host: str, user: str) -> tuple[str, str]:
    host, user = (host or "").strip().strip("[]"), (user or "").strip()
    if not _USER.match(user):
        raise ShellError("that user name cannot be used for an SSH sign-in")
    if not (_HOST.match(host) or (":" in host and _IP6.match(host))) or host.startswith("-"):
        raise ShellError("that is not an address SSH can be pointed at")
    # the same rule every other address the portal dials goes through
    try:
        urlguard.check(f"https://{'[' + host + ']' if ':' in host else host}/")
    except urlguard.BlockedURL as e:
        raise ShellError(str(e)) from e
    return host, user


def _askpass(work: str) -> str:
    """The program ssh asks for the password. It holds no secret: it prints
    the one in its environment, which only that ssh process was given."""
    script = os.path.join(work, "askpass")
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(fd, "w") as fh:
        fh.write(f'#!/bin/sh\nprintf \'%s\' "${SECRET}"\n')
    return script


def ssh(host: str, port, user: str, password: str, command: str, *, pin: str, who: str = "",
        stdin: bytes = b"", timeout: float = 60, methods: tuple = HOST_METHODS) -> tuple[int, bytes, str, list]:
    """Run one command on `host` over SSH, signed in by password.

    Returns (exit code, what it printed, what ssh and the command said on
    their error stream, the key fingerprints written down if this was the
    first contact). Exit code 255 is ssh's own: no connection, a refused
    sign-in or a refused host key; 124 is no end in time."""
    host, user = _dest(host, user)
    try:
        port = int(port or 22)
    except (TypeError, ValueError):
        raise ShellError("an SSH port is a number") from None
    if not 0 < port < 65536:
        raise ShellError("an SSH port is a number between 1 and 65535")
    work = ansible._term_scratch()
    try:
        known = os.path.join(work, "known_hosts")
        strict = pam.seed_known_hosts(pin, host, port, known)
        runenv = {"PATH": env.TOOL_PATH, "HOME": work, SECRET: password,
                  "SSH_ASKPASS": _askpass(work), "SSH_ASKPASS_REQUIRE": "force",
                  "DISPLAY": os.environ.get("DISPLAY", ":0")}
        code, out, err = 255, b"", ""
        # the way that worked there last goes first: a watcher signs in every two
        # seconds, and a refused first try each time is a stream of failed
        # sign-ins in the far end's log (and, with a recent sshd, a penalty)
        first = _worked.get((host, port, user))
        for method in ([first] if first in methods else []) + [m for m in methods if m != first]:
            argv = [env.SSH, "-F", "/dev/null", "-p", str(port), "-T",
                    "-o", "PubkeyAuthentication=no",
                    "-o", f"PreferredAuthentications={method}",
                    "-o", "NumberOfPasswordPrompts=1",
                    "-o", "BatchMode=no",
                    "-o", f"ConnectTimeout={CONNECT}",
                    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                    "-o", f"StrictHostKeyChecking={strict}",
                    "-o", f"UserKnownHostsFile={known}",
                    "-o", "GlobalKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "--", f"{user}@{host}", command]
            try:
                got = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout, env=runenv)
                code, out, err = got.returncode, got.stdout or b"", (got.stderr or b"").decode(errors="replace")
            except subprocess.TimeoutExpired:
                code, out, err = 124, b"", f"no end within {int(timeout)}s"
            except OSError as e:
                code, out, err = 255, b"", f"ssh could not be started: {e}"
            if code != 255 or not _DENIED.search(err):
                if code != 255 and code != 124:
                    _worked[(host, port, user)] = method
                break
            offered = _OFFERED.search(err)
            if not offered or method in [m.strip() for m in offered.group(1).split(",")]:
                break                # this way of signing in was open and the password was refused: once is enough
        new = []
        if code != 124 and not (code == 255 and (pam.hostkey_refused(err) or err.startswith("ssh could not"))):
            pinned = pam.pin_after(pin, host, port, known, who)
            if pinned:
                new = list(pinned.get("fingerprints") or [])
                try:
                    from . import auth
                    was = pinned.get("replaced") or {}
                    auth.audit(who or "envmap", "virt_move_ssh_key_pinned", f"{host}:{port}",
                               (f"{pin}: {', '.join(new)}" + (f"; it replaces the key written down for "
                                f"{was.get('host')}:{was.get('port')}" if was else ""))[:300])
                except Exception:                              # noqa: BLE001
                    pass
        if password:
            err = err.replace(password, "•••")
        return code, out, err.strip(), new
    finally:
        shutil.rmtree(work, ignore_errors=True)


def why_not(err: str, port) -> str:
    """ssh's own failure, in words for the person who has to fix it."""
    low = err.lower()
    if low.startswith("ssh could not be started"):
        # EnvMap's own side: say so, and never as a refused sign-in
        return err[:240]
    if pam.hostkey_refused(err):
        return ("its SSH key is not the one EnvMap wrote down at its first contact. If the machine was "
                "reinstalled, an administrator can let EnvMap trust the new key on the Moves page")
    if _DENIED.search(err):
        return "the sign-in was refused over SSH"
    if "connection refused" in low:
        return f"port {port} refuses connections (is SSH switched on there?)"
    if "timed out" in low or "no route" in low or "unreachable" in low:
        return f"port {port} does not answer from EnvMap (SSH switched off, or a firewall in between)"
    if "could not resolve" in low or "name or service not known" in low:
        return "its name does not resolve from EnvMap"
    return (err.splitlines() or ["ssh gave no reason"])[-1][:240]


# ── the .vmx file ──────────────────────────────────────────────
def vmx_guest(guest_id: str) -> str:
    """The .vmx spelling of a guest type the API calls rhel9_64Guest."""
    g = (guest_id or "").strip()
    if g in VMX_GUEST:
        return VMX_GUEST[g]
    if not re.match(r"^[A-Za-z0-9_]+Guest$", g):
        return "otherlinux-64"
    g = g[:-5]
    if g.endswith("_64"):
        g = g[:-3] + "-64"
    elif g.endswith("64"):
        g = g[:-2] + "-64"
    return g.lower()


def _manual_range(mac: str) -> bool:
    m = moveside.mac_ok(mac)
    return m.startswith("00:50:56:") and int(m[9:11], 16) <= 0x3F


def vmx_text(src: dict, *, name: str, stem: str, nets: list[dict], transfer: dict | None,
             iso_file: str | None, hw: str) -> tuple[str, list[tuple[str, int]]]:
    """The new VM as a .vmx file, and the disks to make beside it as
    [(file name, size in KiB)]. From an ESXi source: the same controllers in
    the same PCI slots, the same hardware version, every card in its slot with
    its own address. From Proxmox: one paravirtual SCSI controller and VMXNET3
    cards. The same choices as moveside.esxi_spec makes through the API.

    With `iso_file` None the VM gets an empty CD drive, no transfer card, and
    starts from its disk: the new VM of a powered-off move (coldside)."""
    lines: list[str] = []

    def put(key: str, value) -> None:
        v = str(value)
        if '"' in v or "\n" in v or "\r" in v:
            raise VirtError("a value that cannot be written into a .vmx file")
        lines.append(f'{key} = "{v}"')

    cpus = int(src["cpus"])
    cps = max(1, int(src.get("cores") or cpus))
    if cpus % cps:
        cps = 1
    put(".encoding", "UTF-8")
    put("config.version", "8")
    put("virtualHW.version", int(hw))
    put("displayName", E.check_name(name, "VM name"))
    put("guestOS", vmx_guest(src.get("guest_id", "")) if src["flavor"] == "esxi" else "otherlinux-64")
    put("memSize", int(src["memory_mb"]))
    put("numvcpus", cpus)
    if cps > 1:
        put("cpuid.coresPerSocket", cps)
    put("firmware", "efi" if src["firmware"] == "efi" else "bios")
    if src["firmware"] == "efi":
        put("uefi.secureBoot.enabled", "FALSE")
    if iso_file is not None:
        # the CD before the disk, at every start: see the module's notes
        put("bios.bootOrder", "cdrom,hdd")
    put("nvram", f"{stem}.nvram")
    put("uuid.action", "create")
    put("pciBridge0.present", "TRUE")
    for b in (4, 5, 6, 7):
        put(f"pciBridge{b}.present", "TRUE")
        put(f"pciBridge{b}.virtualDev", "pcieRootPort")
        put(f"pciBridge{b}.functions", "8")
    put("vmci0.present", "TRUE")
    put("hpet0.present", "TRUE")
    put("svga.present", "TRUE")
    put("floppy0.present", "FALSE")
    put("tools.syncTime", "FALSE")

    sata_bus = None
    if src["flavor"] == "esxi":
        names = {}
        for c in src["controllers"]:
            bus = int(c.get("bus") or 0)
            if c["type"] in VMX_SCSI:
                p = f"scsi{bus}"
                put(f"{p}.present", "TRUE")
                put(f"{p}.virtualDev", VMX_SCSI[c["type"]])
                put(f"{p}.sharedBus", VMX_SHARE.get(c.get("shared") or "noSharing", "none"))
            elif c["type"] == "VirtualAHCIController":
                p = f"sata{bus}"
                put(f"{p}.present", "TRUE")
                sata_bus = bus if sata_bus is None else sata_bus
            elif c["type"] == "VirtualNVMEController":
                p = f"nvme{bus}"
                put(f"{p}.present", "TRUE")
            else:
                continue
            if c.get("slot") is not None:
                put(f"{p}.pciSlotNumber", int(c["slot"]))
            names[c["key"]] = p
        where = [(names.get(d["ctrl_key"]), d.get("unit") or 0) for d in src["disks"]]
        if any(p is None for p, _ in where):
            raise VirtError("a disk of the VM sits on a controller that cannot be built on the new VM")
    else:
        put("scsi0.present", "TRUE")
        put("scsi0.virtualDev", "pvscsi")
        put("scsi0.sharedBus", "none")
        units = [u for u in range(16) if u != 7]
        if len(src["disks"]) > len(units):
            raise VirtError("more disks than one controller holds")
        where = [("scsi0", units[i]) for i in range(len(src["disks"]))]
    disks = []
    for i, (d, (p, unit)) in enumerate(zip(src["disks"], where)):
        fname = f"{stem}.vmdk" if i == 0 else f"{stem}_{i}.vmdk"
        put(f"{p}:{int(unit)}.present", "TRUE")
        put(f"{p}:{int(unit)}.fileName", fname)
        if p.startswith("scsi"):
            put(f"{p}:{int(unit)}.deviceType", "scsi-hardDisk")
        disks.append((fname, int(math.ceil(d["bytes"] / 1024))))
    if sata_bus is None:
        sata_bus = 3
        put("sata3.present", "TRUE")
    cd = f"sata{sata_bus}:29"
    put(f"{cd}.present", "TRUE")
    if iso_file is not None:
        put(f"{cd}.deviceType", "cdrom-image")
        put(f"{cd}.fileName", iso_file)
        put(f"{cd}.startConnected", "TRUE")
    else:
        put(f"{cd}.deviceType", "atapi-cdrom")
        put(f"{cd}.fileName", "emptyBackingString")
        put(f"{cd}.clientDevice", "TRUE")
        put(f"{cd}.startConnected", "FALSE")

    def card(i: int, model: str, network: str, mac: str, slot=None, at_power_on: bool = True) -> None:
        p = f"ethernet{i}"
        put(f"{p}.present", "TRUE")
        put(f"{p}.virtualDev", model)
        put(f"{p}.networkName", E.check_name(network, "network"))
        put(f"{p}.addressType", "static")
        put(f"{p}.address", moveside.mac_ok(mac))
        if not _manual_range(mac):
            # an address from outside VMware's range for addresses set by hand
            put(f"{p}.checkMACAddress", "FALSE")
        if slot is not None:
            put(f"{p}.pciSlotNumber", int(slot))
        put(f"{p}.startConnected", "TRUE" if at_power_on else "FALSE")

    for i, (n, m) in enumerate(zip(src["nics"], nets)):
        card(i, VMX_NIC.get(n.get("model", ""), "vmxnet3"), m["network"], n["mac"],
             n.get("slot") if src["flavor"] == "esxi" else None)
    if transfer is not None:
        # the transfer card is connected by hand after each start (EsxiShell.start):
        # disconnected at the end, it then stays disconnected for good
        card(len(src["nics"]), "vmxnet3", transfer["dst_net"], transfer["dst_mac"], at_power_on=False)
    return "\n".join(lines) + "\n", disks


def _key(line: str) -> str:
    return line.split("=", 1)[0].strip().lower() if "=" in line else ""


def vmx_set(text: str, values: dict) -> str:
    """The .vmx with these keys set: replaced where they are, added otherwise."""
    want = {k.lower(): (k, v) for k, v in values.items()}
    out, seen = [], set()
    for line in text.splitlines():
        k = _key(line)
        if k in want:
            if k not in seen:
                out.append(f'{want[k][0]} = "{want[k][1]}"')
                seen.add(k)
            continue
        out.append(line)
    out += [f'{name} = "{v}"' for k, (name, v) in want.items() if k not in seen]
    return "\n".join(out) + "\n"


def vmx_drop(text: str, prefix: str) -> str:
    """The .vmx without any key that starts with `prefix` (like "ethernet2.")."""
    p = prefix.lower()
    return "\n".join(ln for ln in text.splitlines() if not _key(ln).startswith(p)) + "\n"


def vmx_cards(text: str) -> list[int]:
    """The numbers of the network cards a .vmx has."""
    got = set()
    for line in text.splitlines():
        m = re.match(r'^\s*ethernet(\d+)\.present\s*=\s*"?true"?\s*$', line, re.I)
        if m:
            got.add(int(m.group(1)))
    return sorted(got)


def vmx_card_with(text: str, mac: str) -> int | None:
    """The number of the card that has this address, set by hand or generated."""
    want = moveside.mac_ok(mac)
    for line in text.splitlines():
        m = re.match(r'^\s*ethernet(\d+)\.(?:generatedAddress|address)\s*=\s*"([^"]*)"\s*$', line, re.I)
        if m and m.group(2).strip().lower() == want:
            return int(m.group(1))
    return None


# ── the side ───────────────────────────────────────────────────
class EsxiShell(moveside.Esxi):
    """An ESXi host on the free licence: read through the API, changed
    through its shell, its guests reached over SSH."""
    road = "shell"

    def __init__(self, conn: dict, moid: str | None = None, guest_user: str = "",
                 guest_password: str = "", guest_host: str = "", who: str = "", guest_fixed: bool = False):
        super().__init__(conn, moid, guest_user, guest_password)
        self.guest_host, self.who = (guest_host or "").strip(), who
        self.guest_fixed = guest_fixed         # the address was settled when the move was checked
        self.card_mac = ""
        self.pinned: list[str] = []            # keys written down by a first contact, for the check to show
        self._guest_at: tuple[str, int] | None = None
        self._said = ""                        # what the guest's last command said on its error stream
        self.tcard = ""                        # the new VM's transfer card: connected by hand after a start
        self.cd = ""                           # the new VM's receiver CD: a reset must find it connected
        self.made_vmx = ""                     # the settings file EnvMap wrote for this VM, when it made it
        self.blank = False                     # the new VM's disks hold nothing yet (its first start)

    # the host's shell
    @property
    def _addr(self) -> tuple[str, int]:
        return urllib.parse.urlsplit(self.conn["base_url"]).hostname or "", 22

    @property
    def _vmid(self) -> int:
        if not re.match(r"^\d{1,9}$", str(self.moid or "")):
            raise VirtError("this VM has no number the host's shell knows it by")
        return int(self.moid)

    def sh(self, command: str, stdin: bytes = b"", timeout: float = 120) -> str:
        """One command in the host's shell; what it printed. Anything but a
        clean exit is an error carrying the host's own words."""
        host, port = self._addr
        code, out, err, new = ssh(host, port, self.conn.get("username", ""), self.conn.get("token", ""),
                                  command, pin=f"move:host:{self.conn.get('id', '')}", who=self.who,
                                  stdin=stdin, timeout=timeout, methods=HOST_METHODS)
        name = self.conn.get("name", host)
        for f in new:
            self.pinned.append(f"first SSH contact with {name}: its key was written down ({f}); a different key "
                               "is refused from now on")
        what = command.split(" /vmfs")[0].split(" '/vmfs")[0][:60]
        if code == 124:
            raise ShellError(f"{name} did not finish `{what}` in {int(timeout)}s (it may still be running there)")
        if code == 255:
            raise ShellError(f"{name} could not be reached over SSH: {why_not(err, port)}")
        if code:
            said = (out.decode(errors="replace") + "\n" + err).strip().splitlines()
            raise ShellError(f"{name} refused `{what}`: {' | '.join(said[-3:])[:300] or f'exit {code}'}")
        return out.decode(errors="replace")

    def _vol(self, ds_path: str) -> str:
        """`[datastore] dir/file` as the path the shell sees. Every use is
        quoted, so only what quoting cannot carry is refused: a path that
        climbs, or one with a control character in it."""
        m = re.match(r"^\[([^\]]+)\] ?(.*)$", ds_path or "")
        if not m:
            raise VirtError("not a datastore path")
        ds = E.check_name(m.group(1), "datastore")
        rest = m.group(2).strip("/")
        if rest and (".." in rest.split("/") or any(ord(ch) < 32 or ord(ch) == 127 for ch in rest)):
            raise VirtError("a datastore path the shell cannot be given")
        return f"/vmfs/volumes/{ds}" + (f"/{rest}" if rest else "")

    def _look(self, path: str) -> bool:
        """Whether `path` is there, on a datastore that can be looked into.
        One that cannot (unmounted, or gone) raises: "it is not there" must
        never be what a failed look reads as, because what follows from "not
        there" is deleting less, or saying more was deleted than was."""
        m = re.match(r"^(/vmfs/volumes/[^/]+)(/.*)?$", path)
        if not m:
            raise VirtError("not a path on a datastore")
        out = self.sh(f"test -d {q(m.group(1))} || {{ echo blind; exit 0; }}; "
                      f"test -e {q(path)} && echo taken || echo free")
        if "blind" in out:
            raise ShellError(f"{self.conn.get('name', 'the host')}: the datastore {m.group(1).rsplit('/', 1)[1]} "
                             "cannot be looked into from the host's shell (is it mounted?)")
        return "taken" in out

    def _write(self, path: str, data: bytes, timeout: float = 300) -> None:
        """Put `data` at `path`, whole or not at all: received under another
        name, hashed there, and only then moved into place."""
        tmp = path + ".envmap"
        digest = hashlib.sha256(data).hexdigest()
        self.sh(f"cat > {q(tmp)} && [ \"$(sha256sum < {q(tmp)} | cut -d ' ' -f 1)\" = {digest} ] "
                f"&& mv -f {q(tmp)} {q(path)} || {{ rm -f {q(tmp)}; exit 1; }}", stdin=data, timeout=timeout)

    def _until(self, ok, what: str, limit: float = 60) -> None:
        """A change, read back through the API: vim-cmd's word is not taken for it."""
        t0, last = time.time(), ""
        while True:
            try:
                if ok():
                    return
                last = ""
            except VirtError as e:
                last = str(e)                   # the host could not be read: that is not "it did not happen"
            if time.time() - t0 > limit:
                name = self.conn.get("name", "the host")
                if last:
                    raise ShellError(f"{name}: whether it worked could not be read back ({last})")
                raise ShellError(f"{name}: {what}, as read back from the host")
            time.sleep(1)

    def preflight(self) -> tuple[list[str], list[str]]:
        """Whether the shell road is open on this host: (problems, notes)."""
        name = self.conn.get("name", "the host")
        lic = licence(self.conn).get("name") or "the free ESXi licence"
        notes = [f"{name} runs {lic}, on which VMware's API only reads: EnvMap works on this host "
                 "through its own shell over SSH"]
        problems: list[str] = []
        try:
            svc = {s.get("key"): s for s in E.host_detail(self.es).get("services", [])}
            if "TSM-SSH" in svc and not svc["TSM-SSH"].get("running"):
                problems.append(f"SSH is switched off on {name}. Start it in the host's own client (Host → Manage → "
                                "Services → TSM-SSH → Start); EnvMap cannot, because switching it on is a change the "
                                "free licence refuses")
                return problems, notes
        except VirtError:
            pass
        try:
            out = self.sh("vim-cmd vmsvc/getallvms > /dev/null && echo envmap-shell-ok", timeout=40)
            if "envmap-shell-ok" not in out:
                problems.append(f"{name}: the shell answered, but not the way an ESXi shell does")
        except VirtError as e:
            problems.append(str(e))
        if self.moid and not problems:
            # the VM that moves: its settings file is edited at the end, so a
            # path the shell cannot be given is said now, not after the move
            try:
                self._vol(E.vm_detail(self.es, self.moid).get("vmx", ""))
            except VirtError as e:
                problems.append(f"the VM's folder on {name}: {e}")
        notes += self.pinned
        self.pinned = []
        return problems, notes

    # into the guest: SSH, with the guest's own sign-in
    def guest_address(self) -> str:
        host, port = self._guest()
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def _guest(self) -> tuple[str, int]:
        """Where the guest's SSH is. Only ever an address VMware Tools report
        for this VM: the form's address chooses among them (and the port), it
        cannot point EnvMap's SSH at some other machine. Never this machine
        itself: what the guest says its addresses are is the guest's to say."""
        if self._guest_at:
            return self._guest_at
        raw, port = self.guest_host, 22
        m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$", raw) or re.match(r"^([^:\[\]]+):(\d{1,5})$", raw)
        if m:
            raw, port = m.group(1), int(m.group(2) or 22)
        if not self.guest_fixed:
            d = E.vm_detail(self.es, self.moid)
            known = [d.get("ip") or ""] + [ip for n in d.get("nets") or [] for ip in n.get("ips") or []]
            known = [ip for ip in dict.fromkeys(known) if ip]
            if not known:
                raise VirtError("VMware Tools report no address for this guest, so EnvMap cannot tell where its SSH is")
            if raw and raw not in known:
                raise VirtError(f"{raw} is not an address VMware Tools report for this guest (they report "
                                f"{', '.join(known[:6])})")
            raw = raw or known[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            raise VirtError("the guest's address is not an IP address") from None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise VirtError(f"{raw} is not an address a guest is reached at")
        self._guest_at = (raw, port)
        return self._guest_at

    def _gsh(self, command: str, stdin: bytes = b"", timeout: float = 60) -> tuple[int, bytes]:
        if not self.user:
            raise VirtError("the guest's own sign-in is needed to reach into an ESXi guest")
        host, port = self._guest()
        code, out, err, new = ssh(host, port, self.user, self.password, command,
                                  pin=f"move:guest:{self.conn.get('id', '')}:{self.moid}", who=self.who,
                                  stdin=stdin, timeout=timeout, methods=GUEST_METHODS)
        for f in new:
            self.pinned.append(f"first SSH contact with the guest at {host}: its key was written down ({f})")
        if code == 124:
            raise ShellError("the guest command did not finish in time")
        if code == 255:
            e = ShellError(f"the guest at {host} could not be reached over SSH: {why_not(err, port)}")
            # the sign-in itself was refused: what the migration page asks for again
            e.denied = bool(_DENIED.search(err)) and not pam.hostkey_refused(err)
            raise e
        self._said = err
        return code, out

    def _root(self, command: str) -> str:
        return command if self.user == "root" else f"sudo -n /bin/sh -c {q(command)}"

    @staticmethod
    def _after(mark: str, out: bytes) -> bytes | None:
        """What a command printed, after its own first line. A login shell may
        print before the command starts (bash reads ~/.bashrc under sshd):
        that is not the command's, and counted as its output it would shift
        every position the engine's log is read from."""
        k = out.find(mark.encode() + b"\n")
        return None if k < 0 else out[k + len(mark) + 1:]

    def exec(self, script: str, timeout: float = 300) -> tuple[int, str]:
        """The script runs as root: directly when signed in as root, otherwise
        through sudo without a password (which the user must have)."""
        mark = "envmap-" + secrets.token_hex(8)
        code, out = self._gsh(self._root("/bin/sh -s 2>&1"),
                              stdin=f"printf '%s\\n' {mark}\n{script}\n".encode(), timeout=timeout + 15)
        body = self._after(mark, out)
        if body is None:
            said = (self._said or out.decode(errors="replace")).strip()
            if self.user != "root":
                raise ShellError(f"the guest commands do not run as root: sign in as root, or as a user who may use "
                                 f"sudo without a password ({said.splitlines()[-1][:160] if said else 'sudo gave no reason'})")
            raise ShellError("the guest's shell did not run the command: " + (said[-200:] or "it said nothing"))
        return code, body.decode(errors="replace")

    def put(self, path: str, data: bytes) -> None:
        code, out = self._gsh(self._root(f"umask 077; cat > {q(path)}"), stdin=data, timeout=900)
        if code:
            raise VirtError(f"the guest refused the file: {out.decode(errors='replace')[-200:]}")

    def get(self, path: str, limit: int = 1 << 20) -> bytes:
        mark = "envmap-" + secrets.token_hex(8)
        code, out = self._gsh(self._root(f"printf '%s\\n' {mark}; head -c {int(limit)} {q(path)}"), timeout=120)
        body = self._after(mark, out)
        if code or body is None:
            raise VirtError("the guest did not hand the file over")
        return body[:limit]

    def _start_quiet(self, cmd: str) -> None:
        try:
            self.exec(cmd, 20)
        except VirtError:
            pass

    # devices
    def cards(self) -> list[str]:
        """The keys of the VM's network cards, as the host reports them now."""
        return [str(n["key"]) for n in E.vm_detail(self.es, self.moid)["nics"]]

    def strays(self, before: list, network: str) -> list[str]:
        """Cards the VM has now and did not have then that could be the
        transfer card EnvMap was adding: a VMXNET3 card on that network."""
        return [str(n["key"]) for n in E.vm_detail(self.es, self.moid)["nics"]
                if str(n["key"]) not in [str(k) for k in before] and n.get("type") == "VirtualVmxnet3"
                and n.get("network") == network]

    def _device(self, key) -> dict:
        return next((d for d in E.vm_detail(self.es, self.moid)["devices"] if str(d["key"]) == str(key)), {})

    def _connect(self, key, on: bool) -> None:
        self.sh(f"vim-cmd vmsvc/device.connection {self._vmid} {int(key)} {1 if on else 0}")
        self._until(lambda: bool(self._device(key).get("connected")) is on,
                    f"the device was not {'connected' if on else 'disconnected'}", 30)

    def add_card(self, mac: str, network: str, vlan: str = "", model: str = "vmxnet3") -> str:
        """vim-cmd adds a card with an address VMware chooses, not the one
        asked for: the address it got is left in `card_mac` for the move."""
        before = set(self.cards())
        self.sh(f"vim-cmd vmsvc/devices.createnic {self._vmid} vmxnet3 {q(E.check_name(network, 'network'))}")
        new = []
        for _ in range(30):
            new = [n for n in E.vm_detail(self.es, self.moid)["nics"] if str(n["key"]) not in before]
            if new and new[0].get("mac"):
                break
            time.sleep(1)
        if not new or not new[0].get("mac"):
            raise VirtError("the host did not add the transfer card")
        self.card_mac = moveside.mac_ok(new[0]["mac"])
        return str(new[0]["key"])

    def remove_card(self, key) -> str | None:
        if not str(key or "").strip():
            return None
        if self.status() == "stopped":
            # found in the settings file by its address, not by counting cards
            mac = next((n.get("mac") or "" for n in E.vm_detail(self.es, self.moid)["nics"]
                        if str(n["key"]) == str(key)), "")
            if not mac:
                return None                     # it is not on the VM any more

            def drop(text: str) -> str:
                n = vmx_card_with(text, mac)
                if n is None:
                    raise VirtError("the transfer card was not found in the VM's settings file")
                return vmx_drop(text, f"ethernet{n}.")
            self._edit_vmx(drop)
            self._until(lambda: str(key) not in self.cards(), "the transfer card is still on the VM", 30)
            return None
        dev = self._device(key)
        if not dev:
            return None
        self._connect(key, False)
        if dev.get("start_connected"):
            return ("the transfer card disconnected and left on the VM: the host's shell cannot take a card out of a "
                    "running VM. It connects again when the VM is next powered on, so remove it in the VM's "
                    "settings before then")
        return ("the transfer card disconnected and left on the VM (the host's shell cannot take a card out of a "
                "running VM). It stays disconnected; remove it in the VM's settings when the VM is next powered off")

    # power
    def _cd_ready(self) -> None:
        """Before a receiver is powered on: its CD is there, set to connect
        at power-on, and its image is on the datastore. Refused otherwise,
        before anything starts: a VM started without its CD runs whatever its
        disks hold."""
        name = self.conn.get("name", "the host")
        dev = self._device(self.cd)
        if dev.get("kind") != "cdrom":
            raise ShellError(f"{name}: the new VM has no receiver CD any more, so it was not started")
        if not dev.get("start_connected"):
            raise ShellError(f"{name}: the new VM's CD drive is set not to connect at power-on, so the VM was not "
                             "started: without the CD it would start whatever its disks hold. In the host's own "
                             "client, tick Connect at power on for it, then try again")
        if not dev.get("iso") or not self._look(self._vol(dev["iso"])):
            raise ShellError(f"{name}: the new VM's CD no longer points at the receiver's image on the datastore, "
                             "so the VM was not started")

    def start(self) -> None:
        """Power on. For the new VM while it is still a receiver (`cd` is
        set): its CD is looked at before the power-on, and a receiver that
        does not come up whole is powered off again, not left to run what its
        disks hold."""
        if self.cd:
            self._cd_ready()
        try:
            self.sh(f"vim-cmd vmsvc/power.on {self._vmid}", timeout=150)
        except ShellError as e:
            asked = ""
            try:
                asked = self.sh(f"vim-cmd vmsvc/message {self._vmid}", timeout=30).strip()
            except VirtError:
                pass
            if asked and "no message" not in asked.lower():
                raise ShellError(f"ESXi asks a question before it starts the VM, and waits for an answer in the "
                                 f"host's own client: {' '.join(asked.split())[:300]}") from e
            raise
        if not self.cd:
            self._until(lambda: self.status() == "running", "the VM did not power on")
            return
        try:
            self._until(lambda: self.status() == "running", "the VM did not power on")
            grace = CD_GRACE_BLANK if self.blank else CD_GRACE
            t0 = time.time()
            while not self._device(self.cd).get("connected"):
                # the host may show the device a moment after the power state
                if time.time() - t0 > grace:
                    raise ShellError(f"{self.conn.get('name', 'the host')}: the host did not connect the new VM's "
                                     f"receiver CD within {grace}s of its start")
                time.sleep(1)
            if self.tcard and not self._device(self.tcard).get("connected"):
                # the transfer card does not connect at power-on by itself (vmx_text)
                self._connect(self.tcard, True)
        except VirtError as e:
            # it runs, but not as a whole receiver: without its CD it starts
            # whatever its disks hold, and once the copy is there that is a
            # second system
            try:
                self.stop()
                off = "It was powered off again at once"
            except VirtError as e2:
                off = f"It could not be powered off again ({e2}): power it off now"
            raise ShellError(f"{e}. {off}: a receiver that did not come up whole is not left running, because "
                             "without its CD the VM starts whatever its disks hold") from e

    def stop(self) -> None:
        if self.status() == "stopped":
            return
        try:
            self.sh(f"vim-cmd vmsvc/power.off {self._vmid}", timeout=150)
        except ShellError:
            if self.status() != "stopped":      # it may have powered itself off a moment before
                raise
        self._until(lambda: self.status() == "stopped", "the VM did not power off")

    def reset(self) -> None:
        """A restart, as a power-off and a power-on. A power-on is what
        connects the receiver CD (it is set to connect then), and it is what
        this same move's first start already did; whether a reset keeps a
        device connected only a real host can say, and what a restart without
        the CD would start is the copy on the disks. `start` then connects
        the transfer card, whoever switched the VM off and on in between."""
        self.stop()
        self.start()

    def _is_mine(self) -> None:
        """A VM is destroyed only if its number still names the settings file
        EnvMap wrote: a host gives numbers out again."""
        if self.made_vmx and E.vm_detail(self.es, self.moid).get("vmx") != self.made_vmx:
            raise ShellError(f"{self.conn.get('name', 'the host')}: VM number {self.moid} is no longer the VM EnvMap "
                             "made there, so it is left alone")

    def destroy(self) -> None:
        self._is_mine()
        if self.status() == "running":
            self.stop()
        self.sh(f"vim-cmd vmsvc/destroy {self._vmid}", timeout=600)
        self._until(lambda: self.status() == "", "the VM is still there", 30)

    def status(self) -> str:
        try:
            return super().status()
        except VirtError as e:
            if getattr(e, "fault", "") == "ManagedObjectNotFound":
                return ""                       # gone: the host's own name for it, not words in a message
            raise

    # the .vmx of a VM that is powered off
    def _edit_vmx(self, change) -> None:
        if self.status() != "stopped":
            raise VirtError("a VM's settings file is edited only while the VM is powered off")
        path = self._vol(E.vm_detail(self.es, self.moid).get("vmx", ""))
        if not path.endswith(".vmx"):
            raise VirtError("the VM's settings file could not be found")
        text = self.sh(f"cat {q(path)}")
        new = change(text)
        if new.strip() == text.strip():
            return
        self._write(path, new.encode())
        self.sh(f"vim-cmd vmsvc/reload {self._vmid}")

    def rename(self, name: str) -> None:
        name = E.check_name(name, "VM name")
        if E.vm_detail(self.es, self.moid).get("name") == name:
            return
        self._edit_vmx(lambda t: vmx_set(t, {"displayName": name}))
        self._until(lambda: E.vm_detail(self.es, self.moid).get("name") == name, "the VM was not renamed", 30)

    def disconnect_cards(self) -> None:
        self._edit_vmx(lambda t: vmx_set(t, {f"ethernet{n}.startConnected": "FALSE" for n in vmx_cards(t)}))
        self._until(lambda: not any(n.get("start_connected") for n in E.vm_detail(self.es, self.moid)["nics"]),
                    "a card of the old VM would still connect at power-on", 30)

    def boot_disk_first(self) -> None:
        raise VirtError("the host's shell cannot change a running VM's start order: after a move the receiver CD "
                        "is dealt with by cd_done")

    def cd_out(self, key) -> str | None:
        if not str(key or "").strip():
            return None
        self._connect(key, False)
        return "the receiver CD disconnected (the host's shell cannot take it out of a running VM)"

    def cd_done(self, key, iso: str) -> str:
        """The system has arrived: the receiver must never start on this VM
        again. The shell can neither take the CD out of a running VM nor
        change its start order, so the CD is disconnected and its image
        emptied (64 KiB stay: an image that is gone makes ESXi ask a question
        at the next power-on, and nobody is there to answer).

        Returns what was done. While the image still holds the receiver it
        raises instead, saying what that means for this VM's next start: the
        move's log and its last line must not say less than that."""
        out = emptied = False
        why: list[str] = []
        if str(key or "").strip():
            try:
                self._connect(key, False)
            except VirtError as e:
                why.append(f"it could not be disconnected: {e}")
            try:
                out = not self._device(key).get("connected")    # as the host says, whatever the command said
            except VirtError:
                out = False
        if iso:
            try:
                file = self._vol(iso)
                if not _ISO.match(file.rsplit("/", 1)[-1]):
                    raise VirtError("not a receiver CD")
                self._write(file, bytes(STUB))
                emptied = True
            except VirtError as e:
                why.append(f"its image could not be emptied: {e}")
        if emptied:
            return ("the receiver CD " + ("disconnected and its image emptied" if out else "left connected, its image emptied")
                    + ": 64 KiB stay on the datastore, because it is still the image of the CD on the VM. The CD stays "
                    "first in the VM's start order (the host's shell cannot change that on a running VM) and has "
                    "nothing to start, so the VM starts from its disk. Take the CD out of the VM's settings when the "
                    "VM is next powered off, then delete the image")
        said = "; ".join(why) or "this move has no record of its image"
        if out:
            raise ShellError(f"the receiver CD is disconnected, but its image still holds the receiver ({said}). The "
                             "CD is first in the VM's start order and connects again at the next power-on, so a "
                             "power-off and power-on of this VM would start the receiver, not the system. Before the "
                             "VM is next powered off, edit its CD drive in the host's own client: untick Connect at "
                             "power on")
        raise ShellError(f"the receiver CD is still connected and still holds the receiver ({said}). The CD is first "
                         "in the VM's start order, so this VM's next restart would start the receiver, not the "
                         "system. Edit its CD drive in the host's own client now: untick Connected and Connect at "
                         "power on")

    # the target
    def upload_iso(self, datastore: str, name: str, data: bytes) -> str:
        if not _ISO.match(name):
            raise VirtError("not a receiver CD's name")
        folder = self._vol(E.ds_path(datastore, "envmove"))
        self.sh(f"mkdir -p {q(folder)}")
        self._write(f"{folder}/{name}", data, timeout=1800)
        return E.ds_path(datastore, f"envmove/{name}")

    def delete_iso(self, path: str) -> str | None:
        """Delete a receiver CD's image that no VM uses any more (one a VM
        still uses is emptied instead: `cd_done`), and see that it is gone:
        `rm -f` on a path that cannot be reached says nothing."""
        file = self._vol(path)
        if not _ISO.match(file.rsplit("/", 1)[-1]):
            raise VirtError("not a receiver CD")
        if not self._look(file):
            return "the receiver CD's image was already gone"
        self.sh(f"rm -f {q(file)}")
        if self._look(file):
            raise ShellError(f"{self.conn.get('name', 'the host')}: the receiver CD's image is still there after "
                             "it was deleted")
        return None

    def _hw(self, src: dict) -> str:
        m = re.match(r"^vmx-(\d+)$", src.get("hw_version") or "") if src["flavor"] == "esxi" else None
        if m:
            return m.group(1)
        ver = str(self.es.svc.get("version") or "")
        return next((hw for start, hw in HW_FOR if ver.startswith(start)), "13")

    def plan_build(self, src: dict, *, name: str, datastore: str) -> dict:
        """What `build` will make, so it can be written down before any of it
        exists: {"datastore", "folder", "stem", "disks", "vmx"}. Nothing is
        made here."""
        stem = re.sub(r"[^A-Za-z0-9._-]", "-", E.check_name(name, "VM name")).strip(".-") or "vm"
        ds = E.check_name(datastore, "datastore")
        folder = stem
        if self._look(self._vol(E.ds_path(ds, folder))):
            folder = f"{stem}-{secrets.token_hex(3)}"
        n = len(src["disks"])
        return {"datastore": ds, "folder": folder, "stem": stem, "mark": f".envmap-{secrets.token_hex(8)}",
                "disks": [f"{stem}.vmdk" if i == 0 else f"{stem}_{i}.vmdk" for i in range(n)],
                "vmx": E.ds_path(ds, f"{folder}/{stem}.vmx")}

    def _registered(self, vmx: str) -> str:
        """The number of the VM whose settings file is exactly `vmx`, or ""."""
        for line in self.sh("vim-cmd vmsvc/getallvms").splitlines():
            m = re.match(r"^\s*(\d+)\s", line)
            if m and re.search(re.escape(vmx) + r"(\s|$)", line):
                return m.group(1)
        return ""

    def unmake(self, plan: dict, vm: str = "") -> str:
        """Take away what `build` made of `plan`, however far it got: the VM
        if the host knows it, the files `build` wrote, by name, and the folder
        if that leaves it empty. Nothing else is touched. `vm` is the number
        the move's record holds for the new VM, when it got that far.

        Returns what was done, in a sentence for the move's log. When it
        returns, no VM of this move is registered on the host any more: what
        it could not find out, or could not do, raises instead. The caller
        decides from that, never from the words of the sentence."""
        base = self._vol(E.ds_path(plan["datastore"], plan["folder"]))
        mark = plan.get("mark") or ""
        if not re.match(r"^\.envmap-[0-9a-f]{16}$", mark):
            raise ShellError("this move's record of the new VM is not complete, so nothing of it was touched")
        # only a folder that carries this move's own mark is EnvMap's to empty:
        # one that was there before, or that somebody else made since, is not
        mine = self._look(f"{base}/{mark}")
        # the VM: by the mark and its settings file, or, with the mark gone, by
        # the number AND the settings file the move's record holds (`destroy`
        # refuses a number that names any other file)
        moid = self._registered(plan["vmx"]) if mine else str(vm or "")
        did = ""
        if moid:
            self.moid, self.made_vmx = moid, plan["vmx"]
            if self.status() != "":
                self.destroy()                  # takes the VM's own files with it
                did = "the new VM deleted"
        if not mine:
            if self._look(base):
                return ((did + "; " if did else "") + f"the folder {plan['folder']} on the target was left alone: it "
                        "does not carry this move's mark, so it is not EnvMap's to empty")
            return did or "nothing of the new VM is on the target"
        stem = plan["stem"]
        for f in ([f"{stem}.vmx", f"{stem}.vmx.envmap", f"{stem}.nvram", f"{stem}.vmsd", f"{stem}.vmxf"]
                  + [x for d in plan["disks"] for x in (d, f"{d[:-5]}-flat.vmdk")] + [mark]):
            self.sh(f"rm -f {q(base + '/' + f)}")
        try:
            self.sh(f"rmdir {q(base)}")
        except VirtError:
            return (f"what had been made of the new VM taken away; its folder {plan['folder']} stays, because "
                    "something that is not EnvMap's is in it")
        return "what had been made of the new VM taken away"

    def settle(self, plan: dict) -> None:
        """The move is over and the VM stays: its folder needs no mark any more."""
        mark = (plan or {}).get("mark") or ""
        if re.match(r"^\.envmap-[0-9a-f]{16}$", mark):
            self.sh(f"rm -f {q(self._vol(E.ds_path(plan['datastore'], plan['folder'])) + '/' + mark)}")

    def build(self, src: dict, *, name: str, datastore: str, nets: list[dict], transfer: dict | None,
              iso: str | None, plan: dict | None = None) -> dict:
        """The new VM: a folder, blank disks of the same sizes, a .vmx, and
        the host told about it. {"vm", "cd", "tcard", "vmx"}. A failed attempt
        takes away what it made. With `iso` None: no receiver CD and no
        transfer card (the new VM of a powered-off move)."""
        plan = plan or self.plan_build(src, name=name, datastore=datastore)
        stem = plan["stem"]
        base = self._vol(E.ds_path(plan["datastore"], plan["folder"]))
        vmx, disks = vmx_text(src, name=name, stem=stem, nets=nets, transfer=transfer,
                              iso_file=self._vol(iso) if iso is not None else None, hw=self._hw(src))
        self.moid = None
        mark = plan.get("mark") or f".envmap-{secrets.token_hex(8)}"
        plan["mark"] = mark
        # a plain mkdir: it fails if the folder is there, and then nothing of it is EnvMap's
        self.sh(f"mkdir {q(base)} && : > {q(base + '/' + mark)}")
        try:
            for fname, kib in disks:
                self.sh(f"vmkfstools -c {int(kib)}k -d thin {q(base + '/' + fname)}", timeout=900)
            self._write(f"{base}/{stem}.vmx", vmx.encode())
            out = self.sh(f"vim-cmd solo/registervm {q(base + '/' + stem + '.vmx')}", timeout=120)
            m = re.search(r"^\s*(\d+)\s*$", out, re.M)
            self.moid = m.group(1) if m else self._registered(plan["vmx"])
            if not self.moid:
                raise VirtError(f"the host did not register the VM: {out.strip()[-160:]}")
            self.made_vmx = plan["vmx"]
            keys = self.device_keys()
            cd = (keys["cdroms"] or [""])[0]
            tcard = keys["nics"].get(moveside.mac_ok(transfer["dst_mac"]), "") if transfer is not None else ""
            if iso is not None and (not cd or not tcard):
                # without them the receiver cannot start or cannot be reached,
                # and that would only show much later, as something else
                raise VirtError("the host registered the new VM without its " + ("receiver CD" if not cd else "transfer card"))
        except Exception:
            try:
                self.unmake(plan)
            except VirtError:
                pass
            raise
        # the mark stays in the folder until the move is over (settle): whatever
        # happens before then, `unmake` still knows the folder is this move's
        return {"vm": self.moid, "cd": cd, "vmx": plan["vmx"], "tcard": tcard}

    def create(self, cfg_xml: str) -> str:
        raise VirtError("on the free ESXi licence a VM is built through the host's shell, not created through the API")
