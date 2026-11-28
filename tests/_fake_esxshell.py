"""What stands on the far end of SSH in tests/test_esxshell.py.

    SshWorld    a program that takes ssh's place (app.env.SSH points at it). It
                reads the password the way ssh does (the askpass program),
                keeps the known_hosts file ssh would, tries the one way of
                signing in it was told to, and asks this process what the far
                end says.
    EsxiShell   the shell of a stand-in ESXi host (tests/_fake_esxi.py): the
                vim-cmd, vmkfstools and file commands EnvMap Move sends, acting
                on the same VMs the stand-in's API shows. It knows what a VM
                starts from (the CD or the disk), can be told to fail a
                command, to drop the connection after one, to cut an upload
                short, to register a VM without its CD or its last card, to
                have its datastore unmounted, or to find a VM already off when
                it is asked to power it off.
    Guest       a Linux guest that answers SSH and runs a simulated EnvMap
                Move engine, the way tests/_fake_pve_agent.py's guests do. Its
                engine reaches the receiver only through the new VM's
                transfer card: with that card disconnected the send fails,
                and a restarted receiver reaches nobody. A copy that starts
                from the new VM's disks shows VMware Tools a few seconds on.

It answers commands the way the real things are documented to and refuses what
it does not know, so a command that is wrong fails here rather than passing
unseen. It was still written by the hand that wrote app/esxshell.py: where it
agrees with that code about how ESXi behaves, only a real host can say whether
both are right.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SSH_PROGRAM = r'''
import base64, json, os, subprocess, sys, urllib.request
a = sys.argv[1:]
port, opts, dest, cmd, config = 22, {}, None, None, ""
i = 0
while i < len(a):
    x = a[i]
    if x == "--":
        dest, cmd = a[i + 1], " ".join(a[i + 2:]); break
    if x == "-p":
        port = int(a[i + 1]); i += 2; continue
    if x == "-F":
        config = a[i + 1]; i += 2; continue
    if x == "-o":
        k, _, v = a[i + 1].partition("="); opts[k] = v; i += 2; continue
    if x.startswith("-"):
        i += 1; continue
    dest, cmd = x, " ".join(a[i + 1:]); break
user, _, host = dest.rpartition("@")
password, on_disk = "", False
ask = os.environ.get("SSH_ASKPASS", "")
if ask and os.environ.get("SSH_ASKPASS_REQUIRE") == "force":
    password = subprocess.run([ask, "Password:"], capture_output=True, text=True).stdout
    # a password kept in a file beside the askpass program outlives a stopped process
    on_disk = any(password and password in open(os.path.join(os.path.dirname(ask), f), errors="replace").read()
                  for f in os.listdir(os.path.dirname(ask)))
known = opts.get("UserKnownHostsFile", "")
have = open(known).read() if known and os.path.exists(known) else ""
req = {"host": host, "port": port, "user": user, "password": password, "command": cmd,
       "stdin": base64.b64encode(sys.stdin.buffer.read()).decode(), "known": have,
       "strict": opts.get("StrictHostKeyChecking", "ask"), "method": opts.get("PreferredAuthentications", ""),
       "config": config, "on_disk": on_disk}
r = json.loads(urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:%(port)d/", json.dumps(req).encode(), {"Content-Type": "application/json"}), timeout=120).read())
if r.get("learn") and known:
    with open(known, "a") as f:
        f.write(r["learn"] + "\n")
sys.stdout.buffer.write(base64.b64decode(r.get("out", "")))
sys.stderr.write(r.get("err", ""))
sys.exit(r.get("code", 255))
'''


def host_key(seed: str) -> str:
    """A key line as known_hosts holds one (after the host name)."""
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(seed.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def unquote(word: str) -> str:
    return shlex.split(word)[0]


QUOTED = r"'(?:[^']|'\\'')*'"


class SshWorld:
    """Every machine SSH can reach in a test, by address."""

    def __init__(self):
        self.ends: dict = {}                       # host -> endpoint
        self.seen: list = []                       # (host, user, command)
        self.requests: list = []                   # what ssh was started with, each time
        world = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                out = json.dumps(world.answer(req)).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a, **k):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def install(self, folder: str) -> str:
        """Write the program that takes ssh's place; its path."""
        body = os.path.join(folder, "fake-ssh.py")
        with open(body, "w") as f:
            f.write(SSH_PROGRAM % {"port": self._srv.server_address[1]})
        # a shell wrapper: the interpreter's path may hold a space, which a
        # "#!" line cannot carry
        path = os.path.join(folder, "fake-ssh")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(body)} "$@"\n')
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def answer(self, req: dict) -> dict:
        self.requests.append({k: req[k] for k in ("host", "user", "method", "config", "strict", "on_disk")})
        end = self.ends.get(req["host"])
        port = req["port"]
        if end is None or not end.up or port != end.port:
            return {"code": 255, "err": f"ssh: connect to host {req['host']} port {port}: Connection timed out\r\n"}
        name = req["host"] if port == 22 else f"[{req['host']}]:{port}"
        line = f"{name} {end.key}"
        held = [ln for ln in req["known"].splitlines() if ln.split()[:1] == [name]]
        learn = ""
        if req["strict"] == "no":
            pass                                   # ssh told to trust whoever answers: it does
        elif held:
            if line not in held:
                return {"code": 255, "err": "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
                                            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
                                            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
                                            "Host key verification failed.\r\n"}
        elif req["strict"] == "accept-new":
            learn = line
        else:
            return {"code": 255, "err": f"No ED25519 host key is known for {name} and you have requested strict "
                                        "checking.\r\nHost key verification failed.\r\n"}
        denied = {"code": 255, "learn": learn,
                  "err": f"{req['user']}@{req['host']}: Permission denied ({','.join(end.offers)}).\r\n"}
        tried = [m for m in req["method"].split(",") if m in end.offers]
        if not tried:
            return denied                          # that way of signing in is not open here: nothing was tried
        for _ in tried:
            end.attempts += 1
            if req["user"] == end.user and req["password"] == end.password:
                break
        else:
            return denied
        self.seen.append((req["host"], req["user"], req["command"]))
        code, out, err = end.run(req["command"], base64.b64decode(req["stdin"]))
        return {"code": code, "out": base64.b64encode(out).decode(), "err": err, "learn": learn}


# ── an ESXi host's shell ───────────────────────────────────────
VMX_TO_API = {"pvscsi": "ParaVirtualSCSIController", "lsisas1068": "VirtualLsiLogicSASController",
              "lsilogic": "VirtualLsiLogicController", "buslogic": "VirtualBusLogicController"}
NIC_TO_API = {"vmxnet3": "VirtualVmxnet3", "e1000e": "VirtualE1000e", "e1000": "VirtualE1000"}


def parse_vmx(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([^=\s]+)\s*=\s*"(.*)"\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


class EsxiShell:
    """The shell of a tests/_fake_esxi.FakeEsxi."""
    offers = ("publickey", "keyboard-interactive")

    def __init__(self, fake, host: str, password: str = "lab-password"):
        self.fake, self.host, self.port = fake, host, 22
        self.user, self.password = "root", password
        self.key = host_key(host)
        self.up = True
        self.attempts = 0
        self.files: dict = {}                      # path -> bytes
        self.dirs: set = {"/vmfs/volumes/datastore1"}
        self.log: list = []
        self.question = ""                         # what ESXi asks before it powers a VM on
        self.fail: dict = {}                       # a word of a command -> what the host says instead of doing it
        self.drop_after = ""                       # a word of a command after which the connection is lost
        self.cut_next_upload = False               # the next file sent arrives half
        self.boots: list = []                      # (VM number, "receiver" | "disk" | "nothing") at each start
        self.on_boot = None                        # called with (VM number, what it started from)
        self.copied: set = set()                   # VM numbers whose disks hold a system by now
        self.omit = ""                             # "cd" | "card": what the host leaves out of the next VM it registers
        self.mounted: set = {"/vmfs/volumes/datastore1"}   # the datastores the shell can look into
        self.off_meanwhile = False                 # the next VM asked to power off is found off already
        self.undeletable: set = set()              # files `rm -f` leaves where they are, without a word
        self.cd_fails = False                      # the host does not connect a CD at power-on although it is set to
        self.cd_late = 0.0                         # seconds after a power-on before the host shows the CD as connected

    def vmx_path(self, vm: dict) -> str:
        m = re.match(r"^\[([^\]]+)\] (.+)$", vm.get("vmx") or f"[datastore1] {vm['name']}/{vm['name']}.vmx")
        return f"/vmfs/volumes/{m.group(1)}/{m.group(2)}"

    def vmx_of(self, vm: dict) -> str:
        """The settings file of a VM that was there before the test wrote one."""
        lines = [f'displayName = "{vm["name"]}"', f'memSize = "{vm["mem"]}"']
        for d in [d for d in vm["devices"] if d["type"] in NIC_TO_API.values()]:
            n = d["key"] - 4000
            lines += [f'ethernet{n}.present = "TRUE"', f'ethernet{n}.networkName = "{d["network"]}"',
                      f'ethernet{n}.generatedAddress = "{d["mac"]}"']
        return "\n".join(lines) + "\n"

    def reachable(self, path: str) -> bool:
        return any(path == root or path.startswith(root + "/") for root in self.mounted)

    def is_dir(self, path: str) -> bool:
        """A folder made here, or the folder of a VM the host had from the start."""
        return self.reachable(path) and (
            path in self.dirs or any(self.vmx_path(vm).rsplit("/", 1)[0] == path for vm in self.fake.vms.values()))

    def exists(self, path: str) -> bool:
        return self.reachable(path) and (self.is_dir(path) or path in self.files)

    def boot(self, moid: str) -> None:
        """What the firmware starts from: the order in the settings file, then
        the first device in it that has something to start."""
        vm = self.fake.vms[moid]
        v = vm.get("vmx_keys") or {}
        cd = next((d for d in vm["devices"] if d["type"] == "VirtualCdrom"), None)
        cd_ok = bool(cd and cd["connected"] and len(self.files.get(
            "/vmfs/volumes/" + cd["iso"][1:].replace("] ", "/", 1), b"")) > 1024 * 1024)
        disk_ok = moid in self.copied
        order = [x.strip() for x in (v.get("bios.bootOrder") or "hdd,cdrom").split(",")]   # VMware's own: the disk first
        what = next((("receiver" if dev == "cdrom" else "disk") for dev in order
                     if (dev == "cdrom" and cd_ok) or (dev == "hdd" and disk_ok)), "nothing")
        self.boots.append((moid, what))
        if self.on_boot:
            self.on_boot(moid, what)

    def register(self, path: str) -> str:
        v = parse_vmx(self.files[path].decode())
        folder = path.rsplit("/", 1)[0]
        m = re.match(r"^/vmfs/volumes/([^/]+)/(.+)$", path)
        if not re.match(r"^[a-z0-9-]+$", v.get("guestOS", "")) or "guest" in v.get("guestOS", "").lower():
            raise ValueError(f"guestOS {v.get('guestOS')!r} is not one a .vmx names")
        if int(v.get("virtualHW.version", 0)) > 21:
            raise ValueError("This virtual machine's hardware version is not supported by this host")
        devices = [{"type": "VirtualPCIController", "key": 100}]
        keys = {}
        for k, val in v.items():
            mm = re.match(r"^(scsi|sata|nvme)(\d+)\.present$", k)
            if mm and val.upper() == "TRUE":
                kind, bus = mm.group(1), int(mm.group(2))
                key = {"scsi": 1000, "sata": 15000, "nvme": 31000}[kind] + bus
                t = (VMX_TO_API[v[f"scsi{bus}.virtualDev"]] if kind == "scsi" else
                     "VirtualAHCIController" if kind == "sata" else "VirtualNVMEController")
                d = {"type": t, "key": key, "bus": bus}
                if f"{kind}{bus}.pciSlotNumber" in v:
                    d["slot"] = int(v[f"{kind}{bus}.pciSlotNumber"])
                devices.append(d)
                keys[f"{kind}{bus}"] = key
        for k, val in sorted(v.items()):
            mm = re.match(r"^(scsi|sata|nvme)(\d+):(\d+)\.present$", k)
            if not mm or val.upper() != "TRUE":
                continue
            ctrl, unit = f"{mm.group(1)}{mm.group(2)}", int(mm.group(3))
            p = f"{ctrl}:{unit}"
            if v.get(f"{p}.deviceType") == "atapi-cdrom":
                # an empty drive, as the host's own client writes one
                devices.append({"type": "VirtualCdrom", "key": 16000 + unit, "controller": keys[ctrl], "unit": unit,
                                "iso": "", "connected": False, "start_connected": False})
                continue
            if v.get(f"{p}.deviceType") == "cdrom-image":
                if self.omit == "cd":
                    continue
                dm = re.match(r"^/vmfs/volumes/([^/]+)/(.+)$", v[f"{p}.fileName"])
                devices.append({"type": "VirtualCdrom", "key": 16000 + unit, "controller": keys[ctrl], "unit": unit,
                                "iso": f"[{dm.group(1)}] {dm.group(2)}", "connected": False,
                                "start_connected": v.get(f"{p}.startConnected", "TRUE").upper() == "TRUE"})
                continue
            named = v[f"{p}.fileName"]
            if named.startswith("/vmfs/volumes/"):
                # another VM's disk, named by its full path: the file is used where it is
                dm = re.match(r"^/vmfs/volumes/([^/]+)/(.+)$", named)
                file = f"[{dm.group(1)}] {dm.group(2)}"
                flat = named[:-5] + "-flat.vmdk"
                owner = next((d for x in self.fake.vms.values() for d in x["devices"]
                              if d["type"] == "VirtualDisk" and d.get("file") == file), None)
                if owner is None and flat not in self.files:
                    raise ValueError(f"the disk {named} is not there")
                kb = owner["kb"] if owner else int(self.files[flat])
            else:
                flat = f"{folder}/{named[:-5]}-flat.vmdk"
                if flat not in self.files:
                    raise ValueError(f"the disk {named} is not there")
                file, kb = f"[{m.group(1)}] {m.group(2).rsplit('/', 1)[0]}/{named}", int(self.files[flat])
            devices.append({"type": "VirtualDisk", "key": 2000 + len([d for d in devices if d["type"] == "VirtualDisk"]),
                            "controller": keys[ctrl], "unit": unit, "kb": kb, "thin": True, "file": file})
        n = 0
        while v.get(f"ethernet{n}.present", "").upper() == "TRUE":
            p = f"ethernet{n}"
            d = {"type": NIC_TO_API[v[f"{p}.virtualDev"]], "key": 4000 + n, "controller": 100, "unit": 7 + n,
                 "network": v[f"{p}.networkName"], "connected": False, "mac": v[f"{p}.address"],
                 "address_type": "manual", "start_connected": v.get(f"{p}.startConnected", "TRUE").upper() == "TRUE"}
            if f"{p}.pciSlotNumber" in v:
                d["slot"] = int(v[f"{p}.pciSlotNumber"])
            if not (v[f"{p}.address"].startswith("00:50:56") and int(v[f"{p}.address"][9:11], 16) <= 0x3F) \
                    and v.get(f"{p}.checkMACAddress", "").upper() != "FALSE":
                raise ValueError(f"Invalid MAC address specified: {v[f'{p}.address']} is not a valid static address")
            devices.append(d)
            n += 1
        if self.omit == "card":
            devices.pop()
        self.omit = ""
        with self.fake.lock:
            moid = str(next(self.fake._ids))
            self.fake.vms[moid] = {
                "name": v["displayName"], "power": "poweredOff", "cpus": int(v["numvcpus"]),
                "cps": int(v.get("cpuid.coresPerSocket", 1)), "uuid": f"4210{moid:0>4}-shell",
                "mem": int(v["memSize"]), "guestId": v["guestOS"], "guestFull": v["guestOS"],
                "tools": "guestToolsNotRunning", "ip": "", "notes": "", "firmware": v.get("firmware", "bios"),
                "secure_boot": False, "enter_setup": False, "uptime": 0, "snapshots": [], "current": "",
                "devices": devices, "vmx": f"[{m.group(1)}] {m.group(2)}", "hw": f"vmx-{v['virtualHW.version']}",
                "vmx_keys": v}
        return moid

    def reload(self, vm: dict) -> None:
        v = parse_vmx(self.files[self.vmx_path(vm)].decode())
        vm["name"] = v.get("displayName", vm["name"])
        keep = []
        for d in vm["devices"]:
            if d["type"] in NIC_TO_API.values():
                n = d["key"] - 4000
                if v.get(f"ethernet{n}.present", "").upper() != "TRUE":
                    continue
                d["start_connected"] = v.get(f"ethernet{n}.startConnected", "TRUE").upper() == "TRUE"
            keep.append(d)
        vm["devices"] = keep

    def run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        self.log.append(command)
        for word, said in self.fail.items():
            if word in command:
                return 1, b"", said + "\n"
        try:
            got = self._run(command, stdin)
        except KeyError as e:
            got = 1, b"", f"No such file or VM: {e}\n"
        except ValueError as e:
            got = 1, b"", f"{e}\n"
        if self.drop_after and self.drop_after in command:
            self.drop_after = ""
            return 255, b"", "client_loop: send disconnect: Broken pipe\r\n"
        return got

    def _run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        f, vms = self.fake, self.fake.vms
        # a file received under another name, hashed there, then moved into place
        m = re.match(rf'^cat > ({QUOTED}) && \[ "\$\(sha256sum < ({QUOTED}) \| cut -d \' \' -f 1\)" = ([0-9a-f]{{64}}) \] '
                     rf'&& mv -f ({QUOTED}) ({QUOTED}) \|\| \{{ rm -f ({QUOTED}); exit 1; \}}$', command)
        if m:
            tmp, path = unquote(m.group(1)), unquote(m.group(5))
            if not (m.group(1) == m.group(2) == m.group(4) == m.group(6)) or not self.is_dir(tmp.rsplit("/", 1)[0]):
                return 1, b"", "sh: cannot create the file\n"
            data = stdin[:len(stdin) // 2] if self.cut_next_upload else stdin
            self.cut_next_upload = False
            if hashlib.sha256(data).hexdigest() != m.group(3):
                return 1, b"", ""                  # the temporary file is removed; nothing was replaced
            self.files[path] = data
            return 0, b"", ""
        # a look that says when it could not look
        m = re.match(rf"^test -d ({QUOTED}) \|\| \{{ echo blind; exit 0; \}}; "
                     rf"test -e ({QUOTED}) && echo taken \|\| echo free$", command)
        if m:
            root, path = unquote(m.group(1)), unquote(m.group(2))
            if root not in self.mounted or not path.startswith(root):
                return 0, b"blind\n", ""
            return 0, (b"taken\n" if self.exists(path) else b"free\n"), ""
        a = shlex.split(command)
        if a[:2] == ["vim-cmd", "vmsvc/getallvms"]:
            rows = "Vmid   Name   File   Guest OS   Version   Annotation\n" + "".join(
                f"{k}   {vm['name']}   {vm.get('vmx') or '[datastore1] ' + vm['name'] + '/' + vm['name'] + '.vmx'}   "
                f"{vm['guestId']}   {vm.get('hw') or 'vmx-21'}\n" for k, vm in vms.items())
            if a[2:] == [">", "/dev/null", "&&", "echo", "envmap-shell-ok"]:
                return 0, b"envmap-shell-ok\n", ""
            return (0, rows.encode(), "") if len(a) == 2 else (2, b"", "sh: syntax error\n")
        if a[0] == "vim-cmd" and len(a) >= 3 and a[1].startswith(("vmsvc/", "solo/")):
            op = a[1]
            if op == "solo/registervm" and len(a) == 3:
                return 0, (self.register(a[2]) + "\n").encode(), ""
            vm = vms[a[2]]
            with f.lock:
                if op == "vmsvc/devices.createnic" and len(a) == 5 and a[3] in NIC_TO_API:
                    if a[4] not in ("VM Network", "DB Network", "Transfer"):
                        raise ValueError(f"Network {a[4]} not found")
                    n = len([d for d in vm["devices"] if d["type"] in NIC_TO_API.values()])
                    mac = "00:0c:29:%02x:%02x:%02x" % (int(a[2]) % 256, n, len(vm["name"]))
                    vm["devices"].append({"type": NIC_TO_API[a[3]], "key": 4000 + n, "controller": 100, "unit": 7 + n,
                                          "network": a[4], "connected": vm["power"] == "poweredOn", "mac": mac})
                    return 0, b"", ""
                if op == "vmsvc/device.connection" and len(a) == 5 and a[4] in ("0", "1"):
                    d = next(d for d in vm["devices"] if d["key"] == int(a[3]))
                    if vm["power"] != "poweredOn":
                        raise ValueError("The attempted operation cannot be performed in the current state (Powered off).")
                    d["connected"] = a[4] == "1"
                    return 0, b"", ""
                if op == "vmsvc/power.on" and len(a) == 3:
                    if self.question:
                        return 124, b"", ""                # it waits for the answer
                    vm["power"] = "poweredOn"
                    for d in vm["devices"]:
                        if "connected" in d:
                            d["connected"] = d.get("start_connected", True)
                    cd = next((d for d in vm["devices"] if d["type"] == "VirtualCdrom"), None)
                    if cd and self.cd_fails:
                        cd["connected"] = False
                    self.boot(a[2])
                    if cd and cd["connected"] and self.cd_late:
                        # it is connected, and the firmware used it; the API shows that a moment later
                        cd["connected"] = False
                        threading.Timer(self.cd_late, cd.__setitem__, ("connected", True)).start()
                    return 0, b"Powering on VM:\n", ""
                if op in ("vmsvc/power.off", "vmsvc/power.reset") and len(a) == 3:
                    if op.endswith("off") and self.off_meanwhile:
                        # it powered itself off a moment before the command arrived
                        self.off_meanwhile = False
                        vm["power"], vm["tools"] = "poweredOff", "guestToolsNotRunning"
                    if vm["power"] != "poweredOn":
                        raise ValueError("The attempted operation cannot be performed in the current state (Powered off).")
                    if op.endswith("off"):
                        vm["power"], vm["tools"] = "poweredOff", "guestToolsNotRunning"
                        for d in vm["devices"]:
                            if "connected" in d:
                                d["connected"] = False
                    else:
                        vm["tools"] = "guestToolsNotRunning"
                        self.boot(a[2])
                    return 0, b"", ""
                if op == "vmsvc/message" and len(a) == 3:
                    return 0, (self.question or "No message.").encode() + b"\n", ""
                if op == "vmsvc/reload" and len(a) == 3:
                    self.reload(vm)
                    return 0, b"", ""
                if op in ("vmsvc/destroy", "vmsvc/unregister") and len(a) == 3:
                    if vm["power"] == "poweredOn":
                        raise ValueError("The attempted operation cannot be performed in the current state (Powered on).")
                    folder = self.vmx_path(vm).rsplit("/", 1)[0]
                    del vms[a[2]]
                    if op.endswith("destroy"):
                        mine = (f"{folder}/{vm['name']}", f"{folder}/{self.vmx_path(vm).rsplit('/', 1)[1][:-4]}")
                        self.files = {k: v for k, v in self.files.items()
                                      if not (k.startswith(folder + "/") and k.startswith(mine))}
                        if not any(k.startswith(folder + "/") for k in self.files):
                            self.dirs.discard(folder)
                    return 0, b"", ""
            return 1, b"", f"Invalid command '{op}' or wrong number of arguments\n"
        if a[0] == "vmkfstools" and len(a) == 6 and a[1] == "-c" and a[3:5] == ["-d", "thin"] \
                and re.match(r"^\d+k$", a[2]) and a[5].endswith(".vmdk"):
            if a[5].rsplit("/", 1)[0] not in self.dirs:
                raise KeyError(a[5])
            self.files[a[5]] = b"# Disk DescriptorFile\n"
            self.files[a[5][:-5] + "-flat.vmdk"] = a[2][:-1].encode()
            return 0, b"Create: 100% done.\n", ""
        if a[0] == "mkdir" and len(a) == 6 and a[2:5] == ["&&", ":", ">"]:
            if self.exists(a[1]):
                return 1, b"", f"mkdir: can't create directory '{a[1]}': File exists\n"
            self.dirs.add(a[1])
            self.files[a[5]] = b""
            return 0, b"", ""
        if a[0] == "mkdir" and len(a) == 3 and a[1] == "-p":
            self.dirs.add(a[2])
            return 0, b"", ""
        if a[0] == "rmdir" and len(a) == 2:
            if any(k.startswith(a[1] + "/") for k in self.files):
                return 1, b"", f"rmdir: '{a[1]}': Directory not empty\n"
            self.dirs.discard(a[1])
            return 0, b"", ""
        if a[0] == "cat" and a[1] == ">" and len(a) == 3:
            if not self.is_dir(a[2].rsplit("/", 1)[0]):
                raise KeyError(a[2])
            self.files[a[2]] = stdin
            return 0, b"", ""
        if a[0] == "cat" and len(a) == 2:
            if a[1] not in self.files:
                vm = next((vm for vm in vms.values() if self.vmx_path(vm) == a[1]), None)
                if vm is None:
                    raise KeyError(a[1])
                # from now on the file is where it is, whatever the VM is renamed to
                vm.setdefault("vmx", f"[datastore1] {vm['name']}/{vm['name']}.vmx")
                self.files[a[1]] = self.vmx_of(vm).encode()
            return 0, self.files[a[1]], ""
        if a[0] == "rm" and a[1] == "-f" and len(a) == 3:
            # `rm -f` says nothing about a file that is not there, or that it cannot reach
            if self.reachable(a[2]) and a[2] not in self.undeletable:
                self.files.pop(a[2], None)
            return 0, b"", ""
        return 127, b"", f"sh: {a[0]}: not found, or not the way it is called\n"


# ── a guest that answers SSH and runs a simulated engine ───────
class Guest:
    """After the send command the guest freezes at `freeze_at` seconds (SSH
    and VMware Tools stop answering). Then, by `mode`:

    "arrive"  at `end_at` the old copy powers itself off and the new VM shows
              VMware Tools;
    "thaw"    at `end_at` the guest answers again, with THAWED in its log;
    "hang"    it stays frozen until the receiver tells it to carry on, which
              the receiver does when the new VM is started from the CD again
              AND its transfer card is connected: a receiver with no link
              reaches nobody.
    """
    offers = ("publickey", "password")

    def __init__(self, host: str, src, src_moid: str, dst, dst_shell: EsxiShell | None = None, user: str = "root",
                 password: str = "guest-password", freeze_at: float = 1.2, end_at: float = 3.0):
        self.host, self.port, self.user, self.password = host, 22, user, password
        self.key = host_key("guest-" + host)
        self.src, self.src_moid, self.dst, self.dst_shell = src, src_moid, dst, dst_shell
        self.freeze_at, self.end_at = freeze_at, end_at
        self.mode = "arrive"
        self.attempts = 0
        self.files: dict = {}
        self.scripts: list = []
        self.sent: list = []
        self.move = None
        self.reachable = True
        self.noise = ""                            # what the login shell prints before any command runs
        self.sudo = True                           # True, or what sudo says when it refuses a user who is not root
        self.copy_up_after = 8.0                   # seconds a copy started from the disks needs to show VMware Tools
        self.lines = ("receiver: memory: every range the sender uses is memory here\n"
                      "disks: pass 1 sent 812 MiB\n")
        if dst_shell is not None:
            dst_shell.on_boot = self.new_vm_started

    def new_vm_started(self, moid: str, what: str) -> None:
        m = self.move
        if not m or m.get("ended") or time.time() - m["t0"] <= self.freeze_at:
            return
        # the receiver runs; whether it reaches the waiting system is for its
        # transfer card to say (tick)
        m["receiver"] = moid if what == "receiver" else None
        # the copy on the new VM's disks starts: a second system, with the same
        # name and cards, which shows VMware Tools once it has come up (tick)
        m["copy"] = (moid, time.time()) if what == "disk" else None

    @property
    def up(self) -> bool:
        self.tick()
        m = self.move
        if not self.reachable or self.src.vms.get(self.src_moid, {}).get("power") != "poweredOn":
            return False
        if not m or m.get("ended"):
            return True
        return time.time() - m["t0"] <= self.freeze_at

    def tick(self) -> None:
        """Where the simulated move stands now. A frozen system answers nobody:
        not SSH, and not VMware Tools either."""
        m = self.move
        if not m or m.get("ended"):
            return
        dt = time.time() - m["t0"]
        old = self.src.vms[self.src_moid]
        if m.get("copy"):
            moid, since = m["copy"]
            new = self.dst.vms.get(moid) or {}
            if new.get("power") == "poweredOn" and time.time() - since > self.copy_up_after:
                new["tools"] = "guestToolsRunning"
        if m.get("receiver") and self.linked(m["receiver"]):
            # the receiver finds the system still waiting and tells it to carry on
            m["ended"] = True
            self.mode = "thaw"
            old["tools"] = "guestToolsRunning"
            return
        if dt > self.freeze_at and self.dst_shell is not None:
            self.dst_shell.copied.add(max(self.dst.vms, key=lambda k: int(k)))
        if dt > self.end_at and self.mode != "hang":
            m["ended"] = True
            if self.mode == "arrive":
                with self.src.lock:
                    old["power"], old["tools"] = "poweredOff", "guestToolsNotRunning"
                with self.dst.lock:
                    new = max(self.dst.vms, key=lambda k: int(k))
                    self.dst.vms[new]["tools"] = "guestToolsRunning"
            else:
                old["tools"] = "guestToolsRunning"
        elif dt > self.freeze_at:
            old["tools"] = "guestToolsNotRunning"

    def linked(self, moid: str) -> bool:
        """The new VM runs and its transfer card (the one card that does not
        connect at power-on by itself) is connected."""
        vm = self.dst.vms.get(moid) or {}
        return vm.get("power") == "poweredOn" and any(
            d.get("connected") for d in vm.get("devices", []) if "mac" in d and d.get("start_connected") is False)

    def _clock(self) -> None:
        while self.move and not self.move.get("ended"):
            self.tick()
            time.sleep(0.1)

    def run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        code, out, err = self._run(command, stdin)
        return code, self.noise.encode() + out, err

    def _run(self, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        inner = command
        if self.user != "root":
            m = re.match(r"^sudo -n /bin/sh -c (.+)$", command)
            if not m:
                return 1, b"", "this account is not root and did not ask through sudo\n"
            if self.sudo is not True:
                return 1, b"", (self.sudo or "sudo: a password is required") + "\n"
            inner = unquote(m.group(1))
        if inner == "/bin/sh -s 2>&1":
            text = stdin.decode()
            first, _, rest = text.partition("\n")
            m = re.match(r"^printf '%s\\n' (envmap-[0-9a-f]+)$", first)
            if not m:
                return 2, b"sh: the first line is not a command\n", ""
            code, out = self.script(rest)
            return code, (m.group(1) + "\n" + out).encode(), ""
        m = re.match(r"^umask 077; cat > (.+)$", inner)
        if m:
            self.files[unquote(m.group(1))] = stdin
            return 0, b"", ""
        m = re.match(r"^printf '%s\\n' (envmap-[0-9a-f]+); head -c (\d+) (.+)$", inner)
        if m:
            path = unquote(m.group(3))
            if path not in self.files:
                return 1, (m.group(1) + "\n").encode(), "No such file\n"
            return 0, (m.group(1) + "\n").encode() + self.files[path][:int(m.group(2))], ""
        return 127, b"", "not a command this guest was expected to be sent\n"

    def script(self, script: str) -> tuple[int, str]:
        script = script.strip()
        if 'echo "arch=' in script:
            return 0, ("arch=x86_64\nkernel=5.14.0-427.el9.x86_64\nuid=0\nsnapshot=1\n"
                       "lockdown=[none] integrity confidentiality\nkernelfile=1\nmkrx=/usr/bin/dracut\n"
                       "iptool=/usr/sbin/ip\ngzip=/usr/bin/gzip\nnm=/usr/bin/nmcli\nos=AlmaLinux 9.4 (Seafoam Ocelot)\n"
                       "selinux=unconfined_u:unconfined_r:unconfined_t:s0\nmount=plain /dev/sda2\nroot=/dev/sda2\n"
                       "defroute=default via 10.20.0.1 dev ens192\nbusy=0\n")
        self.scripts.append(script)
        if "gzip -dc /tmp/envmove.gz" in script:
            data = gzip.decompress(self.files.get("/tmp/envmove.gz", b""))
            return 0, hashlib.sha256(data).hexdigest() + "  /usr/local/sbin/envmove\n"
        if "/sys/class/net/*/address" in script:
            # the card must be looked for by the address the host really gave it
            macs = [d["mac"].lower() for d in self.src.vms[self.src_moid]["devices"] if d.get("mac")]
            asked = re.search(r"grep -l -i -x (\S+) ", script).group(1).lower()
            if asked not in macs:
                return 1, "the transfer card did not appear in the guest\n"
            return 0, "card=ens224\n"
        if "'send'" in script:
            self.sent.append(script)
            new = max(self.dst.vms, key=lambda k: int(k))
            if self.dst_shell is not None and not self.linked(new):
                # the engine reaches the receiver through the new VM's transfer card, or not at all
                self.move = {"t0": time.time(), "ended": True, "dead": True}
                return 0, ""
            self.move = {"t0": time.time()}
            threading.Thread(target=self._clock, daemon=True).start()
            return 0, ""
        if script.startswith("tail -c +") and self.move and self.move.get("dead"):
            return 0, "envmove: the receiver does not answer on the transfer card\n"[int(script.split("+")[1].split()[0]) - 1:]
        if script.startswith("tail -c +"):
            dt = time.time() - self.move["t0"] if self.move else 0
            n = max(1, len(self.lines.splitlines()))
            lines = "".join(ln + "\n" for i, ln in enumerate(self.lines.splitlines()) if i * self.freeze_at / n <= dt)
            if self.move and self.move.get("ended") and self.mode == "thaw":
                lines += "WAITING: this system stays frozen.\nTHAWED: carrying on here\n"
            return 0, lines[int(script.split("+")[1].split()[0]) - 1:]
        if "kill -0" in script and "envmove.pid" in script:
            return (1 if self.move and self.move.get("ended") else 0), ""
        if script.startswith("grep -E"):
            return 0, "OLD COPY: asked to power off; it answered TAKEN\nARRIVED: thawed and running here\n"
        return 0, ""
