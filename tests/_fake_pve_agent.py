"""A fake Proxmox whose guests answer a QEMU guest agent and run a simulated
EnvMap Move engine (tests/test_vmmove.py, and the docs demo of Move).

After the send command the guest freezes at `freeze_at` seconds (its agent stops
answering); at `end_at` either (mode "arrive") the old copy powers off and the
new VM's agent answers, or (mode "thaw") the guest answers again with THAWED in
its log. `lines` is the engine log the guest shows, spread over the run.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import time

from _fake_pve import FakePve


class AgentPve(FakePve):
    """Guest agent calls, and a simulated engine: after the send command the
    guest freezes, then (mode "arrive") the old copy powers off and the new
    VM's agent answers, or (mode "thaw") it comes back where it was."""

    def __init__(self, freeze_at: float = 1.5, end_at: float = 4.0, lines: str = ""):
        super().__init__()
        self.freeze_at, self.end_at = freeze_at, end_at
        self.lines = lines or ("receiver: memory: every range the sender uses is memory here\n"
                               "disks: pass 1 sent 812 MiB\n")
        self.files: dict = {}
        self.runs: dict = {}
        self.pid = 1000
        self.mode = "arrive"
        self.move = None            # {"src": vmid, "t0": time}
        self.sent: list = []
        self.ha: list = []           # HA resources, as /cluster/ha/resources lists them
        self.scripts: list = []      # every command a guest was asked to run

    def frozen(self, vmid) -> bool:
        m = self.move
        if not m or m["src"] != vmid:
            return False
        dt = time.time() - m["t0"]
        return self.freeze_at < dt and (self.mode == "arrive" or dt < self.end_at)

    def tick(self) -> None:
        m = self.move
        if not m or m.get("ended"):
            return
        if time.time() - m["t0"] > self.end_at:
            m["ended"] = True
            if self.mode == "arrive":
                self.guests[m["src"]]["status"] = "stopped"
                m["arrived"] = True

    def has_agent(self, vmid) -> bool:
        g = self.guests.get(vmid)
        if not g or g["status"] != "running" or str(g["config"].get("agent", "0"))[:1] != "1":
            return False
        if self.frozen(vmid):
            return False
        m = self.move
        if m and "dst" in m and vmid == m["dst"]:
            return bool(m.get("arrived"))      # the receiver has no agent; the moved system has
        return True

    def run_script(self, vmid, script: str) -> tuple[int, str]:
        if 'echo "arch=' in script:
            return 0, ("arch=x86_64\nkernel=5.14.0-427.el9.x86_64\nuid=0\nsnapshot=1\n"
                       "lockdown=[none] integrity confidentiality\nkernelfile=1\nmkrx=/usr/bin/dracut\n"
                       "iptool=/usr/sbin/ip\ngzip=/usr/bin/gzip\nnm=/usr/bin/nmcli\nos=AlmaLinux 9.4 (Seafoam Ocelot)\n"
                       "selinux=unconfined_u:unconfined_r:unconfined_t:s0\nmount=plain /dev/sda2\nroot=/dev/sda2\n"
                       "defroute=default via 10.20.0.1 dev ens18\nbusy=0\n")
        self.scripts.append(script)
        if script.startswith("rm -f ") and ".part*" in script:
            stem = script.split()[2].split(".part")[0]
            for k in [k for k in self.files if k.startswith(stem + ".part")]:
                del self.files[k]
            return 0, ""
        if script.startswith("cat ") and ".part*" in script:
            path = script.split()[1].split(".part")[0]
            parts = sorted(k for k in self.files if k.startswith(path + ".part"))
            self.files[path] = b"".join(self.files.pop(k) for k in parts)
            return 0, ""
        if "gzip -dc /tmp/envmove.gz" in script:
            data = gzip.decompress(self.files.get("/tmp/envmove.gz", b""))
            return 0, hashlib.sha256(data).hexdigest() + "  /usr/local/sbin/envmove\n"
        if "/sys/class/net/*/address" in script:
            return 0, "card=ens19\n"
        if "'send'" in script:
            self.sent.append(script)
            dst = max(i for i, g in self.guests.items() if g["config"].get("name", "").endswith("-moving"))
            self.move = {"src": vmid, "t0": time.time(), "dst": dst}
            return 0, ""
        if script.startswith("tail -c +"):
            dt = time.time() - self.move["t0"] if self.move else 0
            lines = "".join(l + "\n" for i, l in enumerate(self.lines.splitlines())
                            if i * self.freeze_at / max(1, len(self.lines.splitlines())) <= dt)
            if self.move and self.move.get("ended") and self.mode == "thaw":
                lines += "WAITING: this system stays frozen.\nTHAWED: carrying on here\n"
            pos = int(script.split("+")[1].split()[0]) - 1
            return 0, lines[pos:]
        if "kill -0" in script and "envmove.pid" in script:
            return (1 if self.move and self.move.get("ended") else 0), ""
        if script.startswith("grep -E"):
            return 0, "OLD COPY: asked to power off; it answered TAKEN\nARRIVED: thawed and running here\n"
        return 0, ""

    def route(self, m, path, p, raw, headers):
        if path == "/cluster/ha/resources":
            return 200, self.ha
        return super().route(m, path, p, raw, headers)

    def guest(self, m, node, kind, vmid, rest, p):
        self.tick()
        g = self.guests.get(vmid)
        if rest and rest[0] == "agent" and rest != ["agent", "network-get-interfaces"]:
            if not self.has_agent(vmid):
                return 500, {"data": None, "message": "QEMU guest agent is not running"}
            if rest == ["agent", "ping"]:
                return 200, {}
            if rest == ["agent", "file-write"]:
                self.files[p["file"]] = base64.b64decode(p["content"])
                return 200, None
            if rest == ["agent", "exec"]:
                self.pid += 1
                self.runs[self.pid] = self.run_script(vmid, p["command"])
                return 200, {"pid": self.pid}
            if rest == ["agent", "exec-status"]:
                code, out = self.runs[int(p["pid"])]
                return 200, {"exited": 1, "exitcode": code, "out-data": out}
        if rest == ["config"] and m == "GET" and g:
            return 200, g["config"]
        return super().guest(m, node, kind, vmid, rest, p)
