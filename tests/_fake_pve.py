"""A stateful fake Proxmox VE API (/api2/json) for tests and the docs' demo:
nodes, VMs and containers, their config, snapshots and power, storage and
ISOs, tasks (UPIDs, finished at once) and the console handshake. Answers the
shapes the Proxmox API documents; checks the API token header.

    pve = FakePve(); pve.start()     # http://127.0.0.1:<pve.port>
"""
from __future__ import annotations

import itertools
import json
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "PVEAPIToken=root@pam!envmap=pve-token-secret"
GiB = 1024 ** 3


class FakePve:
    def __init__(self):
        self.lock = threading.RLock()
        self.calls: list[tuple] = []
        self._upid = itertools.count(1)
        self.tasks: dict = {}
        self.nodes = {"pve-01": {"cpu": 0.21, "maxcpu": 64, "mem": 210 * GiB, "maxmem": 512 * GiB},
                      "pve-02": {"cpu": 0.09, "maxcpu": 48, "mem": 96 * GiB, "maxmem": 384 * GiB}}
        self.guests = {
            100: {"node": "pve-01", "kind": "qemu", "status": "running",
                  "config": {"name": "app-01", "cores": 4, "sockets": 1, "memory": 8192, "ostype": "l26",
                             "smbios1": "uuid=6f1d9c2e-4b7a-4e3d-9a51-2c8e7f40b113",
                             "scsihw": "virtio-scsi-single", "agent": "1", "onboot": 1, "bios": "ovmf",
                             "scsi0": "local-lvm:vm-100-disk-0,iothread=1,size=64G",
                             "efidisk0": "local-lvm:vm-100-disk-1,efitype=4m,size=4M",
                             "net0": "virtio=BC:24:11:0A:00:01,bridge=vmbr0,tag=20",
                             "ide2": "local:iso/almalinux-9.4-x86_64-minimal.iso,media=cdrom",
                             "description": "API servers"},
                  "snapshots": [{"name": "before-patch", "description": "monthly patching",
                                 "snaptime": 1763380000, "vmstate": 0}]},
            101: {"node": "pve-01", "kind": "qemu", "status": "stopped",
                  "config": {"name": "test-vm-07", "cores": 2, "sockets": 1, "memory": 4096, "ostype": "l26",
                             "scsi0": "local-lvm:vm-101-disk-0,size=32G",
                             "net0": "virtio=BC:24:11:0A:00:02,bridge=vmbr0", "ide2": "none,media=cdrom"},
                  "snapshots": []},
            200: {"node": "pve-02", "kind": "lxc", "status": "running",
                  "config": {"hostname": "dns-01", "cores": 2, "memory": 1024, "ostype": "debian",
                             "rootfs": "local-lvm:vm-200-disk-0,size=8G",
                             "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:0B:00:01,ip=dhcp"},
                  "snapshots": []},
        }
        self.storage = {"local": {"type": "dir", "content": "iso,vztmpl,backup", "total": 100 * GiB,
                                  "used": 41 * GiB},
                        "local-lvm": {"type": "lvmthin", "content": "images,rootdir", "total": 3600 * GiB,
                                      "used": 1210 * GiB}}
        self.content = {"local": [{"volid": "local:iso/almalinux-9.4-x86_64-minimal.iso", "content": "iso",
                                   "size": 2_010_000_000, "format": "iso", "ctime": 1762000000},
                                  {"volid": "local:iso/debian-12.7.0-amd64-netinst.iso", "content": "iso",
                                   "size": 659_554_304, "format": "iso", "ctime": 1762500000}]}
        self.port = 0
        self._srv = None

    def start(self) -> "FakePve":
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, method):
                if self.headers.get("Authorization") != TOKEN:
                    return self._send(401, {"data": None, "message": "authentication failure"})
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                form = {}
                if raw and "multipart" not in (self.headers.get("Content-Type") or ""):
                    form = dict(urllib.parse.parse_qsl(raw.decode()))
                q = dict(urllib.parse.parse_qsl(u.query))
                with fake.lock:
                    fake.calls.append((method, u.path, {**q, **form}))
                    try:
                        code, data = fake.route(method, u.path.removeprefix("/api2/json"),
                                                {**q, **form}, raw, self.headers)
                    except KeyError as e:
                        code, data = 500, {"data": None, "message": f"{e} does not exist"}
                self._send(code, data if isinstance(data, dict) and "message" in data else {"data": data})

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

            def do_PUT(self):
                self._go("PUT")

            def do_DELETE(self):
                self._go("DELETE")

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def upid(self, node: str, kind: str, vmid="", ok: bool = True) -> str:
        u = f"UPID:{node}:{next(self._upid):08X}:00000000:00000000:{kind}:{vmid}:root@pam!envmap:"
        self.tasks[u] = {"node": node, "type": kind, "id": str(vmid), "ok": ok, "time": int(time.time())}
        return u

    def _g(self, vmid) -> dict:
        g = self.guests.get(int(vmid))
        if not g:
            raise KeyError(f"VM {vmid}")
        return g

    def route(self, m: str, path: str, p: dict, raw: bytes, headers) -> tuple[int, object]:
        parts = [x for x in path.split("/") if x]
        if path == "/nodes":
            return 200, [{"node": n, "status": "online", "cpu": v["cpu"], "maxcpu": v["maxcpu"],
                          "mem": v["mem"], "maxmem": v["maxmem"], "uptime": 86400 * 31,
                          "level": ""} for n, v in self.nodes.items()]
        if path == "/cluster/nextid":
            return 200, str(max(self.guests) + 1)
        if len(parts) >= 2 and parts[0] == "nodes":
            node = parts[1]
            if node not in self.nodes:
                raise KeyError(f"node {node}")
            rest = parts[2:]
            if rest in (["qemu"], ["lxc"]) and m == "GET":
                return 200, [{"vmid": i, "name": g["config"].get("name") or g["config"].get("hostname"),
                              "status": g["status"], "cpu": 0.07 if g["status"] == "running" else 0,
                              "cpus": g["config"]["cores"], "mem": g["config"]["memory"] * 1024 * 400,
                              "maxmem": g["config"]["memory"] * 1024 * 1024, "maxdisk": 64 * GiB,
                              "uptime": 86400 * 3 if g["status"] == "running" else 0}
                             for i, g in self.guests.items() if g["node"] == node and g["kind"] == rest[0]]
            if rest == ["qemu"] and m == "POST":
                vmid = int(p["vmid"])
                cfg = {k: (int(v) if str(v).isdigit() else v) for k, v in p.items() if k != "vmid"}
                self.guests[vmid] = {"node": node, "kind": "qemu", "status": "stopped", "config": cfg, "snapshots": []}
                return 200, self.upid(node, "qmcreate", vmid)
            if rest == ["status"] and m == "GET":
                n = self.nodes[node]
                return 200, {"cpu": n["cpu"], "uptime": 86400 * 31,
                             "memory": {"used": n["mem"], "total": n["maxmem"], "free": n["maxmem"] - n["mem"]},
                             "cpuinfo": {"model": "AMD EPYC 7443P 24-Core Processor", "cpus": n["maxcpu"], "sockets": 1},
                             "pveversion": "pve-manager/8.2.4/faa83925c9641325", "kversion": "Linux 6.8.8-2-pve",
                             "loadavg": ["0.42", "0.38", "0.31"]}
            if rest == ["status"] and m == "POST":
                return 200, None
            if rest == ["services"]:
                return 200, [{"service": s, "name": s, "desc": d, "state": st, "unit-state": "enabled"}
                             for s, d, st in (("pveproxy", "PVE API Proxy Server", "running"),
                                              ("pvedaemon", "PVE API Daemon", "running"),
                                              ("chronyd", "NTP daemon", "running"),
                                              ("postfix", "Postfix Mail Transport Agent", "stopped"))]
            if len(rest) == 3 and rest[0] == "services" and m == "POST":
                return 200, self.upid(node, f"srv{rest[2]}", rest[1])
            if rest == ["network"]:
                return 200, [{"iface": "vmbr0", "type": "bridge", "active": 1, "cidr": "10.20.0.11/24",
                              "bridge_ports": "eno1", "bridge_vlan_aware": 1},
                             {"iface": "eno1", "type": "eth", "active": 1}]
            if rest == ["storage"]:
                return 200, [{"storage": s, "type": v["type"], "content": v["content"], "total": v["total"],
                              "used": v["used"], "avail": v["total"] - v["used"], "active": 1, "enabled": 1}
                             for s, v in self.storage.items()]
            if len(rest) == 3 and rest[0] == "storage" and rest[2] == "content" and m == "GET":
                return 200, self.content.get(rest[1], [])
            if len(rest) == 4 and rest[0] == "storage" and rest[2] == "content" and m == "DELETE":
                vol = urllib.parse.unquote(rest[3])
                self.content[rest[1]] = [c for c in self.content.get(rest[1], []) if c["volid"] != vol]
                return 200, self.upid(node, "imgdel", "")
            if len(rest) == 3 and rest[0] == "storage" and rest[2] == "upload" and m == "POST":
                name = re.search(rb'filename="([^"]+)"', raw)
                name = name.group(1).decode() if name else "upload.iso"
                self.content.setdefault(rest[1], []).append(
                    {"volid": f"{rest[1]}:iso/{name}", "content": "iso", "size": len(raw), "format": "iso",
                     "ctime": int(time.time())})
                self.calls.append(("UPLOAD", rest[1], name, len(raw)))
                return 200, self.upid(node, "imgcopy", "")
            if rest == ["tasks"]:
                return 200, [{"upid": u, "type": t["type"], "id": t["id"], "user": "root@pam!envmap",
                              "starttime": t["time"], "endtime": t["time"] + 2,
                              "status": "OK" if t["ok"] else "command failed"}
                             for u, t in list(self.tasks.items())[::-1] if t["node"] == node][:int(p.get("limit", 50))]
            if len(rest) == 3 and rest[0] == "tasks" and rest[2] == "status":
                t = self.tasks[urllib.parse.unquote(rest[1])]
                return 200, {"status": "stopped", "exitstatus": "OK" if t["ok"] else "command failed",
                             "type": t["type"], "id": t["id"]}
            if len(rest) >= 2 and rest[0] in ("qemu", "lxc"):
                return self.guest(m, node, rest[0], int(rest[1]), rest[2:], p)
        raise KeyError(path)

    def guest(self, m, node, kind, vmid, rest, p):
        g = self._g(vmid)
        cfg = g["config"]
        if rest == ["status", "current"]:
            return 200, {"status": g["status"], "qmpstatus": g["status"],
                         "cpu": 0.12 if g["status"] == "running" else 0,
                         "mem": cfg["memory"] * 1024 * 1024 * 0.4, "maxmem": cfg["memory"] * 1024 * 1024,
                         "uptime": 86400 * 3 + 600 if g["status"] == "running" else 0}
        if len(rest) == 2 and rest[0] == "status" and m == "POST":
            op = rest[1]
            g["status"] = {"start": "running", "stop": "stopped", "shutdown": "stopped", "reboot": "running",
                           "reset": "running", "suspend": "paused", "resume": "running"}[op]
            return 200, self.upid(node, f"qm{op}", vmid)
        if rest == ["config"] and m == "GET":
            return 200, cfg
        if rest == ["config"] and m in ("POST", "PUT"):
            for k, v in p.items():
                if k == "delete":
                    for d in v.split(","):
                        cfg.pop(d, None)
                else:
                    cfg[k] = int(v) if str(v).isdigit() else v
            return 200, None
        if rest == ["resize"] and m == "PUT":
            key, size = p["disk"], p["size"]
            cfg[key] = re.sub(r"size=[^,]+", f"size={size}", cfg[key])
            return 200, None
        if rest == ["snapshot"] and m == "GET":
            snaps = list(g["snapshots"])
            return 200, snaps + [{"name": "current", "description": "You are here!",
                                  "parent": snaps[-1]["name"] if snaps else ""}]
        if rest == ["snapshot"] and m == "POST":
            g["snapshots"].append({"name": p["snapname"], "description": p.get("description", ""),
                                   "snaptime": int(time.time()), "vmstate": int(p.get("vmstate", 0)),
                                   "parent": g["snapshots"][-1]["name"] if g["snapshots"] else ""})
            return 200, self.upid(node, "qmsnapshot", vmid)
        if len(rest) == 3 and rest[0] == "snapshot" and rest[2] == "rollback":
            return 200, self.upid(node, "qmrollback", vmid)
        if len(rest) == 2 and rest[0] == "snapshot" and m == "DELETE":
            g["snapshots"] = [s for s in g["snapshots"] if s["name"] != rest[1]]
            return 200, self.upid(node, "qmdelsnapshot", vmid)
        if rest == [] and m == "DELETE":
            if g["status"] != "stopped":
                return 500, {"data": None, "message": f"VM {vmid} is running - destroy failed"}
            del self.guests[vmid]
            return 200, self.upid(node, "qmdestroy", vmid)
        if rest == ["clone"] and m == "POST":
            new = int(p["newid"])
            self.guests[new] = {"node": p.get("target", node), "kind": "qemu", "status": "stopped",
                                "config": {**cfg, "name": p["name"]}, "snapshots": []}
            return 200, self.upid(node, "qmclone", vmid)
        if rest == ["migrate"] and m == "POST":
            g["node"] = p["target"]
            return 200, self.upid(node, "qmigrate", vmid)
        if rest == ["vncproxy"] and m == "POST":
            return 200, {"port": "5900", "ticket": "PVEVNC:FAKE::ticket", "user": "root@pam!envmap",
                         "cert": "-----BEGIN CERTIFICATE-----"}
        if rest == ["agent", "network-get-interfaces"]:
            return 200, {"result": [{"name": "eth0", "ip-addresses": [
                {"ip-address": "10.20.0.%d" % (vmid % 200), "ip-address-type": "ipv4"}]}]}
        if rest == ["interfaces"]:
            return 200, [{"name": "eth0", "inet": "10.20.0.53/24"}]
        raise KeyError("/".join(rest))
