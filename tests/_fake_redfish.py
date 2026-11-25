"""A stateful fake Dell iDRAC: the Redfish API EnvMap reads and acts on, and
the iDRAC's VNC server over TLS with VNC authentication — enough for every
server-management action, the console relay and the docs' screenshots.

The shapes are the ones a real iDRAC9 (7.00.60, Redfish 1.18) answered on
24 November 2026: the reset types it allows, its boot-override targets, the
CD and RemovableDisk virtual media, the Sel/Lclog/FaultList log services,
and the VNCServer.1.* attributes (a password of exactly 8 characters).
State changes are applied, so a test acts and then reads the result back.

    bmc = FakeRedfish(); bmc.start()     # http://127.0.0.1:<bmc.port>
    ...                                  # bmc.calls, bmc.power, bmc.attrs, ...
    bmc.stop()
"""
from __future__ import annotations

import base64
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SYS = "/redfish/v1/Systems/System.Embedded.1"
CHA = "/redfish/v1/Chassis/System.Embedded.1"
MGR = "/redfish/v1/Managers/iDRAC.Embedded.1"
RESETS = ["On", "ForceOff", "ForceRestart", "GracefulRestart", "GracefulShutdown",
          "PushPowerButton", "Nmi", "PowerCycle"]
TARGETS = ["None", "Pxe", "Floppy", "Cd", "Hdd", "BiosSetup", "Utilities",
           "UefiTarget", "SDCard", "UefiHttp"]


def vnc_response(password: str, challenge: bytes) -> bytes:
    """VNC authentication as a VNC server checks it, written apart from
    EnvMap's own: each password byte mirrored bit by bit, then DES."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    raw = password.encode()[:8] + b"\0" * (8 - len(password.encode()[:8]))
    mirrored = bytes(sum(((b >> i) & 1) << (7 - i) for i in range(8)) for b in raw)
    enc = Cipher(TripleDES(mirrored + mirrored + mirrored), modes.ECB()).encryptor()
    return enc.update(challenge) + enc.finalize()


def _self_signed(where: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idrac-fake")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    crt, pem = os.path.join(where, "vnc.crt"), os.path.join(where, "vnc.key")
    with open(crt, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(pem, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return crt, pem


class FakeRedfish:
    def __init__(self, user: str = "root", password: str = "calvin",
                 model: str = "PowerEdge R650", serial: str = "FAKE650",
                 uuid: str = "4c4c4544-0046-4110-8045-b6c04f363530",
                 os_name: str = "", os_version: str = "", os_host: str = "",
                 os_path: str = "managers"):
        self.lock = threading.RLock()
        # ServerOS.1.*: what the iDRAC Service Module on the host tells the
        # iDRAC, blank without it. os_path "oem" answers only at the Dell OEM
        # place an iDRAC before 4.x keeps the System attributes in.
        self.os = {"ServerOS.1.OSName": os_name, "ServerOS.1.OSVersion": os_version,
                   "ServerOS.1.HostName": os_host, "ServerOS.1.ServerPoweredOnTime": 86400}
        self.os_path = os_path
        self.user, self.password = user, password
        self.model, self.serial, self.uuid = model, serial, uuid
        self.power = "On"
        self.led = False
        self.boot = {"BootSourceOverrideTarget": "None",
                     "BootSourceOverrideEnabled": "Disabled"}
        self.media = {"CD": {"Inserted": False, "Image": None, "types": ["CD", "DVD"]},
                      "RemovableDisk": {"Inserted": False, "Image": None,
                                        "types": ["USBStick"]}}
        self.sel = [self._entry(i, sev, msg, "Temperature" if "temp" in msg.lower() else "")
                    for i, (sev, msg) in enumerate([
                        ("OK", "The system inlet temperature is within range."),
                        ("Warning", "The system inlet temperature is greater than the upper warning threshold."),
                        ("OK", "Log cleared."),
                        ("Critical", "Correctable memory error rate exceeded for DIMM_A3.")])]
        self.lclog = [self._entry(i, "OK", f"Successfully logged in using root, from 10.0.0.{i}.", "")
                      for i in range(6)]
        self.faults: list = []
        self.bmc_resets = 0
        self.attrs = {"VNCServer.1.Enable": "Disabled", "VNCServer.1.Password": "",
                      "VNCServer.1.Port": 5901, "VNCServer.1.Timeout": 300,
                      "VNCServer.1.SSLEncryptionBitLength": "Disabled",
                      "VNCServer.1.ActiveSessions": 0, "VNCServer.1.MaxSessions": 2}
        self.calls: list = []
        self.vnc_auth: list = []            # True / False per VNC sign-in
        self.vnc_seen: list = []            # client messages after the handshake
        self.fail_next = ""                 # a Redfish message to refuse the next change with
        self._srv = None
        self._vnc = None
        self._tmp = tempfile.mkdtemp(prefix="fake-idrac-")

    @staticmethod
    def _entry(i: int, sev: str, msg: str, sensor: str) -> dict:
        return {"Id": str(100 + i), "Created": f"2026-11-2{i % 4}T0{i}:1{i}:00+00:00",
                "Severity": sev, "Message": msg, "SensorType": sensor,
                "MessageId": f"SYS{100 + i}"}

    # ── HTTP ────────────────────────────────────────────────
    def start(self) -> "FakeRedfish":
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _auth(self) -> bool:
                want = "Basic " + base64.b64encode(f"{fake.user}:{fake.password}".encode()).decode()
                if self.headers.get("Authorization") != want:
                    self._send(401, {"error": {"message": "Unauthorized"}})
                    return False
                return True

            def _body(self) -> dict:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    return json.loads(raw or b"{}")
                except ValueError:
                    return {}

            def do_GET(self):
                if self.path.split("?")[0] != "/redfish/v1" and not self._auth():
                    return
                code, doc = fake.get(self.path)
                self._send(code, doc)

            def do_POST(self):
                if not self._auth():
                    return
                code, doc = fake.change("POST", self.path, self._body())
                self._send(code, doc)

            def do_PATCH(self):
                if not self._auth():
                    return
                code, doc = fake.change("PATCH", self.path, self._body())
                self._send(code, doc)

            def _send(self, code, doc):
                raw = json.dumps(doc).encode() if doc is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self._start_vnc()
        return self

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()
        if self._vnc:
            try:
                self._vnc.close()
            except OSError:
                pass

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @staticmethod
    def _error(code: int, msg: str):
        return code, {"error": {"code": "Base.1.12.GeneralError", "message": msg,
                                "@Message.ExtendedInfo": [{"Message": msg, "Severity": "Warning"}]}}

    # ── reads ───────────────────────────────────────────────
    def get(self, raw_path: str):
        path, _, query = raw_path.partition("?")
        q = dict(urllib.parse.parse_qsl(query))
        expand = "$expand" in q
        with self.lock:
            self.calls.append(("GET", raw_path, None))
            if path == "/redfish/v1":
                return 200, {"Vendor": "Dell", "RedfishVersion": "1.18.0",
                             "Systems": {"@odata.id": "/redfish/v1/Systems"}}
            if path == "/redfish/v1/Systems":
                return 200, {"Members": [{"@odata.id": SYS}]}
            if path == "/redfish/v1/Chassis":
                return 200, {"Members": [{"@odata.id": CHA}]}
            if path == "/redfish/v1/Managers":
                return 200, {"Members": [{"@odata.id": MGR}]}
            if path == SYS:
                return 200, self._system()
            if path == CHA + "/Thermal":
                return 200, {"Temperatures": [
                    {"Name": "System Board Inlet Temp", "ReadingCelsius": 24,
                     "UpperThresholdCritical": 47, "Status": {"Health": "OK"}},
                    {"Name": "CPU1 Temp", "ReadingCelsius": 58 if self.power == "On" else 0,
                     "UpperThresholdCritical": 100, "Status": {"Health": "OK"}}],
                    "Fans": [{"Name": f"Fan {i}", "Reading": 6240 + 120 * i, "ReadingUnits": "RPM",
                              "Status": {"Health": "OK"}} for i in range(1, 5)]}
            if path == CHA + "/Power":
                return 200, {"PowerControl": [{"PowerConsumedWatts": 286 if self.power == "On" else 9}],
                             "PowerSupplies": [{"Name": f"PS{i}", "Model": "PWR SPLY,800W,RDNT,LTON",
                                                "LastPowerOutputWatts": 143, "Status": {"State": "Enabled", "Health": "OK"}}
                                               for i in (1, 2)]}
            if path == "/redfish/v1/UpdateService/FirmwareInventory":
                return 200, {"Members": [{"Name": "Integrated Dell Remote Access Controller", "Version": "7.00.60.00"},
                                         {"Name": "BIOS", "Version": "1.14.1"}]}
            if path == SYS + "/Processors":
                docs = [{"@odata.id": f"{SYS}/Processors/CPU.Socket.{i}", "Id": f"CPU.Socket.{i}",
                         "Model": "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz ", "TotalCores": 32,
                         "TotalThreads": 64, "MaxSpeedMHz": 4000, "ProcessorType": "CPU",
                         "Status": {"Health": "OK"}} for i in (1, 2)]
                return 200, self._coll(docs, expand)
            if path == SYS + "/Memory":
                docs = [{"@odata.id": f"{SYS}/Memory/DIMM.Socket.{s}", "Id": f"DIMM.Socket.{s}",
                         "CapacityMiB": 32768, "OperatingSpeedMhz": 3200, "MemoryDeviceType": "DDR4",
                         "Manufacturer": "Hynix Semiconductor",
                         "Status": {"Health": "Warning" if s == "A3" else "OK", "State": "Enabled"}}
                        for s in ("A1", "A2", "A3", "B1", "B2", "B3")]
                return 200, self._coll(docs, expand)
            if path == SYS + "/EthernetInterfaces":
                docs = [{"@odata.id": f"{SYS}/EthernetInterfaces/NIC.Integrated.1-{i}-1",
                         "Id": f"NIC.Integrated.1-{i}-1", "MACAddress": f"B0:7B:25:00:00:0{i}",
                         "SpeedMbps": 25000 if i < 3 else 0, "LinkStatus": "LinkUp" if i < 3 else "LinkDown",
                         "Status": {"Health": "OK"}} for i in (1, 2, 3, 4)]
                return 200, self._coll(docs, expand)
            if path == SYS + "/Storage":
                return 200, {"Members": [{"@odata.id": f"{SYS}/Storage/RAID.SL.3-1"}]}
            if path == f"{SYS}/Storage/RAID.SL.3-1":
                return 200, {"Id": "RAID.SL.3-1", "Name": "PERC H755 Front", "Status": {"Health": "OK"},
                             "Drives": [{"@odata.id": f"{SYS}/Storage/Drives/Disk.Bay.{i}"} for i in (0, 1)],
                             "Volumes": {"@odata.id": f"{SYS}/Storage/RAID.SL.3-1/Volumes"}}
            m = re.match(rf"^{re.escape(SYS)}/Storage/Drives/Disk\.Bay\.(\d)$", path)
            if m:
                return 200, {"Id": f"Disk.Bay.{m.group(1)}:Enclosure.Internal.0-1:RAID.SL.3-1",
                             "Model": "MZ7L3960HCJR0D3", "CapacityBytes": 960 * 1000 ** 3,
                             "MediaType": "SSD", "Protocol": "SATA", "PredictedMediaLifeLeftPercent": 99,
                             "Status": {"Health": "OK"}}
            if path == f"{SYS}/Storage/RAID.SL.3-1/Volumes":
                docs = [{"@odata.id": f"{SYS}/Storage/Volumes/Disk.Virtual.0:RAID.SL.3-1",
                         "Id": "Disk.Virtual.0:RAID.SL.3-1", "Name": "OS", "CapacityBytes": 893 * 1024 ** 3,
                         "RAIDType": "RAID1", "Status": {"Health": "OK"}}]
                return 200, self._coll(docs, expand)
            m = re.match(rf"^{re.escape(MGR)}/LogServices/(Sel|Lclog|FaultList)/Entries$", path)
            if m:
                rows = {"Sel": self.sel, "Lclog": self.lclog, "FaultList": self.faults}[m.group(1)]
                top = int(q.get("$top") or 50)
                return 200, {"Members": list(reversed(rows))[:top]}
            if path == MGR + "/VirtualMedia":
                return 200, self._coll([self._vm(k) for k in self.media], expand)
            m = re.match(rf"^{re.escape(MGR)}/VirtualMedia/(\w+)$", path)
            if m and m.group(1) in self.media:
                return 200, self._vm(m.group(1))
            sys_attrs = {"managers": "/redfish/v1/Managers/System.Embedded.1/Attributes",
                         "oem": MGR + "/Oem/Dell/DellAttributes/System.Embedded.1"}[self.os_path]
            if path == sys_attrs:
                return 200, {"Id": "SystemAttributes", "Attributes": {
                    **self.os, "ServerTopology.1.DataCenterName": "", "ServerPwr.1.PSRapidOn": "Enabled"}}
            if path == MGR + "/Attributes":
                shown = {k: ("" if k == "VNCServer.1.Password" else v) for k, v in self.attrs.items()}
                return 200, {"Attributes": shown}
            return self._error(404, f"{path} not found")

    @staticmethod
    def _coll(docs: list, expand: bool) -> dict:
        return {"Members": docs if expand else [{"@odata.id": d["@odata.id"]} for d in docs]}

    def _vm(self, k: str) -> dict:
        d = self.media[k]
        base = f"{MGR}/VirtualMedia/{k}"
        return {"@odata.id": base, "Id": k, "MediaTypes": d["types"], "Inserted": d["Inserted"],
                "Image": d["Image"], "Actions": {
                    "#VirtualMedia.InsertMedia": {"target": base + "/Actions/VirtualMedia.InsertMedia"},
                    "#VirtualMedia.EjectMedia": {"target": base + "/Actions/VirtualMedia.EjectMedia"}}}

    def _system(self) -> dict:
        return {"@odata.id": SYS, "Id": "System.Embedded.1", "Manufacturer": "Dell Inc.",
                "Model": self.model, "SerialNumber": "CN" + self.serial + "00A1", "SKU": self.serial,
                "UUID": self.uuid,
                "HostName": self.os["ServerOS.1.HostName"] or "r650-lab.example.internal",
                "PowerState": self.power,
                "BiosVersion": "1.14.1", "Status": {"Health": "Warning", "State": "Enabled"},
                "ProcessorSummary": {"Count": 2, "Model": "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz"},
                "MemorySummary": {"TotalSystemMemoryGiB": 192},
                "IndicatorLED": "Blinking" if self.led else "Lit",
                "LocationIndicatorActive": self.led,
                "Boot": {**self.boot,
                         "BootSourceOverrideTarget@Redfish.AllowableValues": TARGETS,
                         "BootSourceOverrideMode": "UEFI"},
                "Actions": {"#ComputerSystem.Reset": {
                    "target": SYS + "/Actions/ComputerSystem.Reset",
                    "ResetType@Redfish.AllowableValues": RESETS}},
                "Links": {"ManagedBy": [{"@odata.id": MGR}]}}

    # ── changes ─────────────────────────────────────────────
    def change(self, method: str, path: str, body: dict):
        with self.lock:
            self.calls.append((method, path, body))
            if self.fail_next:
                msg, self.fail_next = self.fail_next, ""
                return self._error(400, msg)
            if method == "POST" and path == SYS + "/Actions/ComputerSystem.Reset":
                rt = body.get("ResetType")
                if rt not in RESETS:
                    return self._error(400, f"The value {rt} for the property ResetType is not in the list of acceptable values.")
                if rt == "On" and self.power == "On":
                    return self._error(409, "The server is already powered on.")
                if rt in ("ForceOff", "GracefulShutdown"):
                    self.power = "Off"
                elif rt in ("On", "PowerCycle", "ForceRestart", "GracefulRestart"):
                    self.power = "On"
                return 204, None
            if method == "PATCH" and path == SYS:
                for k, v in body.items():
                    if k == "LocationIndicatorActive":
                        self.led = bool(v)
                    elif k == "IndicatorLED":
                        self.led = v in ("Lit", "Blinking")
                    elif k == "Boot":
                        t = v.get("BootSourceOverrideTarget")
                        if t and t not in TARGETS:
                            return self._error(400, f"The value {t} is not acceptable.")
                        self.boot.update({kk: vv for kk, vv in v.items() if kk in self.boot})
                    else:
                        return self._error(400, f"The property {k} is not known.")
                return 200, {}
            m = re.match(rf"^{re.escape(MGR)}/VirtualMedia/(\w+)/Actions/VirtualMedia\.(InsertMedia|EjectMedia)$", path)
            if method == "POST" and m and m.group(1) in self.media:
                d = self.media[m.group(1)]
                if m.group(2) == "InsertMedia":
                    if d["Inserted"]:
                        return self._error(400, "Virtual Media is already connected.")
                    d.update(Inserted=True, Image=body.get("Image"))
                else:
                    if not d["Inserted"]:
                        return self._error(400, "No Virtual Media devices are currently connected.")
                    d.update(Inserted=False, Image=None)
                return 204, None
            if method == "POST" and path == MGR + "/LogServices/Sel/Actions/LogService.ClearLog":
                self.sel = [self._entry(0, "OK", "Log cleared.", "")]
                return 204, None
            if method == "POST" and path == MGR + "/Actions/Manager.Reset":
                if body.get("ResetType") != "GracefulRestart":
                    return self._error(400, "ResetType")
                self.bmc_resets += 1
                return 204, None
            if method == "PATCH" and path == MGR + "/Attributes":
                attrs = body.get("Attributes") or {}
                for k, v in attrs.items():
                    if k not in self.attrs or k in ("VNCServer.1.ActiveSessions",):
                        return self._error(400, f"The attribute {k} is read-only or unknown.")
                    if k == "VNCServer.1.Password" and len(str(v)) != 8:
                        return self._error(400, "The VNC password must be exactly 8 characters.")
                    if k == "VNCServer.1.SSLEncryptionBitLength" and v not in (
                            "Disabled", "Auto Negotiate", "128-Bit or higher",
                            "168-Bit or higher", "256-Bit or higher"):
                        return self._error(400, f"The value {v} is not acceptable.")
                    if k == "VNCServer.1.Enable" and v not in ("Enabled", "Disabled"):
                        return self._error(400, f"The value {v} is not acceptable.")
                self.attrs.update(attrs)
                return 200, {}
            return self._error(405, f"{method} {path} is not allowed")

    # ── the VNC server ──────────────────────────────────────
    def _start_vnc(self) -> None:
        crt, key = _self_signed(self._tmp)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(crt, key)
        self._vnc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._vnc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._vnc.bind(("127.0.0.1", 0))
        self._vnc.listen(4)
        self.attrs["VNCServer.1.Port"] = self.vnc_port = self._vnc.getsockname()[1]

        def serve():
            while True:
                try:
                    raw, _ = self._vnc.accept()
                except OSError:
                    return
                threading.Thread(target=self._vnc_session, args=(raw, tls), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()

    def _vnc_session(self, raw: socket.socket, tls: ssl.SSLContext) -> None:
        def exactly(s, n):
            out = b""
            while len(out) < n:
                got = s.recv(n - len(out))
                if not got:
                    raise ConnectionError("closed")
                out += got
            return out
        try:
            with self.lock:
                on = self.attrs["VNCServer.1.Enable"] == "Enabled"
                wrap = self.attrs["VNCServer.1.SSLEncryptionBitLength"] != "Disabled"
                password = self.attrs["VNCServer.1.Password"]
            if not on:
                raw.close()
                return
            s = tls.wrap_socket(raw, server_side=True) if wrap else raw
            s.sendall(b"RFB 003.008\n")
            exactly(s, 12)
            s.sendall(b"\x01\x02")                       # one type: VNC authentication
            if exactly(s, 1) != b"\x02":
                s.close()
                return
            challenge = os.urandom(16)
            s.sendall(challenge)
            ok = exactly(s, 16) == vnc_response(password, challenge)
            self.vnc_auth.append(ok)
            if not ok:
                reason = b"Authentication failed"
                s.sendall(struct.pack(">II", 1, len(reason)) + reason)
                s.close()
                return
            s.sendall(struct.pack(">I", 0))
            exactly(s, 1)                                # ClientInit
            name = f"{self.model} {self.serial}".encode()
            fmt = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
            s.sendall(struct.pack(">HH", 1024, 768) + fmt + struct.pack(">I", len(name)) + name)
            sizes = {0: 19, 3: 9, 4: 7, 5: 5}
            shifts, big = (16, 8, 0), False
            while True:
                t = exactly(s, 1)[0]
                if t == 0:
                    body = exactly(s, 19)
                    big, shifts = bool(body[5]), (body[13], body[14], body[15])
                elif t == 2:
                    _pad, n = struct.unpack(">BH", exactly(s, 3))
                    body = exactly(s, 4 * n)
                    self.vnc_seen.append(("encodings", list(struct.unpack(f">{n}i", body))))
                elif t == 6:
                    _p, n = struct.unpack(">3sI", exactly(s, 7))
                    exactly(s, n)
                elif t in sizes:
                    body = exactly(s, sizes[t])
                    self.vnc_seen.append((t, body))
                    if t == 3 and not body[0]:
                        # the whole screen for a full request; nothing changes after
                        s.sendall(struct.pack(">BxH", 0, 1) + struct.pack(">HHHHi", 0, 0, 1024, 768, 0)
                                  + self._frame(shifts, big))
                else:
                    return
        except (OSError, ConnectionError, ssl.SSLError):
            pass

    _frames: dict = {}

    def _frame(self, shifts, big) -> bytes:
        """The host's own console, as the docs show it: a hypervisor's
        status screen on the server's display."""
        key = (shifts, big)
        if key in self._frames:
            return self._frames[key]
        W, H = 1024, 768
        try:
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new("RGB", (W, H), (178, 178, 178))
            d = ImageDraw.Draw(img)
            try:
                f, fb = ImageFont.load_default(size=17), ImageFont.load_default(size=19)
            except TypeError:
                f = fb = ImageFont.load_default()
            d.rectangle((0, 0, W, 300), fill=(54, 54, 54))
            d.rectangle((0, 300, W, H - 34), fill=(214, 184, 60))
            d.rectangle((0, H - 34, W, H), fill=(54, 54, 54))
            top = ["ESXi 8.0.3 (VMKernel Release Build 24022510)", "",
                   f"Dell Inc. {self.model}", "",
                   "2 x Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz", "191.6 GiB Memory"]
            for i, ln in enumerate(top):
                d.text((60, 60 + i * 30), ln, fill=(235, 235, 235), font=fb if i == 0 else f)
            low = ["To manage this host, go to:", "https://esx-lab-01.example.internal/",
                   "https://10.20.0.31/ (STATIC)", "", "https://[fe80::b27b:25ff:fe00:1]/ (STATIC)"]
            for i, ln in enumerate(low):
                d.text((60, 340 + i * 30), ln, fill=(30, 30, 30), font=fb if i == 0 else f)
            d.text((16, H - 26), "<F2> Customize System/View Logs", fill=(230, 230, 230), font=f)
            d.text((W - 300, H - 26), "<F12> Shut Down/Restart", fill=(230, 230, 230), font=f)
            px = img.tobytes()
        except ImportError:
            px = bytes([60, 60, 60] * (W * H))
        out = bytearray(W * H * 4)
        rs, gs, bs = shifts
        order = "big" if big else "little"
        for i in range(W * H):
            v = (px[3 * i] << rs) | (px[3 * i + 1] << gs) | (px[3 * i + 2] << bs)
            out[4 * i:4 * i + 4] = v.to_bytes(4, order)
        self._frames[key] = bytes(out)
        return self._frames[key]
