"""A stateful fake standalone ESXi host: the vSphere SOAP API at /sdk, the
datastore file service at /folder, and a WebMKS console (RFB over a
websocket) — enough for EnvMap's readers, every management action and the
console relay, and for the docs' screenshots.

It answers the shapes a real ESXi 8.0.3 answered on 24 November 2026 (the
request bodies EnvMap sends were checked against that host; see
app/esxiops.py). State changes are applied, so a test can act and then read
the result back the way the page would.

    host = FakeEsxi(); host.start()          # http://127.0.0.1:<host.port>
    ...                                      # host.calls, host.vms, ...
    host.stop()
"""
from __future__ import annotations

import asyncio
import itertools
import re
import struct
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape as x

XSI = "{http://www.w3.org/2001/XMLSchema-instance}type"
ENV = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope '
       'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
       'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
       '<soapenv:Body>{}</soapenv:Body></soapenv:Envelope>')
GiB = 1024 ** 3


def _l(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _k(el, name):
    return next((c for c in el if _l(c.tag) == name), None)


def _t(el, name, default=""):
    k = _k(el, name) if el is not None else None
    return (k.text or "").strip() if k is not None else default


# what the free licence still answers: reading, and nothing else
READ_OPS = {"RetrieveServiceContent", "Login", "Logout", "RetrievePropertiesEx", "ContinueRetrievePropertiesEx",
            "CreateContainerView", "DestroyView", "QueryConfigOption", "SearchDatastore_Task",
            "SearchDatastoreSubFolders_Task"}


def free_licence(host) -> None:
    """Make a stand-in host behave as one on the free ESXi licence does."""
    host.licence = ("vSphere 8 Hypervisor", "esx.hypervisor.cpuPackageCoreLimited")
    host.read_only = True


class Fault(Exception):
    def __init__(self, kind: str, msg: str):
        super().__init__(msg)
        self.kind, self.msg = kind, msg


def _vm(name, guest, guest_full, cpus, mem_gib, disk_gib, net, power="poweredOn",
        ip="", tools="guestToolsRunning", notes="", iso=""):
    import uuid as _uuid
    return {"name": name, "power": power, "cpus": cpus, "cps": 1,
            # the SMBIOS UUID, as vSphere prints it (config.uuid)
            "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_DNS, f"{name}.vm.fake")),
            "mem": int(mem_gib * 1024), "guestId": guest, "guestFull": guest_full,
            "tools": tools if power == "poweredOn" else "guestToolsNotRunning",
            "ip": ip if power == "poweredOn" else "", "notes": notes,
            "firmware": "efi", "secure_boot": False, "enter_setup": False,
            "uptime": 86400 * 12 + 3600 * 5 if power == "poweredOn" else 0,
            "snapshots": [], "current": "",
            "devices": [
                {"type": "VirtualPCIController", "key": 100},
                {"type": "ParaVirtualSCSIController", "key": 1000, "bus": 0},
                {"type": "VirtualAHCIController", "key": 15000, "bus": 0},
                {"type": "VirtualDisk", "key": 2000, "controller": 1000, "unit": 0,
                 "kb": int(disk_gib * 1048576), "thin": True,
                 "file": f"[datastore1] {name}/{name}.vmdk"},
                {"type": "VirtualVmxnet3", "key": 4000, "controller": 100, "unit": 7,
                 "network": net, "connected": power == "poweredOn",
                 "mac": "00:50:56:%02x:%02x:%02x" % (len(name), sum(map(ord, name)) % 256, cpus)},
                {"type": "VirtualCdrom", "key": 16000, "controller": 15000, "unit": 0,
                 "iso": iso, "connected": False}]}


class FakeEsxi:
    # the identity of the box this host is installed on: what its BMC reports
    # too (tests/_fake_redfish.py takes the same two values)
    HOST_UUID = "4c4c4544-0058-4b10-8032-b7c04f513134"
    HOST_SERIAL = "7XK2Q14"
    _ID_PATHS = ("hardware.systemInfo.uuid", "hardware.systemInfo.serialNumber",
                 "summary.hardware.vendor", "summary.hardware.model")

    def __init__(self, name: str = "esx-lab-01.example.internal", uuid: str = HOST_UUID,
                 serial: str = HOST_SERIAL, api_type: str = "HostAgent", old: bool = False):
        self.lock = threading.RLock()
        self.name = name
        self.uuid, self.serial, self.api_type = uuid, serial, api_type
        self.old = old                    # an ESXi older than 6.7: no serial property
        self.calls: list[tuple] = []
        self.encodings_seen: list[list[int]] = []
        self.pings_seen = 0
        # (name, edition key) as LicenseManager reports them. With read_only the
        # API behaves as it does on the free licence: it reads, and refuses the
        # rest with VMware's own sentence (measured on ESXi 7.0 and 8.0).
        self.licence = ("vSphere 8 Enterprise Plus", "esx.enterprisePlus.cpuPackage")
        self.read_only = False
        self.refused: list[str] = []
        self.tickets: set = set()
        self.maintenance = False
        self.fail_next: dict = {}
        self._ids = itertools.count(10)
        self._tasks = itertools.count(1)
        self.tasks: dict = {}
        self.vms = {
            "1": _vm("web-01", "almalinux_64Guest", "AlmaLinux (64-bit)", 4, 8, 60,
                     "VM Network", ip="10.20.0.21", notes="Public site, behind the load balancer"),
            "2": _vm("db-01", "rhel9_64Guest", "Red Hat Enterprise Linux 9 (64-bit)", 8, 32, 400,
                     "DB Network", ip="10.20.1.10"),
            "3": _vm("k8s-worker-07", "ubuntu64Guest", "Ubuntu Linux (64-bit)", 8, 16, 120,
                     "VM Network", ip="10.20.0.47"),
            "4": _vm("old-builder", "debian12_64Guest", "Debian GNU/Linux 12 (64-bit)", 2, 4, 40,
                     "VM Network", power="poweredOff"),
            "5": _vm("win-jump-01", "windows2019srvNext_64Guest",
                     "Microsoft Windows Server 2022 (64-bit)", 4, 8, 90, "VM Network",
                     ip="10.20.0.30"),
        }
        self.vms["2"]["snapshots"] = [
            {"id": "2-snapshot-1", "name": "before-upgrade-9.4", "description": "taken before the 9.4 upgrade",
             "created": "2026-11-02T09:14:00Z", "state": "poweredOn", "children": [
                 {"id": "2-snapshot-2", "name": "after-tuning", "description": "",
                  "created": "2026-11-19T16:40:00Z", "state": "poweredOff", "children": []}]}]
        self.vms["2"]["current"] = "2-snapshot-2"
        self.portgroups = [{"name": "VM Network", "vlan": 0, "vswitch": "vSwitch0"},
                           {"name": "DB Network", "vlan": 20, "vswitch": "vSwitch0"},
                           {"name": "Management Network", "vlan": 0, "vswitch": "vSwitch0"}]
        self.services = [
            {"key": "DCUI", "label": "Direct Console UI", "running": True, "policy": "on"},
            {"key": "TSM", "label": "ESXi Shell", "running": False, "policy": "off"},
            {"key": "TSM-SSH", "label": "SSH", "running": False, "policy": "off"},
            {"key": "ntpd", "label": "NTP Daemon", "running": True, "policy": "on"},
            {"key": "vpxa", "label": "VMware vCenter Agent", "running": False, "policy": "off"}]
        self.files = {"datastore1": {
            "ISO/almalinux-9.4-x86_64-minimal.iso": 2_010_000_000,
            "ISO/ubuntu-24.04-live-server-amd64.iso": 2_690_000_000,
            "ISO/windows-server-2022.iso": 5_300_000_000}}
        for vm in self.vms.values():
            self.files["datastore1"][f"{vm['name']}/{vm['name']}.vmx"] = 3600
            self.files["datastore1"][f"{vm['name']}/{vm['name']}.vmdk"] = 600
        self.port = self.wmks_port = 0
        self._srv = self._loop = None

    # ── servers ─────────────────────────────────────────────
    def start(self) -> "FakeEsxi":
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                if self.path != "/sdk":
                    return self._send(404, b"")
                code, out, cookie = fake.soap(body, self.headers.get("Cookie", ""))
                self._send(code, out.encode(), cookie)

            def do_PUT(self):
                m = re.match(r"^/folder/([^?]+)\?(.*)$", self.path)
                if not m or "vmware_soap_session" not in self.headers.get("Cookie", ""):
                    return self._send(403, b"")
                import urllib.parse as up
                q = dict(up.parse_qsl(m.group(2)))
                n = int(self.headers.get("Content-Length") or 0)
                left = n
                while left > 0:
                    left -= len(self.rfile.read(min(65536, left)))
                with fake.lock:
                    fake.files.setdefault(q.get("dsName", ""), {})[up.unquote(m.group(1))] = n
                    fake.calls.append(("UPLOAD", q.get("dsName"), up.unquote(m.group(1)), n))
                self._send(201, b"")

            def do_GET(self):
                if self.path.startswith("/api/"):
                    return self._send(400, b"Unsupported content type")
                m = re.match(r"^/folder/([^?]+)\?(.*)$", self.path)
                if m and "vmware_soap_session" in self.headers.get("Cookie", ""):
                    import urllib.parse as up
                    q = dict(up.parse_qsl(m.group(2)))
                    with fake.lock:
                        raw = fake.read_file(q.get("dsName", ""), up.unquote(m.group(1)))
                    if raw is not None:
                        return self._send(200, raw)
                self._send(404, b"")

            def _send(self, code, raw, cookie=""):
                self.send_response(code)
                self.send_header("Content-Type", "text/xml; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(raw)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        ready = threading.Event()
        threading.Thread(target=self._wmks_thread, args=(ready,), daemon=True).start()
        ready.wait(10)
        return self

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()
        # the console server's loop runs on a daemon thread and goes with the
        # process; stopping it mid-serve only prints asyncio's complaints

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def read_file(self, ds: str, path: str):
        """What the file service returns for a file, or None when it has none
        to return (a stand-in that keeps file contents overrides this)."""
        return None

    # ── SOAP ────────────────────────────────────────────────
    def soap(self, body: str, cookie: str) -> tuple[int, str, str]:
        root = ET.fromstring(body)
        b = next(c for c in root if _l(c.tag) == "Body")
        req = list(b)[0]
        op = _l(req.tag)
        this = _t(req, "_this")
        with self.lock:
            self.calls.append((op, this, body))
            try:
                if op == "RetrieveServiceContent":
                    return 200, ENV.format(self._service_content()), ""
                if op == "Login":
                    if _t(req, "userName") != "root" or _t(req, "password") != "lab-password":
                        raise Fault("InvalidLogin", "Cannot complete login due to an incorrect user name or password.")
                    return 200, ENV.format('<LoginResponse xmlns="urn:vim25"><returnval><key>k</key>'
                                           '</returnval></LoginResponse>'), \
                        'vmware_soap_session="fake-session"; Path=/; HttpOnly'
                if "vmware_soap_session" not in cookie:
                    raise Fault("NotAuthenticated", "The session is not authenticated.")
                if op in self.fail_next:
                    kind, msg = self.fail_next.pop(op)
                    raise Fault(kind, msg)
                if self.read_only and op not in READ_OPS:
                    self.refused.append(op)
                    raise Fault("RestrictedVersion", "Current license or ESXi version prohibits execution of "
                                                     "the requested operation.")
                handler = getattr(self, "op_" + op, None)
                if not handler:
                    raise Fault("MethodNotFound", op)
                out = handler(req, this)
                return 200, ENV.format(f'<{op}Response xmlns="urn:vim25">{out}</{op}Response>'), ""
            except Fault as f:
                return 500, ENV.format(
                    f'<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>{x(f.msg)}'
                    f'</faultstring><detail><{f.kind}Fault xmlns="urn:vim25" xsi:type="{f.kind}"/>'
                    '</detail></soapenv:Fault>'), ""

    def _service_content(self) -> str:
        return ('<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval>'
                '<rootFolder type="Folder">ha-folder-root</rootFolder>'
                '<propertyCollector type="PropertyCollector">ha-property-collector</propertyCollector>'
                '<viewManager type="ViewManager">ViewManager</viewManager>'
                '<about><name>VMware ESXi</name><fullName>VMware ESXi 8.0.3 build-24414501</fullName>'
                '<version>8.0.3</version><build>24414501</build>'
                f'<apiType>{self.api_type}</apiType>'
                '<apiVersion>8.0.3.0</apiVersion></about>'
                '<sessionManager type="SessionManager">ha-sessionmgr</sessionManager>'
                '<taskManager type="TaskManager">ha-taskmgr</taskManager>'
                '<fileManager type="FileManager">ha-nfc-file-manager</fileManager>'
                '</returnval></RetrieveServiceContentResponse>')

    def _vm(self, moid: str) -> dict:
        vm = self.vms.get(moid)
        if not vm:
            raise Fault("ManagedObjectNotFound", f"The object 'vim.VirtualMachine:{moid}' has already been deleted or has not been completely created")
        return vm

    def _task(self, entity: str, desc: str, result: str = "", error: str = "",
              result_xml: str = "") -> str:
        tid = f"haTask-{next(self._tasks)}-{desc}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.tasks[tid] = {"state": "error" if error else "success", "error": error,
                           "desc": desc, "entity": entity, "result": result, "time": now,
                           "result_xml": result_xml}
        return f'<returnval type="Task">{tid}</returnval>'

    # ── properties ──────────────────────────────────────────
    def op_RetrievePropertiesEx(self, req, this):
        spec = _k(req, "specSet")
        props = [(_t(p, "type"), [(c.text or "") for c in p if _l(c.tag) == "pathSet"])
                 for p in spec if _l(p.tag) == "propSet"]
        objs = []
        for o in spec:
            if _l(o.tag) != "objectSet":
                continue
            ob = _k(o, "obj")
            if ob.get("type") == "ContainerView":
                for kind, _paths in props:
                    if kind == "HostSystem":
                        objs.append(("HostSystem", "ha-host"))
                    if kind == "VirtualMachine":
                        objs += [("VirtualMachine", m) for m in self.vms]
            else:
                objs.append((ob.get("type"), (ob.text or "").strip()))
        want = dict(props)
        if self.old and any(p == "hardware.systemInfo.serialNumber" for _k2, ps in props for p in ps):
            raise Fault("InvalidProperty", "hardware.systemInfo.serialNumber")
        out = ""
        for kind, moid in objs:
            paths = want.get(kind, [])
            ps = "".join(f"<propSet><name>{x(p)}</name>{self._prop(kind, moid, p)}</propSet>"
                         for p in paths if self._prop(kind, moid, p) is not None)
            out += f'<objects><obj type="{kind}">{x(moid)}</obj>{ps}</objects>'
        return f"<returnval>{out}</returnval>"

    def op_CreateContainerView(self, req, this):
        return '<returnval type="ContainerView">session[fake]view-1</returnval>'

    def op_DestroyView(self, req, this):
        return ""

    def op_ContinueRetrievePropertiesEx(self, req, this):
        return "<returnval></returnval>"

    @staticmethod
    def _s(v, t="xsd:string"):
        return f'<val xsi:type="{t}">{x(str(v))}</val>'

    @staticmethod
    def _mo(kind, moid):
        return f'<val type="{kind}" xsi:type="ManagedObjectReference">{x(moid)}</val>'

    @staticmethod
    def _mos(kind, ids):
        inner = "".join(f'<ManagedObjectReference type="{kind}" xsi:type="ManagedObjectReference">'
                        f'{x(i)}</ManagedObjectReference>' for i in ids)
        return f'<val xsi:type="ArrayOfManagedObjectReference">{inner}</val>'

    def _prop(self, kind, moid, p):
        S, MO, MOS = self._s, self._mo, self._mos
        if kind == "LicenseManager":
            if p != "licenses":
                return None
            name, edition = self.licence
            feature = ("" if edition.startswith("esx.hypervisor") else
                       '<properties><key>feature</key><value xsi:type="KeyValue"><key>vsphereapi</key>'
                       '<value>vSphere API</value></value></properties>')
            return ('<val xsi:type="ArrayOfLicenseManagerLicenseInfo"><LicenseManagerLicenseInfo>'
                    f'<licenseKey>00000-00000-00000-00000-00000</licenseKey><editionKey>{x(edition)}</editionKey>'
                    f'<name>{x(name)}</name><total>0</total><used>2</used><costUnit>cpuPackage</costUnit>'
                    f'{feature}</LicenseManagerLicenseInfo></val>')
        if kind == "Folder" and moid == "ha-folder-root" and p == "childEntity":
            return MOS("Datacenter", ["ha-datacenter"])
        if kind == "Folder" and moid == "ha-folder-host" and p == "childEntity":
            return MOS("ComputeResource", ["ha-compute-res"])
        if kind == "Datacenter":
            return {"vmFolder": MO("Folder", "ha-folder-vm"), "hostFolder": MO("Folder", "ha-folder-host"),
                    "name": S("ha-datacenter")}.get(p)
        if kind == "ComputeResource":
            return {"resourcePool": MO("ResourcePool", "ha-root-pool"),
                    "host": MOS("HostSystem", ["ha-host"]),
                    "environmentBrowser": MO("EnvironmentBrowser", "ha-env-browser")}.get(p)
        if kind == "HostSystem":
            return self._host_prop(p)
        if kind == "VirtualMachine":
            return self._vm_prop(self._vm(moid), moid, p)
        if kind == "Datastore":
            used = sum(self.files.get("datastore1", {}).values())
            return ('<val xsi:type="DatastoreSummary"><datastore type="Datastore">ds-1</datastore>'
                    '<name>datastore1</name><url>/vmfs/volumes/ds-1</url>'
                    f'<capacity>{2048 * GiB}</capacity><freeSpace>{2048 * GiB - used - 900 * GiB}</freeSpace>'
                    '<accessible>true</accessible><type>VMFS</type></val>') if p == "summary" else None
        if kind == "TaskManager" and p == "recentTask":
            return MOS("Task", list(self.tasks)[-15:])
        if kind == "Task":
            t = self.tasks.get(moid)
            if not t:
                raise Fault("ManagedObjectNotFound", "no such task")
            if p == "info.result":
                return t.get("result_xml") or (self._s(t["result"]) if t["result"] else None)
            if p == "info":
                err = (f'<error><localizedMessage>{x(t["error"])}</localizedMessage></error>'
                       if t["error"] else "")
                res = f'<result type="VirtualMachine" xsi:type="ManagedObjectReference">{x(t["result"])}</result>' if t["result"] else ""
                return (f'<val xsi:type="TaskInfo"><key>{moid}</key><task type="Task">{moid}</task>'
                        f'<descriptionId>VirtualMachine.{t["desc"]}</descriptionId>'
                        f'<entityName>{x(t["entity"])}</entityName><state>{t["state"]}</state>'
                        f'{err}{res}<reason xsi:type="TaskReasonUser"><userName>root</userName></reason>'
                        f'<queueTime>{t["time"]}</queueTime><startTime>{t["time"]}</startTime>'
                        f'<completeTime>{t["time"]}</completeTime></val>')
        return None

    def _host_prop(self, p):
        S, MOS = self._s, self._mos
        on = [v for v in self.vms.values() if v["power"] == "poweredOn"]
        simple = {
            "name": S(self.name), "runtime.connectionState": S("connected"),
            "runtime.powerState": S("poweredOn"),
            "runtime.inMaintenanceMode": S("true" if self.maintenance else "false", "xsd:boolean"),
            "runtime.bootTime": S("2026-09-07T20:38:37Z", "xsd:dateTime"),
            "summary.hardware.numCpuCores": S(32), "summary.hardware.cpuMhz": S(2300),
            "summary.hardware.memorySize": S(512 * GiB),
            "summary.quickStats.overallCpuUsage": S(9800 + 1100 * len(on)),
            "summary.quickStats.overallMemoryUsage": S(sum(v["mem"] for v in on) + 24000),
            "summary.quickStats.uptime": S(78 * 86400 + 4 * 3600),
            "summary.config.product.fullName": S("VMware ESXi 8.0.3 build-24414501"),
            "hardware.systemInfo.uuid": S(self.uuid),
            "hardware.systemInfo.serialNumber": S(self.serial),
            "summary.hardware.vendor": S("Dell Inc."), "summary.hardware.model": S("PowerEdge R650"),
            "datastoreBrowser": self._mo("HostDatastoreBrowser", "ha-host-datastorebrowser"),
            "configManager.serviceSystem": self._mo("HostServiceSystem", "serviceSystem"),
            "configManager.networkSystem": self._mo("HostNetworkSystem", "networkSystem"),
            "datastore": MOS("Datastore", ["ds-1"]), "vm": MOS("VirtualMachine", list(self.vms)),
        }
        if p in simple:
            return simple[p]
        if p == "summary.hardware":
            return ('<val xsi:type="HostHardwareSummary"><vendor>Dell Inc.</vendor>'
                    '<model>PowerEdge R650</model><memorySize>%d</memorySize>'
                    '<cpuModel>Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz</cpuModel><cpuMhz>2300</cpuMhz>'
                    '<numCpuPkgs>2</numCpuPkgs><numCpuCores>32</numCpuCores><numCpuThreads>64</numCpuThreads>'
                    '</val>') % (512 * GiB)
        if p == "config.product":
            return ('<val xsi:type="AboutInfo"><fullName>VMware ESXi 8.0.3 build-24414501</fullName>'
                    '<version>8.0.3</version><build>24414501</build></val>')
        if p == "config.network.portgroup":
            items = ""
            for g in self.portgroups:
                ports = "".join('<port><key>k</key><type>virtualMachine</type></port>'
                                for v in self.vms.values() for d in v["devices"]
                                if d["type"] == "VirtualVmxnet3" and d.get("network") == g["name"])
                items += (f'<HostPortGroup xsi:type="HostPortGroup"><key>key-{x(g["name"])}</key>{ports}'
                          f'<spec><name>{x(g["name"])}</name><vlanId>{g["vlan"]}</vlanId>'
                          f'<vswitchName>{x(g["vswitch"])}</vswitchName><policy/></spec></HostPortGroup>')
            return f'<val xsi:type="ArrayOfHostPortGroup">{items}</val>'
        if p == "config.network.vswitch":
            return ('<val xsi:type="ArrayOfHostVirtualSwitch"><HostVirtualSwitch xsi:type="HostVirtualSwitch">'
                    '<name>vSwitch0</name><numPorts>2560</numPorts><mtu>1500</mtu>'
                    '<pnic>key-vim.host.PhysicalNic-vmnic0</pnic><pnic>key-vim.host.PhysicalNic-vmnic1</pnic>'
                    '</HostVirtualSwitch></val>')
        if p == "config.network.pnic":
            return ('<val xsi:type="ArrayOfPhysicalNic">' + "".join(
                f'<PhysicalNic xsi:type="PhysicalNic"><device>vmnic{i}</device><mac>3c:fd:fe:0a:11:0{i}</mac>'
                f'<linkSpeed><speedMb>{25000 if i < 2 else 0}</speedMb><duplex>true</duplex></linkSpeed>'
                f'<driver>i40en</driver></PhysicalNic>' for i in range(4)) + '</val>')
        if p == "config.service":
            return ('<val xsi:type="HostServiceInfo">' + "".join(
                f'<service><key>{s["key"]}</key><label>{x(s["label"])}</label><required>false</required>'
                f'<running>{"true" if s["running"] else "false"}</running><policy>{s["policy"]}</policy></service>'
                for s in self.services) + '</val>')
        return None

    def _devices_xml(self, vm) -> str:
        out = ""
        nic_t = ("VirtualVmxnet3", "VirtualE1000e", "VirtualE1000")
        disks = [e["key"] for e in vm["devices"] if e["type"] == "VirtualDisk"]
        nics = [e["key"] for e in vm["devices"] if e["type"] in nic_t]
        for d in vm["devices"]:
            t, key = d["type"], d["key"]
            if t == "VirtualDisk":
                label = f"Hard disk {disks.index(key) + 1}"
            elif t in nic_t:
                label = f"Network adapter {nics.index(key) + 1}"
            elif t == "VirtualCdrom":
                label = "CD/DVD drive 1"
            else:
                label = t.replace("Virtual", "") + " 0"
            inner = f"<key>{key}</key><deviceInfo><label>{x(label)}</label><summary>{x(label)}</summary></deviceInfo>"
            if d.get("slot") is not None:
                inner += ('<slotInfo xsi:type="VirtualDevicePciBusSlotInfo">'
                          f'<pciSlotNumber>{int(d["slot"])}</pciSlotNumber></slotInfo>')
            if t == "VirtualDisk":
                inner += (f'<backing xsi:type="VirtualDiskFlatVer2BackingInfo"><fileName>{x(d["file"])}</fileName>'
                          '<datastore type="Datastore">ds-1</datastore><diskMode>persistent</diskMode>'
                          f'<thinProvisioned>{"true" if d["thin"] else "false"}</thinProvisioned></backing>'
                          f'<controllerKey>{d["controller"]}</controllerKey><unitNumber>{d["unit"]}</unitNumber>'
                          f'<capacityInKB>{d["kb"]}</capacityInKB><capacityInBytes>{d["kb"] * 1024}</capacityInBytes>')
            elif t in ("VirtualVmxnet3", "VirtualE1000e", "VirtualE1000"):
                inner += (f'<backing xsi:type="VirtualEthernetCardNetworkBackingInfo"><deviceName>{x(d["network"])}'
                          f'</deviceName><network type="Network">HaNetwork-{x(d["network"])}</network></backing>'
                          f'<connectable><startConnected>{"true" if d.get("start_connected", True) else "false"}'
                          f'</startConnected><allowGuestControl>true</allowGuestControl>'
                          f'<connected>{"true" if d["connected"] else "false"}</connected><status>ok</status></connectable>'
                          f'<controllerKey>{d.get("controller", 100)}</controllerKey><unitNumber>{d.get("unit", 7)}</unitNumber>'
                          f'<addressType>{d.get("address_type", "generated")}</addressType><macAddress>{d["mac"]}</macAddress>')
            elif t == "VirtualCdrom":
                back = (f'<backing xsi:type="VirtualCdromIsoBackingInfo"><fileName>{x(d["iso"])}</fileName></backing>'
                        if d["iso"] else '<backing xsi:type="VirtualCdromRemotePassthroughBackingInfo">'
                        '<deviceName></deviceName><useAutoDetect>false</useAutoDetect><exclusive>false</exclusive></backing>')
                inner += (back + f'<connectable><startConnected>{"true" if d.get("start_connected", bool(d["iso"])) else "false"}</startConnected>'
                          f'<allowGuestControl>true</allowGuestControl><connected>{"true" if d["connected"] else "false"}'
                          f'</connected><status>ok</status></connectable><controllerKey>{d["controller"]}</controllerKey>'
                          f'<unitNumber>{d["unit"]}</unitNumber>')
            elif t.endswith("Controller"):
                kids = "".join(f"<device>{e['key']}</device>" for e in vm["devices"] if e.get("controller") == key)
                inner += f"<busNumber>{d.get('bus', 0)}</busNumber>{kids}"
            out += f'<VirtualDevice xsi:type="{t}">{inner}</VirtualDevice>'
        return f'<val xsi:type="ArrayOfVirtualDevice">{out}</val>'

    def _snap_xml(self, nodes, moid) -> str:
        out = ""
        for s in nodes:
            out += (f'<rootSnapshotList><snapshot type="VirtualMachineSnapshot">{s["id"]}</snapshot>'
                    f'<vm type="VirtualMachine">{moid}</vm><name>{x(s["name"])}</name>'
                    f'<description>{x(s["description"])}</description><id>1</id>'
                    f'<createTime>{s["created"]}</createTime><state>{s["state"]}</state><quiesced>false</quiesced>'
                    + self._snap_xml(s["children"], moid).replace("<rootSnapshotList>", "<childSnapshotList>")
                    .replace("</rootSnapshotList>", "</childSnapshotList>") + "</rootSnapshotList>")
        return out

    def _vm_prop(self, vm, moid, p):
        S = self._s
        on = vm["power"] == "poweredOn"
        disk_kb = sum(d["kb"] for d in vm["devices"] if d["type"] == "VirtualDisk")
        simple = {
            "name": S(vm["name"]), "runtime.powerState": S(vm["power"]),
            "runtime.host": self._mo("HostSystem", "ha-host"),
            "runtime.connectionState": S("connected"),
            "config.guestFullName": S(vm["guestFull"]), "config.guestId": S(vm["guestId"]),
            "config.annotation": S(vm["notes"]), "config.hardware.numCPU": S(vm["cpus"]),
            "config.hardware.numCoresPerSocket": S(vm["cps"]), "config.hardware.memoryMB": S(vm["mem"]),
            "config.firmware": S(vm["firmware"]),
            "config.files.vmPathName": S(vm.get("vmx") or f"[datastore1] {vm['name']}/{vm['name']}.vmx"),
            "config.version": S(vm.get("hw") or "vmx-21"), "config.uuid": S(vm.get("uuid") or f"4210{moid:0>4}-fake"),
            "config.template": S("false", "xsd:boolean"),
            "guest.toolsRunningStatus": S(vm["tools"]), "guest.toolsVersionStatus2": S("guestToolsCurrent"),
            "guestHeartbeatStatus": S("green" if on and vm["tools"] == "guestToolsRunning" else "gray"),
            "summary.config.numCpu": S(vm["cpus"]), "summary.config.memorySizeMB": S(vm["mem"]),
            "summary.config.template": S("false"),
            "summary.runtime.maxCpuUsage": S(vm["cpus"] * 2300),
            "summary.quickStats.overallCpuUsage": S(int(vm["cpus"] * 2300 * (0.18 + 0.01 * len(vm["name"]))) if on else 0),
            "summary.quickStats.guestMemoryUsage": S(int(vm["mem"] * 0.42) if on else 0),
            "summary.quickStats.uptimeSeconds": S(vm["uptime"] if on else 0),
            "summary.storage.committed": S(int(disk_kb * 1024 * 0.55)),
            "summary.storage.uncommitted": S(int(disk_kb * 1024 * 0.45)),
            "config.hardware.device": self._devices_xml(vm),
        }
        if p in simple:
            return simple[p]
        if p == "runtime.bootTime":
            return S("2026-11-12T08:00:00Z", "xsd:dateTime") if on else None
        if p == "guest.ipAddress":
            return S(vm["ip"]) if on and vm["ip"] else None
        if p == "guest.hostName":
            return S(vm["name"]) if on else None
        if p == "guest.guestFullName":
            return S(vm["guestFull"]) if on else None
        if p == "guest.net":
            if not (on and vm["ip"]):
                return None
            nic = next(d for d in vm["devices"] if d["type"] == "VirtualVmxnet3")
            return (f'<val xsi:type="ArrayOfGuestNicInfo"><GuestNicInfo xsi:type="GuestNicInfo">'
                    f'<network>{x(nic["network"])}</network><ipAddress>{vm["ip"]}</ipAddress>'
                    f'<macAddress>{nic["mac"]}</macAddress><connected>true</connected></GuestNicInfo></val>')
        if p == "config.bootOptions":
            return (f'<val xsi:type="VirtualMachineBootOptions"><bootDelay>0</bootDelay>'
                    f'<enterBIOSSetup>{"true" if vm["enter_setup"] else "false"}</enterBIOSSetup>'
                    f'<efiSecureBootEnabled>{"true" if vm["secure_boot"] else "false"}</efiSecureBootEnabled></val>')
        if p == "snapshot":
            if not vm["snapshots"]:
                return None
            return (f'<val xsi:type="VirtualMachineSnapshotInfo"><currentSnapshot type="VirtualMachineSnapshot">'
                    f'{vm["current"]}</currentSnapshot>{self._snap_xml(vm["snapshots"], moid)}</val>')
        if p == "recentTask":
            mine = [t for t, v in self.tasks.items() if v["entity"] == vm["name"]][-5:]
            return self._mos("Task", mine) if mine else None
        return None

    # ── VM actions ──────────────────────────────────────────
    def _power(self, this, want, desc, allowed):
        vm = self._vm(this)
        if vm["power"] not in allowed:
            return self._task(vm["name"], desc, error=f"The attempted operation cannot be performed in the current state ({vm['power']}).")
        vm["power"] = want
        vm["tools"] = "guestToolsRunning" if want == "poweredOn" else "guestToolsNotRunning"
        vm["uptime"] = 60 if want == "poweredOn" else 0
        for d in vm["devices"]:
            if d["type"] == "VirtualVmxnet3":
                d["connected"] = want == "poweredOn"
        return self._task(vm["name"], desc)

    def op_PowerOnVM_Task(self, req, this):
        return self._power(this, "poweredOn", "powerOn", ("poweredOff", "suspended"))

    def op_PowerOffVM_Task(self, req, this):
        return self._power(this, "poweredOff", "powerOff", ("poweredOn", "suspended"))

    def op_ResetVM_Task(self, req, this):
        return self._power(this, "poweredOn", "reset", ("poweredOn",))

    def op_SuspendVM_Task(self, req, this):
        return self._power(this, "suspended", "suspend", ("poweredOn",))

    def op_ShutdownGuest(self, req, this):
        vm = self._vm(this)
        if vm["tools"] != "guestToolsRunning":
            raise Fault("ToolsUnavailable", "Cannot complete operation because VMware Tools is not running in this virtual machine.")
        self._power(this, "poweredOff", "shutdownGuest", ("poweredOn",))
        return ""

    def op_RebootGuest(self, req, this):
        vm = self._vm(this)
        if vm["tools"] != "guestToolsRunning":
            raise Fault("ToolsUnavailable", "Cannot complete operation because VMware Tools is not running in this virtual machine.")
        vm["uptime"] = 30
        return ""

    def _find_snap(self, sid):
        for moid, vm in self.vms.items():
            stack = [(vm["snapshots"], None)]
            while stack:
                nodes, parent = stack.pop()
                for s in nodes:
                    if s["id"] == sid:
                        return moid, vm, s, nodes
                    stack.append((s["children"], s))
        raise Fault("ManagedObjectNotFound", "no such snapshot")

    def op_CreateSnapshot_Task(self, req, this):
        vm = self._vm(this)
        s = {"id": f"{this}-snapshot-{next(self._ids)}", "name": _t(req, "name"),
             "description": _t(req, "description"),
             "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "state": vm["power"] if _t(req, "memory") == "true" else "poweredOff", "children": []}
        if vm["current"]:
            _m, _v, cur, _n = self._find_snap(vm["current"])
            cur["children"].append(s)
        else:
            vm["snapshots"].append(s)
        vm["current"] = s["id"]
        return self._task(vm["name"], "createSnapshot")

    def op_RevertToSnapshot_Task(self, req, this):
        moid, vm, s, _n = self._find_snap(this)
        vm["current"] = s["id"]
        vm["power"] = s["state"]
        return self._task(vm["name"], "revertToSnapshot")

    def op_RemoveSnapshot_Task(self, req, this):
        moid, vm, s, nodes = self._find_snap(this)
        nodes.remove(s)
        if _t(req, "removeChildren") != "true":
            nodes.extend(s["children"])
        if vm["current"] == s["id"]:
            vm["current"] = ""
        return self._task(vm["name"], "removeSnapshot")

    def op_RemoveAllSnapshots_Task(self, req, this):
        vm = self._vm(this)
        vm["snapshots"], vm["current"] = [], ""
        return self._task(vm["name"], "removeAllSnapshots")

    def op_RenameSnapshot(self, req, this):
        _m, _v, s, _n = self._find_snap(this)
        s["name"], s["description"] = _t(req, "name"), _t(req, "description")
        return ""

    def op_ReconfigVM_Task(self, req, this):
        vm = self._vm(this)
        spec = _k(req, "spec")
        for el in spec:
            n = _l(el.tag)
            if n == "numCPUs":
                vm["cpus"] = int(el.text)
            elif n == "numCoresPerSocket":
                vm["cps"] = int(el.text)
            elif n == "memoryMB":
                if vm["power"] == "poweredOn" and int(el.text) != vm["mem"]:
                    return self._task(vm["name"], "reconfigure", error="Memory hot-add is not enabled for this virtual machine. Power it off to change its memory.")
                vm["mem"] = int(el.text)
            elif n == "annotation":
                vm["notes"] = el.text or ""
            elif n == "firmware":
                vm["firmware"] = el.text
            elif n == "bootOptions":
                if _k(el, "enterBIOSSetup") is not None:
                    vm["enter_setup"] = _t(el, "enterBIOSSetup") == "true"
                if _k(el, "efiSecureBootEnabled") is not None:
                    vm["secure_boot"] = _t(el, "efiSecureBootEnabled") == "true"
            elif n == "deviceChange":
                self._device_change(vm, el)
        return self._task(vm["name"], "reconfigure")

    def _device_change(self, vm, ch):
        op = _t(ch, "operation")
        dev = _k(ch, "device")
        t = dev.get(XSI)
        key = int(_t(dev, "key") or 0)
        if op == "remove":
            vm["devices"] = [d for d in vm["devices"] if d["key"] != key]
            return
        if op == "add":
            key = 2000 + next(self._ids) if t == "VirtualDisk" else 4000 + next(self._ids)
        back = _k(dev, "backing")
        con = _k(dev, "connectable")
        if op == "edit":
            d = next(d for d in vm["devices"] if d["key"] == key)
        else:
            d = {"type": t, "key": key}
            vm["devices"].append(d)
        if t == "VirtualDisk":
            d["kb"] = int(_t(dev, "capacityInKB") or 0)
            if op == "add":
                d.update(controller=int(_t(dev, "controllerKey")), unit=int(_t(dev, "unitNumber")),
                         thin=_t(back, "thinProvisioned") == "true",
                         file=f"[datastore1] {vm['name']}/{vm['name']}_{key}.vmdk")
        elif t in ("VirtualVmxnet3", "VirtualE1000e", "VirtualE1000"):
            if back is not None and _t(back, "deviceName"):
                d["network"] = _t(back, "deviceName")
            if con is not None:
                d["connected"] = _t(con, "connected") == "true"
            if op == "add":
                d.update(mac="00:50:56:aa:bb:%02x" % (key % 256), controller=100, unit=8)
        elif t == "VirtualCdrom":
            d["iso"] = _t(back, "fileName") if back is not None and back.get(XSI) == "VirtualCdromIsoBackingInfo" else ""
            d["connected"] = con is not None and _t(con, "connected") == "true"

    def op_Rename_Task(self, req, this):
        vm = self._vm(this)
        vm["name"] = _t(req, "newName")
        return self._task(vm["name"], "rename")

    def op_Destroy_Task(self, req, this):
        vm = self._vm(this)
        if vm["power"] != "poweredOff":
            return self._task(vm["name"], "destroy", error="The attempted operation cannot be performed in the current state (Powered on).")
        del self.vms[this]
        return self._task(vm["name"], "destroy")

    def op_UnregisterVM(self, req, this):
        self._vm(this)
        del self.vms[this]
        return ""

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
                d.update(controller=abs(int(_t(dev, "controllerKey"))) * 10, unit=int(_t(dev, "unitNumber")),
                         kb=int(_t(dev, "capacityInKB")), thin=_t(back, "thinProvisioned") == "true",
                         file=f"[datastore1] {name}/{name}.vmdk")
            elif t == "VirtualCdrom":
                d.update(controller=abs(int(_t(dev, "controllerKey"))) * 10, unit=0, connected=False,
                         iso=_t(back, "fileName") if back.get(XSI) == "VirtualCdromIsoBackingInfo" else "")
            else:
                d.update(network=_t(back, "deviceName"), connected=False, mac="00:50:56:00:00:%02x" % int(moid),
                         controller=100, unit=7)
            vm["devices"].append(d)
        self.vms[moid] = vm
        self.files.setdefault("datastore1", {})[f"{name}/{name}.vmx"] = 3200
        tid = self._task(name, "createVm", result=moid)
        return tid

    # ── host actions ────────────────────────────────────────
    def _host(self, this):
        if this != "ha-host":
            raise Fault("ManagedObjectNotFound", "no such host")

    def op_EnterMaintenanceMode_Task(self, req, this):
        self._host(this)
        if any(v["power"] == "poweredOn" for v in self.vms.values()):
            return self._task(self.name, "enterMaintenanceMode",
                              error="The host cannot enter maintenance mode while virtual machines are running.")
        self.maintenance = True
        return self._task(self.name, "enterMaintenanceMode")

    def op_ExitMaintenanceMode_Task(self, req, this):
        self._host(this)
        self.maintenance = False
        return self._task(self.name, "exitMaintenanceMode")

    def op_RebootHost_Task(self, req, this):
        self._host(this)
        if not self.maintenance and _t(req, "force") != "true":
            return self._task(self.name, "reboot", error="The operation is not allowed in the current state.")
        return self._task(self.name, "reboot")

    def op_ShutdownHost_Task(self, req, this):
        self._host(this)
        if not self.maintenance and _t(req, "force") != "true":
            return self._task(self.name, "shutdown", error="The operation is not allowed in the current state.")
        return self._task(self.name, "shutdown")

    def _svc(self, this, req):
        if this != "serviceSystem":
            raise Fault("ManagedObjectNotFound", "no such service system")
        s = next((s for s in self.services if s["key"] == _t(req, "id")), None)
        if not s:
            raise Fault("NotFound", "no such service")
        return s

    def op_StartService(self, req, this):
        self._svc(this, req)["running"] = True
        return ""

    def op_StopService(self, req, this):
        self._svc(this, req)["running"] = False
        return ""

    def op_RestartService(self, req, this):
        self._svc(this, req)["running"] = True
        return ""

    def op_UpdateServicePolicy(self, req, this):
        self._svc(this, req)["policy"] = _t(req, "policy")
        return ""

    def _net(self, this):
        if this != "networkSystem":
            raise Fault("ManagedObjectNotFound", "no such network system")

    def op_AddPortGroup(self, req, this):
        self._net(this)
        pg = _k(req, "portgrp")
        if any(g["name"] == _t(pg, "name") for g in self.portgroups):
            raise Fault("AlreadyExists", "The specified key, name, or identifier already exists.")
        self.portgroups.append({"name": _t(pg, "name"), "vlan": int(_t(pg, "vlanId")),
                                "vswitch": _t(pg, "vswitchName")})
        return ""

    def op_UpdatePortGroup(self, req, this):
        self._net(this)
        g = next((g for g in self.portgroups if g["name"] == _t(req, "pgName")), None)
        if not g:
            raise Fault("NotFound", "The object or item referred to could not be found.")
        g["vlan"] = int(_t(_k(req, "portgrp"), "vlanId"))
        return ""

    def op_RemovePortGroup(self, req, this):
        self._net(this)
        self.portgroups = [g for g in self.portgroups if g["name"] != _t(req, "pgName")]
        return ""

    # ── datastores ──────────────────────────────────────────
    def _search(self, ds: str, folder: str, recursive: bool, iso_only: bool):
        files = self.files.get(ds, {})
        folder = folder.strip("/")
        results: dict = {}
        for path, size in files.items():
            parent, _, name = path.rpartition("/")
            if recursive:
                if iso_only and not name.lower().endswith(".iso"):
                    continue
                results.setdefault(parent, []).append((name, size, "IsoImageFileInfo"))
                continue
            if parent == folder:
                results.setdefault(folder, []).append(
                    (name, size, "IsoImageFileInfo" if name.endswith(".iso") else
                     "VmDiskFileInfo" if name.endswith(".vmdk") else
                     "VmConfigFileInfo" if name.endswith(".vmx") else "FileInfo"))
            elif (parent + "/").startswith(folder + "/" if folder else ""):
                sub = parent[len(folder):].strip("/").split("/")[0]
                if sub and (sub, 0, "FolderFileInfo") not in results.setdefault(folder, []):
                    results[folder].append((sub, 0, "FolderFileInfo"))
        return results

    def _result_xml(self, ds, folder, items, tag="val", t="HostDatastoreBrowserSearchResults"):
        fp = f"[{ds}] {folder}/" if folder else f"[{ds}]"
        files = "".join(f'<file xsi:type="{k}"><path>{x(n)}</path><fileSize>{s}</fileSize>'
                        '<modification>2026-11-20T10:00:00Z</modification></file>' for n, s, k in items)
        return f'<{tag} xsi:type="{t}"><datastore type="Datastore">ds-1</datastore><folderPath>{x(fp)}</folderPath>{files}</{tag}>'

    def _ds_path(self, p: str):
        m = re.match(r"^\[([^\]]+)\]\s?(.*)$", p)
        if not m:
            raise Fault("InvalidDatastorePath", "Invalid datastore path")
        return m.group(1), m.group(2)

    def op_SearchDatastore_Task(self, req, this):
        ds, folder = self._ds_path(_t(req, "datastorePath"))
        res = self._search(ds, folder, False, False).get(folder.strip("/"), [])
        return self._task(ds, "searchDatastore",
                          result_xml=self._result_xml(ds, folder.strip("/"), res))

    def op_SearchDatastoreSubFolders_Task(self, req, this):
        ds, folder = self._ds_path(_t(req, "datastorePath"))
        res = self._search(ds, folder, True, True)
        inner = "".join(self._result_xml(ds, f, items, "HostDatastoreBrowserSearchResults", "HostDatastoreBrowserSearchResults")
                        for f, items in res.items())
        return self._task(ds, "searchDatastoreSubFolders",
                          result_xml=f'<val xsi:type="ArrayOfHostDatastoreBrowserSearchResults">{inner}</val>')

    def op_MakeDirectory(self, req, this):
        if this != "ha-nfc-file-manager":
            raise Fault("ManagedObjectNotFound", "no such file manager")
        ds, path = self._ds_path(_t(req, "name"))
        self.files.setdefault(ds, {})[path.strip("/") + "/.dir"] = 0
        return ""

    def op_DeleteDatastoreFile_Task(self, req, this):
        if this != "ha-nfc-file-manager":
            raise Fault("ManagedObjectNotFound", "no such file manager")
        ds, path = self._ds_path(_t(req, "name"))
        path = path.strip("/")
        files = self.files.get(ds, {})
        gone = [p for p in files if p == path or p.startswith(path + "/")]
        if not gone:
            return self._task(ds, "deleteFile", error=f"File [{ds}] {path} was not found")
        for p in gone:
            del files[p]
        return self._task(ds, "deleteFile")

    def op_QueryConfigOption(self, req, this):
        os_ = [("almalinux_64Guest", "AlmaLinux (64-bit)", "linuxGuest"),
               ("rhel9_64Guest", "Red Hat Enterprise Linux 9 (64-bit)", "linuxGuest"),
               ("ubuntu64Guest", "Ubuntu Linux (64-bit)", "linuxGuest"),
               ("debian12_64Guest", "Debian GNU/Linux 12 (64-bit)", "linuxGuest"),
               ("windows2019srvNext_64Guest", "Microsoft Windows Server 2022 (64-bit)", "windowsGuest"),
               ("otherGuest64", "Other (64-bit)", "otherGuestFamily")]
        d = "".join(f"<guestOSDescriptor><id>{i}</id><family>{f}</family><fullName>{x(n)}</fullName>"
                    "<supportLevel>supported</supportLevel></guestOSDescriptor>" for i, n, f in os_)
        return f"<returnval>{d}</returnval>"

    def op_AcquireTicket(self, req, this):
        self._vm(this)
        if _t(req, "ticketType") != "webmks":
            raise Fault("InvalidArgument", "ticketType")
        t = f"ticket{next(self._ids)}"
        self.tickets.add((t, this))
        return (f"<returnval><ticket>{t}</ticket><cfgFile>x.vmx</cfgFile>"
                f"<port>{self.wmks_port}</port><url>wss://localhost.localdomain:443/ticket/{t}</url></returnval>")

    # ── the console: RFB over a websocket ───────────────────
    def _wmks_thread(self, ready):
        import websockets.asyncio.server as wss
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def handler(ws):
            path = ws.request.path
            m = re.match(r"^/ticket/(\w+)$", path)
            with self.lock:
                hit = next((t for t in self.tickets if m and t[0] == m.group(1)), None)
                if hit:
                    self.tickets.discard(hit)
            if not hit:
                await ws.close(1008, "bad ticket")
                return
            vm = self.vms.get(hit[1], {})
            try:
                await self._rfb(ws, vm.get("name", "vm"), vm)
            except Exception:                                 # noqa: BLE001
                pass                                          # the other side went away: nothing to say

        fake = self

        class NoPings(wss.ServerConnection):
            """What ESXi 8.0.3 does (measured 27 November 2026): a websocket
            ping is not answered, the console connection is closed."""

            def process_event(self, event):
                if getattr(event, "opcode", None) == 9:
                    fake.pings_seen += 1
                    asyncio.get_running_loop().create_task(self.close(1000))
                    return
                super().process_event(event)

        async def main():
            async with wss.serve(handler, "127.0.0.1", 0, subprotocols=["binary"], max_size=None,
                                 create_connection=NoPings) as srv:
                self.wmks_port = list(srv.sockets)[0].getsockname()[1]
                ready.set()
                await asyncio.Future()
        try:
            self._loop.run_until_complete(main())
        except RuntimeError:
            pass

    async def _rfb(self, ws, name, vm):
        W, H = 800, 480
        buf = bytearray()

        async def need(n):
            while len(buf) < n:
                buf.extend(await ws.recv())

        await ws.send(b"RFB 003.008\n")
        await need(12); del buf[:12]
        await ws.send(b"\x01\x01")
        await need(1); del buf[:1]
        await ws.send(struct.pack(">I", 0))
        await need(1); del buf[:1]
        nb = name.encode()
        await ws.send(struct.pack(">HHBBBBHHHBBBxxx", W, H, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
                      + struct.pack(">I", len(nb)) + nb)
        shifts, big = (16, 8, 0), False
        try:
            while True:
                await need(1)
                t = buf[0]
                if t == 0:
                    await need(20)
                    big = bool(buf[6]); shifts = (buf[14], buf[15], buf[16]); del buf[:20]
                elif t == 2:
                    await need(4)
                    n = struct.unpack(">H", bytes(buf[2:4]))[0]
                    await need(4 + 4 * n)
                    self.encodings_seen.append([struct.unpack(">i", bytes(buf[4 + 4 * k:8 + 4 * k]))[0] for k in range(n)])
                    del buf[:4 + 4 * n]
                elif t == 3:
                    await need(10)
                    incr = buf[1]; del buf[:10]
                    if not incr:
                        await ws.send(struct.pack(">BxH", 0, 1) + struct.pack(">HHHHi", 0, 0, W, H, 0)
                                      + self._frame(W, H, name, vm, shifts, big))
                elif t == 4:
                    await need(8); del buf[:8]
                elif t == 5:
                    await need(6); del buf[:6]
                elif t == 6:
                    await need(8)
                    ln = struct.unpack(">I", bytes(buf[4:8]))[0]
                    await need(8 + ln); del buf[:8 + ln]
                else:
                    del buf[:1]
        except Exception:                                     # noqa: BLE001
            return

    _frames: dict = {}

    def _frame(self, W, H, name, vm, shifts, big) -> bytes:
        key = (name, shifts, big)
        if key in self._frames:
            return self._frames[key]
        try:
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new("RGB", (W, H), (12, 12, 12))
            d = ImageDraw.Draw(img)
            try:
                font = ImageFont.load_default(size=15)
            except TypeError:
                font = ImageFont.load_default()
            lines = [f"{vm.get('guestFull', 'Linux')}", "Kernel 5.14.0-427.13.1.el9_4.x86_64 on an x86_64", "",
                     f"Activate the web console with: systemctl enable --now cockpit.socket", "",
                     f"{name} login: root", "Password:", f"Last login: Mon Nov 24 09:12:41 on tty1",
                     f"[root@{name} ~]# uptime",
                     " 11:02:17 up 12 days,  5:01,  1 user,  load average: 0.21, 0.18, 0.12",
                     f"[root@{name} ~]# "]
            for i, ln in enumerate(lines):
                d.text((14, 14 + i * 22), ln, fill=(205, 205, 205), font=font)
            px = img.tobytes()
        except ImportError:
            px = bytes([30, 60, 120] * (W * H))
        out = bytearray(W * H * 4)
        rs, gs, bs = shifts
        for i in range(W * H):
            r, g, b = px[3 * i], px[3 * i + 1], px[3 * i + 2]
            v = (r << rs) | (g << gs) | (b << bs)
            out[4 * i:4 * i + 4] = v.to_bytes(4, "big" if big else "little")
        self._frames[key] = bytes(out)
        return self._frames[key]
