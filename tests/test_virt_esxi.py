#!/usr/bin/env python3
"""A standalone ESXi host is read through its own API (/sdk), not vCenter's.

Reported 24 November 2026: the Hypervisors page promised "a standalone ESXi
host", and a connection to one failed with "HTTP 400" whatever the password.
The code only spoke the vSphere REST API (/api/session, /api/vcenter/...),
which exists on vCenter alone. A real ESXi answers the REST login with 400
"Unsupported content type: application/x-www-form-urlencoded", and with 503
"upstream connect error" when the type is JSON. Its own API is the SOAP one
at /sdk, which says without a login whether it is ESXi ("HostAgent") or
vCenter ("VirtualCenter").

The fake ESXi below answers /api exactly as the real one did, so the old code
fails here the way it failed there. It checks:

  * an ESXi connection lists its host (CPU, memory, uptime) and its VMs (power
    state, usage, disk, host name), across a paged property read
  * a wrong password reads "authentication rejected", not "HTTP 400"
  * a session the host forgot is replaced by one new login, not an error
  * a password with XML characters arrives intact
  * an answer carrying a DTD is refused, not expanded
  * a vCenter still goes through REST, now with a JSON content type
  * a host whose /sdk is not vSphere still gets the REST path

    ./.venv/bin/python tests/test_virt_esxi.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("virt-esxi-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import virt                                           # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


PASSWORD = 'Pa<ss>&"word\''
ENV = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope '
       'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
       'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
       '<soapenv:Body>{}</soapenv:Body></soapenv:Envelope>')


def fault(kind: str, msg: str) -> str:
    return ENV.format(f'<soapenv:Fault><faultcode>ServerFaultCode</faultcode>'
                      f'<faultstring>{msg}</faultstring><detail>'
                      f'<{kind}Fault xmlns="urn:vim25" xsi:type="{kind}"/>'
                      f'</detail></soapenv:Fault>')


def objects(items) -> str:
    out = ""
    for kind, moid, props in items:
        out += f'<objects><obj type="{kind}">{moid}</obj>'
        for k, v in props.items():
            out += f'<propSet><name>{k}</name><val xsi:type="xsd:string">{v}</val></propSet>'
        out += "</objects>"
    return out


HOST = ("HostSystem", "ha-host", {
    "name": "esxi01.lab", "runtime.connectionState": "connected",
    "runtime.powerState": "poweredOn", "summary.hardware.numCpuCores": "16",
    "summary.hardware.cpuMhz": "2500",
    "summary.hardware.memorySize": str(128 * 1024**3),
    "summary.quickStats.overallCpuUsage": "10000",
    "summary.quickStats.overallMemoryUsage": str(32 * 1024),
    "summary.quickStats.uptime": str(3 * 86400 + 5 * 3600),
    "summary.config.product.fullName": "VMware ESXi 8.0.2 build-22380479"})
VMS = [("VirtualMachine", "1", {
            "name": "talos-cp-1", "runtime.powerState": "poweredOn",
            "runtime.host": "ha-host", "summary.config.numCpu": "4",
            "summary.config.memorySizeMB": "8192",
            "summary.config.template": "false",
            "summary.runtime.maxCpuUsage": "10000",
            "summary.quickStats.overallCpuUsage": "2500",
            "summary.quickStats.guestMemoryUsage": "2048",
            "summary.quickStats.uptimeSeconds": "7200",
            "summary.storage.committed": str(40 * 1024**3)}),
       ("VirtualMachine", "2", {
            "name": "old-builder", "runtime.powerState": "poweredOff",
            "runtime.host": "ha-host", "summary.config.numCpu": "2",
            "summary.config.memorySizeMB": "4096",
            "summary.config.template": "false"})]

state = {"logins": 0, "forget_once": False, "calls": [], "passwords": [],
         "rest_types": [], "doctype": False, "sdk_404": False,
         "api_type": "HostAgent"}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: str, ctype="text/xml; charset=utf-8",
              cookie=""):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/api/vcenter/host":
            return self._send(200, '[{"host":"host-1","name":"esx-a",'
                              '"connection_state":"CONNECTED",'
                              '"power_state":"POWERED_ON"}]', "application/json")
        if self.path == "/api/vcenter/vm":
            return self._send(200, '[{"vm":"vm-9","name":"web-1",'
                              '"power_state":"POWERED_ON","cpu_count":2,'
                              '"memory_size_MiB":4096}]', "application/json")
        self._send(404, "")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path == "/api/session":
            ctype = self.headers.get("Content-Type", "")
            state["rest_types"].append(ctype)
            if state["api_type"] == "HostAgent":
                # what the real ESXi answered on 24 November 2026
                if "json" in ctype:
                    return self._send(503, "upstream connect error or disconnect"
                                      "/reset before headers. reset reason: "
                                      "connection termination", "text/plain")
                return self._send(400, "Unsupported content type: " + ctype,
                                  "text/plain")
            return self._send(201, '"rest-session-1"', "application/json")
        if self.path != "/sdk" or state["sdk_404"]:
            return self._send(404, "")
        op = re.search(r"<soapenv:Body><(\w+)", body).group(1)
        state["calls"].append(op)
        if state["doctype"]:
            return self._send(200, '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a '
                              '"aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><x>&b;</x>')
        if op == "RetrieveServiceContent":
            return self._send(200, ENV.format(
                '<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval>'
                '<rootFolder type="Folder">ha-folder-root</rootFolder>'
                '<propertyCollector type="PropertyCollector">ha-property-collector'
                '</propertyCollector><viewManager type="ViewManager">ViewManager'
                '</viewManager><about><name>VMware ESXi</name><fullName>VMware '
                'ESXi 8.0.2 build-22380479</fullName><apiType>'
                f'{state["api_type"]}</apiType><apiVersion>8.0.2.0</apiVersion>'
                '</about><sessionManager type="SessionManager">ha-sessionmgr'
                '</sessionManager></returnval></RetrieveServiceContentResponse>'))
        if op == "Login":
            pw = re.search(r"<password>(.*?)</password>", body, re.S).group(1)
            state["passwords"].append(pw)
            if "<userName>norole</userName>" in body:
                # the real host's answer for a right password on an account
                # with no role (24 November 2026)
                return self._send(500, fault("NoPermission", "Permission to "
                                  "perform this operation was denied."))
            if pw != "Pa&lt;ss&gt;&amp;&quot;word&apos;" and \
                    pw != "Pa&lt;ss&gt;&amp;\"word'":
                return self._send(500, fault("InvalidLogin", "Cannot complete "
                                  "login due to an incorrect user name or "
                                  "password."))
            state["logins"] += 1
            return self._send(200, ENV.format(
                '<LoginResponse xmlns="urn:vim25"><returnval><key>k</key>'
                '</returnval></LoginResponse>'),
                cookie=f'vmware_soap_session="s{state["logins"]}"; Path=/; '
                'HttpOnly; Secure;')
        cookie = self.headers.get("Cookie", "")
        if not cookie.startswith("vmware_soap_session="):
            return self._send(500, fault("NotAuthenticated", "not logged in"))
        if op == "CreateContainerView":
            if state["forget_once"]:
                state["forget_once"] = False
                return self._send(500, fault("NotAuthenticated",
                                             "The session is not authenticated."))
            return self._send(200, ENV.format(
                '<CreateContainerViewResponse xmlns="urn:vim25"><returnval '
                'type="ContainerView">session[52]view-1</returnval>'
                '</CreateContainerViewResponse>'))
        if op == "RetrievePropertiesEx":
            check("the property read walks the container view",
                  "<path>view</path>" in body and "session[52]view-1" in body)
            return self._send(200, ENV.format(
                '<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>'
                '<token>page-2</token>' + objects([HOST, VMS[0]])
                + '</returnval></RetrievePropertiesExResponse>'))
        if op == "ContinueRetrievePropertiesEx":
            return self._send(200, ENV.format(
                '<ContinueRetrievePropertiesExResponse xmlns="urn:vim25">'
                '<returnval>' + objects([VMS[1]])
                + '</returnval></ContinueRetrievePropertiesExResponse>'))
        if op == "DestroyView":
            return self._send(200, ENV.format(
                '<DestroyViewResponse xmlns="urn:vim25"/>'))
        self._send(500, fault("MethodNotFound", op))


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    conn = {"id": "esx1", "type": "vsphere", "name": "lab", "base_url": base,
            "username": "root", "token": PASSWORD, "skip_tls": 1}

    # 1. the host and its VMs, across two pages
    virt.invalidate()
    ok, msg = virt.test(conn)
    check(f"a standalone ESXi connects (got {msg!r})", ok)
    got = virt.read(conn)
    check("kind says ESXi", got.get("kind") == "ESXi")
    h = (got.get("hosts") or [{}])[0]
    check(f"the host is listed with its state: {h}",
          h.get("name") == "esxi01.lab" and h.get("state") == "connected")
    check(f"host CPU is used MHz over cores x MHz: {h.get('cpu_pct')}",
          h.get("cpu_pct") == 25.0 and h.get("cores") == 16)
    check(f"host memory: {h.get('mem_pct')}% of {h.get('mem_gib')}",
          h.get("mem_pct") == 25.0 and h.get("mem_gib") == 128.0)
    check(f"host uptime: {h.get('uptime')!r}", h.get("uptime") == "3d 5h")
    check("the host link is the Host Client", h.get("url") == f"{base}/ui/#/host")
    vms = {g["name"]: g for g in got.get("guests") or []}
    check(f"both VMs, including the second page: {sorted(vms)}",
          sorted(vms) == ["old-builder", "talos-cp-1"])
    on = vms.get("talos-cp-1", {})
    check(f"a running VM: {on}",
          on.get("state") == "On" and on.get("host") == "esxi01.lab"
          and on.get("cores") == 4 and on.get("cpu_pct") == 25.0
          and on.get("mem_gib") == 8.0 and on.get("mem_pct") == 25.0
          and on.get("disk_gib") == 40.0 and on.get("uptime") == "2h"
          and on.get("url") == f"{base}/ui/#/host/vms/1")
    check("running/stopped are counted",
          got.get("running") == 1 and got.get("stopped") == 1)
    check("the REST API was never asked", state["rest_types"] == [])
    check("the view is destroyed after reading", "DestroyView" in state["calls"])
    check(f"the password arrived escaped and intact: {state['passwords']}",
          state["logins"] == 1)

    # 2. the session is reused, and replaced once when the host forgets it
    virt.read(conn, refresh=True)
    check("a second read reuses the session", state["logins"] == 1)
    state["forget_once"] = True
    ok, msg = virt.test(conn)
    check(f"a forgotten session is replaced by one new login ({msg!r})",
          ok and state["logins"] == 2)

    # 3. a wrong password
    virt.invalidate()
    ok, msg = virt.test({**conn, "id": "esx2", "token": "wrong"})
    check(f"a wrong password reads as such, not HTTP 400 ({msg!r})",
          not ok and "authentication rejected" in msg and "400" not in msg)

    # 3b. the right password on an account with no role on the host
    ok, msg = virt.test({**conn, "id": "esx5", "username": "norole"})
    check(f"an account without a role is told so ({msg!r})",
          not ok and "no role on the host" in msg and "Read-only" in msg)

    # 4. a DTD in the answer is refused
    virt.invalidate()
    state["doctype"] = True
    ok, msg = virt.test({**conn, "id": "esx3"})
    state["doctype"] = False
    check(f"an answer with a DTD is refused ({msg!r})",
          not ok and "aaaaaaaaaa" not in msg)

    # 5. vCenter keeps the REST path, now with a JSON content type
    virt.invalidate()
    state["api_type"] = "VirtualCenter"
    ok, msg = virt.test({**conn, "id": "vc1"})
    got = virt.read({**conn, "id": "vc1"})
    check(f"a vCenter still reads through REST ({msg!r})",
          ok and got.get("kind") == "vSphere"
          and [g["name"] for g in got["guests"]] == ["web-1"]
          and [x["name"] for x in got["hosts"]] == ["esx-a"])
    check(f"the REST login is sent as JSON: {state['rest_types']}",
          state["rest_types"] and all("application/json" in t
                                      for t in state["rest_types"]))

    # 6. no vSphere SOAP at /sdk: the REST path, as before
    virt.invalidate()
    state["sdk_404"] = True
    ok, msg = virt.test({**conn, "id": "vc2"})
    check(f"without /sdk the REST path still answers ({msg!r})", ok)
    state["sdk_404"] = False

    # 7. an edited password is not answered from the old session
    virt.invalidate()
    state["api_type"] = "HostAgent"
    virt.test({**conn, "id": "esx4"})
    ok, msg = virt.test({**conn, "id": "esx4", "token": "wrong"})
    check(f"a changed password logs in again ({msg!r})",
          not ok and "authentication rejected" in msg)

    # 8. what the connection form says
    note = virt.PROVIDERS["vsphere"]["note"]
    check("the form explains ESXi uses /sdk", "/sdk" in note and "ESXi" in note)

    srv.shutdown()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
