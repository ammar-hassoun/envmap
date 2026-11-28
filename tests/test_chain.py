#!/usr/bin/env python3
"""What runs on each server: the chain from a server's BMC, through the
hypervisor host and its VMs, to Kubernetes nodes and their pods (app/chain.py).

Asked for on 25 November 2026. The joins are by identity, and the cases here
are the ones a real estate produced on 24 November 2026:

  1. the rules, on made-up data: a host joins its server by hardware UUID,
     else by service tag; a node joins its VM by the VM's UUID byte-swapped
     (VMware) or as printed (others); bare metal joins the server; a name
     joins only where one side has no UUID — a VM and a node that share a
     name but not a UUID are two machines (talos-worker02, seen on dev); one
     VM seen through two connections is one machine; a clue that fits two
     candidates joins nothing; a link set by hand wins, "not linked"
     included, and "automatic" undoes it
  2. the readers: ESXi reports host and VM identity in its one read, and an
     older host that does not know the serial is read without it; a vCenter's
     identity comes over SOAP; a Proxmox VM's from smbios1; a BMC's UUID
  3. the pages: the Runs here tab, the server list's Runs column, a host's
     server, a VM's node, the node tables' "runs on" line, and what a power
     button takes with it — each as far as the person may see, never naming
     a cluster or a host their roles do not open
  4. links set by hand: Settings only, both ends visible, JSON only, audited

    ./.venv/bin/python tests/test_chain.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("chain-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_esxi import FakeEsxi                                # noqa: E402
from _fake_pve import FakePve                                  # noqa: E402
from _fake_redfish import FakeRedfish                          # noqa: E402
from app import auth, bmc, chain, cluster, db, rbac, store, virt  # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Chains-Run-From-Rack-To-Pod-7"


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def swap(u: str) -> str:
    """The same UUID as a Linux kernel prints a VMware VM's: the first three
    groups byte-reversed. Written here apart from app/chain.py."""
    a, b, c, d, e = u.split("-")
    rev = lambda h: "".join(reversed([h[i:i + 2] for i in range(0, len(h), 2)]))
    return f"{rev(a)}-{rev(b)}-{rev(c)}-{d}-{e}"


def _user(email: str, areas: list[str] | None, admin: bool = False, clusters=(), projects=()) -> None:
    uid = auth.create_user(email, "Chain Tester", PW, role="admin" if admin else "user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    if areas is not None:
        rbac.set_for_user(uid, [rbac.save("", f"role-{email}", "", areas, list(projects), list(clusters))])


def _client(email: str) -> TestClient:
    c = TestClient(portal.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": PW}, follow_redirects=False)
    auth.forget_totp_use(auth.by_email(email)["id"])
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)
    return c


def audits(action: str) -> list:
    return db.q("SELECT * FROM audit WHERE action=?", (action,))


# ── 1. the rules ───────────────────────────────────────────────
U1 = "4c4c4544-0058-4b10-8032-b7c04f513134"
U2 = "4c4c4544-0031-4e10-8054-c4c04f433634"
U3 = "4c4c4544-0042-3010-8036-b3c04f4d5331"
VM1 = "564d6c2a-91f0-3b5e-a2c4-7d18e0f3b6a1"
VM3 = "4210aa3c-5b6d-4e7f-8091-a2b3c4d5e6f7"
VM4 = "564d0b1e-2c3d-4e5f-a6b7-c8d9e0f1a2b3"
VMX = "564de894-5141-35eb-304e-b456f9b5766e"
VMP = "6f1d9c2e-4b7a-4e3d-9a51-2c8e7f40b113"
VM7 = "564d7777-1a2b-3c4d-5e6f-7a8b9c0d1e2f"
VM8 = "564d8888-1a2b-3c4d-5e6f-7a8b9c0d1e2f"
U6 = "4c4c4544-0036-3610-8036-b6c04f363636"
OTHER = "4232a84f-b755-1e80-5355-30f2f50cf9fc"


def _parts() -> tuple:
    bmcs = [{"id": f"b{i}", "name": f"srv-{i}", "pid": ""} for i in range(1, 8)]
    virts = [{"id": "v1", "name": "esx-1", "pid": ""}, {"id": "v2", "name": "vc", "pid": ""},
             {"id": "v3", "name": "pve", "pid": ""}, {"id": "v4", "name": "esx-dup", "pid": ""},
             {"id": "v5", "name": "esx-5", "pid": ""}]

    def server(uuid, sku, host=""):
        return {"uuid": uuid, "sku": sku, "serial": "CN" + sku if sku else "", "hostname": host,
                "power": "On", "health": "OK", "ok": True, "vendor": "Dell Inc.", "model": "PowerEdge R650"}

    def guest(i, name, uuid="", host="localhost.localdomain", state="On", kind="VM"):
        return {"id": i, "name": name, "host": host, "state": state, "kind": kind, "uuid": uuid}
    parts = {
        "bmc:b1": server(U1, "7XK2Q14"), "bmc:b2": server(U2, "ABC1234"),
        "bmc:b3": server(U3, "", "metal-03"),
        "bmc:b4": server("", "DUP0001"), "bmc:b5": server("", "DUP0001"),
        # one iDRAC added twice: one machine
        "bmc:b6": server(U6, "SIX6666"), "bmc:b7": server(U6, "SIX6666"),
        "virt:v5": {"data": {"kind": "ESXi", "hosts": [{"name": "esx-5", "uuid": U6, "serial": "SIX6666"}],
                             "guests": []}, "ident": {}},
        "virt:v1": {"data": {"kind": "ESXi", "hosts": [
            {"name": "localhost.localdomain", "uuid": U1, "serial": "7XK2Q14", "state": "connected"}],
            "guests": [guest("1", "web-01", VM1), guest("2", "talos-worker02.dev.example.com", VMX),
                       guest("3", "db-01", VM3), guest("4", "twin", VM4),
                       guest("5", "noid-01", "564d0000-1111-2222-3333-444455556666"),
                       guest("6", "stopped-01", "", state="Off"),
                       guest("7", "claimed-twice", VM7),
                       guest("8", "copy-on", VM8), guest("9", "copy-off", VM8, state="Off"),
                       guest("10", "k8s-master", "")]}, "ident": {}},
        "virt:v2": {"data": {"kind": "vSphere", "hosts": [{"name": "esx-2.example.com", "state": "CONNECTED"}],
                             "guests": [guest("vm-9", "twin", "", host="")]},
                    "ident": {"hosts": {"esx-2.example.com": {"uuid": "", "serial": "ABC1234"}},
                              "vms": {"vm-9": {"uuid": VM4, "host": "esx-2.example.com"}}}},
        "virt:v3": {"data": {"kind": "Proxmox", "hosts": [{"name": "pve-01", "state": "online"}],
                             "guests": [guest("100", "app-01", "", host="pve-01", state="running")]},
                    "ident": {"hosts": {}, "vms": {"100": {"uuid": VMP}}}},
        "virt:v4": {"data": {"kind": "ESXi", "hosts": [{"name": "esx-dup", "uuid": "", "serial": "DUP0001"}],
                             "guests": []}, "ident": {}},
        "nodes": [{"pid": "", "project": "Acme", "cid": "c1", "cluster": "prod", "nodes": [
            {"name": "k8s-w1", "ready": True, "uuid": swap(VM1), "ips": ["10.0.0.11"]},
            {"name": "k8s-cp", "ready": True, "uuid": VM3, "roles": ["control-plane"]},
            {"name": "talos-worker02", "ready": True, "uuid": OTHER},
            {"name": "metal-03", "ready": True, "uuid": U3},
            {"name": "twin-node", "ready": False, "uuid": swap(VM4)},
            {"name": "app-01", "ready": True, "uuid": VMP},
            {"name": "noid-01", "ready": True, "uuid": ""},
            {"name": "k8s-w1-old", "ready": False, "uuid": swap(VM1)},
            {"name": "dup-a", "ready": True, "uuid": swap(VM7)},
            {"name": "copy-node", "ready": True, "uuid": swap(VM8)},
            {"name": "k8s-master", "ready": True, "uuid": ""}]},
                  {"pid": "", "project": "Acme", "cid": "c2", "cluster": "other", "nodes": [
            {"name": "dup-b", "ready": True, "uuid": swap(VM7)},
            {"name": "k8s-master", "ready": True, "uuid": ""}]}],
        "pods": [{"cid": "c1", "pods": [{"node": "k8s-w1", "problem": ""}] * 3
                  + [{"node": "k8s-w1", "problem": "CrashLoopBackOff"}]}],
    }
    return parts, bmcs, virts


def test_rules() -> None:
    parts, bmcs, virts = _parts()
    g = chain._join(parts, [], bmcs, virts)
    hs, how = g["host_servers"], g["host_how"]
    check(f"a host joins its server by hardware UUID: {hs['v1|localhost.localdomain']}",
          hs["v1|localhost.localdomain"] == ["b1"] and how["v1|localhost.localdomain"] == "hardware UUID")
    check(f"a vCenter host with no UUID joins by service tag: {hs['v2|esx-2.example.com']}",
          hs["v2|esx-2.example.com"] == ["b2"] and how["v2|esx-2.example.com"] == "service tag")
    check(f"a service tag on two servers joins nothing: {how['v4|esx-dup']}",
          not hs["v4|esx-dup"] and "more than one" in how["v4|esx-dup"])
    check("a Proxmox node with no identity is not guessed", not hs["v3|pve-01"])
    check("a standalone ESXi host called localhost is labelled by its connection",
          g["hosts"]["v1|localhost.localdomain"]["label"] == "esx-1")
    check(f"one BMC added twice is one server: {hs.get('v5|esx-5')}", sorted(hs.get("v5|esx-5") or []) == ["b6", "b7"])
    check("a vCenter VM sits on its host by the identity read (the REST list does not say)",
          "v2|vm-9" in g["hosts"]["v2|esx-2.example.com"]["vms"])
    vn, vh = g["vm_node"], g["vm_how"]
    check(f"a VMware VM is its node by the byte-swapped UUID: {vn.get('v1|1')}",
          vn.get("v1|1") == "c1|k8s-w1" and vh["v1|1"] == "hardware UUID")
    check("and a NotReady node object with the same UUID is named, not chosen",
          "not Ready" in g["notes"].get("v1|1", ""))
    check("another VM is its node by the UUID as printed", vn.get("v1|3") == "c1|k8s-cp")
    check(f"a name shared by two machines with different UUIDs joins nothing: {vn.get('v1|2')}",
          vn.get("v1|2") != "c1|talos-worker02")
    check(f"one VM seen through two connections is one machine: {g['node_vms'].get('c1|twin-node')}",
          sorted(g["node_vms"].get("c1|twin-node") or []) == ["v1|4", "v2|vm-9"])
    check("a Proxmox VM is its node by smbios1", vn.get("v3|100") == "c1|app-01")
    check(f"a node with no UUID joins a VM of its name: {vn.get('v1|5')}", vn.get("v1|5") == "c1|noid-01" and vh["v1|5"] == "name")
    check(f"two Ready nodes claiming one VM: neither, and both are named: {g['doubt'].get('v1|7')}",
          "v1|7" not in vn and sorted(g["doubt"].get("v1|7") or []) == ["c1|dup-a", "c2|dup-b"])
    check(f"two copies of a VM on one connection, one running: the running one: {vn.get('v1|8')} {vn.get('v1|9')}",
          vn.get("v1|8") == "c1|copy-node" and "v1|9" not in vn)
    check(f"two VMs and two nodes all called k8s-master join nothing, whatever the order: {vn.get('v1|10')}",
          "v1|10" not in vn and not any(g["node_vms"].get(k) for k in ("c1|k8s-master", "c2|k8s-master")))
    check("bare metal: a node reporting the server's own UUID sits on the server",
          g["server_nodes"].get("b3") == ["c1|metal-03"])
    check("pods are counted on their node, the unhealthy apart",
          g["nodes"]["c1|k8s-w1"]["pods"] == 4 and g["nodes"]["c1|k8s-w1"]["bad"] == 1)
    check("placeholder UUIDs identify nothing",
          not chain.uuid_keys("03000200-0400-0500-0006-000700080009")
          and not chain.uuid_keys("00000000-0000-0000-0000-000000000000"))
    check("a vSphere providerID is a UUID", chain.uuid_keys("vsphere://" + VM1) == chain.uuid_keys(VM1))
    # the same order, reversed, gives the same answer
    rev = dict(parts)
    rev["nodes"] = [{**grp, "nodes": list(reversed(grp["nodes"]))} for grp in reversed(parts["nodes"])]
    g2 = chain._join(rev, [], list(reversed(bmcs)), list(reversed(virts)))
    check("nothing depends on the order things are read in",
          g2["vm_node"] == g["vm_node"] and sorted(g2["doubt"]) == sorted(g["doubt"])
          and {k: sorted(v) for k, v in g2["host_servers"].items()}
          == {k: sorted(v) for k, v in g["host_servers"].items()})
    # one machine counted once
    _user("rules@chain.test", None, admin=True)
    adm = auth.by_email("rules@chain.test")
    v = chain.for_server(adm, "b1", g=g)
    check(f"a server's totals count each machine once: {v['totals']}", v["totals"]["vms"] == len(
        {chain._machine(g["vms"][k]) for k in g["hosts"]["v1|localhost.localdomain"]["vms"]}))
    check("a host page with a wrong node name shows nothing, not another host's server",
          chain._host_key(g, "v3", "not-a-node") == "" and chain._host_key(g, "v1", "") == "v1|localhost.localdomain")

    # links set by hand
    store.set_estate_link("hosts", "v3|pve-01", "b2")
    store.set_estate_link("hosts", "v1|localhost.localdomain", "")
    store.set_estate_link("vms", "v1|2", {"to": "c1|talos-worker02", "fp": min(chain.uuid_keys(VMX))})
    g = chain._join(parts, [], bmcs, virts)
    check("a host linked by hand", g["host_servers"]["v3|pve-01"] == ["b2"] and g["host_how"]["v3|pve-01"] == "set by hand")
    check("'not linked' wins over a matching UUID", not g["host_servers"]["v1|localhost.localdomain"])
    check("a VM linked to a node by hand", g["vm_node"].get("v1|2") == "c1|talos-worker02" and g["vm_how"]["v1|2"] == "set by hand")
    store.set_estate_link("vms", "v1|2", {"to": "c1|talos-worker02", "fp": "0" * 31 + "1"})
    g = chain._join(parts, [], bmcs, virts)
    check(f"a link set for another machine behind the same id stops applying: {g['notes'].get('v1|2')}",
          g["vm_node"].get("v1|2") != "c1|talos-worker02" and "no longer applies" in g["notes"].get("v1|2", ""))
    store.set_estate_link("hosts", "v3|pve-01", "gone")
    g = chain._join(parts, [], bmcs, virts)
    check(f"a link to a server that is gone says so: {g['host_how']['v3|pve-01']}",
          g["host_how"]["v3|pve-01"] == "set by hand to a server that is gone")
    for kind, key in (("hosts", "v3|pve-01"), ("hosts", "v1|localhost.localdomain"), ("vms", "v1|2")):
        store.set_estate_link(kind, key, None)
    g = chain._join(parts, [], bmcs, virts)
    check("'automatic' undoes every link set by hand",
          g["host_servers"]["v1|localhost.localdomain"] == ["b1"]
          and not g["host_servers"]["v3|pve-01"] and g["vm_node"].get("v1|2") != "c1|talos-worker02")


# ── 2. the readers ─────────────────────────────────────────────
def test_why_empty() -> None:
    """The words in an empty Runs cell, one per cause."""
    _user("why@chain.test", None, admin=True)
    me = auth.by_email("why@chain.test")
    g = {"servers": {"unread": {"pid": "", "read": False}, "read": {"pid": "", "read": True}},
         "server_hosts": {}, "hosts": {}, "vms": {}, "vm_node": {}, "server_nodes": {}}
    real = virt.store_all
    try:
        virt.store_all = lambda: []
        w = chain.why_empty(me, g)
        check(f"nothing connected, and a BMC not read: {w}",
              {k: v["text"] for k, v in w.items()}
              == {"unread": "BMC not read yet", "read": "no hypervisor connected"}
              and not any(v["os"] for v in w.values()))
        virt.store_all = lambda: [{"id": "v1", "pid": ""}]
        w = chain.why_empty(me, g)
        check(f"a hypervisor connected that this server is not on: {w}",
              w.get("read", {}).get("text") == "no hypervisor matches")
        g3 = {**g, "servers": {
            "ubu": {"pid": "", "read": True, "os": "Ubuntu 22.04.4 LTS", "hostname": "app-node-05",
                    "os_hypervisor": False},
            "esx": {"pid": "", "read": True, "os": "ESXi 7.0 U3", "hostname": "esx9",
                    "os_hypervisor": True}}}
        w = chain.why_empty(me, g3)
        check(f"an OS the BMC reports comes before any reason, with its host name: {w.get('ubu')}",
              w.get("ubu") == {"text": "Ubuntu 22.04.4 LTS", "sub": "app-node-05", "os": True})
        check(f"a hypervisor OS that is not connected says so: {w.get('esx')}",
              w.get("esx") == {"text": "ESXi 7.0 U3", "sub": "not connected", "os": True})
        check("a server with something under it shows its summary, not its OS",
              "ubu" not in chain.why_empty(me, {**g3, "server_nodes": {"ubu": ["c|n1"]}}))
        g2 = {**g, "server_nodes": {"read": ["c|n1"]}}
        check("a server with something under it has no reason, only its summary",
              "read" not in chain.why_empty(me, g2))
        _user("nobmc@chain.test", ["virt"])
        check("a server the person may not open is not described",
              chain.why_empty(auth.by_email("nobmc@chain.test"), g) == {})
    finally:
        virt.store_all = real


def test_os_words() -> None:
    """The OS label: the name and the release, never the kernel or build."""
    for name, version, want in (
            ("Ubuntu", "22.04.4 LTS (Jammy Jellyfish) Kernel 5.15.0-91-generic", "Ubuntu 22.04.4 LTS"),
            ("Red Hat Enterprise Linux", "Version 8.6 (Ootpa) (x86_64)", "Red Hat Enterprise Linux 8.6"),
            ("VMware ESXi", "7.0.3 build-21424296", "ESXi 7.0 U3"),
            ("VMware ESXi", "8.0 Update 3 build-25595708", "ESXi 8.0 U3"),
            ("VMware ESXi", "8.0.3 25595708 U3 P102", "ESXi 8.0 U3"),
            ("VMware ESXi", "8.0.2 22380479 U2", "ESXi 8.0 U2"),
            ("DellEMC-VMware ESXi", "7.0 Update 2 Build-18538813 (A07)", "ESXi 7.0 U2"),
            ("Dell-VMware ESXi", "8.0 Update 2 Build-22380479 (A00)", "ESXi 8.0 U2"),
            ("VMware ESXi", "8.0.0 20513097", "ESXi 8.0"),
            ("VMware ESXi 8.0.2", "", "ESXi 8.0 U2"),
            ("VMware ESXi 7.0 Update 3", "", "ESXi 7.0 U3"),
            ("Ubuntu 22.04.1 LTS", "22.04.1 LTS", "Ubuntu 22.04.1 LTS"),
            ("Rocky Linux", "", "Rocky Linux"),
            ("", "22.04", ""),
            ("Bad\x1b[31mName\nhere", "1.0", "Bad [31mName here 1.0")):
        got = bmc.os_label(name, version)
        check(f"os_label({name!r}, {version!r}) = {got!r}", got == want)
    check("ESXi and Proxmox are hypervisors EnvMap can connect, Ubuntu is not",
          bmc.is_hypervisor_os("VMware ESXi 8.0") and bmc.is_hypervisor_os("Proxmox VE 8.2")
          and not bmc.is_hypervisor_os("Ubuntu 22.04"))
    check("each vendor names its own BMC and agent",
          bmc.agent("Dell")[0] == "iDRAC" and "iDRAC Service Module" in bmc.agent("Dell")[1]
          and bmc.agent("HPE")[0] == "iLO" and "Agentless Management" in bmc.agent("HPE")[1]
          and bmc.agent("Supermicro") == ("BMC", ""))
    got = bmc._hpe_os({"Oem": {"Hpe": {"HostOS": {"OsName": "Ubuntu 22.04.1 LTS",
                                                  "OsVersion": "5.15.0-56-generic"}}}})
    check(f"an iLO's OS comes from its system's HostOS: {got}",
          got.get("label") == "Ubuntu 22.04.1 LTS" and got.get("version") == "5.15.0-56-generic")
    check("an iLO without its agent reports none", bmc._hpe_os({"Oem": {"Hpe": {}}}) == {})
    got = bmc._hpe_os({"Oem": {"Hpe": {"HostOS": {"OsName": "VMware ESXi 8.0.2", "OsVersion": "8.0.2"}}}})
    check(f"and an iLO's ESXi reads like an iDRAC's: {got.get('label')}", got.get("label") == "ESXi 8.0 U2")


def test_os_reads(ubu_c: dict, esx_os_c: dict, bare_c: dict, ubu: FakeRedfish) -> None:
    """What the iDRAC Service Module told the iDRAC, read from it."""
    b = bmc.read(ubu_c, refresh=True, detail=False)
    check(f"an iDRAC with iSM reports the OS and its host name: {b.get('os')} {b.get('hostname')}",
          b.get("os") == "Ubuntu 22.04.4 LTS" and b.get("hostname") == "app-node-05"
          and b.get("os_name") == "Ubuntu" and "Jammy" in b.get("os_version", ""))
    attrs = "/redfish/v1/Managers/System.Embedded.1/Attributes"
    asked = sum(1 for c in ubu.calls if c[1] == attrs)
    bmc._cache.clear()
    bmc.read(ubu_c, detail=False)
    check("the OS is not asked again within half an hour",
          sum(1 for c in ubu.calls if c[1] == attrs) == asked)
    was = ubu.os["ServerOS.1.OSVersion"]
    ubu.os["ServerOS.1.OSVersion"] = "24.04.1 LTS (Noble Numbat) Kernel 6.8.0-45-generic"
    b = bmc.read(ubu_c, refresh=True, detail=False)
    check(f"Refresh reads it again: {b.get('os')}", b.get("os") == "Ubuntu 24.04.1 LTS")
    ubu.os["ServerOS.1.OSVersion"] = was
    bmc.read(ubu_c, refresh=True, detail=False)
    b = bmc.read(esx_os_c, refresh=True, detail=False)
    check(f"an iDRAC before 4.x answers at the Dell OEM place: {b.get('os')}",
          b.get("os") == "ESXi 7.0 U3")
    b = bmc.read(bare_c, refresh=True, detail=False)
    check(f"an iDRAC without iSM reports no OS, and the read still works: {b.get('os')!r}",
          b.get("os") == "" and b.get("model") == "PowerEdge R650")


def test_readers(esx_c: dict, old_c: dict, vc_c: dict, pve_c: dict, bmc_c: dict) -> None:
    got = virt.read(esx_c, refresh=True)
    h = got["hosts"][0]
    check(f"ESXi reports its box's UUID and service tag: {h.get('uuid')} {h.get('serial')}",
          h.get("uuid") == FakeEsxi.HOST_UUID and h.get("serial") == FakeEsxi.HOST_SERIAL
          and h.get("model") == "PowerEdge R650")
    check("and each VM its own UUID", all(len(g.get("uuid") or "") == 36 for g in got["guests"]))
    got = virt.read(old_c, refresh=True)
    check(f"an older host is read without what it does not know ({len(got['guests'])} VMs)",
          got["guests"] and not got["hosts"][0].get("uuid"))
    check("and is not asked again", virt._who(old_c) in virt._NO_ID)
    ids = virt.identities(vc_c)
    check(f"a vCenter's identity comes over SOAP: {sorted(ids['hosts'])}",
          ids["hosts"] and next(iter(ids["hosts"].values()))["uuid"] == "4c4c4544-0032-3910-8033-c2c04f564331"
          and ids["vms"].get("1", {}).get("uuid"))
    ids = virt.identities(pve_c)
    check(f"a Proxmox VM's UUID comes from smbios1: {ids['vms'].get(100) or ids['vms'].get('100')}",
          (ids["vms"].get(100) or ids["vms"].get("100") or {}).get("uuid") == VMP)
    b = bmc.read(bmc_c, refresh=True)
    check(f"a BMC reports its system's UUID: {b.get('uuid')}", b.get("uuid") == FakeEsxi.HOST_UUID)


# ── 3 and 4. pages, impact, permissions, links ─────────────────
def test_pages(esx: FakeEsxi, esx_c: dict, old_c: dict, bmc_c: dict, bmc2_c: dict,
               ubu_c: dict, esx_os_c: dict) -> None:
    W1 = esx.vms["1"]["uuid"]
    W2 = esx.vms["2"]["uuid"]
    nodes = [{"pid": "", "project": "Acme", "cid": "c-prod", "cluster": "prod-k8s", "error": "", "nodes": [
        {"name": "k8s-web", "ready": True, "roles": ["worker"], "ip": "10.0.0.31", "uuid": swap(W1),
         "provider_id": "", "ips": ["10.0.0.31"], "hostname": "k8s-web", "schedulable": True,
         "pressure": [], "version": "v1.31.4", "os": "Talos", "runtime": "containerd", "taints": [],
         "cpu_cap": 4000, "mem_cap": 8192, "cpu_use": None, "mem_use": None, "age": "12d", "kernel": "6.6"},
        {"name": "k8s-db", "ready": False, "roles": ["worker"], "ip": "10.0.0.32", "uuid": W2,
         "provider_id": "", "ips": ["10.0.0.32"], "hostname": "k8s-db", "schedulable": True,
         "pressure": [], "version": "v1.31.4", "os": "Talos", "runtime": "containerd", "taints": [],
         "cpu_cap": 4000, "mem_cap": 8192, "cpu_use": None, "mem_use": None, "age": "12d", "kernel": "6.6"}]}]
    pods = [{"pid": "", "project": "Acme", "cid": "c-prod", "cluster": "prod-k8s", "error": "",
             "pods": [{"node": "k8s-web", "problem": ""}] * 5 + [{"node": "k8s-db", "problem": "Pending"}]}]
    real_everywhere = cluster.everywhere
    cluster.everywhere = lambda part, refresh=False: nodes if part == "nodes" else pods
    chain.invalidate()
    try:
        _user("admin@chain.test", None, admin=True)
        _user("ops@chain.test", ["bmc", "bmc_power", "virt", "virt_power"])
        _user("hw@chain.test", ["bmc"])
        _user("linker@chain.test", ["bmc", "virt", "clusters", "settings"])
        adm, ops, hw, lnk = (_client(e) for e in ("admin@chain.test", "ops@chain.test",
                                                    "hw@chain.test", "linker@chain.test"))
        S, S2, E, O = bmc_c["id"], bmc2_c["id"], esx_c["id"], old_c["id"]
        S3, S4 = ubu_c["id"], esx_os_c["id"]
        import re as _re_os

        r = adm.get(f"/bmc?device={S}&sec=runs")
        check(f"the Runs here tab answers ({r.status_code})", r.status_code == 200 and "Runs here" in r.text)
        check("it shows the host, linked by hardware UUID",
              "esx-lab-01.example.internal" in r.text and "linked by hardware UUID" in r.text)
        check("the VMs that are nodes, with their node, cluster and pods",
              "k8s-web" in r.text and "prod-k8s" in r.text and "web-01" in r.text and "NotReady" in r.text)
        import re as _re
        if os.environ.get("CHAIN_DEBUG"):
            print("FLOW", _re.findall(r'<div class="n"[^>]*>([^<]*)', r.text))
        flow = _re.findall(r'<div class="n"[^>]*>([^<]*)', r.text)
        check(f"the flow strip: server, 1 host, 5 VMs, 2 nodes, 6 pods: {flow}",
              [f.strip() for f in flow] == ["r650-lab", "1", "5", "2", "6"])
        check("the other VMs fold away", "other virtual machine" in r.text)
        r = adm.get(f"/bmc?device={S2}&sec=runs")
        check("a server with nothing found says why, with its identity",
              "Nothing is linked to this server yet" in r.text and "FAKEOLD" in r.text)
        check("and that its iDRAC reports no OS either, and what would make it",
              "The iDRAC does not report an operating system either: it does once the iDRAC "
              "Service Module (iSM) runs on the host." in r.text)
        r = adm.get(f"/bmc?device={S3}&sec=runs")
        check("a server whose iDRAC reports an OS names it on its Runs here tab",
              "Ubuntu 22.04.4 LTS runs on this server" in r.text
              and "with the host name <b>app-node-05</b>" in r.text
              and "If it is a Kubernetes node, connect its cluster" in r.text
              and "Nothing is linked to this server yet" not in r.text
              and "does not report an operating system" not in r.text)
        r = adm.get(f"/bmc?device={S4}&sec=runs")
        check("an ESXi that is not connected is pointed at Settings → Hypervisors",
              "ESXi 7.0 U3 runs on this server" in r.text
              and "To see its virtual machines here, connect it in Settings → Hypervisors." in r.text)
        r = adm.get(f"/bmc?device={S3}")
        check("the Overview's identity names the OS and who reported it",
              _re_os.search(r'operating system</td><td>Ubuntu 22\.04\.4 LTS\s*<span class="os-by"[^>]*>· reported by the iDRAC</span>', r.text)
              and "· Ubuntu 22.04.4 LTS" in r.text)
        r = adm.get(f"/bmc?device={S2}")
        check("and says how to get one where the iDRAC has none",
              "the iDRAC does not report one; it does once the iDRAC Service Module (iSM) runs on the host" in r.text)
        chain.graph()
        r = adm.get("/bmc")
        if os.environ.get("CHAIN_DEBUG"):
            print("RUNS", _re.findall(r'sec=runs">([^<]*)', r.text))
        check(f"the server list's Runs column: {'ESXi · ' in r.text}",
              "ESXi · 5 VMs · 2 nodes" in r.text and f"device={S}&sec=runs" in r.text)
        import re as _re3
        check("a server with nothing linked says why in its Runs cell, and the cell opens its tab",
              _re3.search(r'<a class="runs-why"[^>]*href="/bmc\?device=' + S2
                          + r'&sec=runs">no hypervisor matches</a>', r.text))
        check("a server whose iDRAC reports an OS shows it in the cell, with its host name under it",
              _re3.search(r'<a class="runs-os" href="/bmc\?device=' + S3
                          + r'&sec=runs"\s+title="[^"]*"[^>]*>Ubuntu 22\.04\.4 LTS</a><div class="runs-sub"[^>]*>app-node-05</div>',
                          r.text))
        check("an ESXi the iDRAC reports, not connected, says so under it",
              _re3.search(r'href="/bmc\?device=' + S4 + r'&sec=runs"\s+title="[^"]*"[^>]*>ESXi 7\.0 U3</a>'
                          r'<div class="runs-sub"[^>]*>not connected</div>', r.text))
        r = adm.get(f"/bmc?device={S}")
        check("the Overview carries one line of it", "See what runs here" in r.text)

        j = adm.get(f"/bmc/impact?c={S}").json()
        check(f"powering the server off names what goes with it: {j.get('text')}",
              j.get("ok") and "esx-lab-01.example.internal" in j["text"] and "running VM" in j["text"]
              and "prod-k8s: 2" in j["text"] and "6 pods" in j["text"])
        j = adm.get(f"/virt/impact?c={E}").json()
        check(f"so does rebooting the host: {j.get('text')}", "of them 2 Kubernetes nodes" in j.get("text", ""))
        j = adm.get(f"/virt/impact?c={E}&vm=1").json()
        check(f"and stopping a VM that is a node: {j.get('text')}",
              "Kubernetes node k8s-web of prod-k8s" in j.get("text", "") and "5 pods" in j.get("text", ""))
        j = adm.get(f"/virt/impact?c={E}&vm=3").json()
        check("a VM that is no node warns of nothing", j.get("ok") and j.get("text") == "")
        r = adm.get(f"/bmc?device={S}")
        check("the power buttons ask for it at the click",
              f'data-impact="/bmc/impact?c={S}"' in r.text)

        r = adm.get(f"/virt/vm?c={E}&vm=1")
        check("a VM's page names its node and its server",
              "Kubernetes node" in r.text and "k8s-web" in r.text and bmc_c["name"] in r.text
              and f"/virt/impact?c={E}&amp;vm=1" in r.text)
        import re as _re2
        check("each VM power button asks for it at the click, with a working address",
              _re2.search(r'data-act="vm\.stop"[^>]*data-impact="/virt/impact\?c=' + E + r'&amp;vm=1"', r.text)
              and "&amp;#34;" not in r.text)
        r = adm.get(f"/virt/host?c={E}")
        check("a host's page names its physical server",
              "Physical server" in r.text and bmc_c["name"] in r.text and "2 of its VMs are Kubernetes nodes" in r.text)
        r = adm.get("/nodes")
        check("the fleet's node table says where each node runs",
              r.status_code == 200 and "web-01" in r.text and bmc_c["name"] in r.text)

        # ── what each person may see ──
        r = ops.get(f"/bmc?device={S}&sec=runs")
        check("without Clusters: that a VM is a node, never which",
              "a node in a cluster your roles do not open" in r.text and "prod-k8s" not in r.text
              and "k8s-web" not in r.text)
        j = ops.get(f"/bmc/impact?c={S}").json()
        check(f"and the warning counts it without naming it: {j.get('text')}",
              "in clusters you cannot open" in j.get("text", "") and "prod-k8s" not in j.get("text", ""))
        check("no link forms without Settings", 'data-link="/bmc/link"' not in r.text)
        r = hw.get(f"/bmc?device={S}&sec=runs")
        check("without Hypervisors: the host is counted, not named",
              "esx-lab-01" not in r.text and "hypervisor host on this" in r.text)
        r = hw.get(f"/virt/impact?c={E}")
        check(f"and the hypervisor routes stay closed ({r.status_code})", r.status_code in (302, 303, 403))

        # ── "still reading" names only what the person may see ──
        hidden_p = store.add_project("Hidden")
        secret = store.add_bmc(hidden_p, {"type": "redfish", "name": "secret-bmc", "base_url": "https://10.9.9.9",
                                          "username": "x", "token": "y", "skip_tls": "1"})
        open_p = store.add_project("Open")
        _user("scoped@chain.test", ["bmc"], projects=[open_p])
        lens = chain._Lens(auth.by_email("scoped@chain.test"))
        src = chain._sources({"pending": [f"bmc:{secret}"], "late": [("c-x", "secret-cluster")],
                              "failed": {f"bmc:{secret}": "timeout"}}, lens)
        check(f"what is still being read is named only where it may be seen: {src}",
              not src["pending"] and not src["failed"] and src["hidden"] == 3)
        store.delete_bmc(hidden_p, secret)

        # ── links set by hand ──
        old_key = f"{O}|esx-lab-02.example.internal"
        r = ops.post("/bmc/link", json={"server": S2, "host": old_key, "action": "link"})
        check(f"linking needs Settings ({r.status_code})", r.status_code == 403 and audits("estate_link_refused"))
        r = lnk.post("/bmc/link", content=b'{"action": "link"}', headers={"Content-Type": "text/plain"})
        check("and a JSON body", r.status_code == 415)
        r = lnk.post("/bmc/link", json={"server": "nope", "host": old_key, "action": "link"})
        check("both ends must exist", r.status_code == 403)
        r = lnk.get(f"/bmc?device={S2}&sec=runs")
        check("the server page offers the unlinked host", 'data-link="/bmc/link"' in r.text and old_key in r.text)
        j = lnk.post("/bmc/link", json={"server": S2, "host": old_key, "action": "link"}).json()
        check(f"an older host linked by hand: {j}", j.get("ok") and audits("estate_link_set"))
        r = lnk.get(f"/bmc?device={S2}&sec=runs")
        check("and shown under its server", "esx-lab-02.example.internal" in r.text and "set by hand" in r.text
              and "linked by set by hand" not in r.text)
        j = lnk.post("/bmc/link", json={"host": old_key, "action": "auto"}).json()
        check("back to automatic", j.get("ok") and audits("estate_link_cleared")
              and not chain.graph()["host_servers"][old_key])
        j = lnk.post("/virt/link", json={"vm": f"{E}|3", "node": "c-prod|k8s-db", "action": "link"}).json()
        check(f"a VM linked to a node by hand: {j}", j.get("ok") and "is the node k8s-db" in j.get("said", ""))
        r = lnk.post("/virt/link", json={"vm": f"{E}|3", "node": "c-prod|k8s-db", "action": "link"},
                     headers={"Origin": "https://evil.example"})
        check("not from another site", r.status_code == 403)
        lnk.post("/virt/link", json={"vm": f"{E}|3", "action": "auto"})
        for c in (adm, ops, hw, lnk):
            c.__exit__(None, None, None)
    finally:
        cluster.everywhere = real_everywhere


def main() -> int:
    esx = FakeEsxi().start()
    old = FakeEsxi(name="esx-lab-02.example.internal", uuid="4c4c4544-0037-4b10-8047-c4c04f343134",
                   serial="FAKEOLD", old=True).start()
    vc = FakeEsxi(name="esx-vc-01.example.internal", uuid="4c4c4544-0032-3910-8033-c2c04f564331",
                  serial="VC12345", api_type="VirtualCenter").start()
    pve = FakePve().start()
    rf = FakeRedfish(model="PowerEdge R650", serial=FakeEsxi.HOST_SERIAL, uuid=FakeEsxi.HOST_UUID).start()
    rf2 = FakeRedfish(model="PowerEdge R650", serial="FAKEOLD", uuid="").start()
    rf3 = FakeRedfish(model="PowerEdge R660xs", serial="FAKEUBU", uuid="4c4c4544-0055-4210-8042-c2c04f555555",
                      os_name="Ubuntu", os_version="22.04.4 LTS (Jammy Jellyfish) Kernel 5.15.0-91-generic",
                      os_host="app-node-05").start()
    rf4 = FakeRedfish(model="PowerEdge R740", serial="FAKEESX", uuid="4c4c4544-0056-4310-8043-c3c04f666666",
                      os_name="VMware ESXi", os_version="7.0.3 build-21424296", os_host="esx-9",
                      os_path="oem").start()
    try:
        test_rules()
        test_why_empty()
        test_os_words()
        esx_c = {"type": "vsphere", "name": "lab-esxi", "base_url": esx.url, "username": "root",
                 "token": "lab-password", "skip_tls": "1"}
        old_c = {**esx_c, "name": "old-esxi", "base_url": old.url}
        vc_c = {**esx_c, "name": "lab-vcenter", "base_url": vc.url}
        pve_c = {"type": "proxmox", "name": "pve-lab", "base_url": pve.url,
                 "username": "root@pam!envmap", "token": "pve-token-secret", "skip_tls": "1"}
        for c in (esx_c, old_c, pve_c):
            c["id"] = store.add_virt("", dict(c))
        vc_c["id"] = "vc-not-stored"
        bmc_c = {"type": "redfish", "name": "r650-lab", "base_url": rf.url, "username": "root",
                 "token": "calvin", "skip_tls": "1"}
        bmc2_c = {**bmc_c, "name": "r650-old", "base_url": rf2.url}
        ubu_c = {**bmc_c, "name": "r660-ubuntu", "base_url": rf3.url}
        esx_os_c = {**bmc_c, "name": "r740-esxi", "base_url": rf4.url}
        for c in (bmc_c, bmc2_c, ubu_c, esx_os_c):
            c["id"] = store.add_bmc("", dict(c))
        test_os_reads(store.get_bmc("", ubu_c["id"]), store.get_bmc("", esx_os_c["id"]),
                      store.get_bmc("", bmc2_c["id"]), rf3)
        test_readers(store.get_virt("", esx_c["id"]), store.get_virt("", old_c["id"]), vc_c,
                     store.get_virt("", pve_c["id"]), store.get_bmc("", bmc_c["id"]))
        # the vCenter and Proxmox fakes are left out of the pages: they serve
        # no REST list here, and the pages are about one host and its VMs
        store.delete_virt("", pve_c["id"])
        virt.invalidate()
        bmc.invalidate()
        test_pages(esx, esx_c, old_c, bmc_c, bmc2_c, ubu_c, esx_os_c)
    finally:
        for f in (esx, old, vc, pve, rf, rf2, rf3, rf4):
            f.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
