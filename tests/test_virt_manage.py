#!/usr/bin/env python3
"""Managing ESXi and Proxmox from the Hypervisors pages: every action, every
gate, the audit, the pages, uploads and the console relay.

Asked for on 24 November 2026: "fully manage the ESXi host and the VMs and
open their consoles, all from inside EnvMap". This walks the whole surface
against two fakes that keep state (tests/_fake_esxi.py, tests/_fake_pve.py):

  1. the action table is complete: every action has an area and an audit
     name, and the three new areas escalate and are not answerable
  2. every ESXi action runs and changes the fake host as it should
  3. every Proxmox action runs and sends what the Proxmox API documents
  4. the gates: a connection that does not allow management refuses
     everything; a reader may look but not act; power and console without
     administer; administer includes both; production wants the VM's own name
     (the hypervisor's, not the page's); every refusal is audited
  5. the pages render for both engines, with buttons disabled and saying why
     for somebody who may not use them
  6. an upload reaches the datastore / storage
  7. the console: a one-time session bound to its owner, relayed RFB, and
     Zlib taken out of the client's encodings (it stalls a real ESXi)
  8. ticking management on a connection is audited

    ./.venv/bin/python tests/test_virt_manage.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import struct
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("virt-manage-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_esxi import FakeEsxi                                # noqa: E402
from _fake_pve import FakePve                                  # noqa: E402
from app import answers, auth, db, rbac, store, virt, virtops   # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Hypervisors-Are-Managed-42"


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _user(email: str, areas: list[str] | None, admin: bool = False) -> None:
    uid = auth.create_user(email, "Virt Tester", PW, role="admin" if admin else "user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    if areas is not None:
        rbac.set_for_user(uid, [rbac.save("", f"role-{email}", "", areas, [], [])])


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


def act(c: TestClient, body: dict):
    r = c.post("/virt/act", json=body)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def finish(c: TestClient, cid: str, j: dict, node: str = "") -> dict:
    if not j.get("task"):
        return j
    for _ in range(20):
        t = c.get(f"/virt/task?c={cid}&task={j['task']}&node={node}").json()
        if t.get("state") not in ("queued", "running"):
            return t
        time.sleep(0.2)
    return {"state": "timeout"}


# ── 1. the table ───────────────────────────────────────────────
def test_table() -> None:
    for name, (need, target, label) in virtops.ACTIONS.items():
        check(f"{name}: a known area", need in virtops.AREAS)
        check(f"{name}: a target", target in ("vm", "host"))
        check(f"{name}: an audit name", virtops.audit_name(name).startswith("virt_"))
    check("engine-only actions are actions",
          (virtops.ESXI_ONLY | virtops.PVE_ONLY | virtops.NOT_RUN) <= set(virtops.ACTIONS))
    for a in ("virt_console", "virt_power", "virt_admin"):
        check(f"{a} is an area", a in rbac.AREAS)
        check(f"{a} escalates", a in rbac.ESCALATING)
        check(f"{a} is not answerable", a in answers.NOT_ANSWERABLE)
        check(f"{a} is handler-enforced (no prefix)", rbac.AREAS[a][2] == ())
    z = struct.pack(">BxH", 2, 4) + b"".join(struct.pack(">i", e) for e in (16, 6, 0, -239))
    out = virtops.strip_zlib(z)
    check(f"Zlib is taken out of SetEncodings: {out.hex()}",
          out == struct.pack(">BxH", 2, 3) + b"".join(struct.pack(">i", e) for e in (16, 0, -239)))
    check("other messages pass untouched", virtops.strip_zlib(b"\x03\x00\x00") == b"\x03\x00\x00"
          and virtops.strip_zlib(b"\x01") == b"\x01")


# ── 2. ESXi ────────────────────────────────────────────────────
def test_esxi_engine(conn: dict, host: FakeEsxi) -> None:
    def run(action, **p):
        out = virtops.run(conn, action, p)
        info = virtops.task(conn, out["task"]) if out.get("task") else {"state": "success"}
        return out, info

    _o, i = run("vm.stop", vm="1")
    check(f"power off: {i}", i["state"] == "success" and host.vms["1"]["power"] == "poweredOff")
    _o, i = run("vm.start", vm="1")
    check("power on", host.vms["1"]["power"] == "poweredOn")
    _o, i = run("vm.start", vm="1")
    check(f"powering on a running VM fails with the host's reason: {i}",
          i["state"] == "error" and "current state" in i["error"])
    run("vm.suspend", vm="3")
    check("suspend", host.vms["3"]["power"] == "suspended")
    run("vm.start", vm="3")
    run("vm.reset", vm="3")
    run("vm.reboot", vm="3")
    run("vm.shutdown", vm="3")
    check("guest shutdown", host.vms["3"]["power"] == "poweredOff")
    try:
        run("vm.shutdown", vm="4")
        check("a guest shutdown without Tools says why", False)
    except virt.VirtError as e:
        check(f"a guest shutdown without Tools says why: {e}", "VMware Tools" in str(e))
    run("vm.snapshot", vm="1", name="pre-change", description="d", memory="1")
    snaps = host.vms["1"]["snapshots"]
    check("a snapshot is taken", snaps and snaps[0]["name"] == "pre-change")
    sid = snaps[0]["id"]
    run("vm.snapshot_rename", vm="1", snapshot=sid, name="renamed", description="x")
    check("a snapshot is renamed", host.vms["1"]["snapshots"][0]["name"] == "renamed")
    run("vm.revert", vm="1", snapshot=sid)
    run("vm.snapshot_delete", vm="1", snapshot=sid)
    check("a snapshot is deleted", not host.vms["1"]["snapshots"])
    for action in ("vm.revert", "vm.snapshot_delete", "vm.snapshot_rename"):
        try:
            run(action, vm="1", snapshot="2-snapshot-1", name="x")
            check(f"{action}: another VM's snapshot is refused", False)
        except virt.VirtError as e:
            check(f"{action}: another VM's snapshot is refused ({e})", "not one of this VM's" in str(e))
    check("and it was left alone", host.vms["2"]["snapshots"][0]["name"] == "before-upgrade-9.4")
    run("vm.snapshot_delete_all", vm="2")
    check("every snapshot is deleted", not host.vms["2"]["snapshots"])
    _o, i = run("vm.resources", vm="1", memory_mb="16384")
    check(f"memory on a running VM: the host's refusal comes back: {i}",
          i["state"] == "error" and "Power it off" in i["error"])
    run("vm.resources", vm="4", cpus="4", cores_per_socket="2", memory_mb="8192", notes="build box")
    v4 = host.vms["4"]
    check(f"CPU, memory and notes: {v4['cpus']}/{v4['cps']}/{v4['mem']}/{v4['notes']}",
          (v4["cpus"], v4["cps"], v4["mem"], v4["notes"]) == (4, 2, 8192, "build box"))
    run("vm.boot", vm="4", firmware="bios", secure_boot="0", enter_setup="1")
    check("boot options", v4["firmware"] == "bios" and v4["enter_setup"])
    run("vm.disk_extend", vm="4", key="2000", gib="64")
    check("a disk grows", next(d for d in v4["devices"] if d["key"] == 2000)["kb"] == 64 * 1048576)
    try:
        run("vm.disk_extend", vm="4", key="2000", gib="10")
        check("a disk cannot shrink", False)
    except virt.VirtError as e:
        check(f"a disk cannot shrink: {e}", "only grow" in str(e))
    run("vm.disk_add", vm="4", gib="20", datastore="datastore1")
    added = [d for d in v4["devices"] if d["type"] == "VirtualDisk" and d["key"] != 2000]
    check(f"a disk is added on the SCSI controller, unit 1: {added}",
          added and added[0]["controller"] == 1000 and added[0]["unit"] == 1)
    run("vm.device_remove", vm="4", key=str(added[0]["key"]), delete_file="1")
    check("a disk is removed", not [d for d in v4["devices"] if d["type"] == "VirtualDisk" and d["key"] != 2000])
    run("vm.nic_add", vm="4", network="DB Network", adapter="vmxnet3")
    nics = [d for d in v4["devices"] if d["type"] == "VirtualVmxnet3"]
    check(f"an adapter is added: {[n['network'] for n in nics]}", len(nics) == 2 and nics[1]["network"] == "DB Network")
    run("vm.nic_set", vm="4", key=str(nics[1]["key"]), network="VM Network")
    run("vm.nic_set", vm="4", key=str(nics[1]["key"]), connected="1")
    check("an adapter moves and connects", nics[1]["network"] == "VM Network" and nics[1]["connected"])
    run("vm.device_remove", vm="4", key=str(nics[1]["key"]))
    run("vm.cd", vm="4", key="16000", iso="[datastore1] ISO/almalinux-9.4-x86_64-minimal.iso")
    cd = next(d for d in v4["devices"] if d["type"] == "VirtualCdrom")
    check("an ISO is inserted", cd["iso"].endswith("almalinux-9.4-x86_64-minimal.iso"))
    run("vm.cd", vm="4", key="16000", iso="")
    for bad_iso in ("[datastore1] web-01/web-01-flat.vmdk", "[datastore1] ISO/../web-01/x.iso",
                    "[datastore1] ISO/notes.txt"):
        try:
            run("vm.cd", vm="4", key="16000", iso=bad_iso)
            check(f"a CD takes only an ISO: {bad_iso}", False)
        except virt.VirtError:
            pass
    check("and ejected", cd["iso"] == "")
    run("vm.rename", vm="4", name="builder-02")
    check("a VM is renamed", v4["name"] == "builder-02")
    o, i = run("vm.create", name="made-here", datastore="datastore1", cpus="2", cores_per_socket="1",
               memory_mb="2048", disk_gib="16", guest_id="almalinux_64Guest", network="VM Network",
               iso="[datastore1] ISO/almalinux-9.4-x86_64-minimal.iso", firmware="efi", secure_boot="1")
    new = i.get("result")
    check(f"a VM is created and its id comes back: {i}", new in host.vms and host.vms[new]["name"] == "made-here")
    run("vm.start", vm=new)
    _o, i = run("vm.delete", vm=new)
    check("deleting a running VM is refused by the host", i["state"] == "error" and new in host.vms)
    run("vm.stop", vm=new)
    run("vm.delete", vm=new)
    check("a stopped VM is deleted", new not in host.vms)
    run("vm.unregister", vm="5")
    check("a VM is unregistered", "5" not in host.vms)
    _o, i = run("host.maintenance_enter")
    check("maintenance waits for running VMs", i["state"] == "error" and not host.maintenance)
    _o, i = run("host.reboot")
    check("a reboot outside maintenance needs force", i["state"] == "error")
    _o, i = run("host.reboot", force="1")
    check("and goes with it", i["state"] == "success")
    for m in list(host.vms):
        host.vms[m]["power"] = "poweredOff"
    run("host.maintenance_enter")
    check("maintenance mode", host.maintenance)
    run("host.maintenance_exit")
    check("out of maintenance", not host.maintenance)
    run("host.service", op="start", key="TSM-SSH")
    run("host.service_policy", key="TSM-SSH", policy="on")
    ssh = next(s for s in host.services if s["key"] == "TSM-SSH")
    check("a service starts and its policy changes", ssh["running"] and ssh["policy"] == "on")
    run("host.portgroup_add", name="Lab 42", vlan="42", vswitch="vSwitch0")
    run("host.portgroup_update", name="Lab 42", vlan="43", vswitch="vSwitch0")
    check("a port group is added and re-tagged", any(g["name"] == "Lab 42" and g["vlan"] == 43 for g in host.portgroups))
    run("host.portgroup_remove", name="Lab 42")
    check("and removed", not any(g["name"] == "Lab 42" for g in host.portgroups))
    run("ds.mkdir", datastore="datastore1", path="ISO/new")
    run("ds.delete", datastore="datastore1", path="ISO/ubuntu-24.04-live-server-amd64.iso")
    check("a datastore file is deleted",
          "ISO/ubuntu-24.04-live-server-amd64.iso" not in host.files["datastore1"])
    for bad_path in ("../etc", "ISO/../../x"):
        try:
            run("ds.delete", datastore="datastore1", path=bad_path)
            check(f"a climbing path is refused: {bad_path}", False)
        except virt.VirtError:
            pass
    try:
        run("vm.clone", vm="1", name="x")
        check("a Proxmox-only action is refused on ESXi", False)
    except virt.VirtError:
        pass
    for m in list(host.vms):
        host.vms[m]["power"] = "poweredOn"


# ── 3. Proxmox ─────────────────────────────────────────────────
def test_pve_engine(conn: dict, pve: FakePve) -> None:
    def run(action, **p):
        p.setdefault("node", "pve-01")
        p.setdefault("kind", "qemu")
        out = virtops.run(conn, action, p)
        info = virtops.task(conn, out["task"], p["node"]) if out.get("task") else {"state": "success"}
        return out, info

    def last(method=None, path=None):
        for c in reversed(pve.calls):
            if (method is None or c[0] == method) and (path is None or re.search(path, c[1])):
                return c
        return None

    _o, i = run("vm.stop", vm="100")
    check(f"PVE power off: {i}", i["state"] == "success" and pve.guests[100]["status"] == "stopped")
    for op in ("start", "suspend", "resume", "reset", "reboot", "shutdown"):
        run(f"vm.{op}", vm="100")
        check(f"PVE {op} posts status/{op}", last("POST", rf"/qemu/100/status/{op}$"))
    run("vm.start", vm="200", kind="lxc")
    check("a container's power goes to lxc/", last("POST", r"/lxc/200/status/start$"))
    run("vm.snapshot", vm="100", name="pre-change", description="d", memory="1")
    c = last("POST", r"/qemu/100/snapshot$")
    check(f"PVE snapshot with RAM: {c}", c and c[2].get("vmstate") == "1" and c[2]["snapname"] == "pre-change")
    run("vm.revert", vm="100", snapshot="pre-change")
    run("vm.snapshot_delete", vm="100", snapshot="pre-change")
    check("PVE revert and delete", last("POST", r"/snapshot/pre-change/rollback$") and last("DELETE", r"/snapshot/pre-change$"))
    try:
        run("vm.snapshot", vm="100", name="1-bad name")
        check("a Proxmox snapshot name is checked", False)
    except virt.VirtError:
        pass
    run("vm.resources", vm="101", cpus="4", sockets="2", memory_mb="8192", notes="n", onboot="1")
    cfg = pve.guests[101]["config"]
    check(f"PVE cores, sockets, memory, notes, onboot: {cfg}",
          (cfg["cores"], cfg["sockets"], cfg["memory"], cfg["description"], cfg["onboot"]) == (4, 2, 8192, "n", 1))
    run("vm.resources", vm="200", kind="lxc", cpus="3")
    check("a container's config is PUT", last("PUT", r"/lxc/200/config$"))
    run("vm.rename", vm="101", name="test-vm-08")
    check("PVE rename", cfg["name"] == "test-vm-08")
    run("vm.disk_extend", vm="101", key="scsi0", gib="48")
    check(f"PVE resize: {cfg['scsi0']}", "size=48G" in cfg["scsi0"])
    run("vm.disk_add", vm="101", gib="20", datastore="local-lvm")
    check(f"PVE add disk on the next SCSI slot: {cfg.get('scsi1')}", cfg.get("scsi1", "").startswith("local-lvm:20"))
    run("vm.device_remove", vm="101", key="scsi1")
    check("PVE remove disk", "scsi1" not in cfg)
    run("vm.nic_add", vm="101", network="vmbr0", vlan="30")
    check(f"PVE add adapter: {cfg.get('net1')}", cfg.get("net1") == "virtio,bridge=vmbr0,tag=30")
    run("vm.nic_set", vm="100", key="net0", network="vmbr0", vlan="", connected="0")
    n0 = pve.guests[100]["config"]["net0"]
    check(f"PVE adapter keeps its MAC, loses its tag, link down: {n0}",
          n0.startswith("virtio=BC:24:11:0A:00:01") and "tag=" not in n0 and "link_down=1" in n0)
    run("vm.cd", vm="101", key="ide2", iso="local:iso/almalinux-9.4-x86_64-minimal.iso")
    for bad_iso in ("local-lvm:vm-100-disk-0", "local:images/100/vm-100-disk-0.qcow2", "local:iso/../x.iso"):
        try:
            run("vm.cd", vm="101", key="ide2", iso=bad_iso)
            check(f"a Proxmox CD takes only an ISO: {bad_iso}", False)
        except virt.VirtError:
            pass
    check("PVE insert ISO", cfg["ide2"] == "local:iso/almalinux-9.4-x86_64-minimal.iso,media=cdrom")
    run("vm.cd", vm="101", key="ide2", iso="")
    check("PVE eject", cfg["ide2"] == "none,media=cdrom")
    o, _i = run("vm.clone", vm="101", name="test-copy", full="1")
    check(f"PVE clone gets the next id: {o}", o.get("new_id") in pve.guests)
    run("vm.migrate", vm="101", target="pve-02", online="0")
    check("PVE migrate", pve.guests[101]["node"] == "pve-02")
    o, _i = run("vm.create", name="made-here", cpus="2", sockets="1", memory_mb="2048", disk_gib="16",
                storage="local-lvm", network="vmbr0", vlan="20", ostype="l26",
                iso="local:iso/almalinux-9.4-x86_64-minimal.iso", firmware="efi", secure_boot="1")
    new = pve.guests.get(o.get("new_id"), {}).get("config", {})
    check(f"PVE create: {new}", new.get("name") == "made-here" and new.get("bios") == "ovmf"
          and "pre-enrolled-keys=1" in new.get("efidisk0", "") and new.get("net0") == "virtio,bridge=vmbr0,tag=20")
    run("vm.start", vm=str(o["new_id"]))
    try:
        virtops.run(conn, "vm.delete", {"node": "pve-01", "kind": "qemu", "vm": str(o["new_id"])})
        check("deleting a running PVE VM is refused", False)
    except virt.VirtError as e:
        check(f"deleting a running PVE VM says why: {e}", "running" in str(e))
    run("vm.stop", vm=str(o["new_id"]))
    run("vm.delete", vm=str(o["new_id"]))
    check("PVE delete purges", o["new_id"] not in pve.guests
          and last("DELETE", rf"/qemu/{o['new_id']}$")[2].get("purge") == "1")
    run("host.service", op="restart", key="pveproxy")
    check("PVE service restart", last("POST", r"/services/pveproxy/restart$"))
    run("host.reboot")
    check("PVE node reboot", last("POST", r"/nodes/pve-01/status$")[2].get("command") == "reboot")
    run("ds.delete", datastore="local", path="local:iso/debian-12.7.0-amd64-netinst.iso")
    check("PVE delete an ISO", not any("debian" in c["volid"] for c in pve.content["local"]))
    try:
        run("host.maintenance_enter")
        check("an ESXi-only action is refused on Proxmox", False)
    except virt.VirtError:
        pass
    pve.guests[100]["status"] = "running"


# ── 4-8. pages, gates, audit, upload, console ─────────────────
def test_pages_and_gates(esx: dict, esx_ro: dict, pve_c: dict, host: FakeEsxi, pve: FakePve) -> None:
    _user("admin@virt.test", None, admin=True)
    _user("reader@virt.test", ["virt"])
    _user("operator@virt.test", ["virt", "virt_power", "virt_console"])
    _user("admin2@virt.test", ["virt", "virt_admin"])
    adm, rdr, opr, ad2 = (_client(e) for e in ("admin@virt.test", "reader@virt.test",
                                                "operator@virt.test", "admin2@virt.test"))
    E, R, P = esx["id"], esx_ro["id"], pve_c["id"]

    # the list links into the pages
    r = adm.get("/virt")
    check(f"/virt answers ({r.status_code})", r.status_code == 200)
    check("the ESXi card links to its host page and New VM",
          f'/virt/host?c={E}' in r.text and f'/virt/new?c={E}' in r.text)
    for title in ("Virtual machines", "Hosts", "Host CPU", "Host memory"):
        check(f"the overview shows the {title} chart", f"</svg>" in r.text and title in r.text)
    check("the host charts link to the ESXi host page",
          re.search(rf'class="fval" href="/virt/host\?c={E}"', r.text))
    check(f"guests link to their pages and consoles: {re.findall(r'href=.(/virt/vm[^ ]{0,60})', r.text)[:1]}",
          re.search(rf'/virt/vm\?c={E}&(amp;)?vm=1&', r.text) and '/virt/console?c=' in r.text)

    # every page and tab renders, for both engines
    pages = [f"/virt/vm?c={E}&vm=1&sec={s}" for s in ("summary", "hardware", "snapshots", "tasks")]
    pages += [f"/virt/vm?c={P}&vm=100&node=pve-01&kind=qemu&sec={s}" for s in ("summary", "hardware", "snapshots", "tasks")]
    pages += [f"/virt/vm?c={P}&vm=200&node=pve-02&kind=lxc&sec=hardware"]
    pages += [f"/virt/host?c={E}&sec={s}" for s in ("summary", "vms", "storage", "network", "services", "tasks")]
    pages += [f"/virt/host?c={E}&sec=storage&ds=datastore1", f"/virt/host?c={E}&sec=storage&ds=datastore1&path=ISO"]
    pages += [f"/virt/host?c={P}&node=pve-01&sec={s}" for s in ("summary", "vms", "storage", "network", "services", "tasks")]
    pages += [f"/virt/host?c={P}&node=pve-01&sec=storage&ds=local", f"/virt/new?c={E}", f"/virt/new?c={P}&node=pve-01",
              f"/virt/console?c={E}&vm=1&name=web-01"]
    for path in pages:
        r = adm.get(path)
        ok = r.status_code == 200 and "Traceback" not in r.text and "flash err" not in r.text
        check(f"{path} renders ({r.status_code}) {re.findall(r'flash err[^<]*<[^>]*>?([^<]{0,160})', r.text)[:1]}", ok)
    r = adm.get(f"/virt/vm?c={E}&vm=1&sec=hardware")
    check("the hardware tab offers the host's ISOs and networks",
          "ISO/almalinux-9.4-x86_64-minimal.iso" in r.text and "DB Network" in r.text)
    r = adm.get(f"/virt/host?c={E}&sec=storage&ds=datastore1&path=ISO")
    check("the datastore browser lists the ISOs", "windows-server-2022.iso" in r.text)

    # a reader sees the page, with every button disabled and saying why
    host.vms["4"]["power"] = "poweredOff"
    virt.invalidate()
    r = rdr.get(f"/virt/vm?c={E}&vm=4")
    btn = re.search(r'<button[^>]*data-act="vm\.start"[^>]*>', r.text)
    check(f"a reader's Start is disabled with its reason: {btn.group(0) if btn else None}",
          btn and "disabled" in btn.group(0) and "Hypervisors: power" in btn.group(0))
    s, j = act(rdr, {"c": E, "action": "vm.start", "vm": "4"})
    check(f"a reader cannot act ({s} {j})", s == 403 and "power" in j.get("error", ""))
    check("and the refusal is audited", audits("virt_vm_start_refused"))

    # the operator: power and console, not administer
    s, j = act(opr, {"c": E, "action": "vm.stop", "vm": "3"})
    t = finish(opr, E, j)
    check(f"an operator powers off ({s} {t})", s == 200 and t.get("state") == "success"
          and host.vms["3"]["power"] == "poweredOff")
    row = (audits("virt_vm_stop") or [{}])[-1]
    check(f"the change is audited with the VM's name: {dict(row) if row else None}",
          row and row["user"] == "operator@virt.test" and "k8s-worker-07" in row["target"])
    s, j = act(opr, {"c": E, "action": "vm.delete", "vm": "3"})
    check(f"an operator cannot delete ({s})", s == 403 and "administer" in j.get("error", ""))
    s, j = act(ad2, {"c": E, "action": "vm.start", "vm": "3"})
    finish(ad2, E, j)
    check("administer includes power", s == 200 and host.vms["3"]["power"] == "poweredOn")

    # a connection that does not allow management refuses everything
    s, j = act(adm, {"c": R, "action": "vm.start", "vm": "4"})
    check(f"a read-only connection refuses ({s} {j})", s == 403 and "read-only in EnvMap" in j.get("error", ""))
    r = adm.get(f"/virt/vm?c={R}&vm=4")
    check("its page says so", "read-only in EnvMap" in r.text)

    # production wants the VM's own name
    s, j = act(adm, {"c": P, "action": "vm.stop", "vm": "100", "node": "pve-01", "kind": "qemu"})
    check(f"production without the name is refused ({s} {j})", s == 403 and "app-01" in j.get("error", ""))
    s, j = act(adm, {"c": P, "action": "vm.stop", "vm": "100", "node": "pve-01", "kind": "qemu",
                     "confirm": "not-it"})
    check("the wrong name is refused", s == 403)
    s, j = act(adm, {"c": P, "action": "vm.stop", "vm": "100", "node": "pve-01", "kind": "qemu",
                     "confirm": "app-01", "vm_name": "anything"})
    finish(adm, P, j, "pve-01")
    check(f"the right name goes through ({s} {j})", s == 200 and pve.guests[100]["status"] == "stopped")
    s, j = act(adm, {"c": P, "action": "host.reboot", "node": "pve-01", "confirm": "nope"})
    check("a host action on production wants the connection's name", s == 403 and pve_c["name"] in j.get("error", ""))

    # uploads
    data = b"\x00" * 300_000
    r = adm.post(f"/virt/upload?c={E}&ds=datastore1&path=ISO&name=tools.iso", content=data,
                 headers={"Content-Type": "application/octet-stream"})
    check(f"an upload reaches the datastore ({r.status_code} {r.text[:120]})",
          r.json().get("ok") and host.files["datastore1"].get("ISO/tools.iso") == len(data))
    check("and is audited", audits("virt_ds_upload"))
    r = rdr.post(f"/virt/upload?c={E}&ds=datastore1&path=ISO&name=x.iso", content=b"x")
    check("a reader cannot upload", r.status_code == 403)
    r = adm.post(f"/virt/upload?c={E}&ds=datastore1&path=ISO&name=../x.iso", content=b"x")
    check("an upload name cannot climb", r.status_code == 403)
    r = adm.post(f"/virt/upload?c={P}&node=pve-01&ds=local&name=alpine.iso&confirm={pve_c['name']}",
                 content=b"\x01" * 4096)
    check(f"an upload reaches a Proxmox storage ({r.text[:120]})",
          r.json().get("ok") and any(c["volid"] == "local:iso/alpine.iso" for c in pve.content["local"]))

    # the review's findings (24 November 2026)
    r = opr.get(f"/virt/choices?c={E}")
    check(f"the ISO search is for administrators only ({r.status_code})", r.status_code == 403)
    r = rdr.get(f"/virt/task?c={E}&task=task-1")
    check(f"a reader cannot follow tasks ({r.status_code})", r.status_code == 403)
    r = adm.post("/virt/act", content=b'{"c": "%s", "action": "vm.start", "vm": "1"}' % E.encode(),
                 headers={"Content-Type": "text/plain"})
    check(f"a change that is not sent as JSON is refused ({r.status_code})", r.status_code == 415)
    before_calls = len(host.calls)
    r = rdr.post("/virt/act", json={"c": E, "action": "vm.stop", "vm": "x" * 5000 + "\nforged"})
    rows = audits("virt_vm_stop_refused")
    check(f"a reader's refusal costs the host nothing and is bounded in the audit "
          f"({len(host.calls) - before_calls} calls, target {len(rows[-1]['target']) if rows else 0} chars)",
          r.status_code == 403 and len(host.calls) == before_calls and rows
          and len(rows[-1]["target"]) <= 300 and "\n" not in rows[-1]["target"])
    code, j = act(adm, {"c": P, "action": "vm.start", "vm": "999", "node": "pve-01", "kind": "qemu",
                        "confirm": ""})
    check(f"production: a VM that cannot be found is not confirmed by an empty name ({code} {j})",
          code == 403 and "could not be found" in j.get("error", ""))
    r = adm.get(f"/virt/console?c={E}&vm=1&name=web-01", headers={"Sec-Fetch-Site": "cross-site"})
    check("a console reached from another site waits for a click",
          r.status_code == 200 and "opened from a link on another site" in r.text and "clickFirst = true" in r.text)
    r = adm.get(f"/virt/console?c={E}&vm=1&name=web-01", headers={"Sec-Fetch-Site": "same-origin"})
    check("from EnvMap itself it opens straight away", "clickFirst = false" in r.text)

    # the console
    s_open = opr.post("/virt/console/open", json={"c": E, "vm": "1"}).json()
    check(f"the operator opens a console session: {s_open}", s_open.get("ok") and s_open.get("session"))
    check("it is audited as privileged access", audits("virt_console"))
    before = len(host.encodings_seen)
    try:
        with opr.websocket_connect(f"/virt/console.ws?session={s_open['session']}") as ws:
            ver = ws.receive_bytes()
            check(f"the relay carries the host's RFB greeting: {ver!r}", ver == b"RFB 003.008\n")
            ws.send_bytes(b"RFB 003.008\n")
            sec = ws.receive_bytes()
            check("security type None", sec[:2] == b"\x01\x01")
            ws.send_bytes(b"\x01")
            ws.receive_bytes()
            ws.send_bytes(b"\x01")
            init = ws.receive_bytes()
            w, h = struct.unpack(">HH", init[:4])
            check(f"the VM's screen size and name: {w}x{h} {init[24:]!r}", (w, h) == (800, 480) and b"web-01" in init)
            ws.send_bytes(struct.pack(">BxH", 2, 4) + b"".join(struct.pack(">i", e) for e in (16, 6, 0, -239)))
            ws.send_bytes(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))
            got = b""
            while len(got) < 16:
                got += ws.receive_bytes()
            check("a framebuffer update comes back", got[0] == 0)
    except Exception as e:                                    # noqa: BLE001
        check(f"the console relay works: {type(e).__name__}: {e}", False)
    seen = host.encodings_seen[before:]
    check(f"the host never saw Zlib: {seen}", seen and 6 not in seen[-1] and 16 in seen[-1])
    try:
        with opr.websocket_connect(f"/virt/console.ws?session={s_open['session']}") as ws:
            ws.receive_bytes()
            check("a console session is single-use", False)
    except Exception:                                         # noqa: BLE001
        pass
    s2 = opr.post("/virt/console/open", json={"c": E, "vm": "1"}).json()
    try:
        with ad2.websocket_connect(f"/virt/console.ws?session={s2['session']}") as ws:
            ws.receive_bytes()
            check("somebody else cannot use another's console session", False)
    except Exception:                                         # noqa: BLE001
        pass
    r = rdr.post("/virt/console/open", json={"c": E, "vm": "1"})
    check("a reader cannot open a console", r.status_code == 403 and audits("virt_console_refused"))
    r = adm.post("/virt/console/open", json={"c": P, "vm": "100", "node": "pve-01", "kind": "qemu"})
    check("a production console wants the name", r.status_code == 403)
    pve.guests[100]["status"] = "running"
    r = adm.post("/virt/console/open", json={"c": P, "vm": "100", "node": "pve-01", "kind": "qemu",
                                             "confirm": "app-01"}).json()
    check(f"a Proxmox console hands noVNC its VNC password: {r}", r.get("ok") and r.get("password") == "PVEVNC:FAKE::ticket")
    check("the console page refuses a reader", rdr.get(f"/virt/console?c={E}&vm=1").status_code == 403)

    # ticking management on is an audited access decision
    conn = store.get_virt("", R)
    r = adm.post(f"/settings/conns/virt/{R}/update",
                 data={"pid": "", "name": conn["name"], "base_url": conn["base_url"],
                       "username": conn["username"], "skip_tls": "1", "manage": "1"},
                 follow_redirects=False)
    check(f"the manage tick is saved ({r.status_code})", store.get_virt("", R).get("manage") == "1")
    check("and audited", audits("virt_manage_on"))
    for c in (adm, rdr, opr, ad2):
        c.__exit__(None, None, None)


def main() -> int:
    host, pve = FakeEsxi().start(), FakePve().start()
    try:
        test_table()
        esx = {"type": "vsphere", "name": "lab-esxi", "base_url": host.url, "username": "root",
               "token": "lab-password", "skip_tls": "1", "manage": "1"}
        esx_ro = {**esx, "name": "lab-esxi-readonly", "manage": ""}
        pve_c = {"type": "proxmox", "name": "pve-lab", "base_url": host.url.replace(str(host.port), str(pve.port)),
                 "username": "root@pam!envmap", "token": "pve-token-secret", "skip_tls": "1",
                 "manage": "1", "production": "1"}
        for c in (esx, esx_ro, pve_c):
            c["id"] = store.add_virt("", dict(c))
        test_esxi_engine({**esx, "id": esx["id"]}, host)
        test_pve_engine({**pve_c, "id": pve_c["id"]}, pve)
        virt.invalidate()
        test_pages_and_gates(esx, esx_ro, pve_c, host, pve)
    finally:
        host.stop()
        pve.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
