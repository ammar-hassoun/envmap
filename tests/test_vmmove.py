#!/usr/bin/env python3
"""EnvMap Move: the receiver CD, the new VM's configuration, the checks, and a
whole move through EnvMap's own routes against a fake Proxmox whose guests
answer a guest agent and run a simulated engine.

Asked for on 26 November 2026 ("in one click I should be able to transfer the
VM"). The engine itself is tested in the lab (reports/vm-move); this holds
what EnvMap does around it:

  1. the ISO 9660 writer reads back: files, El Torito catalog, ISOLINUX's
     boot information table; the cpio archive reads back
  2. the receiver CD carries the engine, the drivers in order and the move's
     settings; envmove-core is the binary built from core.c (hashes recorded)
  3. the new VM's configuration, Proxmox and ESXi, from either kind of source:
     same disks and cards with their own addresses, a transfer card, the CD
     first, Secure Boot off, nothing secret copied
  4. what the guest must offer, and the transfer addresses
  5. a move from start to end: refused without Administer on both sides,
     checked, started, followed through the freeze to the arrival, finished
     (CD out, transfer cards out, names, the old VM kept from starting), audited
  6. a move the guest calls off (thawed): everything built for it removed
  7. the pages

    ./.venv/bin/python tests/test_vmmove.py
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import pathlib
import struct
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("vmmove-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
PARTS = pathlib.Path(tempfile.mkdtemp(prefix="vmmove-parts-"))
os.environ["PORTAL_ENVMOVE_DIR"] = str(PARTS)

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_pve_agent import AgentPve                           # noqa: E402
from app import auth, db, moveiso, moveside, rbac, store, virt, vmmove   # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Moves-Are-Checked-Twice-42"
ENGINE = b"\x7fELF" + b"fake envmove engine " * 4000
CORE_C = "c0d8c1b6c3e5c0f0"         # replaced below by the real hashes


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── a reader for what the writer wrote ─────────────────────────
def iso_files(img: bytes) -> dict:
    S = 2048
    pvd = img[16 * S:17 * S]
    assert pvd[1:6] == b"CD001"
    root = pvd[156:156 + 34]

    def rec(b):
        lba, size, flags, nl = struct.unpack_from("<I", b, 2)[0], struct.unpack_from("<I", b, 10)[0], b[25], b[32]
        return lba, size, flags, b[33:33 + nl]

    out = {}

    def walk(lba, size, prefix):
        data = img[lba * S:lba * S + size]
        pos = 0
        while pos < len(data):
            ln = data[pos]
            if ln == 0:
                pos = (pos // S + 1) * S
                continue
            l2, sz, flags, name = rec(data[pos:pos + ln])
            pos += ln
            if name in (b"\x00", b"\x01"):
                continue
            n = name.decode().split(";")[0].rstrip(".")
            if flags & 2:
                walk(l2, sz, prefix + n + "/")
            else:
                out[prefix + n] = img[l2 * S:l2 * S + sz]
    l0, s0, _, _ = rec(root)
    walk(l0, s0, "")
    return out


def cpio_files(data: bytes) -> list:
    out, pos = [], 0
    while pos < len(data):
        h = data[pos:pos + 110]
        if h[:6] != b"070701":
            break
        f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        mode, size, nlen = f[1], f[6], f[11]
        pos += 110
        name = data[pos:pos + nlen - 1].decode()
        pos += nlen
        pos += (-pos) % 4
        body = data[pos:pos + size]
        pos += size
        pos += (-pos) % 4
        if name == "TRAILER!!!":
            break
        out.append((name, mode, body))
    return out


def test_iso() -> None:
    files = {"BOOT/A.BIN": b"isolinux" + bytes(4000), "BOOT/EFI.IMG": b"\xeb\x3c" + bytes(9000),
             "X/Y/Z.TXT": b"deep" * 900, "TOP.JSN": b'{"a":1}'}
    img = moveiso.build(files, bios="BOOT/A.BIN", efi="BOOT/EFI.IMG", label="TESTLBL")
    check("whole sectors", len(img) % 2048 == 0)
    got = iso_files(img)
    for k, v in files.items():
        g = got.get(k, b"")
        # ISOLINUX's boot information table is written over bytes 8 to 24
        check(f"{k} reads back", (g[:8] == v[:8] and g[24:] == v[24:]) if k == "BOOT/A.BIN" else g == v)
    br = img[17 * 2048:18 * 2048]
    check("El Torito boot record", br[7:30] == b"EL TORITO SPECIFICATION")
    cat_lba = struct.unpack_from("<I", br, 71)[0]
    cat = img[cat_lba * 2048:cat_lba * 2048 + 2048]
    check("validation entry sums to zero", sum(struct.unpack("<16H", cat[:32])) & 0xFFFF == 0)
    check("BIOS entry bootable", cat[32] == 0x88)
    check("UEFI section header", cat[64] == 0x91 and cat[65] == 0xEF)
    a = got["BOOT/A.BIN"]
    pvd_lba, file_lba, ln, csum = struct.unpack_from("<IIII", a, 8)
    check("boot information table: the volume descriptor", pvd_lba == 16)
    body = a[64:] + bytes((-len(a[64:])) % 4)
    check("boot information table: checksum", csum == sum(w for (w,) in struct.iter_unpack("<I", body)) & 0xFFFFFFFF)
    check("boot information table: length", ln == len(files["BOOT/A.BIN"]))
    c = moveiso.cpio([("d", 0o040755, b""), ("d/f", 0o100644, b"hello"), ("e", 0o100755, b"x" * 7)])
    back = cpio_files(c)
    check("cpio reads back", [(n, b) for n, _, b in back] == [("d", b""), ("d/f", b"hello"), ("e", b"x" * 7)])
    check("cpio modes", back[2][1] == 0o100755)


def make_parts() -> None:
    (PARTS / "rx" / "mods").mkdir(parents=True, exist_ok=True)
    (PARTS / "envmove").write_bytes(ENGINE)
    for n, d in (("vmlinuz", b"MZ kernel" * 300), ("initrd", b"initrd" * 500), ("isolinux.bin", bytes(2048)),
                 ("ldlinux.c32", b"ld" * 100), ("efi.img", bytes(2880 * 512)), ("bootx64.efi", b"MZ efi" * 50)):
        (PARTS / "rx" / n).write_bytes(d)
    for n in ("failover.ko", "virtio_net.ko", "vmxnet3.ko"):
        (PARTS / "rx" / "mods" / n).write_bytes(b"\x7fELF" + n.encode())
    (PARTS / "rx" / "mods" / "order").write_text("failover.ko\nvirtio_net.ko\nvmxnet3.ko\n")


def test_receiver() -> None:
    ok, why = moveiso.parts()
    check(f"parts found ({why})", ok)
    settings = {"ip": "169.254.9.2/30", "mac": "02:11:22:33:44:55", "port": 8100, "token": "t" * 30,
                "verdict": "169.254.9.1:47001", "vtoken": "v" * 30, "gw": ""}
    got = iso_files(moveiso.receiver_iso(settings))
    check("settings on the CD", json.loads(got["ENVMOVE.JSN"]) == settings)
    check("the kernel", got["BOOT/VMLINUZ"] == (PARTS / "rx" / "vmlinuz").read_bytes())
    check("both boot menus", b"rdinit=/envmove envmove.role=boot" in got["BOOT/SYSLINUX/SYSLINUX.CFG"]
          and b"envboot.img" in got["BOOT/GRUB/GRUB.CFG"])
    names = [n for n, _, _ in cpio_files(got["BOOT/ENVBOOT.IMG"])]
    check("engine first in the boot initramfs", names[0] == "envmove")
    check("drivers in their order", names[2:5] == ["envmove-mods/failover.ko", "envmove-mods/virtio_net.ko",
                                                   "envmove-mods/vmxnet3.ko"])
    body = dict((n, b) for n, _, b in cpio_files(got["BOOT/ENVBOOT.IMG"]))
    check("the engine is the engine", body["envmove"] == ENGINE)
    # the frozen part is the binary built from core.c: change one, rebuild the other
    core_c = hashlib.sha256((ROOT / "envmove" / "core" / "core.c").read_bytes()).hexdigest()
    core_b = hashlib.sha256((ROOT / "envmove" / "coreimg" / "envmove-core").read_bytes()).hexdigest()
    rec = json.loads((ROOT / "envmove" / "coreimg" / "BUILT-FROM.json").read_text())
    check("envmove-core was built from this core.c (envmove/core/build.sh, then record both hashes)",
          rec == {"core.c": core_c, "envmove-core": core_b})


# ── the new VM's configuration ─────────────────────────────────
TR = {"dst_mac": "02:aa:bb:cc:dd:ee", "dst_net": "vmbr1", "dst_vlan": "3999"}


def test_specs() -> None:
    cfg = {"name": "app-01", "cores": 4, "sockets": 1, "memory": 8192, "ostype": "l26", "bios": "ovmf",
           "machine": "q35", "scsihw": "virtio-scsi-single", "agent": "1", "onboot": 1,
           "cipassword": "**********", "affinity": "0-3", "hookscript": "local:snippets/x.pl",
           "efidisk0": "local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1,size=4M",
           "scsi0": "local-lvm:vm-100-disk-0,iothread=1,discard=on,serial=disk0,size=64G",
           "scsi1": "local-lvm:vm-100-disk-2,size=10752M",
           "net0": "virtio=BC:24:11:0A:00:01,bridge=vmbr0,tag=20,firewall=1",
           "net1": "e1000=BC:24:11:0A:00:02,bridge=vmbr0", "ide2": "local-lvm:vm-100-cloudinit,media=cdrom",
           "boot": "order=scsi0;ide2"}
    facts = {"flavor": "proxmox", "config": cfg, "cpus": 4, "cores": 4, "memory_mb": 8192, "firmware": "efi",
             "disks": [], "nics": [], "cdroms": [{"key": "ide2", "volume": "local-lvm:vm-100-cloudinit"}]}
    o = moveside.P._opts
    for k in ("scsi0", "scsi1"):
        x = o(cfg[k])
        facts["disks"].append({"key": k, "bytes": int(moveside.P._size_gib(x["size"]) * 1024 ** 3),
                               "opts": {a: x[a] for a in moveside.DISK_OPTS if a in x}})
    for k in ("net0", "net1"):
        x = o(cfg[k])
        m = next(mm for mm in moveside.PVE_MODELS if mm in x)
        facts["nics"].append({"key": k, "mac": x[m].lower(), "model": m, "network": "vmbr0",
                              "opts": {a: x[a] for a in moveside.NIC_OPTS if a in x}})
    nets = [{"network": "vmbr2", "vlan": "30"}, {"network": "vmbr2", "vlan": ""}]
    spec, where = moveside.pve_spec(facts, "proxmox", name="app-01-moving", storage="fast",
                                    nets=nets, transfer=TR, iso="local:iso/envmove-x.iso")
    check("disks on the chosen storage, options kept", spec["scsi0"] == "fast:64,iothread=1,discard=on,serial=disk0")
    check("a size that is not whole gibibytes", spec["scsi1"] == "fast:10.5")
    check("the card keeps its own address on the new network",
          spec["net0"] == "virtio=BC:24:11:0A:00:01,bridge=vmbr2,tag=30,firewall=1")
    check("the second card, its own model", spec["net1"].startswith("e1000=BC:24:11:0A:00:02,bridge=vmbr2"))
    check("the transfer card", spec[where["transfer"]] == "virtio=02:AA:BB:CC:DD:EE,bridge=vmbr1,tag=3999")
    check("the receiver CD on a free slot of its own", where["cd"] == "ide0" and spec["ide0"] == "local:iso/envmove-x.iso,media=cdrom")
    check("the cloud-init drive made again where it was", spec["ide2"] == "fast:cloudinit")
    check("starts from the CD", spec["boot"] == "order=ide0")
    check("the old boot order kept for after", where["boot"] == "order=scsi0;ide2")
    check("does not start with its host until done", spec["onboot"] == 0 and where["onboot"] == 1)
    check("Secure Boot off (the CD's loader is not signed)", "pre-enrolled-keys=0" in spec["efidisk0"])
    for k in ("cipassword", "affinity", "hookscript"):
        check(f"{k} not copied", k not in spec)
    check("same machine", spec["machine"] == "q35" and spec["bios"] == "ovmf" and spec["memory"] == 8192)
    # ESXi target from a Proxmox source
    xml = moveside.esxi_spec(facts, name="app-01-moving", datastore="datastore1",
                             nets=[{"network": "VM Network"}, {"network": "VM Network"}],
                             transfer={"dst_mac": "00:50:56:12:34:56", "dst_net": "Transfer"},
                             iso="[datastore1] envmove/envmove-x.iso")
    root = ET.fromstring('<c xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                         'xmlns:xsd="http://www.w3.org/2001/XMLSchema">' + xml + "</c>")
    check("ESXi spec is well-formed", root is not None)
    check("ESXi: the source's addresses, by hand", xml.count("<addressType>manual</addressType>") == 3
          and "bc:24:11:0a:00:01" in xml)
    check("ESXi: other hypervisors' addresses allowed card by card", "ethernet0.checkMACAddress" in xml
          and "ethernet1.checkMACAddress" in xml)
    check("ESXi: the CD carries the receiver", "[datastore1] envmove/envmove-x.iso" in xml)
    check("ESXi: starts from the CD", "VirtualMachineBootOptionsBootableCdromDevice" in xml)
    check("ESXi: UEFI kept", xml.endswith("<firmware>efi</firmware>"))
    check("ESXi: disks of the sizes", "<capacityInKB>67108864</capacityInKB>" in xml
          and "<capacityInKB>11010048</capacityInKB>" in xml)
    # ESXi to ESXi: the same slots and hardware version
    efacts = {"flavor": "esxi", "cpus": 4, "cores": 2, "memory_mb": 4096, "firmware": "bios", "hw_version": "vmx-19",
              "guest_id": "rhel9_64Guest",
              "controllers": [{"key": 1000, "type": "ParaVirtualSCSIController", "bus": 0, "slot": 160, "shared": "noSharing"}],
              "disks": [{"key": 2000, "bytes": 40 * 1024 ** 3, "ctrl_key": 1000, "unit": 0}],
              "nics": [{"key": 4000, "mac": "00:50:56:aa:bb:cc", "model": "VirtualVmxnet3", "slot": 192}]}
    xml2 = moveside.esxi_spec(efacts, name="db-01", datastore="ds2", nets=[{"network": "VM Network"}],
                              transfer={"dst_mac": "00:50:56:12:34:57", "dst_net": "VM Network"},
                              iso="[ds2] envmove/envmove-y.iso")
    check("ESXi→ESXi: controller in its slot", "<pciSlotNumber>160</pciSlotNumber>" in xml2)
    check("ESXi→ESXi: card in its slot", "<pciSlotNumber>192</pciSlotNumber>" in xml2)
    check("ESXi→ESXi: the hardware version", "<version>vmx-19</version>" in xml2)
    check("ESXi→ESXi: a VMware address needs no exception", "checkMACAddress" not in xml2)
    nic = xml2[xml2.index('<device xsi:type="VirtualVmxnet3">'):]
    check("ESXi: a card's slot comes after its connection (schema order)",
          nic.index("<connectable>") < nic.index("<slotInfo") < nic.index("<addressType>"))


def test_checks() -> None:
    good = {"arch": "x86_64", "uid": "0", "snapshot": "1", "lockdown": "[none] integrity confidentiality",
            "kernelfile": "1", "mkrx": "/usr/bin/dracut", "iptool": "/usr/sbin/ip", "gzip": "/usr/bin/gzip",
            "root": "/dev/sda2", "mount": ["plain /dev/sda2"], "busy": "0"}
    check("a plain guest passes", vmmove.guest_problems(good, cross=False) == [])
    check("across hypervisors a plain root does not", any("LVM" in w for w in vmmove.guest_problems(good, cross=True)))
    lv = {**good, "root": "/dev/mapper/rl-root", "mount": ["dm /dev/mapper/rl-root", "plain /dev/sda1"]}
    check("an LVM root with a plain /boot passes across", vmmove.guest_problems(lv, cross=True) == [])
    check("locked down", any("locked down" in w for w in vmmove.guest_problems({**good, "lockdown": "none [integrity] confidentiality"}, False)))
    check("no snapshot device", any("snapshot" in w for w in vmmove.guest_problems({**good, "snapshot": "0"}, False)))
    check("SELinux confining the agent", any("virt_qemu_ga_run_unconfined" in w for w in
                                              vmmove.guest_problems({**good, "selinux": "system_u:system_r:virt_qemu_ga_t:s0"}, False)))
    check("not root", any("root" in w for w in vmmove.guest_problems({**good, "uid": "1000"}, False)))
    kv = vmmove.parse_kv("arch=x86_64\nmount=dm /dev/mapper/a\nmount=plain /dev/sda1\nos=Alma Linux 9.4\n")
    check("key=value lines", kv["arch"] == "x86_64" and kv["mount"] == ["dm /dev/mapper/a", "plain /dev/sda1"]
          and kv["os"] == "Alma Linux 9.4")
    import ipaddress
    for _ in range(200):
        t = vmmove.transfer_addresses({})
        a, b = ipaddress.IPv4Address(t["src_ip"]), ipaddress.IPv4Address(t["dst_ip"])
        net = ipaddress.IPv4Network(f"{t['src_ip']}/30", strict=False)
        if not (a in ipaddress.IPv4Network("169.254.0.0/16") and b in net and a != b
                and t["src_ip"].split(".")[2] != "169" and a != net.network_address and b != net.broadcast_address):
            check(f"link-local /30 pair {t}", False)
            break
    try:
        vmmove.transfer_addresses({"transfer_mode": "routed", "src_cidr": "10.0.0.5", "dst_cidr": "x"})
        check("a routed address needs IP/BITS", False)
    except vmmove.MoveError:
        pass
    r = vmmove.transfer_addresses({"transfer_mode": "routed", "src_cidr": "10.1.0.5/24", "src_gw": "10.1.0.1",
                                   "dst_cidr": "10.2.0.7/23", "dst_gw": ""})
    check("routed addresses", r["src_ip"] == "10.1.0.5" and r["dst_prefix"] == 23 and r["src_gw"] == "10.1.0.1")
    check("transfer card addresses: VMware's manual range on ESXi",
          moveside.new_mac("esxi").startswith("00:50:56:") and int(moveside.new_mac("esxi")[9:11], 16) <= 0x3F)
    check("transfer card addresses: locally administered on Proxmox", moveside.new_mac("proxmox").startswith("02:"))


def _user(email: str, areas: list[str]) -> None:
    uid = auth.create_user(email, "Move Tester", PW, role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
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


def wait_end(c: TestClient, jid: str, limit: float = 90) -> dict:
    t0, j = time.time(), {}
    while time.time() - t0 < limit:
        r = c.get(f"/virt/moves/state?id={jid}").json()
        j = r.get("job") or {}
        if j.get("state") in ("done", "undone", "failed", "stuck") and not j.get("running"):
            return j
        time.sleep(0.3)
    return j


def test_move() -> None:
    pve = AgentPve().start()
    try:
        pve.guests[100]["config"].pop("efidisk0", None)
        conn = {"name": "lab-pve", "type": "proxmox", "base_url": pve.url, "username": "root@pam!envmap",
                "token": "pve-token-secret", "skip_tls": "1", "manage": "1"}
        cid = store.add_virt("", dict(conn))
        ro = store.add_virt("", {**conn, "name": "lab-pve-readonly", "manage": ""})
        _user("mover@example.com", ["virt", "virt_admin"])
        _user("looker@example.com", ["virt"])
        admin, looker = _client("mover@example.com"), _client("looker@example.com")
        form = {"c": cid, "vm": "100", "node": "pve-01", "to": cid, "dst_node": "pve-02",
                "storage": "local-lvm", "iso_storage": "local", "net0": "vmbr0", "vlan0": "20"}

        r = looker.post("/virt/move/check", json=form).json()
        check("a reader may not move", not r["ok"] and "administer" in r["error"].lower())
        check("the refusal is audited", audits("virt_vm_move_check_refused"))
        r = admin.post("/virt/move/check", json={**form, "to": ro}).json()
        check("a target that does not allow management refuses", not r["ok"] and "read-only" in r["error"])
        r = admin.post("/virt/move/check", data="c=x", headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("only a JSON body", r.status_code == 415)

        r = admin.post("/virt/move/check", json=form).json()
        check(f"the check passes ({r.get('error') or r.get('plan', {}).get('problems')})", r["ok"] and r["plan"]["ok"])
        if not (r["ok"] and r["plan"]["ok"]):
            return
        plan = r["plan"]
        check("the plan names the guest", "AlmaLinux" in plan["src"]["os"])
        check("Proxmox to Proxmox keeps the controllers", plan["cross"] is False)
        check("no token or sign-in in the plan", "token" not in json.dumps(plan).lower())
        check("the check is audited", audits("virt_vm_move_check"))

        r = admin.post("/virt/move/start", json=form).json()
        check(f"started ({r.get('error')})", r.get("ok"))
        jid = r.get("id", "")
        job = wait_end(admin, jid)
        check(f"moved (ended {job.get('state')}: {[e['text'] for e in job.get('log', [])][-4:]})", job.get("state") == "done")
        states = [e["text"] for e in job.get("log", [])]
        check("the arrival was seen by the new VM's agent", any("guest agent answers" in s for s in states))
        new = pve.move["dst"] if pve.move else 0
        nc = pve.guests.get(new, {}).get("config", {})
        check("the new VM carries the name", nc.get("name") == "app-01")
        check("its CD is out and its disk starts it", nc.get("ide2") == "none,media=cdrom" and nc.get("boot") == "order=scsi0")
        check("its transfer card is gone", not any(k.startswith("net3") for k in nc))
        check("its cards keep their addresses", nc.get("net0", "").startswith("virtio=BC:24:11:0A:00:01,bridge=vmbr0,tag=20"))
        check("it starts with its host again, as the old one did", nc.get("onboot") == 1)
        oc = pve.guests[100]["config"]
        check("the old VM is kept, renamed", oc.get("name", "").startswith("app-01-left-"))
        check("the old VM no longer starts with its host", oc.get("onboot") == 0)
        check("the old VM's transfer card is gone", not any(k.startswith("net3") for k in oc))
        check("the receiver CD is deleted", not any("envmove-" in c["volid"] for c in pve.content.get("local", [])))
        sent = pve.sent[0] if pve.sent else ""
        check("same hypervisor: controllers kept", "'-keep' 'auto'" in sent and "-repoint" not in sent)
        check("the move goes over the transfer card", "'-via'" in sent and "'-after'" in sent and "'-copy'" in sent)
        check("no token in the job page's data", "verdict" not in json.dumps(job.get("tokens") or {}) and "tokens" not in job)
        check("the start and the end are audited", audits("virt_vm_move") and audits("virt_vm_move_done"))
        check("the tokens are not on the guest's command line", "'-boottoken'" not in sent and "'-verdicttoken'" not in sent
              and "ENVMOVE_BOOTTOKEN=" in sent and "ENVMOVE_VERDICTTOKEN=" in sent)
        check("the engine's process id is kept in a file", f"> {vmmove.PIDFILE}" in sent)
        check("nothing asks pgrep, which matches its own shell", not any("pgrep" in sc for sc in pve.scripts))
        check("the transfer card is let through the guest's firewall",
              any("firewall-cmd --zone=trusted" in sc and "iptables -I INPUT -i" in sc for sc in pve.scripts))
        check("the verdict port is below the range of outgoing ports", vmmove.VERDICT_PORT < 32768)
        check("the old VM's cards are disconnected", "link_down=1" in oc.get("net0", ""))
        disk = json.loads((vmmove.MOVES / f"{jid}.json").read_text())
        check("the job file is the owner's alone", oct((vmmove.MOVES / f"{jid}.json").stat().st_mode & 0o777) == "0o600")
        check("no password in the job file", "password" not in json.dumps(disk).lower())

        # the guest calls it off: everything built for it goes
        pve.mode, pve.move, pve.sent = "thaw", None, []
        pve.guests[101].update(status="running")
        pve.guests[101]["config"].update(agent="1")
        before = set(pve.guests)
        f2 = {**form, "vm": "101", "dst_node": "pve-01"}
        r = admin.post("/virt/move/start", json=f2).json()
        check(f"second move started ({r.get('error')})", r.get("ok"))
        job = wait_end(admin, r.get("id", ""))
        check(f"undone ({job.get('state')})", job.get("state") == "undone")
        check("the new VM was removed", set(pve.guests) == before)
        check("the VM still runs where it was", pve.guests[101]["status"] == "running")
        check("its transfer card was taken out", not any(k.startswith("net3") for k in pve.guests[101]["config"]))
        check("the CD was deleted", not any("envmove-" in c["volid"] for c in pve.content.get("local", [])))
        check("the undo is audited", audits("virt_vm_move_undone"))

        # Proxmox HA would start the old copy again: refused before anything is made
        pve.ha = [{"sid": "vm:101", "state": "started"}]
        r = admin.post("/virt/move/check", json=f2).json()
        check("an HA-managed VM is refused", r.get("ok") and any("HA" in w for w in r["plan"]["problems"]))
        pve.ha = []

        # once the engine runs, a failure never takes the new VM away
        pve.mode, pve.move = "arrive", None
        pve.guests[300] = {"node": "pve-01", "kind": "qemu", "status": "running", "snapshots": [],
                           "config": {"name": "test-vm-07-moving", "cores": 2, "memory": 4096, "agent": "1"}}
        fake = {"id": "a1b2c3d4e5f6", "created": time.time(), "state": "copying",
                "by": {"id": "", "email": "mover@example.com", "name": "Mover"},
                "src": {"conn": cid, "conn_name": "lab-pve", "flavor": "proxmox", "node": "pve-01", "vm": "101",
                        "name": "test-vm-07", "production": False},
                "dst": {"conn": cid, "conn_name": "lab-pve", "flavor": "proxmox", "node": "pve-01",
                        "production": False},
                "transfer": {}, "cross": False, "built": {"vm": "300", "iso": "local:iso/x.iso", "scard": "net31"},
                "times": {}, "log": [], "tokens": {"boot": "b" * 32, "verdict": "v" * 32}}
        vmmove.save(dict(fake))
        vmmove._after_failure(dict(fake), "a call timed out")
        j = vmmove.load(fake["id"])
        check(f"a failure while copying leaves it for a person ({j.get('state')})", j.get("state") == "stuck")
        check("…and the new VM is still there", 300 in pve.guests)
        # the decisions refuse what would lose the system
        r = admin.post("/virt/moves/decide", json={"id": fake["id"], "what": "keep"}).json()
        check(f"keep is refused while the old copy answers ({r.get('error')})", not r["ok"] and "answers" in r["error"])
        r = admin.post("/virt/moves/decide", json={"id": fake["id"], "what": "back"}).json()
        check(f"back is refused while the system answers on the new VM ({r.get('error')})",
              not r["ok"] and "runs there" in r["error"])
        r = looker.post("/virt/moves/decide", json={"id": fake["id"], "what": "keep"}).json()
        check("a reader may not decide", not r.get("ok"))
        vmmove.update(dict(fake), lambda c: c.update(state="undone"))
        del pve.guests[300]

        # pages
        for path in ("/virt/moves", f"/virt/moves/job?id={jid}", "/virt/move?c=" + cid + "&vm=100&node=pve-01"):
            g = admin.get(path)
            check(f"{path} renders ({g.status_code})", g.status_code == 200)
        g = admin.get(f"/virt/vm?c={cid}&vm=101&node=pve-01&kind=qemu").text
        check("the VM page offers the move", "/virt/move?c=" in g and "Move while running" in g)
        g = looker.get(f"/virt/vm?c={cid}&vm=101&node=pve-01&kind=qemu").text
        check("…greyed for a reader", "Move while running</button>" in g)
        g = looker.get("/virt/move?c=" + cid + "&vm=101&node=pve-01").text
        check("the move page tells a reader why not", "Administer" in g or "not include" in g)
    finally:
        pve.stop()


def main() -> int:
    make_parts()
    for t in (test_iso, test_receiver, test_specs, test_checks, test_move):
        try:
            t()
        except Exception as e:                                # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(f"{t.__name__} raised {e!r}", False)
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main())
