"""EnvMap Move on ESXi hosts with the free licence (app/esxshell.py).

On that licence VMware's API reads and refuses everything else, so EnvMap
works on the host through its shell over SSH and reaches the guest over SSH.

  1. the .vmx file of the new VM, and the edits to an old one
  2. one command over SSH: the password handed over the way ssh takes it and
     never written down, one sign-in attempt per call, the host's key written
     down at the first contact and held to afterwards
  3. which road a host gets, from its licence, and that a licence which
     cannot be read is never guessed at
  4. a whole move between two free hosts, with the API refusing every change:
     nothing is even asked of it
  5. a move the guest calls off: what was built is taken away again
  6. a move brought back by a person: the new VM starts from the CD again,
     not from the copy on its disks
  7. a move that dies while the new VM is being made, or while the transfer
     card is being added: what exists of it is taken away, and nothing else
  8. what the check says when the road is closed
  9. the pages: the guest's address, the keys and forgetting one
 10. what is read back from the host: a VM that is gone, a host that cannot
     be read, a power-off that is not needed

    ./.venv/bin/python tests/test_esxshell.py

The far end is tests/_fake_esxshell.py. It has not been a real ESXi host: the
command forms are VMware's documented ones, not ones seen to work. Sections 6
and 7 exist because an independent review found, before any real run, that a
reset started the copy and that a failed build could unregister somebody
else's VM. A second review of those fixes found ten more, each with a check
here: a new VM switched off and on by hand before "Bring it back" (its
transfer card stayed off), a new VM registered just before EnvMap stopped, a
VM registered without its CD or its transfer card, an IPv6 guest address, the
way of signing in that worked tried first, what sudo said, which stray cards
are EnvMap's, and a key that replaces another said so. A third read found
that the clean-up took "the new VM is gone" from the words of a sentence
(sections 6b and 7: a datastore that cannot be looked into, a VM already
gone, another move's folder), that the log said the receiver CD was harmless
before its image had been emptied (6b), and five checks here that passed with
their fix removed; those are rewritten.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("esxshell-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
PARTS = pathlib.Path(tempfile.mkdtemp(prefix="esxshell-parts-"))
os.environ["PORTAL_ENVMOVE_DIR"] = str(PARTS)

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_esxi import FakeEsxi, free_licence                  # noqa: E402
from _fake_esxshell import EsxiShell, Guest, SshWorld          # noqa: E402
from app import auth, db, env, esxshell, moveside, pam, rbac, store, virt, vmmove   # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Free-Hosts-Move-Too-42"


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def make_parts() -> None:
    (PARTS / "rx" / "mods").mkdir(parents=True, exist_ok=True)
    (PARTS / "envmove").write_bytes(b"\x7fELF" + b"fake envmove engine " * 4000)
    for n, d in (("vmlinuz", b"MZ kernel" * 300), ("initrd", b"initrd" * 500), ("isolinux.bin", bytes(2048)),
                 ("ldlinux.c32", b"ld" * 100), ("efi.img", bytes(2880 * 512)), ("bootx64.efi", b"MZ efi" * 50)):
        (PARTS / "rx" / n).write_bytes(d)
    for n in ("failover.ko", "virtio_net.ko", "vmxnet3.ko"):
        (PARTS / "rx" / "mods" / n).write_bytes(b"\x7fELF" + n.encode())
    (PARTS / "rx" / "mods" / "order").write_text("failover.ko\nvirtio_net.ko\nvmxnet3.ko\n")


def _user(email: str, areas: list[str]) -> None:
    uid = auth.create_user(email, "Shell Tester", PW, role="user")
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


def wait_for(c: TestClient, jid: str, states: tuple, limit: float = 120) -> dict:
    t0, j = time.time(), {}
    while time.time() - t0 < limit:
        j = (c.get(f"/virt/moves/state?id={jid}").json().get("job")) or {}
        if j.get("state") in states and (j.get("state") not in ("done", "undone", "failed") or not j.get("running")):
            return j
        time.sleep(0.3)
    return j


def wait_end(c: TestClient, jid: str, limit: float = 120) -> dict:
    return wait_for(c, jid, ("done", "undone", "failed", "stuck"), limit)


def form_for(ca: dict, cb: dict, vm: str, **more) -> dict:
    return {"c": ca["id"], "vm": vm, "node": "", "to": cb["id"], "storage": "datastore1", "net0": "VM Network",
            "guest_user": "root", "guest_password": "guest-password", **more}


def another_vm(host: FakeEsxi, moid: str, name: str, ip: str) -> None:
    """One more running VM on a stand-in host, shaped like its k8s-worker-07."""
    host.vms[moid] = dict(host.vms["3"], name=name, ip=ip,
                          devices=[dict(d) for d in host.vms["3"]["devices"] if d["key"] in (100, 1000, 15000, 2000, 4000, 16000)])


# ── 1. the .vmx file ───────────────────────────────────────────
TR = {"dst_mac": "00:50:56:1a:2b:3c", "dst_net": "Transfer"}


def test_text() -> None:
    for api, vmx in (("rhel9_64Guest", "rhel9-64"), ("otherLinux64Guest", "otherlinux-64"), ("ubuntu64Guest", "ubuntu-64"),
                     ("almalinux_64Guest", "almalinux-64"), ("debian12_64Guest", "debian12-64"), ("rhel6Guest", "rhel6"),
                     ("vmwarePhoton64Guest", "vmware-photon-64"), ("", "otherlinux-64"), ('x" y', "otherlinux-64")):
        check(f"guest type {api!r} is {vmx} in a .vmx", esxshell.vmx_guest(api) == vmx)
    src = {"flavor": "esxi", "cpus": 4, "cores": 2, "memory_mb": 4096, "firmware": "efi", "hw_version": "vmx-19",
           "guest_id": "rhel9_64Guest",
           "controllers": [{"key": 1000, "type": "ParaVirtualSCSIController", "bus": 0, "slot": 160, "shared": "noSharing"},
                           {"key": 15000, "type": "VirtualAHCIController", "bus": 0, "slot": 33, "shared": "noSharing"}],
           "disks": [{"key": 2000, "bytes": 64 * 1024 ** 3, "ctrl_key": 1000, "unit": 0},
                     {"key": 2001, "bytes": 10 * 1024 ** 3 + 512, "ctrl_key": 1000, "unit": 1}],
           "nics": [{"key": 4000, "mac": "00:0C:29:B9:7D:6F", "model": "VirtualVmxnet3", "slot": 192},
                    {"key": 4001, "mac": "00:50:56:01:02:03", "model": "VirtualE1000e", "slot": 224}]}
    text, disks = esxshell.vmx_text(src, name="db-01", stem="db-01", nets=[{"network": "V12"}, {"network": "DB Network"}],
                                    transfer=TR, iso_file="/vmfs/volumes/ds2/envmove/envmove-abc123.iso", hw="19")
    v = dict(line.split(" = ", 1) for line in text.splitlines())
    v = {k: val.strip('"') for k, val in v.items()}
    check("the hardware version of the source", v.get("virtualHW.version") == "19")
    check("processors, cores and memory", (v.get("numvcpus"), v.get("cpuid.coresPerSocket"), v.get("memSize")) == ("4", "2", "4096"))
    check("UEFI kept, Secure Boot off", v.get("firmware") == "efi" and v.get("uefi.secureBoot.enabled") == "FALSE")
    check("it starts from the CD before the disk, at every start", v.get("bios.bootOrder") == "cdrom,hdd")
    check("the controller in its slot", v.get("scsi0.virtualDev") == "pvscsi" and v.get("scsi0.pciSlotNumber") == "160")
    check("the SATA controller in its slot", v.get("sata0.present") == "TRUE" and v.get("sata0.pciSlotNumber") == "33")
    check("the slots have a bridge to sit behind", v.get("pciBridge4.virtualDev") == "pcieRootPort")
    check("disks of the same sizes, to the kibibyte", disks == [("db-01.vmdk", 64 * 1024 ** 2), ("db-01_1.vmdk", 10 * 1024 ** 2 + 1)])
    check("disks on the same units", v.get("scsi0:0.fileName") == "db-01.vmdk" and v.get("scsi0:1.fileName") == "db-01_1.vmdk")
    check("every card keeps its address, set by hand", v.get("ethernet0.address") == "00:0c:29:b9:7d:6f"
          and v.get("ethernet0.addressType") == "static" and v.get("ethernet1.address") == "00:50:56:01:02:03")
    check("an address outside VMware's range for hand-set ones is allowed card by card",
          v.get("ethernet0.checkMACAddress") == "FALSE" and "ethernet1.checkMACAddress" not in v)
    check("cards in their slots and models", v.get("ethernet0.pciSlotNumber") == "192" and v.get("ethernet1.virtualDev") == "e1000e")
    check("cards on the networks chosen for the target", v.get("ethernet0.networkName") == "V12")
    check("the VM's own cards connect at power-on", v.get("ethernet0.startConnected") == "TRUE" and v.get("ethernet1.startConnected") == "TRUE")
    check("the transfer card comes last, and does not connect at power-on by itself",
          v.get("ethernet2.address") == "00:50:56:1a:2b:3c" and v.get("ethernet2.networkName") == "Transfer"
          and v.get("ethernet2.startConnected") == "FALSE")
    check("the receiver CD on the SATA controller the VM has", v.get("sata0:29.deviceType") == "cdrom-image"
          and v.get("sata0:29.fileName") == "/vmfs/volumes/ds2/envmove/envmove-abc123.iso" and "sata3.present" not in v)
    pve = {"flavor": "proxmox", "cpus": 2, "cores": 2, "memory_mb": 2048, "firmware": "bios",
           "disks": [{"key": "scsi0", "bytes": 8 * 1024 ** 3}], "controllers": [],
           "nics": [{"key": "net0", "mac": "BC:24:11:0A:00:01", "model": "virtio"}]}
    text, disks = esxshell.vmx_text(pve, name="app", stem="app", nets=[{"network": "VM Network"}], transfer=TR,
                                    iso_file="/vmfs/volumes/datastore1/envmove/envmove-abc123.iso", hw="20")
    check("from Proxmox: one paravirtual controller, VMXNET3 cards, a SATA controller for the CD",
          'scsi0.virtualDev = "pvscsi"' in text and 'ethernet0.virtualDev = "vmxnet3"' in text
          and 'sata3:29.deviceType = "cdrom-image"' in text and 'guestOS = "otherlinux-64"' in text)
    try:
        esxshell.vmx_text({**pve, "disks": [{"key": "x", "bytes": 1}] * 16}, name="a", stem="a", nets=[{"network": "n"}],
                          transfer=TR, iso_file="/x", hw="20")
        check("more disks than a controller holds are refused", False)
    except virt.VirtError:
        pass
    try:
        esxshell.vmx_text(pve, name='a"b', stem="a", nets=[{"network": "VM Network"}], transfer=TR, iso_file="/x", hw="20")
        check("a name that would break out of its quotes is refused", False)
    except virt.VirtError:
        pass
    old = 'displayName = "web"\nethernet0.present = "TRUE"\nethernet0.startConnected = "TRUE"\nethernet1.present = "TRUE"\n' \
          'ethernet1.address = "00:0c:29:00:00:01"\nEthernet10.present = "true"\n'
    check("the cards of a .vmx", esxshell.vmx_cards(old) == [0, 1, 10])
    new = esxshell.vmx_set(old, {"displayName": "web-left", "ethernet0.startConnected": "FALSE", "ethernet1.startConnected": "FALSE"})
    check("a key is replaced where it is, added where it is not",
          'displayName = "web-left"' in new and new.count("ethernet0.startConnected") == 1
          and 'ethernet1.startConnected = "FALSE"' in new and 'displayName = "web"\n' not in new)
    check("a card is found by its address, whichever way it was given", esxshell.vmx_card_with(old, "00:0C:29:00:00:01") == 1
          and esxshell.vmx_card_with(old + 'ethernet10.generatedAddress = "00:0c:29:aa:bb:cc"\n', "00:0c:29:aa:bb:cc") == 10
          and esxshell.vmx_card_with(old, "00:0c:29:00:00:02") is None)
    gone = esxshell.vmx_drop(old, "ethernet1.")
    check("a card is taken out whole, and only that card", "ethernet1." not in gone and "Ethernet10.present" in gone)


# ── 2. one command over SSH ────────────────────────────────────
def test_transport(world: SshWorld, a: EsxiShell, conn: dict) -> None:
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first",
                                       who="mover@example.com")
    check(f"a command runs and answers ({code} {err})", code == 0 and b"web-01" in out)
    check("the first contact writes the host's key down", len(new) == 1 and new[0].startswith("ED25519 SHA256:")
          and (pam.host_pin("t:first") or {}).get("fingerprints") == new)
    check("and that is audited at once, under the person's name",
          any(new and new[0] in (r["detail"] or "") for r in audits("virt_move_ssh_key_pinned")))
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("the second contact is held to that key and writes nothing new", code == 0 and new == [])
    check("the password is never part of the command", not any("lab-password" in c for _h, _u, c in world.seen))
    check("the password is in no file while ssh runs: a stopped process leaves none behind",
          world.requests and not any(r["on_disk"] for r in world.requests))
    check("ssh reads no configuration file of its own", all(r["config"] == "/dev/null" for r in world.requests))
    before, real = len(a.log), a.key
    a.key = a.key[:-8] + "AAAAAAA="
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("another key is refused, and the command never reaches that machine", code == 255 and len(a.log) == before)
    check("in words that say what happened and who can settle it",
          "not the one EnvMap wrote down" in esxshell.why_not(err, 22) and "Moves page" in esxshell.why_not(err, 22))
    a.key = real
    tries = a.attempts
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "wrong", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("a wrong password is a refused sign-in", code == 255 and "sign-in was refused" in esxshell.why_not(err, 22))
    check(f"and costs one failed attempt there, not one per way of signing in ({a.attempts - tries})", a.attempts - tries == 1)
    a.offers, tries = ("publickey", "keyboard-interactive", "password"), a.attempts
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "wrong", "vim-cmd vmsvc/getallvms", pin="t:first")
    check(f"also where both ways of signing in are open: one failed attempt, not two ({a.attempts - tries})",
          code == 255 and a.attempts - tries == 1)
    a.offers, tries = ("publickey", "password"), a.attempts
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("a host that only takes the other way of signing in is still signed in to, in one attempt",
          code == 0 and a.attempts - tries == 1)
    seen = len(world.requests)
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check(f"the way that worked there is tried first the next time: one connection, not two ({len(world.requests) - seen})",
          code == 0 and len(world.requests) - seen == 1 and world.requests[-1]["method"] == "password")
    a.offers, tries = ("publickey", "keyboard-interactive"), a.attempts
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("and when the host stops taking that way, the other is found again, still in one attempt",
          code == 0 and a.attempts - tries == 1)
    a.up = False
    code, out, err, new = esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:first")
    check("a host that does not answer", code == 255 and "does not answer from EnvMap" in esxshell.why_not(err, 22))
    a.up = True
    for host, user, why in (("-oProxyCommand=id", "root", "an option"), ("127.0.0.1", "-lroot", "an option as the user"),
                            ("127.0.0.1", "root;id", "a shell character"), ("169.254.169.254", "root", "the metadata address"),
                            ("a b", "root", "a space")):
        try:
            esxshell.ssh(host, 22, user, "x", "id", pin="t:x")
            check(f"{why} is not a place SSH is pointed at", False)
        except esxshell.ShellError:
            pass
    check("nothing of those reached any machine", not any(u != "root" for _h, u, _c in world.seen))
    # the same target at another address is a first contact, and the audit line says which key it replaces
    world.ends["10.20.9.9"] = a
    esxshell.ssh("127.0.0.1", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:moved", who="mover@example.com")
    code, out, err, new = esxshell.ssh("10.20.9.9", 22, "root", "lab-password", "vim-cmd vmsvc/getallvms", pin="t:moved",
                                       who="mover@example.com")
    said = [r["detail"] or "" for r in audits("virt_move_ssh_key_pinned") if "t:moved" in (r["detail"] or "")]
    check(f"a key written down in place of another says which one it replaces ({said})", code == 0 and len(new) == 1
          and len(said) == 2 and "replaces" not in said[0] and "it replaces the key written down for 127.0.0.1:22" in said[1])
    del world.ends["10.20.9.9"]
    # a file is whole where it is put, or not there at all
    side = esxshell.EsxiShell(conn, "1")
    a.dirs.add("/vmfs/volumes/datastore1/t")
    side._write("/vmfs/volumes/datastore1/t/x.vmx", b"first\n" * 50)
    a.cut_next_upload = True
    try:
        side._write("/vmfs/volumes/datastore1/t/x.vmx", b"second\n" * 50)
        check("a file that arrives cut short is refused", False)
    except esxshell.ShellError:
        pass
    check("and what was there before is still there, untouched", a.files.get("/vmfs/volumes/datastore1/t/x.vmx") == b"first\n" * 50
          and "/vmfs/volumes/datastore1/t/x.vmx.envmap" not in a.files)
    for path, ok in (("[datastore1] web01,eu/web01,eu.vmx", True), ("[datastore1] büro (1)/a@b#c.vmx", True),
                     ("[datastore1] a/../../etc/passwd", False), ("[datastore1] a\nb/x.vmx", False), ("no brackets", False)):
        try:
            side._vol(path)
            check(f"the path {path!r} is refused", ok)
        except virt.VirtError:
            check(f"an ordinary folder name is taken: {path!r}", not ok)


# ── 3. which road ──────────────────────────────────────────────
def test_roads(free_conn: dict, paid_conn: dict, a: FakeEsxi, c: FakeEsxi) -> None:
    check("a free licence is read as one", esxshell.restricted(free_conn)
          and esxshell.licence(free_conn)["name"] == "vSphere 8 Hypervisor")
    check("a paid licence is not", not esxshell.restricted(paid_conn))
    check("a free host is worked through its shell", isinstance(vmmove.side(free_conn, "", "1"), esxshell.EsxiShell)
          and vmmove.side(free_conn, "", "1").road == "shell")
    check("a licensed host through the API, as before", type(vmmove.side(paid_conn, "", "1")) is moveside.Esxi
          and vmmove.side(paid_conn, "", "1").road == "api")
    try:
        moveside.Esxi(free_conn, "1").stop()
        check("the API refuses a change on the free licence", False)
    except virt.VirtError as e:
        check(f"and EnvMap says why in its own words, not VMware's ({e})",
              "read-only" in str(e) and "prohibits" not in str(e) and "licence" in str(e))
    a.refused.clear()
    # a licence that cannot be read is not guessed at, and the failure is not remembered
    esxshell._lic.clear()
    a.fail_next["RetrievePropertiesEx"] = ("HostCommunication", "the host is not answering")
    try:
        vmmove.side(free_conn, "", "1")
        check("a host whose licence cannot be read is not handed to the API by default", False)
    except virt.VirtError as e:
        check(f"it says the licence could not be read ({e})", "licence could not be read" in str(e))
    check("the next read is a fresh one, and right", esxshell.restricted(free_conn))
    kept, c.licence = c.licence, ("", "")
    esxshell._lic.clear()
    try:
        vmmove.side(paid_conn, "", "1")
        check("a host that shows no licence is not guessed at either", False)
    except virt.VirtError as e:
        check(f"a host that shows its licence to nobody says what that is, and what to look at ({e})",
              "shows no licence to the account" in str(e) and "Global.Licenses" in str(e))
    c.licence = kept
    esxshell._lic.clear()
    # a move in progress carries its road, and does not ask the host again
    esxshell._lic.clear()
    job = {"id": "x" * 12, "state": "copying", "built": {"vm": "1", "tcard": "4001", "vmx": "[datastore1] a/a.vmx", "cd": "16029"},
           "src": {"conn": free_conn["id"], "node": "", "vm": "1", "road": "shell", "guest_at": "10.20.0.21:2222"},
           "dst": {"conn": free_conn["id"], "node": "", "road": "shell"}}
    calls = len(a.calls)
    src, dst = vmmove._sides(job)
    check("a move in progress is given the road it was checked with, without asking the host for its licence",
          src.road == "shell" and dst.road == "shell" and len(a.calls) == calls)
    check("and the guest's address it was checked with", src._guest() == ("10.20.0.21", 2222) and len(a.calls) == calls)
    check("the new VM's side knows its transfer card, its CD and the file that makes it EnvMap's",
          (dst.tcard, dst.cd, dst.made_vmx) == ("4001", "16029", "[datastore1] a/a.vmx"))
    job["src"]["guest_at"] = "[fd00:20::10]:2222"
    src, dst = vmmove._sides(job)
    check("an IPv6 guest address comes back as the address and the port it was",
          src._guest() == ("fd00:20::10", 2222) and src.guest_address() == "[fd00:20::10]:2222")
    for text, want in (("[fd00:20::10]", ("fd00:20::10", 22)), ("fd00:20::10", ("fd00:20::10", 22)),
                       ("10.20.0.21", ("10.20.0.21", 22)), ("10.20.0.21:2022", ("10.20.0.21", 2022))):
        at = esxshell.EsxiShell(free_conn, "1", guest_host=text, guest_fixed=True)
        check(f"the guest address {text!r} is read as {want}", at._guest() == want)
        again = esxshell.EsxiShell(free_conn, "1", guest_host=at.guest_address(), guest_fixed=True)
        check(f"and {at.guest_address()!r}, as the move keeps it, is read as the same", again._guest() == want)


# ── 4. a whole move ────────────────────────────────────────────
def test_move(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
              world: SshWorld) -> None:
    src_vm = a.vms["1"]
    next(d for d in src_vm["devices"] if d["type"] == "ParaVirtualSCSIController")["slot"] = 160
    nic = next(d for d in src_vm["devices"] if d["type"] == "VirtualVmxnet3")
    nic["slot"] = 192
    # long enough for the whole log to be read before the freeze, on a machine that is busy with other things too
    guest = Guest("10.20.0.21", a, "1", b, sb, freeze_at=9.0, end_at=11.0)
    guest.noise = "Welcome to web-01\nLast login: Thu Nov 26 09:12:01 2026\n"     # what a login shell prints first
    pam.forget_pin(f"move:host:{ca['id']}")                 # the transport test above met host a already
    world.ends["10.20.0.21"] = guest
    sb.dirs.add("/vmfs/volumes/datastore1/web-01")          # a folder of that name is there already
    form = form_for(ca, cb, "1")
    pins = len(audits("virt_move_ssh_key_pinned"))
    r = admin.post("/virt/move/check", json=form).json()
    plan = r.get("plan") or {}
    check(f"the check passes between two free hosts ({r.get('error') or plan.get('problems')})", r.get("ok") and plan.get("ok"))
    if not plan.get("ok"):
        return
    notes = " | ".join(plan["notes"])
    check("it says both hosts are worked through their shell", notes.count("through its own shell over SSH") == 2
          and "vSphere 8 Hypervisor" in notes)
    check("it says which keys it wrote down: two hosts and the guest",
          notes.count("first SSH contact") == 3 and "ED25519 SHA256:" in notes)
    check(f"writing a key down is audited ({len(audits('virt_move_ssh_key_pinned')) - pins})",
          len(audits("virt_move_ssh_key_pinned")) - pins == 3)
    check("the guest was read over SSH, past what its login shell prints", "AlmaLinux" in plan["src"]["os"])
    check("the plan keeps the road of each host and where the guest's SSH is",
          plan["src"]["road"] == "shell" and plan["dst"]["road"] == "shell" and plan["src"]["guest_at"] == "10.20.0.21:22")
    check("no password in the plan", "guest-password" not in str(plan) and "lab-password" not in str(plan))
    check("the check asked the API for no change", a.refused == [] and b.refused == [])

    r = admin.post("/virt/move/start", json=form).json()
    check(f"started ({r.get('error')})", r.get("ok"))
    job = wait_end(admin, r.get("id", ""))
    log = [e["text"] for e in job.get("log", [])]
    check(f"moved (ended {job.get('state')}: {log[-4:]})", job.get("state") == "done")
    check("the API was asked for no change at all, on either host", a.refused == [] and b.refused == [])
    new_id = max(b.vms, key=lambda k: int(k))
    new = b.vms[new_id]
    v = new.get("vmx_keys") or {}
    check("the new VM carries the VM's name from the start", new["name"] == "web-01" and v.get("displayName") == "web-01")
    check("a taken folder name is stepped aside from", new["vmx"].startswith("[datastore1] web-01-") and new["vmx"].endswith("/web-01.vmx"))
    check("the folder EnvMap stepped aside from was not touched", "/vmfs/volumes/datastore1/web-01" in sb.dirs)
    check("it runs", new["power"] == "poweredOn")
    check("it started from the receiver CD", sb.boots[:1] == [(new_id, "receiver")])
    check("the controller and the card sit where they sat", v.get("scsi0.pciSlotNumber") == "160" and v.get("ethernet0.pciSlotNumber") == "192")
    check("the card keeps its address", v.get("ethernet0.address") == nic["mac"].lower())
    check("the same hardware version and firmware", v.get("virtualHW.version") == "21" and v.get("firmware") == "efi")
    check("the same guest type", v.get("guestOS") == "almalinux-64")
    folder = sb.vmx_path(new).rsplit("/", 1)[0]
    check("a blank disk of the same size", int(sb.files[folder + "/web-01-flat.vmdk"]) == 60 * 1048576)
    check("the mark that made the folder EnvMap's while it was being filled is gone", not any("/.envmap-" in k for k in sb.files))
    cd = next(d for d in new["devices"] if d["type"] == "VirtualCdrom")
    iso = [k for k in sb.files if "/envmove/envmove-" in k]
    check("its receiver CD is disconnected, and the log says disconnected and emptied, not taken out or deleted",
          cd["connected"] is False and any("receiver CD disconnected and its image emptied" in t for t in log)
          and "the receiver CD taken out" not in log and "the receiver CD deleted" not in log)
    check("the CD's image is emptied, not deleted, so ESXi has nothing to ask at the next power-on",
          len(iso) == 1 and sb.files[iso[0]] == bytes(64 * 1024))
    tcard = next(d for d in new["devices"] if d.get("mac") == job["transfer"]["dst_mac"])
    check("its transfer card was connected by hand after the start",
          any(c == f"vim-cmd vmsvc/device.connection {new_id} {tcard['key']} 1" for c in sb.log))
    check("and is disconnected now, and the log says it stays so", tcard["connected"] is False
          and any("It stays disconnected" in t for t in log))
    old = a.vms["1"]
    check("the old copy is off, kept and renamed", old["power"] == "poweredOff" and old["name"].startswith("web-01-left-"))
    old_nics = [d for d in old["devices"] if d["type"] == "VirtualVmxnet3"]
    check("the old VM's transfer card is out", len(old_nics) == 1 and old_nics[0]["key"] == 4000)
    check("the old VM's card will not connect at power-on", old_nics[0].get("start_connected") is False)
    real_mac = job["transfer"]["src_mac"]
    check("the move went over the card with the address VMware gave it", real_mac.startswith("00:0c:29:")
          and guest.sent and f"'-via' '{real_mac}'" in guest.sent[0])
    check("same hypervisor: controllers kept", "'-keep' 'auto'" in guest.sent[0])
    check("the guest was looked for by that address", any(f"grep -l -i -x {real_mac} " in s for s in guest.scripts))
    check("the transfer card was added through the shell", any(c.startswith("vim-cmd vmsvc/devices.createnic 1 vmxnet3") for c in sa.log))
    check("no password reached a command line", not any("guest-password" in c or "lab-password" in c for _h, _u, c in world.seen))
    check("no password was in a file at any time", not any(r["on_disk"] for r in world.requests))
    check("the tokens are in the environment, not on the command line", "ENVMOVE_BOOTTOKEN=" in guest.sent[0] and "-boottoken" not in guest.sent[0])
    check(f"the engine's log is read once, line by line, whatever the login shell prints ({[t for t in log if 'sent 812' in t or 'every range' in t]})",
          len([t for t in log if t == "disks: pass 1 sent 812 MiB"]) == 1
          and len([t for t in log if t.startswith("receiver: memory: every range")]) == 1
          and not any("Welcome to web-01" in t or "Last login" in t for t in log))
    check("the log says how the start order stands once the image is empty, and does not claim the disk was made the start device",
          any("stays first in the VM's start order" in t and "has nothing to start" in t for t in log)
          and "the disk made the start device" not in log)
    check("the folder's mark goes when the move is over, and that is said", any("folder is its own now" in t for t in log))
    check("the end is audited", audits("virt_vm_move_done"))
    # switched off and on again later, by anybody: the transfer card stays off, the VM starts from its disk
    sb.run(f"vim-cmd vmsvc/power.off {new_id}", b"")
    sb.copied.add(new_id)
    sb.run(f"vim-cmd vmsvc/power.on {new_id}", b"")
    check("after a later power-off and power-on the transfer card stays disconnected", tcard["connected"] is False)
    check("and the VM starts from its disk: the emptied CD has nothing to start", sb.boots[-1] == (new_id, "disk"))


# ── 5. a move called off ───────────────────────────────────────
def test_undo(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
              world: SshWorld) -> None:
    guest = Guest("10.20.0.47", a, "3", b, sb)
    guest.mode = "thaw"
    world.ends["10.20.0.47"] = guest
    before = set(b.vms)
    r = admin.post("/virt/move/start", json=form_for(ca, cb, "3")).json()
    check(f"a second move starts ({r.get('error')})", r.get("ok"))
    job = wait_end(admin, r.get("id", ""))
    log = [e["text"] for e in job.get("log", [])]
    check(f"called off by the guest, it ends undone (ended {job.get('state')}: {log[-4:]})", job.get("state") == "undone")
    check("the new VM is gone", set(b.vms) == before)
    check("so are its files and its receiver CD", not any("k8s-worker-07" in k or f"envmove-{job.get('id')}" in k for k in sb.files))
    check("the log says what was taken away", any("what had been made of the new VM taken away" in t for t in log))
    old = a.vms["3"]
    check("the VM runs where it was, under its name", old["power"] == "poweredOn" and old["name"] == "k8s-worker-07")
    card = [d for d in old["devices"] if d["type"] == "VirtualVmxnet3" and d["key"] != 4000]
    check("its transfer card is disconnected, and the log says it comes back at the next power-on unless removed",
          len(card) == 1 and card[0]["connected"] is False and any("connects again when the VM is next powered on" in t for t in log))
    check("still no change asked of the API", a.refused == [] and b.refused == [])


# ── 6. a move brought back by a person ─────────────────────────
def test_back(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
              world: SshWorld) -> None:
    another_vm(a, "5", "queue-02", "10.20.0.60")
    guest = Guest("10.20.0.60", a, "5", b, sb)
    guest.mode = "hang"
    world.ends["10.20.0.60"] = guest
    before = set(b.vms)
    r = admin.post("/virt/move/start", json=form_for(ca, cb, "5")).json()
    check(f"a third move starts ({r.get('error')})", r.get("ok"))
    jid = r.get("id", "")
    job = wait_for(admin, jid, ("frozen", "stuck", "done", "undone", "failed"), 90)
    check(f"it freezes and stays frozen ({job.get('state')})", job.get("state") == "frozen")
    new_id = max(b.vms, key=lambda k: int(k))
    check("by then the new VM's disks hold a copy of the system", new_id in sb.copied and new_id not in before)
    # somebody switches the new VM off and on in between: its transfer card does not connect by itself
    sb.run(f"vim-cmd vmsvc/power.off {new_id}", b"")
    sb.run(f"vim-cmd vmsvc/power.on {new_id}", b"")
    tcard = next(d for d in b.vms[new_id]["devices"] if "mac" in d and d.get("start_connected") is False)
    time.sleep(1.0)
    check("switched off and on by hand, the new VM runs its receiver with the transfer card disconnected",
          sb.boots[-1] == (new_id, "receiver") and tcard["connected"] is False)
    check("so its receiver reaches nobody, and the system stays frozen", a.vms["5"]["tools"] != "guestToolsRunning")
    # and somebody set its CD not to connect at power-on: a start without the CD would run the copy
    cd = next(d for d in b.vms[new_id]["devices"] if d["type"] == "VirtualCdrom")
    cd["start_connected"] = False
    nb = len(sb.boots)
    r = admin.post("/virt/moves/decide", json={"id": jid, "what": "back"}).json()
    check(f"brought back while its CD is set not to connect: refused before anything is started, in words ({r})",
          not r.get("ok") and "set not to connect at power-on" in (r.get("error") or "") and len(sb.boots) == nb)
    check("the new VM was switched off for the restart and stays off; the VM is still frozen where it was",
          b.vms[new_id]["power"] == "poweredOff" and a.vms["5"]["power"] == "poweredOn"
          and a.vms["5"]["tools"] != "guestToolsRunning")
    cd["start_connected"] = True

    def frozen_job() -> tuple:
        j = (admin.get(f"/virt/moves/state?id={jid}").json().get("job")) or {}
        return j, [e["text"] for e in j.get("log", [])]

    def intact() -> bool:
        return (a.vms["5"]["power"] == "poweredOn" and a.vms["5"]["tools"] != "guestToolsRunning"
                and a.vms["5"]["name"] == "queue-02")
    # the host does not connect the CD although it is set to: the copy on the disks starts
    sb.cd_fails = True
    r = admin.post("/virt/moves/decide", json={"id": jid, "what": "back"}).json()
    check(f"a new VM the host starts without its CD is powered off again at once, and the start says so ({r})",
          not r.get("ok") and "did not connect the new VM's receiver CD" in (r.get("error") or "")
          and "It was powered off again at once" in (r.get("error") or "")
          and sb.boots[-1] == (new_id, "disk") and b.vms[new_id]["power"] == "poweredOff")
    # the same, and this time the host will not power the VM off either: the copy runs
    sb.fail = {f"vmsvc/power.off {new_id}": "A general system error occurred"}
    r = admin.post("/virt/moves/decide", json={"id": jid, "what": "back"}).json()
    check(f"when it cannot be powered off again either, the start says that ({r})",
          not r.get("ok") and "could not be powered off again" in (r.get("error") or "")
          and b.vms[new_id]["power"] == "poweredOn" and sb.boots[-1] == (new_id, "disk"))
    job = wait_for(admin, jid, ("stuck", "done", "undone", "failed"), 60)
    log = [e["text"] for e in job.get("log", [])]
    check(f"the system that then answers on the new VM is not taken for the VM: the move waits and says why ({job.get('state')}: {log[-1:]})",
          job.get("state") == "stuck" and intact()
          and any("that is the copy on its disks" in t and "could not be powered off" in t for t in log)
          and not any("powering the old copy off" in t for t in log))
    time.sleep(10)                                          # the watcher looks again, the copy still running
    job, log = frozen_job()
    check(f"while the copy cannot be powered off, the VM itself is never powered off in its place, and it is said once ({job.get('state')})",
          intact() and job.get("state") == "stuck" and b.vms[new_id]["power"] == "poweredOn"
          and len([t for t in log if "that is the copy on its disks" in t]) == 1)
    sb.fail, sb.cd_fails = {}, False
    t0 = time.time()
    while b.vms[new_id]["power"] != "poweredOff" and time.time() - t0 < 30:
        time.sleep(0.5)
    time.sleep(1.0)
    job, log = frozen_job()
    check("once the host allows it, the copy is powered off, and that is said too",
          b.vms[new_id]["power"] == "poweredOff" and intact()
          and any("that is the copy on its disks" in t and "The new VM was powered off" in t for t in log))
    n = len(sb.log)
    r = admin.post("/virt/moves/decide", json={"id": jid, "what": "back"}).json()
    check(f"a person brings it back ({r.get('error')})", r.get("ok"))
    since = sb.log[n:]
    on = next((i for i, c in enumerate(since) if c == f"vim-cmd vmsvc/power.on {new_id}"), -1)
    link = next((i for i, c in enumerate(since) if c == f"vim-cmd vmsvc/device.connection {new_id} {tcard['key']} 1"), -1)
    check(f"bringing it back powers the new VM on afresh, then connects its transfer card ({since})",
          0 <= on < link and not any("power.reset" in c for c in since))
    check("its start looked at the CD's image before the power-on",
          any("test -e" in c and "/envmove/envmove-" in c for c in since[:on]))
    job = wait_end(admin, jid, 60)
    log = [e["text"] for e in job.get("log", [])]
    check(f"the restarted new VM started from the receiver CD again, not from the copy on its disks ({sb.boots[-2:]})",
          sb.boots[-1] == (new_id, "receiver"))
    check(f"so the system carried on where it was, and the move is undone (ended {job.get('state')}: {log[-3:]})",
          job.get("state") == "undone")
    check("one system, where it was: the VM runs, the new one is gone",
          a.vms["5"]["power"] == "poweredOn" and a.vms["5"]["tools"] == "guestToolsRunning" and set(b.vms) == before)


# ── 6b. arrived, and the receiver CD could not be put out of use ─
def test_cd_left(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
                 world: SshWorld) -> None:
    another_vm(a, "11", "ledger-01", "10.20.0.70")
    world.ends["10.20.0.70"] = Guest("10.20.0.70", a, "11", b, sb, freeze_at=4.0, end_at=6.0)
    sb.cd_late = 2.5                    # this host shows a connected CD a moment after it shows the VM running
    r = admin.post("/virt/move/start", json=form_for(ca, cb, "11")).json()
    check(f"a fourth move starts ({r.get('error')})", r.get("ok"))
    jid = r.get("id", "")
    job = wait_for(admin, jid, ("copying", "frozen", "done", "undone", "failed", "stuck"), 90)
    sb.cd_late = 0.0
    check(f"a CD the host shows a moment late does not fail the new VM's first start ({job.get('state')})",
          job.get("state") in ("copying", "frozen", "done"))
    # from here on the datastore will not let the CD's image be replaced
    sb.fail = {"/envmove/envmove-": "mv: can't rename: Device or resource busy"}
    job = wait_end(admin, jid)
    sb.fail = {}
    log = [e["text"] for e in job.get("log", [])]
    new_id = max(b.vms, key=lambda k: int(k))
    cd = next(d for d in b.vms[new_id]["devices"] if d["type"] == "VirtualCdrom")
    image = next((k for k in sb.files if f"envmove-{jid}" in k), "")
    check(f"the system arrived ({job.get('state')}: {log[-2:]})", job.get("state") == "done" and b.vms[new_id]["power"] == "poweredOn")
    check("the image could not be emptied: it still holds the receiver, behind a disconnected CD",
          len(sb.files.get(image, b"")) > 1024 * 1024 and cd["connected"] is False)
    said = [t for t in log if "its image still holds the receiver" in t]
    check(f"the log says what that means for this VM's next power-on, and what to do about it ({said[:1]})",
          bool(said) and "connects again at the next power-on" in said[0]
          and "would start the receiver, not the system" in said[0] and "Connect at power on" in said[0])
    check("the move's last line carries it, and nothing says the image was emptied or the CD deleted",
          any("some tidying is left" in t and "would start the receiver, not the system" in t for t in log)
          and not any("image emptied" in t or "receiver CD deleted" in t or "has nothing to start" in t for t in log))
    # what the sentence warns of is what the stand-in host does
    sb.run(f"vim-cmd vmsvc/power.off {new_id}", b"")
    sb.run(f"vim-cmd vmsvc/power.on {new_id}", b"")
    check("switched off and on as it is, this VM starts the receiver", sb.boots[-1] == (new_id, "receiver") and cd["connected"] is True)
    side = vmmove.side(cb, "", new_id, road="shell")
    iso = "[datastore1] " + image.split("/vmfs/volumes/datastore1/")[-1]
    sb.fail = {"device.connection": "A general system error occurred", "/envmove/envmove-": "Device or resource busy"}
    try:
        side.cd_done(cd["key"], iso)
        check("a CD that is connected and whole is not passed over", False)
    except esxshell.ShellError as e:
        check(f"connected and whole, it says the next restart starts the receiver, as the host reports the CD ({e})",
              "still connected and still holds the receiver" in str(e) and "next restart" in str(e))
    sb.fail = {}
    did = side.cd_done(cd["key"], iso)
    check(f"once the host allows it, the CD is disconnected and its image emptied ({did[:60]})",
          "disconnected and its image emptied" in did and cd["connected"] is False and sb.files[image] == bytes(64 * 1024))
    sb.run(f"vim-cmd vmsvc/power.off {new_id}", b"")
    sb.run(f"vim-cmd vmsvc/power.on {new_id}", b"")
    check("and then a power-off and power-on starts the system from its disk", sb.boots[-1] == (new_id, "disk"))


# ── 7. a move that dies while things are being made ────────────
def test_half_made(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
                   world: SshWorld, c: FakeEsxi, paid: dict) -> None:
    another_vm(a, "6", "db-01", "10.20.0.61")
    world.ends["10.20.0.61"] = Guest("10.20.0.61", a, "6", b, sb)
    # host b has a VM of its own in a folder called db-01 (a VM renamed since keeps its folder's
    # name): none of it is EnvMap's
    theirs = b.vms["2"]
    theirs["vmx"] = "[datastore1] db-01/db-01.vmx"
    check("the target has its own VM in a folder of that name",
          theirs["name"] == "b-db-01" and sb.vmx_path(theirs) == "/vmfs/volumes/datastore1/db-01/db-01.vmx")
    sb.dirs.add("/vmfs/volumes/datastore1/db-01")
    sb.files["/vmfs/volumes/datastore1/db-01/db-01.vmx"] = sb.vmx_of(theirs).encode()
    sb.files["/vmfs/volumes/datastore1/db-01/db-01.vmdk"] = b"# theirs\n"
    kept = {k: v for k, v in sb.files.items() if k.startswith("/vmfs/volumes/datastore1/db-01/")}
    # what will be made is on record before any of it is made
    on_record, real_build = [], esxshell.EsxiShell.build

    def watched(self, src, **kw):
        jobs = [j for j in vmmove.all_jobs() if j.get("state") == "preparing"]
        on_record.append(bool(jobs) and (jobs[0].get("built") or {}).get("making") == kw.get("plan"))
        return real_build(self, src, **kw)
    esxshell.EsxiShell.build = watched
    for word, what in (("vmkfstools", "a disk cannot be made"), ("solo/registervm", "the host will not register the VM")):
        before, files = set(b.vms), set(sb.files)
        sb.fail = {word: "No space left on device" if word == "vmkfstools" else "A general system error occurred"}
        r = admin.post("/virt/move/start", json=form_for(ca, cb, "6")).json()
        job = wait_end(admin, r.get("id", ""))
        sb.fail = {}
        log = [e["text"] for e in job.get("log", [])]
        check(f"when {what}, the move fails before it starts ({job.get('state')}: {log[-3:]})", job.get("state") == "failed")
        check(f"when {what}, the target's own db-01 is still registered and its files untouched",
              set(b.vms) == before and b.vms["2"] is theirs and {k: sb.files.get(k) for k in kept} == kept)
        check(f"when {what}, nothing EnvMap made is left: no folder, no disk, no settings file, no CD",
              set(sb.files) == files and not any(d.startswith("/vmfs/volumes/datastore1/db-01-") for d in sb.dirs))
        check(f"when {what}, the VM runs where it was with no transfer card on it",
              a.vms["6"]["power"] == "poweredOn" and len([d for d in a.vms["6"]["devices"] if d["type"] == "VirtualVmxnet3"]) == 1)
    esxshell.EsxiShell.build = real_build
    check(f"what is to be made is in the move's record on disk before the first of it is made ({on_record})",
          on_record == [True, True])
    # EnvMap stopped between two commands: the move's record says what was being made, and it is taken away
    side = vmmove.side(cb, "", None, road="shell")
    facts = vmmove.side(ca, "", "6", road="shell").facts()
    plan = side.plan_build(facts, name="db-01", datastore="datastore1")
    base = f"/vmfs/volumes/datastore1/{plan['folder']}"
    sb.run(f"mkdir '{base}' && : > '{base}/{plan['mark']}'", b"")
    sb.run(f"vmkfstools -c 1024k -d thin '{base}/db-01.vmdk'", b"")
    check("half a new VM exists", base in sb.dirs and f"{base}/db-01-flat.vmdk" in sb.files)
    dead = {"id": "feedfacecafe", "created": time.time(), "state": "preparing", "log": [], "times": {},
            "by": {"email": "mover@example.com"}, "transfer": {}, "tokens": {},
            "built": {"making": plan, "cards_before": ["4000"]},
            "src": {"conn": ca["id"], "conn_name": "free-a", "node": "", "vm": "6", "name": "db-01", "flavor": "esxi", "road": "shell"},
            "dst": {"conn": cb["id"], "conn_name": "free-b", "node": "", "flavor": "esxi", "road": "shell"}}
    vmmove.save(dead)
    vmmove.resume_all()
    done = vmmove.load("feedfacecafe") or {}
    check(f"when EnvMap starts again it is taken away whole ({done.get('state')}: {[e['text'] for e in done.get('log', [])][-3:]})",
          done.get("state") == "failed" and base not in sb.dirs and not any(k.startswith(base + "/") for k in sb.files))
    side.unmake({**plan, "folder": "db-01"})
    check("a folder without this move's mark is not EnvMap's to empty, whatever the plan says",
          {k: sb.files.get(k) for k in kept} == kept and "/vmfs/volumes/datastore1/db-01" in sb.dirs)
    # EnvMap stopped right after the host registered the new VM, before the move's record had its number
    def made_whole(jid: str) -> tuple:
        plan = side.plan_build(facts, name="db-01", datastore="datastore1")
        iso = side.upload_iso("datastore1", f"envmove-{jid}.iso", bytes(2 << 20))
        made = side.build(facts, name="db-01", datastore="datastore1", nets=[{"network": "VM Network"}],
                          transfer={"dst_mac": "00:50:56:3f:00:09", "dst_net": "Transfer"}, iso=iso, plan=plan)
        return plan, made, iso, f"/vmfs/volumes/datastore1/{plan['folder']}"

    def stopped(jid: str, built: dict, vm: str = "6", transfer: dict | None = None, dst: dict | None = None) -> list:
        vmmove.save({**dead, "id": jid, "log": [], "built": built, "transfer": transfer or {},
                     "src": {**dead["src"], "vm": vm}, "dst": dst or dead["dst"]})
        vmmove.resume_all()
        return [e["text"] for e in (vmmove.load(jid) or {}).get("log", [])]

    before, files = set(b.vms), set(sb.files)
    plan, made, iso, base = made_whole("feedface0001")
    check("the host knows the new VM, and its folder carries this move's mark for as long as the move lives",
          made["vm"] in b.vms and f"{base}/{plan['mark']}" in sb.files and made["cd"] and made["tcard"])
    log = stopped("feedface0001", {"making": plan, "iso": iso, "cards_before": ["4000"]})
    check(f"a new VM the host registered just before EnvMap stopped is taken away, with its files and its CD ({log[-3:]})",
          set(b.vms) == before and set(sb.files) == files and base not in sb.dirs
          and any("what had been made of the new VM taken away" in t for t in log))
    # a new VM that cannot be taken away keeps the image its CD points at
    plan, made, iso, base = made_whole("feedface0002")
    image = "/vmfs/volumes/datastore1/envmove/envmove-feedface0002.iso"
    sb.fail = {"vmsvc/destroy": "A general system error occurred"}
    log = stopped("feedface0002", {"making": plan, "iso": iso, "cards_before": ["4000"]})
    sb.fail = {}
    check(f"a new VM that cannot be taken away keeps its receiver CD's image, and the log says both ({log[-4:]})",
          made["vm"] in b.vms and len(sb.files.get(image, b"")) == 2 << 20
          and any("could not be taken away" in t for t in log) and any("image kept" in t for t in log))
    check("asked again once the host allows it, it goes", "taken away" in side.unmake(plan) and made["vm"] not in b.vms)
    side.moid = None
    side.delete_iso(iso)
    # the folder's mark is gone, but the VM's number and settings file are both on record
    plan, made, iso, base = made_whole("feedface0003")
    sb.files.pop(f"{base}/{plan['mark']}")
    log = stopped("feedface0003", {"making": plan, **made, "iso": iso, "cards_before": ["4000"]})
    check(f"without the mark, a VM whose number and settings file are both on record is still deleted ({log[-3:]})",
          set(b.vms) == before and set(sb.files) == files and "the new VM deleted" in log)
    plan, made, iso, base = made_whole("feedface0004")
    sb.files.pop(f"{base}/{plan['mark']}")
    log = stopped("feedface0004", {"making": plan, **made, "vm": "2", "iso": iso, "cards_before": ["4000"]})
    check(f"but not when that number names another VM by now: nothing is deleted, and the CD's image stays ({log[-4:]})",
          "2" in b.vms and made["vm"] in b.vms and any("no longer the VM EnvMap made" in t for t in log)
          and any("image kept" in t for t in log) and iso.split("] ")[1] in " ".join(sb.files))
    sb.run(f"vim-cmd vmsvc/destroy {made['vm']}", b"")
    side.delete_iso(iso)
    check("the stand-in is as it was before these", set(b.vms) == before and set(sb.files) == files)
    # the datastore cannot be looked into: "not there" is not what that reads as
    plan, made, iso, base = made_whole("feedface0007")
    image = "/vmfs/volumes/datastore1/envmove/envmove-feedface0007.iso"
    sb.mounted = set()
    log = stopped("feedface0007", {"making": plan, **made, "iso": iso, "cards_before": ["4000"]})
    try:
        side.delete_iso(iso)
        check("an image on a datastore that cannot be looked into is not called deleted", False)
    except esxshell.ShellError as e:
        check(f"deleting it says the datastore cannot be looked into ({e})", "cannot be looked into" in str(e))
    sb.mounted = {"/vmfs/volumes/datastore1"}
    check(f"a datastore that cannot be looked into: nothing is called gone or deleted, and the VM keeps its image ({log[-3:]})",
          made["vm"] in b.vms and len(sb.files.get(image, b"")) == 2 << 20
          and any("cannot be looked into" in t for t in log) and any("image kept" in t for t in log)
          and not any("receiver CD deleted" in t or "nothing of the new VM" in t for t in log))
    check("asked again once it is mounted, all of it goes",
          "taken away" in side.unmake(plan, made["vm"]) and side.delete_iso(iso) is None
          and set(b.vms) == before and set(sb.files) == files)
    # another move made the folder of that name a moment earlier: nothing in it is this move's
    plan = side.plan_build(facts, name="db-01", datastore="datastore1")
    iso = side.upload_iso("datastore1", "envmove-feedface0008.iso", bytes(2 << 20))
    base = f"/vmfs/volumes/datastore1/{plan['folder']}"
    sb.dirs.add(base)
    sb.files[f"{base}/db-01.vmx"] = b"somebody else's\n"
    log = stopped("feedface0008", {"making": plan, "iso": iso, "cards_before": ["4000"]})
    check(f"a folder that is another move's is left alone, and this move's own image is still deleted ({log[-3:]})",
          sb.files.get(f"{base}/db-01.vmx") == b"somebody else's\n" and any("left alone" in t for t in log)
          and "the receiver CD deleted" in log and not any("envmove-feedface0008" in k for k in sb.files))
    sb.files.pop(f"{base}/db-01.vmx")
    sb.dirs.discard(base)
    # a licensed target, worked through the API: a new VM that is already gone is no reason to keep its image
    api = {"conn": paid["id"], "conn_name": "paid-c", "node": "", "flavor": "esxi", "road": "api"}
    c.files["datastore1"]["envmove/envmove-feedface0009.iso"] = 700
    log = stopped("feedface0009", {"vm": "999", "iso": "[datastore1] envmove/envmove-feedface0009.iso"}, dst=api)
    check(f"through the API too: a new VM already gone is said to be, and its image is deleted ({log[-3:]})",
          "the new VM was already gone" in log and "the receiver CD deleted" in log
          and "envmove/envmove-feedface0009.iso" not in c.files["datastore1"])
    c.files["datastore1"]["envmove/envmove-feedface000a.iso"] = 700
    log = stopped("feedface000a", {"vm": "4", "iso": "[datastore1] envmove/envmove-feedface000a.iso"}, dst=api)
    check(f"and one that is there is deleted, then its image ({log[-3:]})",
          "the new VM deleted" in log and "4" not in c.vms and "envmove/envmove-feedface000a.iso" not in c.files["datastore1"])
    # the host registers the new VM without one of the two things the receiver needs
    for omit, what in (("card", "transfer card"), ("cd", "receiver CD")):
        sb.omit = omit
        r = admin.post("/virt/move/start", json=form_for(ca, cb, "6")).json()
        job = wait_end(admin, r.get("id", ""), 60)
        sb.omit = ""
        log = [e["text"] for e in job.get("log", [])]
        check(f"a new VM registered without its {what} is refused at once and taken away ({job.get('state')}: {log[-3:]})",
              job.get("state") == "failed" and any(f"without its {what}" in t for t in log)
              and set(b.vms) == before and set(sb.files) == files)
    # cards the VM did not have before: only one that can be EnvMap's is touched, and only if there is one

    def nic(key: int, kind: str, net: str) -> dict:
        return {"type": kind, "key": key, "controller": 100, "unit": 7 + key - 4000, "network": net,
                "connected": True, "mac": "00:0c:29:aa:00:%02x" % (key - 4000)}
    another_vm(a, "8", "mq-03", "10.20.0.63")
    a.vms["8"]["devices"] += [nic(4001, "VirtualVmxnet3", "VM Network"), nic(4002, "VirtualVmxnet3", "VM Network")]
    log = stopped("feedface0005", {"cards_before": ["4000"]}, vm="8", transfer={"src_net": "VM Network"})
    check(f"two cards that could each be the transfer card: neither is touched, and a person is told ({log[-3:]})",
          all(d["connected"] for d in a.vms["8"]["devices"] if d["key"] in (4001, 4002))
          and any("which one EnvMap added cannot be told" in t for t in log))
    another_vm(a, "9", "mq-04", "10.20.0.64")
    a.vms["9"]["devices"] += [nic(4001, "VirtualE1000e", "VM Network"), nic(4002, "VirtualVmxnet3", "DB Network"),
                              nic(4003, "VirtualVmxnet3", "VM Network")]
    log = stopped("feedface0006", {"cards_before": ["4000"]}, vm="9", transfer={"src_net": "VM Network"})
    now = {d["key"]: d["connected"] for d in a.vms["9"]["devices"] if d["key"] > 4000 and "mac" in d}
    check(f"a card of another kind or on another network is somebody else's: only the one that fits is disconnected ({now})",
          now == {4001: True, 4002: True, 4003: False})
    # the connection is lost right after the host added the transfer card
    sa.drop_after = "devices.createnic"
    r = admin.post("/virt/move/start", json=form_for(ca, cb, "6")).json()
    job = wait_end(admin, r.get("id", ""))
    log = [e["text"] for e in job.get("log", [])]
    extra = [d for d in a.vms["6"]["devices"] if d["type"] == "VirtualVmxnet3" and d["key"] != 4000]
    check(f"a transfer card added just before the connection was lost is found again and disconnected ({job.get('state')}: {log[-3:]})",
          job.get("state") == "failed" and len(extra) == 1 and extra[0]["connected"] is False
          and any("disconnected and left on the VM" in t for t in log))
    # a VM number the host has given to another VM since
    made = vmmove.side(cb, "", "2", road="shell")
    made.made_vmx = "[datastore1] db-01-abc123/db-01.vmx"
    try:
        made.destroy()
        check("a number that now names another VM is not destroyed", False)
    except esxshell.ShellError as e:
        check(f"it is left alone, and said so ({e})", "no longer the VM EnvMap made" in str(e) and "2" in b.vms)


# ── 8. the road closed ─────────────────────────────────────────
def test_closed(admin: TestClient, ca: dict, cb: dict, a: FakeEsxi, b: FakeEsxi, sa: EsxiShell, sb: EsxiShell,
                world: SshWorld) -> None:
    another_vm(a, "7", "cache-01", "10.20.1.10")
    g = world.ends["10.20.1.10"] = Guest("10.20.1.10", a, "7", b, sb)
    form = form_for(ca, cb, "7")

    def problems(**more) -> list:
        r = admin.post("/virt/move/check", json={**form, **more}).json()
        return (r.get("plan") or {}).get("problems", [r.get("error") or "no plan"])

    check(f"open to begin with ({problems()})", problems() == [])
    ssh_b = next(s for s in b.services if s["key"] == "TSM-SSH")
    ssh_b["running"] = False
    seen = len([1 for h, _u, _c in world.seen if h == "localhost"])
    got = problems()
    check(f"SSH switched off on the host: said so, with where to start it ({got})",
          any("SSH is switched off on free-b" in p and "TSM-SSH" in p and "EnvMap cannot" in p for p in got))
    check("and the host is not tried while it says its SSH is off", len([1 for h, _u, _c in world.seen if h == "localhost"]) == seen)
    ssh_b["running"] = True
    sb.up = False
    got = problems()
    check(f"port 22 filtered: said so ({got})", any("free-b could not be reached over SSH" in p and "does not answer" in p for p in got))
    sb.up = True
    g.reachable = False
    got = problems()
    check(f"the guest not reachable over SSH: said so ({got})",
          any("the guest at 10.20.1.10 could not be reached over SSH" in p for p in got))
    g.reachable = True
    g.password, tries = "another", g.attempts
    got = problems()
    check(f"the guest's sign-in refused: said so ({got})", any("sign-in was refused" in p for p in got))
    check(f"and a check with a wrong password costs the guest one failed sign-in ({g.attempts - tries})", g.attempts - tries == 1)
    g.password = "guest-password"
    g.user, g.sudo = "deploy", False
    got = problems(guest_user="deploy")
    check(f"a user who is not root and may not use sudo: said so, with what sudo said ({got})",
          any("do not run as root" in p and "sudo: a password is required" in p for p in got))
    g.sudo = "Sorry, user deploy is not allowed to execute '/bin/sh -c /bin/sh -s 2>&1' as root on cache-01."
    got = problems(guest_user="deploy")
    check(f"sudo's own refusal is passed on as sudo's, not answered with advice for a Proxmox guest agent ({got})",
          any("do not run as root" in p and "is not allowed to execute" in p for p in got)
          and not any("qemu-ga" in p or "guest agent" in p for p in got))
    g.sudo = True
    got = problems(guest_user="deploy")
    check(f"a user who may use sudo without a password is enough ({got})", got == [])
    g.user = "root"
    a.vms["7"]["ip"] = "fd00:20::10"
    world.ends["fd00:20::10"] = g
    r = admin.post("/virt/move/check", json=form).json()
    plan = r.get("plan") or {}
    check(f"a guest reached at an IPv6 address keeps it as an address and a port ({plan.get('problems') or r.get('error')})",
          plan.get("ok") and plan["src"]["guest_at"] == "[fd00:20::10]:22")
    check("and the key written down for the guest's old address is said to be replaced",
          any("it replaces the key written down for 10.20.1.10:22" in (x["detail"] or "")
              for x in audits("virt_move_ssh_key_pinned")))
    a.vms["7"]["ip"] = "10.20.1.10"
    got = problems(guest_host="10.20.1.10:2222")
    check(f"another port for the guest is used when given ({got})", any("port 2222" in p for p in got))
    seen = len(world.requests)
    got = problems(guest_host="10.99.0.5")
    check(f"but not an address VMware Tools do not report for this guest: SSH is not pointed elsewhere ({got})",
          any("10.99.0.5 is not an address VMware Tools report" in p for p in got)
          and not any(r["host"] == "10.99.0.5" for r in world.requests[seen:]))
    a.vms["7"]["ip"] = "127.0.0.1"
    got = problems()
    check(f"nor this machine itself, whatever the guest says its address is ({got})",
          any("127.0.0.1 is not an address a guest is reached at" in p for p in got))
    a.vms["7"]["ip"] = "10.20.1.10"
    a.vms["7"]["vmx"] = "[datastore1] cache-01/../cache-01/cache-01.vmx"
    got = problems()
    check(f"a folder the shell cannot be given is said before the move, not after it ({got})", any("the VM's folder on free-a" in p for p in got))
    a.vms["7"].pop("vmx")
    esxshell._lic.clear()
    a.fail_next["RetrievePropertiesEx"] = ("HostCommunication", "the host is not answering")
    got = problems()
    check(f"a licence that cannot be read stops the check; it is not taken for a paid one ({got})",
          any("licence could not be read" in p for p in got))
    sb.key = sb.key[:-8] + "BBBBBBB="
    got = problems()
    check(f"a host whose key changed is refused ({got})", any("not the one EnvMap wrote down" in p for p in got))


# ── 9. the pages ───────────────────────────────────────────────
def test_pages(admin: TestClient, looker: TestClient, ca: dict, cb: dict, paid: dict) -> None:
    r = admin.get(f"/virt/move?c={ca['id']}&vm=2")
    check("a free host's form asks for the guest's SSH address and says why",
          r.status_code == 200 and "Guest address for SSH" in r.text and "free ESXi licence" in r.text)
    r = admin.get(f"/virt/move?c={paid['id']}&vm=2")
    check("a licensed host's form is as it was", r.status_code == 200 and "Guest address for SSH" not in r.text
          and "through VMware Tools" in r.text)
    r = admin.get("/virt/moves")
    check("the Moves page lists the keys written down", "SSH keys written down for moves" in r.text
          and "ED25519 SHA256:" in r.text and "a guest on free-a" in r.text)
    check("someone who does not administer the hosts sees no keys", "SSH keys written down" not in looker.get("/virt/moves").text)
    tid = f"move:host:{cb['id']}"
    r = looker.post("/virt/moves/forget-key", json={"id": tid})
    check("and may not forget one", r.status_code == 403 and pam.host_pin(tid))
    r = admin.post("/virt/moves/forget-key", json={"id": "move:host:nope"})
    check("a key that is not there cannot be forgotten", r.status_code == 403)
    r = admin.post("/virt/moves/forget-key", json={"id": tid})
    check("an administrator forgets the changed key", r.json().get("ok") and not pam.host_pin(tid)
          and audits("virt_move_ssh_key_forgotten"))
    plan = admin.post("/virt/move/check", json=form_for(ca, cb, "7")).json().get("plan") or {}
    check(f"and the next contact is a first one again ({plan.get('problems')})",
          plan.get("ok") and any("first SSH contact with free-b" in n for n in plan.get("notes", [])))


# ── 10. what is read back ──────────────────────────────────────
def test_readback(cb: dict, b: FakeEsxi, sb: EsxiShell) -> None:
    gone = vmmove.side(cb, "", "999", road="shell")
    check("a VM the host no longer has reads as gone", gone.status() == "")
    b.fail_next["RetrievePropertiesEx"] = ("HostCommunication", "the host is not answering")
    try:
        got = gone.status()
        check(f"a host that cannot be read is not a VM that is gone ({got!r})", False)
    except virt.VirtError:
        pass
    here = vmmove.side(cb, "", "3", road="shell")
    check("a VM that is there reads as running", here.status() == "running" and here.exists())
    b.fail_next["RetrievePropertiesEx"] = ("ManagedObjectNotFound", "Das Objekt wurde bereits gelöscht oder noch nicht vollständig erstellt")
    check("gone is the host's own name for it, whatever language its message is in", here.status() == "")
    b.fail_next["RetrievePropertiesEx"] = ("InvalidState", "The snapshot has already been deleted")
    try:
        got = here.status()
        check(f"another fault is not a VM that is gone because its message says deleted ({got!r})", False)
    except virt.VirtError:
        pass
    check("asked whether it is there: a VM the host no longer has is not, and that is an answer", not gone.exists())
    b.fail_next["RetrievePropertiesEx"] = ("HostCommunication", "the host is not answering")
    try:
        got = here.exists()
        check(f"and a host that cannot be read gives no answer to it ({got!r})", False)
    except virt.VirtError:
        pass

    def unreadable():
        raise virt.VirtError("the host is not answering")
    for ok, word in ((unreadable, "could not be read back (the host is not answering)"),
                     (lambda: False, "the VM did not power on, as read back")):
        try:
            gone._until(ok, "the VM did not power on", limit=0)
            check("a read-back that never comes true is an error", False)
        except esxshell.ShellError as e:
            check(f"it says which it was: not read, or read and not so ({e})",
                  word in str(e) and (ok is not unreadable or "did not power on" not in str(e)))
    off = vmmove.side(cb, "", "4", road="shell")
    n = len(sb.log)
    off.stop()
    check("a VM that is already off is not asked to power off again", len(sb.log) == n)
    on = vmmove.side(cb, "", "3", road="shell")
    sb.off_meanwhile = True
    n = len(sb.log)
    on.stop()
    check("a VM that powered itself off a moment before the command is off, not an error",
          b.vms["3"]["power"] == "poweredOff" and any(c == "vim-cmd vmsvc/power.off 3" for c in sb.log[n:]))
    b.vms["3"]["power"] = "poweredOn"
    sb.fail = {"power.off": "A general system error occurred"}
    try:
        on.stop()
        check("a power-off the host refuses is an error while the VM still runs", False)
    except esxshell.ShellError:
        pass
    sb.fail = {}
    check("and that VM runs on", b.vms["3"]["power"] == "poweredOn")
    # an image is deleted when it is seen to be gone
    side = vmmove.side(cb, "", None, road="shell")
    iso = side.upload_iso("datastore1", "envmove-feedface00aa.iso", bytes(4096))
    file = "/vmfs/volumes/datastore1/envmove/envmove-feedface00aa.iso"
    sb.undeletable.add(file)
    try:
        side.delete_iso(iso)
        check("an image still there after it was deleted is not called deleted", False)
    except esxshell.ShellError as e:
        check(f"it says the image is still there ({e})", "still there" in str(e))
    sb.undeletable.clear()
    check("deleted and seen to be gone, it says nothing more", side.delete_iso(iso) is None and file not in sb.files)
    check("deleted again, it says the image was gone already", "already gone" in (side.delete_iso(iso) or ""))


def main() -> int:
    make_parts()
    a, b, c = FakeEsxi().start(), FakeEsxi(name="esx-lab-02.example.internal").start(), FakeEsxi().start()
    world = SshWorld()
    env.SSH = world.install(tempfile.mkdtemp(prefix="esxshell-ssh-"))
    try:
        test_text()
        free_licence(a)
        free_licence(b)
        for h in (a, b):
            next(s for s in h.services if s["key"] == "TSM-SSH")["running"] = True
            h.vms["2"]["snapshots"], h.vms["2"]["current"] = [], ""
        # an ESXi host has one VM of a name, and the new VM carries the VM's
        # name: the second stand-in's own VMs are called something else
        for vm in b.vms.values():
            vm["name"] = "b-" + vm["name"]
        base = {"type": "vsphere", "username": "root", "token": "lab-password", "skip_tls": "1", "manage": "1"}
        # two hosts on this machine, told apart the way SSH tells them apart: by name
        ca = {**base, "name": "free-a", "base_url": a.url}
        cb = {**base, "name": "free-b", "base_url": b.url.replace("127.0.0.1", "localhost")}
        paid = {**base, "name": "paid-c", "base_url": c.url}
        for conn in (ca, cb, paid):
            conn["id"] = store.add_virt("", dict(conn))
        sa, sb = EsxiShell(a, "127.0.0.1"), EsxiShell(b, "localhost")
        world.ends.update({"127.0.0.1": sa, "localhost": sb})
        _user("mover@example.com", ["virt", "virt_admin"])
        _user("looker@example.com", ["virt"])
        admin, looker = _client("mover@example.com"), _client("looker@example.com")
        test_transport(world, sa, ca)
        test_roads(ca, paid, a, c)
        test_move(admin, ca, cb, a, b, sa, sb, world)
        test_undo(admin, ca, cb, a, b, sa, sb, world)
        test_back(admin, ca, cb, a, b, sa, sb, world)
        test_cd_left(admin, ca, cb, a, b, sa, sb, world)
        test_half_made(admin, ca, cb, a, b, sa, sb, world, c, paid)
        test_closed(admin, ca, cb, a, b, sa, sb, world)
        test_pages(admin, looker, ca, cb, paid)
        test_readback(cb, b, sb)
    finally:
        for h in (a, b, c):
            h.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
