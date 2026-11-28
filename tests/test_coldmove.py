"""EnvMap Move for a VM that is powered off (app/coldmove.py, app/coldside.py).

Asked for on 28 November 2026: "i need to be able to move even if the VM is
off, i need both options". A VM that is off is not started to be moved: two
helper machines of EnvMap's own copy its disks, and every byte is read back.

  1. the check: a powered-off VM is a move, with nothing asked of a guest;
     what stops it is said in words
  2. every way out before the copy is confirmed is the same one: the helpers,
     their CDs and the new VM are removed and the VM is exactly as it was
        a helper says it failed · a helper is switched off · the two helpers
        name different digests · a helper cannot be heard · nothing moves ·
        the VM was started meanwhile · a person stops the move
  3. a helper is never deleted with a disk on it: when a disk cannot be
     detached, the helper stays, and nothing of anybody's is deleted
  4. Proxmox to Proxmox, done: what was made, in which order, what is left
  5. EnvMap restarted during the copy, and during the preparation
  6. ESXi to Proxmox, and Proxmox to ESXi (the API's road)
  7. ESXi to ESXi on the free licence (the shell's road)
  8. the pages: a powered-off VM can be selected, a helper cannot, one click
     moves it with no sign-in, and Stop undoes it

    ./.venv/bin/python tests/test_coldmove.py

The hosts are the stand-ins of tests/_fake_cold.py. They are harsh on
purpose: deleting a VM there deletes every disk attached to it.
"""
from __future__ import annotations

import copy
import os
import pathlib
import re
import sys
import tempfile
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("coldmove-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
PARTS = pathlib.Path(tempfile.mkdtemp(prefix="coldmove-parts-"))
os.environ["PORTAL_ENVMOVE_DIR"] = str(PARTS)

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_cold import ColdEsxi, ColdLab, ColdPve, ColdShell, role_of   # noqa: E402
from _fake_esxi import free_licence                            # noqa: E402
from _fake_esxshell import SshWorld, parse_vmx                 # noqa: E402
from app import auth, coldmove, coldside, db, env, rbac, store, vmmove   # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Powered-Off-And-Moved-42"
HOSTS: list = []


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


def _user(email: str, areas: list[str], role: str = "user") -> None:
    uid = auth.create_user(email, "Cold Tester", PW, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    if areas:
        rbac.set_for_user(uid, [rbac.save("", f"role-{email}", "", areas, [], [])])


def _client(email: str) -> TestClient:
    c = TestClient(portal.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": PW}, follow_redirects=False)
    auth.forget_totp_use(auth.by_email(email)["id"])
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)
    return c


def until(cond, limit: float = 90) -> bool:
    t0 = time.time()
    while time.time() - t0 < limit:
        if cond():
            return True
        time.sleep(0.05)
    return False


def wait_end(jid: str, limit: float = 300) -> dict:
    if not jid:
        return {}                               # it never started: there is nothing to wait for
    until(lambda: (vmmove.load(jid) or {}).get("state") in vmmove.DONE and jid not in vmmove._running, limit)
    return vmmove.load(jid) or {}


def up(jid: str, lab: ColdLab, limit: float = 90) -> bool:
    """Both helpers of this move run and it copies. False at once when the
    move never started or has ended already."""
    if not jid:
        return False
    until(lambda: (len(lab.on) == 2 and (vmmove.load(jid) or {}).get("state") == "copying")
          or (vmmove.load(jid) or {}).get("state") in vmmove.DONE, limit)
    return len(lab.on) == 2


def said(job: dict) -> str:
    return " | ".join(e["text"] for e in job.get("log", []))


def new_lab(**k) -> ColdLab:
    lab = ColdLab(**k)
    for h in HOSTS:
        h.lab = lab
    return lab


def start(c: TestClient, form: dict) -> str:
    r = c.post("/virt/move/start", json=form).json()
    check(f"the move starts ({r.get('error')})", r.get("ok"))
    return r.get("id", "")


def helpers_on(pve: ColdPve) -> dict:
    return {role_of(g["config"].get("name", "")): i for i, g in pve.guests.items() if role_of(g["config"].get("name", ""))}


def main() -> int:
    make_parts()
    coldmove.POLL = 0.15
    pve = ColdPve().start()
    ea, eb = ColdEsxi().start(), ColdEsxi(name="esx-lab-02.example.internal").start()
    fa, fb = ColdEsxi(name="esx-free-01.example.internal").start(), ColdEsxi(name="esx-free-02.example.internal").start()
    world = SshWorld()
    env.SSH = world.install(tempfile.mkdtemp(prefix="coldmove-ssh-"))
    sa, sb = ColdShell(fa, "127.0.0.1"), ColdShell(fb, "localhost")
    world.ends.update({"127.0.0.1": sa, "localhost": sb})
    HOSTS.extend([pve, ea, eb, fa, fb, sa, sb])
    try:
        for h in (fa, fb):
            free_licence(h)
            next(s for s in h.services if s["key"] == "TSM-SSH")["running"] = True
        # a second disk on the Proxmox stand-in's powered-off VM
        pve.guests[101]["config"]["scsi1"] = "local-lvm:vm-101-disk-1,size=8G"
        pve.volumes["local-lvm:vm-101-disk-1"] = 101
        cfg0 = copy.deepcopy(pve.guests[101]["config"])
        base = {"type": "vsphere", "username": "root", "token": "lab-password", "skip_tls": "1", "manage": "1"}
        cp = {"type": "proxmox", "name": "lab-pve", "base_url": pve.url, "username": "root@pam!envmap",
              "token": "pve-token-secret", "skip_tls": "1", "manage": "1"}
        cea, ceb = {**base, "name": "esx-a", "base_url": ea.url}, {**base, "name": "esx-b", "base_url": eb.url}
        cfa = {**base, "name": "free-a", "base_url": fa.url}
        cfb = {**base, "name": "free-b", "base_url": fb.url.replace("127.0.0.1", "localhost")}
        for c in (cp, cea, ceb, cfa, cfb):
            c["id"] = store.add_virt("", dict(c))
        _user("mover@example.com", ["virt", "virt_admin"])
        _user("looker@example.com", ["virt"])
        admin, looker = _client("mover@example.com"), _client("looker@example.com")
        pp = {"c": cp["id"], "vm": "101", "node": "pve-01", "to": cp["id"], "dst_node": "pve-02",
              "storage": "local-lvm", "iso_storage": "local", "net0": "vmbr0"}

        def pve_untouched(what: str) -> None:
            names = [g["config"].get("name", "") for g in pve.guests.values()]
            check(f"{what}: no helper and no new VM is left on the node ({names})",
                  not any(role_of(n) or n.endswith("-moving") for n in names))
            check(f"{what}: the helpers' CDs are gone",
                  not any("envmove-" in c["volid"] for c in pve.content.get("local", [])))
            check(f"{what}: the VM is exactly as it was, and powered off",
                  pve.guests[101]["config"] == cfg0 and pve.guests[101]["status"] == "stopped")
            check(f"{what}: none of the VM's disks was deleted ({pve.gone})",
                  not any(v.startswith("local-lvm:vm-101-") for v in pve.gone))

        # ── 1. the check ───────────────────────────────────────
        new_lab()
        calls = len(pve.calls)
        r = admin.post("/virt/move/check", json=pp).json()
        plan = r.get("plan") or {}
        check(f"a powered-off VM can be moved ({r.get('error') or plan.get('problems')})",
              r.get("ok") and plan.get("ok") and plan.get("mode") == "off")
        check("nothing is asked of its guest: nothing runs in it",
              not any("/agent/" in c[1] for c in pve.calls[calls:] if len(c) > 1 and isinstance(c[1], str)))
        check("the check says how it will be moved, and that it is not started",
              any("is not started" in n for n in plan.get("notes", [])))
        check("the check created nothing", len(pve.guests) == 3)
        r = looker.post("/virt/move/check", json=pp).json()
        check("somebody who may only look may not move it", not r["ok"] and "dminister" in r["error"])
        pve.no_allocate = True
        plan = admin.post("/virt/move/check", json=pp).json()["plan"]
        check(f"without the right to attach another VM's disk, the check says which right is missing, for the VM's own disks ({plan['problems']})",
              not plan["ok"] and any("Datastore.Allocate" in p and "is read by a helper" in p and "local-lvm" in p for p in plan["problems"]))
        check("and, separately, for the storage the new VM's disks go on",
              any("Datastore.Allocate" in p and "the helper on the new host" in p and "local-lvm" in p for p in plan["problems"]))
        pve.no_allocate = False
        pve.guests[101]["status"] = "paused"
        plan = admin.post("/virt/move/check", json=pp).json()["plan"]
        check(f"a VM that is neither running nor off is neither kind of move ({plan['problems']})",
              not plan["ok"] and any("resume it, or power it off" in p for p in plan["problems"]))
        pve.guests[101]["status"] = "stopped"
        for key, value, word in (("template", 1, "template"), ("tpmstate0", "local-lvm:vm-101-disk-9,size=4M", "TPM"),
                                 ("lock", "backup", "locked")):
            pve.guests[101]["config"][key] = value
            plan = admin.post("/virt/move/check", json=pp).json()["plan"]
            check(f"{word}: refused in words ({plan['problems']})", not plan["ok"] and any(word in p for p in plan["problems"]))
            del pve.guests[101]["config"][key]
        was = pve.nodes["pve-01"]["mem"]
        pve.nodes["pve-01"]["mem"] = pve.nodes["pve-01"]["maxmem"] - 600 * 1024 * 1024
        plan = admin.post("/virt/move/check", json=pp).json()["plan"]
        check(f"no memory on the VM's host for the helper that reads: said before anything is made ({plan['problems']})",
              not plan["ok"] and any("the helper that reads" in p for p in plan["problems"]))
        pve.nodes["pve-01"]["mem"] = was
        pve.guests[101]["config"]["hostpci0"] = "0000:01:00.0"
        plan = admin.post("/virt/move/check", json=pp).json()["plan"]
        check("a device of the host does not stop a powered-off move: the new VM is built without it, and it says so",
              plan["ok"] and any("hostpci0" in n and "without it" in n for n in plan["notes"]))
        del pve.guests[101]["config"]["hostpci0"]
        check("the stand-in's VM is as it was after the checks", pve.guests[101]["config"] == cfg0)
        on_esxi, on_pve = coldside.slots("esxi", [10] * 9), coldside.slots("proxmox", [10] * 3)
        check(f"a disk's place in a helper is written down: on ESXi a target, skipping the controller's own ({[x['t'] for x in on_esxi]})",
              [x["t"] for x in on_esxi] == [0, 1, 2, 3, 4, 5, 6, 8, 9] and all(x["l"] == 0 for x in on_esxi))
        check("on Proxmox a unit", [(x["t"], x["l"]) for x in on_pve] == [(0, 0), (0, 1), (0, 2)])
        try:
            coldside.slots("esxi", [10] * 16)
            check("more disks than a helper holds are refused", False)
        except Exception as e:                                # noqa: BLE001
            check(f"more disks than a helper holds are refused in words ({e})", "holds 15" in str(e))

        # ── 2. every way out before the copy is confirmed ──────
        lab = new_lab()
        lab.fail = {"take": "disk 1 of the new VM holds 100 bytes and must hold 200"}
        job = wait_end(start(admin, pp))
        check(f"a helper that says it failed: undone, with its own reason ({job.get('state')}: {said(job)[-200:]})",
              job.get("state") == "undone" and "must hold 200" in said(job))
        check("what is deleted is the new VM's own disks, and only those",
              pve.gone and all(re.match(r"^local-lvm:vm-(?!101-)\d+-disk-\d$", v) for v in pve.gone))
        pve_untouched("a helper failed")

        lab = new_lab(copy_s=4.0)
        jid = start(admin, pp)
        up(jid, lab)
        taker = helpers_on(pve).get("take")
        pve.guests[taker]["status"] = "stopped"
        lab.stop("take")
        job = wait_end(jid)
        check(f"a helper switched off before it confirmed: it has said nothing, so the move is undone ({said(job)[-160:]})",
              job.get("state") == "undone" and "no longer running" in said(job))
        pve_untouched("a helper was switched off")

        lab = new_lab()
        lab.digests = {"take": ["aa" * 8, "bb" * 8]}
        job = wait_end(start(admin, pp))
        check(f"both say done and name different digests: not kept ({said(job)[-160:]})",
              job.get("state") == "undone" and "do not name the same digest" in said(job))
        pve_untouched("the digests differ")

        lab = new_lab()
        lab.mute = {"take"}
        coldmove.UNHEARD = 1.0
        job = wait_end(start(admin, pp))
        coldmove.UNHEARD = 600
        check(f"a helper that runs and cannot be heard: undone, and it says how a helper is heard ({said(job)[-220:]})",
              job.get("state") == "undone" and "could not be heard" in said(job) and "guest agent" in said(job))
        pve_untouched("a helper could not be heard")

        lab = new_lab()
        lab.apart = True
        coldmove.APART = 1.0
        job = wait_end(start(admin, pp))
        coldmove.APART = 300
        check(f"the two helpers run and never find each other: undone soon, naming the two networks and where to change them ({said(job)[-260:]})",
              job.get("state") == "undone" and "have not found each other" in said(job)
              and "vmbr0" in said(job) and "Transfer network" in said(job))
        pve_untouched("the helpers could not reach each other")

        lab = new_lab(copy_s=30.0)
        lab.hold = 0.3
        coldmove.STALL = 1.2
        job = wait_end(start(admin, pp))
        coldmove.STALL = 1200
        check(f"nothing moves any more: given up, undone ({said(job)[-160:]})",
              job.get("state") == "undone" and "nothing moved" in said(job))
        pve_untouched("the copy stood still")

        lab = new_lab(copy_s=1.2)
        jid = start(admin, pp)
        up(jid, lab)
        pve.upid("pve-01", "qmstart", 101)          # started and stopped again meanwhile: only the task list knows
        job = wait_end(jid)
        check(f"the VM was started while it was read (Proxmox has no lock): the copy is thrown away ({said(job)[-200:]})",
              job.get("state") == "undone" and "was started" in said(job))
        pve.tasks = {u: t for u, t in pve.tasks.items() if not (t["type"] == "qmstart" and t["id"] == "101")}
        pve_untouched("the VM was started meanwhile")

        lab = new_lab(copy_s=30.0)
        jid = start(admin, pp)
        up(jid, lab)
        r = looker.post("/virt/moves/decide", json={"id": jid, "what": "stop"}).json()
        check("somebody who may only look may not stop it", not r["ok"] and "dminister" in r.get("error", ""))
        r = admin.post("/virt/moves/decide", json={"id": jid, "what": "stop"}).json()
        job = wait_end(jid)
        check(f"a person stops it: undone, and it says who ({r}, {said(job)[-120:]})",
              r.get("ok") and job.get("state") == "undone" and "stopped by Cold Tester" in said(job))
        check("stopping is audited", db.q("SELECT * FROM audit WHERE action='virt_vm_move_stop'"))
        r = admin.post("/virt/moves/decide", json={"id": jid, "what": "stop"}).json()
        check("a move that has ended is not stopped again", not r["ok"])
        pve_untouched("a person stopped it")

        # ── 3. a helper is never deleted with a disk on it ─────
        lab = new_lab()
        lab.fail = {"give": "disk 2 of the VM cannot be read at byte 4096: input/output error"}
        pve.stuck_disks = True
        gone = len(pve.gone)
        job = wait_end(start(admin, pp))
        left = helpers_on(pve)
        check(f"a disk cannot be detached from the helpers: they are left where they are ({job.get('state')}, {sorted(left)})",
              job.get("state") == "failed" and sorted(left) == ["give", "take"])
        check("nothing at all was deleted: not the VM's disks, and not the new VM's, which its helper still holds",
              len(pve.gone) == gone and any(g["config"].get("name", "").endswith("-moving") for g in pve.guests.values()))
        check(f"and the move says what is left for a person ({job['log'][-1]['text']})",
              "left for you to remove" in job["log"][-1]["text"] and "the new VM is still there" in job["log"][-1]["text"])
        check("the VM is as it was", pve.guests[101]["config"] == cfg0)
        pve.stuck_disks = False
        for i in [i for i, g in pve.guests.items() if role_of(g["config"].get("name", "")) or g["config"].get("name", "").endswith("-moving")]:
            del pve.guests[i]
        pve.content["local"] = [c for c in pve.content["local"] if "envmove-" not in c["volid"]]

        # a host gives a number out again: a VM that now has a helper's number is not a helper
        lab = new_lab(copy_s=30.0)
        jid = start(admin, pp)
        up(jid, lab)
        giver = helpers_on(pve)["give"]
        pve.guests[giver]["config"]["name"] = "somebody-elses-vm"
        gone = len(pve.gone)
        admin.post("/virt/moves/decide", json={"id": jid, "what": "stop"})
        job = wait_end(jid)
        check(f"a VM that now has a helper's number is left alone, and the move says so ({job.get('state')}: {said(job)[-200:]})",
              job.get("state") == "failed" and giver in pve.guests and "no longer the helper" in said(job)
              and pve.guests[giver]["status"] == "running")
        check("nothing of the VM's was deleted meanwhile", not any(v.startswith("local-lvm:vm-101-") for v in pve.gone[gone:]))
        del pve.guests[giver]
        pve_untouched("a helper's number was taken")

        # ── 5a. EnvMap restarted while a move was being prepared ─
        lab = new_lab()
        me = auth.by_email("mover@example.com")
        plan = vmmove.check(me, pp)
        job = {"id": "c01dc01dc01d", "created": time.time(), "state": "starting", "by": {"email": me["email"], "name": "Cold Tester"},
               "src": plan["src"], "dst": plan["dst"], "transfer": plan["transfer"], "cross": plan["cross"], "mode": "off",
               "built": {}, "times": {}, "log": [], "tokens": {"boot": "b" * 32, "verdict": "v" * 32, "cold": "c" * 32}}
        vmmove.save(job)
        coldmove.prepare(job, plan["facts"])
        check("prepared by hand: two helpers run and a new VM waits", sorted(helpers_on(pve)) == ["give", "take"])
        vmmove.resume_all()
        job = wait_end("c01dc01dc01d")
        check(f"EnvMap restarted while it was being prepared: undone from the record ({job.get('state')})",
              job.get("state") == "undone")
        pve_untouched("restarted while preparing")

        # a helper that was made a moment before EnvMap stopped, and not yet written down
        lab = new_lab()
        job = {**job, "id": "c01dc01dc03d", "state": "starting", "built": {}, "log": [], "times": {}}
        vmmove.save(job)
        coldmove.prepare(job, plan["facts"])
        job["built"]["giver"].pop("vm")
        job["built"]["taker"].pop("vm")
        vmmove.update(job, lambda c: None)
        coldmove.after_failure(job, "EnvMap stopped between making a helper and writing that down")
        job = vmmove.load("c01dc01dc03d")
        check(f"a helper whose number was never written down is found by its name and removed ({job.get('state')})",
              job.get("state") == "undone" and not helpers_on(pve))
        pve_untouched("a helper was not written down")

        # ── 5b. EnvMap restarted during the copy ───────────────
        lab = new_lab()
        job = {**job, "id": "c01dc01dc02d", "state": "starting", "built": {}, "log": [], "times": {}}
        vmmove.save(job)
        coldmove.prepare(job, plan["facts"])
        vmmove.phase(job, "copying")
        vmmove.resume_all()
        job = wait_end("c01dc01dc02d")
        check(f"EnvMap restarted during the copy: the helpers went on, and the move ends done ({job.get('state')}: {said(job)[-200:]})",
              job.get("state") == "done" and "listened to again" in said(job))
        # put the stand-in back for the next move: the VM, off, under its own name
        moved_id = max(i for i, g in pve.guests.items() if g["config"].get("name") == "test-vm-07")
        del pve.guests[moved_id]
        pve.guests[101]["config"] = copy.deepcopy(cfg0)

        # ── 4. Proxmox to Proxmox, done ────────────────────────
        lab = new_lab()
        mark = len(pve.calls)
        gone = len(pve.gone)
        jid = start(admin, pp)
        seen = {}
        up(jid, lab)
        for role, i in helpers_on(pve).items():
            seen[role] = (i, copy.deepcopy(pve.guests[i]["config"]), pve.guests[i]["node"])
        job = wait_end(jid)
        check(f"it ends done ({job.get('state')}: {said(job)[-300:]})", job.get("state") == "done")
        calls = [c for c in pve.calls[mark:] if len(c) == 3]
        new = next((i for i, g in pve.guests.items() if g["config"].get("name") == "test-vm-07" and i != 101), None)
        ncfg = pve.guests.get(new, {}).get("config", {})
        check(f"the new VM is on the other node, carries the VM's name, and is powered off ({new}, {ncfg.get('name')})",
              new and pve.guests[new]["node"] == "pve-02" and pve.guests[new]["status"] == "stopped")
        check("it has the VM's two disks as volumes of its own, its card with the same address, and no CD and no card of EnvMap's",
              ncfg.get("scsi0", "").startswith(f"local-lvm:vm-{new}-disk-0") and ncfg.get("scsi1", "").startswith(f"local-lvm:vm-{new}-disk-1")
              and "BC:24:11:0A:00:02" in ncfg.get("net0", "") and not any(k.startswith("net") and k != "net0" for k in ncfg)
              and "envmove" not in str(ncfg) and ncfg.get("boot") == "order=scsi0;scsi1")
        starts = [c[1] for c in calls if c[0] == "POST" and c[1].endswith("/status/start")]
        check(f"EnvMap started the two helpers and nothing else: not the VM, not the new VM ({starts})",
              len(starts) == 2 and not any(f"/qemu/{i}/" in s for s in starts for i in (101, new)))
        check(f"the taker was started first: it waits for the giver ({lab.starts})", lab.starts == ["take", "give"])
        g, t = seen.get("give", (0, {}, "")), seen.get("take", (0, {}, ""))
        check(f"the giver was on the VM's node with the VM's disks at their places, read-only ({g[1].get('scsi0')}, {g[1].get('scsi1')})",
              g[2] == "pve-01" and g[1].get("scsi0") == "local-lvm:vm-101-disk-0,ro=1"
              and g[1].get("scsi1") == "local-lvm:vm-101-disk-1,ro=1")
        check(f"the taker was on the new node with the new VM's disks, to write ({t[1].get('scsi0')})",
              t[2] == "pve-02" and t[1].get("scsi0") == f"local-lvm:vm-{new}-disk-0" and t[1].get("scsi1") == f"local-lvm:vm-{new}-disk-1")
        check("a helper is small, has the agent's port, one card, and starts from its CD only",
              all(c.get("memory") == coldside.HELPER_MB and str(c.get("agent")) == "1" and c.get("boot") == "order=ide2"
                  and "envmove-" in c.get("ide2", "") and c.get("scsihw") == "virtio-scsi-pci"
                  and [k for k in c if k.startswith("net")] == ["net0"] for c in (g[1], t[1])))
        for role, (i, _, node) in seen.items():
            path = f"/api2/json/nodes/{node}/qemu/{i}"
            order = [(c[0], c[1], c[2].get("delete", "")) for c in calls if c[1] in (path, path + "/config") and c[0] in ("PUT", "DELETE")]
            check(f"the {role}r's disks were detached before it was deleted ({order})",
                  [o[0] for o in order] == ["PUT", "DELETE"] and order[0][2] == "scsi0,scsi1")
        check("the helpers are gone", not helpers_on(pve))
        check(f"and no disk was deleted, neither the VM's nor the new VM's ({pve.gone[gone:]})", len(pve.gone) == gone)
        old = pve.guests[101]["config"]
        check(f"the old VM is kept: renamed, not started with its host, its card's link down ({old.get('name')}, {old.get('net0')})",
              re.match(r"^test-vm-07-left-\d{8}$", old.get("name", "")) and old.get("onboot") == 0
              and "link_down=1" in old.get("net0", "") and pve.guests[101]["status"] == "stopped")
        check("its disks are where they were", old.get("scsi0") == cfg0["scsi0"] and old.get("scsi1") == cfg0["scsi1"])
        check("both CDs were uploaded and both are deleted",
              len([c for c in pve.calls[mark:] if c[0] == "UPLOAD"]) == 2
              and not any("envmove-" in c["volid"] for c in pve.content.get("local", [])))
        check("each helper was heard through the guest agent's port", {("give", "agent"), ("take", "agent")} <= set(lab.asked))
        check("the move's record carries how far it got, and the digests both helpers named",
              (job.get("progress") or {}).get("digests") == ["00000000c01d0000", "00000000c01d0001"])
        check("it is said plainly: moved, and powered off as it was", "powered off as it was" in job["log"][-1]["text"])
        pub = admin.get(f"/virt/moves/state?id={jid}").json()["job"]
        check("no token is on the move's page", "tokens" not in pub and "c01d" not in str(pub.get("tokens", "")))
        check("the outcome is audited", db.q("SELECT * FROM audit WHERE action='virt_vm_move_done'"))

        # ── 6a. ESXi to Proxmox ────────────────────────────────
        lab = new_lab()
        ep = {"c": cea["id"], "vm": "4", "node": "", "to": cp["id"], "dst_node": "pve-02",
              "storage": "local-lvm", "iso_storage": "local", "net0": "vmbr0"}
        src_disk = "[datastore1] old-builder/old-builder.vmdk"
        plan = admin.post("/virt/move/check", json=ep).json().get("plan") or {}
        check(f"a powered-off ESXi VM can be moved to Proxmox, with no sign-in asked for ({plan.get('problems')})",
              plan.get("ok") and plan.get("mode") == "off" and plan["src"]["signin"] == "")
        check("the check says which device types the new VM gets", any("paravirtual SCSI" in n for n in plan.get("notes", [])))
        gone = len(pve.gone)
        jid = start(admin, ep)
        up(jid, lab)
        giver = next((vm for vm in ea.vms.values() if role_of(vm["name"]) == "give"), {})
        gdisks = [d for d in giver.get("devices", []) if d["type"] == "VirtualDisk"]
        check(f"the giver on ESXi holds the VM's own disk file, at its place, and made no disk of its own ({gdisks})",
              len(gdisks) == 1 and gdisks[0]["file"] == src_disk and gdisks[0]["unit"] == 0)
        check("its serial port is a file on the datastore, and its annotation warns against deleting it",
              any(f.endswith("-give.log") for f in ea.serials.values()) and "Do not delete it" in giver.get("notes", ""))
        ea.calls.clear()
        job = wait_end(jid)
        check(f"it ends done ({job.get('state')}: {said(job)[-300:]})", job.get("state") == "done")
        check(f"the VM's disk file was not deleted with the helper ({ea.gone})", not ea.gone and not pve.gone[gone:])
        ops = [c[0] for c in ea.calls if c[0] in ("ReconfigVM_Task", "Destroy_Task", "PowerOnVM_Task")]
        check(f"on ESXi the disk came off the helper before the helper was destroyed ({ops})",
              "Destroy_Task" in ops and ops.index("ReconfigVM_Task") < ops.index("Destroy_Task"))
        check("the VM was never powered on", "PowerOnVM_Task" not in ops and ea.vms["4"]["power"] == "poweredOff")
        check("the giver was heard through its console's file, the taker through the agent",
              {("give", "console"), ("take", "agent")} <= set(lab.asked))
        new = next((i for i, g in pve.guests.items() if g["config"].get("name") == "old-builder"), None)
        ncfg = pve.guests.get(new, {}).get("config", {})
        check(f"the new Proxmox VM has the device types the system already drives ({ncfg.get('scsihw')}, {ncfg.get('net0')})",
              ncfg.get("scsihw") == "pvscsi" and ncfg.get("net0", "").startswith("vmxnet3=") and ncfg.get("bios") == "ovmf"
              and ncfg.get("scsi0", "").startswith(f"local-lvm:vm-{new}-disk-"))
        check(f"the old ESXi VM is renamed and its card will not connect ({ea.vms['4']['name']})",
              re.match(r"^old-builder-left-\d{8}$", ea.vms["4"]["name"])
              and not any(d.get("connected") or d.get("start_connected", False) for d in ea.vms["4"]["devices"] if d["type"] == "VirtualVmxnet3"))
        check("no helper and no CD of EnvMap's is left on the ESXi host",
              not any(role_of(vm["name"]) for vm in ea.vms.values()) and not any("envmove-" in f for f in ea.files["datastore1"]))

        # ── 6b. Proxmox to ESXi ────────────────────────────────
        lab = new_lab()
        pve.guests[110] = {"node": "pve-01", "kind": "qemu", "status": "stopped", "snapshots": [],
                           "config": {"name": "cold-02", "cores": 2, "sockets": 1, "memory": 2048, "ostype": "l26",
                                      "scsihw": "virtio-scsi-single", "scsi0": "local-lvm:vm-110-disk-0,size=20G",
                                      "net0": "virtio=BC:24:11:0A:00:10,bridge=vmbr0"}}
        pve.volumes["local-lvm:vm-110-disk-0"] = 110
        pe = {"c": cp["id"], "vm": "110", "node": "pve-01", "to": ceb["id"], "dst_node": "",
              "storage": "datastore1", "net0": "VM Network"}
        plan = admin.post("/virt/move/check", json=pe).json().get("plan") or {}
        check(f"a powered-off Proxmox VM can be moved to ESXi ({plan.get('problems')})", plan.get("ok"))
        check("and the check is honest about what the system needs to start there",
              any("no VirtIO devices" in n and "pvscsi" in n for n in plan.get("notes", [])))
        gone = len(pve.gone)
        jid = start(admin, pe)
        up(jid, lab)
        new = next((k for k, vm in eb.vms.items() if vm["name"] == "cold-02"), None)
        nfile = next((d["file"] for d in eb.vms.get(new, {}).get("devices", []) if d["type"] == "VirtualDisk"), "")
        taker = next((vm for vm in eb.vms.values() if role_of(vm["name"]) == "take"), {})
        check(f"the taker on ESXi holds the new VM's disk file ({nfile})",
              nfile and [d["file"] for d in taker.get("devices", []) if d["type"] == "VirtualDisk"] == [nfile])
        eb.calls.clear()
        job = wait_end(jid)
        check(f"it ends done ({job.get('state')}: {said(job)[-300:]})", job.get("state") == "done")
        vm = eb.vms.get(new, {})
        check("the new ESXi VM is powered off, was never powered on, has an empty CD drive and only the VM's own card",
              vm.get("power") == "poweredOff"
              and not any(c[0] == "PowerOnVM_Task" and c[1] == new for c in eb.calls)
              and [d["iso"] for d in vm["devices"] if d["type"] == "VirtualCdrom"] == [""]
              and [d["mac"] for d in vm["devices"] if d["type"] == "VirtualVmxnet3"] == ["bc:24:11:0a:00:10"])
        check(f"its disk is still there after its helper was removed ({eb.gone})",
              not eb.gone and nfile.split("] ", 1)[1] in eb.files["datastore1"] and not pve.gone[gone:])
        check("the old Proxmox VM is kept and renamed", re.match(r"^cold-02-left-\d{8}$", pve.guests[110]["config"]["name"]))

        # ── 3b. the same rule on ESXi, at the end of a good copy ─
        lab = new_lab()
        pve.guests[111] = copy.deepcopy(pve.guests[110])
        pve.guests[111]["config"].update(name="cold-03", scsi0="local-lvm:vm-111-disk-0,size=20G",
                                         net0="virtio=BC:24:11:0A:00:11,bridge=vmbr0")
        pve.guests[111]["config"].pop("onboot", None)
        pve.volumes["local-lvm:vm-111-disk-0"] = 111
        eb.stuck_disks = True
        job = wait_end(start(admin, {**pe, "vm": "111"}))
        eb.stuck_disks = False
        stuck = [vm["name"] for vm in eb.vms.values() if role_of(vm["name"])]
        check(f"the copy is confirmed and a disk will not come off the helper: the move is done, and the helper stays ({stuck})",
              job.get("state") == "done" and len(stuck) == 1 and "some tidying is left" in job["log"][-1]["text"]
              and "deletes the disks attached to it" in said(job))
        check(f"the new VM's disk was not deleted with it ({eb.gone})", not eb.gone)
        for k in [k for k, vm in eb.vms.items() if role_of(vm["name"])]:
            del eb.vms[k]

        # ── 7. ESXi to ESXi on the free licence ────────────────
        lab = new_lab()
        ff = {"c": cfa["id"], "vm": "4", "node": "", "to": cfb["id"], "dst_node": "", "storage": "datastore1",
              "net0": "VM Network"}
        plan = admin.post("/virt/move/check", json=ff).json().get("plan") or {}
        check(f"a VM of the same name on the new ESXi host is said before anything is made ({plan.get('problems')})",
              not plan.get("ok") and any("already has a VM called old-builder" in p for p in plan.get("problems", [])))
        del fb.vms["4"]
        plan = admin.post("/virt/move/check", json=ff).json().get("plan") or {}
        check(f"between two hosts on the free licence, a powered-off VM can be moved, with no sign-in and no guest address ({plan.get('problems')})",
              plan.get("ok") and plan.get("mode") == "off" and plan["src"]["road"] == "shell" and plan["dst"]["road"] == "shell"
              and plan["src"]["signin"] == "" and plan["src"]["guest_at"] == "")
        jid = start(admin, ff)
        up(jid, lab)
        hv = {role_of(vm["name"]): (k, vm) for h in (fa, fb) for k, vm in h.vms.items() if role_of(vm["name"])}
        gv = parse_vmx(sa.files.get(f"/vmfs/volumes/datastore1/{hv.get('give', ('', {'name': 'x'}))[1]['name']}/helper.vmx", b"").decode())
        check(f"the giver's settings file names the VM's disk by its full path, a serial file, and the CD as its only start device ({gv.get('scsi0:0.fileName')})",
              gv.get("scsi0:0.fileName") == "/vmfs/volumes/datastore1/old-builder/old-builder.vmdk"
              and gv.get("serial0.fileType") == "file" and gv.get("bios.bootOrder") == "cdrom"
              and gv.get("scsi0.virtualDev") == "pvscsi" and gv.get("memSize") == str(coldside.HELPER_MB))
        job = wait_end(jid)
        check(f"it ends done ({job.get('state')}: {said(job)[-300:]})", job.get("state") == "done")
        ids = {role: k for role, (k, _) in hv.items()}
        log = sa.log + sb.log
        check(f"a helper is taken off the host's list, never destroyed ({[c for c in log if 'vmsvc/destroy' in c or 'unregister' in c]})",
              any(c == f"vim-cmd vmsvc/unregister {ids.get('give')}" for c in sa.log)
              and any(c == f"vim-cmd vmsvc/unregister {ids.get('take')}" for c in sb.log)
              and not any("vmsvc/destroy" in c for c in log))
        check(f"no disk file was deleted on either host ({sa.gone}, {sb.gone})", not sa.gone and not sb.gone)
        check("each helper's own folder is gone, and nothing of EnvMap's is left on either datastore",
              not any("envmap-helper-" in p for s in (sa, sb) for p in list(s.files) + list(s.dirs))
              and not any("envmove-" in p and p.endswith(".iso") for s in (sa, sb) for p in s.files))
        new = next((k for k, vm in fb.vms.items() if vm["name"] == "old-builder"), None)
        nv = parse_vmx(sb.files.get("/vmfs/volumes/datastore1/old-builder/old-builder.vmx", b"").decode())
        check("the new VM is powered off, was never powered on, starts from its disk and has an empty CD drive",
              new and fb.vms[new]["power"] == "poweredOff" and f"vim-cmd vmsvc/power.on {new}" not in sb.log
              and "bios.bootOrder" not in nv and any(v == "atapi-cdrom" for v in nv.values()))
        check("the VM itself was never powered on", "vim-cmd vmsvc/power.on 4" not in sa.log and fa.vms["4"]["power"] == "poweredOff")
        check("both helpers were heard through their consoles' files", {("give", "console"), ("take", "console")} <= set(lab.asked))
        check(f"the old VM is renamed ({fa.vms['4']['name']})", re.match(r"^old-builder-left-\d{8}$", fa.vms["4"]["name"]))
        check("the host's API was asked to change nothing: the free licence would have refused", not fa.refused and not fb.refused)

        # the same road, undone: what goes is what was made, and nothing of the VM's
        lab = new_lab()
        lab.fail = {"give": "the helper on the new host did not answer for 30m0s"}
        fa.vms["3"]["power"], fa.vms["3"]["tools"] = "poweredOff", "guestToolsNotRunning"
        for k in [k for k, vm in fb.vms.items() if vm["name"] == "k8s-worker-07"]:
            del fb.vms[k]
        job = wait_end(start(admin, {**ff, "vm": "3"}))
        check(f"on the free licence a failed copy is undone too ({job.get('state')}: {said(job)[-200:]})", job.get("state") == "undone")
        check(f"the VM's disk was not deleted; the new VM's own was ({sa.gone}, {sb.gone})",
              not sa.gone and sb.gone == ["[datastore1] k8s-worker-07/k8s-worker-07.vmdk"])
        check("nothing of the move is left on either host",
              not any(role_of(vm["name"]) for h in (fa, fb) for vm in h.vms.values())
              and not any(vm["name"] == "k8s-worker-07" for vm in fb.vms.values())
              and fa.vms["3"]["name"] == "k8s-worker-07")
        sb.keep_on_list = True
        lab = new_lab()
        lab.fail = {"take": "disk 1 of the new VM cannot be written at byte 0: input/output error"}
        job = wait_end(start(admin, {**ff, "vm": "3"}))
        sb.keep_on_list = False
        check(f"a helper the host will not take off its list is left, and so is the new VM whose disk it holds ({job.get('state')})",
              job.get("state") == "failed" and "left for you to remove" in job["log"][-1]["text"]
              and any(role_of(vm["name"]) == "take" for vm in fb.vms.values())
              and any(vm["name"] == "k8s-worker-07" for vm in fb.vms.values()))
        check("and nothing more was deleted", sb.gone == ["[datastore1] k8s-worker-07/k8s-worker-07.vmdk"] and not sa.gone)

        # ── 8. the pages ───────────────────────────────────────
        r = admin.get(f"/virt/migrate/vms?c={cfb['id']}").json()
        vms = {v["name"]: v for v in r.get("vms", [])}
        helper_row = next((v for n, v in vms.items() if role_of(n)), {})
        check("on the migration page a powered-off VM can be selected, and says it is off",
              vms.get("old-builder", {}).get("off") is True and vms["old-builder"]["why"] == "" and not vms["old-builder"]["live"])
        check(f"a helper is listed as what it is, and cannot be selected ({helper_row.get('why')})",
              "own helper" in helper_row.get("why", ""))
        for k in [k for k, vm in fb.vms.items() if role_of(vm["name"]) or vm["name"] == "k8s-worker-07"]:
            del fb.vms[k]
        lab = new_lab()
        ea.vms["9"] = copy.deepcopy(eb.vms["4"])
        ea.vms["9"].update(name="spare-01")
        ea.files["datastore1"]["spare-01/spare-01.vmdk"] = 600
        ea.vms["9"]["devices"] = [dict(d, file="[datastore1] spare-01/spare-01.vmdk") if d["type"] == "VirtualDisk" else dict(d)
                                  for d in ea.vms["9"]["devices"]]
        r = admin.post("/virt/migrate/go", json={"c": cea["id"], "vm": "9", "node": "", "to": ceb["id"], "dst_node": ""}).json()
        check(f"the arrow moves a powered-off ESXi VM in one request: no sign-in is asked for, though none is saved ({r.get('needs')}, {r.get('error')})",
              r.get("ok") and r.get("started") and r.get("power") == "stopped" and r.get("signin") == "")
        active = admin.get("/virt/migrate/active").json().get("jobs", [])
        mine = next((j for j in active if j["id"] == r.get("id")), {})
        check("the page's list of moves says what kind it is", mine.get("mode") == "off")
        job = wait_end(r.get("id", ""))
        check(f"and it ends done ({job.get('state')}: {said(job)[-200:]})", job.get("state") == "done" and not ea.gone and not eb.gone)
        mine = next((j for j in admin.get("/virt/migrate/active").json().get("jobs", []) if j["id"] == r.get("id")), {})
        check("with its numbers for the page to draw", (mine.get("progress") or {}).get("total") == lab.total)
        r = looker.post("/virt/migrate/go", json={"c": cea["id"], "vm": "9", "node": "", "to": ceb["id"], "dst_node": ""}).json()
        check("the arrow is refused for somebody who may only look", r.get("ok") is False and "dminister" in r.get("error", ""))
        page = admin.get(f"/virt/move?c={cea['id']}&vm=5").text
        check("the full form of a running ESXi VM asks for the guest's sign-in", "The guest's sign-in" in page and "while it runs" in page)
        ea.vms["5"]["power"] = "poweredOff"
        page = admin.get(f"/virt/move?c={cea['id']}&vm=5").text
        check("the full form of a powered-off one does not, and says what will happen",
              "The guest's sign-in" not in page and "powered off" in page and "Neither the VM nor its copy is started" in page)
        page = admin.get(f"/virt/vm?c={cea['id']}&vm=5&kind=qemu").text
        check("a powered-off VM's own page offers to move it", "Move to another host" in page)
        page = admin.get(f"/virt/moves/job?id={jid}").text
        check("a powered-off move's page shows its own steps and a Stop button",
              'data-mode="off"' in page and "Disks copied and read back" in page and 'data-decide="stop"' in page
              and "Last changes cross" not in page)
    finally:
        for h in (pve, ea, eb, fa, fb):
            h.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
