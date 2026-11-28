"""The VM migration page: two hosts side by side, and an arrow.

Asked for on 27 November 2026: "i select the host on the right ... then i can
click the arrow and i can see the VM moving", and "it is not a good experience
to ask me for the password again". The page decides nothing itself: the arrow
posts to /virt/migrate/go, vmmove.autofill fills in what is certain, and what
is not comes back as a question instead of a guess.

  1. the page and its two lists: which hosts, which VMs, who may move
  2. the arrow with no sign-in saved for the host: nothing starts, and the one
     thing asked for is the VM's own sign-in
  3. typed once and saved for the host: the move runs; the sign-in is sealed
     on the connection and is on no page, in no answer and in no job
  4. the next VM of that host: one request, no question
  5. a VM that refuses the saved sign-in: asked again for that VM, and what is
     saved for the host stays
  6. a network the other host does not have: asked, never guessed, and
     remembered for these two hosts afterwards
  7. a production hypervisor: the VM's name is asked for
  8. Settings → Hypervisors: save, keep on an untouched form, replace, forget
  9. somebody who may look and may not move
 10. Proxmox to Proxmox: no sign-in at all

    ./.venv/bin/python tests/test_vmmigrate.py

The hosts are the stand-ins of tests/test_esxshell.py (two ESXi hosts on the
free licence, worked through a stand-in shell) and tests/_fake_pve_agent.py.
"""
from __future__ import annotations

import copy
import html
import json
import os
import pathlib
import re
import sys
import tempfile
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("vmmigrate-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
PARTS = pathlib.Path(tempfile.mkdtemp(prefix="vmmigrate-parts-"))
os.environ["PORTAL_ENVMOVE_DIR"] = str(PARTS)

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_esxi import FakeEsxi, free_licence                  # noqa: E402
from _fake_esxshell import EsxiShell, Guest, SshWorld          # noqa: E402
from _fake_pve_agent import AgentPve                           # noqa: E402
from app import auth, db, env, rbac, store, vmmove             # noqa: E402
from app import main as portal                                # noqa: E402

bad = 0
PW = "Two-Boxes-And-An-Arrow-42"
SECRET = "guest-password"                                      # what the stand-in guests take


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
    uid = auth.create_user(email, "Migration Tester", PW, role=role)
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


def audits(action: str) -> list:
    return db.q("SELECT * FROM audit WHERE action=?", (action,))


def wait_end(c: TestClient, jid: str, limit: float = 120) -> dict:
    t0, j = time.time(), {}
    while time.time() - t0 < limit:
        j = (c.get(f"/virt/moves/state?id={jid}").json().get("job")) or {}
        if j.get("state") in ("done", "undone", "failed", "stuck") and not j.get("running"):
            return j
        time.sleep(0.3)
    return j


SHAPE: dict = {}              # the stand-in's k8s-worker-07 as it was before anything moved


def another_vm(host: FakeEsxi, moid: str, name: str, ip: str, network: str = "VM Network") -> None:
    """One more running VM on a stand-in host, shaped like its k8s-worker-07."""
    host.vms[moid] = dict(copy.deepcopy(SHAPE), name=name, ip=ip)
    host.vms[moid]["devices"] = [d for d in host.vms[moid]["devices"] if d["key"] in (100, 1000, 15000, 2000, 4000, 16000)]
    for d in host.vms[moid]["devices"]:
        if d["key"] == 4000:
            d["network"] = network


def hosts_of(page: str) -> list:
    m = re.search(r"data-hosts='([^']*)'", page)
    return json.loads(html.unescape(m.group(1))) if m else []


def go(c: TestClient, ca: dict, cb: dict, vm: str, **more) -> dict:
    r = c.post("/virt/migrate/go", json={"c": ca["id"], "vm": vm, "node": "", "to": cb["id"], "dst_node": "", **more})
    return {"_text": r.text, **r.json()}


def conn(cid: str) -> dict:
    return next(c for c in store.all_virt() if c["id"] == cid)


def moved(c: TestClient, r: dict, what: str) -> dict:
    check(f"{what}: started ({r.get('error') or r.get('needs') or r.get('problems')})", r.get("ok") and r.get("started"))
    job = wait_end(c, r.get("id", "")) if r.get("started") else {}
    check(f"{what}: moved (ended {job.get('state')}: {[e['text'] for e in job.get('log', [])][-3:]})",
          job.get("state") == "done")
    return job


def main() -> int:
    make_parts()
    a, b = FakeEsxi().start(), FakeEsxi(name="esx-lab-02.example.internal").start()
    pve = AgentPve().start()
    world = SshWorld()
    env.SSH = world.install(tempfile.mkdtemp(prefix="vmmigrate-ssh-"))
    try:
        for h in (a, b):
            free_licence(h)
            next(s for s in h.services if s["key"] == "TSM-SSH")["running"] = True
            h.vms["2"]["snapshots"], h.vms["2"]["current"] = [], ""
        # an ESXi host has one VM of a name, and the new VM carries the VM's
        # name: the second stand-in's own VMs are called something else
        for vm in b.vms.values():
            vm["name"] = "b-" + vm["name"]
        pve.guests[100]["config"].pop("efidisk0", None)
        SHAPE.update(copy.deepcopy(a.vms["3"]))
        base = {"type": "vsphere", "username": "root", "token": "lab-password", "skip_tls": "1", "manage": "1"}
        ca = {**base, "name": "free-a", "base_url": a.url}
        cb = {**base, "name": "free-b", "base_url": b.url.replace("127.0.0.1", "localhost")}
        cp = {"type": "proxmox", "name": "lab-pve", "base_url": pve.url, "username": "root@pam!envmap",
              "token": "pve-token-secret", "skip_tls": "1", "manage": "1"}
        for c in (ca, cb, cp):
            c["id"] = store.add_virt("", dict(c))
        sa, sb = EsxiShell(a, "127.0.0.1"), EsxiShell(b, "localhost")
        world.ends.update({"127.0.0.1": sa, "localhost": sb})
        _user("mover@example.com", ["virt", "virt_admin"])
        _user("looker@example.com", ["virt"])
        _user("boss@example.com", [], role="admin")
        admin, looker, boss = _client("mover@example.com"), _client("looker@example.com"), _client("boss@example.com")

        # ── 1. the page and its lists ──────────────────────────
        r = admin.get("/virt")
        check("the Hypervisors page has a VM migration button, above its charts",
              'href="/virt/migrate"' in r.text and r.text.index('href="/virt/migrate"') < r.text.index('class="apanels"'))
        r = admin.get("/virt/migrate")
        hs = hosts_of(r.text)
        names = [h["name"] for h in hs]
        check(f"the page lists every ESXi host and every Proxmox node ({names})",
              r.status_code == 200 and names == ["free-a", "free-b", "lab-pve · pve-01", "lab-pve · pve-02"])
        check("each can be moved from and to by an administrator of it, and none has a sign-in saved yet",
              all(h["why"] == "" and not h["off"] and h["signin"] is False for h in hs))
        r = admin.get(f"/virt/migrate/vms?c={ca['id']}").json()
        vms = {v["name"]: v for v in r.get("vms", [])}
        check(f"a host's list has its VMs, the running ones first ({[v['name'] for v in r.get('vms', [])]})",
              r.get("ok") and list(vms)[-1] == "old-builder" and vms["web-01"]["live"] and vms["web-01"]["why"] == "")
        check("a VM that is powered off is there and can be selected: it is moved by its disks",
              vms["old-builder"]["off"] is True and vms["old-builder"]["why"] == "" and not vms["old-builder"]["live"])
        r = admin.get(f"/virt/migrate/vms?c={cp['id']}&node=pve-02").json()
        check(f"a Proxmox node's list holds that node's guests only, and a container says it is one ({r.get('vms')})",
              [v["name"] for v in r.get("vms", [])] == ["dns-01"] and "container" in r["vms"][0]["why"])
        check("a connection that is not there is not read", admin.get("/virt/migrate/vms?c=nope").status_code == 404)

        # ── 2. the arrow, with no sign-in saved ────────────────
        world.ends["10.20.0.21"] = Guest("10.20.0.21", a, "1", b, sb)
        jobs = len(vmmove.all_jobs())
        r = go(admin, ca, cb, "1")
        check(f"with no sign-in saved for the host, nothing starts ({r.get('needs')})",
              r.get("ok") and r.get("started") is False and len(vmmove.all_jobs()) == jobs)
        check("and the one thing asked for is the VM's own sign-in", r.get("needs") == {"signin": "none"})
        check(f"the datastore and the network were chosen meanwhile, and say how ({r.get('chosen')}, {r.get('cards')})",
              r["chosen"]["storage"] == "datastore1" and r["cards"][0]["network"] == "VM Network"
              and r["cards"][0]["how"] == "same name")
        check("the guest was not asked anything yet: no sign-in was tried", world.ends["10.20.0.21"].attempts == 0)

        # ── 3. typed once, and saved for the host ──────────────
        r = go(admin, ca, cb, "1", guest_user="root", guest_password=SECRET, save_signin=True)
        check("the answer to the arrow never carries the sign-in back", SECRET not in r["_text"])
        during = admin.get("/virt/migrate/active").json()
        check(f"the move is listed as under way, from one host to the other ({during.get('jobs')})",
              any(j["name"] == "web-01" and j["from"]["key"] == f"{ca['id']}|" and j["to"]["key"] == f"{cb['id']}|"
                  for j in during.get("jobs", [])) and SECRET not in json.dumps(during))
        seen, t0 = [], time.time()
        while not seen and time.time() - t0 < 30:
            seen = [v for v in admin.get(f"/virt/migrate/vms?c={cb['id']}&refresh=1").json().get("vms", []) if v.get("arriving")]
            time.sleep(0.3)
        check(f"while it moves, the new VM on the other host is listed as arriving, and cannot be selected ({seen})",
              len(seen) == 1 and seen[0]["arriving"] == r.get("id") and "arriving" in seen[0]["why"])
        job = moved(admin, r, "the first VM")
        check("it used the sign-in that was typed", (job.get("src") or {}).get("signin") == "typed")
        kept = conn(ca["id"])
        check("the sign-in is kept on the host's connection", (kept.get("guest_user"), kept.get("guest_password")) == ("root", SECRET))
        raw = db.q("SELECT data FROM conns WHERE id=?", (ca["id"],))[0]["data"]
        check("sealed where it is stored, like the connection's own password", SECRET not in raw and "lab-password" not in raw)
        said = [x["detail"] or "" for x in audits("virt_guest_signin_saved")]
        check(f"saving it is audited, with the user and without the password ({said})",
              len(said) == 1 and "user root" in said[0] and SECRET not in said[0])
        check("the other host has none: one host's sign-in is not another's", not conn(cb["id"]).get("guest_password"))
        pages = {p: boss.get(p).text for p in ("/virt/migrate", "/settings/conns/virt", "/virt/moves",
                                               f"/virt/move?c={ca['id']}&vm=3", f"/virt/moves/job?id={job.get('id')}")}
        check(f"it is on no page ({[p for p, t in pages.items() if SECRET in t]})", not any(SECRET in t for t in pages.values()))
        check("the migration page knows the host has one saved",
              next(h for h in hosts_of(pages["/virt/migrate"]) if h["name"] == "free-a")["signin"] is True)
        check("the per-VM form says a saved sign-in is used when its password is left empty",
              "A sign-in is saved for this host" in pages[f"/virt/move?c={ca['id']}&vm=3"])
        disk = (vmmove.MOVES / f"{job.get('id')}.json").read_text()
        check("and it is in no move's record", SECRET not in disk)
        r = admin.get(f"/virt/migrate/vms?c={cb['id']}&refresh=1").json()
        check("the VM is now in the other host's list, running, and can be selected like any other",
              any(v["name"] == "web-01" and v["live"] and not v["why"] and not v["arriving"] for v in r.get("vms", [])))
        after = admin.get("/virt/migrate/active").json()
        check("a move that has just ended is still shown as ended, so the page can say so",
              any(j["id"] == job.get("id") and j["state"] == "done" for j in after.get("jobs", [])))

        # ── 4. the next VM: one request ────────────────────────
        world.ends["10.20.0.47"] = Guest("10.20.0.47", a, "3", b, sb)
        r = go(admin, ca, cb, "3")
        check("with the host's sign-in saved, the arrow asks nothing", r.get("started") is True and not r.get("needs"))
        job = moved(admin, r, "the second VM, one click")
        check("it used the saved sign-in, and its record says so without holding it",
              (job.get("src") or {}).get("signin") == "saved"
              and SECRET not in (vmmove.MOVES / f"{job.get('id')}.json").read_text())

        # ── 5. a VM that refuses the saved sign-in ─────────────
        another_vm(a, "6", "queue-02", "10.20.0.60")
        odd = world.ends["10.20.0.60"] = Guest("10.20.0.60", a, "6", b, sb, password="its-own-password")
        r = go(admin, ca, cb, "6")
        check(f"a VM that refuses the host's saved sign-in is not moved, and is asked for its own ({r.get('needs')}, {r.get('problems')})",
              r.get("started") is False and r.get("needs") == {"signin": "refused"}
              and any("sign-in was refused" in p for p in r.get("problems", [])))
        check(f"the check cost that VM one failed sign-in, not several ({odd.attempts})", odd.attempts == 1)
        r = go(admin, ca, cb, "6", guest_user="root", guest_password="its-own-password")
        moved(admin, r, "the VM with its own sign-in")
        check("typed without the save tick, it replaces nothing: the host's saved sign-in stays",
              conn(ca["id"]).get("guest_password") == SECRET and len(audits("virt_guest_signin_saved")) == 1)

        # ── 6. a network the other host does not have ──────────
        b.portgroups = [g for g in b.portgroups if g["name"] != "DB Network"]
        world.ends["10.20.1.10"] = Guest("10.20.1.10", a, "2", b, sb)
        r = go(admin, ca, cb, "2")
        check(f"a card whose network the other host does not have: asked, never guessed ({r.get('needs')}, {r.get('cards')})",
              r.get("started") is False and r.get("needs") == {"nets": [0]} and r["cards"][0]["network"] == ""
              and r["cards"][0]["now"] == "DB Network" and "VM Network" in r.get("networks", []))
        r = go(admin, ca, cb, "2", net0="VM Network")
        job = moved(admin, r, "the VM with a network chosen by hand")
        check("the new VM's card is on the network that was chosen",
              ((job.get("dst") or {}).get("nets") or [{}])[0].get("network") == "VM Network")
        another_vm(a, "7", "db-02", "10.20.1.11", network="DB Network")
        world.ends["10.20.1.11"] = Guest("10.20.1.11", a, "7", b, sb)
        r = go(admin, ca, cb, "7", ask=True)
        check(f"asked to see the choices first, nothing starts, and the card is on the network chosen last time ({r.get('cards')})",
              r.get("started") is False and not r.get("needs") and r["cards"][0]["network"] == "VM Network"
              and r["cards"][0]["how"] == "as last time")
        r = go(admin, ca, cb, "7")
        moved(admin, r, "the next VM on that network, one click")

        # ── 7. production ──────────────────────────────────────
        store.update_virt("", cb["id"], production="1")
        another_vm(a, "8", "ledger-01", "10.20.0.70")
        world.ends["10.20.0.70"] = Guest("10.20.0.70", a, "8", b, sb)
        r = go(admin, ca, cb, "8")
        check(f"a production hypervisor: the VM's name is asked for, and nothing starts ({r.get('needs')})",
              r.get("started") is False and r.get("needs") == {"confirm": "ledger-01"})
        r = go(admin, ca, cb, "8", confirm="ledger")
        check("another name is not it", r.get("started") is False and r.get("needs") == {"confirm": "ledger-01"})
        r = go(admin, ca, cb, "8", confirm="ledger-01")
        moved(admin, r, "the VM, once its name was typed")
        store.update_virt("", cb["id"], production="")

        # ── 8. Settings → Hypervisors ──────────────────────────
        form = {"pid": "", "name": "free-b", "base_url": cb["base_url"], "username": "root", "skip_tls": "on", "manage": "on"}
        url = f"/settings/conns/virt/{cb['id']}/update"
        r = boss.get("/settings/conns/virt")
        check("the connection's Edit form has the sign-in for the host's VMs",
              "sign-in for this host's VMs" in r.text and 'name="guest_password"' in r.text)
        boss.post(url, data={**form, "guest_user": "deploy", "guest_password": "from-settings"}, follow_redirects=False)
        check("saved from Settings", (conn(cb["id"]).get("guest_user"), conn(cb["id"]).get("guest_password")) == ("deploy", "from-settings"))
        store.update_virt("", cb["id"], guest_password="")
        check("the store itself keeps a stored sign-in that arrives blank, whoever sends it",
              conn(cb["id"]).get("guest_password") == "from-settings")
        boss.post(url, data={**form, "guest_user": "deploy", "guest_password": ""}, follow_redirects=False)
        check("a form saved without touching the password keeps it", conn(cb["id"]).get("guest_password") == "from-settings"
              and conn(cb["id"]).get("manage") and conn(cb["id"]).get("token") == "lab-password")
        r = boss.get("/settings/conns/virt")
        check("the page says one is stored and never shows it", "stored — type to replace" in r.text and "from-settings" not in r.text
              and 'name="guest_forget"' in r.text)
        boss.post(url, data={**form, "guest_user": "deploy", "guest_password": "replaced"}, follow_redirects=False)
        check("typed again, it is replaced", conn(cb["id"]).get("guest_password") == "replaced")
        boss.post(url, data={**form, "guest_user": "deploy", "guest_password": "", "guest_forget": "on"}, follow_redirects=False)
        check("forgotten, it is gone, and the connection itself is as it was",
              not conn(cb["id"]).get("guest_password") and not conn(cb["id"]).get("guest_user")
              and conn(cb["id"]).get("token") == "lab-password" and conn(cb["id"]).get("manage"))
        check("saving and forgetting are both audited",
              len(audits("virt_guest_signin_saved")) == 3 and len(audits("virt_guest_signin_forgotten")) == 1)
        check("the Proxmox connection has no such field: its VMs need no sign-in",
              boss.get("/settings/conns/virt").text.count('name="guest_password"') == 2)

        # ── 9. somebody who may look ───────────────────────────
        r = looker.get("/virt/migrate")
        check("somebody who may only look sees the page, and each host says why its VMs cannot be moved",
              r.status_code == 200 and all("Administer" in h["why"] or "administer" in h["why"] for h in hosts_of(r.text)))
        check("and sees a host's VMs", looker.get(f"/virt/migrate/vms?c={ca['id']}").json().get("ok"))
        another_vm(a, "9", "idle-01", "10.20.0.90")
        refused = len(audits("virt_vm_move_refused"))
        r = go(looker, ca, cb, "9")
        check(f"the arrow is refused for them, in words, and that is audited ({r.get('error')})",
              r.get("ok") is False and "dminister" in (r.get("error") or "")
              and len(audits("virt_vm_move_refused")) == refused + 1)
        r = go(admin, ca, ca, "9")
        check(f"a VM is not moved to the host it is on ({r.get('error')})", r.get("ok") is False and "already" in (r.get("error") or ""))
        a.vms["4"]["power"] = "suspended"
        r = go(admin, ca, cb, "4")
        check(f"a VM that is neither running nor powered off is not moved, and it says what to do ({r.get('error')})",
              r.get("ok") is False and "resume it, or power it off" in (r.get("error") or ""))
        r = admin.get(f"/virt/migrate/vms?c={ca['id']}&refresh=1").json()
        why = next((v["why"] for v in r.get("vms", []) if v["name"] == "old-builder"), "")
        check(f"and its row says the same ({why})", "resume it, or power it off" in why)
        a.vms["4"]["power"] = "poweredOff"

        # ── 10. Proxmox to Proxmox: no sign-in ─────────────────
        body = {"c": cp["id"], "vm": "100", "node": "pve-01", "to": cp["id"], "dst_node": "pve-01"}
        r = admin.post("/virt/migrate/go", json=body).json()
        check(f"the node a VM is on is not a place to move it to ({r.get('error')})", r.get("ok") is False and "already" in (r.get("error") or ""))
        r = admin.post("/virt/migrate/go", json={**body, "dst_node": "pve-02", "ask": True}).json()
        check(f"between two Proxmox nodes nothing is asked: storage, CD, bridge and VLAN tag are filled in ({r.get('needs')}, {r.get('chosen')}, {r.get('cards')})",
              r.get("ok") and not r.get("needs") and r["chosen"] == {"storage": "local-lvm", "iso_storage": "local"}
              and r["cards"][0]["network"] == "vmbr0" and r["cards"][0]["vlan"] == "20" and r.get("signin") == "")
        r = admin.post("/virt/migrate/go", json={**body, "dst_node": "pve-02"}).json()
        job = moved(admin, r, "a Proxmox VM, one click and no sign-in")
        check("it went to the node that was chosen, with its VLAN tag",
              (job.get("dst") or {}).get("node") == "pve-02" and ((job.get("dst") or {}).get("nets") or [{}])[0].get("vlan") == "20")
    finally:
        for h in (a, b, pve):
            h.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
