#!/usr/bin/env python3
"""Managing servers through their BMCs from the Server hardware pages: every
action, every gate, the audit, the pages, the charts and the console relay.

Asked for on 24 November 2026: "do the same for the iDRAC page so we can also
fully manage it from EnvMap in the same way". This walks the whole surface
against a fake iDRAC that keeps state (tests/_fake_redfish.py):

  1. the action table: every action has an area and an audit name; the three
     new areas escalate, are handler-enforced and are not answerable; the
     audit puts the console under Privileged and the rest under Infrastructure
  2. every action runs and changes the fake server as it should, and a
     reset type the BMC does not list, an unknown boot device or an image
     that is not a URL or a share is refused before anything is sent
  3. the gates: a server that does not allow management refuses everything;
     a reader may look but not act; power and console without administer;
     administer includes both; production wants the server's name; every
     refusal is audited
  4. the pages: the list with its charts, every tab of a server, buttons
     disabled and saying why for somebody who may not use them
  5. the console: turning it on sets a random 8-character VNC password with
     TLS on the iDRAC, keeps it sealed in the connection and never sends it
     to a browser; the relay answers the VNC challenge itself and the browser
     gets a session with no password; one-time and bound to its owner; a
     wrong password fails cleanly and is audited; turning it off forgets it
  6. ticking management on a BMC connection is audited

    ./.venv/bin/python tests/test_bmc_manage.py
"""
from __future__ import annotations

import os
import pathlib
import re
import struct
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("bmc-manage-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi.testclient import TestClient                      # noqa: E402

from _fake_redfish import FakeRedfish, vnc_response           # noqa: E402
from app import answers, auth, bmc, bmcops, db, rbac, store    # noqa: E402
from app import main as portal                                # noqa: E402
from app.bmc import BmcError                                   # noqa: E402

bad = 0
PW = "Servers-Are-Managed-42"


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _user(email: str, areas: list[str] | None, admin: bool = False, projects=()) -> None:
    uid = auth.create_user(email, "BMC Tester", PW, role="admin" if admin else "user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    if areas is not None:
        rbac.set_for_user(uid, [rbac.save("", f"role-{email}", "", areas, list(projects), [])])


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
    r = c.post("/bmc/act", json=body)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


# ── 1. the table ───────────────────────────────────────────────
def test_table() -> None:
    for name, (need, label) in bmcops.ACTIONS.items():
        check(f"{name}: a known area", need in bmcops.AREAS)
        check(f"{name}: a label", bool(label))
        check(f"{name}: an audit name", bmcops.audit_name(name).startswith("bmc_"))
    check("every power action has a Redfish reset type", set(bmcops.POWER) <= set(bmcops.ACTIONS))
    for a in bmcops.AREAS.values():
        check(f"{a} is an area", a in rbac.AREAS)
        check(f"{a} escalates", a in rbac.ESCALATING)
        check(f"{a} is not answerable", a in answers.NOT_ANSWERABLE)
        check(f"{a} is handler-enforced (no prefix)", rbac.AREAS[a][2] == ())
    groups = {k: v[3] for k, v in auth.AUDIT_GROUPS.items()}
    for action, want in (("bmc_console", "privileged"), ("bmc_console_closed", "privileged"),
                         ("bmc_power_off", "infra"), ("bmc_media_insert", "infra")):
        # the predicate on its own: the audit is a hash chain, never written by hand
        got = db.q(f"SELECT 1 FROM (SELECT ? AS action) WHERE ({groups[want]})", (action,))
        check(f"{action} is in the {want} audit group", bool(got))
    check("a console row reads as privileged", auth.audit_severity("bmc_console") == "warn"
          and auth.audit_severity("virt_console") == "warn")
    pw = {bmcops._new_password() for _ in range(200)}
    check("a console password is 8 characters, mixed, and fresh each time",
          len(pw) == 200 and all(len(p) == 8 and re.search(r"[a-z]", p) and re.search(r"[A-Z]", p)
                                 and re.search(r"\d", p) for p in pw))
    ch = bytes(range(16))
    check("VNC authentication matches a VNC server's own check (and noVNC's)",
          bmcops._vnc_des("Ab3dEf7h", ch) == vnc_response("Ab3dEf7h", ch)
          and bmcops._vnc_des("Ab3dEf7h", ch).hex() == "4bac91fed2322a73783d686a4e9d49f5")


# ── 2. the engine against the fake iDRAC ───────────────────────
def test_engine(conn: dict, fake: FakeRedfish) -> None:
    st = bmcops.state(conn)
    check(f"state: power, the light, the reset types: {st['power']} {st['reset_allowed'][:3]}",
          st["power"] == "On" and not st["identify"] and "PowerCycle" in st["reset_allowed"]
          and st["dell"] and st["led_style"] == "location")
    inv = bmcops.inventory(conn)
    check(f"inventory: 2 CPUs, 6 DIMMs, a PERC with 2 drives and a RAID1: "
          f"{len(inv['cpus'])} {len(inv['dimms'])} {[(c['name'], len(c['drives']), len(c['volumes'])) for c in inv['controllers']]}",
          len(inv["cpus"]) == 2 and len(inv["dimms"]) == 6 and inv["mem_gib"] == 192
          and inv["controllers"] and inv["controllers"][0]["volumes"][0]["raid"] == "RAID1"
          and len(inv["controllers"][0]["drives"]) == 2 and len(inv["nics"]) == 4)
    check("a DIMM's warning comes through", any(d["health"] == "Warning" for d in inv["dimms"]))
    lg = bmcops.logs(conn, "sel")
    check(f"the hardware log, newest first: {[e['id'] for e in lg]}",
          [e["id"] for e in lg] == ["103", "102", "101", "100"] and lg[0]["severity"] == "Critical")
    check("the lifecycle log", len(bmcops.logs(conn, "lclog", 3)) == 3)
    md = bmcops.media(conn)
    check(f"virtual media: {[m['id'] for m in md]}", [m["id"] for m in md] == ["CD", "RemovableDisk"]
          and all(m["insert"] and m["eject"] for m in md))
    cs = bmcops.console_state(conn)
    check(f"the console starts off: {cs}", cs["available"] and not cs["enabled"])

    def run(action, **p):
        return bmcops.run(conn, action, p)

    run("power.off")
    check("power off = ForceOff", fake.power == "Off"
          and fake.calls[-1][2] == {"ResetType": "ForceOff"})
    run("power.on")
    check("power on = On", fake.power == "On" and fake.calls[-1][2] == {"ResetType": "On"})
    for action, rt in (("power.shutdown", "GracefulShutdown"), ("power.on", "On"),
                       ("power.restart", "GracefulRestart"), ("power.reset", "ForceRestart"),
                       ("power.cycle", "PowerCycle")):
        run(action)
        check(f"{action} sends {rt}", fake.calls[-1][2] == {"ResetType": rt})
    try:
        run("power.on")
        check("powering on a server that is on: the BMC's own reason", False)
    except BmcError as e:
        check(f"the BMC's own reason comes through: {e}", "already powered on" in str(e))
    run("identify.on")
    check("identify on", fake.led is True and bmcops.state(conn)["identify"])
    run("identify.off")
    check("identify off", fake.led is False)
    run("boot.once", target="Pxe")
    check(f"boot once from the network: {fake.boot}", fake.boot == {
        "BootSourceOverrideTarget": "Pxe", "BootSourceOverrideEnabled": "Once"})
    sent = len(fake.calls)
    for bad_target in ("None", "Network", "Pxe;reboot", ""):
        try:
            run("boot.once", target=bad_target)
            check(f"boot device {bad_target!r} refused", False)
        except BmcError:
            pass
    check("an unknown boot device is refused before anything is sent",
          not any(c[0] != "GET" for c in fake.calls[sent:]))
    run("boot.clear")
    check("boot override cleared", fake.boot["BootSourceOverrideEnabled"] == "Disabled")
    run("media.insert", device="CD", image="https://files.example.com/ubuntu-24.04.iso")
    check(f"an ISO by URL: {fake.media['CD']}", fake.media["CD"]["Inserted"]
          and fake.media["CD"]["Image"] == "https://files.example.com/ubuntu-24.04.iso"
          and fake.calls[-1][2]["WriteProtected"] is True)
    run("media.eject", device="CD")
    check("ejected", not fake.media["CD"]["Inserted"])
    for share in ("10.0.0.5:/exports/os.iso", "//10.0.0.5/share/os.iso"):
        run("media.insert", device="CD", image=share)
        check(f"a share: {share}", fake.media["CD"]["Image"] == share)
        run("media.eject", device="CD")
    sent = len(fake.calls)
    for bad_image in ("javascript:alert(1)", "file:///etc/passwd", "ftp://x/y.iso", "",
                      'https://x/"a.iso', "https://x/<b>.iso", "a" * 1200, "http://x/ a.iso",
                      "file:/etc/passwd", "smb://x/y.iso", "https:///etc/x", "///x/y", "nfs01://x"):
        try:
            run("media.insert", device="CD", image=bad_image)
            check(f"image {bad_image[:30]!r} refused", False)
        except BmcError:
            pass
    try:
        run("media.insert", device="Floppy", image="https://x/y.iso")
        check("an unknown media device is refused", False)
    except BmcError:
        pass
    check("a bad image is refused before anything is sent",
          not any(c[0] != "GET" for c in fake.calls[sent:]))
    run("log.clear")
    check("the hardware log cleared", [e["Message"] for e in fake.sel] == ["Log cleared."])
    run("bmc.reset")
    check("the BMC restarted, gracefully", fake.bmc_resets == 1
          and fake.calls[-1][2] == {"ResetType": "GracefulRestart"})
    fake.fail_next = "The iDRAC is busy with a firmware update."
    try:
        run("identify.on")
        check("a refusal from the BMC", False)
    except BmcError as e:
        check(f"a refusal carries the BMC's message: {e}", "firmware update" in str(e))
    for action in ("console.open", "nope"):
        try:
            run(action)
            check(f"{action} is not run here", False)
        except BmcError:
            pass


# ── 3-6. pages, gates, audit, console ──────────────────────────
def test_pages_and_gates(srv: dict, srv_ro: dict, srv_prod: dict, fake: FakeRedfish) -> None:
    _user("admin@bmc.test", None, admin=True)
    _user("reader@bmc.test", ["bmc"])
    _user("operator@bmc.test", ["bmc", "bmc_power", "bmc_console"])
    _user("admin2@bmc.test", ["bmc", "bmc_admin"])
    adm, rdr, opr, ad2 = (_client(e) for e in ("admin@bmc.test", "reader@bmc.test",
                                                "operator@bmc.test", "admin2@bmc.test"))
    S, R, P = srv["id"], srv_ro["id"], srv_prod["id"]

    # the list: charts above the table
    r = adm.get("/bmc?refresh=1")
    check(f"/bmc answers ({r.status_code})", r.status_code == 200)
    for title in ("Server health", "Power", "Hottest sensor", "Power draw"):
        check(f"the list shows the {title} chart", f"{title}" in r.text)
    check("the charts link to each server", f'href="/bmc?device={S}"' in r.text)
    check("the draw and temperatures are read", "286 W" in r.text and "58 °C" in r.text)

    # every tab of a server, for an administrator
    for sec in ("overview", "hardware", "logs", "boot", "console"):
        r = adm.get(f"/bmc?device={S}&sec={sec}")
        check(f"the {sec} tab answers ({r.status_code})", r.status_code == 200 and "data-endpoint=\"/bmc/act\"" in r.text)
    r = adm.get(f"/bmc?device={S}&sec=hardware")
    check("Hardware lists CPUs, DIMMs, the PERC and NICs",
          "Gold 6338" in r.text and "DIMM" not in r.text.split("Memory")[0][-50:]
          and "PERC H755 Front" in r.text and "B0:7B:25:00:00:01" in r.text)
    r = adm.get(f"/bmc?device={S}&sec=logs&log=lclog")
    check("the Lifecycle log tab", "Successfully logged in" in r.text)
    r = adm.get(f"/bmc?device={S}&sec=logs&log=../../etc")
    check("an unknown log name falls back to the hardware log", r.status_code == 200 and "Correctable memory" in r.text
          or "Log cleared" in r.text)
    r = adm.get(f"/bmc?device={S}&sec=boot")
    check("Boot & media: the targets and both media devices",
          "Network (PXE)" in r.text and "RemovableDisk" in r.text and 'data-act="media.insert"' in r.text)
    r = adm.get(f"/bmc?device={S}&sec=nope")
    check("an unknown tab is the Overview", r.status_code == 200 and "Temperatures" in r.text)
    check("the overview no longer says the portal never acts",
          "does not\n    act on it" not in r.text and "BIOS and RAID settings" in r.text)

    # a reader sees every button disabled, saying why
    r = rdr.get(f"/bmc?device={S}")
    check("a reader sees the page", r.status_code == 200)
    check("a reader's power buttons are disabled and say why",
          re.search(r'data-act="power\.off"[^>]*disabled title="your roles do not include', r.text, re.S))
    r = rdr.get(f"/bmc?device={R}")
    check("a read-only server says how to allow management",
          "Allow management from EnvMap" in r.text)

    # a greyed console button says why in words beside it: a tooltip never
    # shows on a phone
    r = adm.get(f"/bmc?device={R}&sec=console")
    note = r.text.split('class="sec-note why-off"', 1)[1].split("</div>", 1)[0] if "why-off" in r.text else ""
    check(f"a read-only server's Console tab says why it cannot be turned on: {note[:160]!r}",
          "You cannot turn it on from here" in note and "Allow management from EnvMap" in note)
    check("and links to that server's settings",
          f'href="/settings/conns/bmc?edit={R}#{R}"' in note)
    r2 = adm.get(f"/settings/conns/bmc?edit={R}")
    check("the settings page opens that row's Edit fold, and only that one",
          re.search(r'id="' + R + r'".*?<details class="adv"[^>]*\bopen>', r2.text, re.S)
          and r2.text.count('style="margin-top:8px;" open>') == 1)
    r = rdr.get(f"/bmc?device={S}&sec=console")
    check("a reader's Console tab names the missing role, with no settings link",
          "You cannot turn it on from here: your roles do not include" in r.text
          and "/settings/conns/bmc?edit=" not in r.text)
    r = adm.get(f"/bmc?device={R}")
    check("while the console is off, the bar's Console goes to the Console tab",
          f'href="/bmc?device={R}&sec=console"' in r.text and "aria-disabled" not in r.text)

    # the reader may not act
    code, j = act(rdr, {"c": S, "action": "power.off"})
    check(f"a reader cannot power off ({code})", code == 403 and audits("bmc_power_off_refused"))
    check("and nothing was sent", fake.power == "On")
    # the operator: power and console, not administer
    code, j = act(opr, {"c": S, "action": "power.off"})
    check(f"the operator powers off ({code} {j})", code == 200 and j.get("ok") and fake.power == "Off")
    row = audits("bmc_power_off")
    check(f"audited with who and where: {row[-1] if row else None}",
          row and row[-1]["user"] == "operator@bmc.test" and row[-1]["target"] == srv["name"])
    code, j = act(opr, {"c": S, "action": "power.on"})
    check("and on again", code == 200 and fake.power == "On")
    code, j = act(opr, {"c": S, "action": "boot.once", "target": "Pxe"})
    check(f"the operator cannot set the boot device ({code})", code == 403 and audits("bmc_boot_once_refused"))
    code, j = act(opr, {"c": S, "action": "console.enable"})
    check("the operator cannot turn the console on", code == 403)
    # administer includes power
    code, j = act(ad2, {"c": S, "action": "identify.on"})
    check("administer includes power", code == 200 and fake.led)
    act(ad2, {"c": S, "action": "identify.off"})
    code, j = act(ad2, {"c": S, "action": "media.insert", "device": "CD", "image": "https://files.example.com/os.iso"})
    check(f"administer inserts media ({code} {j})", code == 200 and fake.media["CD"]["Inserted"])
    row = audits("bmc_media_insert")
    check(f"the image is in the audit: {row[-1]['detail'] if row else None}",
          row and "image=https://files.example.com/os.iso" in row[-1]["detail"] and "device=CD" in row[-1]["detail"])
    code, j = act(ad2, {"c": S, "action": "media.insert", "device": "CD", "image": "https://files.example.com/os.iso"})
    check(f"a BMC refusal is a failure, audited: {j}", not j.get("ok") and audits("bmc_media_insert_failed"))
    act(ad2, {"c": S, "action": "media.eject", "device": "CD"})
    # a server that does not allow management refuses everything
    for action in ("power.on", "identify.on", "log.clear", "console.enable"):
        code, j = act(adm, {"c": R, "action": action})
        check(f"read-only server refuses {action} ({code})", code == 403 and "read-only" in j.get("error", ""))
    # production wants the server's own name
    code, j = act(adm, {"c": P, "action": "identify.on"})
    check(f"production wants the name ({code})", code == 403 and "type" in j.get("error", ""))
    code, j = act(adm, {"c": P, "action": "identify.on", "confirm": "something-else"})
    check("a wrong name is refused", code == 403)
    code, j = act(adm, {"c": P, "action": "identify.on", "confirm": srv_prod["name"]})
    check(f"the right name goes through ({code} {j})", code == 200)
    act(adm, {"c": P, "action": "identify.off", "confirm": srv_prod["name"]})
    # nonsense is refused
    for body in ({"c": S, "action": "console.open"}, {"c": S, "action": "rm -rf"},
                 {"c": "nope", "action": "power.on"}):
        code, j = act(adm, body)
        check(f"{body} is refused ({code})", code == 400)
    r = adm.post("/bmc/act", content=b"[1,2]", headers={"Content-Type": "application/json"})
    check("a body that is not an object is refused", r.status_code == 400)
    r = adm.post("/bmc/act", json={"c": S, "action": "power.off"},
                 headers={"Origin": "https://evil.example"})
    check(f"a cross-origin change is refused ({r.status_code})", r.status_code in (400, 403) and fake.power == "On")

    # ── the review's findings (24 November 2026) ──
    other = store.add_project("Elsewhere")
    _user("scoped@bmc.test", ["bmc", "bmc_admin"], projects=[other])
    scp = _client("scoped@bmc.test")
    r = scp.get("/bmc")
    check("a role confined to another project does not list these servers",
          r.status_code == 200 and srv["name"] not in r.text)
    code, j = act(scp, {"c": S, "action": "power.off"})
    check(f"nor acts on them ({code} {j})", code in (400, 403) and fake.power == "On")
    scp.__exit__(None, None, None)
    r = adm.post("/bmc/act", content=('{"c": "%s", "action": "power.off"}' % S).encode(),
                 headers={"Content-Type": "text/plain"})
    check(f"a change not sent as JSON is refused ({r.status_code})", r.status_code == 415 and fake.power == "On")
    r = adm.post("/bmc/act", json={"c": S, "action": "power.off"},
                 headers={"Authorization": "Basic dXNlcjpwYXNz", "Sec-Fetch-Site": "cross-site"})
    check(f"a Basic Authorization header carries no cross-site change through ({r.status_code})",
          r.status_code == 403 and fake.power == "On")
    code, j = act(ad2, {"c": S, "action": "media.insert", "device": "CD",
                        "image": "https://user:secret@files.example.com/os.iso"})
    check(f"a password in the image address is refused ({j.get('error')})",
          code == 200 and not j.get("ok") and "own fields" in j.get("error", "") and not fake.media["CD"]["Inserted"])
    code, j = act(ad2, {"c": S, "action": "media.insert", "device": "CD",
                        "image": "//nas.example.com/iso/os.iso", "username": "svc-iso", "password": "S3cret-share"})
    sent = next((c[2] for c in reversed(fake.calls) if c[0] == "POST" and "InsertMedia" in c[1]), {})
    check(f"a share's username and password go to the BMC in their own fields: {sorted(sent)}",
          code == 200 and sent.get("UserName") == "svc-iso" and sent.get("Password") == "S3cret-share")
    check("and never into the audit", "S3cret-share" not in str(db.q("SELECT detail, target FROM audit")))
    act(ad2, {"c": S, "action": "media.eject", "device": "CD"})
    r = adm.get(f"/bmc/console?c={S}", headers={"Sec-Fetch-Site": "cross-site"})
    check("a console reached from another site waits for a click", "opened from a link on another site" in r.text)

    # ── the console ──
    r = opr.post("/bmc/console/open", json={"c": S})
    check(f"the console cannot open while it is off: {r.json()}", not r.json().get("ok"))
    code, j = act(ad2, {"c": S, "action": "console.enable"})
    check(f"turning the console on ({code} {j})", code == 200 and j.get("ok"))
    pw = fake.attrs["VNCServer.1.Password"]
    check(f"the iDRAC gets VNC with TLS and a fresh 8-character password: {fake.attrs['VNCServer.1.SSLEncryptionBitLength']}",
          fake.attrs["VNCServer.1.Enable"] == "Enabled" and len(pw) == 8
          and fake.attrs["VNCServer.1.SSLEncryptionBitLength"] == "256-Bit or higher")
    check("the password is not in the answer", pw not in str(j))
    check("it is kept in the connection", store.get_bmc("", S).get("vnc_password") == pw)
    raw = db.q("SELECT data FROM conns WHERE id=?", (S,))[0]["data"]
    check("and sealed at rest", pw not in raw)
    for sec in ("overview", "console", "boot"):
        check(f"it is never on the {sec} page", pw not in adm.get(f"/bmc?device={S}&sec={sec}").text)
    check("the audit says it was turned on, without the password",
          audits("bmc_console_enable") and pw not in str(db.q("SELECT detail FROM audit")))
    r = adm.get(f"/bmc?device={S}&sec=console")
    check("the console tab says it is on", ">on</b>" in r.text and "/bmc/console?c=" in r.text)
    check("with nothing greyed out, it explains nothing", "why-off" not in r.text)
    r = rdr.get(f"/bmc?device={S}&sec=console")
    check("a reader's Open the console is a disabled button saying why, never a dead link",
          re.search(r'<button[^>]*disabled title="your roles do not include[^>]*>▣ Open the console', r.text)
          and "You cannot open it from here: your roles do not include" in r.text)
    r = opr.get(f"/bmc/console?c={S}")
    check(f"the console page opens for the operator ({r.status_code})", r.status_code == 200
          and "/bmc/console/open" in r.text and "/bmc/console.ws" in r.text and pw not in r.text)
    check("the console page refuses a reader", rdr.get(f"/bmc/console?c={S}").status_code == 403)
    j = opr.post("/bmc/console/open", json={"c": S}).json()
    check(f"the operator opens a console session: {j}", j.get("ok") and j.get("session") and not j.get("password"))
    check("it is audited as privileged access", audits("bmc_console"))
    try:
        with opr.websocket_connect(f"/bmc/console.ws?session={j['session']}") as ws:
            ver = ws.receive_bytes()
            check(f"the browser is greeted as RFB 3.8: {ver!r}", ver == b"RFB 003.008\n")
            ws.send_bytes(b"RFB 003.008\n")
            sec = ws.receive_bytes()
            check(f"the browser is offered only None: {sec!r}", sec == b"\x01\x01")
            ws.send_bytes(b"\x01")
            res = ws.receive_bytes()
            check(f"and accepted: {res!r}", res == b"\x00\x00\x00\x00")
            ws.send_bytes(b"\x01")
            init = ws.receive_bytes()
            w, h = struct.unpack(">HH", init[:4])
            check(f"the server's screen and name: {w}x{h} {init[24:]!r}", (w, h) == (1024, 768) and b"PowerEdge R650" in init)
            ws.send_bytes(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))
            got = b""
            while len(got) < 16 + w * h * 4:
                got += ws.receive_bytes()
            check("the whole screen comes back", got[0] == 0 and len(got) == 16 + w * h * 4)
            ws.send_bytes(struct.pack(">BBxxI", 4, 1, 0xffe3))
            time.sleep(0.2)
    except Exception as e:                                    # noqa: BLE001
        check(f"the console relay works: {type(e).__name__}: {e}", False)
    check(f"the iDRAC accepted EnvMap's answer to its challenge: {fake.vnc_auth}", fake.vnc_auth[-1:] == [True])
    check(f"keys reach the server: {fake.vnc_seen[-1:]}", any(t == 4 for t, _b in fake.vnc_seen))
    time.sleep(0.3)
    check("the session's end is audited with its length", audits("bmc_console_closed"))
    try:
        with opr.websocket_connect(f"/bmc/console.ws?session={j['session']}") as ws:
            ws.receive_bytes()
            check("a console session is single-use", False)
    except Exception:                                         # noqa: BLE001
        pass
    j2 = opr.post("/bmc/console/open", json={"c": S}).json()
    try:
        with ad2.websocket_connect(f"/bmc/console.ws?session={j2['session']}") as ws:
            ws.receive_bytes()
            check("somebody else cannot use another's console session", False)
    except Exception:                                         # noqa: BLE001
        pass
    try:
        with rdr.websocket_connect(f"/bmc/console.ws?session={j2['session']}") as ws:
            ws.receive_bytes()
            check("a reader cannot reach the relay", False)
    except Exception:                                         # noqa: BLE001
        pass
    r = rdr.post("/bmc/console/open", json={"c": S})
    check("a reader cannot open a console", r.status_code == 403 and audits("bmc_console_refused"))
    # a session opened, then management closed: the relay refuses it
    j3 = opr.post("/bmc/console/open", json={"c": S}).json()
    store.update_bmc("", S, manage="")
    try:
        with opr.websocket_connect(f"/bmc/console.ws?session={j3['session']}") as ws:
            ws.receive_bytes()
            check("a session dies when the server is closed to management", False)
    except Exception:                                         # noqa: BLE001
        pass
    store.update_bmc("", S, manage="1")
    # a wrong password: the relay fails cleanly and says so
    store.update_bmc("", S, vnc_password="Wrong123")
    j4 = opr.post("/bmc/console/open", json={"c": S}).json()
    before = len(audits("bmc_console_failed"))
    try:
        with opr.websocket_connect(f"/bmc/console.ws?session={j4['session']}") as ws:
            ws.receive_bytes()
            ws.send_bytes(b"RFB 003.008\n")
            ws.receive_bytes()
            check("a refused password never reaches the browser's security step", False)
    except Exception:                                         # noqa: BLE001
        pass
    time.sleep(0.3)
    failed = audits("bmc_console_failed")
    check(f"a refused password is audited as a failure: {fake.vnc_auth[-1:]} {failed[-1]['detail'] if failed else ''}",
          fake.vnc_auth[-1:] == [False] and len(failed) > before
          and "refused the password" in failed[-1]["detail"])
    store.update_bmc("", S, vnc_password=pw)
    # TLS turned off on the iDRAC behind EnvMap's back: no console in the clear
    fake.attrs["VNCServer.1.SSLEncryptionBitLength"] = "Disabled"
    r = opr.post("/bmc/console/open", json={"c": S}).json()
    check(f"a console without TLS is refused: {r.get('error')}", not r.get("ok") and "without TLS" in r.get("error", ""))
    fake.attrs["VNCServer.1.SSLEncryptionBitLength"] = "256-Bit or higher"
    # turning it off
    code, j = act(ad2, {"c": S, "action": "console.disable"})
    check("turning the console off", code == 200 and fake.attrs["VNCServer.1.Enable"] == "Disabled"
          and not store.get_bmc("", S).get("vnc_password"))
    r = opr.post("/bmc/console/open", json={"c": S})
    check("and it no longer opens", not r.json().get("ok"))

    # ticking management on is an audited access decision
    conn = store.get_bmc("", R)
    r = adm.post(f"/settings/conns/bmc/{R}/update",
                 data={"pid": "", "name": conn["name"], "base_url": conn["base_url"],
                       "username": conn["username"], "skip_tls": "1", "manage": "1"},
                 follow_redirects=False)
    check(f"the manage tick is saved ({r.status_code})", store.get_bmc("", R).get("manage") == "1")
    check("and audited", audits("bmc_manage_on"))
    check("the password survived the edit", store.get_bmc("", R).get("token") == "calvin")
    r = adm.post(f"/settings/conns/bmc/{R}/update",
                 data={"pid": "not-the-project", "name": conn["name"], "base_url": conn["base_url"],
                       "username": conn["username"], "skip_tls": "1", "manage": ""},
                 follow_redirects=False)
    check("a wrong project in the form still audits switching management off",
          store.get_bmc("", R).get("manage") == "" and audits("bmc_manage_off"))
    r = adm.post(f"/settings/conns/bmc/{R}/update",
                 data={"pid": "", "name": conn["name"], "base_url": conn["base_url"],
                       "username": conn["username"], "skip_tls": ""}, follow_redirects=False)
    check("turning TLS verification back on is audited", audits("bmc_skip_tls_off"))
    for c in (adm, rdr, opr, ad2):
        c.__exit__(None, None, None)


def main() -> int:
    fake = FakeRedfish().start()
    if os.environ.get("BMC_DEBUG"):
        import atexit
        atexit.register(lambda: print([(r["action"], r["target"], r["detail"][:80]) for r in
                                       db.q("SELECT * FROM audit WHERE action LIKE 'bmc%' ORDER BY id")]))
    try:
        test_table()
        srv = {"type": "redfish", "name": "r650-lab", "base_url": fake.url, "username": "root",
               "token": "calvin", "skip_tls": "1", "manage": "1"}
        srv_ro = {**srv, "name": "r650-readonly", "manage": ""}
        srv_prod = {**srv, "name": "r650-prod", "production": "1"}
        for c in (srv, srv_ro, srv_prod):
            c["id"] = store.add_bmc("", dict(c))
        test_engine(store.get_bmc("", srv["id"]), fake)
        bmc.invalidate()
        test_pages_and_gates(srv, srv_ro, srv_prod, fake)
    finally:
        fake.stop()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
