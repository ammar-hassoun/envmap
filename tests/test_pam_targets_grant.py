"""Where a brokered credential goes is its own grant, and moving a target
forgets the credential and the pinned key it had.

WHY THIS EXISTS
    `POST /pam/target/save` asked for nothing but the read-only `pam` area, and
    for no target scope at all. Anybody who could read the catalogue could add
    a target, or change an existing one's address, port or protocol -- and a
    blank secret on an edit meant "keep the stored one", so the next session
    on a moved target handed its password or key to whatever answered at the
    new address. `pam` is documented as read-only on its own; it was not.

    `pam_targets` ("Privileged Access: manage targets") is the grant now:
    escalating, scoped like the others, unconfined to create, and backfilled
    onto nobody. Pointing a target somewhere new refuses to carry the stored
    credential (it has to be typed again), drops the pinned host key, and is
    audited with the old and the new address and never the secret.

    This drives every route with roles on both sides of each line, and pins
    the module rule underneath them, because a route is not the only caller of
    `pam.save_target`.
"""
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamtargets-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app import ansible, answers, auth, db, main, pam, rbac  # noqa: E402

bad = 0
KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
LABEL = "Privileged Access: manage targets"
NOTE = ("adding targets and changing them — address, port, protocol and the "
        "credential each one brokers")


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


def enrol(email: str, pw: str, role_ids, role: str = "viewer") -> dict:
    uid = auth.create_user(email, "N", pw, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, role_ids)
    return auth.by_id(uid)


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def known(text: str) -> str:
    path = os.path.join(tempfile.mkdtemp(), "known_hosts")
    with open(path, "w") as fh:
        fh.write(text)
    return path


def mark() -> int:
    return int(db.q("SELECT COALESCE(MAX(id), 0) AS n FROM audit")[0]["n"])


def audits(since: int, action: str) -> list:
    return [dict(r) for r in db.q("SELECT * FROM audit WHERE id > ? AND "
                                  "action = ? ORDER BY id", (since, action))]


def err_of(r) -> str:
    return urllib.parse.unquote(r.headers.get("location", ""))


def target(name: str, address: str, **more) -> str:
    return pam.save_target("", {"name": name, "protocol": "ssh",
                                "address": address, "port": "22",
                                "auth_kind": "none", **more}, "t")


def form(tid: str, name: str, address: str, **more) -> dict:
    """The fields the target page posts, as the browser would send them."""
    return {"tid": tid, "name": name, "protocol": "ssh", "address": address,
            "port": "22", "auth_kind": "none", "secret": "", "secret_key": "",
            **more}


def row_actions(page: str, tid: str) -> str:
    """The action cell of one catalogue row."""
    i = page.find(f'id="t-{tid}"')
    if i < 0:
        return ""
    j = page.find("</tr>", i)
    return page[i:j]


def the_area() -> None:
    print("manage targets is one new escalating area, next to the others")
    check("it is in the role editor's list, with its label and note",
          rbac.AREAS.get("pam_targets", ("", "", None))[:2] == (LABEL, NOTE),
          str(rbac.AREAS.get("pam_targets")))
    check("its prefix is empty, so the handlers enforce it",
          rbac.AREAS["pam_targets"][2] == ())
    keys = list(rbac.AREAS)
    check("it sits among the Privileged Access grants",
          keys.index("pam") < keys.index("pam_targets")
          < keys.index("pam_connect"))
    check("only an administrator may hand it out",
          "pam_targets" in rbac.ESCALATING)
    check("and a question cannot use it",
          "pam_targets" in answers.NOT_ANSWERABLE
          and not answers.coverage()["missing"])
    check("pam_delete was not widened to cover it",
          "changing" not in rbac.AREAS["pam_delete"][1]
          and "adding" not in rbac.AREAS["pam_delete"][1])

    # NOT BACKFILLED. A role as the last release stored it, holding `pam`, is
    # put through the migrations that ship -- and must not come out holding
    # the new grant, because editing with `pam` alone was the bug.
    with db.tx() as c:
        c.execute("INSERT INTO roles (id, name, note, areas, projects, "
                  "clusters, targets, created) VALUES ('r-old', 'old', '', ?, "
                  "'[]', '[]', '[]', '')", (json.dumps(["pam", "pam_connect"]),))
        c.execute("DELETE FROM rbac_migrations")
    conn = db.connect()
    rbac._migrate(conn)
    conn.commit()
    got = set((rbac.get("r-old") or {}).get("areas") or [])
    check("an existing role holding pam is not handed it on upgrade",
          "pam_targets" not in got and "pam" in got, str(sorted(got)))


def role_editor() -> None:
    print("the role editor lists it, marked as full control")
    enrol("adm@pamtargets.test", "Admin-Targets-Pass-42", [], role="admin")
    c = signed_in("adm@pamtargets.test", "Admin-Targets-Pass-42")
    page = c.get("/admin/roles").text
    box = page.find('value="pam_targets"')
    check("there is a checkbox for it", box > 0)
    tail = page[box:box + 700]
    check("labelled with its name and note",
          f"<b>{LABEL}</b>" in tail and NOTE in tail, tail[:300])
    check("and flagged as a route to full control", "full control" in tail)
    check("and the area table explains it",
          page.count(NOTE) >= 2)
    # A user manager who is not an administrator may not hand it out.
    rid = rbac.save("", "managers", "", ["pam", "pam_targets"], [], [], [])
    why = main._guard_user_edit({"role": "viewer"}, None, False, [rid])
    check("a delegated user manager cannot hand out a role carrying it",
          "pam_targets" in why, why)


def readers_change_nothing() -> None:
    print("the read-only area, even with connect, adds and moves nothing")
    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    tid = pam.save_target("", {"name": "readers box", "protocol": "ssh",
                               "address": "10.0.0.10", "port": "22",
                               "auth_kind": "password", "secret": "Kept-1"},
                          "t")
    rid = rbac.save("", "operators", "", ["pam", "pam_connect"], [], [], [])
    enrol("op@pamtargets.test", "Operator-Targets-42", [rid])
    c = signed_in("op@pamtargets.test", "Operator-Targets-42")

    r = c.post("/pam/target/save", data=form("", "planted", "10.6.6.6"),
               follow_redirects=False)
    check("a new target is refused", r.status_code == 303
          and "manage targets" in err_of(r)
          and not any(t["name"] == "planted" for t in pam.targets()),
          err_of(r))
    r = c.post("/pam/target/save",
               data=form(tid, "readers box", "10.6.6.7",
                         auth_kind="password"), follow_redirects=False)
    after = pam._target_raw(tid)
    check("an existing target cannot be pointed elsewhere",
          r.status_code == 303 and after["address"] == "10.0.0.10"
          and "manage targets" in err_of(r), err_of(r))
    check("and its credential is still the one it had",
          pam.target_secret(tid) == "Kept-1")

    page = c.get("/pam?sec=targets").text
    check("the catalogue's New target is disabled, with the reason",
          re.search(r'<button type="button" class="btn" disabled\s+'
                    r'title="adding a target needs “Privileged Access: '
                    r'manage targets”">＋ New target</button>', page)
          is not None)
    check("and is not a link", 'href="/pam/targets/new"' not in page)
    acts = row_actions(page, tid)
    check("a row offers view, not edit, and says why",
          ">view</a>" in acts and ">edit</a>" not in acts
          and "changing this target needs “Privileged Access: manage "
              "targets” on it" in acts, acts[-600:])

    r = c.get(f"/pam/targets/{tid}")
    check("the target page still opens, read-only",
          r.status_code == 200 and "<h1>Target</h1>" in r.text
          and "Read-only — changing this target needs" in r.text)
    check("every control is disabled", '<fieldset class="tgt-set" disabled>'
          in r.text)
    check("and so is Save, with the reason in its title",
          re.search(r'<button type="submit" disabled title="changing this '
                    r'target needs[^"]*"', r.text) is not None)
    r = c.get("/pam/targets/new")
    check("the new-target page says why it cannot be used",
          r.status_code == 200 and "Read-only — adding a target needs" in r.text
          and '<fieldset class="tgt-set" disabled>' in r.text)


def managers_change_targets() -> None:
    print("the grant adds and changes targets")
    rid = rbac.save("", "catalogue keepers", "", ["pam", "pam_targets"],
                    [], [], [])
    enrol("keeper@pamtargets.test", "Keeper-Targets-42", [rid])
    c = signed_in("keeper@pamtargets.test", "Keeper-Targets-42")
    r = c.post("/pam/target/save",
               data=form("", "kept box", "10.0.0.20", auth_kind="password",
                         secret="First-Secret-9"), follow_redirects=False)
    made = next((t for t in pam.targets() if t["name"] == "kept box"), None)
    check("it creates a target", r.status_code == 303 and made is not None
          and "target saved" in err_of(r), err_of(r))
    tid = made["id"] if made else ""
    r = c.post("/pam/target/save",
               data=form(tid, "kept box", "10.0.0.20", auth_kind="password",
                         label="rack 4"), follow_redirects=False)
    check("and changes one without retyping a credential it is not moving",
          pam.target(tid)["label"] == "rack 4"
          and pam.target_secret(tid) == "First-Secret-9")
    # A refused NEW target re-renders too: it used to redirect to an empty
    # form, and the floor in retry.js was all that kept what was typed.
    r = c.post("/pam/target/save",
               data=form("", "half typed", "-oProxyCommand=x", label="keep me"),
               follow_redirects=False)
    check("a refused new target comes back as the form, holding what was typed",
          r.status_code == 200 and "<h1>New target</h1>" in r.text
          and 'value="half typed"' in r.text and 'value="keep me"' in r.text
          and 'name="tid" value=""' in r.text
          and "is not one that can be reached safely" in r.text
          and not any(t["name"] == "half typed" for t in pam.targets()),
          f"{r.status_code}")
    page = c.get("/pam?sec=targets").text
    check("its catalogue offers New target and edit",
          'href="/pam/targets/new">＋ New target</a>' in page
          and ">edit</a>" in row_actions(page, tid))
    r = c.get(f"/pam/targets/{tid}")
    check("and its target page is a live form",
          "<h1>Edit target</h1>" in r.text and "Read-only" not in r.text
          and '<fieldset class="tgt-set">' in r.text)
    # The new grant does not quietly include re-trusting a key: that stays
    # the whole of Privileged Access, unconfined.
    pam.pin_after(tid, "10.0.0.20", 22, known(f"10.0.0.20 ssh-ed25519 {KEY}\n"))
    c.post("/pam/target/hostkey/forget", data={"tid": tid},
           follow_redirects=False)
    check("it does not re-trust a host key", pam.host_pin(tid) is not None)
    c.post("/pam/target/delete", data={"tid": tid}, follow_redirects=False)
    check("nor delete a target -- that is still pam_delete's",
          pam.target(tid) is not None)


def scoped() -> None:
    print("changing is scoped to the role's targets; adding needs it unconfined")
    mine = target("scoped mine", "10.0.0.31")
    theirs = target("scoped theirs", "10.0.0.32")
    reads = rbac.save("", "read all", "", ["pam"], [], [], [])
    edits = rbac.save("", "edit mine", "", ["pam_targets"], [], [], [mine])
    enrol("scoped@pamtargets.test", "Scoped-Targets-42", [reads, edits])
    c = signed_in("scoped@pamtargets.test", "Scoped-Targets-42")
    c.post("/pam/target/save", data=form(mine, "scoped mine", "10.0.0.41"),
           follow_redirects=False)
    check("a target in its scope can be changed",
          pam._target_raw(mine)["address"] == "10.0.0.41")
    r = c.post("/pam/target/save", data=form(theirs, "scoped theirs",
                                             "10.0.0.42"),
               follow_redirects=False)
    check("one outside it cannot, by id",
          pam._target_raw(theirs)["address"] == "10.0.0.32"
          and "your roles grant that for other targets" in err_of(r),
          err_of(r))
    r = c.post("/pam/target/save", data=form("", "scoped new", "10.0.0.43"),
               follow_redirects=False)
    check("and a confined grant cannot add one, and says why",
          not any(t["name"] == "scoped new" for t in pam.targets())
          and "a new target is in nobody's list" in err_of(r), err_of(r))
    page = c.get("/pam?sec=targets").text
    check("the catalogue agrees, row by row",
          ">edit</a>" in row_actions(page, mine)
          and ">view</a>" in row_actions(page, theirs))

    # The catalogue's own scope holds on the target page too: a role
    # confined to one target could open any other by id and read it.
    one = rbac.save("", "one target", "", ["pam"], [], [], [mine])
    enrol("narrow@pamtargets.test", "Narrow-Targets-42", [one])
    n = signed_in("narrow@pamtargets.test", "Narrow-Targets-42")
    r = n.get(f"/pam/targets/{theirs}", follow_redirects=False)
    check("a target outside the reader's scope does not open",
          r.status_code == 303 and "do not include this target" in err_of(r)
          and "10.0.0.32" not in r.text, err_of(r))
    check("one inside it does",
          n.get(f"/pam/targets/{mine}").status_code == 200)


def moving() -> None:
    print("pointing a target somewhere new never takes its credential along")
    enrol("mover@pamtargets.test", "Mover-Targets-42",
          [rbac.save("", "movers", "", ["pam", "pam_targets"], [], [], [])])
    c = signed_in("mover@pamtargets.test", "Mover-Targets-42")
    tid = pam.save_target("", {"name": "mover box", "protocol": "ssh",
                               "address": "10.0.0.50", "port": "22",
                               "auth_kind": "password",
                               "secret": "Old-Secret-7"}, "t")
    pam.pin_after(tid, "10.0.0.50", 22, known(f"10.0.0.50 ssh-ed25519 {KEY}\n"))
    fp = pam.host_pin(tid)["fingerprints"][0]

    for what, change in (("a new address", {"address": "10.6.6.50"}),
                         ("a new port", {"port": "2222"}),
                         ("a new protocol", {"protocol": "rdp"})):
        since = mark()
        data = form(tid, "mover box", "10.0.0.50", auth_kind="password")
        data.update(change)
        r = c.post("/pam/target/save", data=data, follow_redirects=False)
        t = pam._target_raw(tid)
        check(f"{what} with the secret left blank is refused, in place",
              r.status_code == 200 and "is not carried over" in r.text
              and t["address"] == "10.0.0.50" and t["port"] == 22
              and t["protocol"] == "ssh", f"{r.status_code}")
        check("  and nothing about the target moved",
              pam.target_secret(tid) == "Old-Secret-7"
              and pam.host_pin(tid) is not None
              and not audits(since, "pam_target_redirected"))
    # RE-RENDERED, with what was typed: the address somebody just changed is
    # exactly what a redirect would have thrown away.
    r = c.post("/pam/target/save",
               data=form(tid, "mover box", "10.6.6.51", auth_kind="password",
                         label="new home"), follow_redirects=False)
    check("the form comes back holding the new address and the label",
          r.status_code == 200 and 'value="10.6.6.51"' in r.text
          and 'value="new home"' in r.text
          and f'name="tid" value="{tid}"' in r.text, r.text[:200])
    check("still as an edit of the saved target",
          "<h1>Edit target</h1>" in r.text and "mover box" in r.text)
    check("with the reason beside the credential, not only at the top",
          re.search(r'class="note tgt-err" role="alert">⚠ this target now '
                    r'points at 10\.6\.6\.51:22 over SSH, so the stored '
                    r'password is not carried over', r.text) is not None)
    check("and the stored secret is not on the page",
          "Old-Secret-7" not in r.text)

    since = mark()
    r = c.post("/pam/target/save",
               data=form(tid, "mover box", "10.6.6.52", auth_kind="password",
                         secret="New-Secret-8"), follow_redirects=False)
    t = pam._target_raw(tid)
    check("with the credential typed again it saves",
          r.status_code == 303 and t["address"] == "10.6.6.52"
          and pam.target_secret(tid) == "New-Secret-8")
    check("and the pinned host key is gone with the old address",
          pam.host_pin(tid) is None)
    moved = audits(since, "pam_target_redirected")
    detail = (moved[0]["detail"] if moved else "")
    check("the move is audited once, old and new",
          len(moved) == 1 and "10.0.0.50:22 ssh → 10.6.6.52:22 ssh" in detail
          and moved[0]["target"] == "mover box", detail)
    check("saying the credential was not carried and naming the dropped key",
          "the stored credential was not carried over — a new one was "
          "entered" in detail and f"pinned host key dropped, was {fp}" in detail,
          detail)
    every = json.dumps([dict(r) for r in db.q("SELECT * FROM audit")])
    check("and no secret, old or new, is anywhere in the audit log",
          "Old-Secret-7" not in every and "New-Secret-8" not in every)

    print("...and the same machine spelled differently is not a move")
    host = pam.save_target("", {"name": "spelled", "protocol": "ssh",
                                "address": "db01.example.com", "port": "22",
                                "auth_kind": "password", "secret": "Same-1"},
                           "t")
    pam.pin_after(host, "db01.example.com", 22,
                  known(f"db01.example.com ssh-ed25519 {KEY}\n"))
    since = mark()
    r = c.post("/pam/target/save",
               data=form(host, "spelled", "DB01.example.com.",
                         auth_kind="password", port=""),
               follow_redirects=False)
    check("case, a trailing dot and the default port keep the credential",
          r.status_code == 303 and pam.target_secret(host) == "Same-1"
          and pam.host_pin(host) is not None
          and not audits(since, "pam_target_redirected"), f"{r.status_code}")

    print("...and a credential of one kind is never reused as the other")
    keyed = pam.save_target("", {"name": "keyed", "protocol": "ssh",
                                 "address": "10.0.0.60", "port": "22",
                                 "auth_kind": "key",
                                 "secret_key": ansible.new_keypair()[0]}, "t")
    r = c.post("/pam/target/save",
               data=form(keyed, "keyed", "10.0.0.60", auth_kind="password"),
               follow_redirects=False)
    check("a stored key is not kept as a password",
          r.status_code == 200 and "cannot be used as a password" in r.text
          and pam._target_raw(keyed)["auth_kind"] == "key")

    print("...and a target with no credential moves, and says so")
    bare = target("bare box", "10.0.0.70")
    pam.pin_after(bare, "10.0.0.70", 22, known(f"10.0.0.70 ssh-ed25519 {KEY}\n"))
    since = mark()
    c.post("/pam/target/save", data=form(bare, "bare box", "10.0.0.71"),
           follow_redirects=False)
    moved = audits(since, "pam_target_redirected")
    check("it is pointed at the new address and its pin dropped",
          pam._target_raw(bare)["address"] == "10.0.0.71"
          and pam.host_pin(bare) is None)
    check("and the audit line does not invent a credential",
          len(moved) == 1 and "credential" not in moved[0]["detail"]
          and "pinned host key dropped" in moved[0]["detail"],
          moved[0]["detail"] if moved else "")


def module_rule() -> None:
    print("the rule is the module's, not only the route's")
    tid = pam.save_target("", {"name": "module box", "protocol": "ssh",
                               "address": "10.0.0.80", "port": "22",
                               "auth_kind": "password", "secret": "Mod-1"}, "t")
    try:
        pam.save_target(tid, {"name": "module box", "protocol": "ssh",
                              "address": "10.6.6.80", "port": "22",
                              "auth_kind": "password", "secret": ""}, "t")
        refused = False
    except pam.SecretNotCarried:
        refused = True
    check("save_target refuses to carry a secret to a new address",
          refused and pam._target_raw(tid)["address"] == "10.0.0.80")

    # AN EDIT NAMES A TARGET THAT EXISTS. It used to INSERT under the posted
    # id, so an inventory host's id became a second target shadowing it.
    priv, _ = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "shadowed", "ssh_user": "root",
                                  "key": priv}, "t")
    ansible.add_host(gid, "inv01", "10.0.0.90", "t")
    hid = next(t["id"] for t in pam.targets() if t.get("source") == "ansible"
               and t["name"] == "inv01")
    for what, tid2 in (("an inventory host's id", hid),
                       ("an id nothing has", "pt-nothinghere")):
        try:
            pam.save_target(tid2, {"name": "shadow", "protocol": "ssh",
                                   "address": "10.6.6.90",
                                   "auth_kind": "none"}, "t")
            ok = False
        except pam.Refused:
            ok = True
        check(f"saving under {what} is refused, and creates nothing",
              ok and pam._target_raw(tid2) is None)
    enrol("adm2@pamtargets.test", "Admin2-Targets-Pass-42", [], role="admin")
    a = signed_in("adm2@pamtargets.test", "Admin2-Targets-Pass-42")
    r = a.post("/pam/target/save", data=form(hid, "shadow", "10.6.6.91"),
               follow_redirects=False)
    check("and through the route, even for an administrator",
          r.status_code == 303 and pam._target_raw(hid) is None
          and "inventory host" in err_of(r), err_of(r))
    r = a.get(f"/pam/targets/{hid}", follow_redirects=False)
    check("an inventory host has no edit form here",
          r.status_code == 303 and "changed on its group in Ansible"
          in err_of(r), err_of(r))


if __name__ == "__main__":
    the_area()
    role_editor()
    readers_change_nothing()
    managers_change_targets()
    scoped()
    moving()
    module_rule()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
