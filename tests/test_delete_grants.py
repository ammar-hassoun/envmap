"""Deleting a record is its own grant, never part of the one that uses it.

WHY THIS EXISTS
    A role holding the read-only `pam` area could delete any target by id --
    one outside its own scope included -- and one holding `certs` could delete
    a certificate order, and the only copy of its private key, with nothing
    more. An unconfined `pam` + `pam_connect` role could also delete and clear
    the recordings that are the evidence of what it did. Found when a set of
    operators was meant to have no delete rights at all and had all of them.

    `pam_delete` and `certs_delete` are the grants now. This drives every one
    of those routes with a role that lacks them and one that holds them, and
    pins the backfill that keeps existing roles whole on upgrade -- including
    the property that matters most: it runs ONCE, so a grant an administrator
    withdraws is never handed back on the next start.
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("delgrants-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, certs, db, main, pam, rbac  # noqa: E402

bad = 0
KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


def enrol(email: str, pw: str, role_ids) -> dict:
    uid = auth.create_user(email, "N", pw, role="viewer")
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
    open(path, "w").write(text)
    return path


def seed():
    """One target with a pinned key, one finished recording, one cert order."""
    tid = pam.save_target("", {"name": "keep me", "protocol": "ssh",
                               "address": "10.0.0.70", "port": "22",
                               "auth_kind": "none"}, "t")
    pam.pin_after(tid, "10.0.0.70", 22, known(f"10.0.0.70 ssh-ed25519 {KEY}\n"),
                  who="t")
    rec = pam.start_recording("op@t", "1.2.3.4", protocol="ssh", target_id=tid,
                              target_name="keep me", address="10.0.0.70",
                              rec_kind="asciinema")
    rec.output("hello\r\n")
    rec.finish("closed")
    oid = certs.create_external("u-1", "keep.example.com", name="keep")
    return tid, rec.id, oid


def attempts(c: TestClient, tid: str, sid: str, oid: str) -> None:
    c.post("/pam/target/delete", data={"tid": tid}, follow_redirects=False)
    c.post("/pam/session/delete", data={"sid": sid}, follow_redirects=False)
    c.post("/pam/sessions/clear", data={}, follow_redirects=False)
    c.post("/pam/target/hostkey/forget", data={"tid": tid},
           follow_redirects=False)
    c.post(f"/certs/{oid}/delete", follow_redirects=False)


def still(tid: str, sid: str, oid: str) -> dict:
    return {"target": pam.target(tid) is not None,
            "recording": pam.session(sid) is not None,
            "pin": pam.host_pin(tid) is not None,
            "cert": certs.one(oid) is not None}


def without() -> None:
    print("a role without the delete grants deletes nothing")
    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    # Exactly the shape the operators had: every area of use, unconfined, and
    # no delete grant.
    rid = rbac.save("", "operators", "", ["expiry", "certs", "pam",
                                           "pam_connect"], [], [], [])
    u = enrol("op@delgrants.test", "Operator-Pass-4242", [rid])
    check("it is not the whole of Privileged Access", not rbac.may_pam_full(u))
    tid, sid, oid = seed()
    c = signed_in("op@delgrants.test", "Operator-Pass-4242")
    attempts(c, tid, sid, oid)
    left = still(tid, sid, oid)
    check("the target survives its delete", left["target"], str(left))
    check("the recording survives its delete and a clear", left["recording"],
          str(left))
    check("the pinned host key survives a re-trust", left["pin"], str(left))
    check("the certificate order, and its only key, survive a delete",
          left["cert"], str(left))

    # A PAM delete is HIDDEN from somebody who cannot use it, not shown
    # disabled (changed on request): the absent title is what proves it is
    # gone rather than merely formless. The certificate's delete is outside
    # that change and still renders disabled with its reason.
    listing = c.get("/pam?sec=targets").text
    check("the catalogue's delete is hidden, not offered",
          'action="/pam/target/delete"' not in listing
          and "deleting a target needs" not in listing)
    recs = c.get("/pam?sec=sessions").text
    check("so is a recording's",
          'action="/pam/session/delete"' not in recs
          and "deleting a recording needs" not in recs)
    page = c.get(f"/certs?id={oid}").text
    check("and a certificate's delete is disabled, with the reason",
          "deleting a certificate needs “TLS certificates: delete”" in page
          and f'action="/certs/{oid}/delete"' not in page)


def holding() -> None:
    print("the same role with the grants deletes what it asks to")
    rid = rbac.save("", "operators + delete", "",
                    ["expiry", "certs", "pam", "pam_connect", "pam_delete",
                     "certs_delete"], [], [], [])
    enrol("keeper@delgrants.test", "Keeper-Pass-4242", [rid])
    tid, sid, oid = seed()
    c = signed_in("keeper@delgrants.test", "Keeper-Pass-4242")
    c.post("/pam/target/hostkey/forget", data={"tid": tid},
           follow_redirects=False)
    check("it re-trusts a host key", pam.host_pin(tid) is None)
    c.post("/pam/session/delete", data={"sid": sid}, follow_redirects=False)
    check("it deletes a recording", pam.session(sid) is None)
    c.post("/pam/target/delete", data={"tid": tid}, follow_redirects=False)
    check("it deletes a target", pam.target(tid) is None)
    c.post(f"/certs/{oid}/delete", follow_redirects=False)
    check("it deletes a certificate order", certs.one(oid) is None)


def scoped() -> None:
    print("the delete grant is still confined to its own targets")
    mine = pam.save_target("", {"name": "mine", "protocol": "ssh",
                                "address": "10.0.0.71", "auth_kind": "none"}, "t")
    theirs = pam.save_target("", {"name": "theirs", "protocol": "ssh",
                                  "address": "10.0.0.72", "auth_kind": "none"}, "t")
    rid = rbac.save("", "scoped delete", "", ["pam", "pam_delete"], [], [],
                    [mine])
    enrol("scoped@delgrants.test", "Scoped-Pass-4242", [rid])
    c = signed_in("scoped@delgrants.test", "Scoped-Pass-4242")
    c.post("/pam/target/delete", data={"tid": theirs}, follow_redirects=False)
    check("a target outside the role's scope cannot be deleted by id",
          pam.target(theirs) is not None)
    c.post("/pam/target/delete", data={"tid": mine}, follow_redirects=False)
    check("one inside it can", pam.target(mine) is None)


def backfill() -> None:
    print("existing roles keep their deletes on upgrade -- once")
    # A role as the previous release stored it: the areas of use, no grant.
    with db.tx() as c:
        c.execute("INSERT INTO roles (id, name, note, areas, projects, clusters, "
                  "targets, created) VALUES ('r-legacy', 'legacy', '', ?, '[]', "
                  "'[]', '[]', '')", (json.dumps(["pam", "certs", "expiry"]),))
        c.execute("DELETE FROM rbac_migrations WHERE name = 'delete-grants'")
    conn = db.connect()
    rbac._migrate(conn)
    conn.commit()
    got = set((rbac.get("r-legacy") or {}).get("areas") or [])
    check("a role that could delete before keeps both grants",
          {"pam_delete", "certs_delete"} <= got, str(sorted(got)))
    plain = set((rbac.get(rbac.save("", "made later", "", ["pam", "certs"],
                                      [], [], [])) or {}).get("areas") or [])
    check("a role made after the upgrade starts without them",
          not {"pam_delete", "certs_delete"} & plain, str(sorted(plain)))
    # THE PROPERTY THAT MATTERS: an administrator withdraws the grant, the
    # portal restarts, and the grant stays withdrawn.
    r = rbac.get("r-legacy")
    rbac.save(r["id"], r["name"], r["note"] or "",
              [a for a in r["areas"] if a not in ("pam_delete", "certs_delete")],
              [], [], [])
    conn = db.connect()
    rbac._migrate(conn)
    conn.commit()
    again = set((rbac.get("r-legacy") or {}).get("areas") or [])
    check("a withdrawn grant is not handed back on the next start",
          not {"pam_delete", "certs_delete"} & again, str(sorted(again)))


def listed() -> None:
    print("they are areas like any other")
    check("both appear in the role editor's list",
          {"pam_delete", "certs_delete"} <= set(rbac.AREAS))
    check("and only an administrator may hand them out",
          {"pam_delete", "certs_delete"} <= rbac.ESCALATING)
    check("connecting no longer claims to delete anything",
          "recording" not in rbac.AREAS["pam_connect"][1])


if __name__ == "__main__":
    without()
    holding()
    scoped()
    backfill()
    listed()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
