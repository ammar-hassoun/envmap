"""A PAM delete control is hidden entirely for anyone without the delete grant,
never shown as a dead, disabled button.

A target delete needs Privileged Access: delete (`pam_delete`); a recording
delete needs the whole of Privileged Access, unrestricted (`may_pam_full`).
Someone without the grant must not see the button at all. Edit / view is
unchanged — it stays offered.

    ./.venv/bin/python tests/test_pam_delete_hidden.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamdelhide-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, main, pam, rbac  # noqa: E402

bad = 0


def check(what: str, ok: bool) -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok   " if ok else "  FAIL ") + what)


def enrol(email: str, pw: str, areas: list) -> None:
    uid = auth.create_user(email, "N", pw, role="viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    rid = rbac.save("", email.split("@")[0], "", areas, [], [], [])
    rbac.set_for_user(uid, [rid])


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
    return c


def main_test() -> int:
    tid = pam.save_target("", {"name": "web-lb-01", "protocol": "ssh",
                               "address": "10.0.0.9", "port": "22",
                               "auth_kind": "none"}, "setup")
    rec = pam.start_recording("op@t.local", "10.0.0.9", protocol="ssh",
                              target_id=tid, target_name="web-lb-01",
                              address="10.0.0.9", rec_kind="asciinema")
    rec.finish("closed")

    enrol("full@t.local", "Full-Delete-1", ["pam", "pam_connect", "pam_delete"])
    enrol("reader@t.local", "Reader-NoDel-1", ["pam", "pam_connect"])
    full = signed_in("full@t.local", "Full-Delete-1")
    reader = signed_in("reader@t.local", "Reader-NoDel-1")

    print("with the delete grant, both delete controls are present")
    cat = full.get("/pam").text
    recs = full.get("/pam?sec=sessions").text
    check("target delete form is shown", 'action="/pam/target/delete"' in cat)
    check("recording delete form is shown", 'action="/pam/session/delete"' in recs)

    print("without the grant, the delete controls are GONE, not disabled")
    rcat = reader.get("/pam").text
    rrecs = reader.get("/pam?sec=sessions").text
    check("no target delete form for the reader",
          'action="/pam/target/delete"' not in rcat)
    check("no disabled target-delete button either",
          "deleting a target needs" not in rcat)
    check("no recording delete form for the reader",
          'action="/pam/session/delete"' not in rrecs)
    check("no disabled recording-delete button either",
          "deleting a recording needs" not in rrecs)

    print("edit / view is unchanged — still offered to the reader")
    check("the catalogue still offers a view or edit control",
          ">view<" in rcat or ">edit<" in rcat)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
