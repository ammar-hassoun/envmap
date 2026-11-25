"""Watching a live SSH session is on the record -- once per watcher.

WHY THIS EXISTS
    `GET /pam/session/{sid}/live.json` is what the watch window polls while a
    supervisor follows somebody's SSH session as it runs, and nothing it served
    was audited. Joining a desktop wrote `pam_session_watch`; replaying a
    recording afterwards wrote `pam_session_replayed`; reading the very same
    screen live wrote nothing at all.

    It is audited now under the desktop's own action, once per watcher per
    session. Not per poll: the window polls about once a second, and a row per
    poll would bury the line it exists to keep. Not per `frm=0` either: a
    watcher who starts past zero would never be written down. The session
    layer is faked the way tests/test_pam.py fakes it -- a real cast, written
    by a real Recording, registered by hand -- because what is under test is
    the route.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamwatch-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, main, pam, rbac  # noqa: E402

bad = 0


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


def enrol(email: str, pw: str, areas, targets=()) -> dict:
    uid = auth.create_user(email, "N", pw, role="viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], [],
                                      list(targets))])
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


def watches(sid: str, who: str = "") -> list:
    return [dict(r) for r in db.q(
        "SELECT * FROM audit WHERE action = 'pam_session_watch' AND "
        "target LIKE ? AND (? = '' OR user = ?) ORDER BY id",
        (f"session {sid} %", who, who))]


def live(tid: str, who: str):
    rec = pam.start_recording(who, "10.0.0.9", protocol="ssh", target_id=tid,
                              target_name="db01", address="10.0.0.9",
                              rec_kind="asciinema", rows=24, cols=100)
    pam.register_active(rec.id, {"who": who, "target": "db01",
                                 "target_id": tid, "address": "10.0.0.9",
                                 "protocol": "ssh", "ip": "10.0.0.9",
                                 "recorded": True, "cast": rec.cast.path},
                        lambda: None)
    rec.output("$ uptime\r\n up 3 days\r\n")
    return rec


def poll(c: TestClient, sid: str, frm: int = 0) -> dict:
    return c.get(f"/pam/session/{sid}/live.json?frm={frm}").json()


if __name__ == "__main__":
    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    tid = pam.save_target("", {"name": "db01", "protocol": "ssh",
                               "address": "10.0.0.9", "port": "22",
                               "auth_kind": "none"}, "t")
    other = pam.save_target("", {"name": "elsewhere", "protocol": "ssh",
                                 "address": "10.0.0.8", "port": "22",
                                 "auth_kind": "none"}, "t")
    sup, pw = "sup@pamwatch.test", "Supervisor-Watch-42"
    enrol(sup, pw, ["pam"])
    c = signed_in(sup, pw)

    print("watching a live SSH session writes one audit line, not one a poll")
    rec = live(tid, "op@pamwatch.test")
    j = poll(c, rec.id)
    for _ in range(4):
        rec.output("more\r\n")
        j = poll(c, rec.id, j["next"])
    rows = watches(rec.id, sup)
    check(f"five polls, one line ({len(rows)})", len(rows) == 1)
    check("under the desktop watch's own action, naming whose session",
          rows and rows[0]["target"] == f"session {rec.id} (op@pamwatch.test)",
          rows[0]["target"] if rows else "")
    check("and saying it was read-only",
          rows and rows[0]["detail"].startswith("watching, read-only"),
          rows[0]["detail"] if rows else "")
    check("the polls themselves still served the session",
          j.get("ok") and j.get("live") and j.get("next", 0) > 0, str(j))

    print("...whatever the first poll asks for")
    sup2, pw2 = "sup2@pamwatch.test", "Supervisor-Two-Watch-42"
    enrol(sup2, pw2, ["pam"])
    c2 = signed_in(sup2, pw2)
    poll(c2, rec.id, 7)
    poll(c2, rec.id, 9)
    check("a watcher who starts past zero is written down too, once",
          len(watches(rec.id, sup2)) == 1)
    check("and the first watcher is still on file once",
          len(watches(rec.id, sup)) == 1)

    print("...and only for somebody who may watch it")
    nosy, pw3 = "nosy@pamwatch.test", "Nosy-Watch-Pass-42"
    enrol(nosy, pw3, ["pam"], targets=[other])
    c3 = signed_in(nosy, pw3)
    r = c3.get(f"/pam/session/{rec.id}/live.json?frm=0")
    check(f"a session on a target outside the role is refused ({r.status_code})",
          r.status_code == 403)
    check("and the refusal is not recorded as a watch",
          not watches(rec.id, nosy))

    print("...and a new session is a new line, an ended one none")
    rec.finish()
    pam.drop_active(rec.id)
    done = poll(c, rec.id)
    check("an ended session reports done", done.get("done") is True, str(done))
    check("and writes nothing more", len(watches(rec.id)) == 2)
    again = live(tid, "op@pamwatch.test")
    poll(c, again.id)
    poll(c, again.id)
    check("the same supervisor on the next session is audited again, once",
          len(watches(again.id, sup)) == 1)
    again.finish()
    pam.drop_active(again.id)

    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
