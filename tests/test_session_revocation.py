#!/usr/bin/env python3
"""A session ends when it should -- auth.session_open and main._session_uid.

WHY THIS EXISTS
    The session cookie is signed and the server kept nothing, so a copied
    cookie worked for its whole lifetime (8 hours by default) after its owner
    signed out, changed the password, or had the second factor reset by an
    administrator. Found by the 10 November 2026 sweep. Each sign-in is now a
    row the cookie names, and a cookie whose row is gone is signed out.

    Proved here, with a COPY of a real cookie standing in for a stolen one:
      * signing out ends the copy too
      * changing the password ends every other session, and keeps the one
        that made the change
      * an administrator resetting the second factor, or disabling the
        account, ends its sessions
      * a cookie that has proved only the password stops proving it when the
        password changes -- the right code cannot finish that sign-in
      * a new authenticator ends the sessions the old one opened
      * a cookie from before this change, which carries no session id, is
        signed out

    ./.venv/bin/python tests/test_session_revocation.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("sessrevoke-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, throttle                       # noqa: E402

bad = 0
PW = "Session-Revoke-Pass-42"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


def enrol(email: str, role: str = "admin") -> str:
    uid = auth.create_user(email, "S", PW, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, email_verified=1 "
           "WHERE id=?", ("TESTSECRET", uid))
    return uid


def sign_in(email: str, pw: str = PW, finish: bool = True) -> TestClient:
    throttle.reset()
    auth.forget_totp_use(auth.by_email(email)["id"])
    c = TestClient(main.app)
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    if finish:
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
    return c


def copy_of(c: TestClient) -> TestClient:
    return TestClient(main.app, cookies=dict(c.cookies))


def session_of(c: TestClient) -> dict:
    """What the signed cookie carries -- signed, not encrypted, so readable."""
    import base64
    import json
    raw = c.cookies.get("portal_session", "").split(".")[0]
    return json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))


def signed_in(c: TestClient) -> bool:
    return c.get("/me", follow_redirects=False).status_code == 200


def main_test() -> int:
    uid = enrol("sam@sessions.test")
    enrol("root@sessions.test")

    print("signing out")
    c = sign_in("sam@sessions.test")
    stolen = copy_of(c)
    check("the copy works while the owner is signed in", signed_in(stolen))
    page = c.get("/logout", follow_redirects=False)
    check("a plain link to /logout only asks: it shows the button and ends nothing (SEC-13)",
          page.status_code == 200 and 'method="post" action="/logout"' in page.text
          and signed_in(stolen) and signed_in(c))
    check("the account menu signs out with a POST, never a link",
          'action="/logout" class="acc-outf"' in c.get("/me").text
          and 'href="/logout"' not in c.get("/me").text)
    c.post("/logout", follow_redirects=False)
    check("signing out ends the copy too", not signed_in(stolen))

    print("changing the password")
    c = sign_in("sam@sessions.test")
    other = sign_in("sam@sessions.test")
    stolen = copy_of(other)
    r = c.post("/me/password", data={"current": PW, "new": PW + "-new",
                                     "again": PW + "-new"},
               follow_redirects=False)
    check(f"the change is accepted ({r.headers.get('location')})",
          "msg=password" in (r.headers.get("location") or ""))
    check("the session that changed it goes on", signed_in(c))
    check("every other session is ended", not signed_in(other))
    check("and so is its copy", not signed_in(stolen))
    auth.set_password(uid, PW)

    print("AI client tokens and a new password (SEC-12)")
    from app import mcp
    c = sign_in("sam@sessions.test")
    check("the change form offers to revoke them, ticked",
          '<input type="checkbox" name="revoke_tokens" checked>' in c.get("/me").text)
    _, kept = mcp.mint(uid, "laptop")
    c.post("/me/password", data={"current": PW, "new": PW + "-a", "again": PW + "-a"},
           follow_redirects=False)
    check("unticked, a change keeps the owner's tokens", mcp.token(kept["id"])["live"])
    _, gone = mcp.mint(uid, "laptop 2")
    r = c.post("/me/password", data={"current": PW + "-a", "new": PW + "-b",
                                     "again": PW + "-b", "revoke_tokens": "on"},
               follow_redirects=False)
    check(f"ticked, it revokes every one and says so ({r.headers.get('location')})",
          not mcp.token(kept["id"])["live"] and not mcp.token(gone["id"])["live"]
          and "2%20AI%20client%20tokens%20revoked" in (r.headers.get("location") or ""))
    _, reset = mcp.mint(uid, "laptop 3")
    admin = sign_in("root@sessions.test")
    admin.post(f"/admin/users/{uid}/update", data={"name": "Sam", "role": "user",
                                            "password": PW + "-Reset9"},
               follow_redirects=False)
    check("an administrator's reset revokes them with no box to untick",
          not mcp.token(reset["id"])["live"])
    auth.set_password(uid, PW)

    print("an administrator acts on the account")
    c = sign_in("sam@sessions.test")
    stolen = copy_of(c)
    admin = sign_in("root@sessions.test")
    admin.post(f"/admin/users/{uid}/reset-mfa", follow_redirects=False)
    # Put the authenticator straight back: an account with none is sent to
    # enrolment anyway, which would pass this check with the session alive.
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    check("resetting the second factor ends its sessions",
          not signed_in(c) and not signed_in(stolen))
    c = sign_in("sam@sessions.test")
    auth.update_user(uid, disabled=True)
    auth.update_user(uid, disabled=False)
    check("disabling the account ends them too, even once it is re-enabled",
          not signed_in(c))

    print("a cookie that has proved only the password")
    half = sign_in("sam@sessions.test", finish=False)
    auth.set_password(uid, PW + "-moved")
    r = half.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    check(f"cannot finish with the right code after the password changed "
          f"({r.headers.get('location')})",
          r.headers.get("location") == "/login" and not signed_in(half))
    auth.set_password(uid, PW)

    print("a new authenticator")
    c = sign_in("sam@sessions.test")
    other = sign_in("sam@sessions.test")
    c.post("/me/mfa", data={"current": PW, "code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP) + 1)},
        follow_redirects=False)
    c.get("/me?enrol=1")
    secret = session_of(c).get("reenrol_secret", "")
    r = c.post("/me/mfa/confirm", data={"code": auth._totp_at(
        secret, int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
    check(f"the new authenticator is confirmed ({r.headers.get('location')})",
          "authenticator replaced" in __import__("urllib.parse").parse
          .unquote(r.headers.get("location") or ""))
    check("the session that replaced it goes on", signed_in(c))
    check("the others are ended", not signed_in(other))
    db.run("UPDATE users SET totp_secret=? WHERE id=?", ("TESTSECRET", uid))

    print("a cookie from before this change")
    c = sign_in("sam@sessions.test")
    db.run("DELETE FROM sessions")
    check("a session with no record is signed out", not signed_in(c))
    check("and lands on the sign-in page",
          c.get("/", follow_redirects=False).headers.get("location", "")
          .startswith("/login"))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
