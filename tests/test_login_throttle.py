#!/usr/bin/env python3
"""A sign-in stops listening after a handful of wrong guesses -- app/throttle.py.

WHY THIS EXISTS
    Nothing limited a wrong password, a wrong authenticator code or a reset
    request, and an authenticator code could be used twice. Found by the
    10 November 2026 sweep: twelve wrong passwords in a row, then the right one
    went straight through, and the six-digit code behind it could be guessed
    at full speed -- about an hour for the average account. Proved here
    through the real routes:

      * the sixth wrong password from one place is refused, and so is the
        RIGHT one while the limit stands; an address with no account behind it
        is answered word for word the same
      * the same account guessed from many addresses is caught by its own,
        higher limit
      * five wrong codes end the half-finished sign-in, and the right code is
        refused until the window passes
      * a code signs in once; the same code a second time does not
      * reset requests for one address stop being queued after three, while
        the page still says what it always says
      * the address recorded in the audit log is the connection's, never what
        an X-Forwarded-For header claims
      * the window really ends: a limit that never lifts would be a lockout

    ./.venv/bin/python tests/test_login_throttle.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("throttle-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, invite, main, throttle               # noqa: E402

bad = 0
PW = "Throttle-Test-Pass-42"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


def enrol(email: str) -> str:
    uid = auth.create_user(email, "T", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, email_verified=1 "
           "WHERE id=?", ("TESTSECRET", uid))
    return uid


def client(ip: str = "203.0.113.7") -> TestClient:
    return TestClient(main.app, client=(ip, 40000))


def login(c: TestClient, email: str, pw: str):
    return c.post("/login", data={"email": email, "password": pw},
                  follow_redirects=False)


def err(r) -> str:
    return urllib.parse.unquote(r.headers.get("location", ""))


def code(offset: int = 0) -> str:
    return auth._totp_at("TESTSECRET",
                         int(time.time() // auth.TOTP_STEP) + offset)


def age_everything(seconds: int) -> None:
    """Move every recorded failure into the past, as waiting would."""
    with throttle._lock:
        for k in throttle._fails:
            throttle._fails[k] = [t - seconds for t in throttle._fails[k]]


def main_test() -> int:
    uid = enrol("amina@throttle.test")

    print("wrong passwords from one place")
    c = client()
    for i in range(5):
        r = login(c, "amina@throttle.test", f"wrong-{i}")
    check("five wrong passwords are each just wrong",
          "invalid email or password" in err(r))
    r = login(c, "amina@throttle.test", PW)
    check(f"then even the RIGHT password is refused ({err(r)[:60]})",
          "too many failed sign-ins" in err(r) and r.headers.get(
              "location", "").startswith("/login?"))
    check("and the refusal is audited",
          db.one("SELECT 1 FROM audit WHERE action='login_throttled'") is not None)

    print("an address with no account is answered the same")
    throttle.reset()
    c = client()
    for i in range(6):
        r_none = login(c, "nobody@throttle.test", f"x-{i}")
    for i in range(6):
        r_real = login(client("203.0.113.8"), "amina@throttle.test", f"x-{i}")
    check("the sixth try reads the same for both",
          err(r_none) == err(r_real) and "too many" in err(r_none))

    print("one account from many addresses")
    throttle.reset()
    for i in range(20):
        login(client(f"198.51.100.{i + 1}"), "amina@throttle.test", "nope")
    r = login(client("198.51.100.200"), "amina@throttle.test", PW)
    check("the account's own limit stops the twenty-first, from a new address",
          "too many failed sign-ins" in err(r))

    print("the window ends")
    age_everything(throttle.WINDOW + 1)
    r = login(client("198.51.100.200"), "amina@throttle.test", PW)
    check(f"after the window the right password works ({err(r)})",
          r.headers.get("location") == "/mfa")

    print("wrong authenticator codes")
    throttle.reset()
    auth.forget_totp_use(uid)
    c = client("203.0.113.20")
    login(c, "amina@throttle.test", PW)
    for i in range(5):
        r = c.post("/mfa", data={"code": "000000" if i % 2 else "999999"},
                   follow_redirects=False)
    check("five wrong codes are each just wrong",
          "incorrect code" in err(r))
    r = c.post("/mfa", data={"code": code()}, follow_redirects=False)
    check(f"the sixth, even the right one, ends the sign-in ({err(r)[:50]})",
          err(r).startswith("/login?err=too many wrong codes"))
    check("and the half-finished session is gone",
          c.get("/mfa", follow_redirects=False).headers.get("location")
          == "/login")
    login(c, "amina@throttle.test", PW)
    r = c.post("/mfa", data={"code": code()}, follow_redirects=False)
    check("signing in again does not reset the count for the code",
          "too many wrong codes" in err(r))
    check("and it is audited",
          db.one("SELECT 1 FROM audit WHERE action='mfa_throttled'") is not None)

    print("a code signs in once")
    throttle.reset()
    auth.forget_totp_use(uid)
    first = client("203.0.113.30")
    login(first, "amina@throttle.test", PW)
    used = code()
    r = first.post("/mfa", data={"code": used}, follow_redirects=False)
    check("the code signs in", r.headers.get("location") == "/")
    again = client("203.0.113.31")
    login(again, "amina@throttle.test", PW)
    r = again.post("/mfa", data={"code": used}, follow_redirects=False)
    check("the same code a second time does not", "incorrect code" in err(r))
    r = again.post("/mfa", data={"code": code(1)}, follow_redirects=False)
    check("the next one does", r.headers.get("location") == "/")

    print("reset requests")
    throttle.reset()
    before = db.one("SELECT COUNT(*) n FROM reset_requests")["n"]
    pages = []
    for i in range(5):
        r = client("203.0.113.40").post(
            "/forgot", data={"email": "amina@throttle.test"},
            follow_redirects=False)
        pages.append(r.headers.get("location"))
    after = db.one("SELECT COUNT(*) n FROM reset_requests")["n"]
    check(f"only three are queued for one address ({after - before})",
          after - before == 3)
    check("while the page says the same every time",
          set(pages) == {"/forgot?sent=1"})

    print("the audit log records the connection's address")
    throttle.reset()
    c = client("192.0.2.55")
    c.post("/login", data={"email": "amina@throttle.test", "password": "no"},
           headers={"X-Forwarded-For": "10.66.66.66"}, follow_redirects=False)
    row = db.one("SELECT ip FROM audit WHERE action='login_failed' "
                 "ORDER BY id DESC LIMIT 1")
    check(f"not the header's claim (got {row['ip']})",
          row["ip"] == "192.0.2.55")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
