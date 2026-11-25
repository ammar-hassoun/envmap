#!/usr/bin/env python3
"""After signing in you land on this site, never on one a link chose.

WHY THIS EXISTS
    `next` comes from the URL somebody clicked, and the sign-in redirected to
    it as given: found by the 10 November 2026 sweep, a real sign-in with
    `next=https://evil.example/phish` finished on evil.example. Microsoft
    sign-in checked only that it started with "/", which `//evil.example`
    does. main._local_path is the one rule; this drives the real routes.

    ./.venv/bin/python tests/test_login_next.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("loginnext-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, throttle                       # noqa: E402

bad = 0
PW = "Login-Next-Pass-42"
OUTSIDE = ["https://evil.example/phish", "//evil.example/x",
           "/\\evil.example", "http:evil.example", "evil.example",
           "/\x0a/evil.example"]


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


def lands_after(nxt: str) -> str:
    throttle.reset()
    auth.forget_totp_use(UID)
    c = TestClient(main.app)
    c.post("/login", data={"email": "nina@next.test", "password": PW,
                           "next": nxt}, follow_redirects=False)
    r = c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return r.headers.get("location", "")


def main_test() -> int:
    global UID
    UID = auth.create_user("nina@next.test", "N", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, email_verified=1 "
           "WHERE id=?", ("TESTSECRET", UID))

    print("a page on this site is kept")
    got = lands_after("/pam?sec=sessions")
    check(f"/pam?sec=sessions -> {got}", got == "/pam?sec=sessions")

    print("anywhere else lands on the home page")
    for nxt in OUTSIDE:
        got = lands_after(nxt)
        check(f"{nxt!r} -> {got!r}", got == "/")

    print("the rule itself")
    for nxt in OUTSIDE:
        check(f"_local_path refuses {nxt!r}", main._local_path(nxt) == "/")
    check("and keeps a local path with its query and fragment",
          main._local_path("/certs?id=ct-1#top") == "/certs?id=ct-1#top")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
