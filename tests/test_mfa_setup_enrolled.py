#!/usr/bin/env python3
"""The enrolment page never shows an enrolled account's secret.

/mfa/setup is reachable by a session that has presented only the password —
it has to be, it is where a new account adds its authenticator. It used to
answer such a session for an account that was ALREADY enrolled too, and it
answered with the existing secret as a QR code. So the password was the only
factor on every account in the portal: sign in, open that address, scan the
code, confirm one number, and the session was complete. Found while closing
the user-manager takeover, where it turned any password reset into the whole
account whether or not the reset cleared MFA.

Checked through the real middleware and routes, the way an attacker holding a
password would drive them.

    ./.venv/bin/python tests/test_mfa_setup_enrolled.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("mfasetup-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, main                                 # noqa: E402

bad = 0
PW = "Only-The-Password-42"
SECRET = "ENROLLEDSECRETXY"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def code(secret: str) -> str:
    return auth._totp_at(secret, int(time.time() // auth.TOTP_STEP))


def password_only(email: str):
    """A client that has signed in with the password and nothing else."""
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    r = c.post("/login", data={"email": email, "password": PW},
               follow_redirects=False)
    return c, r.headers.get("location", "")


def main_test() -> int:
    uid = auth.create_user("enrolled@test.local", "E", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           (SECRET, uid))

    print("an enrolled account, signed in with only its password")
    c, went = password_only("enrolled@test.local")
    check(f"the sign-in asks for the code, got {went!r}", went == "/mfa")
    r = c.get("/mfa/setup", follow_redirects=False)
    check(f"the enrolment page sends it to the code prompt, got "
          f"{r.status_code} {r.headers.get('location')!r}",
          r.status_code == 303 and r.headers.get("location") == "/mfa")
    check("and the secret is nowhere in the answer", SECRET not in r.text)
    check("nor was a new one minted in its place",
          auth.by_id(uid)["totp_secret"] == SECRET
          and auth.by_id(uid)["mfa_enrolled"])
    r = c.post("/mfa/setup", data={"code": code(SECRET)},
               follow_redirects=False)
    check(f"posting a code to the enrolment page is sent to /mfa, got "
          f"{r.headers.get('location')!r}", r.headers.get("location") == "/mfa")
    r = c.get("/admin/users", follow_redirects=False)
    check(f"so the session is still not signed in, got "
          f"{r.headers.get('location')!r}",
          r.status_code == 303 and r.headers.get("location") == "/mfa")

    print("the code still signs it in where codes belong")
    r = c.post("/mfa", data={"code": code(SECRET)}, follow_redirects=False)
    check("a right code at /mfa completes the sign-in",
          r.status_code == 303 and c.get("/admin/users").status_code == 200)
    r = c.get("/mfa/setup", follow_redirects=False)
    check("and the enrolment page sends a complete session home",
          r.headers.get("location") == "/" and SECRET not in r.text)

    print("an account with no authenticator yet still enrols")
    fresh = auth.create_user("fresh@test.local", "F", PW)
    c, went = password_only("fresh@test.local")
    check(f"the sign-in sends it to enrolment, got {went!r}",
          went == "/mfa/setup")
    page = c.get("/mfa/setup")
    check("which shows a QR to scan", page.status_code == 200
          and "data:image" in page.text)
    minted = auth.by_id(fresh)["totp_secret"]
    check("for a secret minted for it", bool(minted) and minted in page.text)
    r = c.post("/mfa/setup", data={"code": code(minted)},
               follow_redirects=False)
    check("and confirming a code enrols it and signs it in",
          auth.by_id(fresh)["mfa_enrolled"]
          and c.get("/me", follow_redirects=False).status_code == 200)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
