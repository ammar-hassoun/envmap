#!/usr/bin/env python3
"""A code page sent twice is one sign-in, not "incorrect code".

Reported from an installation on 0.7.55, 23 November 2026: a person typed the
right code and was shown "incorrect code", yet the home page opened
afterwards. The code page sent its form by itself on the sixth digit with
form.submit(), which skips the submit event, so pressing Enter, clicking
Verify or a password manager sent it again 85 ms later. The first POST
signed in; the second was checked as a fresh code, refused as already used,
counted as a wrong guess, audited as mfa_failed, and its error page was the
one the browser showed. The enrolment page did the same.

Proved through the real routes and middleware:

  * a repeat from a session that has passed its second factor lands where
    the first one went, with no wrong guess counted and no failure audited
  * the code page itself sends a signed-in session home, error or not
  * the enrolment form sent twice goes home too, not to a code prompt
  * a code is still good for ONE sign-in: another session that has only
    the password cannot use it, and a wrong code is still wrong
  * both pages send their form once: requestSubmit (through the submit
    event, where a second send is cancelled), never form.submit()

    ./.venv/bin/python tests/test_mfa_double_submit.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time
import urllib.parse

import _sandbox                                               # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("mfatwice-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, throttle                       # noqa: E402

bad = 0
PW = "Twice-Sent-Pass-42"
SECRET = "TWICESENTSECRETX"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


def code(secret: str) -> str:
    return auth._totp_at(secret, int(time.time() // auth.TOTP_STEP))


def password_only(email: str, nxt: str = "") -> TestClient:
    c = TestClient(main.app, client=("203.0.113.40", 40000))
    data = {"email": email, "password": PW}
    if nxt:
        data["next"] = nxt
    c.post("/login", data=data, follow_redirects=False)
    return c


def where(r) -> str:
    return urllib.parse.unquote(r.headers.get("location", ""))


def audits(uid: str, action: str) -> int:
    return db.one("SELECT COUNT(*) AS n FROM audit WHERE action = ? AND "
                  "user = ?", (action, auth.by_id(uid)["email"]))["n"]


def fails(uid: str) -> int:
    with throttle._lock:
        return len(throttle._fails.get(("mfa", uid), []))


def main_test() -> int:
    uid = auth.create_user("wanjiru@twice.test", "W", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, email_verified=1 "
           "WHERE id=?", (SECRET, uid))

    print("the code page sent twice")
    c = password_only("wanjiru@twice.test", nxt="/settings")
    right = code(SECRET)
    first = c.post("/mfa", data={"code": right}, follow_redirects=False)
    check(f"the first send signs in and goes where the link asked, got "
          f"{where(first)!r}", first.status_code == 303
          and where(first) == "/settings")
    second = c.post("/mfa", data={"code": right}, follow_redirects=False)
    check(f"the second send of the same code is NOT 'incorrect code', got "
          f"{where(second)!r}", second.status_code == 303
          and "err=" not in where(second) and where(second) == "/")
    check("the session is still signed in after it",
          c.get("/admin/users", follow_redirects=False).status_code == 200)
    check(f"no wrong guess was counted for it ({fails(uid)})", fails(uid) == 0)
    check("no failed sign-in was audited for it",
          audits(uid, "mfa_failed") == 0)
    check("and the sign-in was audited once", audits(uid, "login") == 1)
    third = c.post("/mfa", data={"code": "000000"}, follow_redirects=False)
    check("whatever the repeat carries, it signs nothing new and goes home",
          where(third) == "/" and fails(uid) == 0)

    print("the code page, opened by a session already signed in")
    r = c.get("/mfa?err=incorrect code", follow_redirects=False)
    check(f"goes home instead of showing an error, got {r.status_code} "
          f"{where(r)!r}", r.status_code == 303 and where(r) == "/")

    print("a code is still good for one sign-in")
    other = password_only("wanjiru@twice.test")
    r = other.post("/mfa", data={"code": right}, follow_redirects=False)
    check(f"another session with only the password cannot reuse it, got "
          f"{where(r)!r}", where(r) == "/mfa?err=incorrect code")
    check("and that one is not signed in",
          other.get("/admin/users", follow_redirects=False).headers
          .get("location") == "/mfa")
    check("its refusal is counted and audited as before",
          fails(uid) == 1 and audits(uid, "mfa_failed") == 1)
    page = other.get("/mfa", follow_redirects=False)
    check("and the code page still asks it for a code",
          page.status_code == 200 and 'name="code"' in page.text)
    r = other.post("/mfa", data={"code": "123456" if right != "123456"
                                 else "654321"}, follow_redirects=False)
    check("a wrong code is still wrong", where(r) == "/mfa?err=incorrect code")

    print("the enrolment form sent twice")
    fresh = auth.create_user("otieno@twice.test", "O", PW)
    c = password_only("otieno@twice.test")
    c.get("/mfa/setup")
    minted = auth.by_id(fresh)["totp_secret"]
    first = c.post("/mfa/setup", data={"code": code(minted)},
                   follow_redirects=False)
    check(f"the first send enrols and signs in, got {where(first)!r}",
          where(first) == "/" and auth.by_id(fresh)["mfa_enrolled"])
    second = c.post("/mfa/setup", data={"code": code(minted)},
                    follow_redirects=False)
    check(f"the second goes home, not to a code prompt, got "
          f"{where(second)!r}", where(second) == "/")
    check("still signed in", c.get("/me", follow_redirects=False)
          .status_code == 200)
    pw_only = password_only("otieno@twice.test")
    r = pw_only.post("/mfa/setup", data={"code": code(minted)},
                     follow_redirects=False)
    check("a session with only the password is still sent for its code",
          where(r) == "/mfa")

    print("both pages send their form once")
    once = (ROOT / "templates" / "_code_once.html").read_text()
    script = once.split("#}", 1)[1]
    check("the shared script sends with requestSubmit",
          "requestSubmit()" in script)
    check("and cancels every send after the first",
          "if (sent) { e.preventDefault(); return; }" in script)
    for name in ("mfa.html", "mfa_setup.html"):
        src = (ROOT / "templates" / name).read_text()
        check(f"{name} uses it", '{% include "_code_once.html" %}' in src)
        check(f"{name} has no form.submit() of its own",
              ".submit()" not in src)
    page = other.get("/mfa")
    check("the rendered page carries it, under the page's nonce",
          "requestSubmit" in page.text and "<script nonce=" in page.text)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
