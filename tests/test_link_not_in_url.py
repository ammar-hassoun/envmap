#!/usr/bin/env python3
"""An invitation or reset link never travels in a URL.

The person who issues one has to see it once and be able to copy it, and it
used to reach them as `?link=` on the redirect back to the users page. A URL is
the worst place a credential can be: it is written to the access log of every
proxy between the browser and the portal, it stays in the browser's history,
and it leaves as the Referer of the next page. Whoever holds the link sets the
account's password.

So the link now waits server-side, sealed, under a handle only the issuing
session holds, and the next GET of the users page hands it out and deletes it.
Checked here for every route that issues one: no Location header and no URL on
the way carries any part of it; it is shown once, to its issuer only; it is
not cached; and what waits in the database is ciphertext.

    ./.venv/bin/python tests/test_link_not_in_url.py
"""
from __future__ import annotations

import html
import os
import pathlib
import re
import sqlite3
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("linkurl-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, invite, mailer, main                 # noqa: E402

bad = 0
PW = "Link-Not-In-Url-42"
DBFILE = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "portal.db"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def signed_in(email: str):
    from fastapi.testclient import TestClient
    uid = auth.create_user(email, "CI", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": email, "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c, uid


def shown(page: str) -> str:
    m = re.search(r'id="invlink" readonly value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else ""


def waiting() -> list:
    """What sits in the hand-over table right now, read off the file itself."""
    c = sqlite3.connect(f"file:{DBFILE}?mode=ro", uri=True)
    try:
        return c.execute("SELECT handle, issuer, body FROM invite_shown").fetchall()
    finally:
        c.close()


def issue_and_follow(c, path: str, data=None) -> tuple:
    """POST without following, then GET where it pointed. Returns the POST's
    Location, the page it led to, and that page's response."""
    r = c.post(path, data=data or {}, follow_redirects=False)
    loc = r.headers.get("location", "")
    page = c.get(loc) if loc else None
    return r, loc, page


def clean(url: str, token: str) -> bool:
    return (token not in url and "link=" not in url
            and "/invite/" not in url and "/reset/" not in url)


def main_test() -> int:
    admin, admin_id = signed_in("linkurl-admin@test.local")
    other, _ = signed_in("linkurl-other@test.local")
    claimed = auth.create_user("claimed@test.local", "C", PW)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("SOMESECRET", claimed))

    cases = (
        ("a new invitation", "/admin/users/invite",
         {"email": "newcomer@test.local", "name": "N", "role": "user"},
         "/invite/"),
        ("a reset link", f"/admin/users/{claimed}/reset-link", None, "/reset/"),
    )
    for label, path, data, kind in cases:
        print(label)
        before = len(waiting())
        r = admin.post(path, data=data or {}, follow_redirects=False)
        loc = r.headers.get("location", "")
        rows = waiting()
        check(f"it is held server-side between the POST and the GET "
              f"({len(rows)} waiting)", len(rows) == before + 1)
        page = admin.get(loc)
        link = shown(page.text)
        token = link.rsplit("/", 1)[-1]
        check(f"the issuer is shown it, got {link!r}",
              kind in link and len(token) > 20)
        check(f"and it is a link that works",
              invite.check(token)["ok"])
        check(f"the redirect carries no part of it: {loc!r}", clean(loc, token))
        check("and the page it lands on is not at an address carrying it",
              clean(str(page.url), token))
        check("the response carrying it is not kept by the browser",
              "no-store" in page.headers.get("cache-control", ""))
        held = [row for row in rows if row[1] == admin_id]
        check("what waited in the database was sealed, not the link",
              held and all(row[2].startswith("enc.v1.")
                           and token not in row[2] for row in held))
        check("and showing it deleted it", len(waiting()) == before)
        again = admin.get("/admin/users")
        check("it is shown exactly once: the next visit has no link",
              token not in again.text and not shown(again.text))
        check("and that page is cacheable as any other",
              "no-store" not in again.headers.get("cache-control", ""))

    print("a fresh invitation for an unclaimed account")
    pending = invite.create_user("pending@test.local", "P")
    r, loc, page = issue_and_follow(admin, f"/admin/users/{pending}/invite")
    token = shown(page.text).rsplit("/", 1)[-1]
    check("the issuer is shown the new link", len(token) > 20
          and invite.check(token)["ok"])
    check(f"and the redirect carries none of it: {loc!r}", clean(loc, token))

    print("following the redirects the way a browser does")
    r = admin.post(f"/admin/users/{claimed}/reset-link")
    token = shown(r.text).rsplit("/", 1)[-1]
    urls = [str(h.url) for h in r.history] + [str(r.url)] + \
        [h.headers.get("location", "") for h in r.history]
    check(f"no URL on the way carries it ({len(urls)} looked at)",
          len(token) > 20 and all(clean(u, token) for u in urls))

    print("a stale copy of the session cannot have it handed out again")
    # The session is a signed cookie, valid until it expires, so popping the
    # handle out of it proves nothing about a copy taken before the pop — a
    # proxy log of Set-Cookie, a backup of the browser profile. Only deleting
    # the row on the server makes "once" true.
    from fastapi.testclient import TestClient
    admin.post(f"/admin/users/{claimed}/reset-link", follow_redirects=False)
    stale = admin.cookies.get("portal_session")
    first = admin.get("/admin/users")
    replay = TestClient(main.app)
    replay.cookies.set("portal_session", stale)
    second = replay.get("/admin/users")
    check("the copy is a working session", second.status_code == 200
          and "Accounts" in second.text)
    check("the first page had the link", "/reset/" in shown(first.text))
    check("and the copy is not handed it a second time",
          not shown(second.text))

    print("it belongs to the session that issued it")
    admin.post(f"/admin/users/{claimed}/reset-link", follow_redirects=False)
    elsewhere = other.get("/admin/users")
    check("another administrator's next page does not show it",
          not shown(elsewhere.text))
    mine = admin.get("/admin/users")
    check("the issuer's does", "/reset/" in shown(mine.text))
    handle = invite.hold(admin_id, link="https://portal.example/reset/x")
    check("a handle presented for a different account yields nothing",
          invite.take(handle, "u-somebody-else") == {})
    handle = invite.hold(admin_id, link="https://portal.example/reset/y")
    db.run("UPDATE invite_shown SET at = at - ? WHERE handle = ?",
           (invite.HOLD_SECONDS + 1, handle))
    check("and one left too long is not handed out at all",
          invite.take(handle, admin_id) == {})

    print("a crafted address cannot paint a card around somebody's link")
    bait = admin.get(f"/admin/users?invited={claimed}&kind=reset&sent=1"
                     f"&link=https%3A%2F%2Fattacker.example%2Freset%2Fx")
    check("the query parameters are not read any more",
          "attacker.example" not in bait.text and not shown(bait.text))

    print("emailed, and still shown once, still not in the URL")
    sent: list = []
    mailer.save(host="smtp.example.com", from_addr="portal@example.com",
                base_url="https://portal.example.com")
    real_send = mailer.send
    mailer.send = lambda to, subject, body: sent.append((to, subject, body))
    try:
        r, loc, page = issue_and_follow(
            admin, "/admin/users/invite",
            {"email": "mailed@test.local", "name": "M", "role": "user"})
        link = shown(page.text)
        token = link.rsplit("/", 1)[-1]
        check("the page says it was emailed and shows the same link",
              "emailed</span>" in page.text and sent
              and link in sent[-1][2])
        check(f"and the redirect still carries none of it: {loc!r}",
              len(token) > 20 and clean(loc, token))
    finally:
        mailer.send = real_send
        mailer.save(host="", from_addr="", base_url="")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
