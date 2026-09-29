#!/usr/bin/env python3
"""Invitations: an account somebody else finishes setting up.

The whole point is that a password is never transmitted, so the cases worth
writing down are the ones where a link is more dangerous than a password: a
link that still works after being replaced, after being used, after expiring,
or after the account was disabled.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_invite.py
"""
from __future__ import annotations

import datetime as dt
import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("invite-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, invite, rbac                          # noqa: E402

bad = 0
GOOD = "Choose-A-Real-1"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def raises(fn) -> str:
    try:
        fn()
    except ValueError as e:
        return str(e)
    return ""


def main() -> int:
    print("an invited account cannot be signed into")
    uid = invite.create_user("new@example.com", "New Person", role="user")
    u = auth.by_id(uid)
    check("the account exists straight away", bool(u))
    check("it is pending", invite.is_pending(u))
    # the sentinel is not a hash, so nothing can ever verify against it
    check("no password works on it, including the sentinel itself",
          not auth.verify_password(u["password"], invite.PENDING)
          and not auth.verify_password(u["password"], "")
          and not auth.verify_password(u["password"], GOOD))
    check("and it is not mistaken for a single sign-on account",
          not auth.is_sso_user(u))
    check("with nothing to show before a link is issued",
          invite.outstanding(uid) is None)
    check(f"so it reads as stalled, got {invite.state(u)['key']}",
          invite.state(u)["key"] == "stalled")

    print("the link is issued once and not stored")
    token = invite.issue(uid, "admin@example.com")
    row = db.one("SELECT * FROM invites WHERE uid = ?", (uid,))
    check("the token itself is nowhere in the database",
          token not in str(dict(row)))
    check("only its hash is", len(row["token_hash"]) == 64)
    check("the account now reads as invited",
          invite.state(auth.by_id(uid))["key"] == "invited")
    check("and who invited them is recorded",
          auth.by_id(uid)["invited_by"] == "admin@example.com")
    check("the link is built from the origin it will be opened at",
          invite.link("https://portal.example.com/", token)
          == f"https://portal.example.com/invite/{token}")

    print("a link that should not work, does not")
    check("a made-up token is refused", not invite.check("not-a-real-token")["ok"])
    check("and says so in words somebody can act on",
          "not valid" in invite.check("nope")["why"])

    # issuing a second link must kill the first, or a revoked invitation is
    # only revoked in the admin's imagination
    second = invite.issue(uid, "admin@example.com")
    check("the replaced link stops working", not invite.check(token)["ok"])
    check("and says it was replaced", "replaced" in invite.check(token)["why"])
    check("the new one works", invite.check(second)["ok"])

    # expiry
    third = invite.issue(uid, "admin@example.com")
    db.run("UPDATE invites SET expires = ? WHERE token_hash = ?",
           ((dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
            invite._hash(third)))
    check("an expired link is refused", not invite.check(third)["ok"])
    check("and names the date rather than just failing",
          "expired on" in invite.check(third)["why"])
    check("an account with only an expired link reads as stalled",
          invite.state(auth.by_id(uid))["key"] == "stalled")

    # a disabled account
    fourth = invite.issue(uid, "admin@example.com")
    auth.update_user(uid, disabled=True)
    check("a link to a disabled account is refused",
          not invite.check(fourth)["ok"])
    auth.update_user(uid, disabled=False)

    print("accepting it")
    live = invite.issue(uid, "admin@example.com")
    check("a weak password is refused with the reason",
          "10 characters" in raises(lambda: invite.accept(live, "short")))
    check("and the link still works after that refusal",
          invite.check(live)["ok"])
    who = invite.accept(live, GOOD)
    check("the password they chose is the one that works",
          auth.verify_password(who["password"], GOOD))
    check("the account is no longer pending", not invite.is_pending(who))
    # This link was carried by hand — an administrator copied it somewhere. So
    # opening it proves the person could read that somewhere, not that they
    # hold the mailbox, and the address must NOT come out verified.
    check("a hand-carried invitation verifies nothing",
          not who["email_verified"])
    check("a used link cannot be used again", not invite.check(live)["ok"])
    check("and says it was already used", "already been used" in invite.check(live)["why"])
    check("replaying it raises rather than quietly resetting the password",
          bool(raises(lambda: invite.accept(live, "Another-Password-9"))))
    check("the password from the first acceptance is untouched",
          auth.verify_password(auth.by_id(uid)["password"], GOOD))
    check("MFA is still outstanding, so the account is not yet active",
          invite.state(auth.by_id(uid))["key"] == "no-mfa")
    auth.update_user(uid, totp_secret=auth.new_totp_secret(), mfa_enrolled=True)
    check("and once an authenticator is added it works, but says the address "
          "was never proved",
          invite.state(auth.by_id(uid))["key"] == "unverified")
    check("in words an administrator can act on",
          "not verified" in invite.state(auth.by_id(uid))["note"])

    print("an invitation the portal posted itself")
    # The only case that can honestly claim verification: the link went to the
    # address, so coming back with it proves the mailbox was reachable.
    posted = invite.create_user("posted@example.com", "Posted")
    ptok = invite.issue(posted, "admin@example.com")
    invite.mark_delivery(posted, invite.KIND_INVITE, "email")
    pwho = invite.accept(ptok, GOOD)
    check("an emailed invitation does verify the address",
          bool(pwho["email_verified"]))
    auth.update_user(posted, totp_secret=auth.new_totp_secret(), mfa_enrolled=True)
    check("and the account reads as fully active",
          invite.state(auth.by_id(posted))["key"] == "active")
    # a relay that fails downgrades the claim rather than leaving it standing
    failed = invite.create_user("failed@example.com", "Failed")
    ftok = invite.issue(failed, "admin@example.com")
    invite.mark_delivery(failed, invite.KIND_INVITE, "email")
    invite.mark_delivery(failed, invite.KIND_INVITE, "manual")
    check("a relay that refused leaves the invitation hand-carried",
          not invite.accept(ftok, GOOD)["email_verified"])

    print("through the HTTP stack")
    from fastapi.testclient import TestClient
    from app import main as _main

    admin_mail, admin_pw = "invadmin@test.local", "Invite-Admin-42"
    aid = (auth.by_email(admin_mail) or {}).get("id") or \
        auth.create_user(admin_mail, "CI", admin_pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", aid))
    c = TestClient(_main.app)
    c.post("/login", data={"email": admin_mail, "password": admin_pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    role_id = rbac.save("", "Read the pipelines", "", ["pipelines"], [], [])
    r = c.post("/admin/users/invite",
               data={"email": "invited@example.com", "name": "Invited Person",
                     "role": "user", "roles": [role_id]},
               follow_redirects=False)
    check(f"inviting redirects, got {r.status_code}", r.status_code == 303)
    where = r.headers["location"]
    check("and carries the link back to be shown once", "link=" in where)
    import urllib.parse as up
    link = up.parse_qs(up.urlparse(where).query)["link"][0]
    tok = link.rsplit("/", 1)[-1]

    new_uid = auth.by_email("invited@example.com")["id"]
    check("the role was assigned at creation, not at acceptance",
          [x["id"] for x in rbac.of_user(new_uid)] == [role_id])

    page = c.get(where.replace("/admin/users?", "/admin/users?"))
    check("the admin page shows the link once", link in page.text)
    check("and says this is the only moment it can be shown",
          "the one moment it can be shown" in page.text)

    # the invitee is not signed in and has no account yet
    anon = TestClient(_main.app)
    open_page = anon.get(f"/invite/{tok}")
    check(f"the invitee can open it without signing in, got {open_page.status_code}",
          open_page.status_code == 200)
    check("it shows the address being verified",
          "invited@example.com" in open_page.text)
    check("and names the role they are getting",
          "Read the pipelines" in open_page.text)

    check("a stranger still cannot reach the portal itself",
          anon.get("/spend", follow_redirects=False).headers.get("location", "")
          .startswith("/login"))

    done = anon.post(f"/invite/{tok}",
                     data={"password": GOOD, "confirm": GOOD},
                     follow_redirects=False)
    check(f"accepting sends them to enrolment, got {done.headers.get('location')}",
          done.headers.get("location") == "/mfa/setup")
    setup = anon.get("/mfa/setup")
    check("which renders a QR to scan", setup.status_code == 200
          and "data:image" in setup.text)
    check("mismatched passwords are refused before anything is written",
          anon.post(f"/invite/{tok}", data={"password": "Aaaaaaaaa1",
                                            "confirm": "Bbbbbbbbb2"},
                    follow_redirects=False).headers["location"].startswith("/invite/"))

    print("forgetting a password")
    # Nothing about this may reveal who has an account, and nothing about it
    # may hand a link to whoever typed the address — either would make the form
    # a way to take over an account rather than a way to recover one.
    real, fake = "invited@example.com", "nobody@example.com"
    a = anon.post("/forgot", data={"email": real}, follow_redirects=False)
    b = anon.post("/forgot", data={"email": fake}, follow_redirects=False)
    check("an address that exists and one that does not answer identically",
          (a.status_code, a.headers["location"])
          == (b.status_code, b.headers["location"]))
    page = anon.get(a.headers["location"])
    check("and the page says the same thing either way",
          "If that address has an account" in page.text)
    check("no link is anywhere on it", "/reset/" not in page.text)
    pending = {r["email"] for r in invite.reset_requests()}
    check("both requests reach the administrator", {real, fake} <= pending)
    check("a request for an unknown address carries no account to reset",
          not [r for r in invite.reset_requests()
               if r["email"] == fake and r["uid"]])

    reset_uid = auth.by_email(real)["id"]
    # the invited account has an authenticator by now, as a real one would
    auth.update_user(reset_uid, totp_secret=auth.new_totp_secret(),
                     mfa_enrolled=True)
    before_secret = auth.by_id(reset_uid)["totp_secret"]
    # verified the only way it can be: by an invitation this portal posted
    auth.update_user(reset_uid, email_verified="2026-01-01 00:00:00")
    before_verified = auth.by_id(reset_uid)["email_verified"]
    r = c.post(f"/admin/users/{reset_uid}/reset-link", follow_redirects=False)
    rlink = up.parse_qs(up.urlparse(r.headers["location"]).query)["link"][0]
    check("the reset link is a reset URL, not an invitation one",
          "/reset/" in rlink)
    rtok = rlink.rsplit("/", 1)[-1]

    # the two kinds must not be interchangeable at the URL
    check("a reset token is refused at the invitation page",
          anon.get(f"/invite/{rtok}").status_code == 410)
    check("and an invitation token at the reset page",
          anon.get(f"/reset/{tok}").status_code == 410)

    NEW = "Brand-New-Pass-7"
    # a fresh client: the one above accepted an invitation earlier and already
    # holds a session, which would hide the thing being checked here
    quiet = TestClient(_main.app)
    done = quiet.post(f"/reset/{rtok}", data={"password": NEW, "confirm": NEW},
                      follow_redirects=False)
    check("a reset never signs anybody in — it sends them to sign in",
          done.headers["location"].startswith("/login"))
    check("and no session was created on the way",
          quiet.get("/spend", follow_redirects=False)
          .headers.get("location", "").startswith("/login"))
    fresh = auth.by_id(reset_uid)
    check("the new password works", auth.verify_password(fresh["password"], NEW))
    check("the old one does not", not auth.verify_password(fresh["password"], GOOD))
    # An administrator issued this one, so it clears the authenticator with the
    # password: the two are usually lost together, and the person enrols again
    # at the next sign-in.
    check("an administrator's reset clears the authenticator too",
          not fresh["mfa_enrolled"] and not fresh["totp_secret"])
    check("so the account is back to setting up",
          invite.state(auth.by_id(reset_uid))["key"] == "no-mfa")
    # a reset link is handed over by an administrator, so it proves nothing
    # about who holds the mailbox and must not claim to
    check("a reset leaves the verification stamp exactly as it was",
          fresh["email_verified"] == before_verified)
    check("the waiting request is cleared once it is used",
          real not in {q["email"] for q in invite.reset_requests()})
    check("the reset link cannot be replayed",
          not invite.check(rtok, invite.KIND_RESET)["ok"])

    print("a self-service reset leaves the second factor alone")
    # If reading somebody's inbox also cleared their authenticator, the inbox
    # would be the only factor and MFA would be decoration. An administrator
    # issuing a reset has identified the person some other way; /forgot has
    # only proved that somebody can read an inbox. So the two differ, and the
    # difference is recorded on the link when it is issued.
    auth.update_user(reset_uid, totp_secret=auth.new_totp_secret(),
                     mfa_enrolled=True)
    kept_secret = auth.by_id(reset_uid)["totp_secret"]
    self_tok = invite.issue(reset_uid, "self-service", kind=invite.KIND_RESET)
    invite.accept(self_tok, "Self-Service-Pass-3", invite.KIND_RESET)
    after = auth.by_id(reset_uid)
    check("the password changed",
          auth.verify_password(after["password"], "Self-Service-Pass-3"))
    check("but the authenticator did not",
          after["mfa_enrolled"] and after["totp_secret"] == kept_secret)

    # issuing a reset must not cancel an unopened invitation, and vice versa
    other = invite.create_user("both@example.com", "Both")
    inv_tok = invite.issue(other, "admin@example.com")
    auth.set_password(other, "Temporary-Pass-1")     # no longer pending
    invite.issue(other, "admin@example.com", kind=invite.KIND_RESET)
    check("a reset link does not quietly revoke a live invitation",
          invite.check(inv_tok, invite.KIND_INVITE)["ok"])

    check("an account nobody has claimed is refused a reset link",
          "invitation" in up.unquote(
              c.post(f"/admin/users/{invite.create_user('unclaimed@example.com', 'U')}"
                     f"/reset-link", follow_redirects=False).headers["location"]))

    print("a link that gets emailed is not built from the Host header")
    # /forgot is open to anonymous callers. If the link in the email came from
    # request.base_url, anybody could post a reset with a forged Host and the
    # victim would receive a genuine reset link pointing at the attacker.
    from app import mailer
    sent: list = []
    mailer.save(host="smtp.example.com", from_addr="portal@example.com",
                base_url="")
    real_send = mailer.send
    mailer.send = lambda to, subject, body: sent.append((to, subject, body))
    try:
        victim = auth.by_email("posted@example.com") or {}
        poisoned = TestClient(_main.app, base_url="http://attacker.example")
        poisoned.post("/forgot", data={"email": "invited@example.com"},
                      follow_redirects=False)
        check("with no public address set, nothing is emailed at all",
              not sent)
        check("and it falls back to an administrator issuing the link",
              "invited@example.com" in {q["email"] for q in invite.reset_requests()})

        # configured: the link uses that, whatever the request claims
        mailer.save(base_url="https://portal.example.com")
        sent.clear()
        poisoned.post("/forgot", data={"email": "invited@example.com"},
                      follow_redirects=False)
        check("with one set, the link uses it", sent
              and "https://portal.example.com/reset/" in sent[-1][2])
        check("and never the forged Host",
              sent and "attacker.example" not in sent[-1][2])
    finally:
        mailer.send = real_send
        mailer.save(host="", from_addr="", base_url="")

    print("with a relay configured, the portal posts it itself")
    sent = []
    mailer.save(host="smtp.example.com", from_addr="portal@example.com",
                base_url="https://portal.example.com")
    real_send = mailer.send
    mailer.send = lambda to, subject, body: sent.append((to, subject, body))
    try:
        r = c.post("/admin/users/invite",
                   data={"email": "posted-http@example.com", "name": "Posted",
                         "role": "user"}, follow_redirects=False)
        loc = r.headers["location"]
        # emailed AND shown: mail is slow and filtered, and somebody has to be
        # able to read the link out over the phone
        check("the admin is told it was emailed", "sent=1" in loc)
        check("and is still given the link", "link=" in loc)
        check("and it went to the right address with the link in it",
              sent and sent[-1][0] == "posted-http@example.com"
              and "/invite/" in sent[-1][2])
        tok2 = sent[-1][2].split("/invite/")[1].split()[0]
        fresh_client = TestClient(_main.app)
        fresh_client.post(f"/invite/{tok2}", data={"password": GOOD, "confirm": GOOD},
                          follow_redirects=False)
        posted_u = auth.by_email("posted-http@example.com")
        check("accepting an emailed invitation verifies the address",
              bool(posted_u["email_verified"]))

        # forgotten password stops needing an administrator at all
        sent.clear()
        r = anon.post("/forgot", data={"email": "posted-http@example.com"},
                      follow_redirects=False)
        check("the reset link is emailed to the address itself",
              sent and sent[-1][0] == "posted-http@example.com"
              and "/reset/" in sent[-1][2])
        check("and no administrator is troubled with it",
              "posted-http@example.com" not in
              {q["email"] for q in invite.reset_requests()})
        # the answer must still not differ for an address nobody has
        sent.clear()
        unknown = anon.post("/forgot", data={"email": "ghost@example.com"},
                            follow_redirects=False)
        check("an unknown address gets the same answer as a real one",
              unknown.headers["location"] == r.headers["location"])
        check("and nothing is sent to it", not sent)

        # a relay that fails must not lose the invitation
        mailer.send = lambda to, subject, body: (_ for _ in ()).throw(
            ValueError("the relay refused the message: 550 relay denied"))
        r = c.post("/admin/users/invite",
                   data={"email": "broken@example.com", "name": "B", "role": "user"},
                   follow_redirects=False)
        loc = up.unquote(r.headers["location"])
        check("a refused send still hands over the link", "link=" in loc)
        check("and marks it as not sent", "sent=0" in loc)
        check("and says why it could not be emailed", "relay denied" in loc)
    finally:
        mailer.send = real_send
        mailer.save(host="", from_addr="")

    bad_page = anon.get("/invite/rubbish")
    check(f"a bad link is gone, not a 200, got {bad_page.status_code}",
          bad_page.status_code == 410)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
