#!/usr/bin/env python3
"""Somebody who manages user accounts cannot get into an administrator's.

The edit form was guarded and four routes beside it were not. The worst was
the reset link: issued by a user manager for an administrator, it was shown to
the person who pressed the button, and redeeming it cleared the
administrator's authenticator as well as their password — the whole account,
handed over by a delegated role whose own description says it "cannot touch
an administrator's account". A fresh invitation, revoking one and resetting
the authenticator were the same gap in smaller sizes.

So every route that acts on an account is checked here, three ways each: the
user manager is refused an administrator's account, the user manager is still
allowed an ordinary one (a guard that refuses everything is a guard somebody
removes), and an administrator is allowed. A refusal is also an audit line,
and the page renders the controls the route would refuse as disabled, with the
reason, instead of offering a button that fails on submit.

    ./.venv/bin/python tests/test_user_admin_guard.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("useradmin-guard-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, invite, main, rbac                   # noqa: E402

bad = 0
PW = "Guarded-Pass-42"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def signed_in(email: str, role: str = "user", roles=()):
    from fastapi.testclient import TestClient
    uid = auth.create_user(email, "CI", PW, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, list(roles))
    c = TestClient(main.app)
    c.post("/login", data={"email": email, "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c, uid


def active(email: str, role: str = "user", roles=()) -> str:
    """A claimed account with an authenticator, as a real one would have."""
    uid = auth.create_user(email, "Target", PW, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("ENROLLEDSECRET1", uid))
    rbac.set_for_user(uid, list(roles))
    return uid


def unclaimed(email: str, role: str = "user") -> tuple[str, str]:
    """An invited account nobody has opened yet, and its live link."""
    uid = invite.create_user(email, "Invitee", role=role)
    return uid, invite.issue(uid, "setup@test.local")


def where(r) -> str:
    return urllib.parse.unquote(r.headers.get("location", ""))


def refused(r) -> bool:
    return r.status_code == 303 and "only an administrator" in where(r)


def allowed(r) -> bool:
    return r.status_code == 303 and "err=" not in r.headers.get("location", "")


def audited(target_email: str) -> int:
    return auth.count_audit(action="user_change_refused", q=target_email)


def resets_for(uid: str) -> int:
    return db.one("SELECT COUNT(*) AS n FROM invites WHERE uid = ? "
                  "AND kind = 'reset'", (uid,))["n"]


def enrolled(uid: str) -> bool:
    return bool((auth.by_id(uid) or {}).get("mfa_enrolled"))


def buttons(page: str, uid: str, action: str) -> list[str]:
    """The attributes of every button that submits a form posting to this
    account route — Cancel is a type=button and is left out, because it only
    closes the panel and must keep working."""
    out = []
    at = f'action="/admin/users/{uid}/{action}"'
    for m in re.finditer(re.escape(at), page):
        form = page[m.end():page.find("</form>", m.end())]
        out += [b for b in re.findall(r"<button([^>]*)>", form)
                if 'type="button"' not in b]
    return out


def main_test() -> int:
    people = rbac.save("", "People", "", ["users"], [], [])
    reader = rbac.save("", "Pipelines reader", "", ["pipelines"], [], [])
    admin, admin_id = signed_in("guard-admin@test.local", role="admin")
    mgr, mgr_id = signed_in("guard-mgr@test.local", roles=[people])

    boss = active("boss@test.local", role="admin")
    plain = active("ordinary@test.local", roles=[reader])

    print("a reset link")
    r = mgr.post(f"/admin/users/{boss}/reset-link", follow_redirects=False)
    check(f"a user manager is refused one for an administrator, got "
          f"{where(r)!r}", refused(r))
    check("and no link was issued for that account", resets_for(boss) == 0)
    check("and the refusal is in the audit log", audited("boss@test.local") == 1)
    r = mgr.post(f"/admin/users/{plain}/reset-link", follow_redirects=False)
    check(f"but may issue one for an ordinary account, got {where(r)!r}",
          allowed(r) and resets_for(plain) == 1)
    r = admin.post(f"/admin/users/{boss}/reset-link", follow_redirects=False)
    check(f"and an administrator may issue one for an administrator, got "
          f"{where(r)!r}", allowed(r) and resets_for(boss) == 1)

    print("resetting the authenticator")
    r = mgr.post(f"/admin/users/{boss}/reset-mfa", follow_redirects=False)
    check(f"a user manager is refused an administrator's, got {where(r)!r}",
          refused(r))
    check("and the administrator is still enrolled", enrolled(boss))
    check("and the refusal is audited", audited("boss@test.local") == 2)
    r = mgr.post(f"/admin/users/{plain}/reset-mfa", follow_redirects=False)
    check("but may reset an ordinary account's",
          allowed(r) and not enrolled(plain))
    r = mgr.post("/admin/users/u-nobody/reset-mfa", follow_redirects=False)
    check("an account that does not exist is said to be missing",
          "no such user" in where(r))

    print("a fresh invitation")
    pboss, pboss_tok = unclaimed("new-chief@test.local", role="admin")
    pplain, pplain_tok = unclaimed("newcomer@test.local")
    r = mgr.post(f"/admin/users/{pboss}/invite", follow_redirects=False)
    check(f"a user manager is refused one for an unclaimed administrator, got "
          f"{where(r)!r}", refused(r))
    # issuing revokes the previous link, so a link still working is the proof
    # that nothing was issued behind the refusal
    check("and the administrator's own link was left alone",
          invite.check(pboss_tok)["ok"])
    check("and the refusal is audited", audited("new-chief@test.local") == 1)
    r = mgr.post(f"/admin/users/{pplain}/invite", follow_redirects=False)
    check(f"but may reissue an ordinary one, got {where(r)!r}",
          allowed(r) and not invite.check(pplain_tok)["ok"])
    r = admin.post(f"/admin/users/{pboss}/invite", follow_redirects=False)
    check("and an administrator may reissue the administrator's",
          allowed(r) and not invite.check(pboss_tok)["ok"])
    # accepting an invitation sets the password of the account it names, so
    # one for an account in use is a reset without a reset's rules
    before = db.one("SELECT COUNT(*) AS n FROM invites WHERE uid = ? "
                    "AND kind = 'invite'", (plain,))["n"]
    r = admin.post(f"/admin/users/{plain}/invite", follow_redirects=False)
    check(f"nobody is given an invitation to an account already claimed, got "
          f"{where(r)!r}", "already been claimed" in where(r)
          and db.one("SELECT COUNT(*) AS n FROM invites WHERE uid = ? "
                     "AND kind = 'invite'", (plain,))["n"] == before)

    print("revoking an invitation")
    live_boss = invite.outstanding(pboss)
    r = mgr.post(f"/admin/users/{pboss}/invite/revoke", follow_redirects=False)
    check(f"a user manager is refused an administrator's, got {where(r)!r}",
          refused(r))
    check("and it still works", invite.outstanding(pboss) is not None
          and invite.outstanding(pboss)["id"] == live_boss["id"])
    check("and the refusal is audited", audited("new-chief@test.local") == 2)
    r = mgr.post(f"/admin/users/{pplain}/invite/revoke", follow_redirects=False)
    check("but may revoke an ordinary one",
          allowed(r) and invite.outstanding(pplain) is None)
    r = admin.post(f"/admin/users/{pboss}/invite/revoke", follow_redirects=False)
    check("and an administrator may revoke the administrator's",
          allowed(r) and invite.outstanding(pboss) is None)

    print("the routes that were already guarded are audited too")
    r = mgr.post(f"/admin/users/{boss}/update", follow_redirects=False,
                 data={"name": "hijacked", "role": "admin"})
    check("editing an administrator is refused",
          refused(r) and auth.by_id(boss)["name"] != "hijacked")
    r = mgr.post(f"/admin/users/{boss}/roles", follow_redirects=False,
                 data={"roles": [reader]})
    check("so is changing their roles", refused(r) and not rbac.of_user(boss))
    r = mgr.post(f"/admin/users/{boss}/delete", follow_redirects=False,
                 data={"confirm": "Delete"})
    check("and deleting them", refused(r) and auth.by_id(boss) is not None)
    check("each of those is an audit line",
          audited("boss@test.local") == 5)
    row = (auth.read_audit(1, action="user_change_refused") or [{}])[0]
    check(f"which names who tried, at what, and why: {row}",
          row.get("user") == "guard-mgr@test.local"
          and row.get("target") == "boss@test.local"
          and "delete" in row.get("detail", "")
          and "only an administrator" in row.get("detail", ""))
    check("and reads as a refusal on the audit page",
          auth.audit_severity(row.get("action", "")) == "danger")

    print("an account holding an escalating area counts as an administrator's")
    # Signing in as it hands over that area as surely as assigning the role
    # would — the third door of the guard, approached from the other side.
    ops = rbac.save("", "Operations", "", ["settings", "clusters"], [], [])
    operator = active("operator@test.local", roles=[ops])
    for act, data in (("reset-link", {}), ("reset-mfa", {}),
                      ("update", {"name": "O", "role": "user",
                                  "password": "Taken-Over-Pass-9"}),
                      ("roles", {"roles": [reader]}),
                      ("delete", {"confirm": "Delete"})):
        r = mgr.post(f"/admin/users/{operator}/{act}", data=data,
                     follow_redirects=False)
        check(f"{act}: refused for an account holding Settings, got "
              f"{where(r)!r}", refused(r) and "Settings" in where(r))
    after = auth.by_id(operator) or {}
    check("its password is untouched",
          auth.verify_password(after.get("password", ""), PW))
    check("so is its authenticator", enrolled(operator))
    check("no reset link exists for it", resets_for(operator) == 0)
    check("its roles are what they were",
          [x["id"] for x in rbac.of_user(operator)] == [ops])
    check("it still exists, and every refusal is audited",
          after and audited("operator@test.local") == 5)
    peer = active("peer-mgr@test.local", roles=[people])
    r = mgr.post(f"/admin/users/{peer}/reset-link", follow_redirects=False)
    check(f"so is another user manager's — User accounts is one of those "
          f"areas, got {where(r)!r}", refused(r) and "User accounts" in where(r))
    r = admin.post(f"/admin/users/{operator}/reset-link", follow_redirects=False)
    check("an administrator may still issue one",
          allowed(r) and resets_for(operator) == 1)

    print("the page says so before anybody presses anything")
    invite.request_reset("boss@test.local", "203.0.113.9")
    page = mgr.get("/admin/users").text
    for act in ("reset-link", "reset-mfa", "update", "roles"):
        got = buttons(page, boss, act)
        check(f"{act}: every button for the administrator is disabled for a "
              f"user manager ({len(got)})",
              got and all("disabled" in b for b in got))
        check(f"{act}: and says why",
              all("only an administrator" in b for b in got))
    got = buttons(page, plain, "reset-link")
    check(f"an ordinary account's stay live ({len(got)})",
          got and not any("disabled" in b for b in got))
    got = buttons(page, operator, "reset-link")
    check("an account holding Settings is inert too, and names the area",
          got and all("disabled" in b and "Settings" in b for b in got))
    panel = page[page.find(f'id="acc-acct-{boss}"'):]
    panel = panel[:panel.find("</td></tr>")]
    check("the administrator's panel says it is read-only, and why",
          "Read-only for you: only an administrator" in panel)
    check("its fields are inert", "<fieldset class=\"acc-fs\" disabled>" in panel)
    check("and so is delete",
          re.search(r'<button type="button" class="abtn danger"\s+disabled', panel)
          is not None)
    page = admin.get("/admin/users").text
    got = buttons(page, boss, "reset-link")
    check(f"an administrator sees every one of them live ({len(got)})",
          got and not any("disabled" in b for b in got))

    print("and the administrator may still reset another administrator's MFA")
    r = admin.post(f"/admin/users/{boss}/reset-mfa", follow_redirects=False)
    check("allowed", allowed(r) and not enrolled(boss))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
