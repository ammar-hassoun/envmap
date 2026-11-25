#!/usr/bin/env python3
"""Handing out the Administration pages without handing over the portal.

Users and the audit log are areas now, so a role can carry either. That is only
safe if somebody who manages users cannot use it to become an administrator,
and there are three doors to that: making an account an administrator, editing
one that already is, and assigning a role that carries Settings. All three are
checked here, because a hole in any one makes the other two decorative.

    ./.venv/bin/python tests/test_delegation.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("deleg-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, main, rbac                           # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def signed_in(email: str, pw: str, role: str = "user", roles=()):
    from fastapi.testclient import TestClient
    uid = (auth.by_email(email) or {}).get("id") or \
        auth.create_user(email, "CI", pw, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, list(roles))
    c = TestClient(main.app)
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c, uid


def main_test() -> int:
    print("every sidebar entry is something a role can grant")
    # the check that keeps this honest as pages are added: a route governed by
    # no area is checked by nothing, which is how /setup came to be reachable
    # by anybody who could sign in
    for path, want in (("/setup", "settings"), ("/setup/3", "settings"),
                       ("/overview/layout", "overview"),
                       ("/admin/users", "users"), ("/admin/audit", "audit"),
                       ("/spend", "spend"), ("/db", "db"), ("/vpn", "vpn"),
                       ("/gitops", "gitops"), ("/edge", "edge"),
                       ("/workflows", "workflows"), ("/bmc", "bmc"),
                       ("/virt", "virt"), ("/storage", "storage")):
        got = rbac.area_for_path(path)
        check(f"{path} is governed by {want}, got {got}", got == want)

    print("the delegable areas")
    everything = rbac.save("", "Everything", "", list(rbac.AREAS), [], [])
    people = rbac.save("", "People", "", ["users"], [], [])
    reader = rbac.save("", "Auditor", "", ["audit"], [], [])

    admin, admin_id = signed_in("deleg-admin@test.local", "Admin-Pass-42",
                                role="admin")
    hr, hr_id = signed_in("deleg-hr@test.local", "People-Pass-42",
                          roles=[people])
    aud, aud_id = signed_in("deleg-aud@test.local", "Audit-Pass-42",
                            roles=[reader])
    plain, plain_id = signed_in("deleg-none@test.local", "Plain-Pass-42")

    check("somebody with User accounts reaches the users page",
          hr.get("/admin/users").status_code == 200)
    check("and is refused the audit log",
          aud.get("/admin/users").status_code == 403
          or hr.get("/admin/audit").status_code == 403)
    check("the auditor reaches the audit log",
          aud.get("/admin/audit").status_code == 200)
    check("somebody with neither reaches neither",
          plain.get("/admin/users").status_code == 403
          and plain.get("/admin/audit").status_code == 403)
    check("and roles stays with administrators",
          hr.get("/admin/roles").status_code == 403
          and admin.get("/admin/roles").status_code == 200)

    print("a route nobody named is a route nobody guards")
    # /setup was reachable by anyone signed in: the sidebar hid the link and
    # the route checked nothing, which is not the same as refusing
    check("the project wizard is refused without Settings",
          plain.get("/setup", follow_redirects=False).status_code == 403)
    check("and allowed with it",
          admin.get("/setup", follow_redirects=False).status_code in (200, 303))

    print("managing users is not a way to become an administrator")
    # 1. outright
    r = hr.post("/admin/users/new", follow_redirects=False, data={
        "email": "sneak1@test.local", "name": "S", "password": "Sneaky-Pass-42",
        "role": "admin"})
    check("cannot create an administrator",
          "only an administrator" in urlunquote(r.headers.get("location", "")))
    check("and no such account was created", auth.by_email("sneak1@test.local") is None)

    # 2. by editing one that already is
    r = hr.post(f"/admin/users/{admin_id}/update", follow_redirects=False,
                data={"name": "hijacked", "role": "user"})
    check("cannot edit an administrator's account",
          "only an administrator" in urlunquote(r.headers.get("location", "")))
    check("and the account is untouched",
          auth.by_id(admin_id)["role"] == "admin"
          and auth.by_id(admin_id)["name"] != "hijacked")

    # 3. by handing themselves a role that carries Settings
    r = hr.post(f"/admin/users/{hr_id}/roles", follow_redirects=False,
                data={"roles": [everything]})
    check("cannot assign a role that grants Settings",
          "only an administrator" in urlunquote(r.headers.get("location", "")))
    check("and their own roles did not change",
          [x["id"] for x in rbac.of_user(hr_id)] == [people])
    check("so Settings is still refused to them",
          hr.get("/settings", follow_redirects=False).status_code == 403)

    # and the same door on the invitation route
    r = hr.post("/admin/users/invite", follow_redirects=False, data={
        "email": "sneak2@test.local", "name": "S", "role": "user",
        "roles": [everything]})
    check("nor through an invitation",
          "only an administrator" in urlunquote(r.headers.get("location", "")))
    check("and nobody was invited", auth.by_email("sneak2@test.local") is None)

    print("what they can legitimately do")
    r = hr.post("/admin/users/invite", follow_redirects=False, data={
        "email": "newbie@test.local", "name": "New", "role": "user",
        "roles": [reader]})
    check(f"invite an ordinary account, got {r.status_code}", r.status_code == 303)
    check("which exists afterwards", auth.by_email("newbie@test.local") is not None)
    check("with the harmless role attached",
          [x["id"] for x in
           rbac.of_user(auth.by_email("newbie@test.local")["id"])] == [reader])

    print("deleting an account asks for the word")
    # A confirm() in the browser is a confirmation anybody can skip by posting
    # the form directly, and this endpoint takes an account and its roles away.
    victim, victim_id = signed_in("deleg-victim@test.local", "Victim-Pass-42")
    r = admin.post(f"/admin/users/{victim_id}/delete", follow_redirects=False)
    check("a post with no confirmation is refused",
          "type Delete" in urlunquote(r.headers.get("location", "")))
    check("and the account is still there", auth.by_id(victim_id) is not None)
    r = admin.post(f"/admin/users/{victim_id}/delete",
                   data={"confirm": "nope"}, follow_redirects=False)
    check("the wrong word is refused too",
          "type Delete" in urlunquote(r.headers.get("location", "")))
    check("still there", auth.by_id(victim_id) is not None)
    r = admin.post(f"/admin/users/{victim_id}/delete",
                   data={"confirm": "Delete"}, follow_redirects=False)
    check("the word, in any case, works", auth.by_id(victim_id) is None)

    print("an administrator is still unrestricted")
    r = admin.post("/admin/users/new", follow_redirects=False, data={
        "email": "realadmin@test.local", "name": "A", "password": "Real-Admin-42",
        "role": "admin"})
    check(f"and can create one, got {r.status_code}", r.status_code == 303)
    check("which is an administrator",
          (auth.by_email("realadmin@test.local") or {}).get("role") == "admin")

    print("the sidebar is the same on every page that has one")
    # The version pill was passed through ctx(), so it was blank on the four
    # pages that build their context by hand — Compare, Search, the wizard and
    # the denied page. Nothing failed; the sidebar just quietly rendered an
    # empty pill on a quarter of the product. It is a template global now, and
    # this is the check that a new hand-built page cannot undo that.
    import re as _re
    for path in ("/compare", "/search?q=x", "/setup", "/about",
                 "/settings/deployment", "/settings"):
        r = admin.get(path, follow_redirects=True)
        if r.status_code != 200:
            check(f"{path} renders, got {r.status_code}", False)
            continue
        m = _re.search(r'<a class="brandver label"[^>]*>(.*?)</a>', r.text, _re.S)
        shown = _re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""
        check(f"{path} shows the version in the sidebar, got {shown!r}",
              bool(shown))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


def urlunquote(s: str) -> str:
    import urllib.parse
    return urllib.parse.unquote(s)


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
