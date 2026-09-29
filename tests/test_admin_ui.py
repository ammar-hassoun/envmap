#!/usr/bin/env python3
"""The admin dialogs, as rendered.

A dialog that asks for values is easy to get subtly wrong in ways no unit test
sees: a label/field grid narrow enough to cut a tenant GUID in half, a native
checkbox drawn light on a dark page, a copy button wired to nothing. Every case
here is something that was actually shipped looking wrong.

The page is fetched through the real app so the checks run against what a
browser is sent, not against a template read off disk.

    ./.venv/bin/python tests/test_admin_ui.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("adminui-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def admin_page(path: str) -> str:
    from fastapi.testclient import TestClient
    from app import auth, db, main

    email, pw = "adminui@test.local", "Dialogs-Look-Fine-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    with c:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        # A SECOND, INVITED account, because half the row's controls only exist
        # for one: "Send invitation", "Revoke" and the absence of a password
        # field are all states a fully signed-up admin never renders. With one
        # user the page cannot show what it does to the other kind, and a test
        # that never sees those branches is not testing the page.
        c.post("/admin/users/invite",
               data={"email": "invitee@test.local", "name": "Invitee",
                     "role": "user"}, follow_redirects=False)
        return c.get(path).text


def accounts_are_a_table(page: str) -> None:
    """Seventeen accounts were seventeen cards, and the page was three screens.

    Each card carried a name, an email, three badges, a role chip, two closed
    <details> and up to five buttons — so "who has an admin account here" meant
    scrolling. As rows it is one glance, and the operations that act on an
    account moved into its own panel where they belong.
    """
    print("accounts are ROWS, not a card each")
    check("no account renders as a rowcard any more",
          'class="rowcard"' not in page)
    check("they are rows of one table with real headers",
          'class="jenkins acc-t"' in page
          and all(f">{h}</th>" in page for h in ("Account", "Access", "Status")))
    # A flat sort would scramble a form away from the account it belongs to —
    # the same reason a grouped table opts out. The filter does the finding.
    check("every header opts out of sorting, because it has detail rows",
          page.count('class="no-sort"') == 3 and "no-sort actcol" in page)
    check("and there is a filter instead", 'id="aufind"' in page)
    check("the row's own actions are house buttons on one line",
          'class="actrow oneline"' in page)

    print("and every panel arrives shut")
    panels = re.findall(
        r'<tr class="acc-form au-row-of-[^"]*" id="[^"]*"( hidden)?>', page)
    check(f"there are panels to shut ({len(panels)})", len(panels) >= 4)
    check("all of them are hidden on arrival", all(panels))
    check("adding somebody is shut too, not open under a list of seventeen",
          '<details class="acc-sec">' in page)

    print("nothing an admin can do to an account was lost in the move")
    # These are the operations that were buttons in the old card header. They
    # are in the Account panel now; losing one silently would leave an admin
    # with no way to help somebody who has lost their phone.
    for act in ("/roles", "/update", "/reset-link", "/reset-mfa",
                "/invite", "/invite/revoke", "/admin/users/invite"):
        check(f"{act} is still reachable", act in page)
    check("deleting still asks for the word rather than a confirm()",
          "dropUser(" in page and 'id="dropUser"' in page)


def main() -> int:
    page = admin_page("/admin/users")
    accounts_are_a_table(page)

    print("the Microsoft sign-in dialog")
    check("the dialog is on the page", '<dialog id="ssoDialog"' in page)
    dlg = page[page.find('<dialog id="ssoDialog"'):]
    dlg = dlg[:dlg.find("</dialog>")]

    # every value the route reads still has somewhere to come from
    names = set(re.findall(
        r'<(?:input|select|textarea|button)\b[^>]*\bname="([^"]+)"', dlg))
    for want in ("enabled", "tenant", "client_id", "client_secret",
                 "auto_create", "redirect_override", "do_test"):
        check(f"the dialog still posts '{want}'", want in names)
    # two fields with one name means the parser silently keeps the last, which
    # is how an empty hidden input once ate the repository name
    posted = re.findall(
        r'<(?:input|select|textarea|button)\b[^>]*\bname="([^"]+)"', dlg)
    dupes = sorted({n for n in posted if posted.count(n) > 1})
    check(f"no duplicate field names {dupes}", not dupes)

    # a 620px dialog cannot afford a label column beside the input: a tenant
    # GUID was being cut off mid-value, so fields stack instead
    check("fields stack (.dfield), not a label/field grid",
          dlg.count('class="dfield"') >= 5)
    check("the two-column .field-row grid is gone from this dialog",
          'class="field-row"' not in dlg)
    check("fields are grouped under captions (.dsec)",
          dlg.count('class="dsec"') >= 3)
    check("each awkward field carries its own help line",
          dlg.count('class="dhelp"') >= 3)

    # the redirect URL has to be carried to somebody else's console
    check("the redirect URL is offered in a copy row",
          'class="dcopy"' in dlg
          and 'data-call="portalCopy" data-arg-self' in dlg)
    check("portalCopy exists to be called", "window.portalCopy" in page)
    copyfn = page.partition("window.portalCopy")[2][:900]
    check("it falls back when the clipboard is refused",
          "getSelection" in copyfn)

    # drawn, not typed: a font glyph cannot be brand-coloured and lands at
    # whatever weight the interface font decides to give it
    head = dlg[dlg.find('class="dhead"'):dlg.find('class="dbody"')]
    check("the brand mark is drawn", "#00a4ef" in head and "<svg" in head)
    check("the close control is drawn",
          "<svg" in head.partition('class="dx"')[2])
    for glyph in ("✕", "✖", "❌", "✉"):
        check(f"no font glyph {glyph!r} in the header", glyph not in head)
    check("the close control says what it is",
          'aria-label="Close"' in head)

    # the checkbox is a choice card, not a bare box with a sentence beside it
    check("the toggle is a .pick card", 'class="pick"' in dlg)
    check("no hand-sized inline width override",
          'style="width:auto"' not in dlg)
    check("the rarely-needed field is folded away", "<details" in dlg)

    print("controls the browser draws itself")
    base = (pathlib.Path(__file__).resolve().parent.parent
            / "templates" / "base.html").read_text() \
        + (pathlib.Path(__file__).resolve().parent.parent
           / "static" / "app.css").read_text()
    # without this, a native checkbox is drawn light on the dark theme — it
    # read as a big white box next to the portal's own styled controls
    check("color-scheme is declared for the dark theme",
          re.search(r":root\s*\{[^}]*color-scheme:\s*dark", base, re.S)
          is not None)
    check("color-scheme is declared for the light theme",
          re.search(r':root\[data-theme="light"\]\s*\{[^}]*'
                    r"color-scheme:\s*light", base, re.S) is not None)
    check("checkboxes take the portal's accent",
          "accent-color:var(--accent)" in base)

    # a class with no rule behind it is a silent no-op
    print("every class used has a rule")
    used = {c for v in re.findall(r'class="([^"]+)"', dlg)
            for c in v.split()}
    missing = sorted(c for c in used
                     if f".{c}" not in base and f".{c}" not in page)
    check(f"classes with no CSS rule: {missing}", not missing)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
