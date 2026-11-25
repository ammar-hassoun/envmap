#!/usr/bin/env python3
"""A click goes where it says.

WHY THIS EXISTS
    Reported 22 November 2026: "some clicks inside the portal take me to
    unexpected pages". A crawl of every link on the demo estate found no broken
    link and no stray redirect, and four clicks that landed somewhere other than
    what they named, all of them a page that EXISTS, which is why nothing failed:

      * a project's "⚙︎ Settings" (and a region's) pointed at `/settings#<id>`.
        The hub has no place by either name, so it opened the top of the hub.
        A project's settings are on the projects page, a region's on the
        clusters page, each under its own id.
      * the sidebar's "New project" opened the list of projects that already
        exist, with the form to add one shut at the foot of it.
      * "Back to Privileged Access" on its settings page, with the feature off,
        went to /pam, which sends everybody to the home page.
      * the top bar's kubectl and Troubleshoot skipped the list of clusters
        whenever ONE cluster qualified, on any estate. With management on for
        one cluster of twenty, Troubleshoot opened that cluster and, because the
        address carries `troubleshoot=1`, started a pod there: a page and an
        action nobody had picked.

    The sweeps here are general on purpose: the next anchor somebody points at a
    page that has no such id fails here, not in somebody's hands.

    ./.venv/bin/python tests/test_click_targets.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("clicks-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import main                                            # noqa: E402
from app import auth, db, pam, store                            # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")
    else:
        print(f"  ok   {what}")


def ids(html: str) -> set[str]:
    return set(re.findall(r'\bid="([^"]+)"', html))


def main_test() -> int:
    from fastapi.testclient import TestClient
    uid = auth.create_user("admin@t.local", "Admin", "Clicks-Go-Where-They-Say-42", role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, email_verified=1 WHERE id=?",
           ("TESTSECRET", uid))
    pid = store.add_project("Payments", "💸")
    rgid = store.add_region(pid, "Kenya", "🇰🇪")
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "admin@t.local", "password": "Clicks-Go-Where-They-Say-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)

    print("a settings link opens the settings of the thing it is on")
    proj = c.get(f"/p/{pid}").text
    check("a project's Settings link names the projects page and the project",
          f'href="/settings/projects#{pid}"' in proj)
    projects = c.get("/settings/projects").text
    check("and the projects page has the project under that name, and opens its edit form when named",
          pid in ids(projects) and "const edit = card.querySelector('details.adv');" in projects
          and "if (edit) edit.open = true;" in projects)
    reg = c.get(f"/p/{pid}/{rgid}")
    check(f"a region's page renders ({reg.status_code})", reg.status_code == 200)
    check("a region's Settings links name the clusters page and the region",
          reg.text.count(f'href="/settings/clusters#{rgid}"') == 2)
    check("and the clusters page has the region under that name",
          rgid in ids(c.get("/settings/clusters").text))
    hub_ids = ids(c.get("/settings").text)
    pointed = set()
    for t in (ROOT / "templates").glob("*.html"):
        for frag in re.findall(r'href="/settings#([^"]+)"', t.read_text()):
            pointed.add((t.name, frag))
    check(f"no page points into the hub at a place the hub does not have ({sorted(pointed)[:3]})",
          all(frag in hub_ids for _, frag in pointed))

    print("New project lands on the form that makes one")
    base = (ROOT / "templates" / "base.html").read_text()
    check("the sidebar link asks for the form",
          "link('/settings/projects?new=1#new', 'settings', glyph('plus'), 'New project')" in base)
    adding = c.get("/settings/projects?new=1").text
    check("and that page arrives with the add form open and the caret in its name field",
          re.search(r'<details class="adv" id="new" open>', adding) is not None
          and re.search(r'name="name" required placeholder="e\.g\. Payments Platform"\s+autofocus', adding) is not None)
    plain = c.get("/settings/projects").text
    check("while a plain visit with projects to list keeps it shut",
          re.search(r'<details class="adv" id="new" >', plain) is not None and "autofocus" not in plain)

    print("back goes somewhere that exists")
    pam.save_config(enabled=False)
    off = c.get("/settings/pam").text
    check("with Privileged Access off its settings page offers no way 'back' to it",
          "Back to Privileged Access" not in off)
    r = c.get("/pam", follow_redirects=False)
    check(f"(because /pam is not a page then: {r.status_code} to {r.headers.get('location')})",
          r.status_code in (302, 303, 307) and not (r.headers.get("location") or "").startswith("/pam"))
    pam.save_config(enabled=True)
    check("with it on, the way back is there",
          "Back to Privileged Access" in c.get("/settings/pam").text)
    pam.save_config(enabled=False)

    print("a shortcut does not choose a cluster for you")
    check("kubectl and Troubleshoot go straight in only on an estate of one cluster",
          "if (rows.length === 1 && allowed(rows[0], m)) { location.href = target(rows[0], m); return; }" in base
          and "eligible.length === 1" not in base)
    return 0


if __name__ == "__main__":
    main_test()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
