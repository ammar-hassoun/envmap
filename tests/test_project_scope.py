#!/usr/bin/env python3
"""A role pinned to one project opens that project's pages, and no other.

WHY THIS EXISTS
    The same finding as tests/test_cluster_scope.py, one level up. A role's
    "projects" list was stored, shown on the roles page, and consulted by
    almost nothing: /p/<another project> opened its regions, its values files
    and the commit window over them; the sidebar listed every project; and the
    Clouds hub and an account's own page listed every cloud account — inventory
    and costs — to a role confined to one project, while the pages BELOW them
    refused the same account.

    So: a role pinned to project 1 is refused project 2's pages, GET and POST,
    with a 403 and an audit line; the sidebar names project 1 only; and the
    Clouds hub shows project 1's account and neither project 2's nor the one
    shared by every project, which only an unconfined role sees — the rule the
    account pages already applied.

    ./.venv/bin/python tests/test_project_scope.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("projectscope-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, cloud, db, main, rbac, store             # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P1 = store.add_project("Alpha")
P2 = store.add_project("Beta")
P3 = store.add_project("Gamma")
R1 = store.add_region(P1, "North")
R2 = store.add_region(P2, "South")
ACC1 = store.add_cloud(P1, {"name": "alpha-account", "type": "aws"})
ACC2 = store.add_cloud(P2, {"name": "beta-account", "type": "aws"})
ACC0 = store.add_cloud("", {"name": "shared-account", "type": "aws"})

# Nothing reaches a provider: the hub reads a cache the warmer fills, and an
# account's page reads an inventory, and both are replaced.
cloud.warm_start = lambda: None
cloud.peek = lambda conn, region="": None
cloud.bills_peek = lambda conn, months=12: None
cloud.inventory = lambda conn, refresh=False, region="": {
    "groups": [], "notes": [], "total": 0, "error": "", "region": "r1"}


def signed_in(email: str, areas: list, projects=()):
    uid = auth.create_user(email, "U", "Passw0rd!xY-proj", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, list(projects),
                                      [])])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-proj"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def denied(target: str) -> int:
    return (db.one("SELECT COUNT(*) AS n FROM audit WHERE action = "
                   "'scope_denied' AND target = ?", (target,)) or {"n": 0})["n"]


def main_test() -> int:
    pin = signed_in("config-pinned@test.invalid", ["config"], projects=[P1])
    free = signed_in("config-free@test.invalid", ["config"])

    print("project 2's pages are refused, every method, with an audit line")
    before = denied("project Beta")
    for path in (f"/p/{P2}", f"/p/{P2}/{R2}", f"/p/{P2}/{R2}/dev?stay=1",
                 f"/p/{P2}/{R2}/dev/s/svc-values.yaml/raw.json",
                 f"/p/{P2}/{R2}/dev/new"):
        r = pin.get(path, follow_redirects=False)
        check(f"GET {path} → {r.status_code}", r.status_code == 403)
        check(f"GET {path} does not name the project", "Beta" not in r.text)
    for path in (f"/p/{P2}/{R2}/dev/s/svc-values.yaml/raw/save",
                 f"/p/{P2}/{R2}/dev/s/svc-values.yaml/raw/commit",
                 f"/p/{P2}/{R2}/dev/new"):
        r = pin.post(path, data={"text": "x: 1", "message": "m"},
                     follow_redirects=False)
        check(f"POST {path} → {r.status_code}", r.status_code == 403)
    check("each refusal is audited against the project it reached for",
          denied("project Beta") == before + 8)
    r = pin.get(f"/p/{P2}/{R2}/dev/s/svc-values.yaml/raw.json",
                follow_redirects=False)
    check("the values window's JSON refuses as JSON",
          "outside" in r.json().get("error", ""))

    print("project 1's are not, and an unconfined role opens both")
    for c, who in ((pin, "the pinned role"), (free, "an unconfined role")):
        r = c.get(f"/p/{P1}", follow_redirects=False)
        check(f"{who}: /p/<project 1> → {r.status_code}", r.status_code == 200)
        r = c.get(f"/p/{P1}/{R1}", follow_redirects=False)
        check(f"{who}: its region → {r.status_code}", r.status_code == 200)
    r = free.get(f"/p/{P2}", follow_redirects=False)
    check(f"an unconfined role: /p/<project 2> → {r.status_code}",
          r.status_code == 200)

    print("the sidebar lists the projects that open")
    page = pin.get(f"/p/{P1}").text
    check("project 1 is in the pinned role's sidebar", f'href="/p/{P1}"' in page)
    check("and projects 2 and 3 are not",
          f'href="/p/{P2}"' not in page and f'href="/p/{P3}"' not in page)
    page = free.get(f"/p/{P1}").text
    check("an unconfined role's sidebar has all three",
          all(f'href="/p/{p}"' in page for p in (P1, P2, P3)))
    nocfg = signed_in("no-config@test.invalid", ["clusters"])
    page = nocfg.get("/clusters").text
    check("and a role without Configuration is offered none of them",
          not any(f'href="/p/{p}"' in page for p in (P1, P2, P3)))

    print("the Clouds hub and an account's page follow the project")
    cl = signed_in("clouds-pinned@test.invalid", ["clouds"], projects=[P1])
    hub = cl.get("/clouds", follow_redirects=False)
    check(f"the hub opens ({hub.status_code})", hub.status_code == 200)
    check("and lists project 1's account", "alpha-account" in hub.text)
    check("and not project 2's", "beta-account" not in hub.text)
    # An account belonging to no project is every project's — and so not one a
    # role confined to particular projects was given. The pages below the hub
    # have always ruled that way; the hub now agrees with them.
    check("nor the one shared by every project",
          "shared-account" not in hub.text)
    r = cl.get(f"/clouds?account={ACC2}", follow_redirects=False)
    check(f"project 2's account page → {r.status_code}", r.status_code == 403)
    check("its refusal is audited",
          denied("cloud account beta-account") == 1)
    r = cl.get(f"/clouds?account={ACC0}", follow_redirects=False)
    check(f"the shared account's page → {r.status_code}", r.status_code == 403)
    r = cl.get(f"/clouds?account={ACC1}", follow_redirects=False)
    check(f"project 1's account page → {r.status_code}",
          r.status_code == 200 and "alpha-account" in r.text)
    r = cl.get(f"/clouds/bills?account={ACC2}", follow_redirects=False)
    check(f"and the bills page below it already agreed ({r.status_code})",
          r.status_code == 403)
    wide = signed_in("clouds-free@test.invalid", ["clouds"])
    hub = wide.get("/clouds").text
    check("an unconfined role's hub lists all three",
          all(n in hub for n in ("alpha-account", "beta-account",
                                 "shared-account")))
    none = signed_in("clouds-gamma@test.invalid", ["clouds"], projects=[P3])
    hub = none.get("/clouds").text
    check("a role whose project has no account is told so, not invited to "
          "connect the first one",
          "No cloud account in your projects" in hub
          and "Connect an account" not in hub)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
