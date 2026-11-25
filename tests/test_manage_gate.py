#!/usr/bin/env python3
"""Changing a cluster needs the Cluster management area, on every route.

WHY THIS EXISTS
    Two separate things have to be true before the portal runs kubectl against
    somebody's cluster: the CLUSTER allows management (its "allow management"
    tick), and the PERSON holds the Cluster management area. The first is a
    property of the cluster and the second of the role, and only the second
    answers "may this user".

    Two routes checked the first and not the second. Everything under /clusters
    is governed by the *read* area, so a role with cluster read access — the
    obvious role to hand an on-call engineer who should only look — could POST
    a rolling restart, a scale, a rollback or a pod deletion to any cluster with
    the tick on, and could run kubectl through the console. Neither route looked
    at the area that exists for precisely this; rbac.AREAS spells it out:

        "manage": "running kubectl and the fixed actions — separate from
                   reading, because it changes things"

    The terminal socket had it right, and its own docstring says why the others
    did not: "Writing the checks out a second time is how one of them ends up
    missing." So this does not test the two routes that were wrong — it finds
    every route that can reach kubectl and holds all of them to it, including
    ones written after this.

    ./.venv/bin/python tests/test_manage_gate.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
import urllib.parse
import uuid

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("managegate-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, store                          # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0

# What "can change a cluster" means, in terms a source scan can see.
REACHES_KUBECTL = ("kmanage.act", "kmanage.run", "kmanage.pty_open",
                   "kmanage.netshoot", "kmanage.complete_in_pod")
# The three ways a handler is allowed to establish the area.
GATES = ('_may(request, "manage")', "_cluster_for(", "_ws_user(")


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def handlers() -> list:
    """(name, decorator line, body) for every route in main.py."""
    src = (ROOT / "app" / "main.py").read_text()
    out = []
    # split on decorators so each handler carries its own body
    parts = re.split(r"\n(?=@app\.(?:get|post|put|delete|websocket)\()", src)
    for part in parts[1:]:
        head = part.split("\n", 1)[0]
        name = re.search(r"\n\s*(?:async\s+)?def\s+(\w+)", part)
        # stop at the next decorator, which split() already did
        out.append((name.group(1) if name else "?", head, part))
    return out


def main_test() -> int:
    print("every route that can reach kubectl asks for the area")
    checked = 0
    for name, head, body in handlers():
        if not any(fn in body for fn in REACHES_KUBECTL):
            continue
        checked += 1
        check(f"{name} ({head.strip()[:46]}) establishes Cluster management",
              any(g in body for g in GATES))
    check(f"and there were routes to check ({checked})", checked >= 4)

    print("and it is the role that decides, not only the cluster's own tick")
    pid = store.add_project("Gate")
    cid = store.add_cluster(pid, "c1", "apiVersion: v1\n", "ctx1")
    store.update_cluster(pid, cid, manage="1")     # the cluster allows it

    def signed_in(email: str, areas: list):
        uid = auth.create_user(email, "U", "Passw0rd!xY", role="user")
        db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
               ("TESTSECRET", uid))
        rid = "r-" + uuid.uuid4().hex[:8]
        db.run("INSERT INTO roles (id, name, note, areas, projects, clusters, "
               "created) VALUES (?,?,?,?,?,?,?)",
               (rid, email, "", json.dumps(areas), "[]", "[]", "2026-01-01"))
        db.run("INSERT INTO user_roles (user_id, role_id) VALUES (?,?)",
               (uid, rid))
        c = TestClient(main.app, raise_server_exceptions=False)
        c.post("/login", data={"email": email, "password": "Passw0rd!xY"},
               follow_redirects=False)
        u = auth.by_email(email)
        c.post("/mfa", data={"code": auth._totp_at(
            u["totp_secret"], int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        return c

    reader = signed_in("gate-reader@test.invalid", ["clusters"])
    with reader:
        # It must be refused for being the wrong ROLE. kubectl would also fail
        # here (the context is fake), so the reason is what is asserted — a test
        # that only checked "did not succeed" would have passed before the fix.
        r = reader.post("/clusters/action",
                        data={"project": pid, "cluster": cid, "action": "restart",
                              "kind": "deployment", "namespace": "default",
                              "name": "web"}, follow_redirects=False)
        why = urllib.parse.unquote(r.headers.get("location") or "")
        check(f"a cluster READER is refused the action by role ({why[-60:]})",
              "do not include Cluster management" in why)
        sh = reader.post("/clusters/shell/run",
                         data={"project": pid, "cluster": cid, "cmd": "get pods"},
                         follow_redirects=False)
        check(f"and the console too ({sh.status_code})",
              sh.status_code == 403
              and "Cluster management" in sh.json().get("refused", ""))

    ops = signed_in("gate-ops@test.invalid", ["clusters", "manage"])
    with ops:
        # And the gate is not simply refusing everybody: someone who holds the
        # area gets through to kubectl, which then fails on the fake context.
        r = ops.post("/clusters/action",
                     data={"project": pid, "cluster": cid, "action": "restart",
                           "kind": "deployment", "namespace": "default",
                           "name": "web"}, follow_redirects=False)
        why = urllib.parse.unquote(r.headers.get("location") or "")
        check(f"somebody holding it reaches kubectl ({why[-46:]})",
              "do not include Cluster management" not in why)

    print("a cluster serving production wants its name typed first")
    # The second gate, and the one with no coverage at all until now. It was
    # written out six times — the kubectl console, its JSON twin, the user form,
    # the token minter, propose() and execute() — each with its own wording and
    # its own chance to compare the wrong pair of strings. It is now one
    # function, and this is what holds it up.
    from app import aitools                                    # noqa: E402
    rgid = store.add_region(pid, "R")
    prod_cid = store.add_cluster(pid, "live", "apiVersion: v1\n", "ctx2")
    store.update_cluster(pid, prod_cid, manage="1")
    store.map_env_cluster(pid, rgid, "prod", prod_cid)
    prod = store.get_cluster(pid, prod_cid) or {}
    dev = store.get_cluster(pid, cid) or {}

    check("a cluster with a production environment mapped to it is production",
          aitools.is_prod(pid, prod_cid) is True)
    check("and one with nothing mapped is not", aitools.is_prod(pid, cid) is False)
    # A cluster nobody has called production waves everything through: demanding
    # a typed name for a dev cluster trains people to type it without reading.
    check("so a dev cluster asks for nothing",
          aitools.confirm_prod(pid, cid, dev, "") == "")
    refused = aitools.confirm_prod(pid, prod_cid, prod, "")
    check(f"a production one refuses an empty confirmation ({refused[:38]}…)",
          refused != "" and "live" in refused)
    check("and refuses the wrong name",
          aitools.confirm_prod(pid, prod_cid, prod, "libe") != "")
    # Whitespace is not a different answer — somebody who copies the name out of
    # the page brings a space with it, and refusing that teaches nothing.
    check("accepts the right name",
          aitools.confirm_prod(pid, prod_cid, prod, "live") == "")
    check("and the right name with stray whitespace",
          aitools.confirm_prod(pid, prod_cid, prod, "  live ") == "")
    # The gate must not be case-blind: a cluster named `Live` and one named
    # `live` are two different clusters, and the whole point is knowing which.
    check("a near miss in case is still a miss",
          aitools.confirm_prod(pid, prod_cid, prod, "LIVE") != "")

    with ops:
        # And through a route, so the helper being right cannot hide a caller
        # that forgot to consult it.
        r = ops.post("/clusters/shell/run",
                     data={"project": pid, "cluster": prod_cid,
                           "cmd": "delete pod web --namespace default"},
                     follow_redirects=False)
        said = json.dumps(r.json())
        check(f"the console refuses a write on production unnamed "
              f"({r.status_code})", "serves production" in said)
        r2 = ops.post("/clusters/shell/run",
                      data={"project": pid, "cluster": prod_cid,
                            "cmd": "get pods", "confirm": ""},
                      follow_redirects=False)
        # A read is not a change, so it must not be gated — an SRE looking at a
        # production cluster at 02:00 should not have to type its name to look.
        check("but not a read", "serves production" not in json.dumps(r2.json()))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
