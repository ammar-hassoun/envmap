#!/usr/bin/env python3
"""The Overview builds a panel only for somebody whose roles hold its area.

WHY THIS EXISTS
    Every panel was built for every viewer. The Overview is the page everybody
    may open, so whatever a panel showed, everybody saw: the IT spend panel put
    what IT costs in front of people without IT spend, the activity panel put
    the audit log in front of people without the audit log, and the fleet
    panels listed every cluster to a role pinned to one.

    Each panel now names the area that owns its source (`layout.CATALOGUE`'s
    `area`). This asks, as a role holding one area and then as one holding
    another, whether a panel outside it is drawn, offered in the Arrange tray,
    fetchable on its own, or BUILT at all — every source is a spy, because a
    panel that is computed and then not drawn has still read the data. A saved
    layout naming a forbidden panel must simply skip it. And the fleet panels
    must be cut to the clusters a role may open, with their counts recounted,
    because the tiles link to pages that list only those.

    ./.venv/bin/python tests/test_overview_areas.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("overviewareas-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import (assets, auth, db, fleet, history, layout, main,  # noqa: E402
                 rbac, spend, store)

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P1 = store.add_project("Alpha")
P2 = store.add_project("Beta")
A = store.add_cluster(P1, "alpha-one", "apiVersion: v1\n", "ctx-a")
B = store.add_cluster(P2, "beta-one", "apiVersion: v1\n", "ctx-b")

BUILT: list = []


def _health(cid, name, project, pods, bad_pods):
    return {"cid": cid, "pid": P1 if cid == A else P2, "name": name,
            "project": project, "reachable": True,
            "nodes": {"total": 2, "ready": 2},
            "pods": {"total": pods, "running": pods - bad_pods,
                     "bad": bad_pods, "pending": 0},
            "cpu": {"pct": 10, "used": 100, "cap": 1000, "source": "test"},
            "mem": {"pct": 20, "used": 200, "cap": 1000, "source": "test"},
            "error": "", "problems": [], "nodes_ready": 2, "env": None}


SNAP = {"clusters": [_health(A, "alpha-one", "Alpha", 10, 1),
                     _health(B, "beta-one", "Beta", 30, 3)],
        "projects": [{"id": P1, "name": "Alpha", "icon": "", "tagline": "",
                      "regions": 0, "clusters": 1, "envs": 0, "services": 4},
                     {"id": P2, "name": "Beta", "icon": "", "tagline": "",
                      "regions": 0, "clusters": 1, "envs": 0, "services": 6}],
        "at": "now", "stale": False}
SNAP["totals"] = fleet._totals(SNAP["clusters"], SNAP["projects"])


def _fleet(force=False):
    BUILT.append("fleet")
    return SNAP


def _spend():
    BUILT.append("spend")
    return {"subs": 0, "monthly": 0, "yearly": 0, "lapsed": 0, "soon": [],
            "next": None, "base": "USD", "unconverted": []}


def _assets():
    BUILT.append("assets")
    return {"total": 0, "classes": {}, "warranty": {}}


real_read_audit = auth.read_audit


def _audit(limit=250, **kw):
    BUILT.append("activity")
    return real_read_audit(limit, **kw)


fleet.overview = _fleet
spend.stats = _spend
assets.stats = _assets
auth.read_audit = _audit

# Two samples of history, so a trend has something to sum.
history.FILE.write_text(json.dumps([
    {"t": int(time.time()) - 120, "pods": 40, "bad": 4,
     "c": {A: {"pods": 10, "bad": 1}, B: {"pods": 30, "bad": 3}}},
    {"t": int(time.time()) - 60, "pods": 41, "bad": 6,
     "c": {A: {"pods": 11, "bad": 2}, B: {"pods": 30, "bad": 4}}}]))


def signed_in(email: str, areas=(), clusters=(), role="user"):
    uid = auth.create_user(email, "U", "Passw0rd!xY-board", role=role)
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    if areas:
        rbac.set_for_user(uid, [rbac.save("", email, "", list(areas), [],
                                          list(clusters))])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-board"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c, uid


def board(body: str) -> set:
    return set(re.findall(r'<section class="panel[^"]*"\s+data-id="([a-z]+)"',
                          body))


def tray(body: str) -> set:
    return set(re.findall(r'data-add="([a-z]+)"', body))


def main_test() -> int:
    every = ["tiles", "clusters", "projects", "spend", "assets", "activity",
             "repos"]

    print("a role holding IT spend gets the spend panel and nothing else")
    sp, sp_uid = signed_in("spend-only@test.invalid", areas=["spend"])
    layout.save(sp_uid, [{"id": p} for p in every])
    BUILT.clear()
    r = sp.get("/", follow_redirects=False)
    check(f"the Overview opens ({r.status_code})", r.status_code == 200)
    check(f"its saved layout draws only the spend panel ({board(r.text)})",
          board(r.text) == {"spend"})
    check(f"and builds only that panel's data ({BUILT})", BUILT == ["spend"])
    check(f"the Arrange tray offers no panel outside its areas ({tray(r.text)})",
          tray(r.text) == set())
    check("and the saved layout itself is untouched — skipped, not rewritten",
          [p["id"] for p in layout.get(sp_uid)] == every)
    for pid, want in (("spend", 200), ("assets", 403), ("tiles", 403),
                      ("activity", 403)):
        BUILT.clear()
        r = sp.get(f"/overview/panel/{pid}", follow_redirects=False)
        check(f"/overview/panel/{pid} → {r.status_code}", r.status_code == want)
        if want == 403:
            check(f"and {pid} was not built ({BUILT})", BUILT == [])

    print("a role without IT spend never sees what IT costs")
    cl, cl_uid = signed_in("clusters-only@test.invalid", areas=["clusters"])
    layout.save(cl_uid, [{"id": "spend"}, {"id": "tiles"}, {"id": "activity"}])
    BUILT.clear()
    r = cl.get("/", follow_redirects=False)
    check(f"the spend and activity panels are skipped ({board(r.text)})",
          board(r.text) == {"tiles"})
    check(f"and neither was built ({BUILT})",
          "spend" not in BUILT and "activity" not in BUILT)
    check(f"the tray offers the fleet panels and nothing else ({tray(r.text)})",
          tray(r.text) == {"health", "clusters"})
    r = cl.get("/overview/panel/spend", follow_redirects=False)
    check(f"and the spend panel cannot be fetched by hand ({r.status_code})",
          r.status_code == 403 and "IT spend" in r.text)

    print("the fleet panels are cut to the clusters a role may open")
    pin, pin_uid = signed_in("board-pinned@test.invalid",
                             areas=["clusters"], clusters=[A])
    layout.save(pin_uid, [{"id": "tiles"}, {"id": "clusters"},
                          {"id": "health"}])
    r = pin.get("/", follow_redirects=False)
    check("the cluster cards show A", "alpha-one" in r.text)
    check("and not B, anywhere on the page",
          "beta-one" not in r.text and B not in r.text)
    data = main._board_data({"fleet", "trend", "agg"}, auth.by_id(pin_uid))
    t = data["fleet"]["totals"]
    check(f"the tiles count A alone ({t['clusters']} clusters, {t['pods']} pods)",
          t["clusters"] == 1 and t["pods"] == 10 and t["pods_bad"] == 1)
    check("the trend sums A's history, not the fleet's",
          data["trend"]["bad"] == [1, 2] and data["trend"]["pods"] == [10, 11])
    check("the pooled usage is A's",
          data["agg"]["cpu"]["cap"] == 1000)
    check("and the shared snapshot was not edited by any of it",
          len(SNAP["clusters"]) == 2 and SNAP["totals"]["clusters"] == 2)
    admin = auth.by_id(signed_in("board-admin@test.invalid", role="admin")[1])
    data = main._board_data({"fleet", "trend"}, admin)
    check("an administrator's fleet is the whole fleet",
          data["fleet"]["totals"]["clusters"] == 2
          and data["trend"]["bad"] == [4, 6])
    check("and the per-cluster sum over every cluster IS the fleet series",
          history.series_over({A, B}, "bad") == history.series("", "bad"))
    check("nobody given sees nothing — never the whole estate",
          main._board_data({"fleet"})["fleet"]["clusters"] == [])

    print("the projects panel follows Configuration's projects")
    cfg, cfg_uid = signed_in("board-config@test.invalid", areas=["config"])
    db.run("UPDATE roles SET projects = ? WHERE name = ?",
           (json.dumps([P1]), "board-config@test.invalid"))
    layout.save(cfg_uid, [{"id": "projects"}])
    r = cfg.get("/", follow_redirects=False)
    check(f"it draws the projects panel ({board(r.text)})",
          board(r.text) == {"projects"})
    check("with the project the role names", f'href="/p/{P1}"' in r.text)
    check("and not the other", f'href="/p/{P2}"' not in r.text)

    print("the panel catalogue says whose each panel is")
    for pid, meta in layout.CATALOGUE.items():
        check(f"{pid} names an area that exists ({meta.get('area')})",
              meta.get("area") in rbac.AREAS)
    check("the activity panel is the audit log's, and links there",
          layout.CATALOGUE["activity"]["area"] == "audit"
          and 'href="/admin/audit"' in (pathlib.Path(main.BASE) / "templates"
                                        / "panels" / "activity.html").read_text())
    check("IT spend's is IT spend's", layout.CATALOGUE["spend"]["area"] == "spend")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
