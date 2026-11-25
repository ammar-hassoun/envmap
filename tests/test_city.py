#!/usr/bin/env python3
"""The city: every cluster as a building on a street (app/city.py,
static/cluster3d-city.js).

WHY THIS EXISTS
    A street is looked at from a distance and believed. A building that is
    lit and quiet says "this cluster is fine" to somebody who never walks up
    to it, so what must hold is what would otherwise draw the same calm
    building for four different truths:

      1. **Not read yet is not healthy.** After a restart the fleet snapshot
         holds no cluster. Every cluster is still in the city, marked
         `reading`, with no counts at all.
      2. **Did not answer is not empty.** An unreachable cluster carries no
         pod count (None, never zero) and says why.
      3. **A cluster outside the role is not in the city**: not as a building,
         not in a total, not as a district.
      4. **The street never says more than the cluster did.** A red window
         means a failing pod and there is at least one whenever any fails; no
         window is lit in a building nobody could ask; the board says "all is
         well" only when every cluster answered and is; fireworks the same.
      5. **The city asks no cluster anything and changes nothing.** It is the
         database and the snapshot, and its script sends one GET.
      6. **A door leads into the cluster and back out**, and coming in by a
         door does not change what the 3D view is for anybody else.

    ./.venv/bin/python tests/test_city.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("city-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, city, db, fleet, main, rbac, store       # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0
LONG = "Unable to connect to the server: " + "x" * 400


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def signed_in(email: str, areas: list, clusters=()):
    uid = auth.create_user(email, "U", "Passw0rd!xY-city", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], list(clusters))])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-city"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)
    return c


def row(pid, cid, name, reachable=True, nodes=(3, 3), pods=(40, 0), problems=(), error=""):
    return {"pid": pid, "cid": cid, "name": name, "project": "", "reachable": reachable, "error": error,
            "nodes": {"total": nodes[0], "ready": nodes[1]},
            "pods": {"total": pods[0], "running": pods[0] - pods[1], "bad": pods[1], "pending": 0},
            "cpu": {"pct": 12.5}, "mem": {"pct": 40.0}, "used_by": [{"label": "KE/dev", "url": "/x"}],
            "problems": [{"name": n, "namespace": "ns", "status": s, "restarts": r} for n, s, r in problems]}


def test_data() -> dict:
    print("what the street knows of a cluster")
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"}, None, False)
    check("a cluster nobody has read is being read, with no counts at all",
          b["state"] == "reading" and b["pods"] is None and b["nodes"] is None and b["problems"] == [])
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"}, row("p", "c", "one", reachable=False, error=LONG), False)
    check("one that did not answer is down, with no pod count and its reason, cut to a line",
          b["state"] == "down" and b["pods"] is None and b["why"].startswith("Unable to connect") and len(b["why"]) == city.WHY_CHARS)
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"}, row("p", "c", "one", reachable=False), False)
    check("with no reason given, it still says it did not answer", b["why"] == "it did not answer")
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"}, row("p", "c", "one"), True)
    check("one that answered and is well is ok, with its counts and what it serves",
          b["state"] == "ok" and b["pods"] == {"total": 40, "bad": 0, "pending": 0} and b["nodes"] == {"total": 3, "ready": 3}
          and b["serves"] == ["KE/dev"] and b["prod"] is True and b["cpu"] == 12.5 and b["mem"] == 40.0)
    check("a meter says whether its figure was measured or is only what the pods asked for",
          b["cpu_src"] == "" and city.building("p", {"name": "P"}, "c", {"name": "one"},
                                               {**row("p", "c", "one"), "cpu": {"pct": 9.0, "source": "requests"}}, False)["cpu_src"] == "requests")
    quiet = city.building("p", {"name": "P"}, "c", {"name": "one"}, row("p", "c", "one", reachable=False), False)
    check("a cluster that did not answer, or is unread, has no figure for a meter: none, never nought",
          quiet["cpu"] is None and quiet["mem"] is None
          and city.building("p", {"name": "P"}, "c", {"name": "one"}, None, False)["cpu"] is None)
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"},
                      row("p", "c", "one", pods=(40, 9), problems=[(f"pod-{i}", "CrashLoopBackOff", i) for i in range(9)]), False)
    check("failing pods make it bad, and the crowd it can name is capped",
          b["state"] == "bad" and b["pods"]["bad"] == 9 and len(b["problems"]) == city.PROBLEMS
          and b["problems"][0] == {"name": "pod-0", "ns": "ns", "status": "CrashLoopBackOff", "restarts": 0})
    b = city.building("p", {"name": "Proj"}, "c", {"name": "one"}, row("p", "c", "one", nodes=(4, 3)), False)
    check("a machine that is not ready makes it bad with every pod running", b["state"] == "bad" and b["pods"]["bad"] == 0)

    print("who is in the city")
    pa = store.add_project("Alpha", icon="x")
    pb = store.add_project("Beta", icon="x")
    a1 = store.add_cluster(pa, "a-one", "apiVersion: v1\nkind: Config\n", "a-one")
    a2 = store.add_cluster(pa, "a-two", "apiVersion: v1\nkind: Config\n", "a-two")
    b1 = store.add_cluster(pb, "b-one", "apiVersion: v1\nkind: Config\n", "b-one")
    b2 = store.add_cluster(pb, "b-two", "apiVersion: v1\nkind: Config\n", "b-two")
    snap = {"clusters": [], "at": "10:00:00", "stale": True, "pending": True}
    asked = []
    fleet.overview = lambda force=False: (asked.append(force), snap)[1]
    boss = signed_in("boss@test.invalid", ["clusters"])
    # from here until the snapshot checks are done, any command run is the city asking a cluster something
    really_run, ran = subprocess.run, []
    subprocess.run = lambda *a, **k: (ran.append(a), really_run(*a, **k))[1]
    got = boss.get("/clusters/city.json").json()
    check("before the snapshot has read anything, every cluster is in the city and being read",
          [x["state"] for x in got["buildings"]] == ["reading"] * 4 and got["totals"]["reading"] == 4
          and got["totals"]["pods"] == 0 and got["totals"]["ok"] == 0 and got["stale"] is True)
    check("districts are the projects, in name order, with how many clusters each holds",
          [(d["name"], d["clusters"]) for d in got["districts"]] == [("Alpha", 2), ("Beta", 2)]
          and [x["name"] for x in got["buildings"]] == ["a-one", "a-two", "b-one", "b-two"])
    snap = {"clusters": [row(pa, a1, "a-one", pods=(50, 3), problems=[("web-1", "CrashLoopBackOff", 7)]),
                         row(pa, a2, "a-two", reachable=False, error="timeout"),
                         row(pb, b1, "b-one", pods=(20, 0))], "at": "10:00:30", "stale": False}
    got = boss.get("/clusters/city.json").json()
    states = {x["name"]: x["state"] for x in got["buildings"]}
    check("then each is what it answered, and one the snapshot still lacks is still being read",
          states == {"a-one": "bad", "a-two": "down", "b-one": "ok", "b-two": "reading"})
    check("the totals count pods only where a cluster answered, and say how many did not",
          got["totals"] == {"clusters": 4, "reading": 1, "down": 1, "bad": 1, "ok": 1, "pods": 70, "pods_bad": 3, "nodes": 6})
    check("the snapshot is never forced: a street does not make the reader wait for the clusters", asked and not any(asked))
    subprocess.run = really_run
    check("and nothing was run to answer: the city is the database and the snapshot", not ran)

    print("who may walk it")
    mine = signed_in("narrow@test.invalid", ["clusters"], clusters=[b1])
    got2 = mine.get("/clusters/city.json").json()
    check("a role confined to one cluster has a city of one building, one district, and its totals",
          [x["cid"] for x in got2["buildings"]] == [b1] and [d["name"] for d in got2["districts"]] == ["Beta"]
          and got2["districts"][0]["clusters"] == 1 and got2["totals"]["clusters"] == 1 and got2["totals"]["pods"] == 20
          and "a-one" not in json.dumps(got2))
    other = signed_in("nocluster@test.invalid", ["certs"])
    check("a role without the clusters area gets neither the page nor the data",
          other.get("/clusters/city", follow_redirects=False).status_code in (303, 403)
          and "a-one" not in other.get("/clusters/city.json", follow_redirects=False).text)
    anon = TestClient(main.app, raise_server_exceptions=False)
    check("signed out, both are a sign-in", anon.get("/clusters/city", follow_redirects=False).status_code in (302, 303)
          and anon.get("/clusters/city.json", follow_redirects=False).status_code in (302, 303, 401))

    print("the page")
    page = boss.get("/clusters/city")
    check("the page is the stage, marked as the city, and holds no cluster: the street is fetched",
          page.status_code == 200 and 'data-city=""' in page.text and 'data-json="/clusters/city.json"' in page.text
          and '<body class="bare"' in page.text and "a-one" not in page.text)
    check("it loads what the experts know, then the city, then the engine that hands it the stage, each with the page's nonce",
          page.text.index("/static/cluster3d-quiz.js") < page.text.index("/static/cluster3d-city.js") < page.text.index("/static/cluster3d.js?")
          and page.text.count('nonce="') >= 4 and "<script src=" not in page.text)
    check("the sign in the square carries the installation's own name, and the product's where nobody renamed it",
          'data-love="EnvMap"' in page.text)
    check("it keeps every element the engine finds by id",
          all(f'id="{i}"' in page.text for i in ("c3dCanvas", "c3dOver", "c3dWalk", "c3dSearch", "c3dTalk", "c3dSay",
                                                 "c3dPick", "c3dChat", "c3dHint", "c3dVeil", "c3dTotals", "c3dLive", "c3dBack")))
    check("coming back out of a building names it, and only an id's own shape is taken",
          f'data-city="{a1}"' in boss.get(f"/clusters/city?at={a1}").text
          and 'data-city=""' in boss.get('/clusters/city?at="><script>alert(1)</script>').text)
    one = boss.get(f"/clusters/3d?project={pa}&cluster={a1}")
    check("a cluster's own 3D view is not the city, and does not load its script",
          one.status_code == 200 and "data-city" not in one.text and "cluster3d-city.js" not in one.text
          and f"/clusters/3d.json?project={pa}" in one.text)
    return got


def test_hub() -> None:
    print("the way in")
    src = (ROOT / "templates" / "clusters.html").read_text()
    hub = src[src.index("{% if stage == 'hub' %}\n{%- set cur"):src.index("{% elif stage == 'project' %}")]
    check("the Clusters page, which stands over every cluster, has the way in, and only where there is a cluster",
          '{% if cards %}<a class="btn" href="/clusters/city"' in hub and "Enter the city" in hub
          and hub.index('href="/clusters/city"') < hub.index('href="/settings/clusters"'))
    check("and nowhere below it: one cluster's page offers its own view",
          src.count('href="/clusters/city"') == 1)


def test_script(got: dict) -> None:
    print("the street's script")
    src = (ROOT / "static" / "cluster3d-city.js").read_text()
    eng = (ROOT / "static" / "cluster3d.js").read_text()
    css_text = (ROOT / "static" / "cluster3d.css").read_text()
    check("it sends one request, a read of the city, and nothing else",
          src.count("fetch(") == 1 and "fetch(stage.getAttribute('data-json')" in src and "POST" not in src
          and "method:" not in src and "XMLHttpRequest" not in src and "sendBeacon" not in src)
    check("a door leads into that cluster's own view, marked as come from the street",
          "location.href = '/clusters/3d?project=' + encodeURIComponent(L.b.pid) + '&cluster=' + encodeURIComponent(L.cid) + '&from=city';" in src)
    check("walking in at the door is going in, and so is E",
          "if (dz > 0 && Math.abs(dx) < 1.0 && vz < -0.5 && you.moving) { enter(L); return; }" in src
          and "else if ((k === 'e' || k === 'f' || k === 'Enter') && !e.repeat && near && !chat) enter(near);" in src)
    check("no pod is drawn on a building nobody could ask or has read",
          "if (far > 100 || st === 'down' || st === 'reading' || !b.pods) return;" in src
          and src.index("if (far > 100 || st === 'down' || st === 'reading' || !b.pods) return;") < src.index("wn = windows(b, c * live * 4);"))
    # A building has to be known for a Kubernetes cluster at a glance, and read
    # from across the city: it was a plain tower with a sign nobody could read
    # from far, and whose figures hung over the pods speaking at its door.
    check("a building is a cluster's own shape: a control-plane base, a deck per machine, pods on the decks, and the helm of seven spokes on its roof",
          "for (i = 0; i < 7; i++) { a = a0 + i * TAU / 7;" in src and "for (i = 0; i < L.decks; i++) {" in src
          and "dead = L.dark && i >= L.decks - L.dark;" in src and "live = Math.max(1, L.decks - L.dark);" in src
          and "helm(x, cy, z, R, Math.atan2(e[0] - x, e[2] - z), calm || st === 'down' ? 0 :" in src)
    check("a name stands on every roof, never too small to read, on a board that windows cannot show through",
          "{ own: L, accent: c, far: ROOFS_FAR, size: 13, scale: 0.5, min: 12, solid: true }" in src
          and "size = Math.max(o.min || 0, (o.size || 12) * k);" in src and "if (o.solid) { g.globalAlpha = 1; g.fillStyle = 'rgba(5,7,11,.95)';" in src)
    check("a building's figures are on the card at its door, not hung over the pods speaking there",
          "if (beside && !trip && !going) card(beside.b, near === beside, W, H);" in src and "K.ink('KUBERNETES CLUSTER'," in src
          and "L.dz + 0.6, lines" not in src and "if (!m.well && !crowdSay) {" in src)
    check("the crowd speaks only for pods the portal named, and nobody stands outside a silent building",
          "if (b.state === 'bad') b.problems.slice(0, CROWD).forEach(" in src and "else if (b.state === 'ok') L.crowd.push(" in src)
    # A street that says everything at once says nothing: it was built that way
    # first, and read as "crowded and messy". What is written is capped, and a
    # building speaks for itself only to somebody standing at it.
    check("only so many roofs are named at once, and only three of a crowd stand outside",
          "var ROOFS = 8, ROOFS_FAR = 190, CROWD = 3, BESIDE = 11;" in src and "close.slice(0, ROOFS).forEach(function (o) {" in src)
    check("a packet carries no label, one trace runs each street, and only the last thing that happened is said",
          "'0x' + o.hex" not in src and src.count("K.beam(sx, 0.05, z0, sx, 0.05, z1,") == 1 and "for (k = -1; k <= 1; k++) K.beam(" not in src
          and "n = notes[notes.length - 1];" in src and "FIRST CALL" not in src)
    check("fireworks only when every cluster answered and every pod is well",
          "if (!calm && tt.clusters && !tt.bad && !tt.down && !tt.reading) for (" in src)
    check("the ambulance goes to failing pods, and stands unlit at the gate with none",
          "list = needy(data.buildings).filter(function (b) { return b.pods.bad; }), want = list.length ? list[0].cid : ''" in src
          and "amb.lit = !!want;" in src)
    # The city is the inside of a machine. What moves on it is scenery and
    # must stay scenery: only the meters, the load board and the gears carry
    # a figure, and each only where a cluster gave one.
    check("nothing on the street is a car any more, and what runs the traces claims nothing about a cluster",
          "function car(" not in src and "cars" not in src and "function packets(t, dt)" in src and "function traces(t)" in src
          and "They are scenery" in src and "Nobody\n   measured that traffic" in src)
    check("a meter stands only where the cluster gave a figure, and so does a column on the load board",
          "if (b.cpu == null && b.mem == null) return;" in src and "v = i ? b.mem : b.cpu; if (v == null) continue;" in src
          and "if (b.cpu == null) { box(x, 0.4, z, gap * 0.5, 0.3, 0.5, DOWNC); return; }" in src)
    check("the gears turn with the city's CPU, and stand still when no cluster has said",
          "spin = busy0 == null || calm ? 0 : t * (0.25 + busy0 / 100 * 2.6)" in src and "busy0 = load(bs);" in src)
    check("a meter that is only what the pods asked for says so",
          "K.ink((i ? 'RAM' : 'CPU') + (b.cpu_src === 'live' ? '' : ' ASKED')," in src)
    check("signs that would land on one another are left out, nearest first",
          "signs.sort(function (a, b) { return a.depth - b.depth; });" in src and "if (hit || (!o.must && y0 < 66)) continue;" in src
          and "if (L.sig !== s) { L.sig = s; L.crowd = null; }" in src)
    check("the engine hands the stage to the city and keeps its own hands off the street",
          "if (city) { if (cityHook.click) cityHook.click(); return; }" in eng and "if (walk || city) return;      // the keys belong to your feet" in eng
          and "if (!document.hidden && !city) poll(false);" in eng and "window.C3DCity({ stage: stage," in eng
          and eng.index("if (city) {\n    // The street takes the stage") < eng.index("resize(); legend(); poll(false); requestAnimationFrame(frame);"))
    check("a cluster entered by a door starts in its walk once, and leaving the walk is leaving by the door",
          "if (fromCity && !cameIn) { cameIn = true; enterWalk(); pickClose(); }" in eng
          and "if (fromCity) toStreet();" in eng
          and "function toStreet() { location.href = '/clusters/city?at=' + encodeURIComponent(QS.get('cluster') || ''); }" in eng
          and "var fromCity = !city && VIA.get('from') === 'city'" in eng)
    # You choose who you are the same way wherever you come in: the city opens
    # the cluster's own chooser, not a second one that could drift from it.
    check("the chooser is one, opened by a cluster and by the city alike",
          "function pickAt(x, y, z, first, host) {" in eng and eng.count("function pickScene(") == 1 and eng.count("function pickDraw(") == 1
          and "pick: { open: pickAt, close: pickClose, key: pickKey, aim: pickAim, scene: pickScene, on: function () { return picking; } }" in eng
          and "goal.pitch = pk.pitch; pk.host.done(pk.first);" in eng and "else if (k === 'Escape') { pk.host.quit(); return; }" in eng
          and "pickAt(walk.x, 12, walk.z, first, { quit: leaveWalk, done: function (was) {" in eng)
    check("the city opens it when you arrive from the Clusters page, not when you step back out of a building, and again on P",
          "if (!L) choose(true); else you.riding = me.ride > 0;" in src and "else if (k === 'p' && !e.repeat) choose(false);" in src
          and "K.pick.open(you.x, 12, you.z, first, {" in src and "function pickScene" not in src and "c3dPick" not in src)
    check("while you choose, the street takes no steps, no keys and no clicks, and the chooser has the screen to itself",
          "if (going || K.pick.on()) { you.moving = false; you.v = 0; return; }" in src
          and "if (K.pick.on()) { K.pick.key(k); e.preventDefault(); return; }" in src
          and src.index("if (K.pick.on()) { K.pick.key(k); e.preventDefault(); return; }") < src.index("if ((k === 'e' || k === 'f' || k === 'Enter') && !e.repeat && who && !chat) chatOpen(who);")
          and "hook.click = function () { if (K.pick.on() || chat) return;" in src and "if (!K.pick.on()) { names(t); written(); hud(t); }" in src
          and ".c3d.city .c3d-pick" not in css_text)
    check("the city and a cluster are drawn by one call, so they cannot disagree about a row of numbers",
          eng.count("gpu.draw(") == 1 and "paint(t, { span: fit, mood: moodNow," in eng and "K.paint(t, {" in src)
    css = (ROOT / "static" / "cluster3d.css").read_text()
    check("what belongs to one cluster's inside is put away on the street", ".c3d.city .c3d-tools, .c3d.city .c3d-side" in css)

    node = shutil.which("node")
    if not node:
        print("  (node is not installed: the plan checks were skipped)")
        return
    probe = r"""
const m = require(process.argv[1]);
const mk = (pid, cid, st, pods, bad, nodes, ready, probs) => ({pid, cid, name: cid, state: st, prod: false, why: st === 'down' ? 'timeout' : '',
  pods: pods == null ? null : {total: pods, bad, pending: 0}, nodes: pods == null ? null : {total: nodes, ready}, problems: probs || []});
const out = {plans: {}};
for (const n of [1, 2, 5, 12, 24, 40]) {
  const sizes = n === 12 ? [3, 3, 3, 3] : n === 24 ? [9, 1, 6, 8] : n === 40 ? [40] : [n];
  const d = {districts: sizes.map((s, i) => ({pid: 'p' + i, name: 'P' + i, clusters: s})), buildings: []};
  sizes.forEach((s, i) => { for (let k = 0; k < s; k++) d.buildings.push(mk('p' + i, 'p' + i + '-c' + k, 'ok', 10 + k * 30, 0, 1 + k % 9, 1 + k % 9)); });
  const P = m.plan(d), spots = new Set(P.lots.concat(P.parks).map(o => o.x + ',' + o.z));
  let fits = true, order = true, streets = true, last = '', seen = new Set();
  P.lots.forEach(L => {
    if (L.w > m.LOT - 4 || Math.abs(L.dz - (L.bz + L.w / 2)) > 1e-9 || L.dz > L.z + m.LOT / 2) fits = false;
    if (Math.abs(L.sz - (L.z + m.LOT / 2 + m.ROAD / 2)) > 1e-9) streets = false;
    if (L.b.pid !== last) { if (seen.has(L.b.pid)) order = false; seen.add(L.b.pid); last = L.b.pid; }      // by the building's own project, not the label the plan gave it
  });
  const mine = new Set(P.lots.map(L => L.cid));
  out.plans[n] = { lots: mine.size === d.buildings.length && d.buildings.every(b => mine.has(b.cid)) ? P.lots.length : -1, distinct: spots.size, cells: P.lots.length + P.parks.length, grid: P.cols * P.rows, fits, order, streets,
    gate: P.gate.z > Math.max(...P.lots.map(L => L.z)) + m.LOT / 2 + m.ROAD, heads: P.heads.length, cols: P.cols, rows: P.rows, parks: P.parks.length,
    xs: P.xs.length === P.cols + 1, zs: P.zs.length === P.rows + 1 };
}
out.shape = [m.shape(mk('p', 'a', 'reading', null)), m.shape(mk('p', 'a', 'down', null)), m.shape(mk('p', 'a', 'ok', 4, 0, 1, 1)), m.shape(mk('p', 'a', 'ok', 900, 0, 30, 30)),
  m.shape(mk('p', 'a', 'ok', 60, 0, 5, 5)), m.shape(mk('p', 'a', 'bad', 60, 0, 5, 4)), m.shape(mk('p', 'a', 'bad', 60, 0, 40, 39)), m.shape(mk('p', 'a', 'bad', 60, 0, 3, 0)), m.DECKS];
out.win = { none: m.windows(mk('p', 'a', 'ok', 40, 0, 3, 3), 120), one: m.windows(mk('p', 'a', 'bad', 400, 1, 3, 3), 60), many: m.windows(mk('p', 'a', 'bad', 40, 39, 3, 3), 120),
  all: m.windows(mk('p', 'a', 'bad', 5, 5, 3, 3), 120), down: m.windows(mk('p', 'a', 'down', null), 120), reading: m.windows(mk('p', 'a', 'reading', null), 120),
  empty: m.windows(mk('p', 'a', 'ok', 0, 0, 3, 3), 120), noroom: m.windows(mk('p', 'a', 'bad', 40, 3, 3, 3), 0) };
const mixed = [mk('p', 'well', 'ok', 40, 0, 3, 3), mk('p', 'worse', 'bad', 90, 7, 5, 5, [{name: 'web-1', ns: 'shop', status: 'CrashLoopBackOff', restarts: 41}]),
  mk('p', 'storm', 'bad', 30, 0, 4, 3), mk('p', 'sick', 'bad', 20, 2, 2, 2, [{name: 'db-0', ns: 'data', status: 'Pending', restarts: 0}])];
out.needy = m.needy(mixed).map(b => b.name);
out.news = { mixed: m.headlines({buildings: mixed}), well: m.headlines({buildings: [mixed[0], mk('p', 'b', 'ok', 5, 0, 1, 1)]}),
  unread: m.headlines({buildings: [mixed[0], mk('p', 'late', 'reading', null)]}), silent: m.headlines({buildings: [mixed[0], mk('p', 'gone', 'down', null)]}),
  none: m.headlines({buildings: []}), live: m.headlines(JSON.parse(require('fs').readFileSync(0, 'utf8'))) };
out.load = [m.load([]), m.load([mk('p', 'a', 'down', null)]), m.load([{cpu: 20}, {cpu: 60}, {cpu: null}]), m.load([{cpu: 0}]), m.level(0), m.level(69.9), m.level(70), m.level(90), m.level(100)];
out.shout = [m.placard({status: 'OOMKilled'}), m.placard({status: 'SomethingNew'}), m.placard({status: ''}), m.plea({name: 'db-0', ns: 'data', status: 'Pending', restarts: 0}),
  m.plea({name: 'web-1', ns: 'shop', status: 'CrashLoopBackOff', restarts: 1})];
console.log(JSON.stringify(out));
"""
    r = subprocess.run([node, "-e", probe, str(ROOT / "static" / "cluster3d-city.js")],
                       input=json.dumps(got), capture_output=True, text=True, timeout=60)
    check(f"the plan runs under node ({r.stderr[:300]})", r.returncode == 0)
    if r.returncode:
        return
    out = json.loads(r.stdout)
    for n, o in out["plans"].items():
        check(f"[{n} clusters] every cluster has a lot of its own on the grid, and a lot with no cluster is a park",
              o["lots"] == int(n) and o["distinct"] == o["cells"] == o["grid"])
        check(f"[{n} clusters] a building stands inside its lot with its door on the street side, and its street is the one in front",
              o["fits"] and o["streets"] and o["xs"] and o["zs"])
        check(f"[{n} clusters] a district's buildings stand together, and the gate is south of them all", o["order"] and o["gate"])
    check("a city is about as deep as it is wide, and does not leave half of itself to parks",
          out["plans"]["12"]["parks"] == 0 and out["plans"]["24"]["parks"] <= 6 and 3 <= out["plans"]["40"]["cols"] <= 8
          and out["plans"]["40"]["rows"] <= 8 and out["plans"]["1"]["lots"] == 1)
    sh = out["shape"]
    check("a cluster nobody counted is three bare decks, with none of them dark: unknown is not broken",
          sh[0] == sh[1] and sh[0]["decks"] == 3 and sh[0]["dark"] == 0 and sh[0]["w"] == 9)
    check("a cluster has a deck for each machine, twelve at most, and is taller for it",
          sh[2]["decks"] == 1 and sh[4]["decks"] == 5 and sh[3]["decks"] == sh[8] == 12 and sh[2]["h"] < sh[4]["h"] < sh[3]["h"] and sh[3]["w"] <= 14)
    check("as many decks are dark as machines are not ready: none when all are, at least one when any is not, all when none is",
          sh[4]["dark"] == 0 and sh[5]["dark"] == 1 and sh[6]["dark"] == 1 and sh[6]["decks"] == 12 and sh[7] == {**sh[7], "decks": 3, "dark": 3})
    w = out["win"]
    check("no window is red unless a pod is failing", w["none"] == {"lit": 40, "red": 0})
    check("one failing pod among hundreds still has its red window", w["one"] == {"lit": 60, "red": 1})
    check("red windows are never more than lit ones, and all of them when every pod fails",
          w["many"]["red"] == 39 and w["many"]["lit"] == 40 and w["all"] == {"lit": 5, "red": 5})
    check("no window is lit in a building nobody could ask, has read, or that holds no pod",
          w["down"] == w["reading"] == w["empty"] == w["noroom"] == {"lit": 0, "red": 0})
    check("who needs somebody first: the most failing pods, then machines not ready, and never one that is well",
          out["needy"] == ["worse", "sick", "storm"])
    news = out["news"]
    check("the board names each failing cluster with its numbers and its worst pod",
          news["mixed"][0] == "worse: 7 of 90 pods failing" and news["mixed"][1] == "worse · web-1: CrashLoopBackOff, 41 restarts"
          and "storm: every pod running, 1 machine not ready" in news["mixed"])
    check("it says all is well only when every cluster answered and is",
          news["well"] == ["All 2 clusters answered and every pod is well. Enjoy the walk."]
          and not any("is well" in line for line in news["mixed"] + news["unread"] + news["silent"]))
    check("an unread cluster and a silent one are each said, in words that are not good news",
          news["unread"] == ["1 building still being surveyed: nothing is known about it yet"]
          and news["silent"] == ["No word from gone: timeout"])
    check("an empty city says so, and the live city's board is about the live city",
          "No cluster stands here yet" in news["none"][0] and news["live"][0] == "a-one: 3 of 50 pods failing"
          and "No word from a-two: timeout" in news["live"])
    check("how busy the city is: the mean of the clusters that said, and unknown (not idle) when none did",
          out["load"][:4] == [None, None, 40, 0] and out["load"][4:] == [0, 0, 1, 2, 2])
    check("a placard carries the pod's own reason, and one the street has no phrase for is said as it is",
          out["shout"][0] == "MORE MEMORY!" and out["shout"][1] == "SOMETHINGNEW" and out["shout"][2] == "NOT WELL"
          and out["shout"][3] == "I am db-0 in data: Pending. Go in and help us."
          and "restarted 1 time." in out["shout"][4])


def test_experts(got: dict) -> None:
    """The experts in the street, and what they know (static/cluster3d-quiz.js).

    A question a person is told they got wrong had better be wrong, and an
    expert that says "all is well" had better know. So the bank is held to its
    shape, the choosing to its promises, and what each says of the clusters to
    the same three truths the street is held to."""
    print("the experts and their questions")
    src = (ROOT / "static" / "cluster3d-city.js").read_text()
    quiz = (ROOT / "static" / "cluster3d-quiz.js").read_text()
    check("what the experts know asks nothing of the portal, and neither does talking to one",
          "fetch(" not in quiz and "XMLHttpRequest" not in quiz and src.count("fetch(") == 1
          and "fetch(" not in src[src.index("function chatSay(text)"):src.index("/* The taxi takes you to whoever needs help most,")])
    check("what you have won is kept in this browser when it can be, checked when it is read, and the city plays without it",
          src.count("localStorage") == 2 and "try { localStorage.setItem('c3d.city', JSON.stringify(bag)); } catch (e)" in src
          and "if (kept && kept.stars >= 0 && kept.stars < 1e6) bag.stars = Math.floor(kept.stars);" in src
          and "QZ.EXPERTS.forEach(function (ex) { if (kept && kept.gifts && kept.gifts[ex.gift]) bag.gifts[ex.gift] = 1; });" in src)
    check("a right answer is a star, the first from each expert is its gift, and a wrong one is told the right one and why",
          "bag.stars++; first = !has(ex.gift); if (first) bag.gifts[ex.gift] = 1; save(); celebrate(f, first);" in src
          and "chatSay('Not quite. It is: ' + q.options[q.right] + '. ' + q.why);" in src
          and "var q = chat.q, f = chat.f, ex = f.ex, right = q && i === q.right, first;" in src)
    check("a conversation takes the numbers and Esc, and walking away ends it",
          "if (k >= '1' && k <= '9' && !e.repeat) { if (chat.opts[+k - 1]) chat.opts[+k - 1][1](); e.preventDefault(); return; }" in src
          and "if (chat && Math.hypot(you.x - chat.f.x, you.z - chat.f.z) > 6.5) chatClose();" in src)
    check("the letters of the sign are the installation's name, cut to what a sign can carry, and you walk round them",
          "String(stage.getAttribute('data-love') || '').toUpperCase().replace(/[^A-Z0-9 ]/g, '')" in src and ".slice(0, 14) || 'KUBERNETES';" in src
          and "sign.solid.forEach(function (g2) {" in src)
    node = shutil.which("node")
    if not node:
        print("  (node is not installed: the question checks were skipped)")
        return
    probe = r"""
const m = require(process.argv[1]); const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {n: m.Q.length, by: {}, bad: [], experts: m.EXPERTS.map(e => [e.key, e.hero, e.gift, e.subjects.join(), !!e.has, !!e.hello, !!e.role])};
const seenQ = new Set();
m.Q.forEach((q, i) => { out.by[q[0]] = (out.by[q[0]] || 0) + 1;
  if (q.length !== 7 || q.some(x => typeof x !== 'string' || !x.trim())) out.bad.push(i + ': shape');
  if (new Set(q.slice(2, 6).map(o => o.toLowerCase())).size !== 4) out.bad.push(i + ': two answers alike');
  if (seenQ.has(q[1])) out.bad.push(i + ': asked twice'); seenQ.add(q[1]);
  if (!/\?$/.test(q[1]) || !/\.$/.test(q[6])) out.bad.push(i + ': ' + q[1].slice(0, 30));
  if (!m.SUBJECTS[q[0]]) out.bad.push(i + ': no such subject');
  if (q.slice(2, 6).some(o => o.length > 80)) out.bad.push(i + ': an answer too long for its button'); });
out.subjects = Object.keys(m.SUBJECTS).sort();
out.asked = m.EXPERTS.map(e => [...new Set(e.subjects)].every(s => out.by[s] >= 14));
let r = 7; const rnd = () => { r = (r * 9301 + 49297) % 233280; return r / 233280; };
const e = m.EXPERTS.find(x => x.key === 'noc'), own = out.by.trouble, seen = [], ids = [];
for (let i = 0; i < own * 2; i++) { const q = m.next(e, seen, null, rnd); ids.push(q.id); if (q.options[q.right] !== m.Q[+q.id.slice(1)][2] || q.subject !== 'trouble' || q.options.length !== 4) out.bad.push('asked wrongly: ' + q.id); }
out.round = [new Set(ids.slice(0, own)).size, new Set(ids.slice(own)).size, own, seen.length];
out.places = [0, 0, 0, 0]; for (let i = 0; i < 400; i++) out.places[m.shuffled(m.fromBank(3), rnd).right]++;
const mk = (name, st, pods, bad, nodes, ready, cpu) => ({name, state: st, prod: name === 'big', why: 'timeout', cpu, mem: cpu, pods: pods == null ? null : {total: pods, bad}, nodes: pods == null ? null : {total: nodes, ready}, problems: bad ? [{name: 'x', status: 'CrashLoopBackOff'}] : []});
const mixed = {buildings: [mk('big', 'ok', 90, 0, 5, 5, 40), mk('mid', 'bad', 50, 4, 3, 3, 70), mk('small', 'bad', 20, 1, 2, 2, 10), mk('gone', 'down', null), mk('late', 'reading', null)], totals: {pods: 160, nodes: 10}};
out.live = m.live(mixed).map(q => [q.q, q.options[0], q.options.includes('gone') || q.options.includes('late')]);
out.tie = m.live({buildings: [mk('a', 'ok', 30, 0, 3, 3, 20), mk('b', 'ok', 30, 0, 3, 3, 20), mk('c', 'ok', 30, 0, 3, 3, 20)]}).length;
out.two = m.live({buildings: [mk('a', 'ok', 30, 0, 3, 3, 20), mk('b', 'ok', 10, 0, 1, 1, 5)]}).length;
const liveQ = m.next(e, [], mixed, () => 0.01); out.liveAsked = [liveQ.subject, liveQ.options[liveQ.right]];
const well = {buildings: [mk('a', 'ok', 30, 0, 3, 3, 20), mk('b', 'ok', 10, 0, 1, 1, 5)], totals: {pods: 40, nodes: 4}};
const quiet = {buildings: [mk('a', 'ok', 30, 0, 3, 3, 20), mk('b', 'ok', 10, 0, 1, 1, 5), mk('gone', 'down', null), mk('late', 'reading', null)], totals: {pods: 40, nodes: 4}};
out.quiet = {}; m.EXPERTS.forEach(x => { out.quiet[x.key] = m.brief(x, quiet); });
out.brief = {}; m.EXPERTS.forEach(x => { out.brief[x.key] = [m.brief(x, mixed), m.brief(x, well), m.brief(x, {buildings: [mk('gone', 'down', null)]}), m.brief(x, {buildings: []}), m.brief(x, d)]; });
console.log(JSON.stringify(out));
"""
    r = subprocess.run([node, "-e", probe, str(ROOT / "static" / "cluster3d-quiz.js")],
                       input=json.dumps(got), capture_output=True, text=True, timeout=60)
    check(f"the questions run under node ({r.stderr[:300]})", r.returncode == 0)
    if r.returncode:
        return
    out = json.loads(r.stdout)
    check(f"every question is a question, with one right answer, three different wrong ones and a reason ({out['bad'][:3]})", not out["bad"])
    check("there are many of them, and enough in every subject that an expert does not soon repeat itself",
          out["n"] >= 130 and len(out["by"]) == 8 and min(out["by"].values()) >= 14 and sorted(out["by"]) == out["subjects"])
    ex = out["experts"]
    check("eight experts, each a different figure with a different gift and a subject that has questions",
          len(ex) == 8 and sorted(e[1] for e in ex) == list(range(8)) and len({e[2] for e in ex}) == 8
          and all(e[4] and e[5] and e[6] for e in ex) and all(out["asked"])
          and {s for e in ex for s in e[3].split(",")} == set(out["subjects"]))
    check("an expert asks every question of its subject once before it asks any twice, and marks the right answer wherever it lands",
          out["round"][0] == out["round"][2] and out["round"][1] == out["round"][2] and out["round"][3] == out["round"][2]
          and all(n > 60 for n in out["places"]))
    live = {q[0]: q for q in out["live"]}
    check("it asks about your own clusters only what has one right answer, and never offers one nobody could ask",
          live["Which of our clusters runs the most pods right now?"][1] == "big"
          and live["Which of our clusters has the most failing pods right now?"][1] == "mid"
          and live["Which of our clusters is using the most of its CPU?"][1] == "mid"
          and not any(q[2] for q in out["live"]) and out["tie"] == 0 and out["two"] == 0
          and out["liveAsked"][0] == "live" and out["liveAsked"][1] in ("big", "mid"))
    b = out["brief"]
    check("asked how the clusters are, each expert speaks from the street's own facts",
          "2 clusters need somebody: mid (4 pods failing), small (1 pod failing)." in b["noc"][0]
          and "3 clusters answered" in b["devops"][0] and "The biggest is big with 90 pods." in b["devops"][0]
          and "big (well)" in b["sec"][0] and "I cannot reach gone (timeout)." in b["net"][0]
          and "mid, at 70%" in b["dba"][0] and "2 CrashLoopBackOff" in b["qa"][0] and "1 of 3 clusters that answered is well" in b["pm"][0])
    check("none of them calls it fine while a cluster is silent or unread, and each says what it cannot speak for",
          all("did not answer" in v[0] or "cannot reach" in v[0] or "silent" in v[0] for v in b.values())
          and "Not everything is fine" in b["ceo"][0] and "All 2 clusters are up." in b["ceo"][1]
          and all(v[2].startswith("I have nothing to go on") for v in b.values())
          and all("no cluster in this city" in v[3] for v in b.values())
          and "a-one (3 pods failing)" in b["noc"][4] and "I cannot reach a-two (timeout)." in b["net"][4])
    check("with nothing failing but one cluster silent and one unread, nobody says all is up, and each says what is not known",
          not any("are up" in v or "Every cluster I tried answered" in v for v in out["quiet"].values())
          and all(("did not answer" in v or "cannot reach" in v or "silent" in v) and ("not been read" in v or "not tried yet" in v or "unread" in v)
                  for v in out["quiet"].values()))


def main_test() -> int:
    got = test_data()
    test_hub()
    test_script(got)
    test_experts(got)
    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
