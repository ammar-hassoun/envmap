"""The new look is an ENGINE, and the views stay what they are.

WHAT THIS HOLDS
    The 3D view and the city are `static/cluster3d.js` and
    `static/cluster3d-city.js`: what is where, what a pod says, what a key
    does. They hand a list of shapes to an engine each frame. There are two
    engines: the classic `static/cluster3d-gl.js`, and the new look's
    `static/proto3d/app/engine.js`, drawn on Three.js, which every browser gets
    unless it asks for the classic one (`?look=old`, kept in a cookie).

    Two earlier attempts at a new look rebuilt the place and the figures from
    scratch. They looked right and did nothing, and the answer both times was
    "keep everything as it was, only the design is new". So the rule here is:
    the new look may not carry a second copy of anything the views do. It is
    the same page, the same scripts, and one script swapped.

    Run as a plain script; it prints OK or how many checks failed.
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("look-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, fleet, main, rbac, store             # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTO = ROOT / "static" / "proto3d"
bad = 0


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def signed_in(email: str, areas: list):
    uid = auth.create_user(email, "U", "Passw0rd!xY-look", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], [])])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-look"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)
    return c


def scripts(html: str) -> list:
    """Every script the page loads by address, in the order it loads them."""
    return [re.sub(r"\?.*", "", s) for s in re.findall(r'<script[^>]*\bsrc="([^"]+)"', html)]


def test_pages() -> None:
    print("which engine a page gets")
    pid = store.add_project("Alpha", icon="x")
    cid = store.add_cluster(pid, "a-one", "apiVersion: v1\nkind: Config\n", "a-one")
    fleet.overview = lambda force=False: {"clusters": [], "at": "", "stale": False}
    boss = signed_in("boss@test.invalid", ["clusters"])
    view, town = f"/clusters/3d?project={pid}&cluster={cid}", "/clusters/city"

    # Since 0.7.57 the new look is everybody's. 0.7.56 shipped it only to a
    # browser that asked, and dev, deployed with it, still showed the old city
    # and the old figures: "please make sure you are pushing the correct one".
    for name, url in (("the 3D view", view), ("the city", town)):
        page = boss.get(url)
        got = scripts(page.text)
        check(f"{name}, unasked, is drawn by the new engine, and writes no cookie for a choice nobody made",
              page.status_code == 200 and "/static/proto3d/app/engine.js" in got and "/static/cluster3d-gl.js" not in got
              and "set-cookie" not in {k.lower() for k in page.headers})
    plain = {u: scripts(boss.get(u).text) for u in (view, town)}
    page = boss.get(view)
    got = plain[view]
    check("the engine is there before the view looks for it: it is loaded first, as a module in its place",
          got.count("/static/proto3d/app/engine.js") == 1 and got.index("/static/proto3d/app/engine.js") < got.index("/static/cluster3d.js")
          and re.search(r'<script type="module" nonce="[^"]+" src="/static/proto3d/app/engine\.js\?v=[^"]+\.\d+"', page.text))
    check("the map saying where the engine's own parts live carries the page's nonce, once",
          page.text.count('<script type="importmap" nonce="') == 1
          and '"three": "/static/proto3d/three/build/three.module.min.js"' in page.text
          and '"three/addons/": "/static/proto3d/three/examples/jsm/"' in page.text and "<script src=" not in page.text)
    check("the city keeps its own scripts in their order behind the engine",
          plain[town].index("/static/proto3d/app/engine.js") < plain[town].index("/static/cluster3d-quiz.js") < plain[town].index("/static/cluster3d.js"))
    check("the page offers the classic look",
          "c3d-look" in page.text and "look=old" in page.text and ">Classic look</a>" in page.text)

    sep = "&" if "?" in view else "?"
    page = boss.get(view + sep + "look=old")
    got = scripts(page.text)
    check("asked for the classic look, the 3D view swaps the engine for cluster3d-gl.js and nothing else",
          page.status_code == 200 and "/static/cluster3d-gl.js" in got and "proto3d" not in page.text and "importmap" not in page.text
          and [s for s in got if "cluster3d-gl.js" not in s] == [s for s in plain[view] if "engine.js" not in s])
    kept = page.headers.get("set-cookie", "")
    check("the choice is kept for this browser, for the 3D pages only, where no script can read it",
          "c3d_look=old" in kept and "Path=/clusters" in kept and "HttpOnly" in kept and "samesite=lax" in kept.lower())
    check("and the classic page offers the new look back",
          "look=new" in page.text and ">New look</a>" in page.text)
    again = boss.get(town)
    check("it holds: the city, opened next with nothing asked, is in the classic look too",
          "/static/cluster3d-gl.js" in scripts(again.text) and "proto3d" not in again.text)
    back = boss.get(town + "?look=new")
    check("asked for the new look, it comes back and stays",
          "/static/proto3d/app/engine.js" in scripts(back.text) and "c3d_look=new" in back.headers.get("set-cookie", "")
          and "/static/proto3d/app/engine.js" in scripts(boss.get(view).text))
    odd = boss.get(town + "?look=<script>alert(1)</script>")
    check("anything else asked for is no choice at all: nothing is kept and nothing is written back",
          "set-cookie" not in {k.lower() for k in odd.headers} and "<script>alert(1)" not in odd.text)

    print("the prototype's own addresses")
    hop = boss.get("/clusters/city/prototype", follow_redirects=False)
    check("the city's is the city, asked for in the new look", hop.status_code == 303 and hop.headers["location"] == "/clusters/city?look=new")
    hop = boss.get(f"/clusters/3d/prototype?project={pid}&cluster=a b%26c", follow_redirects=False)
    check("a cluster's is the 3D view, with the cluster named as it was and nothing able to ride in on its name",
          hop.status_code == 303 and hop.headers["location"] == f"/clusters/3d?project={pid}&cluster=a+b%26c&look=new")
    other = signed_in("nocluster@test.invalid", ["certs"])
    anon = TestClient(main.app, raise_server_exceptions=False)
    check("neither is a way round the gate: the page behind it still refuses",
          other.get("/clusters/city?look=new", follow_redirects=False).status_code in (303, 403)
          and "proto3d" not in other.get("/clusters/city?look=new").text
          and anon.get("/clusters/city/prototype", follow_redirects=False).status_code in (302, 303)
          and "login" in anon.get("/clusters/city/prototype", follow_redirects=False).headers["location"])


def test_engine() -> None:
    print("the engine")
    src = (PROTO / "app" / "engine.js").read_text()
    code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    old = (ROOT / "static" / "cluster3d-gl.js").read_text()
    view = (ROOT / "static" / "cluster3d.js").read_text()
    check("it parses as the module the page loads it as",
          subprocess.run(["node", "--input-type=module", "--check"], input=src, capture_output=True, text=True, timeout=60).returncode == 0)
    check("it stands exactly where the other engine stands: the same name, and the same four doors",
          "window.C3DGL = make;" in src and "window.C3DGL = make;" in old
          and "return { resize, draw, atlas, hdr: true, hall: true };" in src and "return { resize: resize, draw: draw, atlas: atlas, hdr: hdr };" in old)
    parts = re.findall(r"from 'three/addons/([^']+)'", src)
    shipped = {str(f.relative_to(PROTO / "three" / "examples" / "jsm")) for f in (PROTO / "three" / "examples" / "jsm").rglob("*.js")}
    check("every part of Three.js it names ships, with the licence that has to travel with it",
          len(parts) >= 6 and set(parts) <= shipped and (PROTO / "three" / "build" / "three.module.min.js").is_file()
          and "MIT" in (PROTO / "three" / "LICENSE").read_text())
    reach = set()      # what the parts it names load in their turn
    for part in parts:
        for dep in re.findall(r"from '(\.[^']+)'", (PROTO / "three" / "examples" / "jsm" / part).read_text()):
            reach.add(os.path.normpath(os.path.join(os.path.dirname(part), dep)))
    check("and so does everything those parts load, and nothing ships that nothing loads",
          reach and reach <= shipped and shipped == set(parts) | reach)
    check("it asks for nothing outside this origin, runs no text as code, and writes no markup",
          not re.search(r"https?://", code) and "eval(" not in src and "new Function" not in src
          and "innerHTML" not in src and "fetch(" not in src and "localStorage" not in src)

    # What a frame hands over is the contract. A list the views start sending
    # that this engine does not take would be drawn by one engine and not the other.
    frame = view[view.index("gpu.draw({"):view.index("});", view.index("gpu.draw({"))]
    handed = set(re.findall(r"(\w+):", frame))
    check("it takes everything a frame hands over, by name",
          len(handed) >= 28 and {"orbs", "boxes", "balls", "softs", "glows", "beams", "sprites", "shadows", "isles", "fogCol"} <= handed
          and all(re.search(rf"\bf\.{k}\b", src) for k in handed))
    check("each list is read at the width the views write it",
          all(call in src for call in ("bank(boxGeo, 14, SOLID)", "bank(ballGeo, 14, SOLID)", "bank(softGeo, 14, SOLID)", "bank(orbGeo, 16, ORB)",
                                       "bank(quad, 8, [['iPosr', 4], ['iCol', 4]])", "bank(strip, 16, [['iA', 3], ['iB', 3], ['iCol', 4], ['iW', 4], ['iD', 2]])",
                                       "bank(quad, 8, [['iPosr', 4], ['iG', 4]])", "bank(quad, 4, [['iS', 4]])"))
          and "SOLID = [['iPos', 3], ['iSize', 3], ['iColG', 4], ['iMisc', 4]], ORB = [['iPosr', 4], ['iCol', 4], ['iFace', 4], ['iOm', 4]]" in src
          and "o = N.ball++ * 14" in view and "o = N.box++ * 14" in view)

    # A pod's face is how it is read. The new engine may glaze the ball; it may
    # not draw a mood another way.
    def face(text: str) -> str:
        a = text.index("if (m == 0) sd = ")
        body = text[a:text.index("sd = dash + 0.008;", a) + 18]
        body = re.sub(r"\s+", "", body).replace("','", "")
        return body.replace("c3arc(", "arc(").replace("c3seg(", "seg(")
    check("every mood's eyes are the old shader's own arithmetic, stroke for stroke",
          face(src) == face(old) and len(face(old)) > 400)

    def stretch(text: str, start: str, end: str) -> str:
        a = text.index(start)
        return re.sub(r"\s+", "", text[a:text.index(end, a) + len(end)]).replace("','", "")
    check("the visor, the blink, the tear and the cap are where they were",
          stretch(src, "float vis = length(", "- 0.17;") == stretch(old, "float vis = length(", "- 0.17;")
          and stretch(src, "float blink = step(", "seed * 7.0));") == stretch(old, "float blink = step(", "seed * 7.0));")
          and "fract(uTime * 0.8 + seed), dr = length((pm - vec2(eye.x, eye.y - 0.20 - f * 0.42)) / vec2(0.035, 0.06));" in src
          and "fract(uTime * 0.8 + seed), dr = length((pm - vec2(eye.x, eye.y - 0.20 - f * 0.42)) / vec2(0.035, 0.06));" in old
          and stretch(src, "if (i < 0.5) return vec3(0.22, 0.48, 0.95);", "return vec3(0.82, 0.52, 0.22); }") == stretch(old, "if (i < 0.5) return vec3(0.22, 0.48, 0.95);", "return vec3(0.82, 0.52, 0.22); }"))
    check("a solid stands and turns as the old vertex shader placed it, kind by kind",
          "if (c3k > 1.5 && c3k < 2.5) transformed = c3rx(c3rz(transformed, 0.7854), 0.6155);" in src and "p = rx(rz(p, 0.7854), 0.6155)" in old
          and "transformed = c3rz(c3rx(transformed, iMisc.y), iMisc.z);" in src and "p = rz(rx(p, i_misc.y), i_misc.z)" in old
          and "transformed = c3ry(transformed, iMisc.x) + iPos;" in src and "p = ry(p, i_misc.x)" in old)
    check("the camera is the caller's own eye and three directions, so what is written over the picture still lands on it",
          "camera.position.fromArray(f.eye)" in src and "basis.makeBasis(R3, U3, F3.clone().negate())" in src
          and "camera.fov = 2 * Math.atan(H / (2 * f.focal)) * 180 / Math.PI" in src)

    print("what the views are")
    for name in ("cluster3d.js", "cluster3d-city.js", "cluster3d-quiz.js", "cluster3d-gl.js"):
        check(f"{name} knows nothing of the prototype", "proto3d" not in (ROOT / "static" / name).read_text())
    check("and the prototype is one script: there is no second copy of what the views do",
          sorted(f.name for f in (PROTO / "app").iterdir()) == ["engine.js"] and not (PROTO / "models").exists()
          and not (ROOT / "templates" / "cluster_city_proto.html").exists())


def test_hall() -> None:
    """The new design is an ARRANGEMENT the engine asks for, and nothing more.

    What the user chose was the design of the second attempt (machines as bays
    either side of an aisle, racks behind them, a city in a hall) with
    everything the views already did. So the engine says it is a hall, the
    views stand the same things differently, and tell the engine where; what a
    pod is, says and does has one copy, and is not in this."""
    print("the hall")
    view = (ROOT / "static" / "cluster3d.js").read_text()
    town = (ROOT / "static" / "cluster3d-city.js").read_text()
    # Every frame before the cluster's layout exists (the city, and a cluster
    # still being read) handed the painter `lay.bays` and threw, once a frame,
    # until data arrived: found in the playable demo's console, 22 November 2026.
    check("the frame loop reads the layout only once there is one",
          "bays: lay.bays," not in view and "bays: lay && lay.bays," in view)
    src = (PROTO / "app" / "engine.js").read_text()
    old = (ROOT / "static" / "cluster3d-gl.js").read_text()
    check("only an engine that says it is a hall gets one: the engine every installation has does not say so",
          "var HALL = !!(gpu && gpu.hall);" in view and "hall: true }" in src and "hall:" not in old
          and "lay = layout(data, groupBy, HALL);" in view)
    check("the views tell that engine where the bays and the streets are, and tell the other nothing",
          "bays: lay && lay.bays, nBays: lay && lay.bays ? lay.plats.length : 0 }" in view and "if (HALL) {" in view
          and "if (K.hall && (!P.town || (sign && !P.town.love))) P.town = {" in town and "town: P.town || null, screens: screens });" in town
          and "window.C3DCity({ stage: stage, hall: HALL," in view)
    check("a hall changes how things stand and nothing of what they are: the views name it in a handful of places",
          len(re.findall(r"\bHALL\b", view)) <= 8 and len(re.findall(r"K\.hall\b", town)) <= 5
          and "HALL" not in view[view.index("function speech("):view.index("function speech(") + 4000])

    node = shutil.which("node")
    if not node:
        print("  (node is not installed: the layout checks were skipped)")
        return
    nodes = [{"name": n, "ready": True, "roles": ["control-plane"] if n == "cp-1" else [], "pressure": [], "schedulable": True} for n in ("w-2", "cp-1", "w-1", "w-3", "w-4")]
    pods = [{"id": f"ns{i % 3}/p{i}", "ns": f"ns{i % 3}", "name": f"p{i}", "wl": f"ns{i % 3}/w{i % 5}", "node": nodes[i % 5]["name"] if i % 11 else "", "tone": "ok"} for i in range(57)]
    probe = r"""
const m = require(process.argv[1]); const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const shape = (L) => ({ w: L.w, d: L.d, plats: L.plats.map(p => ({ key: p.key, x: p.x, z: p.z, w: p.w, d: p.d, side: p.side || 0, limbo: !!p.limbo, rank: p.rank })),
  pods: d.pods.map(p => { const q = L.pos['pod:' + p.id]; return q ? [p.id, p.node, +q.x.toFixed(3), +q.z.toFixed(3)] : [p.id, p.node, null, null]; }) });
console.log(JSON.stringify({ hall: shape(m.layout(d, 'node', true)), plain: shape(m.layout(d, 'node')), again: shape(m.layout(d, 'node', true)), half: 3.6 }));
"""
    got = json.loads(subprocess.run([node, "-e", probe, str(ROOT / "static" / "cluster3d.js")], input=json.dumps({"nodes": nodes, "pods": pods, "namespaces": []}),
                                    capture_output=True, text=True, timeout=60).stdout or "{}")
    hall, plain, half = got.get("hall") or {}, got.get("plain") or {}, got.get("half")
    plats = hall.get("plats") or []
    check("in a hall every machine stands on one side of the aisle or the other, with its front on the aisle's edge",
          len(plats) == 6 and all(p["side"] in (-1, 1) for p in plats)
          and all(abs((p["z"] + p["d"] + half) if p["side"] < 0 else (p["z"] - half)) < 1e-6 for p in plats)
          and {p["side"] for p in plats} == {-1, 1})
    check("no two on a side stand in each other's place",
          all(a["x"] + a["w"] <= b["x"] + 1e-6 or b["x"] + b["w"] <= a["x"] + 1e-6 for a in plats for b in plats if a is not b and a["side"] == b["side"]))
    first = min(plats, key=lambda p: (p["x"], p["side"])) if plats else {}
    wait = [p for p in plats if p["limbo"]]
    check("the machine that runs the cluster is nearest the way in, and the pods no machine has taken are the last on their side",
          first.get("key") == "cp-1" and len(wait) == 1 and all(q["x"] <= wait[0]["x"] for q in plats if q["side"] == wait[0]["side"]))
    where = {p["key"]: p for p in plats}
    check("every pod is placed, on the bay of the machine it runs on, and no two share a spot",
          len(hall.get("pods") or []) == 57 and all(x is not None for _, _, x, _ in hall["pods"])
          and len({(x, z) for _, _, x, z in hall["pods"]}) == 57
          and all(where[n]["x"] <= x <= where[n]["x"] + where[n]["w"] and where[n]["z"] <= z <= where[n]["z"] + where[n]["d"] for _, n, x, z in hall["pods"]))
    check("it is the same every time, and the arrangement nobody asked a hall for is untouched by it",
          got.get("again") == hall and all(p["side"] == 0 for p in plain.get("plats") or [{"side": 1}])
          and [p["key"] for p in plain["plats"]] == [p["key"] for p in plats] and plain != hall)

    check("the engine stands a rack behind each bay, dark where the machine is not ready, and lights each pod's spot",
          "function bayHall(b, n, y, mark)" in src and "face.emissiveIntensity = kind === 3 ? 0.05 : 1.5;" in src
          and "if (f.nBays) { let mark = f.nBays;" in src and "bayHall(f.bays, f.nBays, f.gridY, mark);" in src
          and "pl.limbo ? 2 : pl.node && !pl.node.ready ? 3 : pl.rank === 0 ? 1 : 0" in view
          and "bool pod = mod(iFace.z, 16.0) < 8.5 && iPosr.y < iPosr.w * 3.0 && iCol.a > 0.99;" in src
          and "podLights.visible = !!f.nBays; lit.take(f.nBays ? f.orbs : null, f.nOrbs);" in src)
    check("and in the city it lays the bus down the streets and stands racks where no cluster stands",
          "function townHall(T, y)" in src and "T.parks.forEach(" in src and "T.xs.forEach(" in src and "T.zs.forEach(" in src
          and "if (!K.hall) P.parks.forEach(" in town)


def test_figures() -> None:
    """What you ride, what a person is made of and the sign in the square are
    DRAWN better in the hall, and are still the view's own things: the same
    five rides in the same places, the same people, the same words."""
    print("rides, people and the sign")
    view = (ROOT / "static" / "cluster3d.js").read_text()
    town = (ROOT / "static" / "cluster3d-city.js").read_text()
    src = (PROTO / "app" / "engine.js").read_text()
    rides = re.findall(r"[{] name: '([^']+)', line: '[^']*', speed:", view)
    check("the engine has a made model of every ride the view knows, and of no other",
          len(rides) == 6 and rides[0] == "On foot" and all(f"kind === {i}) {{" in src for i in range(1, 6)) and "kind === 6" not in src
          and "if (kind < 1 || kind > 5) continue;" in src)
    check("the view hands a ride to a hall's engine and draws it itself for any other, nine numbers to a ride on both sides",
          "if (HALL) {      // the engine draws its own model of this ride" in view and "} else if (i === 1) {" in view
          and "PROPS.set([f.x, f.y, f.z, f.yaw, f.tilt, f.k, f.piv, i, moving && !calm ? t : 0], nProps * 9)" in view
          and "const o = i * 9, kind = f.props[o + 7] | 0;" in src and "props: PROPS, nProps: nProps" in view
          and "nIsles = 0; nProps = 0; nFigs = 0;\n" in view and "nIsles = 0; nProps = 0; nFigs = 0; placed.length = 0;" in view)
    check("a ride stands where its rider is, leans as the rider leans, and its lamp and its streak are still the view's",
          "m.lean.position.set(f.props[o], f.props[o + 1] + piv * k, f.props[o + 2]); m.lean.rotation.set(f.props[o + 4], f.props[o + 3], 0); m.g.position.y = -piv;" in src
          and "if (i > 2 && !calm) glo(f.x + f.sn * 1.4" in view and view.index("if (HALL) {      // the engine draws its own model") < view.index("if (i > 2 && !calm) glo(f.x + f.sn * 1.4"))
    check("nothing a person is made of is a cube: a box is softened and a soft box is rounded almost to a pill, each to its own thinnest side",
          "[[boxes, 0.45], [balls, 0], [softs, 0.92]]" in src and "#ifdef C3_ROUND" in src
          and "float r = min(h.x, min(h.y, h.z)) * C3_ROUND;" in src and "if (k > 4.5) {" in src
          and "'#define C3_ROUND ' + round.toFixed(2)" in src and "paint.customProgramCacheKey = depth.customProgramCacheKey = () => 'c3paint' + round;" in src)
    check("the sign says the words the view gave it: I, a heart, and the name of the place as the view cleaned it",
          "sign = { z: z, s: s, w: px * s, bars: [], solid: [], name: name };" in town and "love: sign ? { name: sign.name, w: sign.w, z: sign.z, tall: sign.s * 7 } : null" in town
          and "word = traced(L.name), eye = traced('I')" in src and "heartShape(heartW, cap * 1.04)" in src
          and "if (!K.hall) for (i = 0; i < sign.bars.length; i++) {" in town)
    check("a person is handed over as who, where and every joint, eighteen numbers on both sides, and what a hand holds is still hung by the view",
          "FIGS.set([f.x, f.y, f.z, ya, J.tilt, f.k, o.hero, J.legL, J.legR, J.kneeL, J.kneeR, J.armL, J.armR, J.elbL, J.elbR, J.outL, J.outR, J.nod], nFigs * 18)" in view
          and "const o = i * 18, who = f.figs[o + 6] | 0, L = f.heroes[who];" in src and "figs: FIGS, nFigs: nFigs, heroes: HEROES" in view
          and "var FIGS = new Float32Array(48 * 18), nFigs = 0;" in view and "if (nFigs < 48) {" in view
          and "if (!(J.noProp || o.act)) limb(f, -0.27, 1.42, 0, J.armL, J.outL, 0.3, J.elbL, [], PROP[L.kit]);" in view
          and "if (J.hold && HELD[J.hold]) limb(f, 0.27, 1.42, 0, J.armR, J.outR, 0.3, J.elbR, [], HELD[J.hold]);" in view)
    check("the engine's figure stands on the view's own skeleton: the same joints at the same lengths, turned the same way",
          "limb(f, -0.1, 0.86, 0, J.legL, 0, 0.4, J.kneeL," in view and "limb(-0.1, 0.86, 0.4, THIGH" in src and "limb(0.1, 0.86, 0.4, THIGH" in src
          and "limb(f, 0.27, 1.42, 0, J.armR, J.outR, 0.3, J.elbR," in view and "limb(-0.27, 1.42, 0.3, UPPER" in src and "limb(0.27, 1.42, 0.3, UPPER" in src
          and "swing(legL, a[o + 7], a[o + 9]); swing(legR, a[o + 8], a[o + 10]); swing(armL, a[o + 11], a[o + 13], a[o + 15]); swing(armR, a[o + 12], a[o + 14], a[o + 16]); neck.rotation.x = a[o + 17];" in src
          and "pair[0].rotation.set(-ang, 0, out || 0); pair[1].rotation.x = -bend;" in src
          and "m.lean.position.set(f.figs[o], f.figs[o + 1] + k, f.figs[o + 2]); m.lean.rotation.set(f.figs[o + 4], f.figs[o + 3], 0); m.pose(f.figs, o);" in src)
    kits = re.findall(r"kit: '(\w+)'", view[view.index("var HEROES = ["):view.index("var RIDES = [")])
    check("who the eight are, their colours and what they wear are the view's table, read and never kept; each has a look of its own",
          len(kits) == 8 and len(set(kits)) == 8 and "HEROES" not in src and "skin: [" not in src
          and all(f"kit === '{k}') {{" in src for k in kits[:-1]) and f"'{kits[-1]}'" in src
          and "col(L.skin" in src and "col(L.top)" in src and "col(L.legs)" in src and "col(L.shoes" in src and "col(L.hair" in src)
    body = view[view.index("  function person(x, y, z, yaw, t, o) {"):view.index("  /* The head: it nods on the neck")]
    moves = view[view.index("function emote(J, i, u, t)"):view.index("function joints(o, t)")]
    check("each role's own move is still worked out by the view and still plays when it is chosen: the pose goes to the figure, and what the move adds is drawn after it",
          "J = joints(o, t)" in body and body.index("if (HALL) {") < body.index("// what a move adds") < body.index("if (J.shield)")
          and "emote: u <= 1 ? i : null, eu: u" in view and all(f"i === {k})" in moves for k in range(7)) and "emote" not in src)
    check("the boards at the gate are screens in a hall and written over the picture anywhere else, with the same words either way",
          "var lit = K.hall ? [] : null, tt = data.totals, nk = Math.floor(t / 5);" in town and "if (!lit) return board(x, y, zz, lines, o);" in town
          and "for (key in more || {}) sc[key] = more[key];" in town and "lit.push(sc); hold(sc);" in town
          and all(town.count(f"post('{k}',") == 1 for k in ("gate", "news", "help")) and "screens = lit;" in town and "screens: o.screens || null });" in view)
    check("the news screen is handed the view's own story, every headline and where it is between two, and nothing else to say",
          "hl = news.length ? news[nk % news.length] : '';" in town
          and "story: hl, ticker: news, at: news.length ? nk % news.length : 0, of: news.length, beat: (t / 5) % 1," in town
          and "'Extra, extra! ' + news[Math.floor(t / 5) % news.length]" in town)
    check("what would be written over a screen gives way to it, and what stands behind it is hidden by it, as with the boards",
          "if (o.hold) { put.push([x0, y0, r.w, r.h]); continue; }" in town
          and town.index("if (o.hold) {") < town.index("for (hit = false, j = 0; j < put.length && !hit; j++)")
          and "screens ? screens.map(function (s) { return [s.x, s.z, s.w / 2 + 0.2, s.y - s.h / 2 - 0.2, s.y + s.h / 2 + 0.2]; })" in town)
    shown = src[src.index("const boards = {}, FACE ="):src.index("function screensOf(f) {")]
    drawn = re.findall(r"fillText\(([^,]+),", shown)
    check("a screen shows only what the view said, in the colours it gave: no word is written on it from here, and it is divided only at the view's own marks",
          len(drawn) >= 8 and not [d for d in drawn if d.strip()[:1] in "'\"`"]
          and "story.indexOf(': ')" in shown and "text.indexOf(' · ')" in shown and "sc.lines" in shown
          and set(re.findall(r"sc\.(\w+)", shown)) <= {"lines", "tone", "story", "of", "at", "w", "h", "y", "feet", "kind"}
          and "const said = JSON.stringify([sc.lines, sc.story, sc.at, sc.of, sc.tone]);" in src and "sc.ticker" in src and "sc.beat" in src)
    check("its letters are cut from the type the machine has: no font and no model ships with the prototype",
          not [f for f in PROTO.rglob("*") if f.suffix.lower() in (".ttf", ".otf", ".woff", ".woff2", ".json", ".glb", ".gltf")]
          and "g.getImageData(0, 0, w, h)" in src and "path.toShapes(false)" in src)


def main_test() -> int:
    test_pages()
    test_engine()
    test_hall()
    test_figures()
    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
