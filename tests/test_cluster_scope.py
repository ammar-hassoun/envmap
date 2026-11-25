#!/usr/bin/env python3
"""A role pinned to one cluster opens that cluster, and nothing else.

WHY THIS EXISTS
    rbac has always been able to say which clusters a role may reach —
    `may_cluster`, `visible_clusters` — and until October 2026 nothing asked.
    A role pinned to cluster A opened cluster B's page, its pods' logs, their
    YAML and their descriptions, because every route checked the AREA and no
    route checked the CLUSTER. The role editor's "clusters" list was a promise
    with no code behind it.

    So this signs in as a role pinned to one cluster and walks every door a
    cluster id can come through: the page, each JSON endpoint, the log stream,
    the POST handlers and the terminal socket. Each must refuse cluster B with
    a 403 and an audit line, and each must still let cluster A through — a
    test that only looked for refusals would pass against a portal refusing
    everybody.

    It also holds the project half: a role naming one PROJECT and no clusters
    opens that project's clusters only. The project list used to be ignored
    for clusters altogether.

    Nothing here needs a cluster: every read is replaced in-process, and the
    kubeconfigs point nowhere.

    ./.venv/bin/python tests/test_cluster_scope.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("clusterscope-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402
from starlette.websockets import WebSocketDisconnect           # noqa: E402

from app import (aitools, answers, auth, cluster as clusterview,  # noqa: E402
                 db, fleet, kmanage, logs, main, rbac, store)

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── the estate: two projects, three clusters, nothing reachable ──────────
P1 = store.add_project("Alpha")
P2 = store.add_project("Beta")
A = store.add_cluster(P1, "alpha-one", "apiVersion: v1\n", "ctx-a")
A2 = store.add_cluster(P1, "alpha-two", "apiVersion: v1\n", "ctx-a2")
B = store.add_cluster(P2, "beta-one", "apiVersion: v1\n", "ctx-b")
for _p, _c in ((P1, A), (P1, A2), (P2, B)):
    store.update_cluster(_p, _c, manage="1")
NAMES = {A: "alpha-one", A2: "alpha-two", B: "beta-one"}
HOME = {A: P1, A2: P1, B: P2}


def _health(cid):
    return {"cid": cid, "pid": HOME[cid], "name": NAMES[cid],
            "project": "Alpha" if HOME[cid] == P1 else "Beta",
            "reachable": True, "nodes": {"total": 1, "ready": 1},
            "pods": {"total": 1, "running": 1, "bad": 0, "pending": 0},
            "cpu": {"pct": 1, "used": 1, "cap": 100, "source": "test"},
            "mem": {"pct": 1, "used": 1, "cap": 100, "source": "test"},
            "error": "", "problems": [], "nodes_ready": 1}


SNAP = {"clusters": [_health(c) for c in (A, A2, B)],
        "projects": [], "totals": {}, "at": "now", "stale": False}
fleet.overview = lambda force=False: SNAP
fleet.peek = lambda: SNAP
clusterview.gathered = lambda sel, want, refresh=False: {
    "parts": {**{k: {} for k in want},
              "namespaces": {"namespaces": [{"name": "default", "pods": 1}]}},
    "pending": [], "errors": []}


def _everywhere(part, refresh=False):
    out = []
    for cid in (A, A2, B):
        row = {"pid": HOME[cid], "project": "Alpha" if HOME[cid] == P1
               else "Beta", "cid": cid, "cluster": NAMES[cid]}
        if part == "nodes":
            row["nodes"] = [{"name": f"node-of-{NAMES[cid]}", "ready": True,
                             "schedulable": True, "pressure": [],
                             "roles": ["worker"], "cpu_use": None,
                             "cpu_cap": 0, "mem_use": None, "mem_cap": 0,
                             "version": "v1", "runtime": "x", "age": "1d"}]
        else:
            row["pods"] = [{"name": f"pod-of-{NAMES[cid]}",
                            "namespace": "default", "node": "n",
                            "images": ["img"], "healthy": True, "restarts": 0,
                            "problem": "", "phase": "Running", "ready": "1/1",
                            "age": "1d"}]
        out.append(row)
    return out


clusterview.everywhere = _everywhere
clusterview.describe = lambda sel, kind, name, ns: {
    "text": f"described {sel.get('name')}"}
kmanage.read_yaml = lambda sel, kind, name, ns: {
    "text": f"yaml of {sel.get('name')}"}
logs.containers_of = lambda sel, ns, pod: ["main"]
logs.stream = lambda sel, ns, pod, container="", tail=200, previous=False: \
    iter([logs.sse("log", [f"line from {sel.get('name')}"])])

# Anything that would CHANGE a cluster is a spy: reaching it at all for B is
# the failure, whatever kubectl would then have said.
REACHED = []


def _spy(name):
    def fn(*a, **k):
        REACHED.append(name)
        raise kmanage.Refused(f"{name} reached")
    return fn


for _fn in ("act", "run", "exec_in", "netshoot_start", "pty_open",
            "apply_yaml", "complete", "namespaces"):
    setattr(kmanage, _fn, _spy(_fn))


def signed_in(email: str, areas: list, projects=(), clusters=()):
    uid = auth.create_user(email, "U", "Passw0rd!xY-scope", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, list(projects),
                                      list(clusters))])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-scope"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c, auth.by_email(email)


def denials(target: str) -> int:
    return (db.one("SELECT COUNT(*) AS n FROM audit WHERE action = "
                   "'scope_denied' AND target = ?", (target,)) or {"n": 0})["n"]


def q(project, cid, **extra):
    from urllib.parse import urlencode
    return urlencode({"project": project, "cluster": cid, **extra})


def main_test() -> int:
    pin, pin_user = signed_in("pinned@test.invalid", ["clusters", "manage"],
                              clusters=[A])
    every, _every_user = signed_in("everywhere@test.invalid",
                                   ["clusters", "manage"])

    print("cluster B's page is refused, with a 403 and an audit line")
    before = denials("cluster beta-one")
    r = pin.get(f"/clusters?{q(P2, B, tab='events')}", follow_redirects=False)
    check(f"B's page → {r.status_code}", r.status_code == 403)
    check("and it says so in words", "outside your roles" in r.text)
    # The person typed an id; the answer must not tell them what it names.
    check("without naming the cluster it refused", "beta-one" not in r.text)
    check("the refusal is in the audit log, naming what was asked for",
          denials("cluster beta-one") == before + 1)
    r = pin.get(f"/clusters?{q(P1, A, tab='events')}", follow_redirects=False)
    check(f"while A's page opens ({r.status_code})", r.status_code == 200)
    r = pin.get(f"/clusters?{q(P1, A2, tab='events')}", follow_redirects=False)
    check(f"and A's sibling in the same project does not ({r.status_code})",
          r.status_code == 403)
    r = every.get(f"/clusters?{q(P2, B, tab='events')}", follow_redirects=False)
    check(f"an unpinned role still opens B ({r.status_code})",
          r.status_code == 200)
    # An id that does not exist is refused in the same words as one that does:
    # anything else is a way to find out which ids are real.
    r = pin.get(f"/clusters?{q(P2, 'c-00000000')}", follow_redirects=False)
    check(f"an unknown id is refused like an out-of-scope one ({r.status_code})",
          r.status_code == 403)
    # A cluster id that IS in scope must not carry somebody into another
    # project's page beside it.
    r = pin.get(f"/clusters?{q(P2, A)}", follow_redirects=False)
    check(f"A's id under B's project is refused ({r.status_code})",
          r.status_code == 403)
    r = pin.get(f"/clusters?project={P2}", follow_redirects=False)
    check(f"so is B's project page on its own ({r.status_code})",
          r.status_code == 403)

    print("its JSON, logs and YAML are refused; A's are served")
    for path, want in (
            ("/clusters/describe.json", "described"),
            ("/clusters/yaml.json", "yaml of"),
            ("/clusters/logstream", "line from"),
            ("/clusters/containers.json", "main")):
        r = pin.get(f"{path}?{q(P2, B, namespace='default', name='p', pod='p')}",
                    follow_redirects=False)
        check(f"{path} for B → {r.status_code}", r.status_code == 403)
        check(f"{path} for B says nothing about B", "beta-one" not in r.text)
        r = pin.get(f"{path}?{q(P1, A, namespace='default', name='p', pod='p')}",
                    follow_redirects=False)
        check(f"{path} for A → {r.status_code} and its content",
              r.status_code == 200 and want in r.text)
    r = pin.get(f"/clusters/describe.json?{q(P2, B, name='p')}",
                follow_redirects=False)
    check("a JSON door answers its refusal as JSON",
          r.headers.get("content-type", "").startswith("application/json")
          and "outside" in r.json().get("error", ""))
    for path in ("/clusters/related", "/clusters/scan/report",
                 "/clusters/shell/namespaces", "/clusters/shell/complete"):
        r = pin.get(f"{path}?{q(P2, B, name='p', namespace='default')}",
                    follow_redirects=False)
        check(f"{path} for B → {r.status_code}", r.status_code == 403)

    print("every door that CHANGES a cluster refuses B before reaching it")
    REACHED.clear()
    form = {"project": P2, "cluster": B, "namespace": "default", "pod": "p",
            "name": "web", "kind": "deployment", "action": "restart",
            "cmd": "get pods", "yaml": "kind: Pod", "dry": "1",
            "sa_namespace": "default", "preset": "view"}
    for path in ("/clusters/action", "/clusters/shell", "/clusters/shell/run",
                 "/clusters/exec", "/clusters/exec.json",
                 "/clusters/netshoot", "/clusters/netshoot.json",
                 "/clusters/netshoot/stop", "/clusters/yaml/apply",
                 "/clusters/access/create", "/clusters/access/reissue",
                 "/clusters/access/revoke"):
        r = pin.post(path, data=form, follow_redirects=False)
        check(f"POST {path} for B → {r.status_code}", r.status_code == 403)
    check(f"and none of them reached kubectl ({REACHED})", REACHED == [])
    r = pin.post("/clusters/exec.json", data=form, follow_redirects=False)
    check("a JSON POST refuses in JSON too",
          "outside" in (r.json() if r.headers.get("content-type", "")
                        .startswith("application/json") else {}).get("error", ""))
    r = pin.post("/clusters/action", data={**form, "project": P1, "cluster": A},
                 follow_redirects=False)
    check(f"while A's action reaches kubectl ({REACHED})", REACHED == ["act"])

    print("and so does the terminal socket, which no middleware sees")
    said, code = "", None
    try:
        with pin.websocket_connect(f"/clusters/pty.ws?{q(P2, B, namespace='d', pod='p')}") as ws:
            said = ws.receive_text()
            ws.receive_text()
    except WebSocketDisconnect as e:
        code = e.code
    check(f"B's terminal is refused on screen ({said.strip()[:60]!r})",
          "outside what your roles may reach" in said)
    check(f"and closes as never-started ({code})", code == 4001)
    check("and that refusal is audited too",
          db.one("SELECT 1 FROM audit WHERE action='scope_denied' AND "
                 "detail LIKE '%pty.ws%'") is not None)

    print("the listings show A and only A")
    body = pin.get("/clusters?sec=all", follow_redirects=False).text
    check("the hub's cluster table has A", "alpha-one" in body)
    check("and not A's sibling or B",
          "alpha-two" not in body and "beta-one" not in body
          and B not in body and A2 not in body)
    body = pin.get("/clusters", follow_redirects=False).text
    check("the hub's project cards stop at A's project",
          f"/clusters?project={P1}" in body and f"/clusters?project={P2}" not in body)
    # A count of one cluster under "across every project" is a page that lies.
    check("and its tiles say they count the clusters the roles cover",
          "that your roles cover" in body and "across every project" not in body)
    check("which an unpinned role's do not",
          "across every project" in every.get("/clusters").text)
    body = every.get("/clusters?sec=all", follow_redirects=False).text
    check("while an unpinned role lists all three",
          all(n in body for n in NAMES.values()))
    body = pin.get(f"/clusters?project={P1}", follow_redirects=False).text
    check("A's project page shows A and not its sibling",
          "alpha-one" in body and "alpha-two" not in body)
    nodes = pin.get("/nodes", follow_redirects=False).text
    check("/nodes lists A's node only",
          "node-of-alpha-one" in nodes and "node-of-beta-one" not in nodes
          and "node-of-alpha-two" not in nodes)
    pods = pin.get("/pods", follow_redirects=False).text
    check("/pods lists A's pod only",
          "pod-of-alpha-one" in pods and "pod-of-beta-one" not in pods)
    r = pin.get(f"/pods?cluster={B}", follow_redirects=False)
    check(f"and /pods narrowed to B is refused ({r.status_code})",
          r.status_code == 403)
    # The top bar's cluster picker and the page's own switcher: a shortcut to
    # a cluster the page will refuse is the button-that-always-refuses again.
    # Ids, not names: the switcher's list is JSON in a script, where `&` is
    # escaped, so a URL fragment would be absent from a page that still
    # carried the cluster.
    page = pin.get(f"/clusters?{q(P1, A, tab='events')}").text
    check("the top bar offers A",
          f"cluster={A}&amp;tab=overview&amp;troubleshoot=1" in page)
    check("and so does the page's own cluster switcher",
          f'"cid": "{A}"' in page)
    check("and offer neither B nor A's sibling, anywhere on the page",
          B not in page and A2 not in page)
    page = every.get(f"/clusters?{q(P1, A, tab='events')}").text
    check("while an unpinned role is offered all three",
          B in page and A2 in page)

    print("a role naming a PROJECT opens that project's clusters only")
    proj, _pu = signed_in("project@test.invalid", ["clusters"], projects=[P1])
    for cid, want in ((A, 200), (A2, 200), (B, 403)):
        r = proj.get(f"/clusters?{q(HOME[cid], cid, tab='events')}",
                     follow_redirects=False)
        check(f"{NAMES[cid]} → {r.status_code}", r.status_code == want)
    body = proj.get("/clusters?sec=all").text
    check("and its hub lists both of the project's clusters and not B",
          "alpha-one" in body and "alpha-two" in body and "beta-one" not in body)
    check("visible_clusters agrees", rbac.visible_clusters(_pu) == {A, A2})

    print("the assistant does not resolve B")
    try:
        aitools.propose(pin_user, P2, B, "restart",
                        {"kind": "deployment", "namespace": "default",
                         "name": "web"})
        check("proposing an action on B is refused", False)
    except aitools.Denied as e:
        check(f"proposing an action on B is refused ({e})",
              "outside what your roles may reach" in str(e))
        check("without naming it", "beta-one" not in str(e))
    got = aitools.propose(pin_user, P1, A, "restart",
                          {"kind": "deployment", "namespace": "default",
                           "name": "web"})
    check("while A resolves", got.get("cluster_name") == "alpha-one")
    listed = {c["cluster"] for c in aitools.clusters_for(pin_user)}
    check(f"the clusters a model is told about are A alone ({listed})",
          listed == {A})
    check("and the action briefing names A and not B",
          A in aitools.action_briefing(pin_user)
          and B not in aitools.action_briefing(pin_user))
    rows = answers.q_clusters(pin_user, "list the clusters", "")["rows"]
    check(f"its cluster answers stop at A ({[r['cluster'] for r in rows]})",
          [r["cluster"] for r in rows] == ["alpha-one"])

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
