#!/usr/bin/env python3
"""The doors INTO a production pod want the cluster's name typed first.

WHY THIS EXISTS
    A cluster that serves production asks for its name before the kubectl
    console runs a write, before an action, before a manifest is applied. The
    three doors that run whatever somebody types INSIDE one of its containers
    asked for nothing: the pod terminal, a one-off command (`/clusters/exec`
    and its JSON twin), and the troubleshooting pod that lands you in a shell.
    The gate was on the doors that change Kubernetes objects and missing from
    the ones that hand over a root prompt in a production container.

    So every one of them is driven here against a production cluster with the
    name missing, wrong, and right — the first two must stop before kubectl is
    reached and leave an audit line; the last must reach it. A cluster that is
    not production must ask for nothing, or people learn to type names without
    reading them. Then the page: the terminal asks in the terminal before it
    connects, the troubleshoot window asks before it starts a pod, and the name
    typed for a troubleshooting pod is carried to that pod's terminal and no
    other.

    ./.venv/bin/python tests/test_pod_prod_gate.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("podprodgate-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402
from starlette.websockets import WebSocketDisconnect           # noqa: E402

from app import (auth, cluster as clusterview, db, fleet,      # noqa: E402
                 kmanage, main, store)

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P = store.add_project("Gate")
RG = store.add_region(P, "Main")
LIVE = store.add_cluster(P, "live", "apiVersion: v1\n", "ctx-live")
DEV = store.add_cluster(P, "dev-one", "apiVersion: v1\n", "ctx-dev")
for _c in (LIVE, DEV):
    store.update_cluster(P, _c, manage="1")
store.map_env_cluster(P, RG, "prod", LIVE)
store.map_env_cluster(P, RG, "dev", DEV)

fleet.overview = lambda force=False: {"clusters": [], "projects": [],
                                      "totals": {}, "at": "", "stale": False}
fleet.peek = lambda: None
# The namespace bar is where Troubleshoot lives, and it is drawn only when the
# cluster answered with namespaces.
clusterview.gathered = lambda sel, want, refresh=False: {
    "parts": {**{k: {} for k in want},
              "namespaces": {"namespaces": [{"name": "default", "pods": 1}]},
              "pods": {"pods": [{"name": "web-1", "namespace": "default",
                                 "healthy": True, "phase": "Running",
                                 "ready": "1/1", "restarts": 0, "node": "n1",
                                 "age": "1d", "images": [], "owner": "",
                                 "problem": "", "cpu": None, "mem": None,
                                 "workload": "web"}]}},
    "pending": [], "errors": []}

REACHED: list = []


def _spy(name, answer=None):
    def fn(sel, *a, **k):
        REACHED.append((name, sel.get("name")))
        if answer is None:
            raise kmanage.Refused(f"{name} reached")
        return answer
    return fn


kmanage.exec_in = _spy("exec_in", {"argv": [], "kind": "exec", "code": 0,
                                   "ok": True, "stdout": "hi", "stderr": "",
                                   "took": 0, "display": "kubectl exec"})
kmanage.netshoot_start = _spy("netshoot_start", {
    "name": "netshoot-0123abcd", "namespace": "default", "ttl": 1800,
    "image": "img", "ready": True, "why": ""})
kmanage.pty_open = _spy("pty_open")


def signed_in():
    email, pw = "pod-gate@test.invalid", "Pod-Gate-Wants-A-Name-7"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def refusals(action: str) -> int:
    return (db.one("SELECT COUNT(*) AS n FROM audit WHERE action = ?",
                   (action,)) or {"n": 0})["n"]


def socket(c, cid: str, **extra) -> tuple:
    q = urllib.parse.urlencode({"project": P, "cluster": cid,
                                "namespace": "default", "pod": "web-1",
                                **extra})
    said, code = "", None
    try:
        with c.websocket_connect(f"/clusters/pty.ws?{q}") as ws:
            said = ws.receive_text()
            ws.receive_text()
    except WebSocketDisconnect as e:
        code = e.code
    return said, code


def main_test() -> int:
    c = signed_in()
    form = {"project": P, "cluster": LIVE, "namespace": "default",
            "pod": "web-1", "cmd": "id"}

    print("a command in a production pod: unnamed, misnamed, named")
    for path in ("/clusters/exec.json", "/clusters/exec"):
        for typed, label in (("", "with no name"), ("libe", "with the wrong name"),
                             ("LIVE", "with the name in the wrong case")):
            REACHED.clear()
            before = refusals("pod_exec_refused")
            r = c.post(path, data={**form, "confirm": typed},
                       follow_redirects=False)
            said = (r.json().get("stderr", "") if path.endswith(".json")
                    else urllib.parse.unquote(r.headers.get("location") or ""))
            check(f"{path} {label} is refused in the console's words ({said[:70]!r})",
                  "serves production" in said and "type its name (live)" in said)
            check(f"{path} {label} never reaches kubectl ({REACHED})",
                  REACHED == [])
            check(f"{path} {label} is audited",
                  refusals("pod_exec_refused") == before + 1)
        REACHED.clear()
        c.post(path, data={**form, "confirm": " live "}, follow_redirects=False)
        check(f"{path} with its name goes ahead ({REACHED})",
              REACHED == [("exec_in", "live")])
    REACHED.clear()
    r = c.post("/clusters/exec.json", data={**form, "cluster": DEV},
               follow_redirects=False)
    check(f"a cluster that is not production asks for nothing ({REACHED})",
          REACHED == [("exec_in", "dev-one")])

    print("the pod terminal: refused on the socket, before kubectl")
    REACHED.clear()
    before = refusals("pod_shell_refused")
    said, code = socket(c, LIVE)
    check(f"an unnamed terminal on production is refused on screen ({said.strip()[:70]!r})",
          "serves production" in said and "type its name (live)" in said)
    check(f"and closes as never-started ({code})", code == 4001)
    check(f"without reaching kubectl ({REACHED})", REACHED == [])
    check("and the refusal is audited",
          refusals("pod_shell_refused") == before + 1)
    said, code = socket(c, LIVE, confirm="libe")
    check("a misnamed one is refused too", "serves production" in said)
    REACHED.clear()
    said, _code = socket(c, LIVE, confirm="live")
    check(f"a named one reaches kubectl ({REACHED})",
          REACHED == [("pty_open", "live")])
    REACHED.clear()
    socket(c, DEV)
    check(f"and a dev cluster's terminal asks nothing ({REACHED})",
          REACHED == [("pty_open", "dev-one")])

    print("the troubleshooting pod: both routes")
    for path in ("/clusters/netshoot.json", "/clusters/netshoot"):
        REACHED.clear()
        before = refusals("netshoot_refused")
        r = c.post(path, data={**form}, follow_redirects=False)
        said = (r.json().get("error", "") if path.endswith(".json")
                else urllib.parse.unquote(r.headers.get("location") or ""))
        check(f"{path} unnamed is refused ({said[:70]!r})",
              "serves production" in said)
        check(f"{path} creates no pod ({REACHED})", REACHED == [])
        check(f"{path} is audited", refusals("netshoot_refused") == before + 1)
        REACHED.clear()
        r = c.post(path, data={**form, "confirm": "live"},
                   follow_redirects=False)
        check(f"{path} named starts the pod ({REACHED})",
              REACHED == [("netshoot_start", "live")])
    to = urllib.parse.unquote(r.headers.get("location") or "")
    check(f"the form route lands in the pod's terminal carrying the name ({to[:90]})",
          "inspect=shell" in to and "confirm=live" in to)
    REACHED.clear()
    r = c.post("/clusters/netshoot", data={**form, "cluster": DEV},
               follow_redirects=False)
    to = urllib.parse.unquote(r.headers.get("location") or "")
    check("and on a dev cluster nothing is asked, or carried",
          REACHED == [("netshoot_start", "dev-one")] and "confirm=" not in to)

    print("the page asks for the name before it connects")
    base = f"/clusters?project={P}&cluster={LIVE}&tab=pods&inspect=shell"
    page = c.get(f"{base}&target=default/web-1").text
    check("a production terminal knows it is production",
          "const PROD = true" in page)
    check("and asks for the name in the terminal",
          "type its name (" in page and "to open a terminal in it" in page)
    carried = re.search(r"const carried = (\"[^\"]*\")\.trim\(\)", page)
    check(f"an ordinary pod is carried no name ({carried and carried.group(1)})",
          carried is not None and carried.group(1) == '""')
    page = c.get(f"{base}&target=default/web-1&confirm=live").text
    carried = re.search(r"const carried = (\"[^\"]*\")\.trim\(\)", page)
    check("not even one put in its link — a name in a link is not somebody typing",
          carried is not None and carried.group(1) == '""')
    page = c.get(f"{base}&target=default/netshoot-0123abcd&confirm=live").text
    carried = re.search(r"const carried = (\"[^\"]*\")\.trim\(\)", page)
    check("a troubleshooting pod's terminal takes the name typed to start it",
          carried is not None and carried.group(1) == '"live"')
    page = c.get(f"/clusters?project={P}&cluster={DEV}&tab=pods"
                 f"&inspect=shell&target=default/web-1").text
    check("a dev terminal is not production", "const PROD = false" in page)

    print("and so does the troubleshoot window")
    page = c.get(f"/clusters?project={P}&cluster={LIVE}&tab=pods").text
    win = page[page.find('id="tsDlg"'):]
    check("the window knows the cluster is production",
          "const PROD = true" in win and 'const NAME = "live"' in win)
    check("it builds a gate before it starts anything",
          "ts-gate" in win and "to start a troubleshooting pod on it" in win)
    check("and posts the name with the request",
          "d.append('confirm', typed)" in win)
    check("and carries it to the pod's terminal",
          "'&confirm=' + encodeURIComponent(typed)" in win)
    check("the shell link says the terminal will ask",
          "so the terminal asks for its name first" in page)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
