#!/usr/bin/env python3
"""Minting cluster credentials needs Cluster management, for that cluster.

WHY THIS EXISTS
    The Access tab creates a ServiceAccount, binds it to a role and hands back
    a kubeconfig — up to cluster-admin. Its three routes checked the CLUSTER's
    "allow management" tick and never the PERSON's Cluster management area, so
    a role that could only read Clusters could mint itself a cluster-admin
    token on any cluster with the tick on, re-issue a lost one, or revoke
    somebody else's. Being able to read a cluster became being able to own it.

    So: a reader is refused all three, by role, with the refusal audited and
    nothing reaching the cluster; a manager whose role covers some clusters is
    refused the others; a production cluster still wants its name typed for a
    create and a re-issue; and the page renders the three controls DISABLED,
    saying why, for somebody who would only be refused.

    It also holds the kubectl console's form route to the same rule. The JSON
    route demanded Cluster management; the form route beside it did not, and
    tests/test_manage_gate.py could not see that because it reads a handler as
    everything up to the next route — which took in the helper defined between
    them, and that helper says the right words. The sweep here reads each
    handler as exactly its own function.

    ./.venv/bin/python tests/test_access_manage.py
"""
from __future__ import annotations

import ast
import os
import pathlib
import re
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("accessmanage-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import (access, auth, cluster as clusterview, db,     # noqa: E402
                 fleet, kmanage, main, rbac, store)

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P = store.add_project("Access")
RG = store.add_region(P, "Main")
DEV = store.add_cluster(P, "dev-one", "apiVersion: v1\n", "ctx-dev")
LIVE = store.add_cluster(P, "live", "apiVersion: v1\n", "ctx-live")
OTHER = store.add_cluster(P, "other-one", "apiVersion: v1\n", "ctx-other")
for _c in (DEV, LIVE, OTHER):
    store.update_cluster(P, _c, manage="1")
store.map_env_cluster(P, RG, "prod", LIVE)

fleet.overview = lambda force=False: {"clusters": [], "projects": [],
                                      "totals": {}, "at": "", "stale": False}
fleet.peek = lambda: None
clusterview.gathered = lambda sel, want, refresh=False: {
    "parts": {k: {} for k in want}, "pending": [], "errors": []}
access.listing = lambda sel: {"error": "", "users": [
    {"name": "noc", "namespace": "default", "cluster_roles": [],
     "scoped": [("default", "view")], "orphan": False, "created": "today"}]}

CALLS: list = []


def _created(cluster, **kw):
    CALLS.append(("create", cluster.get("name")))
    return {"name": kw.get("name") or "x", "preset": "view", "namespaces": [],
            "duration": "8760h", "kubeconfig": "apiVersion: v1\n",
            "steps": [], "summary": "created for the test"}


def _reissued(cluster, name, sa_ns, duration):
    CALLS.append(("reissue", cluster.get("name")))
    return {"name": name, "reissued": True, "permissions": [],
            "duration": duration, "kubeconfig": "apiVersion: v1\n",
            "steps": [], "summary": "reissued for the test"}


def _revoked(cluster, name, sa_ns):
    CALLS.append(("revoke", cluster.get("name")))
    return {"ok": True, "steps": []}


def _ran(cluster, raw, allow_write=False):
    CALLS.append(("kubectl", cluster.get("name")))
    raise kmanage.Refused("kubectl reached")


access.create, access.reissue, access.revoke = _created, _reissued, _revoked
kmanage.run = _ran


def signed_in(email: str, *roles):
    uid = auth.create_user(email, "U", "Passw0rd!xY-access", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", f"{email} {i}", "", areas, [],
                                      list(clusters))
                            for i, (areas, clusters) in enumerate(roles)])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-access"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def refused_lines(what: str) -> list:
    return [r["detail"] for r in db.q(
        "SELECT detail FROM audit WHERE action = 'cluster_user_refused' "
        "AND target = ? ORDER BY id", (what,))]


def form(cid: str, **extra) -> dict:
    return {"project": P, "cluster": cid, "name": "noc-ro", "preset": "view",
            "sa_namespace": "default", "duration": "720h", **extra}


def access_form(body: str, action: str) -> str:
    """The markup of the first form posting to `action`."""
    m = re.search(r'<form method="post" action="' + re.escape(action)
                  + r'".*?</form>', body, re.S)
    return m.group(0) if m else ""


def handlers() -> list:
    """(name, source) for every route in main.py — EXACTLY the function, not
    everything up to the next decorator."""
    src = (ROOT / "app" / "main.py").read_text()
    out = []
    for node in ast.parse(src).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                   and isinstance(d.func.value, ast.Name)
                   and d.func.value.id == "app" for d in node.decorator_list):
            continue
        out.append((node.name, ast.get_source_segment(src, node) or ""))
    return out


def main_test() -> int:
    reader = signed_in("access-reader@test.invalid", (["clusters"], []))
    # Reading is fleet-wide; management covers two of the three clusters.
    manager = signed_in("access-manager@test.invalid", (["clusters"], []),
                        (["manage"], [DEV, LIVE]))

    print("a role that only reads Clusters is refused all three, by role")
    CALLS.clear()
    r = reader.post("/clusters/access/create", data=form(DEV),
                    follow_redirects=False)
    check(f"create says why ({r.status_code})",
          "do not include Cluster management" in r.text)
    r = reader.post("/clusters/access/reissue", data=form(DEV, name="noc"),
                    follow_redirects=False)
    check("re-issue says why", "do not include Cluster management" in r.text)
    r = reader.post("/clusters/access/revoke", data=form(DEV, name="noc"),
                    follow_redirects=False)
    check("revoke says why",
          "do not include Cluster management"
          in urllib.parse.unquote(r.headers.get("location") or ""))
    check(f"and none of the three reached the cluster ({CALLS})", CALLS == [])
    lines = refused_lines("dev-one")
    check(f"each refusal is audited ({len(lines)})",
          len(lines) == 3
          and all("Cluster management" in d for d in lines))

    print("a manager's role covers the clusters it names, and no others")
    CALLS.clear()
    r = manager.post("/clusters/access/create", data=form(OTHER),
                     follow_redirects=False)
    check("a cluster outside the management role is refused",
          "not for this cluster" in r.text)
    check("without reaching it", CALLS == [])
    r = manager.post("/clusters/access/create", data=form(DEV),
                     follow_redirects=False)
    check(f"while one inside it creates the user ({CALLS})",
          CALLS == [("create", "dev-one")])

    print("a production cluster wants its name typed for create and re-issue")
    for path, extra, verb in (("/clusters/access/create", {}, "create"),
                              ("/clusters/access/reissue", {"name": "noc"},
                               "reissue")):
        CALLS.clear()
        r = manager.post(path, data=form(LIVE, **extra),
                         follow_redirects=False)
        check(f"{verb} on production, unnamed, is refused",
              "serves production" in r.text and "type its name (live)" in r.text)
        r = manager.post(path, data=form(LIVE, confirm="libe", **extra),
                         follow_redirects=False)
        check(f"{verb} with the wrong name is refused",
              "serves production" in r.text)
        check(f"and neither reached the cluster ({CALLS})", CALLS == [])
        r = manager.post(path, data=form(LIVE, confirm="live", **extra),
                         follow_redirects=False)
        check(f"{verb} with its name goes ahead ({CALLS})",
              CALLS == [(verb, "live")])

    print("the page offers the controls only to somebody they would not refuse")
    page = reader.get(f"/clusters?project={P}&cluster={DEV}&tab=access").text
    made = access_form(page, "/clusters/access/create")
    check("a reader's create button is disabled",
          re.search(r'<button type="submit"[^>]*disabled', made) is not None)
    check("and says why", "Cluster management" in made)
    for action in ("/clusters/access/reissue", "/clusters/access/revoke"):
        f = access_form(page, action)
        check(f"a reader's {action.rsplit('/', 1)[1]} button is disabled",
              re.search(r"<button[^>]*disabled", f) is not None)
    check("and the tab says what reading it allows",
          "need Cluster management" in page)
    page = manager.get(f"/clusters?project={P}&cluster={DEV}&tab=access").text
    made = access_form(page, "/clusters/access/create")
    check("a manager's is not",
          made and re.search(r"<button[^>]*disabled", made) is None)
    page = manager.get(f"/clusters?project={P}&cluster={OTHER}&tab=access").text
    check("but on a cluster outside the role it is, saying so",
          re.search(r"<button[^>]*disabled",
                    access_form(page, "/clusters/access/create")) is not None
          and "not for this cluster" in page)
    # Found in a browser: the three are .btn-ghost, .btn-danger and a bare
    # button, which app.css's disabled look (.abtn, .btn) does not reach, so
    # disabled they still looked live. The page has to carry the rule itself.
    page = reader.get(f"/clusters?project={P}&cluster={DEV}&tab=access").text
    css = re.sub(r"/\*.*?\*/", "", " ".join(
        re.findall(r"<style[^>]*>(.*?)</style>", page, re.S)), flags=re.S)
    rule = re.search(r'form\[action\^="/clusters/access/"\]\s+'
                     r'button\[disabled\]\s*\{([^}]*)\}', css)
    check("and a disabled control looks disabled",
          rule is not None and "opacity" in rule.group(1)
          and "not-allowed" in rule.group(1))

    print("the kubectl console's form route asks for the area too")
    CALLS.clear()
    r = reader.post("/clusters/shell", data={"project": P, "cluster": DEV,
                                             "cmd": "delete pod web -n default"},
                    follow_redirects=False)
    check("a reader's command never reaches kubectl", CALLS == [])
    check("and is told why", "Cluster management" in r.text)
    check("and it is audited",
          db.one("SELECT 1 FROM audit WHERE action = 'kubectl_refused' AND "
                 "detail LIKE '%Cluster management%'") is not None)
    r = manager.post("/clusters/shell", data={"project": P, "cluster": DEV,
                                              "cmd": "get pods -n default"},
                     follow_redirects=False)
    check(f"while a manager's does ({CALLS})", CALLS == [("kubectl", "dev-one")])

    print("every route that reaches kubectl asks, in its OWN body")
    reaches = ("kmanage.act", "kmanage.run", "kmanage.pty_open",
               "kmanage.netshoot", "kmanage.complete_in_pod", "kmanage.exec_in",
               "kmanage.apply_yaml", "access.create", "access.reissue",
               "access.revoke")
    gates = ('_may(request, "manage")', "_cluster_for(", "_ws_user(",
             "_manage_why(")
    checked = 0
    for name, body in handlers():
        if not any(fn in body for fn in reaches):
            continue
        checked += 1
        check(f"{name} establishes Cluster management itself",
              any(g in body for g in gates))
    check(f"and there were routes to check ({checked})", checked >= 10)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
