#!/usr/bin/env python3
"""GitOps: the controller chooser, the application page, and the two actions.

The claims worth testing are the ones about consequence:

  * one controller still gets a chooser, so which Argo CD you are looking at is
    never implied
  * a resource tree is built from parentRefs, worst health first
  * Refresh changes nothing and needs no confirmation
  * Sync will not run without the typed word, sends prune only when asked, and
    is in the audit log either way

Runs against a stand-in Argo CD started by this file — no real controller and
no network.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_gitops.py
"""
from __future__ import annotations

import json
import urllib.parse
import re
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("gitops-test-")
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from fastapi.testclient import TestClient                       # noqa: E402

from app import auth, db, gitops, main, store                   # noqa: E402

PASSWORD = "Tests-Are-Cheap-42"
EMAIL = "gitopstester@example.com"
PORT = 8099
bad = 0


def _app_patches(rows) -> list:
    """The application-spec patches the fake recorded, newest last.

    Read over its /__calls endpoint, NOT by importing the module — importing
    `_fake_argocd` STARTS it (the listen is at module level), so an in-process
    import races the subprocess this file already spawned for the same port.
    Walked into once; the error is "Address already in use" from a line that
    looks like it only reads a list.
    """
    out = []
    for c in rows:
        # the APP-SPEC patch only: a resource edit patches
        # /applications/{name}/resource?… and its body is a manifest, not JSON,
        # so a looser match here turned into "'str' has no attribute 'get'"
        if (c[0] == "PATCH" and len(c) > 2
                and c[1].startswith("/api/v1/applications/")
                and "/resource" not in c[1]):
            try:
                out.append(json.loads(json.loads(c[2]).get("patch") or "{}"))
            except (ValueError, TypeError, AttributeError):
                pass
    return out

FAKE = HERE.parent / "tests" / "_fake_argocd.py"


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


def sign_in(client: TestClient) -> str:
    u = auth.by_email(EMAIL)
    uid = u["id"] if u else auth.create_user(EMAIL, "Tester", PASSWORD, role="admin")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    client.post("/login", data={"email": EMAIL, "password": PASSWORD},
                follow_redirects=False)
    code = auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))
    r = client.post("/mfa", data={"code": code}, follow_redirects=False)
    if r.status_code not in (302, 303):
        raise SystemExit(f"MFA step failed: {r.status_code}")
    return uid


def calls() -> list:
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/__calls", timeout=5) as r:
        return json.loads(r.read())


def main_test() -> int:
    proc = subprocess.Popen([sys.executable, str(FAKE), str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            calls()
            break
        except Exception:                                      # noqa: BLE001
            time.sleep(0.1)
    else:
        proc.kill()
        raise SystemExit("the stand-in Argo CD did not start")

    try:
        client = TestClient(main.app)
        with client:
            sign_in(client)
            cid = store.add_gitops("", {
                "type": "argocd", "name": "Argo (test)",
                "base_url": f"http://127.0.0.1:{PORT}", "token": "tok",
                "status": "ok"})

            # ── 1. one controller still gets a chooser ────────────────────
            r = client.get("/gitops")
            check(f"the landing page renders, got {r.status_code}",
                  r.status_code == 200)
            check("it names the controller", "Argo (test)" in r.text)
            check("and does not jump straight into the applications",
                  "acme-api" not in r.text)
            check("it counts what is wrong", "out of sync" in r.text)
            print("  one controller still gets a card, not a silent redirect")

            # ── 2. inside one controller ──────────────────────────────────
            r = client.get(f"/gitops?conn={cid}")
            for want in ("acme-api", "acme-ledger", "OutOfSync", "Degraded",
                         "auto-sync", "self-heal"):
                check(f"the application list shows {want!r}", want in r.text)
            check("with a way back to the controllers",
                  "all controllers" in r.text)
            print("  a controller's applications are cards, with their state on them")

            # ── 3. the application page ───────────────────────────────────
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            check(f"the application page renders, got {r.status_code}",
                  r.status_code == 200)
            for want in ("acme-api", "Deployment", "ReplicaSet", "Pod",
                         "Service", "Ingress", "CrashLoopBackOff",
                         "acme-uat", "SyncError", "envs/uat/api"):
                check(f"the application page shows {want!r}", want in r.text)
            check("the history is there", "aaa111bbb222" in r.text)
            print("  an application shows its tree, its source, its history and "
                  "what the controller is complaining about")

            # the tree itself, in the shape the page draws from
            t = gitops.tree(store.get_gitops("", cid), "acme-api")
            check(f"six resources, got {t['count']}", t["count"] == 6)
            roots = {r["kind"] for r in t["roots"]}
            check(f"two roots, got {roots}", roots == {"Deployment", "Service"})
            rs = t["roots"][0]["children"][0] if t["roots"][0]["kind"] == "ReplicaSet" \
                else next(c for r in t["roots"] for c in r["children"]
                          if c["kind"] == "ReplicaSet")
            pods = [p["health"] for p in rs["children"]]
            check(f"the unhealthy pod is listed first, got {pods}",
                  pods and pods[0] == "Degraded")
            print("  the tree nests by parentRefs and puts the broken thing first")

            # ── 4. Refresh changes nothing, and needs no ceremony ─────────
            before = len(calls())
            r = client.post(f"/gitops/app/refresh?conn={cid}&name=acme-api",
                            follow_redirects=False)
            check(f"refresh redirects back, got {r.status_code}",
                  r.status_code in (302, 303))
            asked = [c for c in calls()[before:] if "refresh=normal" in str(c)]
            check("and it asked the controller to re-read git", asked)
            posted = [c for c in calls()[before:] if c[0] == "POST"]
            check(f"without posting anything, got {posted}", not posted)
            print("  Refresh re-reads git and posts nothing")

            # ── 5. Sync will not go without the word ──────────────────────
            before = len(calls())
            r = client.post(f"/gitops/app/sync?conn={cid}&name=acme-api",
                            data={"confirm": ""}, follow_redirects=True)
            check("a sync without the typed word is refused", "Type sync" in r.text)
            check("and nothing was sent",
                  not [c for c in calls()[before:] if c[0] == "POST"])

            # a dry run needs no word — it changes nothing
            before = len(calls())
            client.post(f"/gitops/app/sync?conn={cid}&name=acme-api",
                        data={"dry": "1"}, follow_redirects=True)
            sent = [c for c in calls()[before:] if c[0] == "POST"]
            check(f"a dry run is sent, got {len(sent)}", len(sent) == 1)
            body = json.loads(sent[0][2])
            check(f"marked as a dry run, got {body}", body.get("dryRun") is True)
            check("and never prunes", body.get("prune") is False)

            # the real thing
            before = len(calls())
            r = client.post(f"/gitops/app/sync?conn={cid}&name=acme-api",
                            data={"confirm": "sync", "prune": "1"},
                            follow_redirects=True)
            body = json.loads([c for c in calls()[before:] if c[0] == "POST"][0][2])
            check(f"a confirmed sync is not a dry run, got {body}",
                  body.get("dryRun") is False)
            check("and prunes only because it was ticked", body.get("prune") is True)
            print("  Sync needs the word typed; prune is opt-in; dry run is free")

            # ── 5b. the sync is watched here, not in Argo CD ──────────────
            # The POST only queues the operation, so the message must not claim
            # a result — it used to read the phase out of the reply, which
            # carries the *previous* operation and said "sync succeeded" before
            # any work had started.
            r = client.post(f"/gitops/app/sync?conn={cid}&name=acme-api",
                            data={"confirm": "sync"}, follow_redirects=False)
            where = r.headers.get("location", "")
            check(f"a sync lands on the page watching it, got {where}",
                  "watch=1" in where)
            check(f"and says it started, not that it worked, got {where}",
                  "started" in where and "succeeded" not in where)

            frag = client.get(f"/gitops/app/op?conn={cid}&name=acme-api")
            check(f"the operation fragment renders, got {frag.status_code}",
                  frag.status_code == 200)
            check("as a fragment", "<html" not in frag.text.lower())
            check("it reports the phase", "Running" in frag.text
                  or "Succeeded" in frag.text)
            check("and names the resources as they land",
                  "acme-api" in frag.text)

            # keep polling until it settles, exactly as the page does
            for _ in range(8):
                frag = client.get(f"/gitops/app/op?conn={cid}&name=acme-api")
                if 'data-running="1"' not in frag.text:
                    break
            check("it reaches a terminal phase",
                  'data-running="1"' not in frag.text)
            check("a resource that failed is shown as failed",
                  "SyncFailed" in frag.text)
            check("with the controller's reason",
                  "admission webhook" in frag.text)
            check("and the failed one is listed first",
                  frag.text.index("SyncFailed") < frag.text.index("unchanged"))
            print("  a sync is followed here — phase, per-resource result and "
                  "the reason it failed")

            # ── 5c. a node of the tree can be opened ──────────────────────
            # A tree you cannot open is a picture. The questions a red dot
            # raises are what the object looks like, what git wanted instead,
            # what happened to it, and what it is saying.
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            # a drawing, not an indented list: boxes joined by elbows, each one
            # a way into the object it stands for
            check("the resources are drawn as a graph",
                  '<svg id="gsvg"' in r.text and 'class="gedge"' in r.text)
            # seven boxes now: the six objects plus the APPLICATION at the
            # root, which is how Argo draws it — a tree of unconnected roots
            # never said what it was a map of
            check("every object box is openable, under the app's own box",
                  r.text.count('class="gnode') == 7
                  and 'data-uid="u-pod-2"' in r.text
                  and 'data-uid="__app__"' in r.text
                  and 'data-app="1"' in r.text)
            g = gitops.graph(gitops.tree(store.get_gitops("", cid), "acme-api"),
                             "acme-api")
            check(f"the app roots the tree, got {len(g['nodes'])}/{len(g['edges'])}",
                  len(g["nodes"]) == 7 and len(g["edges"]) == 6
                  and g["nodes"][0]["is_app"])
            check("and every box carries its age",
                  all(n["age"] for n in g["nodes"] if not n["is_app"]))
            cols = sorted({n["depth"] for n in g["nodes"]})
            # four columns now: app → deployment/service → replicaset → pods
            check(f"laid out in columns by depth, got {cols}",
                  cols == [0, 1, 2, 3])
            dep = next(n for n in g["nodes"] if n["kind"] == "Deployment")
            pods = [n for n in g["nodes"] if n["kind"] == "Pod"]
            check("a parent sits centred against its children",
                  abs(dep["row"] - sum(p["row"] for p in pods) / len(pods)) < 0.01)

            r = client.get(f"/gitops/app/resource?conn={cid}"
                           f"&name=acme-api&uid=u-pod-2")
            check(f"the resource panel renders, got {r.status_code}",
                  r.status_code == 200)
            check("as a fragment", "<html" not in r.text.lower())
            # a crash-looping pod opens on its log, not on a manifest
            # the active tab is the one with .btn rather than .btn-ghost;
            # matched across whitespace because the attributes wrap
            import re as _re
            active = _re.search(r'class="btn restab"\s+data-tab="(\w+)"', r.text)
            check(f"a pod opens on its logs, got {active and active.group(1)}",
                  active and active.group(1) == "logs")
            check("showing what it said",
                  "password authentication failed" in r.text)
            check("with both containers offered",
                  'data-container="api"' in r.text
                  and 'data-container="envoy"' in r.text)

            got = gitops.resource(store.get_gitops("", cid), "acme-api",
                                  gitops.find_node(
                                      gitops.tree(store.get_gitops("", cid),
                                                  "acme-api"), "u-pod-2"))
            check(f"the unready container is the one read, got "
                  f"{got['container']!r}", got["container"] == "api")
            check("the manifest is YAML, not JSON",
                  got["manifest"].startswith("apiVersion:"))
            check("and the noise Kubernetes adds is left out",
                  "managedFields" not in got["manifest"]
                  and "resourceVersion" not in got["manifest"])
            check("a resource that differs from git says so", not got["synced"])
            check("and offers what git wants", "api:1.25.0" in got["diff"])
            check("a warning event sorts above a normal one",
                  got["events"] and got["events"][0]["type"] == "Warning")

            # the log has its own endpoint, so following it does not mean
            # re-rendering the panel and losing the reader's place
            r = client.get(f"/gitops/app/log?conn={cid}&name=acme-api"
                           f"&uid=u-pod-2&container=api")
            check(f"the log is served as plain text, got "
                  f"{r.headers.get('content-type')}",
                  "text/plain" in r.headers.get("content-type", ""))
            check("with the failure in it",
                  "password authentication failed" in r.text)
            first = len(r.text.splitlines())
            again = client.get(f"/gitops/app/log?conn={cid}&name=acme-api"
                               f"&uid=u-pod-2&container=api")
            check(f"and it re-reads rather than replaying a cache, "
                  f"{first} then {len(again.text.splitlines())}",
                  len(again.text.splitlines()) > first)
            r = client.get(f"/gitops/app/log?conn={cid}&name=acme-api"
                           f"&uid=u-svc")
            check(f"asking a Service for a log is refused, got {r.status_code}",
                  r.status_code == 404)

            # a node that is no longer there is said so, not 500
            r = client.get(f"/gitops/app/resource?conn={cid}"
                           f"&name=acme-api&uid=u-vanished")
            check(f"a stale node is explained, got {r.status_code}",
                  r.status_code == 200 and "no longer in the tree" in r.text)
            print("  a node opens on the question it raises — logs for a "
                  "crash-loop, the diff for a drift, events either way")

            # ── 6. all of it is in the audit log ──────────────────────────
            log = [a["action"] for a in
                   db.q("SELECT action FROM audit ORDER BY id DESC LIMIT 30")]
            for want in ("gitops_refresh", "gitops_sync", "gitops_sync_dryrun"):
                check(f"{want} is recorded", want in log)
            print("  every refresh, dry run and sync is in the audit log")

            # ── 7. per-resource actions: edit, yaml and DIFF ──────────────
            # the sync-result rows address a resource by kind/name/namespace —
            # including one the tree no longer holds — and open the panel
            r = client.get(f"/gitops/app/resource?conn={cid}&name=acme-api"
                           f"&rkind=Pod&rname=acme-api-7d9f-fghij"
                           f"&rns=acme-uat&tab=changes")
            check(f"a ref-addressed resource opens ({r.status_code})",
                  r.status_code == 200)
            check("the Diff tab is a REAL line diff, coloured",
                  'class="df-a"' in r.text and 'class="df-r"' in r.text
                  and "cluster (live)" in r.text)
            check("the diff shows the drifted image line",
                  "api:1.25.0" in r.text)
            r = client.get(f"/gitops/app/resource?conn={cid}&name=acme-api"
                           f"&uid=u-pod-2&tab=edit")
            check("the Edit tab holds the live manifest in an editor",
                  "<textarea" in r.text and "acme-api-7d9f-fghij" in r.text
                  and "type apply" in r.text)

            # the edit itself: refused without the word, lands as a PATCH
            # through Argo with it, audited both ways
            edited = ("apiVersion: v1\nkind: Pod\n"
                      "metadata:\n  name: acme-api-7d9f-fghij\n"
                      "  namespace: acme-uat\n"
                      "spec:\n  activeDeadlineSeconds: 300\n")
            form = {"rkind": "Pod", "rname": "acme-api-7d9f-fghij",
                    "rns": "acme-uat", "rgroup": "", "rversion": "v1",
                    "text": edited, "confirm": ""}
            r = client.post(f"/gitops/app/resource/edit?conn={cid}"
                            f"&name=acme-api", data=form,
                            follow_redirects=False)
            check("no typed word, no change",
                  r.status_code == 303 and "Type+apply" in
                  (r.headers.get("location") or ""))
            check("…and nothing reached Argo",
                  not any(m == "PATCH" for m, *rest in calls()))
            r = client.post(f"/gitops/app/resource/edit?conn={cid}"
                            f"&name=acme-api", data={**form,
                            "confirm": "apply"}, follow_redirects=False)
            check("with it, the edit lands", r.status_code == 303
                  and "patched" in (r.headers.get("location") or ""))
            patches = [x for x in calls() if x[0] == "PATCH"]
            check("as a merge patch through Argo's resource API",
                  patches and "patchType=application%2Fmerge-patch%2Bjson"
                  in patches[-1][1]
                  and "activeDeadlineSeconds" in patches[-1][2])
            r = client.post(f"/gitops/app/resource/edit?conn={cid}"
                            f"&name=acme-api", data={**form,
                            "confirm": "apply",
                            "rname": "something-else"},
                            follow_redirects=False)
            check("a manifest whose name does not match the node is refused",
                  "must+match" in (r.headers.get("location") or ""))
            log = [a["action"] for a in
                   db.q("SELECT action FROM audit ORDER BY id DESC LIMIT 30")]
            check("edits are audited", "gitops_edit" in log)
            print("  every resource row offers edit / yaml / diff, and an edit "
                  "is a typed-word, audited merge patch through Argo")

            # ── 8. speed: fewer round-trips, and the rest together ────────
            n_app = sum(1 for m, p, *r in calls() if m == "GET"
                        and p.startswith("/api/v1/applications/acme-api")
                        and "resource-tree" not in p and "resource?" not in p
                        and "managed-resources" not in p and "events" not in p)
            client.get(f"/gitops/app?conn={cid}&name=acme-api")
            n_app2 = sum(1 for m, p, *r in calls() if m == "GET"
                         and p.startswith("/api/v1/applications/acme-api")
                         and "resource-tree" not in p and "resource?" not in p
                         and "managed-resources" not in p and "events" not in p)
            check("the app page reads the application document AT MOST once "
                  "(history used to refetch it; warm it is served from cache)",
                  n_app2 - n_app <= 1)
            gitops.invalidate()
            client.get(f"/gitops/app?conn={cid}&name=acme-api")
            n_cold = sum(1 for m, p, *r in calls() if m == "GET"
                         and p.startswith("/api/v1/applications/acme-api")
                         and "resource-tree" not in p and "resource?" not in p
                         and "managed-resources" not in p and "events" not in p)
            client.get(f"/gitops/app?conn={cid}&name=acme-api")
            n_warm = sum(1 for m, p, *r in calls() if m == "GET"
                         and p.startswith("/api/v1/applications/acme-api")
                         and "resource-tree" not in p and "resource?" not in p
                         and "managed-resources" not in p and "events" not in p)
            check("a warm reload costs ZERO document reads "
                  "(stale-while-revalidate)", n_warm == n_cold)
            n_tree = sum(1 for m, p, *r in calls()
                         if m == "GET" and "resource-tree" in p)
            client.get(f"/gitops/app/resource?conn={cid}"
                       f"&name=acme-api&uid=u-pod-2")
            n_tree2 = sum(1 for m, p, *r in calls()
                          if m == "GET" and "resource-tree" in p)
            check("opening a panel right after the page reuses the tree "
                  "it just drew (10s cache)", n_tree2 == n_tree)

            conn_doc = store.get_gitops("", cid)
            real_req = gitops._req
            nreq = {"n": 0}

            def slow_req(url, headers, verify=True, body=None, method=""):
                nreq["n"] += 1
                time.sleep(0.06)
                return real_req(url, headers, verify, body, method)
            gitops._req = slow_req
            try:
                node = gitops.find_by_ref(gitops.tree(conn_doc, "acme-api"),
                                          "Pod", "acme-api-7d9f-fghij",
                                          "acme-uat")
                nreq["n"] = 0
                t0 = time.monotonic()
                gitops.resource(conn_doc, "acme-api", node)
                wall = time.monotonic() - t0
                floor = nreq["n"] * 0.06
                check(f"a resource's reads run together — {wall:.2f}s wall vs "
                      f"{floor:.2f}s one-after-another ({nreq['n']} calls)",
                      nreq["n"] >= 3 and wall < floor * 0.75)
            finally:
                gitops._req = real_req
            print("  the app page is one document read + the tree, together; "
                  "a panel reuses the tree and asks its questions in parallel")

            # ── 9. the popup is ONE window, and Edit offers git first ─────
            r = client.get(f"/gitops/app/resource?conn={cid}"
                           f"&name=acme-api&uid=u-pod-2&bare=1")
            check("bare mode drops the inner name and Close (the psh bar has "
                  "them) — one window, one close",
                  'id="resclose"' not in r.text
                  and ">acme-api-7d9f-fghij</b>" not in r.text)
            pid_g = store.add_project("GitEditProj")
            rgid_g = store.add_region(pid_g, "UAT")
            # the repository is the ENVIRONMENT's binding now — the resolver
            # matches Argo's repoURL against each environment's own url
            store.set_env_source(pid_g, rgid_g, "uat",
                                 {"url": "https://git.example.com/acme/deploy.git",
                                  "branch": "", "path": "envs/uat"})
            real_envs = main.repo.list_envs
            main.repo.list_envs = (lambda pid, rgid, include_hidden=False:
                                   {"uat": ["envs~uat~api~api-values.yaml"]})
            try:
                r = client.get(f"/gitops/app/resource?conn={cid}"
                               f"&name=acme-api&uid=u-pod-2&tab=edit&bare=1"
                               f"&arepo=https://git.example.com/acme/deploy.git"
                               f"&apath=envs/uat/api")
                check("a registered repo resolves to the portal's own editor",
                      "Edit in git" in r.text
                      and "/p/" + pid_g + "/" + rgid_g + "/uat/s/" in r.text
                      and "GitEditProj" in r.text)
            finally:
                main.repo.list_envs = real_envs
            r = client.get(f"/gitops/app/resource?conn={cid}"
                           f"&name=acme-api&uid=u-pod-2&tab=edit&bare=1"
                           f"&arepo=https://elsewhere.example.com/x.git"
                           f"&apath=envs/uat/api")
            check("an unregistered repo says so instead of pretending",
                  "not registered in this portal" in r.text)
            check("the resolver itself returns None for the unknown",
                  main._git_editor_for("https://elsewhere.example.com/x.git",
                                       "envs/uat/api") is None)
            print("  the popup is one window; Edit offers git (the durable "
                  "fix) before the live patch")

            # ── 10. everything Argo CD can do, that this page now can ─────
            conn_d = store.get_gitops("", cid)
            node = gitops.find_by_ref(gitops.tree(conn_d, "acme-api"),
                                      "Pod", "acme-api-7d9f-fghij",
                                      "acme-uat")
            acts = gitops.resource_actions(conn_d, "acme-api", node)
            check("the controller's own actions are read, not hardcoded",
                  [a["name"] for a in acts] == ["restart", "pause"]
                  and acts[0]["label"] == "Restart" and acts[1]["disabled"])
            r = client.post(f"/gitops/app/resource/action?conn={cid}"
                            f"&name=acme-api",
                            data={"rkind": "Pod",
                                  "rname": "acme-api-7d9f-fghij",
                                  "rns": "acme-uat", "rversion": "v1",
                                  "action": "restart"},
                            follow_redirects=False)
            check("running one posts the action NAME as the body",
                  r.status_code == 303
                  and any(m == "POST" and "/resource/actions" in p
                          and body.strip() == '"restart"'
                          for m, p, *rest in calls() for body in [rest[0] if rest else ""]))

            r = client.post(f"/gitops/app/resource/delete?conn={cid}"
                            f"&name=acme-api",
                            data={"rkind": "Pod", "rname": "acme-api-7d9f-fghij",
                                  "rns": "acme-uat", "rversion": "v1",
                                  "confirm": ""}, follow_redirects=False)
            check("a delete without the typed word does nothing",
                  "Type+delete" in (r.headers.get("location") or "")
                  and not any(m == "DELETE" and "/resource?" in p
                              for m, p, *rest in calls()))
            r = client.post(f"/gitops/app/resource/delete?conn={cid}"
                            f"&name=acme-api",
                            data={"rkind": "Pod", "rname": "acme-api-7d9f-fghij",
                                  "rns": "acme-uat", "rversion": "v1",
                                  "confirm": "delete", "orphan": "1"},
                            follow_redirects=False)
            check("with it, the object is deleted and children orphaned",
                  r.status_code == 303
                  and any(m == "DELETE" and "orphan=true" in p
                          for m, p, *rest in calls()))

            r = client.post(f"/gitops/app/rollback?conn={cid}&name=acme-api",
                            data={"id": "41", "confirm": ""},
                            follow_redirects=False)
            check("a rollback without the typed word does nothing",
                  "Type+rollback" in (r.headers.get("location") or ""))
            r = client.post(f"/gitops/app/rollback?conn={cid}&name=acme-api",
                            data={"id": "41", "confirm": "rollback"},
                            follow_redirects=False)
            check("with it, Argo is asked to roll back BY HISTORY ID",
                  r.status_code == 303
                  and any(m == "POST" and p.endswith("/rollback")
                          and '"id": 41' in (rest[0] if rest else "")
                          for m, p, *rest in calls()))

            r = client.post(f"/gitops/app/terminate?conn={cid}&name=acme-api",
                            follow_redirects=False)
            check("terminate deletes the operation",
                  r.status_code == 303
                  and any(m == "DELETE" and p.endswith("/operation")
                          for m, p, *rest in calls()))

            # the app-wide review, and a SELECTIVE sync out of it
            d = gitops.app_diff(conn_d, "acme-api")
            states = {r["name"]: r["state"] for r in d["rows"]}
            check("the review names what each change IS",
                  states.get("acme-api-new") == "missing"
                  and states.get("acme-api-orphan") == "extra"
                  and states.get("acme-api-7d9f-fghij") == "changed")
            check("and carries a real line diff",
                  any("api:1.25.0" in r["diff"] for r in d["rows"]))
            r = client.get(f"/gitops/app/diff?conn={cid}&name=acme-api")
            check(f"the review renders ({r.status_code})",
                  r.status_code == 200 and "not in git" in r.text
                  and "Sync selected" in r.text)
            r = client.post(f"/gitops/app/sync?conn={cid}&name=acme-api",
                            data={"confirm": "sync",
                                  "res": ["|ConfigMap|acme-api-new|acme-uat"]},
                            follow_redirects=False)
            syncs = [x for x in calls() if x[0] == "POST" and x[1].endswith("/sync")]
            check("a selective sync sends ONLY the chosen resource",
                  '"resources"' in syncs[-1][2]
                  and "acme-api-new" in syncs[-1][2]
                  and "acme-api-7d9f-fghij" not in syncs[-1][2])

            # what the source is rendered with, and the app's own events
            ev = gitops.app_events(conn_d, "acme-api")
            check("the application's own events are read",
                  ev and ev[0]["reason"] == "OperationFailed")
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            check("the page shows them, and the resource list + filters",
                  "OperationFailed" in r.text and 'id="gfind"' in r.text
                  and 'id="glist"' in r.text and "App diff" in r.text)
            check("the toolbar is Argo CD's own, in its words",
                  all(w in r.text for w in ("App details", "Sync status",
                                            "History and rollback",
                                            "Hard refresh", "Dry run"))
                  and 'id="gappdelBtn"' in r.text)
            check("the three cards lead with health, sync and the last sync",
                  "App health" in r.text and "Sync status" in r.text
                  and "Last sync" in r.text
                  and "Auto sync is enabled" in r.text)
            # The rail lives on the applications list now — on the app page
            # the map IS the page, and the same four filters ride in its own
            # toolbar with their counts in the option labels.
            check("the map's toolbar filters by name, kind, sync and health "
                  "without taking width from the diagram",
                  all(f'id="{i}"' in r.text
                      for i in ("gfind", "gfkind", "gfsync", "gfhealth",
                                "gfclear"))
                  and "OutOfSync" in r.text
                  and 'class="arail"' not in r.text)
            tr = gitops.tree(store.get_gitops("", cid), "acme-api")
            check("per-node sync state comes from status.resources — the tree "
                  "does not carry it",
                  tr["by_sync"] == {"OutOfSync": 1, "Synced": 1}
                  and next(n["sync"] for n in tr["flat"]
                           if n["kind"] == "Service") == "Synced")
            log = [a["action"] for a in
                   db.q("SELECT action FROM audit ORDER BY id DESC LIMIT 40")]
            for want in ("gitops_resource_action", "gitops_resource_delete",
                         "gitops_rollback", "gitops_terminate"):
                check(f"{want} is audited", want in log)
            print("  actions, delete, rollback, terminate, the whole-app review "
                  "and selective sync — all here, all audited")

            # ── 11. the panel's Summary, and deleting the app itself ──────
            # u-pod-1, not u-pod-2: the restart in the section above retired
            # that one, which is what a rollout does
            r = client.get(f"/gitops/app/resource?conn={cid}"
                           f"&name=acme-api&uid=u-pod-1&tab=summary&bare=1")
            check("Summary leads with the facts, Argo's order",
                  r.status_code == 200 and ">Kind<" in r.text
                  and ">Namespace<" in r.text and ">Status<" in r.text
                  and "acme-uat" in r.text)
            check("the manifest is line-numbered like Argo's editor",
                  'class="ln"' in client.get(
                      f"/gitops/app/resource?conn={cid}&name=acme-api"
                      f"&uid=u-pod-1&tab=manifest&bare=1").text)
            check("the desired manifest is its own tab, in Argo's words",
                  "Desired manifest" in r.text)

            # deleting the application needs its OWN NAME typed, not "delete"
            r = client.post(f"/gitops/app/delete?conn={cid}&name=acme-api",
                            data={"confirm": "delete", "cascade": "1"},
                            follow_redirects=False)
            check("a generic word does not delete an application",
                  "Type+acme-api" in (r.headers.get("location") or "")
                  and not any(m == "DELETE" and p.endswith("/applications/acme-api")
                              for m, p, *rest in calls()))
            r = client.post(f"/gitops/app/delete?conn={cid}&name=acme-api",
                            data={"confirm": "acme-api", "cascade": "1"},
                            follow_redirects=False)
            check("its own name does, and cascade is on the wire",
                  r.status_code == 303
                  and any(m == "DELETE" and "cascade=true" in p
                          for m, p, *rest in calls()))
            log = [a["action"] for a in
                   db.q("SELECT action FROM audit ORDER BY id DESC LIMIT 20")]
            check("and it is audited", "gitops_app_delete" in log)
            print("  the panel leads with Summary; deleting the app takes its "
                  "own name, cascades knowingly, and is audited")

            # ── 12. the DIAGRAM is the page ───────────────────────────────
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            body = r.text
            check("the sync-result table and conditions card are gone from the "
                  "page — what a sync did shows on the map",
                  'id="opwatch"' not in body
                  and "What the controller is saying" not in body)
            check("the graph is its own surface, not a card",
                  'class="gsurface"' in body and 'id="ggraph"' in body)
            check("every elbow has a FLOWING copy",
                  body.count('class="gflow"') == body.count('class="gedge"')
                  and body.count('class="gflow"') > 0)
            check("boxes are coloured by resource family, with a legend",
                  "gk-workload" in body and "gk-network" in body
                  and 'class="glegend"' in body)
            # every OBJECT gets a ⋮; the application's own box does not —
            # it is not a cluster object and its actions are the toolbar's
            check("every object box carries a ⋮ and the menu it opens",
                  body.count('class="gkebab"') == body.count('class="gnode') - 1
                  and 'id="gmenu"' in body and 'data-gm="restart"' in body
                  and 'data-gm="delete"' in body
                  and 'data-gm="syncone"' in body)
            check("an action opens the house dialog, and only DELETE asks you "
                  "to type — a restart is one click",
                  'id="gactDlg"' in body and "verb: 'Restart'" in body
                  and "typed: 'delete'" in body
                  and "if (!confirm('Restart" not in body)
            check("the map is PATCHED, never re-created — a full swap every "
                  "two seconds re-ran the enter animation and blinked",
                  "PATCH, never replace" in body
                  and "pan.innerHTML = got.inner" not in body)
            check("a workload is marked restartable, a Service is not",
                  'data-kind="Deployment"' in body
                  and re.search(r'data-kind="Deployment"[^>]*data-restart="1"',
                                body, re.S) is not None)
            check("and the map paints itself from the operation as DATA",
                  "/gitops/app/op.json" in body and 'id="gopbar"' in body)
            check("every box wears its family's icon",
                  body.count('class="gicon"') == body.count('class="gnode')
                  and 'class="ic ' in body)
            check("only a WATCHING poll may reload — the paint-on-load one must "
                  "not, or the page reloads for ever",
                  "if (wasWatching) setTimeout" in body)

            j = client.get(f"/gitops/app/op.json?conn={cid}&name=acme-api")
            check(f"op.json answers with the resources to mark ({j.status_code})",
                  j.status_code == 200 and "resources" in j.json()
                  and "running" in j.json())

            g = gitops.graph(gitops.tree(store.get_gitops("", cid), "acme-api"))
            fam = {n["kind"]: n["family"] for n in g["nodes"]}
            check("families map by kind, and an unknown kind is 'other'",
                  fam.get("Deployment") == "workload"
                  and fam.get("Service") == "network"
                  and fam.get("Pod") == "pod"
                  and gitops.KIND_FAMILY.get("SomethingNobodyHasHeardOf",
                                             "other") == "other")
            # the map is re-read and the DIFFERENCE animated: a restart must
            # be visible as a pod arriving and the old one draining
            r = client.get(f"/gitops/app/graph.json?conn={cid}"
                           f"&name=acme-api")
            check(f"the map has its own live endpoint ({r.status_code})",
                  r.status_code == 200 and "inner" in r.json()
                  and 'class="gnode' in r.json()["inner"]
                  and r.json()["width"] > 0)
            before = {m for m in re.findall(r'data-uid="([^"]+)"',
                                            r.json()["inner"])}
            client.post(f"/gitops/app/resource/action?conn={cid}"
                        f"&name=acme-api",
                        data={"rkind": "Deployment", "rname": "acme-api",
                              "rns": "acme-uat", "rversion": "v1",
                              "rgroup": "apps", "action": "restart"},
                        follow_redirects=False)
            # a rolling update takes a few beats: the new pod appears while
            # the old one is still Terminating, exactly as the page watches it
            for _ in range(4):
                r2 = client.get(f"/gitops/app/graph.json?conn={cid}"
                                f"&name=acme-api&fresh=1")
                after = {m for m in re.findall(r'data-uid="([^"]+)"',
                                               r2.json()["inner"])}
                if after - before and before - after:
                    break
            check("after a restart the map really changes — a box appears and "
                  "one goes, which is what the animation shows",
                  after - before and before - after)
            check("the live partial is the SAME one the page draws (one source)",
                  "_gitops_graph.html" in open(
                      "templates/gitops_app.html").read())
            check("boxes carry an inner group, so a CSS scale cannot replace "
                  "the SVG translate and fling every box to the origin",
                  'class="gin"' in r2.json()["inner"])
            page = open("templates/gitops_app.html").read()
            # A rollout changes the LAYOUT SIZE. The camera is a transform on
            # #gpan and the <svg> is deliberately 100%/no-viewBox, so a refresh
            # must update the canvas dimensions and re-fit — held as consts,
            # the next fit used the old size and pushed the whole tree out of
            # sight (measured: 1 of 7 boxes left on the canvas).
            check("the canvas size is mutable, not baked in",
                  "let NW = " in page and "let NH" not in page.replace("let NW = ", ""))
            check("a live refresh updates it and re-fits",
                  "NW = got.width" in page and "if (!viewTouched) fit();" in page)
            check("and it never writes pixel width/height/viewBox onto the svg, "
                  "which is what broke the camera",
                  "svg.setAttribute('viewBox', `0 0 ${got.width}" not in page)
            check("a reader who panned or zoomed keeps their own view",
                  "viewTouched = true" in page)
            print("  the diagram is the page: flowing arrows, a colour per "
                  "family, a ⋮ per box, the sync painted on the boxes, and a "
                  "restart animated as pods arriving and draining")

            # ── 13. a rollout the reader can actually read ────────────────
            # "progressing" is true of a pod pulling an image, one waiting for
            # a node and one crash-looping. The box has to say WHICH, and the
            # pod on its way out has to say it is going — both are in the same
            # payload Argo already sent.
            c = store.get_gitops("", cid)
            gitops.drop(c, "acme-api")
            tr = gitops.tree(c, "acme-api")
            pods = {n["name"]: n for n in tr["flat"] if n["kind"] == "Pod"}
            check("a pod's real phase is carried, not just Argo's health word",
                  any(p.get("phase") for p in pods.values())
                  and pods["acme-api-7d9f-abcde"]["phase"] == "Running")
            g = gitops.graph(tr, "acme-api", "Healthy", "Synced")
            box = next(n for n in g["nodes"]
                       if n["name"] == "acme-api-7d9f-abcde")
            check("and it reaches the diagram, with its readiness",
                  box["phase"] == "Running" and box["terminating"] is False)
            # restart, then read the tree the way the page polls it
            client.post(f"/gitops/app/resource/action?conn={cid}"
                        f"&name=acme-api",
                        data={"rkind": "Deployment", "rname": "acme-api",
                              "rns": "acme-uat", "rversion": "v1",
                              "rgroup": "apps", "action": "restart"},
                        follow_redirects=False)
            seen = []
            for _ in range(4):
                r = client.get(f"/gitops/app/graph.json?conn={cid}"
                               f"&name=acme-api&fresh=1")
                seen.append(r.json()["inner"])
            first, later = seen[0], seen[-1]
            check("the box of an arriving pod names the step it is on, not the "
                  "word \"progressing\"",
                  ("Pending" in first or "ContainerCreating" in first)
                  and "0/1" in first)
            check("a pod being deleted says terminating and is drawn draining",
                  "terminating" in first and "gdrain" in first)
            check("and once it has settled the box says so on its own — no "
                  "reload, which is what left it stuck on \"progressing\"",
                  "Running · 1/1" in later
                  and "ContainerCreating" not in later)
            check("in-flight is not painted as broken",
                  "gwork" in first and ".gwork" in open(
                      "templates/gitops_app.html").read())
            page = open("templates/gitops_app.html").read()
            check("the content of a box is replaced wholesale when it changes, "
                  "because the third line changes ELEMENT as a pod settles",
                  "mineIn.innerHTML = freshIn.innerHTML" in page)
            check("the watcher stops when the rollout SETTLES, not on a "
                  "stopwatch that could expire mid-rollout",
                  "const unsettled" in page and "quiet >= 3" in page)
            print("  a rollout reads as one: Pending → ContainerCreating → "
                  "Running on the new box, terminating on the old, settled "
                  "without a reload")

            # ── 14. the resource panel is a drawer, and behaves like one ──
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            check("clicking a box opens a right-hand drawer, not a popup over "
                  "the map",
                  'id="resDrawer"' in r.text and 'id="resDlg"' not in r.text
                  and "class=\"sdrawer wide\"" in r.text)
            check("with every action for that object in its own header",
                  "resDrawerActs" in r.text and "window.gnodeAct" in page)
            check("one drawer behaviour: a scrim to click away, a working ✕, "
                  "Escape, and an edge to drag",
                  all(x in page for x in ("sdrawer-scrim", "sdrawer-grip",
                                          "window.gdrawerOpen",
                                          "col-resize", "gdrawer-w-"))
                  and page.count("querySelectorAll('.psh-x, [data-sclose]')") == 1)
            check("the map is laid out at its full height and the PAGE scrolls",
                  "function sizeBox" in page and "height:auto; min-height:360px"
                  in page and "calc(100vh - 300px)" not in page)
            print("  the panel is a drawer: click away, drag it wider, and the "
                  "map keeps the whole page")

            # ── 15. the applications list, as tiles ───────────────────────
            r = client.get(f"/gitops?conn={cid}")
            check("applications are tiles carrying what Argo's own list shows",
                  all(w in r.text for w in ("atile", "Target&nbsp;revision",
                                            "Destination", "Namespace",
                                            "Repository"))
                  and "class=\"arail\"" in r.text)
            check("twelve to a page, and the rail is exactly that many rows "
                  "tall so the two columns end on the same line",
                  "const PER = 12" in r.text and "--arows:" in r.text
                  and "--ath:" in r.text)
            check("a tile's delete opens the application's own page, where the "
                  "confirm can ask for its name — sync is a drawer here now, "
                  "which section 16 covers",
                  "&del=1" in r.text and "p.get('del') === '1'" in page)
            print("  the applications list is Argo's own: a filter rail with "
                  "live counts and twelve tiles to a page")

            # ── 16. the list page: one click per intent ───────────────────
            r = client.get(f"/gitops?conn={cid}")
            check("the WHOLE tile opens the application, not only its title — "
                  "an <a> cannot wrap the buttons, so the link stretches over "
                  "the card and the footer sits above it",
                  'class="atile-h stretch"' in r.text
                  and ".atile-h.stretch::after" in r.text
                  and ".atile-b, .atile-f { position:relative; z-index:1; }"
                  in r.text)
            check("sync from a tile opens a DRAWER rather than navigating to "
                  "the application page to reveal one",
                  'class="abtn asyncbtn"' in r.text
                  and "&sync=1" not in r.text
                  and 'id="listDrawer"' in r.text)
            r2 = client.get(f"/gitops/app/sync/panel?conn={cid}&name=acme-api")
            check(f"and the panel it fetches is the REAL one ({r2.status_code})",
                  r2.status_code == 200 and 'id="syncForm"' in r2.text
                  and 'name="prune"' in r2.text and 'name="res"' in r2.text)
            check("which is the same partial the application page includes, so "
                  "the options cannot differ by where somebody started",
                  '{% include "_gitops_sync.html" %}' in
                  open("templates/gitops_app.html").read())
            r2 = client.get(f"/gitops/app/sync/panel?conn=nope&name=x")
            check("an unknown controller answers 409 so the page reloads "
                  "rather than rendering an empty drawer",
                  r2.status_code == 409)

            print("  the list opens the app from anywhere on the tile, and "
                  "syncs from a drawer without leaving the page")

            # ── 17. Argo CD's own settings, from the rail ─────────────────
            c = store.get_gitops("", cid)
            got = gitops.settings_view(c)
            check("the rail reads Argo's repositories, clusters and projects",
                  got["repos"] and got["clusters"] and got["projects"]
                  and got["repos"][0]["state"] == "Successful")
            check("a project carries what it permits, so the rail can filter "
                  "to it", any(p["name"] == "payments" for p in got["projects"]))
            r = client.get(f"/gitops?conn={cid}")
            check("the rail offers them", "repositories, clusters, projects"
                  in r.text and 'id="argoDrawer"' in r.text)
            check("and each project links to the list filtered to it",
                  "&project=payments" in r.text)

            before = len(gitops.repos(c))
            r = client.post(f"/gitops/repo/add?conn={cid}",
                            data={"url": "https://git.example.com/new/one.git",
                                  "username": "ci", "password": "s3cret"},
                            follow_redirects=False)
            check(f"a repository can be registered from here ({r.status_code})",
                  r.status_code == 303 and len(gitops.repos(c)) == before + 1)
            r = client.post(f"/gitops/repo/add?conn={cid}",
                            data={"url": "https://git.example.com/two.git",
                                  "username": "ci", "password": ""},
                            follow_redirects=False)
            said = urllib.parse.unquote_plus(r.headers.get("location", ""))
            check("Argo validated the credential as part of the call, so a "
                  "wrong one is refused HERE rather than turning up later as a "
                  "failing sync",
                  "err=" in said and "rejected" in said)
            r = client.post(f"/gitops/repo/add?conn={cid}",
                            data={"url": "https://git.example.com/acme/deploy.git"},
                            follow_redirects=False)
            check("and one Argo already holds is refused rather than added twice",
                  "already exists" in urllib.parse.unquote_plus(
                      r.headers.get("location", "")))
            r = client.post(f"/gitops/repo/add?conn={cid}",
                            data={"url": "http://169.254.169.254/creds"},
                            follow_redirects=False)
            check("and an address the URL guard refuses comes back as a "
                  "refusal, not a 500 — the module raises its own error type",
                  r.status_code == 303 and "err=" in urllib.parse.unquote_plus(
                      r.headers.get("location", "")))
            check("the credential never reaches the audit line — only the URL",
                  not any("s3cret" in (a.get("detail") or "")
                          + (a.get("target") or "")
                          for a in auth.read_audit(limit=40)))
            r = client.post(f"/gitops/repo/remove?conn={cid}",
                            data={"url": "https://git.example.com/new/one.git",
                                  "confirm": "wrong"}, follow_redirects=False)
            check("removing one needs its URL typed — applications on it stop "
                  "syncing",
                  "type the repository URL" in urllib.parse.unquote_plus(
                      r.headers.get("location", "")))
            r = client.post(
                f"/gitops/repo/remove?conn={cid}",
                data={"url": "https://git.example.com/new/one.git",
                      "confirm": "https://git.example.com/new/one.git"},
                follow_redirects=False)
            check("and with it typed, it goes",
                  r.status_code == 303 and len(gitops.repos(c)) == before)
            print("  Argo CD's repositories, clusters and projects are in the "
                  "rail, and a repository can be registered without leaving")

            # ── 18. the application's own sync policy ─────────────────────
            r = client.get(f"/gitops/app?conn={cid}&name=acme-api")
            check("the toolbar spans the page rather than hugging its left edge",
                  ".atools > .atool, .atools > .arefresh { flex:1 1 auto; }"
                  in r.text)
            check("and it offers the application's own settings",
                  'id="gpolicyBtn"' in r.text and 'id="policyPanel"' in r.text)
            note = gitops.set_sync_policy(c, "acme-api", False, False, False)
            check("auto-sync can be turned off, and says what that means",
                  "disabled" in note and "until somebody syncs" in note)
            patched = _app_patches(calls())[-1]
            check("turning it off sends NULL, not an empty object — an empty "
                  "`automated: {}` still reads as ON to the controller",
                  patched["spec"]["syncPolicy"]["automated"] is None)
            check("and the application reads as manual afterwards, which is "
                  "the observable half of the same claim",
                  gitops.app_view(c, "acme-api")[0]["auto"] is False)
            note = gitops.set_sync_policy(c, "acme-api", True, True, True)
            patched = _app_patches(calls())[-1]
            check("and turning it on carries prune and self-heal",
                  patched["spec"]["syncPolicy"]["automated"] ==
                  {"prune": True, "selfHeal": True}
                  and "prune" in note and "self-heal" in note)
            check("which the application then reports",
                  gitops.app_view(c, "acme-api")[0]["auto"] is True)
            r = client.post(f"/gitops/app/policy?conn={cid}&name=acme-api",
                            data={"automated": "1", "self_heal": "1"},
                            follow_redirects=False)
            check(f"the route saves it and audits it ({r.status_code})",
                  r.status_code == 303
                  and any(a["action"] == "gitops_policy"
                          for a in auth.read_audit(limit=20)))
            print("  an application's auto-sync, self-heal and prune are "
                  "settable here, through the controller, audited")

            # ── 19. a controller that has gone ────────────────────────────
            r = client.get("/gitops/app?conn=nope&name=x", follow_redirects=False)
            check("an unknown controller redirects rather than raising",
                  r.status_code == 303)
    finally:
        proc.kill()

    print("\nFAILED" if bad else "\nOK")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main_test())
