#!/usr/bin/env python3
"""The 3D cluster view: what app/scene.py says about a cluster, who may ask for
it, and where static/cluster3d.js stands everything.

WHY THIS EXISTS
    The page is a picture, and a picture is believed. So the things it must
    never get wrong are the ones nobody would think to check by looking:

      1. **A cluster that did not answer is not an empty cluster.** No pods and
         "could not ask" would draw the same clean stage.
      2. **A line is drawn only between things that are connected.** A Service
         selects pods in its own namespace; a bare name in a config value
         resolves only in the namespace of the pod holding it.
      3. **No limit is not a limit of nothing**, and a limit only some of the
         containers carry does not bound the pod.
      4. **A config value never leaves the server.** The scan reads plain env
         values, which is where a password sits when nobody used a Secret.
      5. **Reading it is the clusters area, cut to the role's clusters**, like
         the pod table it is another view of.
      6. **A crash loop is not healthy while it happens to be up.** Between
         two crashes the cluster's own words are all good news (Running, ready
         1/1), and a view whose goal is "every pod healthy" could be won by
         looking in the right second.
      7. **A pod's voice is not the cluster's verdict.** The doctor of the walk
         speaks for the pod it examines; a line in the pod's voice closes no
         call and heals nothing.

    The cluster is answered at cluster.py's two kubectl calls with
    kubectl-shaped documents, so the parts scene.py borrows (nodes, storage,
    network) run for real.

    ./.venv/bin/python tests/test_scene.py
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("scene-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, rbac, scene, store             # noqa: E402
from app import cluster as clusterview                         # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0
PASSWORD_IN_ENV = "hunter2-do-not-leak"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def pod(ns, name, node="n1", labels=None, owner=None, phase="Running",
        state=None, ready=True, restarts=0, cons=None, env=None, volumes=None,
        conds=None, env_from=None, last=None):
    cons = cons if cons is not None else [("100m", "500m", "128Mi", "256Mi")]
    containers = []
    for i, (cr, cl, mr, ml) in enumerate(cons):
        res = {"requests": {}, "limits": {}}
        if cr: res["requests"]["cpu"] = cr
        if cl: res["limits"]["cpu"] = cl
        if mr: res["requests"]["memory"] = mr
        if ml: res["limits"]["memory"] = ml
        containers.append({"name": f"c{i}", "image": f"registry.example.com/team/{name}:1",
                           "resources": res,
                           "env": [{"name": k, "value": v} for k, v in (env or {}).items()],
                           "envFrom": [{"configMapRef": {"name": m}} for m in (env_from or [])]})
    return {"metadata": {"namespace": ns, "name": name, "labels": labels or {},
                         "creationTimestamp": "2026-01-01T00:00:00Z",
                         "ownerReferences": owner or []},
            "spec": {"nodeName": node, "containers": containers, "volumes": volumes or []},
            "status": {"phase": phase, "qosClass": "Burstable", "podIP": "10.0.0.9",
                       "conditions": conds or [{"type": "PodScheduled", "status": "True"}],
                       "containerStatuses": [] if state is None and phase == "Pending" and not ready and conds else
                       [{"name": "c0", "ready": ready, "restartCount": restarts, "state": state or {"running": {}},
                         **({"lastState": {"terminated": last}} if last else {})}]}}


def ended(ago: int, ran: int, reason: str = "Error", code: int = 1) -> dict:
    """How a container's previous run ended, as the kubelet keeps it."""
    def at(t):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    now = time.time()
    return {"reason": reason, "exitCode": code, "startedAt": at(now - ago - ran), "finishedAt": at(now - ago)}


RS = [{"kind": "ReplicaSet", "name": "web-7d9f8b6c5"}]
PODS = [
    pod("shop", "web-7d9f8b6c5-aaaaa", labels={"app": "web"}, owner=RS,
        env={"API_URL": "http://api:8080/v1", "DB": "postgres://db.data.svc.cluster.local:5432/x",
             "CACHE": "cache.data", "ELSEWHERE": "only-in-other", "DB_PASSWORD": PASSWORD_IN_ENV,
             "SELF": "http://web:80"},
        env_from=["web-config"]),
    pod("shop", "web-7d9f8b6c5-bbbbb", labels={"app": "web"}, owner=RS,
        state={"waiting": {"reason": "CrashLoopBackOff"}}, ready=False, restarts=9),
    pod("shop", "api-0", labels={"app": "api"}, owner=[{"kind": "StatefulSet", "name": "api"}],
        cons=[("100m", "200m", "64Mi", "100Mi")],
        volumes=[{"name": "d", "persistentVolumeClaim": {"claimName": "api-data"}}]),
    pod("shop", "oom", state={"terminated": {"reason": "OOMKilled"}}, ready=False),
    pod("shop", "nolimits", cons=[("50m", None, None, None)]),
    pod("shop", "half", cons=[("50m", "100m", "64Mi", "128Mi"), (None, None, None, None)]),
    pod("shop", "unready", ready=False),
    pod("shop", "creating", phase="Pending", state={"waiting": {"reason": "ContainerCreating"}}, ready=False),
    pod("shop", "stuck", node="", phase="Pending", ready=False,
        conds=[{"type": "PodScheduled", "status": "False", "reason": "Unschedulable"}]),
    pod("shop", "finished", phase="Succeeded", state={"terminated": {"reason": "Completed"}}, ready=False),
    # the same labels as `web`, in another namespace: the shop Service must not claim it
    pod("other", "web-lookalike", labels={"app": "web"}),
    pod("other", "only-in-other-0", labels={"app": "only-in-other"}),
    pod("data", "db-0", labels={"app": "db"}, owner=[{"kind": "StatefulSet", "name": "db"}]),
    pod("data", "cache-0", labels={"app": "cache"}),
    pod("data", "mq-0", labels={"app": "mq"}),
    # Running and ready this minute, like every crash loop between two crashes
    pod("shop", "looper", restarts=58926, last=ended(40, 20)),
    # and three that are NOT loops: a long run that ended, an old fall, a second fall
    pod("shop", "oldfall", restarts=5, last=ended(300, 30 * 86400, "OOMKilled", 137)),
    pod("shop", "longago", restarts=12, last=ended(7200, 20)),
    pod("shop", "twice", restarts=2, last=ended(40, 20)),
]
METRICS = [{"metadata": {"namespace": "shop", "name": "api-0"},
            "containers": [{"usage": {"cpu": "20m", "memory": "95Mi"}}]}]    # 95 of 100Mi: hot


def svc(ns, name, sel):
    return {"metadata": {"namespace": ns, "name": name},
            "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.1", "selector": sel,
                     "ports": [{"port": 8080}]}, "status": {}}


DOCS = {
    "pods": {"items": PODS},
    "nodes": {"items": [{"metadata": {"name": "n1", "creationTimestamp": "2026-01-01T00:00:00Z", "labels": {}},
                         "spec": {}, "status": {"allocatable": {"cpu": "4", "memory": "8Gi"},
                                                "capacity": {"cpu": "4", "memory": "8Gi", "pods": "110"},
                                                "conditions": [{"type": "Ready", "status": "True"}],
                                                "addresses": [], "nodeInfo": {}}}]},
    "svc": {"items": [svc("shop", "web", {"app": "web"}), svc("shop", "api", {"app": "api"}),
                      svc("shop", "ghost", {"app": "nobody"}), svc("shop", "outside", {}),
                      svc("other", "only-in-other", {"app": "only-in-other"}),
                      svc("data", "db", {"app": "db"}), svc("data", "cache", {"app": "cache"}),
                      svc("data", "mq", {"app": "mq"})]},
    "ingress": {"items": [{"metadata": {"namespace": "shop", "name": "front"},
                           "spec": {"tls": [{"hosts": ["shop.example.com"]}], "rules": [{"host": "shop.example.com", "http": {"paths": [
                               {"backend": {"service": {"name": "web", "port": {"number": 80}}}},
                               {"backend": {"service": {"name": "gone", "port": {"number": 80}}}}]}}]}}]},
    "pvc": {"items": [{"metadata": {"namespace": "shop", "name": "api-data", "creationTimestamp": "2026-01-01T00:00:00Z"},
                       "spec": {"storageClassName": "fast", "resources": {"requests": {"storage": "10Gi"}}},
                       "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}}}]},
    # what owns the pods, each marked the way its tool marks it. The kubectl
    # annotation holds a whole manifest: its CONTENT must never reach the answer
    "deployments,statefulsets,daemonsets,cronjobs,jobs": {"items": [
        {"kind": "Deployment", "metadata": {"namespace": "shop", "name": "web", "annotations": {
            "argocd.argoproj.io/tracking-id": "shop-app:apps/Deployment:shop/web"}}},
        {"kind": "StatefulSet", "metadata": {"namespace": "shop", "name": "api", "labels": {
            "app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "shopapp"},
            "annotations": {"meta.helm.sh/release-name": "shopapp"}}},
        {"kind": "StatefulSet", "metadata": {"namespace": "data", "name": "db", "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": '{"env": "%s"}' % PASSWORD_IN_ENV}}}]},
    "configmaps": {"items": [{"metadata": {"namespace": "shop", "name": "web-config"},
                              "data": {"application.yaml": "queue:\n  brokers: mq.data.svc:5672\n"}},
                             # the same name in another namespace is not the one the pod loads
                             {"metadata": {"namespace": "other", "name": "web-config"},
                              "data": {"x": "only-in-other.other.svc"}}]},
}
DOWN = False


def fake_get(cluster, *args, timeout=18):
    if DOWN:
        return None
    return DOCS.get(args[0], {"items": []} if args[0] in ("pv", "storageclass") else None)


def fake_raw(cluster, path, timeout=12):
    return {"items": METRICS} if path.endswith("v1beta1/pods") and not DOWN else None


clusterview._get, clusterview._raw = fake_get, fake_raw


def test_scene() -> dict:
    print("the scene of a cluster")
    clusterview.invalidate()
    got = scene.collect({"id": "c-test", "context": "x"}, refresh=True)
    pods = {p["id"]: p for p in got["pods"]}
    svcs = {s["id"]: s for s in got["services"]}
    check("no error for a cluster that answered", got["error"] == "")
    check("every pod is in it", len(pods) == len(PODS))

    print("  faces")
    mood = {k.split("/")[1]: p["mood"] for k, p in pods.items()}
    for name, want in (("web-7d9f8b6c5-aaaaa", "happy"), ("web-7d9f8b6c5-bbbbb", "dizzy"),
                       ("oom", "crying"), ("unready", "worried"), ("creating", "hatching"),
                       ("stuck", "sleeping"), ("finished", "done"), ("api-0", "hot")):
        check(f"{name} is {want} (got {mood.get(name)})", mood.get(name) == want)
    check("a failing pod counts as failing", got["totals"]["bad"] == 3)

    print("  a crash loop, caught while it is up")
    loop = pods["shop/looper"]
    check("a pod that is up between two crashes is not healthy",
          loop["mood"] == "dizzy" and loop["tone"] == "bad" and loop["problem"] == scene.CRASH_LOOP
          and loop["phase"] == "Running" and loop["ready"] == "1/1")
    check("and it knows how its last run ended",
          loop["last_exit"]["reason"] == "Error" and loop["last_exit"]["code"] == 1
          and 38 <= loop["last_exit"]["ago"] <= 70 and loop["last_exit"]["ran"] == 20)
    check("a long run that ended is not a loop, nor an old fall, nor a second one",
          (mood.get("oldfall"), mood.get("longago"), mood.get("twice")) == ("happy", "happy", "happy"))
    check("a pod that has never fallen over has no last run to speak of",
          pods["shop/nolimits"]["last_exit"] is None)
    check("the worst are first, so a cut keeps them", got["pods"][0]["tone"] == "bad")

    print("  limits")
    api, free, half = pods["shop/api-0"], pods["shop/nolimits"], pods["shop/half"]
    check("limits are summed in millicores and MiB",
          (api["cpu_req"], api["cpu_lim"], api["mem_req"], api["mem_lim"]) == (100, 200, 64, 100))
    check("usage comes from the metrics", (api["cpu"], api["mem"]) == (20, 95))
    check("no limit is None, never 0", free["cpu_lim"] is None and free["mem_lim"] is None
          and free["cpu_req"] == 50)
    check("a limit on only some containers is flagged", half["lim_partial"] and not api["lim_partial"])
    check("pods with no limit at all are counted", got["totals"]["unlimited"] == 1)

    print("  what is connected to what")
    check("a Service selects its own namespace's pods only",
          svcs["shop/web"]["pods"] == ["shop/web-7d9f8b6c5-aaaaa", "shop/web-7d9f8b6c5-bbbbb"])
    check("a selector that matches nothing is told apart from no selector",
          svcs["shop/ghost"]["selects"] and not svcs["shop/ghost"]["pods"]
          and not svcs["shop/outside"]["selects"])
    route = got["routes"][0]
    check("a route keeps only the Services that exist", route["services"] == ["shop/web"])
    check("a claim knows the pod that mounts it",
          got["claims"][0]["pods"] == ["shop/api-0"] and got["claims"][0]["bound"])
    check("a Deployment's pod is named for the Deployment",
          pods["shop/web-7d9f8b6c5-aaaaa"]["kind"] == "Deployment"
          and pods["shop/web-7d9f8b6c5-aaaaa"]["workload"] == "web"
          and pods["shop/api-0"]["kind"] == "StatefulSet")

    print("  who manages it")
    by = {k.split("/")[1]: p["mgr"] for k, p in pods.items()}
    check("an Argo CD tracking mark is GitOps, and names the application",
          by["web-7d9f8b6c5-aaaaa"] == {"by": "gitops", "tool": "Argo CD", "detail": "shop-app"})
    check("a Helm release with nothing watching it is Helm, not GitOps",
          by["api-0"]["by"] == "helm" and by["api-0"]["detail"] == "shopapp")
    check("something applied by hand says so", by["db-0"]["by"] == "direct")
    check("a pod with no mark on it does not invent one", by["oom"]["by"] == "unknown")
    m = scene._managed_by
    check("the label every Helm chart sets is GitOps only where an Argo CD application of that name exists",
          m({"labels": {"app.kubernetes.io/instance": "x"}})["by"] == "unknown"
          and m({"labels": {"app.kubernetes.io/instance": "x"}}, {"x"})["by"] == "gitops")
    check("an operator's own object is named, and a static pod belongs to its machine",
          m({"ownerReferences": [{"controller": True, "kind": "Kafka", "name": "events"}]}) == {"by": "operator", "tool": "Kafka", "detail": "events"}
          and m({"ownerReferences": [{"controller": True, "kind": "Node", "name": "n1"}]})["by"] == "node")

    print("  links read from configuration")
    links = {(l["from"], l["to"]): l["via"] for l in got["links"]}
    check("a bare name resolves in the pod's own namespace", links.get(("shop/web", "shop/api")) == "API_URL")
    check("a full cluster name resolves across namespaces", links.get(("shop/web", "data/db")) == "DB")
    check("so does name.namespace", links.get(("shop/web", "data/cache")) == "CACHE")
    check("a bare name does NOT reach another namespace", ("shop/web", "other/only-in-other") not in links)
    check("a workload naming its own Service is not a link", ("shop/web", "shop/web") not in links)
    check("a ConfigMap the pod loads is read, and says where",
          links.get(("shop/web", "data/mq"), "").startswith("ConfigMap web-config"))
    check("no value is in the answer, only where it was found",
          PASSWORD_IN_ENV not in json.dumps(got) and "postgres://" not in json.dumps(got))
    return got


def test_unreachable() -> None:
    global DOWN
    print("a cluster that does not answer")
    DOWN = True
    clusterview.invalidate()
    got = scene.collect({"id": "c-test", "context": "x"}, refresh=True)
    DOWN = False
    clusterview.invalidate()
    check("is an error, not an empty and therefore healthy cluster",
          got["error"] == "unreachable" and got["pods"] == [])


def test_tech() -> None:
    print("what a pod is")
    t = scene.tech_of
    check("by image", t(["docker.io/bitnami/kafka:3.9"]) == "kafka"
          and t(["postgres:17"], "orders-db") == "postgres"
          and t(["docker.io/temporalio/server:1.29"]) == "temporal")
    check("by the workload's name when the image says nothing", t(["registry.example.com/x/app:1"], "redis-cache") == "redis")
    check("a private registry's own name is not the product", t(["harbor.example.com/team/orders:1"], "orders") == "")
    check("a needle is a whole word, not letters inside one", t(["x/donations-api:1"], "donations-api") == "")
    check("the image's own name is read before the organisation publishing it",
          t(["docker.io/grafana/promtail:3.5"]) == "logs" and t(["docker.io/grafana/grafana:12"]) == "dashboards"
          and t(["quay.io/prometheus/node-exporter:v1"]) == "metrics")
    check("the specific name wins over the general", t(["registry.k8s.io/ingress-nginx/controller:v1"]) == "ingress")
    check("every glyph family the page colours is one this module uses",
          {f["family"] for f in scene.TECH_FACTS.values()} <= set(
              "db queue cache storage workflow observability network security system delivery".split()))


def signed_in(email: str, areas: list, clusters=()):
    uid = auth.create_user(email, "U", "Passw0rd!xY-scene", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], list(clusters))])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-scene"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)
    return c


def test_routes() -> None:
    print("who may open it")
    pid = store.add_project("Scene", icon="x")
    mine = store.add_cluster(pid, "mine", "apiVersion: v1\nkind: Config\n", "mine")
    theirs = store.add_cluster(pid, "theirs", "apiVersion: v1\nkind: Config\n", "theirs")
    q = f"project={pid}&cluster="
    anon = TestClient(main.app, raise_server_exceptions=False)
    check("signed out, the page is a sign-in", anon.get(f"/clusters/3d?{q}{mine}", follow_redirects=False).status_code in (302, 303))
    check("and so is the data", anon.get(f"/clusters/3d.json?{q}{mine}", follow_redirects=False).status_code in (302, 303, 401))

    reader = signed_in("reader@test.invalid", ["clusters"], clusters=[mine])
    page = reader.get(f"/clusters/3d?{q}{mine}")
    check("a cluster reader gets the page", page.status_code == 200 and 'id="c3dCanvas"' in page.text)
    check("both of the page's scripts carry the nonce the CSP asks for",
          all('nonce="' in page.text.split(f"/static/{name}")[0].rsplit("<script", 1)[-1]
              for name in ("cluster3d-gl.js", "cluster3d.js")))
    check("the page takes the whole window", '<body class="bare"' in page.text)
    check("the page offers the walk, somewhere to hold a conversation, and a field to speak to the doctor",
          'id="c3dWalk"' in page.text and 'id="c3dTalk"' in page.text and 'id="c3dSayText"' in page.text
          and 'id="c3dSayAsk"' in page.text and 'id="c3dSayOpts"' in page.text)
    check("the page itself holds no pod: the picture is fetched", "web-7d9f8b6c5" not in page.text)
    data = reader.get(f"/clusters/3d.json?{q}{mine}")
    check("and the data", data.status_code == 200 and len(data.json().get("pods", [])) == len(PODS)
          and data.json()["cluster"]["name"] == "mine")
    check("a cluster outside the role is refused, page and data",
          reader.get(f"/clusters/3d?{q}{theirs}", follow_redirects=False).status_code in (303, 403)
          and "pods" not in (reader.get(f"/clusters/3d.json?{q}{theirs}", follow_redirects=False).text or ""))
    other = signed_in("nocluster@test.invalid", ["certs"])
    check("a role without the clusters area is refused",
          other.get(f"/clusters/3d?{q}{mine}", follow_redirects=False).status_code in (303, 403)
          and "web-7d9f8b6c5" not in other.get(f"/clusters/3d.json?{q}{mine}", follow_redirects=False).text)
    print("what may be done from inside it")
    from app import aitools, kmanage
    ran = []

    def fake_execute(user, project, cluster, action, args, confirm="", ip=""):
        ran.append((action, args.get("namespace"), args.get("name"), confirm))
        return {"ok": True, "code": 0, "label": "Delete pod", "summary": "pod deleted"}
    aitools.execute = fake_execute
    form = {"project": pid, "cluster": mine, "action": "delete-pod", "namespace": "shop", "name": "oom", "kind": "pod"}
    can = data.json()["can"]
    check("a reader is told they may not act, and why", can["act"] is False and "Cluster management" in can["why"])
    check("and the action route refuses a reader without running anything",
          reader.post("/clusters/3d/act.json", data=form).status_code == 403 and not ran)
    boss = signed_in("manager@test.invalid", ["clusters", "manage"], clusters=[mine])
    can = boss.get(f"/clusters/3d.json?{q}{mine}").json()["can"]
    check("a manager on a read-only cluster is told the cluster is read-only",
          can["act"] is False and can["why"] == kmanage.read_only_why())
    kmanage.writable = lambda c: True
    check("on a cluster that allows management, the manager may act",
          boss.get(f"/clusters/3d.json?{q}{mine}").json()["can"]["act"] is True)
    check("only the two actions a pod's row offers are taken from here",
          boss.post("/clusters/3d/act.json", data={**form, "action": "drain"}).status_code == 400 and not ran)
    done = boss.post("/clusters/3d/act.json", data={**form, "confirm": "typed-name"})
    check("a restart goes through the one guarded executor, with what was typed",
          done.status_code == 200 and done.json()["ok"] and ran == [("delete-pod", "shop", "oom", "typed-name")])
    check("a cluster outside the role cannot be acted on, or have its logs read",
          boss.post("/clusters/3d/act.json", data={**form, "cluster": theirs}, follow_redirects=False).status_code in (303, 403)
          and len(ran) == 1
          and not (boss.get(f"/clusters/3d/logs.json?{q}{theirs}&namespace=shop&pod=oom", follow_redirects=False).text or "").count('"text": "2'))
    clusterview.pod_logs = lambda sel, ns, name, **k: {"error": "", "text": "\n".join(f"line {i}" for i in range(200))}
    tail = boss.get(f"/clusters/3d/logs.json?{q}{mine}&namespace=shop&pod=oom").json()
    check("a pod asked for its log gives the last lines, not the whole of it",
          tail["text"].splitlines()[-1] == "line 199" and len(tail["text"].splitlines()) == 80)

    check("a machine can be reopened to pods from here, and the node's name reaches the executor",
          boss.post("/clusters/3d/act.json", data={"project": pid, "cluster": mine, "action": "uncordon", "node": "n1"}).json()["ok"]
          and ran[-1][0] == "uncordon")
    killed = boss.post("/clusters/3d/act.json", data={**form, "action": "kill-pod", "confirm": "typed-name"})
    check("a kill is its own action, through the same guarded executor with what was typed",
          killed.status_code == 200 and killed.json()["ok"] and ran[-1] == ("kill-pod", "shop", "oom", "typed-name"))
    before = len(ran)
    check("and a reader is refused it like the rest, with nothing run",
          reader.post("/clusters/3d/act.json", data={**form, "action": "kill-pod"}).status_code == 403 and len(ran) == before)

    print("calling the doctor")
    from app import doctor, mcp
    doctor.forget()
    call = reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "pod": "shop/oom", "problem": "OOMKilled"})
    reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "pod": "shop/oom", "problem": "OOMKilled"})
    check("somebody who can read the cluster can call for help, and asking twice is one call",
          call.status_code == 200 and call.json()["ok"] and len(doctor.calls(mine)) == 1)
    check("a call changes nothing in the cluster", len(ran) == 3)
    # Whoever calls is told at once what the doctor they have could do: one
    # that may only look is worth calling, and worth knowing about beforehand.
    who = auth.by_email("reader@test.invalid")
    check("with the MCP server off, the caller is told nobody can answer",
          call.json()["hands"] == mcp.doctor_hands(who["id"]) and call.json()["hands"]["clients"] == 0
          and "switched off" in call.json()["hands"]["why"])
    mcp.save_config(enabled=True, allow_actions=True)
    check("with no client connected, the caller is told that", mcp.doctor_hands(who["id"])["clients"] == 0
          and "no AI client" in mcp.doctor_hands(who["id"])["why"])
    _secret, tok = mcp.mint(who["id"], "laptop")
    hands = mcp.doctor_hands(who["id"])
    check("a read-only token can examine and cannot operate, and the caller is told which gate is shut",
          hands["clients"] == 1 and hands["may_change"] is False and "read and troubleshoot only" in hands["why"])
    mcp.rescope(tok["id"], who["id"], mode="act")
    check("a token scoped to act may operate", mcp.doctor_hands(who["id"]) == {"clients": 1, "may_change": True, "why": ""})
    mcp.save_config(enabled=True, allow_actions=False)
    check("unless actions over MCP are off for the whole installation",
          mcp.doctor_hands(who["id"])["may_change"] is False and "whole installation" in mcp.doctor_hands(who["id"])["why"])
    mcp.rescope(tok["id"], who["id"], mode="read")
    mcp.save_config(enabled=True, allow_actions=True)
    check("a cluster outside the role cannot be called about, or listened in on",
          reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": theirs}, follow_redirects=False).status_code in (303, 403)
          and not doctor.calls(theirs)
          and reader.get(f"/clusters/3d/doctor.json?{q}{theirs}", follow_redirects=False).status_code in (303, 403))
    names = [tool["name"] for tool in mcp.tools(who)]
    told = next(tool["description"] for tool in mcp.tools(who) if tool["name"] == "doctor_calls")
    check("an MCP client of a cluster reader is offered the doctor's tools",
          {"doctor_calls", "doctor_note", "doctor_listen"} <= set(names))
    check("and is told a call is not agreement to change anything", "NOT AGREEMENT TO A PARTICULAR CHANGE" in told)
    check("a role without Clusters is not offered them",
          not [n for n in (tool["name"] for tool in mcp.tools(auth.by_email("nocluster@test.invalid"))) if n.startswith("doctor")])
    told_all = mcp.call(who, "doctor_calls", {}, tok=mcp.token(tok["id"]))["structuredContent"]
    check("the doctor is told whether it may change anything, and which gate is shut when it may not",
          told_all["you_may_change"] is False and "read and troubleshoot only" in told_all["why_not"])
    waiting = told_all["waiting"]
    sick = {p["pod"]: p for p in waiting[0]["unhealthy"]}
    check("a cure for a pod GitOps keeps belongs in Git, and for one nothing marks, in the cluster",
          sick["shop/web-7d9f8b6c5-bbbbb"]["fix_in"] == "git" and sick["shop/oom"]["fix_in"] == "cluster")
    check("a crash loop caught while up is on the doctor's list, with how its last run ended",
          sick["shop/looper"]["problem"] == scene.CRASH_LOOP and sick["shop/looper"]["last_exit"]["code"] == 1)
    check("and whether the cluster itself allows management is said",
          waiting[0]["cluster_allows_management"] is True)
    check("the doctor is handed the call and the pods that are unwell, with who manages each",
          len(waiting) == 1 and waiting[0]["cluster_id"] == mine and waiting[0]["calls"][0]["pod"] == "shop/oom"
          and any(p["pod"] == "shop/oom" and p["problem"] == "OOMKilled" for p in waiting[0]["unhealthy"])
          and all("managed_by" in p for p in waiting[0]["unhealthy"]))
    said = mcp.call(who, "doctor_note", {"cluster": "mine", "pod": "shop/oom", "text": "Reading\x07 its log " + "x" * 400, "state": "examining"})
    feed = reader.get(f"/clusters/3d/doctor.json?{q}{mine}").json()
    check("what the doctor says reaches the view, as one clean line",
          not said.get("isError") and len(feed["notes"]) == 1 and feed["notes"][0]["text"].startswith("Reading its log")
          and len(feed["notes"][0]["text"]) <= 240 and feed["notes"][0]["state"] == "examining")
    check("a note about a cluster the doctor may not read is refused",
          mcp.call(who, "doctor_note", {"cluster": "theirs", "text": "hello"}).get("isError") and not doctor.feed(theirs)["notes"])
    mcp.call(who, "doctor_note", {"cluster": mine, "pod": "shop/oom", "text": "It is back.", "state": "healed"})
    check("saying a pod is healed closes the call about it",
          not doctor.calls(mine) and reader.get(f"/clusters/3d/doctor.json?{q}{mine}&since={feed['last']}").json()["notes"][0]["state"] == "healed")
    check("the doctor's words changed nothing in the cluster either", len(ran) == 3)

    print("the examination is a conversation")
    doctor.forget()
    check("with nobody waiting, a visit asked for by name is still handed the cluster",
          not mcp.call(who, "doctor_calls", {})["structuredContent"]["waiting"]
          and mcp.call(who, "doctor_calls", {"cluster": "mine"})["structuredContent"]["waiting"][0]["cluster_id"] == mine)
    reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "pod": "shop/oom", "problem": "OOMKilled"})
    asked = mcp.call(who, "doctor_note", {"cluster": mine, "pod": "shop/oom", "text": "Why are you not running?", "state": "asking", "who": "Claude"})
    spoke = mcp.call(who, "doctor_note", {"cluster": mine, "pod": "shop/oom", "voice": "pod", "state": "healed",
                                          "text": "I was killed for memory. Please help me."})
    notes = reader.get(f"/clusters/3d/doctor.json?{q}{mine}").json()["notes"]
    check("the doctor asks under the name it gave", not asked.get("isError")
          and (notes[0]["state"], notes[0]["voice"], notes[0]["who"]) == ("asking", "doctor", "Claude"))
    check("and the pod's answer reaches the view as the pod's", not spoke.get("isError")
          and (notes[1]["voice"], notes[1]["pod"]) == ("pod", "shop/oom") and notes[1]["text"].startswith("I was killed"))
    check("a line in a pod's voice carries no verdict: it closes no call, whatever state came with it",
          notes[1]["state"] == "" and len(doctor.calls(mine)) == 1)
    check("a pod's voice with no pod named is refused",
          mcp.call(who, "doctor_note", {"cluster": mine, "voice": "pod", "text": "hello"}).get("isError")
          and len(doctor.feed(mine)["notes"]) == 2)
    print("the person speaks to the doctor from inside the view")
    before = len(ran)
    told = reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "say": "What is wrong\x07 with oom? " + "y" * 400})
    check("a line typed in the view is kept as the person's, clean and short",
          told.status_code == 200 and told.json()["ok"] and told.json()["note"]["voice"] == "person"
          and told.json()["note"]["who"] == "reader@test.invalid" and told.json()["note"]["text"].startswith("What is wrong with oom?")
          and len(told.json()["note"]["text"]) <= 240 and "hands" in told.json())
    check("saying nothing is refused, and so is speaking about a cluster outside the role",
          reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "say": "  "}).status_code == 400
          and reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": theirs, "say": "hello"}, follow_redirects=False).status_code in (303, 403)
          and not doctor.heard(theirs))
    doctor.forget()
    reader.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "say": "Are you there?"})
    check("speaking to the doctor is calling it", len(doctor.calls(mine)) == 1)
    boss.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": mine, "say": "yes, delete it"})
    heard = mcp.call(who, "doctor_listen", {"cluster": "mine"})["structuredContent"]
    check("the doctor hears every line, and is told which are from the person it works for",
          [(h["text"], h["from_your_person"]) for h in heard["said"]] == [("Are you there?", True), ("yes, delete it", False)]
          and heard["last"] == heard["said"][-1]["n"])
    check("what was said is also handed over with the calls",
          [h["text"] for h in mcp.call(who, "doctor_calls", {})["structuredContent"]["waiting"][0]["said_to_you"]] == ["Are you there?", "yes, delete it"])
    t0 = time.time()
    quiet = mcp.call(who, "doctor_listen", {"cluster": mine, "after": heard["last"], "wait": 1})["structuredContent"]
    check("with nothing new it waits no longer than asked, and says so",
          quiet["said"] == [] and quiet["last"] == heard["last"] and 0.9 <= time.time() - t0 < 3)
    import threading
    threading.Timer(0.4, lambda: doctor.tell(mine, "reader@test.invalid", "one more thing")).start()
    t0 = time.time()
    woke = mcp.call(who, "doctor_listen", {"cluster": mine, "after": heard["last"], "wait": 15})["structuredContent"]
    check("a line said while it waits wakes it at once",
          [h["text"] for h in woke["said"]] == ["one more thing"] and time.time() - t0 < 5)
    check("no wait is longer than the ceiling, whatever is asked", doctor.LISTEN_MAX <= 20
          and "min(float(wait), LISTEN_MAX)" in (ROOT / "app" / "doctor.py").read_text())
    check("a cluster outside the role cannot be listened to",
          mcp.call(who, "doctor_listen", {"cluster": "theirs"}).get("isError"))
    asked = mcp.call(who, "doctor_note", {"cluster": mine, "state": "asking", "text": "Which cure?", "who": "Claude",
                                           "choices": ["Roll\x07 back", "Wait", "", "Not now", "a fifth", "a sixth"]})["structuredContent"]
    check("a question to the person keeps the answers offered: four at most, each one clean line",
          asked["choices"] == ["Roll back", "Wait", "Not now"] and asked["pod"] == "" and asked["state"] == "asking")
    about = mcp.call(who, "doctor_note", {"cluster": mine, "pod": "shop/oom", "state": "asking", "text": "Why?", "choices": ["x"]})["structuredContent"]
    check("answers to pick belong to a question put to the person, not to one put to a pod",
          "choices" not in about and "choices" not in mcp.call(who, "doctor_note", {"cluster": mine, "text": "hello", "choices": ["x"]})["structuredContent"])
    check("the offered answers reach the view with the question",
          [n.get("choices") for n in reader.get(f"/clusters/3d/doctor.json?{q}{mine}").json()["notes"] if n["text"] == "Which cure?"] == [["Roll back", "Wait", "Not now"]])
    check("a client cannot speak as the person", "person" not in doctor.VOICES
          and doctor.note(mine, "x", "hello", "shop/oom", "", "person")["voice"] == "doctor")
    check("and nothing said, by anybody, changed the cluster", len(ran) == before)
    tools_now = {tool["name"]: tool for tool in mcp.tools(who)}
    check("the listening tool says whose words count as agreement",
          "only your own person's words are agreement" in tools_now["doctor_listen"]["description"])
    check("the doctor is told to ask, to answer for the pod only from what it read, and where a cure goes",
          "asking" in tools_now["doctor_note"]["inputSchema"]["properties"]["state"]["enum"]
          and tools_now["doctor_note"]["inputSchema"]["properties"]["voice"]["enum"] == ["doctor", "pod"]
          and "actually say and nothing else" in tools_now["doctor_note"]["description"]
          and "fix_in: git" in tools_now["doctor_calls"]["description"])

    hub = reader.get(f"/clusters?{q}{mine}")
    check("the cluster page offers the button", f"/clusters/3d?project={pid}&amp;cluster={mine}" in hub.text
          or f"/clusters/3d?project={pid}&cluster={mine}" in hub.text)


def test_script(got: dict) -> None:
    print("the page's script")
    src = (ROOT / "static" / "cluster3d.js").read_text()
    gpu = (ROOT / "static" / "cluster3d-gl.js").read_text()
    both = src.replace("no innerHTML", "") + gpu
    check("builds its panels from text, never from markup", "innerHTML" not in both
          and "insertAdjacentHTML" not in both and "document.write" not in both)
    check("evaluates nothing", "eval(" not in both and "new Function" not in both)
    # A shader that fails to compile draws a black stage. The engine has to say
    # which one, and the page has to say so when there is no WebGL 2 at all.
    check("a shader that will not compile is named in the console",
          "did not compile" in gpu and "did not link" in gpu)
    check("walking never depends on the browser granting the mouse",
          "asked.catch(refused)" in src and "requestPointerLock" in src and src.count("requestPointerLock") == 1)
    # The walk takes W A S D, E and C for itself. While a text box or a dialog
    # has the keyboard it must take none of them: with the walk on, the word
    # the portal asks for before a delete could not be typed at all.
    guard = src.index("if (typing || document.querySelector('dialog[open]')) { keys = {}; return; }")
    check("typing in a box or a dialog is never taken for walking",
          "isContentEditable" in src and guard < src.index("keys[k] = 1;", guard - 400) + 2000
          and src.index("at.tagName === 'INPUT'") < src.index("keys[k] = 1;", src.index("at.tagName === 'INPUT'")))
    # The blaster and the medkit change a real cluster. They fire only after
    # being armed by the typed word, only for somebody allowed to act, and the
    # arming does not outlive the walk.
    fire = src[src.index("function useTool()"):src.index("function life(t)")]
    check("a tool is refused, with the reason, to somebody who may not act",
          fire.index("is locked: ") < fire.index("send("))
    check("a tool fires only once armed", fire.index("if (!armed) { arm(useTool); return; }") < fire.index("send("))
    check("arming asks for the typed word, and the cluster's name on production",
          "window.confirmDelete(words)" in src and "Type its name to arm" in src)
    check("leaving the walk disarms", "armed = null; tool = 0;" in src[src.index("function leaveWalk()"):src.index("function leaveWalk()") + 400])
    check("the game is won when the cluster's own data says every pod is healthy, and only then",
          "if (walk && game && !game.won && game.sick0 && !needy().length) win();" in src and src.count("win();") == 1)
    # The examination. A question put to a pod is always answered: by whoever
    # is the doctor, or else by the pod from its own row, never by nobody. And
    # a line in a pod's voice moves nothing: it is words over a pod.
    step = src[src.index("function docStep(now)"):src.index("function doctorDraw(t)")]
    check("a question nobody answers for the pod is answered from the pod's own row",
          "plea('pod:' + cur.n.pod, ix" in step and step.index("cur.n.state === 'asking'") < step.index("doc.queue.shift()"))
    check("a line in a pod's voice heals nothing and reads nothing again",
          step.index("if (n.voice === 'pod')") < step.index("burst(it, TONEF.ok)") < step.index("poll(true)")
          and "return; }" in step[step.index("if (n.voice === 'pod')"):step.index("burst(it, TONEF.ok)")])
    check("a doctor's look is drawn by the page: no image is fetched or shipped for it",
          "{ key: 'cross', draw: cross }" in src and "ch.draw(k, cx, cy, 54)" in gpu
          and "new Image" not in both and ".svg" not in both and ".png" not in both)
    # The figures that are not pods (you, and a doctor that says it is Claude)
    # are built of painted boxes. The engine has to know that kind, or they
    # are drawn as dark metal frames, and each has to be used where it belongs.
    check("the engine paints a solid box, and the figures are built of them",
          "} else if (kind < 4.5) {" in gpu and "// painted:" in gpu
          and "f.yaw, p, tip || 0);" in src[src.index("function part("):src.index("function stand(")]
          and "d[o + 10] = yaw; d[o + 11] = lean; d[o + 12] = tip; d[o + 13] = 5;" in src)
    # A figure moves because a painted box can lean and tip before it turns:
    # the engine reads the two angles from the fields a painted box does not
    # otherwise use, and a limb is placed by the same turn it is drawn with.
    check("a painted box can lean and tip, so a limb swings from its joint",
          "p = rz(rx(p, i_misc.y), i_misc.z); n = rz(rx(n, i_misc.y), i_misc.z); }" in gpu
          and "q = list[i]; y = -q[0] * c + q[1] * s; z = q[0] * s + q[1] * c;" in src
          and "q[2], q[3], q[4], q[5], q[6] || 0, -ang, out, q[7] || BOX);" in src)
    # The figures are people, not stacks of cubes: the engine has a ball and a
    # block with its edges rounded off, lit as round however far one is
    # stretched, and a limb bends half way down.
    check("the engine has round solids, lit as round when stretched into a limb",
          "var ball = round(1), soft = round(0.42);" in gpu and "n = n / i_size;" in gpu
          and "inst(S.ball, f.balls, f.nBalls || 0, ball.n, gl.TRIANGLES); inst(S.soft, f.softs, f.nSofts || 0, soft.n, gl.TRIANGLES);" in gpu
          and "balls: A.balls, nBalls: N.ball, softs: A.softs, nSofts: N.soft," in src and "N.box = N.ball = N.soft = N.orb" in src)
    body = src[src.index("function person(x, y, z, yaw, t, o)"):src.index("function head(f, L, J)")]
    check("a person is round, has a face, and limbs that bend at the knee and the elbow",
          "limb(f, -0.1, 0.86, 0, J.legL, 0, 0.4, J.kneeL, thigh, shin);" in body and "limb(f, 0.27, 1.42, 0, J.armR, J.outR, 0.3, J.elbR, upper," in body
          and body.count("BALL") >= 6 and body.count("SOFT") >= 3
          and all(w in src[src.index("function head(f, L, J)"):src.index("function dress(f, L, t, J)")] for w in ("// an eye", "// a brow", "// the nose", "// the mouth", "// an ear")))
    roles = re.findall(r"\{ name: '([^']+)', line: '[^']+', kit: '(\w+)'", src)
    check("the eight people who keep a cluster running, each with its own outfit, kit in hand and move",
          [r[0] for r in roles] == ["DevOps", "DevSecOps", "NOC", "Network engineer", "CEO", "Project manager", "QA", "DBA"]
          and all((r[1] + ": [[") in src[src.index("var PROP = {"):src.index("var RELEASE")] for r in roles)
          and all(("kit === '%s'" % r[1]) in src[src.index("function dress(f, L, t, J)"):src.index("/* What you ride")] for r in roles[:-1]))
    # A local variable called like one of the script's helpers hides it for
    # the whole function: `ease` did, and the picture froze mid-finisher with
    # the action already done.
    check("no local variable hides a helper the drawing calls",
          not re.search(r"(?:\bvar |, )(ease|turn|limb|bone|part|solid|stand|dress|ink|plate|clamp|slam|cube|glo|beam)(?: = |,|;)", src))
    check("on foot you are a person, and a doctor that says it is Claude wears Claude Code's look",
          "person(walk.x, walk.y + RIDES[on].sit - (RIDES[on].pose === 2 ? 0.18 : 0), walk.z, walk.face" in src[src.index("function walkDraw(t)"):src.index("function bubble(")]
          and "if (isClaude(n.who)) claude(" in src[src.index("function doctorDraw(t)"):src.index("function chatterStep(t)")])
    # Claude Code's orange block creature, the doctor the user has always had:
    # a body, an arm each side, four legs and tall eyes, in 3D and as the icon
    # on the map and in the chat. It was swapped for a starburst on 22 November
    # 2026 and they asked for this one back: "the previous one, that we have
    # always used".
    body = src[src.index("function claude(x, y, z, yaw, t, sad, going)"):src.index("function orb(x, y, z, rad")]
    icon = src[src.index("function critter(k, cx, cy, r)"):src.index("function cross(k, cx, cy, r)")]
    check("the doctor is Claude Code's block creature, in the view and as its icon",
          "for (i = 0; i < 4; i++)" in body and body.count("CLAUDEC") == 4 and body.count("INKC") == 2
          and "SPARK" not in src and "// the body" in icon and "// four legs" in icon
          and "k.fillStyle = CLAUDE;" in icon and "lineTo" not in icon)
    # A machine's core is a rack of servers and a volume is a stack of discs.
    # Both are pictures of real figures: every lamp, meter and size is the
    # node's or the claim's own, and nothing is lit for show.
    rk = src[src.index("function rack(x, z, nd, lit, dim, t, seed)"):src.index("function gigs(text)")]
    vol = src[src.index("function volume(x, y, z, ref, c, seen, strong, t, seed)"):src.index("function world(t, dt, k)")]
    check("a machine's core is a rack whose lamps, meters and beacon are the node's own figures",
          "rack(pl.x + 0.1, pl.z + 0.1, nd, lit, dimI, t, n);" in src
          and "!nd.ready ? TONEF.bad : nd.pressure.length || !nd.schedulable ? TONEF.warn : TONEF.ok" in rk
          and "[[nd.cpu_pct, 1], [nd.mem_pct, 0]].forEach" in rk and "if (g[0] == null) return;" in rk
          and "on = (k + 0.5) / 10 <= Math.max(f, 0.05);" in rk)
    check("a volume is a stack of discs as big as its claim, with a lamp for bound or not",
          "if (it.kind === 'claim') volume(ax, ay, az, ref, oc, seen, strong, t, it.seed);" in src
          and "gigs(ref.size)" in vol and "ref.bound ? TONEF.ok : TONEF.bad" in vol
          and "K: 1e-6, M: 1e-3, G: 1, T: 1e3, P: 1e6" in src)
    # The game around the walk: who you are, what you ride and what you carry.
    # All three are costume. What must hold is that none of them can do more
    # than the walk already could, and that a browser with no storage still plays.
    enter = src[src.index("function enterWalk()"):src.index("function pickOpen(first)")]
    check("the walk opens on the chooser, and nothing moves while it is open",
          "pickOpen(true);" in enter and "grab()" not in enter
          and "goal.tx = pk.x; goal.tz = pk.z; goal.dist = 5.6; goal.pitch = 0.1;" in src
          and src.index("if (picking) { walk.moving = false; pickAim(dt); return; }") < src.index("walk.x += vx * dt;")
          and "if (picking) { pickKey(k); e.preventDefault(); return; }" in src
          and src.index("if (picking) { pickKey(k)") < src.index("keys[k] = 1;", src.index("if (picking) { pickKey(k)")))
    # The chooser shows who you could be: every character stands in 3D, and
    # the one chosen does its own move. And the weapon is used by the figure:
    # it is in the hand, the blow is the arm's, and nothing drops from the sky.
    lineup = src[src.index("function pickScene(t)"):src.index("function pickClose()")]
    check("the chooser is a line-up in 3D, and whoever is chosen does its own move",
          "for (i = 0; i < n; i++) {" in lineup and "person(x, pk.y + 0.04, z, a + yaw, t, { hero: i," in lineup
          and "emote: u <= 1 ? i : null" in lineup and "if (picking) { pickScene(t); return; }" in src
          and all(("i === %d" % k) in src[src.index("function emote(J, i, u, t)"):src.index("function joints(o, t)")] for k in range(7)))
    blow = src[src.index("function strikeDraw(t)"):src.index("function life(t)")]
    check("the weapon is in the hand and the blow is the arm's: nothing falls from the sky",
          "J.hold && HELD[J.hold] ? lower.concat(HELD[J.hold]) : lower" in src and "attack(J, o.act.how, o.act.u" in src
          and "handAt(" in blow and "'drop'" not in blow and "walk.act = { how: w.how, w: w, at: now, dur: shot.dur };" in src
          and all(w in src[src.index("HELD = {"):src.index("var RELEASE")] for w in ("Blaster", "Knife", "Shoe", "Hammer", "'Frying pan'", "Snowball", "Medkit")))
    check("a hand weapon closes the distance, and a win ends on the character's own move",
          "if (hand && d > 1.4) walk.dash = {" in src and "walk.move = { at: at + 0.35, dur: 1.5 }; walk.face = goal.yaw;" in src)
    check("the choice is kept in this browser when it can be, checked when read, and the walk works without it",
          "try { localStorage.setItem('c3d.me', JSON.stringify(me)); } catch (e)" in src
          and "kept[k[0]] >= 0 && kept[k[0]] < k[1].length" in src and src.count("localStorage") == 2)
    check("a ride changes how fast you go and nothing else",
          "var sp = 4.6 * (walk.riding ? RIDES[me.ride].speed * (keys.Shift ? 1.5 : 1) : keys.Shift ? 1.96 : 1);" in src
          and "if (!talk && k === 'v' && !e.repeat) { mount(); return; }" in src)
    menu = src[src.index("function weaponMenu(key, r, kill)"):src.index("function talkClose()")]
    doit = src[src.index("function act(action, r, words, key)"):src.index("function talkOpen(key)")]
    check("every weapon is the same one action, through the same typed word and production name",
          "act(kill ? 'kill-pod' : 'delete-pod', r, '', key)();" in menu and menu.count("act(") == 1
          and "window.confirmDelete('pod ' + r.name + (kill ? ', for good' : ''))" in doit and "Type its name to go ahead" in doit
          and "var kill = action === 'kill-pod', goes = kill || action === 'delete-pod';" in doit
          and "opts.push(['Restart you', function () { weaponMenu(key, r); }, no]);" in src)
    # Killing is not restarting: the owner keeps one fewer, so the view must
    # not promise a replacement, and must say so when one arrives anyway.
    check("a kill is offered beside a restart, and disabled with its reason where it cannot be done",
          "opts.push(['Kill you', function () { weaponMenu(key, r, true); }, no || killWhy(r, ix)]);" in src
          and "talkShow(kill ? killLine(r) : r.workload ?" in menu)
    # The finisher: the camera, the slow blow and the stamped verdict. It is
    # theatre laid over an action that has ALREADY gone through, so it may
    # never start before the portal's answer, never hold the result back, and
    # never be the only place the result is shown.
    landing = src[src.index("function land(it, r, w, kind)"):src.index("function finish(it, r, w, kind)")]
    ending = src[src.index("function finEnd()"):src.index("function slam(")]
    check("a pod falls, and the finisher starts, only after the portal said the action went through",
          doit.index("if (d.ok && key && items[key]") > doit.index(".then(function (d) {")
          and "finish(items[key], r," in doit[doit.index("if (d.ok && key && items[key]"):]
          and fire.index("if (!d.ok) { toast('Refused: '") < fire.index("finish(it, r,")
          and "it.dead = at" in landing
          and "it.dead" not in src[src.index("function useTool()"):src.index("function strike(it, w, slow)")])
    check("a kill has its own ending: no replacement is promised, and one that comes anyway is said to have been put back",
          "kill ? 'end' : goes ? 'kill' : 'restart'" in doit and "end: kind === 'end'" in landing
          and "kind === 'end' ? killed(r) : r.workload ?" in landing
          and "toast(graves[i].end ? " in src and "started a pod where you killed one" in src
          and "end: ['NO COMING BACK THIS TIME.', 'GONE FOR GOOD']" in src
          and "v.kind === 'end' ? killed(v.r) : v.r.workload ?" in src)
    # A dance is the one thing here that does nothing: it must stay that way,
    # stay stoppable, and never be the reason somebody cannot leave or act.
    dsrc = src[src.index("var dance = null"):src.index("function strikeDraw(t)")]
    check("a dance asks nothing of the portal and is offered to everybody",
          "fetch(" not in dsrc and "send(" not in dsrc and "XMLHttpRequest" not in dsrc
          and "opts.push(['Dance with me', function () { danceStart(key); }]);" in src)
    check("B dances with the pod in reach, and is your own move where there is none",
          "if (walk.near && !walk.near.indexOf('pod:')) danceStart(walk.near); else if (!walk.riding) walk.move = {" in src)
    check("a dance can be stopped, ends by itself, and ends when its pod goes or the walk does",
          "if (dance) { if (k === ' ' || k === 'Enter' || k === 'Escape' || k === 'b') danceEnd(true); e.preventDefault(); return; }" in src
          and "if (t - d.at > DANCE) { danceEnd(false); return; }" in dsrc
          and "if (!walk || !it || it.dead || it.ax == null) { danceEnd(true); return; }" in dsrc
          and "sayClose(false); danceEnd(true); walk = null;" in src)
    check("a click during a dance fires nothing at the partner, whatever is in your hand",
          src.index("else if (dance) return;") < src.index("else if (locked()) { if (tool) useTool(); else interact(); }")
          and src.index("else if (fin) finEnd();") < src.index("else if (dance) return;"))
    check("no dance starts over a finisher, the chooser or another dance",
          "if (!walk || fin || dance || picking || !r || !it || it.dead || it.ax == null) return;" in dsrc)
    check("less motion gets the tune and the caption without the moves or the camera, and M silences the tune",
          "if (o.dance != null && !calm) groove(J, o.dance);" in src and "goal.yaw = dance.yaw + (calm ? 0 : since * 0.42);" in src
          and "var dnc = dance && !it.dead && !calm ? " in src
          and "if (me.mute) return;" in dsrc[dsrc.index("function beep("):dsrc.index("function danceLine(")])
    check("the head-up display steps back for a dance, and its caption says nothing changes",
          "if (walk && !picking && !fin && !dance) walkHud();" in src and "'NOTHING IN THE CLUSTER CHANGES'" in dsrc
          and ".c3d.dancing .c3d-talk" in (ROOT / "static" / "cluster3d.css").read_text())
    check("a tenth line of a conversation has a key, and goodbye is on Esc when the numbers run out",
          "function optKey(op, i) { return i < 9 ? String(i + 1) : i === 9 ? '0' : op[1] === talkClose ? 'Esc' : ''; }" in src
          and "var op = talk.opts[k === '0' ? 9 : +k - 1];" in src and "b.appendChild(el('kbd', '', optKey(op, i)));" in src)
    check("what happened is said in the feed and re-read from the cluster, finisher or not",
          "toast(r.name + ' ' + w.verb" in landing and "poll(true);" in landing
          and "if (!f.hit) land(f.it, f.r, f.w, f.kind);" in ending)
    check("a finisher can be skipped, and less motion or a second one gets the blow without the camera",
          "if (calm || fin || it.ax == null) {" in src
          and "if (fin) { if (k === ' ' || k === 'Enter' || k === 'Escape') finEnd(); e.preventDefault(); return; }" in src)
    check("the cluster is not re-read under a finisher, and the walk gets its camera back after one",
          "if (fin) { timer = setTimeout(function () { poll(refresh); }, 500); return; }" in src
          and "goal.yaw = f.yaw; goal.pitch = f.pitch;" in ending)
    # This is an open product anybody may install: the look and the words are
    # its own, in the style of a genre and never lifted from a game.
    check("the finisher's words are this view's own",
          "FIN = { kill: ['ANY LAST LOGS?', 'EVICTED'], end: ['NO COMING BACK THIS TIME.', 'GONE FOR GOOD'], restart: ['HOLD STILL.', 'ROLLING RESTART'] }" in src
          and not any(w in src.upper() for w in ("FATALITY", "FINISH HIM", "FINISH HER", "MORTAL KOMBAT", "CALL OF DUTY")))
    hudsrc = src[src.index("function walkHud()"):src.index("function talkShow(")]
    check("the display says what a shot would really do before it is fired",
          "NOTHING OWNS IT: IT WILL NOT COME BACK" in hudsrc and "'ARMED · EVERY SHOT IS REAL'" in hudsrc
          and "NOTHING OWNS IT: NOTHING TO RESTART" in hudsrc)
    check("the sounds are made on the page, can be turned off, and a browser without sound plays the same",
          "if (me.mute) return;" in src and "new (window.AudioContext || window.webkitAudioContext)()" in src
          and "} catch (e) { /* a browser with no sound plays the same game */ }" in src
          and "me.mute = kept.mute === true;" in src and ".mp3" not in src and ".ogg" not in src and "new Audio(" not in src)
    chat = src[src.index("function chatDraw()"):src.index("function hold(n)")]
    check("the chat with the doctor is on screen while you walk, built from text and never from markup",
          "row.appendChild(el('span', '', n.text));" in chat and src.count("innerHTML") == 1
          and "doc.log.push(n)" in src and "chatDraw();" in src[src.index("function doctorPoll()"):src.index("function arrival(")])
    # A question put to you opens the field for your answer, but only while it
    # is still the question: a replayed visit that has moved on must not ask.
    check("a question to the person opens the answer field, unless the visit has moved past it",
          "doc.asked = n.state === 'asking' && !n.pod && !doc.queue.length ? n : null;" in step
          and "if (doc.asked && walk && !talk && $('c3dSay').hidden) sayOpen();" in step)
    check("an answer offered by the doctor is sent as the person's own line, through the same route",
          "b.addEventListener('click', function () { sayClose(true); saySend(text); });" in src
          and "saySend(picks[n - 1])" in src and "!this.value && n >= 1" in src)
    check("a line typed to the doctor is sent as words to the doctor's own route, and the page offers the field",
          "say: text" in src[src.index("function saySend(text)"):src.index("function saySend(text)") + 500]
          and "'/clusters/3d/doctor.json'" in src[src.index("function saySend(text)"):src.index("function saySend(text)") + 300]
          and "if (k === 't' && !e.repeat) {" in src)
    # A pod's talk window covered the "press T" prompt and swallowed the T, so
    # a question the doctor was waiting on could be neither seen nor answered;
    # and with no question waiting, the person could not speak from it at all.
    check("T talks to the doctor from anywhere, a pod's talk window included, and a waiting question's prompt sits above it",
          "if (k === 't' && !e.repeat) { if (talk) { talkClose(); select('', false); } sayOpen();" in src
          and "talk ? Math.min(H - 186, $('c3dTalk').getBoundingClientRect().top" in src)
    # "T tells it something" in the key list was all there was: a doctor that
    # said its piece and left looked like one nobody could answer.
    check("while the doctor is here the screen says how to talk to it, and E beside it opens the field",
          "'E or T   talk to ' + docName()" in src and "'T   talk to ' + docName()" in src
          and "if (walk.doc && !talk) { sayOpen();" in src
          and "walk.doc = docHere() && Math.hypot(walk.x - doc.x, walk.z - doc.z)" in src)
    # Opening the view replayed the last fifteen minutes, so a visit that had
    # ended walked back in although nobody had called.
    check("opening the view replays nothing up to the last finished visit",
          "n.state === 'done' && !n.pod) end = i;" in src and "fresh = fresh.slice(end + 1);" in src)
    # Reported on 21 November 2026: "I told him bye, but he is stuck here with
    # me." A doctor that had said `done` stood beside the person, and followed
    # them, until a minute and a half had passed without a word from it.
    draw = src[src.index("function doctorDraw(t)"):src.index("/* ── souls")]
    check("a doctor that has said goodbye goes once its words have been read, and is gone",
          "return n && n.state === 'done' && !n.pod && !doc.queue.length ? now - s.at - hold(n) : -1;" in src
          and "if (n && bye > (calm ? 0 : LEAVE)) {" in draw and "doc.sv = null; doc.placed = false; return;" in draw
          and draw.index("bye > (calm ? 0 : LEAVE)") < draw.index("now - doc.at > 90")
          and "if (bye > 0) doc.y = ty + 11 * Math.pow(bye / LEAVE, 2);" in draw)
    check("saying goodbye it stops following you, and from then on it is not somebody you can talk to",
          "else if (walk && bye < 0) { tx = walk.x + 1.2; tz = walk.z - 0.6; }" in draw
          and "now - doc.at < 90 && docLeaving(now) <= 0); }" in src)
    check("a goodbye answered to a doctor that has left brings no 'on the way' and no waiting line",
          "if (d.parting) { doc.asked = null; return; }" in src
          and src.index("if (d.parting)") < src.index("if (d.arrival === 'started') toast('Claude is on the way.');"))
    # The doctor's words were drawn only over the doctor, so an answer given
    # from a pod behind the person, or across the cluster, was never seen.
    sub = src[src.index("function subtitle(now, youOn, docShown, podShown)"):src.index("function caption(key)")]
    check("whoever speaks out of sight is shown as a subtitle that says where they are, and only then",
          "subtitle(now, youOn, docShown, !!pp);" in src and "if (n.voice === 'pod' ? podShown : docShown) return;" in sub
          and "!unseen(scr(doc.sv))" in src and "p[1] - 70 < r.bottom - sb.top" in src
          and "'  ·  at ' + name" in sub and "bubble(W / 2, y, n.text, who" in sub)
    check("what is muttered on a walk comes from the pure list and nowhere else",
          "lines = murmurs(key, ix, data.techs || {})" in src and src.count("chatter.push(") == 2)
    check("a browser without WebGL 2 is told, not shown a black page",
          "if (!gpu)" in src and "WebGL 2" in src)
    # every row the scene script writes is as wide as the shader reading it
    import re as _re
    shapes = dict(_re.findall(r"(\w+): shape\(\w+, \[[\d, ]+\], (\d+),", gpu))
    for name, cap, width in (("box", "box", 14), ("orb", "orb", 16), ("spr", "spr", 8),
                             ("glow", "glow", 8), ("beam", "beam", 16), ("sh", "sh", 4)):
        check(f"{name} rows are {width} wide on both sides",
              shapes.get(name) == str(width) and f"CAP.{cap} * {width})" in src)
    node = shutil.which("node")
    if not node:
        print("  (node is not installed: the layout checks were skipped)")
        return
    probe = r"""
const m = require(process.argv[1]); const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const by of ['node', 'ns']) {
  const L = m.layout(d, by), spots = new Set(), pods = d.pods.map(p => L.pos['pod:' + p.id]);
  pods.forEach(p => p && spots.add(p.x.toFixed(2) + ',' + p.z.toFixed(2)));
  out[by] = { placed: pods.filter(Boolean).length, distinct: spots.size,
    loose: L.edges.filter(e => !(e.a.startsWith('wl:') ? L.members[e.a.slice(3)] : L.pos[e.a]) || !L.pos[e.b]).length,
    ghost: !!L.pos['svc:shop/ghost'], outside: !!L.pos['svc:shop/outside'], limbo: L.plats.filter(p => p.limbo).length,
    plats: L.plats.length, kinds: [...new Set(L.edges.map(e => e.kind))].sort().join() };
}
const ix = m.buildIndex(d), rel = m.related('pod:shop/api-0', ix, []);
out.rel = Object.keys(rel).sort();
out.mgr = [m.managedLine({mgr: {by: 'gitops', tool: 'Argo CD', detail: 'shop-app'}, workload: 'web', kind: 'Deployment'}),
  m.managedLine({mgr: {by: 'helm', tool: 'Helm', detail: 'r1'}, workload: 'api', kind: 'StatefulSet'}),
  m.managedLine({mgr: {by: 'unknown'}, workload: '', kind: ''})];
out.talks = [m.linksLine('pod:shop/api-0', ix), m.linksLine('pod:shop/oom', ix)];
const st = (name) => ({ name, workload: 'db', wl: 'shop/db', kind: 'StatefulSet' });
const kix = { wlPods: { 'shop/db': ['shop/db-0', 'shop/db-1', 'shop/db-2', 'shop/db-10'] },
  ref: { 'pod:shop/db-0': st('db-0'), 'pod:shop/db-1': st('db-1'), 'pod:shop/db-2': st('db-2'), 'pod:shop/db-10': st('db-10') } };
out.kill = { last: m.killWhy(st('db-10'), kix), first: m.killWhy(st('db-0'), kix), nine: m.killWhy(st('db-2'), kix) };
out.killKinds = {}; for (const k of ['', 'Deployment', 'ReplicaSet', 'DaemonSet', 'Job', 'Node', 'Cluster'])
  out.killKinds[k] = m.killWhy({ name: 'p', workload: k ? 'w' : '', wl: 'shop/w', kind: k }, kix);
const fin = (kind, phase) => ({ name: 'p', workload: 'w', wl: 'shop/w', kind, phase });
out.killStopped = {}; for (const k of ['Deployment', 'ReplicaSet', 'Job', 'StatefulSet', 'DaemonSet'])
  out.killStopped[k] = [m.killWhy(fin(k, 'Succeeded'), kix), m.killWhy(fin(k, 'Failed'), kix), m.killWhy(fin(k, 'Running'), kix)];
out.killed = [m.killed({ workload: '', kind: '' }), m.killed(fin('Deployment', 'Running')), m.killed(fin('Job', 'Succeeded')), m.killLine(fin('Job', 'Succeeded'))];
out.killSay = [m.killLine({ workload: '', kind: '' }), m.killLine({ workload: 'web', kind: 'Deployment', mgr: { by: 'gitops', tool: 'Argo CD' } }),
  m.killLine({ workload: 'web', kind: 'Deployment', mgr: { by: 'direct' } })];
out.say = {}; for (const k of ['pod:shop/oom', 'pod:shop/nolimits', 'pod:shop/api-0', 'pod:shop/stuck', 'svc:shop/ghost', 'svc:shop/outside', 'claim:shop/api-data'])
  out.say[k] = m.speech(k, ix, d.techs);
out.plea = {}; for (const k of ['pod:shop/looper', 'pod:shop/web-7d9f8b6c5-bbbbb', 'pod:shop/oom', 'pod:shop/unready', 'pod:shop/api-0', 'pod:shop/nolimits'])
  out.plea[k] = m.plea(k, ix, d.techs);
out.mur = {}; for (const k of ['pod:shop/looper', 'pod:shop/web-7d9f8b6c5-aaaaa', 'pod:shop/nolimits', 'pod:shop/api-0', 'pod:shop/stuck', 'pod:shop/oldfall', 'svc:shop/ghost'])
  out.mur[k] = m.murmurs(k, ix, d.techs);
out.say['pod:shop/looper'] = m.speech('pod:shop/looper', ix, d.techs);
console.log(JSON.stringify(out));
"""
    r = subprocess.run([node, "-e", probe, str(ROOT / "static" / "cluster3d.js")],
                       input=json.dumps(got), capture_output=True, text=True, timeout=60)
    check(f"the layout runs under node ({r.stderr[:200]})", r.returncode == 0)
    if r.returncode:
        return
    out = json.loads(r.stdout)
    for by in ("node", "ns"):
        o = out[by]
        check(f"[{by}] every pod has a place, and no two share one", o["placed"] == len(PODS) == o["distinct"])
        check(f"[{by}] no line ends on nothing", o["loose"] == 0)
        check(f"[{by}] a Service that selects nobody is shown, one that selects nothing is not",
              o["ghost"] and not o["outside"])
        check(f"[{by}] all four kinds of line are drawn", o["kinds"] == "claim,link,route,svc")
    check("pods with no machine get a waiting room when grouped by machine",
          out["node"]["limbo"] == 1 and out["ns"]["limbo"] == 0)
    # Walk mode: what a thing says when you walk up to it is read off its own
    # row and nothing else. A pod that invented a status would be worse than a
    # silent one, so each line is held to the fact it is made from.
    say = out["say"]
    check("a failing pod says its own problem and its own restart count",
          say["pod:shop/oom"].startswith("OOMKilled.") and "restarted 0 times" in say["pod:shop/oom"])
    check("a pod with no memory limit says so, and one with a limit says how full it is",
          "Nobody set me a memory limit" in say["pod:shop/nolimits"] and "95 MiB of my 100 MiB" in say["pod:shop/api-0"])
    check("a pod with no machine says why", "Unschedulable" in say["pod:shop/stuck"])
    check("a Service nobody answers behind says so, and one that selects nothing does not claim to be broken",
          "matches no pod" in say["svc:shop/ghost"] and "outside the cluster" in say["svc:shop/outside"])
    check("a volume says its size and who mounts it", say["claim:shop/api-data"] == "10Gi, bound, mounted by 1 pod.")
    check("asked who manages it, a GitOps pod names the tool and the application and says to change Git",
          "Argo CD manages me" in out["mgr"][0] and "shop-app" in out["mgr"][0] and "Git" in out["mgr"][0])
    check("a Helm install is not called GitOps", "GitOps tool is watching" in out["mgr"][1] and "manages me" not in out["mgr"][1])
    from app import kmanage
    check("a pod can be killed in the view exactly where the portal would do it, kind by kind",
          all((why == "") == (kmanage.kill_refusal(kind, "w") == "") for kind, why in out["killKinds"].items())
          and out["killKinds"]["Deployment"] == "" and "every machine" in out["killKinds"]["DaemonSet"] and "Job" in out["killKinds"]["Job"])
    check("a pod that has stopped can be cleared exactly where the portal clears it: a ReplicaSet's or a Job's, never a StatefulSet's",
          all((out["killStopped"][k][0] == "" and out["killStopped"][k][1] == "") == (k in ("Deployment", "ReplicaSet", "Job"))
              for k in out["killStopped"])
          and set(kmanage.STOPPED_OF) == {"ReplicaSet", "Job"}
          and out["killStopped"]["Job"][2] != "" and "still running" in out["killStopped"]["Job"][2])
    check("what a kill did is said as it was: one fewer, already stopped, or nothing owned it",
          "will not come back" in out["killed"][0] and out["killed"][1] == "Deployment w keeps one fewer: nothing starts another"
          and out["killed"][2].startswith("It had already stopped") and "no count changes" in out["killed"][3])
    check("of a StatefulSet only the last pod, counted as a number and not as text",
          out["kill"]["last"] == "" and "db-10" in out["kill"]["first"] and "db-10" in out["kill"]["nine"])
    check("asked to be killed, a pod says what a kill is, and a GitOps pod says Git may put it back",
          "Nothing owns me" in out["killSay"][0] and "keep one fewer" in out["killSay"][1]
          and "Argo CD" in out["killSay"][1] and "Git" in out["killSay"][1]
          and "Git" not in out["killSay"][2] and "autoscaler" in out["killSay"][2])
    check("and a pod nothing marks says it does not know", out["mgr"][2].startswith("Nothing on me says who put me here"))
    check("asked who it talks to, a pod lists what points at it and says none of it was measured",
          "shop/api sends to me" in out["talks"][0] and "shop/web names me" in out["talks"][0] and "shop/api-data" in out["talks"][0]
          and "nobody measured" in out["talks"][0] and out["talks"][1].startswith("Nothing in the cluster points at me"))
    # What a pod answers the doctor, and what it mutters as you pass: each
    # sentence is held to the field it is made from, like the lines above.
    plea, mur = out["plea"], out["mur"]
    check("a pod up between crashes does not say all is good",
          "All good" not in say["pod:shop/looper"] and "I keep falling over" in say["pod:shop/looper"]
          and "58926 restarts" in say["pod:shop/looper"])
    check("asked what is wrong, it says how its last run ended and asks for help",
          "with Error (exit code 1), after 20 seconds" in plea["pod:shop/looper"]
          and "58926 restarts" in plea["pod:shop/looper"] and plea["pod:shop/looper"].endswith("Can you help me?"))
    check("a pod GitOps keeps says its cure is in Git, and one nothing marks does not",
          "my cure is in Git" in plea["pod:shop/web-7d9f8b6c5-bbbbb"] and "Git" not in plea["pod:shop/oom"])
    check("a reason Kubernetes gives is put into words and still quoted",
          plea["pod:shop/oom"].startswith("I was killed for using more memory than I am allowed (OOMKilled).")
          and "Ready 0/1" in plea["pod:shop/unready"])
    check("a pod near its limit asks with its own numbers, and a healthy one has no complaint to invent",
          "95 MiB of my 100 MiB" in plea["pod:shop/api-0"] and plea["pod:shop/nolimits"] == say["pod:shop/nolimits"])
    texts = {k: [line["text"] for line in v] for k, v in mur.items()}
    check("a failing pod calls for help as you pass, and says nothing else",
          texts["pod:shop/looper"][0].startswith("Help! I keep falling over") and len(texts["pod:shop/looper"]) == 2)
    check("a healthy pod mutters facts off its own row",
          "Nobody set me a memory limit." in texts["pod:shop/nolimits"]
          and "There are 2 of us in web." in texts["pod:shop/web-7d9f8b6c5-aaaaa"]
          and "Argo CD keeps me the way Git says." in texts["pod:shop/web-7d9f8b6c5-aaaaa"]
          and "I have fallen over 5 times. Still here." in texts["pod:shop/oldfall"]
          and "I live on n1." in texts["pod:shop/nolimits"])
    named = [line for line in mur["pod:shop/web-7d9f8b6c5-aaaaa"] if line["to"]]
    check("a line about another Service says which, so a pod behind it can answer",
          named and all(("shop/web", line["to"]) in {(l["from"], l["to"]) for l in got["links"]}
                        and line["text"] == f'My settings name {line["to"].split("/")[1]}.' for line in named))
    check("a pod that is not well mutters only that, and a Service says what it always says",
          texts["pod:shop/api-0"] == ["So close to my limit…"] and texts["pod:shop/stuck"] == ["Still waiting for a machine with room for me."]
          and texts["svc:shop/ghost"] == [say["svc:shop/ghost"]])
    check("selecting a pod lights its Service, its volume and who names it",
          {"svc:shop/api", "claim:shop/api-data", "wl:shop/web", "pod:shop/web-7d9f8b6c5-aaaaa"} <= set(out["rel"]))


def main_test() -> int:
    got = test_scene()
    test_unreachable()
    test_tech()
    test_routes()
    test_script(got)
    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
