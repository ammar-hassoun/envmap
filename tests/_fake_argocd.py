#!/usr/bin/env python3
"""A stand-in Argo CD, answering the endpoints the portal calls.

Not a simulator of Argo CD — a way to prove the portal parses the real JSON
shapes, draws the tree from parentRefs, and sends the right sync body. It
records what it was asked to do so the test can assert on it.

    python fake_argocd.py 8099
"""
import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
CALLS = []
# A sync that takes a few polls to finish, so the watcher can be seen doing its
# job rather than only its two end states.
SYNCING = {"at": 0, "polls": 0}
LOGN = {"n": 0}          # the log grows on each read, so Follow has something to do
# A restart replaces the pods: after one, the tree answers with a NEW pod uid
# and the old one gone — which is what the map's enter/exit animation is for.
ROLLED = {"n": 0, "polls": 0}
# Argo CD's own settings. REPOS is mutated by the add/remove endpoints so a test
# can watch a registration land rather than only that the call was made.
REPOS = [{"repo": "https://git.example.com/acme/deploy.git", "type": "git",
          "name": "deploy", "project": "", "username": "ci",
          "connectionState": {"status": "Successful", "message": ""}}]
ARGO_CLUSTERS = [{"server": "https://kubernetes.default.svc", "name": "in-cluster",
                  "info": {"serverVersion": "1.29",
                           "applicationsCount": 2,
                           "connectionState": {"status": "Successful",
                                               "message": ""}}}]
ARGO_PROJECTS = [{"metadata": {"name": "payments"},
                  "spec": {"description": "the payments estate",
                           "sourceRepos": ["*"],
                           "destinations": [{"server": "https://kubernetes.default.svc",
                                             "namespace": "*"}]}},
                 {"metadata": {"name": "default"}, "spec": {}}]
POLICY = {"patched": []}
RESOURCES = [
    {"group": "", "version": "v1", "kind": "Service", "namespace": "acme-uat",
     "name": "acme-api", "status": "Synced", "syncPhase": "Sync",
     "message": "service/acme-api unchanged"},
    {"group": "apps", "version": "v1", "kind": "Deployment",
     "namespace": "acme-uat", "name": "acme-api", "status": "Synced",
     "syncPhase": "Sync", "message": "deployment.apps/acme-api configured"},
    {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress",
     "namespace": "acme-uat", "name": "acme-api", "status": "SyncFailed",
     "syncPhase": "Sync",
     "message": "admission webhook denied the request: host already claimed"},
]

APP = {
    "metadata": {"name": "acme-api", "namespace": "argocd"},
    "spec": {
        "project": "payments",
        "source": {"repoURL": "https://git.example.com/acme/deploy.git",
                   "path": "envs/uat/api", "targetRevision": "main"},
        "destination": {"server": "https://kubernetes.default.svc",
                        "namespace": "acme-uat"},
        "syncPolicy": {"automated": {"prune": False, "selfHeal": True}},
    },
    "status": {
        # what Argo's own UI draws per-node sync state from — the resource tree
        # does not carry it, so a portal that never read this could not show it
        "resources": [
            {"kind": "Deployment", "group": "apps", "version": "v1",
             "namespace": "acme-uat", "name": "acme-api",
             "status": "OutOfSync", "health": {"status": "Degraded"}},
            {"kind": "Service", "version": "v1", "namespace": "acme-uat",
             "name": "acme-api", "status": "Synced",
             "health": {"status": "Healthy"}},
        ],
        "sync": {"status": "OutOfSync", "revision": "9f2c1ab4d5e6f70819"},
        "health": {"status": "Degraded",
                   "message": "Deployment has 1 unavailable replica"},
        "operationState": {"phase": "Failed", "finishedAt": "2026-08-01T09:14:22Z",
                           "message": "one or more objects failed to apply"},
        "conditions": [{"type": "SyncError",
                        "message": "server-side apply rejected the Service"}],
        "history": [
            {"id": 41, "revision": "aaa111bbb222", "deployedAt": "2026-07-30T11:02:00Z",
             "source": {"targetRevision": "main", "path": "envs/uat/api"}},
            {"id": 42, "revision": "9f2c1ab4d5e6", "deployedAt": "2026-08-01T09:14:00Z",
             "source": {"targetRevision": "main", "path": "envs/uat/api"}},
        ],
    },
}

SECOND = json.loads(json.dumps(APP))
SECOND["metadata"]["name"] = "acme-ledger"
SECOND["status"]["sync"]["status"] = "Synced"
SECOND["status"]["health"] = {"status": "Healthy", "message": ""}
SECOND["status"]["conditions"] = []

# a second application with enough objects to be unreadable when squeezed
BIG = {"nodes": []}
for _i in range(8):
    BIG["nodes"].append({"uid": f"b-dep-{_i}", "kind": "Deployment",
                         "name": f"service-{_i}", "namespace": "acme-uat",
                         "group": "apps", "version": "v1",
                         "health": {"status": "Healthy"}, "info": []})
    for _j in range(2):
        rs = f"b-rs-{_i}-{_j}"
        BIG["nodes"].append({"uid": rs, "kind": "ReplicaSet",
                             "name": f"service-{_i}-{_j}bcd",
                             "namespace": "acme-uat", "group": "apps",
                             "version": "v1", "health": {"status": "Healthy"},
                             "parentRefs": [{"uid": f"b-dep-{_i}"}], "info": []})
        for _k in range(2):
            BIG["nodes"].append({"uid": f"b-pod-{_i}-{_j}-{_k}", "kind": "Pod",
                                 "name": f"service-{_i}-{_j}bcd-x{_k}9f",
                                 "namespace": "acme-uat", "version": "v1",
                                 "health": {"status": "Healthy"},
                                 "parentRefs": [{"uid": rs}], "info": []})
BIGTREE = BIG

TREE = {"nodes": [
    {"uid": "u-deploy", "kind": "Deployment", "name": "acme-api",
     "namespace": "acme-uat", "group": "apps", "version": "v1",
     "health": {"status": "Degraded", "message": "1 of 2 replicas available"},
     "createdAt": "2026-07-30T11:02:00Z",
     "info": [{"name": "Revision", "value": "rev:14"}]},
    {"uid": "u-rs", "kind": "ReplicaSet", "name": "acme-api-7d9f",
     "namespace": "acme-uat", "group": "apps", "version": "v1",
     "health": {"status": "Degraded"}, "parentRefs": [{"uid": "u-deploy"}],
     "createdAt": "2026-07-30T11:02:01Z", "info": []},
    {"uid": "u-pod-1", "kind": "Pod", "name": "acme-api-7d9f-abcde",
     "namespace": "acme-uat", "version": "v1",
     "health": {"status": "Healthy"}, "parentRefs": [{"uid": "u-rs"}],
     "images": ["registry.example.com/acme/api:1.24.0"],
     "createdAt": "2026-07-30T11:02:05Z",
     "info": [{"name": "Status Reason", "value": "Running"}]},
    {"uid": "u-pod-2", "kind": "Pod", "name": "acme-api-7d9f-fghij",
     "namespace": "acme-uat", "version": "v1",
     "health": {"status": "Degraded", "message": "CrashLoopBackOff"},
     "parentRefs": [{"uid": "u-rs"}],
     "images": ["registry.example.com/acme/api:1.24.0"],
     "createdAt": "2026-07-30T11:02:05Z",
     "info": [{"name": "Status Reason", "value": "CrashLoopBackOff"}]},
    {"uid": "u-svc", "kind": "Service", "name": "acme-api",
     "namespace": "acme-uat", "version": "v1",
     "health": {"status": "Healthy"}, "createdAt": "2026-07-30T11:02:00Z",
     "info": []},
    {"uid": "u-ing", "kind": "Ingress", "name": "acme-api",
     "namespace": "acme-uat", "group": "networking.k8s.io", "version": "v1",
     "health": {"status": "Healthy"}, "parentRefs": [{"uid": "u-svc"}],
     "createdAt": "2026-07-30T11:02:00Z", "info": []},
]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        CALLS.append(("GET", self.path))
        if "/resource?" in self.path:
            # Echo the object that was ASKED for. One canned Pod for every kind
            # made a real bug invisible: a panel that showed the wrong object
            # under the right title looked correct against this fixture.
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            kind = (q.get("kind") or ["Pod"])[0]
            rname = (q.get("resourceName") or ["acme-api-7d9f-fghij"])[0]
            live = {"apiVersion": "v1", "kind": kind,
                    "metadata": {"name": rname,
                                 "namespace": (q.get("namespace")
                                               or ["acme-uat"])[0],
                                 "managedFields": [{"manager": "noise"}],
                                 "resourceVersion": "8891"}}
            if kind == "Pod":
                live["spec"] = {"containers": [{"name": "api"},
                                               {"name": "envoy"}]}
                live["status"] = {"containerStatuses": [
                    {"name": "api", "ready": False, "restartCount": 7},
                    {"name": "envoy", "ready": True, "restartCount": 0}]}
            else:
                live["spec"] = {"replicas": 2}
                live["status"] = {"readyReplicas": 1}
            return self._send({"manifest": json.dumps(live)})
        if self.path.startswith("/api/v1/repositories"):
            return self._send({"items": REPOS})
        if self.path.startswith("/api/v1/clusters"):
            return self._send({"items": ARGO_CLUSTERS})
        if self.path.startswith("/api/v1/projects"):
            return self._send({"items": ARGO_PROJECTS})
        if "/resource/actions" in self.path:
            # what the controller offers for this object
            return self._send({"actions": [
                {"name": "restart", "displayName": "Restart"},
                {"name": "pause", "disabled": True}]})
        if "/managed-resources" in self.path:
            live_pod = json.dumps(
                {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "acme-api-7d9f-fghij"},
                 "spec": {"containers": [{"name": "api",
                                          "image": "api:1.24.0"}]}})
            target_pod = json.dumps(
                {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "acme-api-7d9f-fghij"},
                 "spec": {"containers": [{"name": "api",
                                          "image": "api:1.25.0"}]}})
            # answer for whichever object was asked about, the way a real
            # Argo does for anything it manages — pinning one hardcoded name
            # meant a test that opened any other resource saw "not managed"
            qs = dict(urllib.parse.parse_qsl(
                urllib.parse.urlparse(self.path).query))
            want = qs.get("resourceName") or "acme-api-7d9f-fghij"
            items = [{"kind": qs.get("kind") or "Pod", "name": want,
                      "namespace": qs.get("namespace") or "acme-uat",
                      "diff": "{\"spec\":{}}",
                      "liveState": live_pod.replace("acme-api-7d9f-fghij", want),
                      "targetState": target_pod.replace("acme-api-7d9f-fghij", want)}]
            if not qs.get("resourceName"):
                # the app-wide review: one changed, one to create, one to prune
                items.append({"kind": "ConfigMap", "name": "acme-api-new",
                              "namespace": "acme-uat", "diff": "{}",
                              "liveState": "",
                              "targetState": json.dumps(
                                  {"apiVersion": "v1", "kind": "ConfigMap",
                                   "metadata": {"name": "acme-api-new"},
                                   "data": {"A": "1"}})})
                items.append({"kind": "Secret", "name": "acme-api-orphan",
                              "namespace": "acme-uat", "diff": "{}",
                              "liveState": json.dumps(
                                  {"apiVersion": "v1", "kind": "Secret",
                                   "metadata": {"name": "acme-api-orphan"}}),
                              "targetState": ""})
            return self._send({"items": items})
        if "/events" in self.path and "resourceUID" not in self.path:
            return self._send({"items": [
                {"type": "Warning", "reason": "OperationFailed",
                 "message": "one or more objects failed to apply",
                 "count": 3, "lastTimestamp": "2026-08-01T09:14:22Z"}]})
        if "/events" in self.path:
            return self._send({"items": [
                {"type": "Warning", "reason": "BackOff",
                 "message": "Back-off restarting failed container api",
                 "count": 14, "lastTimestamp": "2026-08-01T10:31:00Z",
                 "source": {"component": "kubelet"}},
                {"type": "Normal", "reason": "Pulled",
                 "message": "Container image already present on machine",
                 "count": 1, "lastTimestamp": "2026-08-01T10:02:00Z",
                 "source": {"component": "kubelet"}}]})
        if "/logs" in self.path and "/pods/" in self.path:
            LOGN["n"] += 1
            lines = ["starting api", "connecting to postgres",
                     "FATAL: password authentication failed for user \"api\"",
                     "exiting"]
            lines += [f"retry {i}" for i in range(1, LOGN["n"])]
            body = "\n".join(json.dumps({"result": {"content": l}}) for l in lines)
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/__calls":
            return self._send(CALLS)
        if self.path.startswith("/api/v1/applications?") or \
           self.path == "/api/v1/applications":
            return self._send({"items": [APP, SECOND]})
        if "/resource-tree" in self.path:
            if "big" in self.path:
                return self._send(BIGTREE)
            if not ROLLED["n"]:
                return self._send(TREE)
            # rolled: pod-2 has gone, a fresh one has arrived in its place.
            # And it SETTLES: a real pod is Progressing for a moment and then
            # Healthy, which is what the page has to notice on its own — a pod
            # pinned at Progressing for ever could not tell a page that stops
            # watching too early from one that keeps up.
            ROLLED["polls"] = ROLLED.get("polls", 0) + 1
            n = ROLLED["polls"]
            # a real rolling update, one poll per step: the new pod is Pending,
            # then pulling, then Running — and the old one is Terminating for a
            # moment BEFORE it leaves the tree, which is the half of the story
            # a page that only watches for boxes appearing cannot show
            new_phase, new_ready, new_health = (
                ("Pending", "0/1", "Progressing") if n == 1 else
                ("ContainerCreating", "0/1", "Progressing") if n == 2 else
                ("Running", "1/1", "Healthy"))
            doc = json.loads(json.dumps(TREE))
            if n >= 3:                       # gone once the new one is serving
                doc["nodes"] = [x for x in doc["nodes"] if x["uid"] != "u-pod-2"]
            else:
                for x in doc["nodes"]:
                    if x["uid"] == "u-pod-2":
                        x["info"] = [{"name": "Status Reason",
                                      "value": "Terminating"},
                                     {"name": "Containers", "value": "1/1"}]
            doc["nodes"].append({
                "uid": f"u-pod-new-{ROLLED['n']}", "kind": "Pod",
                "name": f"acme-api-7d9f-new{ROLLED['n']}",
                "namespace": "acme-uat", "version": "v1",
                "health": {"status": new_health},
                "parentRefs": [{"uid": "u-rs"}],
                "createdAt": "2026-08-01T11:00:00Z",
                "info": [{"name": "Status Reason", "value": new_phase},
                         {"name": "Containers", "value": new_ready}]})
            return self._send(doc)
        if self.path.startswith("/api/v1/applications/"):
            name = self.path.split("/api/v1/applications/")[1].split("?")[0]
            base = APP if name in ("acme-api", "big") else SECOND
            doc = json.loads(json.dumps(base))
            if SYNCING["at"]:
                SYNCING["polls"] += 1
                n = SYNCING["polls"]
                done = n >= 3
                doc["status"]["operationState"] = {
                    "phase": "Succeeded" if done else "Running",
                    "message": ("one or more objects failed to apply"
                                if done else "waiting for healthy state"),
                    "startedAt": "2026-08-01T10:00:00Z",
                    "finishedAt": "2026-08-01T10:00:12Z" if done else "",
                    "operation": {"sync": {"revision": "9f2c1ab4d5e6",
                                           "prune": SYNCING["at"] == 2}},
                    "syncResult": {"revision": "9f2c1ab4d5e6",
                                   "resources": RESOURCES[:min(3, n)]},
                }
                if done:
                    SYNCING["at"] = 0
            return self._send(doc)
        self._send({"error": "not found"}, 404)

    def do_DELETE(self):
        CALLS.append(("DELETE", self.path))
        if self.path.startswith("/api/v1/repositories/"):
            import urllib.parse as _up
            gone = _up.unquote(self.path.rsplit("/", 1)[-1])
            before = len(REPOS)
            REPOS[:] = [r for r in REPOS if r["repo"] != gone]
            if len(REPOS) == before:
                return self._send({"error": "repo not found"}, 404)
            return self._send({})
        if "/resource?" in self.path:
            return self._send({})
        if self.path.endswith("/operation"):
            SYNCING["at"] = 0
            return self._send({})
        self._send({"error": "not found"}, 404)

    def do_PATCH(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        CALLS.append(("PATCH", self.path, raw))
        if "/resource?" in self.path:
            return self._send({"manifest": raw})
        # the application's own spec — how the sync policy is set
        if self.path.startswith("/api/v1/applications/"):
            sent = json.loads(raw or "{}")
            POLICY["patched"].append(sent.get("patch", ""))
            pol = ((json.loads(sent.get("patch") or "{}").get("spec") or {})
                   .get("syncPolicy") or {})
            auto = pol.get("automated")
            APP["spec"]["syncPolicy"] = ({} if auto is None
                                         else {"automated": auto})
            return self._send({"metadata": {"name": sent.get("name", "")}})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        CALLS.append(("POST", self.path, raw))
        if self.path == "/api/v1/session":
            return self._send({"token": "fake-session-token"})
        if self.path.rstrip("/") == "/api/v1/repositories":
            sent = json.loads(raw or "{}")
            url = sent.get("repo", "")
            if any(r["repo"] == url for r in REPOS):
                return self._send({"error": "repository already exists"}, 409)
            # Argo validates the credential as part of the call, which is what
            # makes a wrong password a refusal here rather than a mystery later
            if sent.get("username") and not sent.get("password"):
                return self._send(
                    {"error": "authentication required: empty password"}, 401)
            REPOS.append({"repo": url, "type": "git",
                          "name": sent.get("name", ""),
                          "project": sent.get("project", ""),
                          "username": sent.get("username", ""),
                          "insecure": bool(sent.get("insecure")),
                          "connectionState": {"status": "Successful",
                                              "message": ""}})
            return self._send({"repo": url})
        if self.path.endswith("/sync"):
            sent = json.loads(raw or "{}")
            SYNCING["at"] = 2 if sent.get("prune") else 1
            SYNCING["polls"] = 0
            return self._send({"status": {"operationState": {
                "phase": "Succeeded",
                "message": ("dry run: 3 resources would change"
                            if sent.get("dryRun")
                            else "3 resources applied"
                                 + (", 1 pruned" if sent.get("prune") else ""))}}})
        if self.path.endswith("/rollback"):
            SYNCING["at"] = 1
            SYNCING["polls"] = 0
            return self._send({"status": {"operationState": {"phase": "Running"}}})
        if "/resource/actions" in self.path:
            if "restart" in raw:
                ROLLED["n"] += 1
                ROLLED["polls"] = 0          # a fresh rollout starts at step 1
            return self._send({})
        self._send({"error": "not found"}, 404)


print(f"fake argocd on :{PORT}", flush=True)
HTTPServer(("127.0.0.1", PORT), H).serve_forever()
