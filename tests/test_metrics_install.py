#!/usr/bin/env python3
"""The one add-on this product installs, and why that is safe to offer.

WHY THIS EXISTS
    Every other write in the portal names an object that already exists. This
    button creates nine of them in kube-system, with whatever rights the stored
    kubeconfig has — which on a cluster marked for management is usually
    cluster-admin. Two things therefore have to hold, and neither is visible by
    reading the page:

      1. **The manifest is checked before any of it is applied.** The URL is
         configuration, not code, so an install pointed at a mirror — or a
         github URL that quietly became an error page — must be refused rather
         than applied. "Fetch a YAML and pipe it into apply" is exactly the
         mistake available here, and it would run as cluster-admin.
      2. **Pressing it twice is the same as pressing it once.** Upstream's own
         instructions append the two kubelet flags with a JSON patch against
         `/args/-`, which on a second run leaves the same flag in the list
         twice. The button sits on a page somebody WILL press again, because
         usage takes a minute to appear.

    Fetching is exercised over a real socket against a local server rather than
    by monkeypatching urlopen: the failure this guards against is a URL
    answering something unexpected, and a stubbed fetch cannot answer anything
    the stub did not think of.

    ./.venv/bin/python tests/test_metrics_install.py
"""
from __future__ import annotations

import http.server
import os
import pathlib
import re
import sys
import threading
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("metrics-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cluster as clusterview                         # noqa: E402
from app import kmanage                                        # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def refuses(what: str, url: str, expect: str = "") -> None:
    """The fetch must refuse, and say something a person can act on."""
    try:
        kmanage.metrics_manifest(url)
    except kmanage.Refused as e:
        if expect and expect not in str(e):
            check(f"{what} — reason names {expect!r}, got {str(e)[:90]!r}", False)
        return
    except Exception as e:                                     # noqa: BLE001
        check(f"{what} — refused with {type(e).__name__} rather than Refused"
              f" ({e})", False)
        return
    check(f"{what} — it was ACCEPTED", False)


# ── what the server hands out ──────────────────────────────────
# Shaped like upstream's components.yaml, small enough to read. The image tag is
# deliberately not a real version, so a check that reports the version cannot
# pass by echoing something hard-coded elsewhere.
def manifest(deployment_ns: str = "kube-system", kinds_extra: str = "",
             with_deployment: bool = True, with_apiservice: bool = True,
             image: str = "registry.k8s.io/metrics-server:v9.9.9") -> str:
    docs = ["""apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-server
  namespace: kube-system
""", """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:metrics-server
rules: []
""", """apiVersion: v1
kind: Service
metadata:
  name: metrics-server
  namespace: kube-system
spec:
  ports: [{port: 443}]
"""]
    if with_deployment:
        docs.append(f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-server
  namespace: {deployment_ns}
spec:
  template:
    spec:
      containers:
        - name: metrics-server
          image: {image}
          args:
            - --cert-dir=/tmp
            - --secure-port=10250
""")
    if with_apiservice:
        docs.append("""apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
spec:
  group: metrics.k8s.io
""")
    if kinds_extra:
        docs.append(kinds_extra)
    return "---\n".join(docs)


# A realistic tampering, not a nonsense one: the metrics-server manifest, plus
# something that mounts the host. A check that only counted objects, or only
# looked at the first document, would pass this.
SMUGGLED = """apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-helper
  namespace: kube-system
spec:
  template:
    spec:
      containers:
        - name: x
          image: busybox
          volumeMounts: [{name: root, mountPath: /host}]
      volumes: [{name: root, hostPath: {path: /}}]
"""

PAGES = {
    "/good.yaml": (200, manifest()),
    "/smuggled.yaml": (200, manifest(kinds_extra=SMUGGLED)),
    "/elsewhere.yaml": (200, manifest(deployment_ns="attacker")),
    "/no-deployment.yaml": (200, manifest(with_deployment=False)),
    "/no-apiservice.yaml": (200, manifest(with_apiservice=False)),
    "/html": (200, "<!doctype html><html><body>Not Found</body></html>"),
    "/empty": (200, ""),
    "/gone": (404, "404 page not found"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                          # noqa: N802
        code, body = PAGES.get(self.path, (404, "no such fixture"))
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):                                 # noqa: D102
        pass


def main() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    at = f"http://127.0.0.1:{srv.server_address[1]}"

    print("a manifest that is metrics-server is accepted, and names its version")
    raw, version = kmanage.metrics_manifest(f"{at}/good.yaml")
    check(f"the version comes out of the manifest, not a constant ({version})",
          version == "v9.9.9")
    check("and the bytes are handed back for apply to read",
          "kind: Deployment" in raw and "metrics-server" in raw)

    print("anything else is refused rather than applied")
    refuses("a DaemonSet smuggled in beside it", f"{at}/smuggled.yaml",
            "DaemonSet")
    refuses("a Deployment aimed at another namespace", f"{at}/elsewhere.yaml",
            "attacker")
    refuses("no metrics-server Deployment at all", f"{at}/no-deployment.yaml",
            "no metrics-server Deployment")
    refuses("nothing registering the metrics API", f"{at}/no-apiservice.yaml",
            "metrics.k8s.io")
    # github answers a wrong release path with an HTML page and HTTP 404; both
    # shapes have to be refused, because both are "there is nothing to apply".
    refuses("an HTML error page", f"{at}/html")
    refuses("an empty body", f"{at}/empty")
    refuses("an HTTP error", f"{at}/gone", "404")
    refuses("a host that is not listening", "http://127.0.0.1:1/components.yaml",
            "PORTAL_METRICS_URL")
    # Whatever this fetch returns is applied to a cluster, so it is the last
    # place to skip the guard every other outbound request passes: a VPN
    # connection pointed at file:///tmp once read the file back through the
    # portal's own error path.
    refuses("a file:// URL, which would be read and then applied",
            "file:///etc/passwd", "http or https")
    refuses("the cloud metadata address",
            "http://169.254.169.254/latest/meta-data/", "http or https")

    print("the kubelet flags: computed, never appended")
    fresh = ["--cert-dir=/tmp", "--secure-port=10250"]
    check("a fresh install needs both",
          kmanage.missing_kubelet_args(fresh) == list(kmanage.TALOS_ARGS))
    check("a second press needs none",
          kmanage.missing_kubelet_args(fresh + list(kmanage.TALOS_ARGS)) == [])
    check("one already there leaves only the other",
          kmanage.missing_kubelet_args(fresh + ["--kubelet-insecure-tls"])
          == ["--kubelet-preferred-address-types=InternalIP"])
    # Somebody who chose Hostname chose it. Appending InternalIP after it would
    # leave two of the same flag with the last one silently winning.
    check("and a value somebody else chose is left alone",
          kmanage.missing_kubelet_args(
              fresh + ["--kubelet-preferred-address-types=Hostname"])
          == ["--kubelet-insecure-tls"])

    print("the action is wired through the same gates as every other")
    spec = kmanage.ACTIONS.get("install-metrics")
    check("it is in the action table", bool(spec))
    check("it needs no arguments from the page", tuple(spec["needs"]) == ())
    check("it carries its own runner, because it is three commands",
          callable(spec.get("run")))
    check("with a timeout of its own, since a fetch is involved",
          int(spec.get("timeout", 0)) >= 60)
    check("and the note says it lands outside git",
          "git" in spec.get("note", ""))
    ro = {"id": "c1", "name": "nope", "context": "x", "manage": ""}
    try:
        kmanage.act(ro, "install-metrics", {}, allow_write=False)
        check("a read-only cluster refuses it", False)
    except kmanage.Refused:
        pass
    # The gate is the same one, not a second copy: allow_write comes from
    # kmanage.writable(sel) in aitools, so this is the value that reaches it.
    check("and writable() is what decides", not kmanage.writable(ro))
    check("a ticked cluster is writable", kmanage.writable({**ro, "manage": "1"}))

    print("several kubectls, reported as one outcome")
    ok = kmanage._steps_result(
        [{"display": "kubectl apply -f -", "code": 0, "stdout": "created",
          "stderr": "Warning: some policy complained"}],
        time.time(), ok=True, head="metrics-server v9.9.9 installed")
    # aitools.execute prefers stderr over stdout when it builds the flash
    # message, and `kubectl apply` writes policy warnings to stderr on a
    # perfectly successful apply — a cluster with a policy engine would have
    # reported "Warning: …" as the outcome of a working install.
    check("a warning on a successful apply is not the outcome",
          ok["stderr"] == "" and ok["code"] == 0)
    check("but it is still on the record underneath",
          "some policy complained" in ok["stdout"])
    check("the first line of stdout is the sentence a person reads",
          ok["stdout"].splitlines()[0] == "metrics-server v9.9.9 installed")
    check("and every command run is on the record",
          "kubectl apply -f -" in ok["display"])
    bad_run = kmanage._steps_result(
        [{"display": "kubectl apply -f -", "code": 1, "stdout": "",
          "stderr": "forbidden"}], time.time(), ok=False, head="applying failed")
    check("a failure reports the failing code", bad_run["code"] == 1)
    check("and says what the cluster said", "forbidden" in bad_run["stderr"])
    check("and is not ok", not bad_run["ok"])

    print("the page offers it exactly where usage would have been")
    from fastapi.testclient import TestClient
    from app import auth, db, main as appmain, store

    email, pw = "metrics@test.invalid", "Install-The-Metrics-Server-7"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    pid = store.add_project("Metrics")
    cid = store.add_cluster(pid, "c1", "apiVersion: v1\n", "ctx1")

    node = {"name": "talos-1", "ready": True, "roles": ["control-plane"],
            "schedulable": True, "taints": [], "pressure": [],
            "version": "v1.31.1", "os": "Talos", "kernel": "", "runtime": "",
            "arch": "amd64", "ip": "10.0.0.1", "age": "40d",
            "cpu_cap": 8000.0, "mem_cap": 32000.0, "cpu_use": None,
            "mem_use": None, "disk_cap": 0, "disk_alloc": 0, "disk_use": None,
            "disk_pct": None, "disk_pressure": False, "cpu_pct": None,
            "mem_pct": None, "pods_cap": 110}

    def with_metrics(present: bool):
        parts = {"nodes": {"error": "", "nodes": [node], "versions": ["v1.31.1"],
                           "metrics": present},
                 "pods": {"pods": []}, "netshoots": []}
        clusterview.gathered = lambda sel, want, refresh=False: {
            "parts": {k: v for k, v in parts.items()
                      if k in want or k == "netshoots"},
            "pending": [], "errors": []}

    client = TestClient(appmain.app, raise_server_exceptions=False)
    with client:
        client.post("/login", data={"email": email, "password": pw},
                    follow_redirects=False)
        u = auth.by_email(email)
        client.post("/mfa", data={"code": auth._totp_at(
            u["totp_secret"], int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

        def nodes_tab() -> str:
            r = client.get(f"/clusters?project={pid}&cluster={cid}&tab=nodes",
                           follow_redirects=False)
            check(f"the nodes tab renders → HTTP {r.status_code}",
                  r.status_code == 200)
            return r.text

        with_metrics(False)
        body = nodes_tab()
        check("the button is on the page when there is no metrics API",
              'value="install-metrics"' in body)
        check("it says what it will do to the cluster",
              "kube-system" in body and "kubelet" in body)
        check("including the flag that is a trade, rather than adding it quietly",
              "--kubelet-insecure-tls" in body)
        check("and that usage takes a moment to appear",
              re.search(r"30-60 seconds|about a minute", body) is not None)
        check("it posts to the audited action route",
              re.search(r'action="/clusters/action"[^>]*>(?:(?!</form>).)*?'
                        r'value="install-metrics"', body, re.S) is not None)
        # A cluster nobody ticked cannot be changed, and the earlier lesson was
        # that a control which VANISHES teaches nothing: Troubleshoot disappeared
        # from read-only clusters and read as a bug in the page.
        check("on a cluster not marked for management it is disabled, not gone",
              re.search(r'value="install-metrics"[^>]*\sdisabled', body)
              is not None)
        check("and says why", "read-only" in body)

        # …and on one somebody DID tick, it is live and it asks first.
        store.update_cluster(pid, cid, manage="1")
        body = nodes_tab()
        check("with management enabled the button is live",
              re.search(r'value="install-metrics"(?:(?!</button>).)*?disabled',
                        body, re.S) is None)
        check("and asks before it runs",
              re.search(r'value="install-metrics"(?:(?!</button>).)*?confirmAct',
                        body, re.S) is not None)
        store.update_cluster(pid, cid, manage="")

        with_metrics(True)
        body = nodes_tab()
        check("with metrics present the button is not offered at all",
              'value="install-metrics"' not in body)
        check("and the header says the usage is live",
              "live usage from metrics-server" in body)

    srv.shutdown()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
