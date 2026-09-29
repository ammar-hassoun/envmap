#!/usr/bin/env python3
"""Updating this installation from its own page — and everything it must refuse.

WHY THIS FILE IS MOSTLY REFUSALS
    `updates.py` says a portal that could update itself would be a portal that
    could be made to install anything. The answer to that is not "we were
    careful", it is a list of things this code cannot be talked into, and a test
    per item. Every assertion below is one of them:

      * a registry it did not already run                      → cannot be named
      * a version nobody announced                             → refused
      * a version that is not a version                        → refused
      * an older version                                       → refused
      * any object but its own Deployment                      → not in the Role
      * the whole feature, when nobody turned it on            → absent

    The last of those is checked against the chart rather than the code, because
    that is where it is decided.

WHAT THE STUB IS FOR
    A Kubernetes API that records the exact patch. The patch body is the product
    here — one field, one container, nothing else touched — and reading it back is
    the only way to know that a strategic-merge patch did not quietly drop the
    operator's own settings.

    ./.venv/bin/python tests/test_selfupdate.py
"""
from __future__ import annotations

import http.server
import json
import os
import pathlib
import ssl
import sys
import threading
import types

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("selfupdate-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── a stub API server, and a pod's-eye view of the world ───────
DEPLOY = {
    # the label Helm writes, which is how the portal reads what Helm believes
    # without being able to read the release Secret itself
    "metadata": {"name": "portal-config-portal", "namespace": "portal",
                 "labels": {"app.kubernetes.io/version": "0.3.3"}},
    "spec": {"template": {"spec": {"containers": [
        # a second container and a set of fields an operator chose: the patch
        # must leave every one of them alone
        {"name": "portal", "image": "ghcr.io/vendor/devops-portal:0.3.3",
         "resources": {"limits": {"memory": "1Gi"}},
         "env": [{"name": "PORTAL_SESSION_HOURS", "value": "8"}]},
        {"name": "sidecar", "image": "busybox:1.36"},
    ]}}},
}


class API(http.server.BaseHTTPRequestHandler):
    patches: list = []
    calls: list = []
    forbid = False

    def log_message(self, *a):
        pass

    def _json(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        API.calls.append(f"GET {self.path}")
        if API.forbid:
            return self._json(403, {"message": "deployments.apps "
                                    "\"portal-config-portal\" is forbidden"})
        if self.path.endswith("/deployments/portal-config-portal"):
            return self._json(200, DEPLOY)
        return self._json(404, {"message": "not found"})

    def do_PATCH(self):
        API.calls.append(f"PATCH {self.path}")
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if API.forbid:
            return self._json(403, {"message": "forbidden"})
        API.patches.append({
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "authorization": self.headers.get("Authorization"),
            "body": json.loads(raw),
        })
        return self._json(200, DEPLOY)


def start_api(tmp: pathlib.Path) -> str:
    """The API server, on TLS, with a CA the client is made to trust — because
    verification is part of what is being tested. A token that can change what
    runs in the namespace must not travel to an unverified server."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "kubernetes.default.svc")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("kubernetes.default.svc"),
                 x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem = tmp / "server.pem"
    pem.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
        + cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "token").write_text("a-service-account-token")
    (tmp / "namespace").write_text("portal")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"https://localhost:{srv.server_address[1]}"


def main() -> int:
    tmp = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "sa"
    tmp.mkdir(parents=True, exist_ok=True)
    api = start_api(tmp)

    from app import env, selfupdate
    # Point the module at the stub: the service-account directory and the API
    # address are the only two things about "running in Kubernetes" that a test
    # cannot have for real.
    selfupdate.SA_DIR = str(tmp)
    selfupdate.API = api
    env.SELF_UPDATE = True
    env.SELF_DEPLOYMENT = "portal-config-portal"
    env.SELF_CONTAINER = "portal"
    env.SELF_NAMESPACE = "portal"
    env.VERSION = "0.3.3"

    print("it can see itself")
    check("it knows it is in a cluster", selfupdate.in_cluster())
    check("and that it is allowed to act", selfupdate.enabled())
    check(f"it reads its own image, got {selfupdate.current_image()}",
          selfupdate.current_image() == "ghcr.io/vendor/devops-portal:0.3.3")
    st = selfupdate.state("0.3.6", True)
    check(f"the page is told it is possible, got {st}", st["possible"])
    check("and what it would become",
          st["target_image"] == "ghcr.io/vendor/devops-portal:0.3.6")

    print("the patch changes one field and touches nothing else")
    API.patches.clear()
    got = selfupdate.apply("0.3.6", "0.3.6", actor="ops@example.com")
    check(f"it reports the move, got {got}",
          got == {"from": "0.3.3", "to": "0.3.6",
                  "image": "ghcr.io/vendor/devops-portal:0.3.6"})
    check(f"exactly one patch was sent, got {len(API.patches)}",
          len(API.patches) == 1)
    p = API.patches[0]
    check("as a strategic merge patch",
          p["content_type"] == "application/strategic-merge-patch+json")
    check("carrying the pod's own token",
          p["authorization"] == "Bearer a-service-account-token")
    check("to its own deployment, in its own namespace",
          p["path"] == "/apis/apps/v1/namespaces/portal/deployments/"
                       "portal-config-portal")
    body = p["body"]
    containers = body["spec"]["template"]["spec"]["containers"]
    check(f"naming one container, got {len(containers)}", len(containers) == 1)
    check("which is the portal's own", containers[0]["name"] == "portal")
    check(f"with only name and image in it, got {sorted(containers[0])}",
          sorted(containers[0]) == ["image", "name"])
    check("and the image is the same repository, new tag",
          containers[0]["image"] == "ghcr.io/vendor/devops-portal:0.3.6")
    # the operator's resources, env and second container are absent from the
    # patch, which is what leaves them alone
    flat = json.dumps(body)
    for gone in ("resources", "memory", "PORTAL_SESSION_HOURS", "sidecar",
                 "busybox"):
        check(f"the patch does not mention {gone}", gone not in flat)

    print("it will not go anywhere it was not sent")
    def refused(target, announced, why):
        try:
            selfupdate.apply(target, announced)
            check(f"{why}: should have been refused", False)
            return ""
        except selfupdate.UpdateError as e:
            return str(e)

    msg = refused("0.4.0", "0.3.6", "a version nobody announced")
    check(f"and says so, got {msg!r}", "announced" in msg)
    msg = refused("0.3.2", "0.3.2", "an older version")
    check(f"and says so, got {msg!r}", "not newer" in msg)
    msg = refused("0.3.3", "0.3.3", "the version already running")
    check(f"and says so, got {msg!r}", "not newer" in msg)
    before = len(API.patches)
    for evil in ("latest", "../../etc", "0.3.6@sha256:deadbeef",
                 "0.3.6;rm -rf /", "other.registry/x:0.3.6", "", "0.3",
                 "0.3.6\n0.3.7", "v0.3.6"):
        msg = refused(evil, evil, f"{evil!r}")
        check(f"{evil!r} is rejected as not a version, got {msg!r}",
              "not a version" in msg or "not newer" in msg)
    check(f"and none of those reached the API, got "
          f"{len(API.patches) - before} extra patches",
          len(API.patches) == before)
    # Surrounding whitespace IS tolerated, deliberately: both sides are trimmed
    # before they are compared, so a padded field cannot disagree with the
    # announcement, and the version that comes out is the same one either way.
    API.patches.clear()
    selfupdate.apply(" 0.3.6\t", "0.3.6")
    check("a padded version is trimmed rather than refused",
          API.patches and API.patches[0]["body"]["spec"]["template"]["spec"]
          ["containers"][0]["image"].endswith(":0.3.6"))

    print("a deployment pinned to a digest is left alone")
    # rpartition(':') read the digest as a tag and produced
    # repo@sha256:0.3.6 — a reference to nothing, written over a pin somebody
    # chose on purpose.
    DEPLOY["spec"]["template"]["spec"]["containers"][0]["image"] = (
        "ghcr.io/vendor/devops-portal@sha256:"
        "9f2c1b0e7a5d43c8f6b1e9d0a7c4b2f8e5d3a1c9b7f4e2d0a8c6b4f2e0d8a6c4")
    selfupdate._dep_cache = (0.0, {})
    API.patches.clear()
    msg = refused("0.3.6", "0.3.6", "a digest-pinned deployment")
    check(f"and says why, got {msg!r}", "digest" in msg)
    check("without patching anything", not API.patches)
    st = selfupdate.state("0.3.6", True)
    check("the page offers no button for it",
          not st["possible"] or "digest" in st.get("why", ""))
    DEPLOY["spec"]["template"]["spec"]["containers"][0]["image"] = (
        "ghcr.io/vendor/devops-portal:0.3.3")
    selfupdate._dep_cache = (0.0, {})

    print("a registry cannot be substituted, because it is never an input")
    # The repository is read from the running Deployment. The only way to change
    # it would be to change what is already running, which is the thing being
    # protected — so this asserts the shape rather than a rejection.
    src = (ROOT / "app" / "selfupdate.py").read_text()
    check("apply() builds the reference from the running image",
          'repo, tag = _split(ref)' in src
          and 'f"{repo}:{target}"' in src)
    check("and takes no repository, registry or image argument",
          "def apply(target: str, announced: str, actor: str = \"\")" in src)
    print("  a registry with a port keeps its port")
    check("host:port/path is not mistaken for a tag",
          selfupdate._split("registry.internal:5000/vendor/portal")
          == ("registry.internal:5000/vendor/portal", ""))
    check("and host:port/path:tag splits at the tag",
          selfupdate._split("registry.internal:5000/vendor/portal:0.3.6")
          == ("registry.internal:5000/vendor/portal", "0.3.6"))
    check("a digest reference is left whole rather than half-rewritten",
          selfupdate._split("ghcr.io/v/p@sha256:abc")[1] == "")

    print("when nobody turned it on, there is nothing to press")
    env.SELF_UPDATE = False
    check("it reports itself impossible", not selfupdate.enabled())
    st = selfupdate.state("0.3.6", True)
    check(f"and says why, got {st['why']!r}",
          "off for this installation" in st["why"])
    msg = refused("0.3.6", "0.3.6", "with the feature off")
    check(f"applying is refused, got {msg!r}", "not enabled" in msg)
    env.SELF_UPDATE = True

    print("a cluster that says no produces something a person can act on")
    API.forbid = True
    selfupdate._dep_cache = (0.0, {})
    st = selfupdate.state("0.3.6", True)
    check(f"the page explains rather than breaking, got {st['why'][:60]!r}",
          not st["possible"] and "permission" in st["why"])
    msg = refused("0.3.6", "0.3.6", "when RBAC forbids it")
    check(f"and names the value that grants it, got {msg!r}",
          "rbac.selfUpdate" in msg)
    API.forbid = False
    selfupdate._dep_cache = (0.0, {})

    print("Helm is behind until somebody reconciles it, and it says so")
    env.VERSION = "0.3.6"                     # the new pod is now serving
    selfupdate._dep_cache = (0.0, {})         # the label still says 0.3.3
    d = selfupdate.drift()
    check(f"the drift is reported, got {bool(d)}", bool(d))
    check("naming both versions",
          d["from"] == "0.3.3" and d["to"] == "0.3.6")
    check(f"and warning what a helm upgrade would do, got {d['note'][:40]!r}",
          "move the image back" in d["note"])
    # It must not name the version Helm holds. This process cannot read the
    # release, and after three in-place updates it claimed 0.3.8 while the
    # release was still on 0.3.7 — a wrong number is worse than "older".
    check(f"without claiming which version Helm records, got {d['note']!r}",
          "records an older version" in d["note"]
          and f"records {d['from']}" not in d["note"])
    selfupdate.reconciled()
    check("once reconciled the notice stops", not selfupdate.drift())
    check("but the history is kept rather than deleted",
          selfupdate.last().get("outcome") == "reconciled")

    print("and it measures the drift rather than remembering it")
    from app import db as _db
    # It used to be "a row says we self-updated and nothing cleared it". So a
    # helm upgrade that brought the release UP TO the running version left the
    # notice standing, insisting Helm held something older while Helm held
    # exactly this. That happened on a customer's install. A warning that
    # outlives what it warns about is how people learn to ignore warnings.
    _db.run("UPDATE selfupdates SET outcome = ? WHERE id = "
            "(SELECT MAX(id) FROM selfupdates)", ("requested",))
    DEPLOY["metadata"]["labels"]["app.kubernetes.io/version"] = "0.3.3"
    selfupdate._dep_cache = (0.0, {})
    check("while Helm's label is behind, it still warns",
          bool(selfupdate.drift()))
    check(f"and reads that label, got {selfupdate.helm_version()!r}",
          selfupdate.helm_version() == "0.3.3")

    # a helm upgrade, which this pod learns about only from the label
    DEPLOY["metadata"]["labels"]["app.kubernetes.io/version"] = "0.3.6"
    selfupdate._dep_cache = (0.0, {})
    check("once the label catches up the notice stops on its own",
          not selfupdate.drift())
    check("and the history records that it was reconciled, unprompted",
          selfupdate.last().get("outcome") == "reconciled")

    # a Deployment with no such label must not be read as agreement
    DEPLOY["metadata"]["labels"] = {}
    _db.run("UPDATE selfupdates SET outcome = ? WHERE id = "
            "(SELECT MAX(id) FROM selfupdates)", ("requested",))
    selfupdate._dep_cache = (0.0, {})
    check("a missing label falls back to what was recorded, not to silence",
          bool(selfupdate.drift()))
    DEPLOY["metadata"]["labels"] = {"app.kubernetes.io/version": "0.3.6"}
    selfupdate._dep_cache = (0.0, {})

    print("one render of the page is one call to the API")
    before = len([c for c in API.calls if c.startswith("GET")])
    selfupdate._dep_cache = (0.0, {})
    selfupdate.state("0.3.9", True)           # what About asks for
    selfupdate.drift()                        # and what it asks next
    after = len([c for c in API.calls if c.startswith("GET")])
    check(f"two questions, one request, got {after - before}",
          after - before == 1)

    print("and every attempt is on the record")
    from app import db as _db2
    rows = [dict(r) for r in
            _db2.q("SELECT * FROM selfupdates ORDER BY id")]
    # Two, because this file applies twice: once properly and once to prove a
    # padded version is trimmed rather than refused. Every refusal above is
    # absent, which is the point — nothing is recorded that did not happen.
    check(f"one row per applied update and no more, got {len(rows)}",
          len(rows) == 2)
    check("with who asked for it",
          rows[0]["actor"] == "ops@example.com")
    check("and from and to",
          all((r["from_version"], r["to_version"]) == ("0.3.3", "0.3.6")
              for r in rows))
    check("and nothing recorded for the attempts that were refused",
          not any(r["outcome"] not in ("requested", "reconciled")
                  for r in rows))

    print("decide, answer, then act — in that order")
    # This is the bug that reached a customer. The route patched and THEN sent a
    # redirect; the browser followed it into the gap where the pod had already
    # been stopped, and the ingress answered "no available server" while the
    # update was in fact succeeding. Nothing can be served after the patch, so
    # nothing may be owed after the patch.
    env.VERSION = "0.3.3"
    API.patches.clear()
    decided = selfupdate.plan("0.3.6", "0.3.6")
    check(f"plan() decides the move, got {decided}",
          decided["to"] == "0.3.6"
          and decided["image"].endswith("devops-portal:0.3.6"))
    check("and changes nothing while doing it", not API.patches)
    from app import db as _db
    check("nor records anything",
          len(_db.q("SELECT id FROM selfupdates")) == 2)
    selfupdate.commit(decided, actor="ops@example.com")
    check("commit() is what patches", len(API.patches) == 1)

    import asyncio
    from app import main as M

    class Req:
        def __init__(self, form, accept="application/json"):
            self._form = form
            self.headers = {"accept": accept}
            self.url = types.SimpleNamespace(path="/about/update")
            self.session, self.scope = {}, {}
            self.client = types.SimpleNamespace(host="10.0.0.9")
            self.query_params = types.SimpleNamespace(
                getlist=lambda k: [], get=lambda k, d=None: d)
            self.state = types.SimpleNamespace(
                user={"id": "u", "email": "ops@example.com", "role": "admin"})

        async def form(self):
            return self._form

    # WHAT THE UPDATE FEED ANNOUNCED, which is what the route compares the
    # form's value against. Stubbed at `updates.peek` rather than by priming a
    # cache: the route reads the announcement there and nowhere else, and this
    # file is about selfupdate's refusals, not about how the news arrives.
    from app import updates as _upd
    _real_peek = _upd.peek
    _upd.peek = lambda: {"configured": True, "current": "0.3.5",
                         "latest": "0.3.6", "available": True,
                         "error": "", "checked": True, "age": 0,
                         "notes": "notes"}

    API.patches.clear()
    res = asyncio.run(M.about_update(Req({"version": "0.3.6"})))
    check(f"an accepted click is answered 202, got {res.status_code}",
          res.status_code == 202)
    check("and nothing has been patched yet when the answer is produced",
          not API.patches)
    check("the patch is owed to a background task instead",
          res.background is not None)
    asyncio.run(res.background())          # what Starlette runs after flushing
    check("which patches once the answer is on the wire",
          len(API.patches) == 1)

    print("a refusal is decided while there is still a process to say so")
    API.patches.clear()
    bad_res = asyncio.run(M.about_update(Req({"version": "9.9.9"})))
    check(f"it answers 400, got {bad_res.status_code}",
          bad_res.status_code == 400)
    check("with the reason in the body",
          b"announced" in bytes(bad_res.body))
    check("and patches nothing", not API.patches)
    check("and owes nothing afterwards", bad_res.background is None)

    print("without JavaScript it answers with a page, never a redirect")
    # A redirect needs a second request, and there will be no process to serve
    # one. So the response that follows the click has to BE the progress page.
    API.patches.clear()
    html = asyncio.run(M.about_update(Req({"version": "0.3.6"}, accept="text/html")))
    check(f"a page, not a redirect, got {html.status_code}",
          html.status_code == 200)
    check("carrying the progress card and its poller",
          b'id="updating"' in bytes(html.body)
          and b"healthz" in bytes(html.body))
    check("and it still patches only afterwards",
          not API.patches and html.background is not None)
    asyncio.run(html.background())
    _upd.peek = lambda: {"configured": False, "current": "0.3.5",
                         "latest": "", "available": False,
                         "error": "", "checked": False, "age": None}

    print("the button is on both pages people look at, from one implementation")
    # It was written twice. The second copy — Settings → Deployment — had no
    # button at all and still told the reader the portal could not update itself,
    # underneath a notice that a new version was available. It also printed the
    # vendor's own chart repository, which the other page deliberately refuses to
    # do. One include cannot disagree with itself.
    tpl = ROOT / "templates"
    progress = (tpl / "_update_progress.html").read_text()
    button = (tpl / "_update_button.html").read_text()
    for page in ("about.html", "set_deployment.html"):
        body = (tpl / page).read_text()
        check(f"{page} includes the progress card",
              '{% include "_update_progress.html" %}' in body)
        check(f"{page} includes the button",
              '{% include "_update_button.html" %}' in body)
        check(f"{page} keeps no copy of the form",
              'id="updform"' not in body)
        check(f"{page} no longer says the portal cannot update itself",
              "cannot do it itself" not in body)
        check(f"{page} prints no vendor chart path",
              "devops-portal/config-portal" not in body)

    # The include sits near the top of a page, so the form does not exist yet when
    # its script runs. Without waiting, getElementById returned null, no handler
    # was attached, and the click fell through to a plain navigation — which is
    # the failure the whole file exists to prevent, reintroduced by moving code.
    check("the script waits for the document before wiring the form",
          "DOMContentLoaded" in progress and "readyState" in progress)
    check("and finds the form by id rather than by position",
          "getElementById('updform')" in progress)
    check("the health URL is rendered by the server, not derived from the path",
          "data-healthz" in progress
          and "request.scope.root_path" in progress)
    check("the click is sent by fetch, not by navigating",
          "fetch(form.action" in progress and "preventDefault" in progress)
    # Feedback comes before the request, not after it. Waiting for the answer
    # meant the page said nothing for as long as the Kubernetes API took, so the
    # button looked broken and got pressed again and again.
    order = progress.index("begin();") < progress.index("fetch(form.action")
    check("the progress card is shown before the request is sent", order)
    check("a request that dies mid-flight does not undo it",
          ".catch(() => {});" in progress)
    check("only a refusal undoes it, and it puts the form back",
          "undo();" in progress and "function undo()" in progress
          and "form.hidden = false" in progress)
    check("and a second press cannot start a second update",
          "if (sending) return;" in progress)
    check("the button posts to the one route that decides",
          'action="/about/update"' in button)

    print("the chart decides whether any of this exists")
    import subprocess
    chart = ROOT / "deploy" / "helm" / "config-portal"

    def render(*extra):
        out = subprocess.run(["helm", "template", "t", str(chart), *extra],
                             capture_output=True, text=True)
        if out.returncode:
            print(f"  FAIL helm template: {out.stderr[:200]}")
            return ""
        return out.stdout

    off = render()
    check("by default there is no Role at all", "kind: Role" not in off)
    check("and the pod is told nothing about self-updating",
          "PORTAL_SELF_UPDATE" not in off)
    on = render("--set", "rbac.selfUpdate=true")
    check("turning it on creates a Role", "kind: Role" in on)
    check("a Role and not a ClusterRole, so it cannot reach another namespace",
          "kind: ClusterRole" not in on)
    check("scoped to one object by name",
          "resourceNames: [t-config-portal]" in on)
    check("with no verb beyond get and patch",
          "verbs: [get, patch]" in on)
    # The Role document on its own, not "everything after the first match" —
    # that swept in the RoleBinding and would have passed whatever the Role said.
    role = next((d for d in on.split("\n---\n")
                 if "kind: Role\n" in d or d.strip().startswith("kind: Role")),
                "")
    check(f"the Role document was found, got {len(role)} chars", bool(role))
    for verb in ("delete", "create", "update", "list", "watch", "*"):
        check(f"and grants no {verb}", f"{verb}" not in
              role.split("verbs:")[-1] if "verbs:" in role else False)
    check("over no resource but deployments",
          role.count("resources:") == 1 and "resources: [deployments]" in role)
    check("and the pod is told which deployment it is",
          'value: "t-config-portal"' in on and "PORTAL_SELF_DEPLOYMENT" in on)
    check("and reads its namespace from itself rather than being told wrongly",
          "fieldPath: metadata.namespace" in on)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
