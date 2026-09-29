"""Updating this installation from its own page, in one click.

WHAT CHANGED ITS MIND
    updates.py said, and still says, that a portal which could update itself
    would be a portal that could be made to install anything. That is true of an
    unconstrained self-update, and this is not one. The whole design here is the
    set of things this code *cannot* be talked into:

      * it cannot choose a registry. The repository comes out of the Deployment
        that is already running; only the tag after the last colon is replaced.
      * it cannot choose a version. The target must be the one the feed
        service (or the configured feed) announced, and it must be newer than
        what is running. A version in a form field is compared against that and
        refused if it differs.
      * it cannot reach anything but its own Deployment. The Role the chart
        creates names that one object in `resourceNames`, so the API server
        refuses the rest — the guard is Kubernetes', not a conditional here.
      * it does not exist unless somebody turned it on. `rbac.selfUpdate` is
        false by default, so an install that wants the original promise keeps it
        and never grants the token any write at all.

WHY PATCHING THE DEPLOYMENT AND NOT RUNNING HELM
    Running helm in-pod would keep the release consistent, and it needs the helm
    binary, credentials to pull a private chart, and permission over every object
    the chart owns. That is a far larger grant for a smaller problem, and the
    chart credential does not exist for customers yet. Patching one image tag
    needs `patch` on one object.

    The cost is honest and has to be said out loud on the page: Helm still
    believes the old appVersion, so the next `helm upgrade` moves the image back.
    `drift()` is what says so, and it keeps saying it until the release catches
    up.

WHY NOTHING IS SERVED AFTER THE PATCH
    The chart's strategy is Recreate — one replica, one volume, so the old pod is
    stopped before the new one starts. The request that asks for the update is
    served by the process that is about to be killed.

    The first version knew that and still got it wrong: it patched, then answered
    with a redirect. The browser followed the redirect into a gap where the pod no
    longer existed, and a customer read "no available server" from the ingress.
    The update had worked perfectly; only the page could not say so.

    So the order is decide (`plan`), answer, then act (`commit`) — and the page
    does not need the answer either. It posts, switches itself into the updating
    state whatever comes back, and watches /healthz until a different version
    answers. A click whose outcome nobody needs cannot be lost.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request

from . import db, env, urlguard

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
TIMEOUT = 15

# Strict, and anchored. This string is interpolated into an image reference, so
# it is the one piece of the target that has to be beyond argument: three
# numbers, optionally a pre-release of word characters. No slashes, no colons,
# no at-signs — nothing that could turn a tag into a different image.
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$")

SCHEMA = ["""CREATE TABLE IF NOT EXISTS selfupdates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    from_version TEXT,
    to_version TEXT,
    actor TEXT,
    outcome TEXT)"""]


def _migrate(c) -> None:
    for stmt in SCHEMA:
        c.execute(stmt)


db.register(_migrate)


class UpdateError(Exception):
    """Something the person who pressed the button needs to read."""


# ── where we are running ───────────────────────────────────────
def _token() -> str:
    with open(f"{SA_DIR}/token", encoding="utf-8") as fh:
        return fh.read().strip()


def namespace() -> str:
    ns = env.SELF_NAMESPACE
    if ns:
        return ns
    try:
        with open(f"{SA_DIR}/namespace", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def in_cluster() -> bool:
    return os.path.exists(f"{SA_DIR}/token")


def enabled() -> bool:
    return bool(env.SELF_UPDATE and env.SELF_DEPLOYMENT and in_cluster())


def _ctx() -> ssl.SSLContext:
    """Verify the API server with the CA the cluster mounted. Not skipped: this
    connection carries a token that can change what runs in the namespace."""
    return ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")


def _api(path: str, method: str = "GET", body: bytes | None = None,
         ctype: str = "") -> dict:
    url = f"{API}{path}"
    headers = {"Authorization": f"Bearer {_token()}",
               "Accept": "application/json"}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(urlguard.check(url), data=body,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT,
                                    context=_ctx()) as res:
            return json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read() or b"{}").get("message", "")
        except Exception:                                      # noqa: BLE001
            pass
        if e.code in (401, 403):
            raise UpdateError(
                "the cluster refused this portal permission to change its own "
                "deployment. Install with rbac.selfUpdate=true, or upgrade with "
                f"Helm instead. ({detail or e.code})") from e
        raise UpdateError(f"the cluster answered {e.code}: "
                          f"{detail or 'no detail'}") from e
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"cannot reach the Kubernetes API: {e}") from e


_dep_cache: tuple[float, dict] = (0.0, {})
DEP_TTL = 3


def _deployment(fresh: bool = False) -> dict:
    """This install's own Deployment, briefly cached.

    One render of the About page asks twice — once for the image it is running,
    once for the version Helm stamped on it — and two calls to the API server to
    draw one card is one too many. Three seconds is long enough to collapse a
    render and short enough that a deliberate action a moment later sees the
    truth.
    """
    global _dep_cache
    if not fresh and time.time() - _dep_cache[0] < DEP_TTL and _dep_cache[1]:
        return _dep_cache[1]
    got = _api(f"/apis/apps/v1/namespaces/{namespace()}/deployments/"
               f"{env.SELF_DEPLOYMENT}")
    _dep_cache = (time.time(), got)
    return got


# ── what is running, and what it would become ──────────────────
def pinned_by_digest(ref: str) -> bool:
    """Whether this reference names a digest rather than a tag.

    `repo@sha256:…` has a colon that belongs to the digest, so a naive tag split
    produced `repo@sha256:0.3.6` — a reference to nothing, applied to a
    deployment that had been deliberately pinned. A digest pin is somebody
    stating they want exactly these bytes; the answer is to refuse and let them
    upgrade with Helm, not to quietly unpin them.
    """
    return "@" in ref.rsplit("/", 1)[-1]


def _split(ref: str) -> tuple[str, str]:
    """An image reference into (repository, tag).

    Split on the LAST colon, and only when it is after the last slash — a
    registry with a port (`registry:5000/x/y`) has a colon that is not a tag,
    and treating it as one would rewrite the host. A digest reference has no tag
    at all and comes back whole.
    """
    if pinned_by_digest(ref):
        return ref, ""
    head, sep, tail = ref.rpartition(":")
    if not sep or "/" in tail:
        return ref, ""
    return head, tail


def current_image(fresh: bool = False) -> str:
    """The image reference the running Deployment asks for."""
    dep = _deployment(fresh=fresh)
    for c in (dep.get("spec", {}).get("template", {})
                 .get("spec", {}).get("containers") or []):
        if c.get("name") == (env.SELF_CONTAINER or "portal"):
            return str(c.get("image", ""))
    raise UpdateError(f"the deployment has no container called "
                      f"{env.SELF_CONTAINER or 'portal'}")


def state(latest: str = "", available: bool = False) -> dict:
    """Everything the page needs to decide what to draw.

    Never raises: this is called while rendering, and a cluster that cannot be
    reached must produce an explanation rather than a 500.
    """
    out = {"possible": False, "why": "", "target": latest,
           "image": "", "repository": "", "in_cluster": in_cluster(),
           "configured": bool(env.SELF_UPDATE)}
    if not env.SELF_UPDATE:
        out["why"] = ("one-click updating is off for this installation — it is "
                      "enabled at install time with rbac.selfUpdate=true")
        return out
    if not in_cluster():
        out["why"] = "this portal is not running inside Kubernetes"
        return out
    if not env.SELF_DEPLOYMENT:
        out["why"] = ("the chart did not tell this pod which deployment it "
                      "belongs to")
        return out
    if not available or not latest:
        out["why"] = "there is nothing newer to move to"
        return out
    try:
        ref = current_image()
    except UpdateError as e:
        out["why"] = str(e)
        return out
    if pinned_by_digest(ref):
        # Checked here as well as in apply(): a button that is offered and then
        # refuses is worse than one that explains itself before being pressed.
        out["why"] = ("this installation pins its image by digest, which a "
                      "one-click update would undo — upgrade with Helm, or pin "
                      "the new digest")
        return out
    repo, _tag = _split(ref)
    out.update(possible=True, image=ref, repository=repo,
               target_image=f"{repo}:{latest}")
    return out


# ── doing it ───────────────────────────────────────────────────
def plan(target: str, announced: str) -> dict:
    """Everything that can be refused, decided before anything is changed.

    Split from the patch because of how the first version failed in front of a
    customer: the route patched and then answered with a redirect, and by the
    time the browser followed it the pod was gone, so the ingress had nothing to
    serve and the page read "no available server". The update had worked.

    So the order has to be: decide, answer, then act. This is the deciding half,
    and it writes nothing.
    """
    if not enabled():
        raise UpdateError("one-click updating is not enabled for this "
                          "installation")
    target = (target or "").strip()
    announced = (announced or "").strip()
    if not VERSION_RE.match(target):
        raise UpdateError(f"{target!r} is not a version number")
    if target != announced:
        raise UpdateError(
            f"{target} is not the release that was announced ({announced or 'none'}) "
            f"— this portal only moves to the version its update feed names")
    running = env.VERSION
    if not _newer(target, running):
        raise UpdateError(f"{target} is not newer than {running}")

    ref = current_image(fresh=True)
    if pinned_by_digest(ref):
        raise UpdateError(
            "this installation pins its image by digest, which is a deliberate "
            "choice this button would undo. Upgrade with Helm instead, or pin "
            "the new digest.")
    repo, tag = _split(ref)
    if not repo:
        raise UpdateError(f"cannot read a repository out of {ref!r}")
    if tag == target:
        raise UpdateError(f"the deployment already asks for {target}")
    return {"from": running, "to": target, "image": f"{repo}:{target}"}


def commit(decided: dict, actor: str = "") -> dict:
    """The acting half: record it, then patch. Runs after the answer is sent."""
    patch = {"spec": {"template": {"spec": {"containers": [
        {"name": env.SELF_CONTAINER or "portal",
         "image": decided["image"]}]}}}}
    _record(decided["from"], decided["to"], actor, "requested")
    _api(f"/apis/apps/v1/namespaces/{namespace()}/deployments/"
         f"{env.SELF_DEPLOYMENT}", method="PATCH",
         body=json.dumps(patch).encode(),
         ctype="application/strategic-merge-patch+json")
    return decided


def apply(target: str, announced: str, actor: str = "") -> dict:
    """Decide and act in one call — for a caller that can wait for both.

    Both versions are passed in so the comparison happens here rather than being
    trusted from the form: `target` is what the button submitted, `announced` is
    what the update feed said. They have to agree.
    """
    return commit(plan(target, announced), actor)


def _newer(a: str, b: str) -> bool:
    def parts(v):
        m = VERSION_RE.match(v)
        return tuple(int(x) for x in v.split("-")[0].split(".")) if m else ()
    pa, pb = parts(a), parts(b)
    return bool(pa) and bool(pb) and pa > pb


def _record(frm: str, to: str, actor: str, outcome: str) -> None:
    db.run("INSERT INTO selfupdates (at, from_version, to_version, actor, "
           "outcome) VALUES (?,?,?,?,?)",
           (int(time.time()), frm, to, actor or "", outcome))


def last() -> dict:
    """The most recent in-place update, if there was one."""
    row = db.one("SELECT * FROM selfupdates ORDER BY id DESC LIMIT 1")
    return dict(row) if row else {}


def helm_version() -> str:
    """The version Helm last wrote onto this Deployment, or "".

    The release itself is a Secret this pod cannot read, but the chart stamps
    `app.kubernetes.io/version` onto the object it creates — so what Helm believes
    is legible from something already permitted. That is the difference between
    measuring the drift and remembering it.
    """
    try:
        labels = (_deployment().get("metadata") or {}).get("labels") or {}
    except UpdateError:
        return ""
    return str(labels.get("app.kubernetes.io/version") or "")


GUACD_CONTAINER = "guacd"


def _check_command() -> str:
    """The one command that answers this when the portal may not look itself.

    A CUSTOMER ON THE LATEST RELEASE still saw "not reachable", and the portal
    is granted nothing over its own namespace by default — so the honest
    answer there is "I cannot tell", which on its own leaves somebody exactly
    where they started. It knows its namespace (from the mounted service
    account) and its Deployment name (from the chart's own env), so it can
    hand over the exact command instead of a shape to fill in.
    """
    ns = namespace() or "<namespace>"
    dep = env.SELF_DEPLOYMENT or "<release>-config-portal"
    return (f"kubectl -n {ns} get deploy {dep} "
            "-o jsonpath='{.spec.template.spec.containers[*].name}'")


def _containers(dep: dict) -> list:
    return (((dep.get("spec") or {}).get("template") or {})
            .get("spec") or {}).get("containers") or []


def gateway_container(image: str, mount: str) -> dict:
    """The gateway sidecar exactly as the chart would render it.

    A FUNCTION so it can be compared with the chart. The portal cannot read
    its own chart from inside a pod, so it must carry a copy of this container
    spec — and a copy is a thing that drifts. `tests/test_chart.py` renders the
    chart with the gateway on and compares that container with this dict, so a
    gateway added from the settings page is the gateway Helm would have
    deployed rather than a near-miss.
    """
    return {"name": GUACD_CONTAINER, "image": image,
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {"allowPrivilegeEscalation": False,
                                "runAsNonRoot": True,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "ports": [{"name": "guacd", "containerPort": 4822}],
            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                          "limits": {"memory": "512Mi"}},
            "volumeMounts": [{"name": "data", "mountPath": mount}]}


def gateway_state() -> dict:
    """Whether the RDP/VNC gateway sidecar is in this install's Deployment.

    WHY LOOK AT ALL. The settings page said "the chart did not deploy it: set
    `guacd.enabled: true`" whenever the socket did not answer, which is a
    GUESS dressed as a diagnosis — and since the chart default became `true`
    it is usually the wrong guess. A customer sent a screenshot of exactly
    that: an install being told to set a value that is already its default.
    The Deployment knows which case it is, so ask it.

    Three answers, kept apart because they need different actions:
      * `absent`   — no such container. The chart did not deploy it (an older
                     chart, or `guacd.enabled: false`), and this is the one
                     case a button can fix.
      * `present`  — the container IS there and the socket still is not
                     answering, so it is starting, crash-looping or bound
                     elsewhere. Adding it again would fix nothing.
      * `unknown`  — the portal has no permission to look, which is the
                     DEFAULT: it is granted nothing over its own namespace
                     unless `rbac.selfUpdate` is on. "I cannot tell" is the
                     honest answer, and better than the confident wrong one it
                     replaces.
    """
    if not in_cluster():
        return {"how": "unknown",
                "why": "this portal is not running in a cluster"}
    try:
        dep = _deployment(fresh=True)
    # ANY failure, not just UpdateError. This is rendered on a settings page,
    # and a page that cannot draw because a DIAGNOSIS failed is worse than the
    # thing it was diagnosing. The reason is carried through either way.
    except Exception as e:                                     # noqa: BLE001
        return {"how": "unknown", "why": str(e) or type(e).__name__,
                "check": _check_command()}
    names = [c.get("name") for c in _containers(dep)]
    if GUACD_CONTAINER in names:
        return {"how": "present", "why": "the gateway container is in this "
                "deployment but is not answering — it may still be starting, "
                "or it may be failing to start"}
    return {"how": "absent", "why": "this deployment has no gateway container",
            "containers": names}


def add_gateway(image: str, actor: str = "") -> dict:
    """Add the gateway sidecar to this install's own Deployment.

    The same one grant self-update already uses — `patch` on exactly this
    Deployment, named in the Role's `resourceNames` — so nothing new is asked
    for, and an install that never turned that on cannot do this either.

    A STRATEGIC MERGE PATCH merges containers BY NAME, so this appends the
    sidecar and leaves the portal's own container untouched. The mount path is
    read off the running portal container rather than assumed: it is a chart
    value, an install may have moved it, and a gateway writing recordings
    somewhere the portal does not serve them from would be worse than none.

    TWO COSTS, both said out loud on the page that offers this:
      * the pod restarts, because changing a pod template is what that means;
      * if the cluster cannot pull this image the WHOLE POD stops, not just
        this container — a sidecar's pull failure takes the portal down with
        it. That is why the image is configuration: a mirrored or air-gapped
        install points it at their own registry first.
    """
    if not enabled():
        raise UpdateError(
            "this portal was not granted permission to change its own "
            "deployment. Install with rbac.selfUpdate=true, or set "
            "guacd.enabled=true in your Helm values and upgrade.")
    ref = (image or "").strip()
    if not ref or " " in ref:
        raise UpdateError("that is not a usable image reference")
    dep = _deployment(fresh=True)
    if GUACD_CONTAINER in [c.get("name") for c in _containers(dep)]:
        raise UpdateError("the gateway container is already in this deployment")
    mine = next((c for c in _containers(dep)
                 if c.get("name") == (env.SELF_CONTAINER or "portal")), {})
    mount = next((m.get("mountPath") for m in (mine.get("volumeMounts") or [])
                  if m.get("name") == "data"), "")
    if not mount:
        raise UpdateError(
            "this portal's own container has no `data` volume mounted, so a "
            "gateway added here could not write recordings where the portal "
            "serves them from. Set guacd.enabled=true in your Helm values "
            "instead.")
    _api(f"/apis/apps/v1/namespaces/{namespace()}/deployments/"
         f"{env.SELF_DEPLOYMENT}", method="PATCH",
         body=json.dumps({"spec": {"template": {"spec": {"containers": [
             gateway_container(ref, mount)]}}}}).encode(),
         ctype="application/strategic-merge-patch+json")
    return {"image": ref, "mount": mount}


def drift() -> dict:
    """Whether this install is running something its Helm release does not know.

    An in-place update changes the Deployment and not the release, so Helm still
    holds the old appVersion and the next `helm upgrade` will put the old image
    back. Saying so is the price of the one-click, and it is a price worth
    stating rather than discovering.

    MEASURED, NOT REMEMBERED
        This used to be "a row says we self-updated and nothing has cleared it",
        which meant a `helm upgrade` that reconciled the release left the notice
        standing until somebody called reconciled(). It happened: a release was
        brought up to the running version and the page went on insisting Helm
        held an older one. A warning that outlives what it warns about teaches
        people to ignore warnings.

        So the label Helm stamps on the Deployment is compared with what is
        running. When they agree there is nothing to say, whoever made them
        agree and whether anything remembered it.
    """
    got = last()
    if not got:
        return {}
    stamped = helm_version()
    if stamped and stamped == env.VERSION:
        # Helm's own label agrees with what is running: reconciled, by whatever
        # route. Record it so the history reads correctly, and say nothing.
        if got.get("outcome") == "requested":
            reconciled()
        return {}
    if got.get("outcome") != "requested":
        return {}
    # `to_version`, which is the column. Reading a key the row does not have made
    # this return {} for every install, so the notice this whole trade-off
    # depends on was never shown — and nothing said so.
    if got.get("to_version") != env.VERSION:
        # either it has not landed yet, or somebody has since moved on
        return {}
    # It does NOT say which version Helm records, because this process cannot
    # know: the release lives in a Secret it has no permission to read, and the
    # version it was running before is not the same thing. After three in-place
    # updates the note claimed Helm held 0.3.8 when the release was still on
    # 0.3.7 — a specific number that is wrong is worse than an honest "older".
    return {"since": got["at"], "from": got["from_version"],
            "to": got["to_version"],
            "note": (f"this installation was updated in place to "
                     f"{got['to_version']}. Its Helm release still records an "
                     f"older version, so the next helm upgrade will move the "
                     f"image back unless it is run with a chart of "
                     f"{got['to_version']} or newer. Reconcile when convenient "
                     f"— nothing is broken in the meantime.")}


def reconciled() -> None:
    """Called when a Helm upgrade has caught the release up, so the notice stops.

    Recorded rather than deleted: an install's history of being updated in place
    is worth keeping when somebody asks why a version moved without a release.
    """
    got = last()
    if got and got.get("outcome") == "requested":
        db.run("UPDATE selfupdates SET outcome = ? WHERE id = ?",
               ("reconciled", got["id"]))
