"""Cluster management: validated kubectl commands, and the actions built on them.

WHY THIS MODULE EXISTS AT ALL
    Every other cluster read in the portal is a fixed command with fixed
    arguments. This one runs what a person typed, and it can change a cluster.
    That is a different risk class, so the rules live in one file where they can
    be read in full rather than being spread across route handlers.

THE SAFETY MODEL
    1. A cluster is read-only until someone ticks "allow management" on it.
       Without that flag, every mutating verb is refused — including through the
       console — so adding a kubeconfig with write permission does not by itself
       make the cluster writable from here.
    2. Identity is never negotiable. The kubeconfig, the context and the
       namespace-less defaults come from the stored cluster; a command that tries
       to supply its own --kubeconfig, --context, --server, --token or --as is
       refused rather than sanitised, because silently ignoring half of what
       someone typed is worse than saying no.
    3. Only kubectl. No shell: the command is split into arguments and executed
       directly, so a pipe, a redirect or a subshell is text, never behaviour.
    4. Nothing interactive or unbounded THROUGH THE CONSOLE. exec, attach,
       port-forward, cp, proxy, debug and edit are refused there, and --watch
       and --follow never return. The pod terminal further down is the one
       place with a real tty, and it is a separate door with its own rules.
    5. Every command is audited with who ran it, against which cluster, and what
       it returned — including the ones that were refused. In the terminal,
       where there is no command boundary, `pty_audit_line` rebuilds one audit
       entry per line typed, and hides the ones the container did not echo.
    6. A cluster mapped to a production environment additionally requires the
       caller to have confirmed by name. The route enforces that; this module
       reports whether a command mutates so the route can ask.

WHAT IS DELIBERATELY NOT HERE
    `kubectl apply -f` from a pasted manifest, and anything that writes to a
    cluster without an equivalent in git. The portal's whole model is that
    desired state lives in the repository and ArgoCD applies it; a manifest typed
    into a web page has no history and no review. Restarting, scaling, cordoning
    and deleting a pod are operational actions on running state, which is a
    different thing from changing what is deployed.

    THE ONE EXCEPTION, AND WHY IT IS ONE: metrics-server, further down. It is
    not a manifest somebody typed — it is one fixed add-on, from one URL set by
    configuration, whose content is read and checked before any of it is
    applied. The reason it earns an exception is that without it this portal
    cannot answer "what is this cluster doing", only "what does it have", and no
    amount of reading fixes that. Anything else that wants to install itself
    from a page belongs in the customer's repository, not here.
"""
import base64
import fcntl
import os
import json
import secrets
import re
import select
import shlex
import signal
import struct
import subprocess
import termios
import threading
import time
import tty

from . import env
from .kube import base_args, reachable

TIMEOUT = 30
OUTPUT_CAP = 200_000        # one HTTP response's worth; the rest is truncated

# Verbs that only read. Anything not in here is treated as mutating, so a new
# kubectl verb is refused by default rather than allowed by omission.
READ_VERBS = {
    "get", "describe", "explain", "top", "logs", "events", "api-resources",
    "api-versions", "version", "cluster-info", "auth", "config-view", "diff",
    "kustomize", "wait",
}

# Verbs that change something, permitted only on a cluster marked for management.
WRITE_VERBS = {
    "apply", "create", "delete", "patch", "replace", "scale", "rollout",
    "annotate", "label", "set", "cordon", "uncordon", "drain", "taint",
    "expose", "autoscale", "rollback", "apply-f",
}

# Refused whatever the flags say: these need a terminal, stream forever, or
# would let the console re-point itself at another cluster.
BLOCKED_VERBS = {
    "exec": "runs a shell inside a container — use the pod logs page, or a "
            "terminal",
    "attach": "attaches to a running container, which needs a terminal",
    "port-forward": "holds a connection open; run it from your own machine",
    "proxy": "starts a long-running local proxy",
    "cp": "copies files in and out of containers",
    "debug": "creates a debug container and attaches to it",
    "edit": "opens an editor, which needs a terminal — use patch or the repo",
    "config": "reads and writes kubeconfig files; the portal decides identity",
    "plugin": "runs arbitrary plugin binaries",
    "completion": "prints shell completion code, which is of no use here",
}

# Flags that would change *who* or *where* the command runs.
BLOCKED_FLAGS = (
    "--kubeconfig", "--context", "--cluster", "--server", "--token",
    "--as", "--as-group", "--as-uid", "--user", "--client-certificate",
    "--client-key", "--insecure-skip-tls-verify", "--certificate-authority",
    "--password", "--username", "--tls-server-name",
)

# Flags that never finish inside a request.
STREAMING_FLAGS = ("--watch", "-w", "--watch-only", "--follow", "-f")

# Shell syntax has no meaning here, but a command containing it is almost
# certainly not the command someone meant to run, so say so.
SHELLISH = re.compile(r"[;&|<>`$\n\r]|\$\(")

# Some kubectl verbs report a refusal in their output and still exit 0, so the
# exit code is not on its own enough to decide whether an action worked.
FAILED_ANYWAY = re.compile(r"(?im)^\s*error\b|is forbidden|unable to |not found")


class Refused(Exception):
    """A command the portal will not run, with the reason in the message."""


def verb_of(argv: list) -> str:
    """The kubectl subcommand, ignoring leading global flags."""
    for a in argv:
        if not a.startswith("-"):
            return a.lower()
    return ""


def classify(argv: list) -> str:
    """"read", "write", or raise Refused."""
    verb = verb_of(argv)
    if not verb:
        return "read"
    if verb in BLOCKED_VERBS:
        raise Refused(f"`kubectl {verb}` is not available here: "
                      f"{BLOCKED_VERBS[verb]}")
    if verb in READ_VERBS:
        # `kubectl logs -f` and `get -w` never return
        return "read"
    if verb in WRITE_VERBS:
        return "write"
    raise Refused(f"`kubectl {verb}` is not a command the portal recognises, so "
                  "it is refused rather than assumed safe")


def parse(raw: str) -> list:
    """A typed command as an argument list, or Refused with the reason."""
    text = (raw or "").strip()
    if not text:
        raise Refused("type a command first")
    if SHELLISH.search(text):
        raise Refused("pipes, redirects and subshells are not supported — the "
                      "command runs directly, not through a shell")
    try:
        argv = shlex.split(text)
    except ValueError as e:
        raise Refused(f"could not read that command: {e}") from e
    if argv and argv[0].lower() in ("kubectl", "k"):
        argv = argv[1:]
    if not argv:
        raise Refused("type a command after kubectl")
    for a in argv:
        low = a.lower()
        base = low.split("=", 1)[0]
        if base in BLOCKED_FLAGS:
            raise Refused(f"`{base}` is not allowed: the cluster, its kubeconfig "
                          "and the identity used are set by the portal")
        if base in STREAMING_FLAGS and verb_of(argv) in ("get", "logs", "events"):
            raise Refused(f"`{a}` would never finish inside a page — the Logs "
                          "page streams logs, and the tabs here refresh")
    return argv


def run(cluster: dict, raw: str, allow_write: bool = False,
        timeout: int = TIMEOUT) -> dict:
    """Run one validated kubectl command against this cluster.

    Returns the outcome rather than raising for a non-zero exit: a command that
    fails in the cluster is a result to read, not an error in the portal.
    """
    argv = parse(raw)
    kind = classify(argv)
    if kind == "write" and not allow_write:
        raise Refused(read_only_why("this command changes it"))
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    alive, why = reachable(cluster)
    if not alive:
        # answered like a failed command, not an exception: the console should
        # print it where the output would have been
        return {"argv": argv, "kind": kind, "code": 1, "stdout": "",
                "stderr": f"cluster unreachable — {why}", "truncated": False,
                "took": 0.0,
                "display": "kubectl " + " ".join(shlex.quote(a) for a in argv)}

    started = time.time()
    try:
        r = subprocess.run(base + argv + [f"--request-timeout={timeout - 3}s"],
                           capture_output=True, text=True, timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", f"timed out after {timeout}s", 124
    except Exception as e:                                    # noqa: BLE001
        out, err, code = "", f"{type(e).__name__}: {e}", 1

    truncated = len(out) > OUTPUT_CAP
    return {
        "argv": argv, "kind": kind, "code": code,
        "stdout": out[:OUTPUT_CAP], "stderr": err[-8000:],
        "truncated": truncated,
        "took": round(time.time() - started, 2),
        "display": "kubectl " + " ".join(shlex.quote(a) for a in argv),
    }


# ── the actions the tabs offer ─────────────────────────────────
# Each one is a kubectl command with fixed shape: the page supplies only names,
# never flags. `destructive` decides whether the UI asks twice.
ACTIONS = {
    "restart": {
        "label": "Rolling restart", "needs": ("kind", "namespace", "name"),
        "destructive": False,
        "build": lambda a: ["rollout", "restart", f"{a['kind']}/{a['name']}",
                            "-n", a["namespace"]],
        "note": "recreates the pods one at a time, keeping the deployed version",
    },
    "scale": {
        "label": "Scale", "needs": ("kind", "namespace", "name", "replicas"),
        "destructive": True,
        "build": lambda a: ["scale", f"{a['kind']}/{a['name']}",
                            f"--replicas={int(a['replicas'])}", "-n", a["namespace"]],
        "note": "changes the running replica count — git still says the old "
                "number, so ArgoCD may put it back",
    },
    "undo": {
        "label": "Roll back", "needs": ("kind", "namespace", "name"),
        "destructive": True,
        "build": lambda a: ["rollout", "undo", f"{a['kind']}/{a['name']}",
                            "-n", a["namespace"]],
        "note": "returns to the previous revision of this workload",
    },
    "delete-pod": {
        "label": "Delete pod", "needs": ("namespace", "name"),
        "destructive": True,
        "build": lambda a: ["delete", "pod", a["name"], "-n", a["namespace"]],
        "note": "the controller recreates it; use this to recycle one replica",
    },
    "cordon": {
        "label": "Cordon", "needs": ("node",),
        "destructive": False,
        "build": lambda a: ["cordon", a["node"]],
        "note": "stops new pods being scheduled here; running pods stay",
    },
    "uncordon": {
        "label": "Uncordon", "needs": ("node",),
        "destructive": False,
        "build": lambda a: ["uncordon", a["node"]],
        "note": "allows scheduling again",
    },
    "drain": {
        "label": "Drain", "needs": ("node",),
        "destructive": True,
        "build": lambda a: ["drain", a["node"], "--ignore-daemonsets",
                            "--delete-emptydir-data", "--timeout=120s"],
        "note": "moves every pod off this node — expect disruption for anything "
                "without a second replica",
    },
    "install-metrics": {
        "label": "Install metrics-server", "needs": (), "destructive": False,
        # What it starts with, and what a preview shows. The patch that follows
        # cannot be written as one kubectl command because it depends on what is
        # already there, so the note carries it and `run` performs it.
        "build": lambda a: ["apply", "-f", env.METRICS_URL],
        "run": lambda cluster, args, timeout: install_metrics(cluster, timeout),
        "timeout": 120,
        "note": "fetches the upstream manifest, applies it into kube-system, "
                "then adds the two kubelet flags a Talos node needs; usage "
                "appears 30-60 seconds later. It is installed outside git, so "
                "a cluster whose add-ons are managed by ArgoCD should carry it "
                "there instead",
    },
    "sync-app": {
        "label": "Sync", "needs": ("namespace", "name"),
        "destructive": False,
        # asking ArgoCD to sync is a write to its Application object, which is
        # how the CLI does it too
        "build": lambda a: ["patch", "application", a["name"], "-n",
                            a["namespace"], "--type", "merge", "-p",
                            '{"operation":{"initiatedBy":{"username":"config-portal"},'
                            '"sync":{"revision":"HEAD"}}}'],
        "note": "asks ArgoCD to reconcile this application now",
    },
}


# ── metrics-server ─────────────────────────────────────────────
# The cluster page can say what a machine HAS from the node object alone, and
# what it is DOING only from the aggregated metrics API — which most
# distributions do not ship. So the page offers to install it, and this is that
# install: fixed source, checked content, computed patch.
METRICS_NAMESPACE = "kube-system"
METRICS_DEPLOYMENT = "metrics-server"

# What a Talos node needs, and in practice most clusters: the kubelet serves a
# certificate the cluster CA did not sign, and metrics-server otherwise dials a
# node name that nothing inside the cluster resolves. --kubelet-insecure-tls is
# a real trade — metrics-server stops verifying the kubelet's certificate — so
# the page says so rather than adding it quietly.
TALOS_ARGS = ("--kubelet-insecure-tls",
              "--kubelet-preferred-address-types=InternalIP")

# Every kind upstream's components.yaml carries. A manifest holding anything
# else is not the file this button asked for.
METRICS_KINDS = {"ServiceAccount", "ClusterRole", "ClusterRoleBinding",
                 "RoleBinding", "Role", "Service", "Deployment", "APIService"}
METRICS_APISERVICE = "v1beta1.metrics.k8s.io"


def metrics_manifest(url: str = "", timeout: int = 25) -> tuple[str, str]:
    """The manifest, and the version it would install.

    Fetched and CHECKED here, before a single object reaches the cluster. This
    button applies with whatever rights the stored kubeconfig has, which for a
    cluster marked for management is usually cluster-admin — so "apply whatever
    that URL returned" is precisely the mistake available to make. A mirror that
    answered with somebody else's manifest, or a github URL that quietly became
    an HTML error page, is refused rather than applied.
    """
    import urllib.error
    import urllib.request
    import yaml as _yaml

    from . import urlguard

    url = url or env.METRICS_URL
    # Through the guard like every other outbound fetch. This URL is
    # configuration, and configuration is exactly what pointed a VPN connection
    # at file:///tmp once — and whatever this fetch returns is then applied to a
    # cluster, so it is the last place to make an exception.
    try:
        req = urllib.request.Request(urlguard.check(url),
                                     headers={"User-Agent": "config-portal"})
    except urlguard.BlockedURL as e:
        raise Refused(f"{url} is not an address this portal will fetch ({e}) — "
                      f"PORTAL_METRICS_URL must be http or https") from e
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(4 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise Refused(f"{url} answered HTTP {e.code}, so there is no manifest "
                      f"to apply") from e
    except Exception as e:                                    # noqa: BLE001
        raise Refused(f"the manifest could not be fetched from {url} — "
                      f"{type(e).__name__}: {e}. An installation with no route "
                      f"out can point PORTAL_METRICS_URL at its own mirror.") from e
    try:
        docs = [d for d in _yaml.safe_load_all(raw) if isinstance(d, dict)]
    except Exception as e:                                    # noqa: BLE001
        raise Refused(f"{url} did not return YAML ({e})") from e
    if not docs:
        raise Refused(f"{url} returned nothing that looks like a manifest")

    version, seen = "", set()
    for d in docs:
        kind, meta = d.get("kind", ""), d.get("metadata") or {}
        name, ns = meta.get("name", ""), meta.get("namespace", "")
        if kind not in METRICS_KINDS:
            raise Refused(f"that manifest also contains a "
                          f"{kind or 'nameless object'}, which metrics-server "
                          f"does not — refusing to apply it")
        # A namespaced object anywhere else is the tell that this is not the
        # file it claims to be: upstream puts all of it in kube-system.
        if ns and ns != METRICS_NAMESPACE:
            raise Refused(f"that manifest writes {kind}/{name} into namespace "
                          f"{ns}; metrics-server installs only into "
                          f"{METRICS_NAMESPACE}")
        seen.add(f"{kind}/{name}")
        if kind == "Deployment" and name == METRICS_DEPLOYMENT:
            containers = ((d.get("spec") or {}).get("template", {})
                          .get("spec", {}).get("containers") or [])
            image = (containers[0].get("image", "") if containers else "")
            version = image.rpartition(":")[2] if ":" in image else image
    if f"Deployment/{METRICS_DEPLOYMENT}" not in seen:
        raise Refused("that manifest has no metrics-server Deployment in it")
    if f"APIService/{METRICS_APISERVICE}" not in seen:
        raise Refused(f"that manifest does not register the {METRICS_APISERVICE} "
                      f"API, which is what makes usage readable")
    return raw, version


def missing_kubelet_args(current: list) -> list:
    """The flags of TALOS_ARGS this container does not already carry.

    By name, not by exact string: `--kubelet-preferred-address-types` set to
    something else is a decision somebody made, and appending ours after it
    would leave two of the same flag with the last one winning silently.
    """
    have = {str(a).split("=", 1)[0] for a in current or []}
    return [a for a in TALOS_ARGS if a.split("=", 1)[0] not in have]


def _kubectl(base: list, argv: list, timeout: int, stdin: str = "") -> dict:
    """One kubectl, as a step in a multi-step action."""
    try:
        r = subprocess.run(base + argv, input=stdin or None, capture_output=True,
                           text=True, timeout=timeout)
        code, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        code, out, err = 124, "", f"timed out after {timeout}s"
    except Exception as e:                                    # noqa: BLE001
        code, out, err = 1, "", f"{type(e).__name__}: {e}"
    return {"display": "kubectl " + " ".join(shlex.quote(a) for a in argv),
            "code": code, "stdout": out, "stderr": err}


def install_metrics(cluster: dict, timeout: int = 120) -> dict:
    """Install metrics-server, then give it the flags it needs to reach kubelets.

    Three commands, not one, and the patch is COMPUTED rather than appended.
    Upstream's instructions append both flags with a JSON patch against
    `/args/-`, which on a second run leaves the same flag in the list twice and
    on a cluster that already has one of them leaves a contradiction. This reads
    the args that are there and writes back only what is missing, so pressing
    the button twice is the same as pressing it once — which matters, because the
    button is on a page somebody will press again when usage has not appeared
    yet.
    """
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    alive, why = reachable(cluster)
    if not alive:
        raise Refused(f"cluster unreachable — {why}")

    started = time.time()
    manifest, version = metrics_manifest()
    named = f"metrics-server {version}".strip()
    steps = [_kubectl(base, ["apply", "-f", "-"], timeout, stdin=manifest)]
    if steps[0]["code"] != 0:
        return _steps_result(steps, started, ok=False,
                             head=f"applying {named} failed")

    # what the deployment carries now, which decides the patch
    got = _kubectl(base, ["-n", METRICS_NAMESPACE, "get", "deployment",
                          METRICS_DEPLOYMENT, "-o", "json"], 30)
    steps.append(got)
    if got["code"] != 0:
        return _steps_result(steps, started, ok=False,
                             head=f"{named} was applied but could not be read "
                                  f"back to add the kubelet flags")
    try:
        containers = (json.loads(got["stdout"])["spec"]["template"]["spec"]
                      ["containers"])
        current = list(containers[0].get("args") or [])
    except Exception as e:                                    # noqa: BLE001
        return _steps_result(steps, started, ok=False,
                             head=f"{named} was applied but its container args "
                                  f"could not be read ({type(e).__name__}: {e})")

    add = missing_kubelet_args(current)
    if add:
        patch = json.dumps([{"op": "replace",
                             "path": "/spec/template/spec/containers/0/args",
                             "value": current + add}])
        steps.append(_kubectl(base, ["-n", METRICS_NAMESPACE, "patch",
                                     "deployment", METRICS_DEPLOYMENT,
                                     "--type=json", "-p", patch], 30))
        if steps[-1]["code"] != 0:
            return _steps_result(steps, started, ok=False,
                                 head=f"{named} is installed but the kubelet "
                                      f"flags could not be added, so usage will "
                                      f"probably stay empty")
    head = (f"{named} installed into {METRICS_NAMESPACE}"
            + (f", with {' and '.join(add)}" if add
               else ", and it already had the kubelet flags")
            + " — usage appears here 30-60 seconds after it starts")
    return _steps_result(steps, started, ok=True, head=head)


def _steps_result(steps: list, started: float, ok: bool, head: str) -> dict:
    """Several kubectls, reported in the shape one of them returns.

    The first line of stdout is the sentence a person reads in the flash
    message, so it says what happened rather than repeating kubectl's last word.

    Only a FAILING step's stderr becomes the result's stderr, because the caller
    prefers stderr over stdout when it builds that message — and `kubectl apply`
    writes policy warnings there on a perfectly successful apply. Every step's
    output, warnings included, is still in the body below.
    """
    body = "\n\n".join(f"$ {s['display']}\n{(s['stdout'] or '').rstrip()}"
                       + (f"\n{s['stderr'].rstrip()}" if s["stderr"] else "")
                       for s in steps)
    fails = [s for s in steps if s["code"] != 0]
    return {"argv": ["apply", "-f", env.METRICS_URL], "kind": "write",
            "code": fails[0]["code"] if fails else 0, "ok": ok,
            "stdout": f"{head}\n\n{body}"[:OUTPUT_CAP],
            "stderr": "\n".join(s["stderr"].strip()
                                for s in fails if s["stderr"])[-8000:],
            "took": round(time.time() - started, 2),
            "display": " && ".join(s["display"] for s in steps)}


def act(cluster: dict, action: str, args: dict, allow_write: bool = False,
        timeout: int = TIMEOUT) -> dict:
    """Run one of the fixed actions above."""
    spec = ACTIONS.get(action)
    if not spec:
        raise Refused(f"unknown action '{action}'")
    missing = [k for k in spec["needs"] if not str(args.get(k, "")).strip()]
    if missing:
        raise Refused(f"missing {', '.join(missing)}")
    for k in ("namespace", "name", "node", "kind"):
        v = str(args.get(k, ""))
        # names come from the cluster's own listings, so anything outside the
        # shape Kubernetes allows means the request was not built by the page
        if v and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,252}", v):
            raise Refused(f"'{v}' is not a valid Kubernetes name")
    if not allow_write:
        raise Refused(read_only_why())
    # An action whose work is more than one command carries its own runner, and
    # reaches it through the same gates as the rest: unknown action, missing
    # arguments, name shape, allow_write. A second entry point for the multi-step
    # ones is a second place for one of those checks to be missing.
    if spec.get("run"):
        return spec["run"](cluster, args, spec.get("timeout", timeout))
    argv = spec["build"](args)
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    started = time.time()
    try:
        r = subprocess.run(base + argv, capture_output=True, text=True,
                           timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", f"timed out after {timeout}s", 124
    return {"argv": argv, "kind": "write", "code": code,
            "stdout": out[:OUTPUT_CAP], "stderr": err[-8000:],
            # `kubectl cordon` exits 0 even when the API refuses it, so the exit
            # code alone would report a failure as a success
            "ok": code == 0 and not FAILED_ANYWAY.search(
                (err or "") + "\n" + (out or "")),
            "took": round(time.time() - started, 2),
            "display": "kubectl " + " ".join(shlex.quote(a) for a in argv)}


# ── completion ─────────────────────────────────────────────────
# What the console offers when Tab is pressed. Read from the cluster, not from a
# list in here: a CRD someone installed yesterday completes like anything else.
_COMPLETE_CACHE: dict = {}
_TTL = {"resources": 300.0, "namespaces": 60.0, "names": 15.0}


def _cached_read(cluster: dict, key: str, ttl: float, produce) -> list:
    ck = f"{cluster.get('id') or cluster.get('context','')}::{key}"
    hit = _COMPLETE_CACHE.get(ck)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    got = produce()
    _COMPLETE_CACHE[ck] = (time.time(), got)
    return got


def _lines(cluster: dict, *args, timeout: int = 12) -> list:
    base = base_args(cluster)
    if not base:
        return []
    try:
        r = subprocess.run(base + list(args), capture_output=True, text=True,
                           timeout=timeout)
        if r.returncode != 0:
            return []
        return [x.strip() for x in r.stdout.splitlines() if x.strip()]
    except Exception:                                         # noqa: BLE001
        return []


def verbs_for(cluster: dict) -> list:
    """The verbs this console will actually accept, so completion never offers
    something that is then refused."""
    out = sorted(READ_VERBS)
    if writable(cluster):
        out += sorted(WRITE_VERBS)
    return out


def resource_types(cluster: dict) -> list:
    return _cached_read(cluster, "resources", _TTL["resources"], lambda: sorted(
        _lines(cluster, "api-resources", "--no-headers", "-o", "name")))


def namespaces(cluster: dict) -> list:
    return _cached_read(cluster, "namespaces", _TTL["namespaces"], lambda: [
        n.split("/", 1)[-1] for n in
        _lines(cluster, "get", "namespaces", "-o", "name")])


def names_of(cluster: dict, resource: str, namespace: str = "") -> list:
    """Object names of one type, for completing the third word."""
    if not re.fullmatch(r"[a-z0-9.\-]{1,60}", resource or ""):
        return []
    scope = ["-n", namespace] if namespace else ["-A"]
    key = f"names:{resource}:{namespace or '-A'}"
    return _cached_read(cluster, key, _TTL["names"], lambda: [
        n.split("/", 1)[-1] for n in
        _lines(cluster, "get", resource, *scope, "-o", "name")][:500])


def complete(cluster: dict, text: str, namespace: str = "") -> dict:
    """Suggestions for a partly typed command.

    Position decides the kind: the first word is a verb, the second a resource
    type, the third a name — and anything after -n is a namespace. Simple, and
    right for the shape of nearly every kubectl command.
    """
    raw = (text or "")
    parts = raw.split()
    trailing_space = raw.endswith((" ", "\t"))
    idx = len(parts) if trailing_space else max(0, len(parts) - 1)
    token = "" if trailing_space else (parts[-1] if parts else "")
    prev = parts[idx - 1] if idx and len(parts) >= idx else ""

    if prev in ("-n", "--namespace"):
        pool, kind = namespaces(cluster), "namespace"
    elif idx == 0:
        pool, kind = verbs_for(cluster), "verb"
    elif idx == 1 and parts[0].lower() in ("logs", "port-forward"):
        # `kubectl logs` takes a pod name where other verbs take a type
        pool, kind = names_of(cluster, "pods", namespace), "pod"
    elif idx == 1 and parts[0].lower() == "top":
        pool, kind = ["nodes", "pods"], "resource"
    elif idx == 1:
        pool, kind = resource_types(cluster), "resource"
    elif idx == 2 and not token.startswith("-"):
        pool, kind = names_of(cluster, parts[1], namespace), "name"
    else:
        # later positions: offer flags already on screen plus namespaces, which
        # is what people are usually reaching for
        pool, kind = (["-n", "-o", "--all-namespaces", "-A", "-l",
                       "--field-selector", "--sort-by", "--tail",
                       "--dry-run=server"], "flag")

    low = token.lower()
    hits = [p for p in pool if p.lower().startswith(low)]
    if not hits and low:
        hits = [p for p in pool if low in p.lower()]
    return {"kind": kind, "token": token, "items": hits[:40],
            "total": len(hits)}


def writable(cluster: dict) -> bool:
    """Whether management is enabled for this cluster."""
    return str(cluster.get("manage", "")).lower() in ("1", "true", "yes", "on")


def read_only_why(because: str = "") -> str:
    """Why a cluster the portal may not change refuses.

    Beside writable() because it is that predicate's negative, and in ONE place
    because there were eight of it — six here, two in main.py, one in aitools —
    in four wordings, one of which forgot to say where the tick is. The useful
    half of the sentence is always the same: which page to go and find.

    `because` names the change when the caller has something more specific to
    say than "run a command".
    """
    return ("this cluster is read-only in the portal"
            + (f" and {because}" if because else "")
            + " — tick “allow management” for it in "
              "Settings → Clusters")


# ── a throwaway pod to troubleshoot from ───────────────────────
# The reason this exists: the exec above runs inside a container that already
# exists, and most containers are distroless — measured on a real cluster,
# `nslookup` in an Argo pod fails with "executable file not found". You cannot
# debug a network from a container that has no network tools in it. So: a pod
# whose whole job is to have the tools, which deletes itself.
#
# WHAT IT IS NOT ALLOWED TO BE
#     No host network, no host PID, no privilege, no escalation, every
#     capability dropped. That keeps it inside PodSecurity `baseline`, which
#     this estate enforces — a pod that needs the cluster's policy relaxed to
#     start is not a debugging aid, it is a second problem. The cost is that
#     packet capture will not work; DNS, curl, nc, dig, traceroute and ss all
#     do, and those are what the questions are actually about.
#
# IT DELETES ITSELF
#     `activeDeadlineSeconds` ends it whether or not anybody comes back, and
#     the pod carries the labels that let `sweep_netshoot` remove the remains.
#     A troubleshooting pod nobody cleaned up is how a cluster acquires a
#     permanent root shell with no owner.
NETSHOOT_IMAGE = os.environ.get("PORTAL_NETSHOOT_IMAGE",
                                "nicolaka/netshoot:v0.13")
NETSHOOT_TTL = int(os.environ.get("PORTAL_NETSHOOT_TTL", "1800"))
NETSHOOT_LABELS = {"app.kubernetes.io/created-by": "config-portal",
                   "config-portal/purpose": "netshoot"}


def _netshoot_manifest(name: str, namespace: str, ttl: int) -> dict:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": dict(NETSHOOT_LABELS)},
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": ttl,
            "terminationGracePeriodSeconds": 1,
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "netshoot", "image": NETSHOOT_IMAGE,
                # it must stay up long enough to be useful and no longer; the
                # deadline above is the real limit, this is what it does while
                # it waits
                "command": ["sleep", str(ttl)],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "readOnlyRootFilesystem": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"requests": {"cpu": "20m", "memory": "64Mi"},
                              "limits": {"cpu": "500m", "memory": "256Mi"}},
            }],
        },
    }


# ── why the cluster said no ────────────────────────────────────
# WHY THIS EXISTS
#     Everything above works on a laptop with an admin kubeconfig and fails on
#     an install whose kubeconfig is a read-only service account — and the
#     failure arrives as whatever kubectl printed, which is a sentence about
#     RBAC groups rather than about what to do. The permissions differ per
#     install by design, so the portal has to ASK rather than assume, and it
#     asks only when something has already gone wrong: `auth can-i` is a round
#     trip, and the happy path must not pay for it.
CAN_I_TIMEOUT = 8


def _can_i(cluster: dict, verb: str, resource: str, namespace: str = "") -> bool | None:
    """True / False / None when the question itself could not be asked."""
    base = base_args(cluster)
    if not base:
        return None
    argv = base + ["auth", "can-i", verb, resource]
    if namespace:
        argv += ["-n", namespace]
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=CAN_I_TIMEOUT)
    except Exception:                                          # noqa: BLE001
        return None
    out = (r.stdout or "").strip().lower()
    return True if out.startswith("yes") else False if out.startswith("no") else None


def whoami(cluster: dict) -> str:
    """The identity this cluster's kubeconfig authenticates as, if it will say."""
    base = base_args(cluster)
    if not base:
        return ""
    try:
        r = subprocess.run(base + ["auth", "whoami", "-o",
                                   "jsonpath={.status.userInfo.username}"],
                           capture_output=True, text=True, timeout=CAN_I_TIMEOUT)
        return (r.stdout or "").strip()[:120]
    except Exception:                                          # noqa: BLE001
        return ""


def why_refused(cluster: dict, namespace: str, want: str = "exec") -> str:
    """A sentence about THIS install, or "" when nothing can be established.

    Never guesses: an unanswerable question returns nothing rather than a
    plausible cause, because a wrong explanation costs more than none.
    """
    ok, why_not = reachable(cluster)
    if not ok:
        return f"the portal cannot reach this cluster: {why_not}"
    verb, resource = ("create", "pods/exec") if want == "exec" else ("create", "pods")
    allowed = _can_i(cluster, verb, resource, namespace)
    if allowed is False:
        who = whoami(cluster)
        doing = ("open a shell in a pod" if want == "exec"
                 else "create the troubleshooting pod")
        return (f"this cluster's kubeconfig is not allowed to {doing} in "
                f"namespace “{namespace}”"
                + (f" — it authenticates as {who}" if who else "")
                + f". It needs {verb} on {resource}.")
    return ""


def netshoot_start(cluster: dict, namespace: str, allow_write: bool = False,
                   ttl: int = 0) -> dict:
    """Create the pod and wait until it can be exec'd into."""
    if not allow_write:
        raise Refused(read_only_why())
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace or ""):
        raise Refused(f"'{namespace}' is not a valid namespace")
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    ttl = max(60, min(int(ttl or NETSHOOT_TTL), 4 * 3600))
    name = f"netshoot-{secrets.token_hex(4)}"
    body = json.dumps(_netshoot_manifest(name, namespace, ttl))
    try:
        r = subprocess.run(base + ["apply", "-f", "-"], input=body,
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Refused("the cluster did not answer in time")
    if r.returncode != 0:
        # kubectl's own words first — they name the object and the namespace —
        # then what this install can actually do about it, which is the half
        # that differs between one customer's cluster and another's.
        said = (r.stderr or "").strip()[:300]
        why = why_refused(cluster, namespace, "create")
        raise Refused(f"could not start it: {said}" + (f" — {why}" if why else ""))
    # Waiting here rather than in the page: "it is starting" is not a useful
    # thing to hand somebody who asked for a shell.
    wait = subprocess.run(
        base + ["wait", f"pod/{name}", "-n", namespace,
                "--for=condition=Ready", "--timeout=60s"],
        capture_output=True, text=True, timeout=90)
    return {"name": name, "namespace": namespace, "ttl": ttl,
            "image": NETSHOOT_IMAGE, "ready": wait.returncode == 0,
            "why": (wait.stderr or wait.stdout or "").strip()[:300]}


def netshoot_stop(cluster: dict, namespace: str, name: str,
                  allow_write: bool = False) -> dict:
    if not allow_write:
        raise Refused(read_only_why())
    if not re.fullmatch(r"netshoot-[a-f0-9]{8}", name or ""):
        # only ever removes what this feature created
        raise Refused("that is not a troubleshooting pod this portal started")
    base = base_args(cluster)
    r = subprocess.run(base + ["delete", "pod", name, "-n", namespace,
                               "--ignore-not-found", "--wait=false"],
                       capture_output=True, text=True, timeout=TIMEOUT)
    return {"ok": r.returncode == 0,
            "detail": (r.stdout or r.stderr).strip()[:200]}


def netshoot_list(cluster: dict) -> list:
    """Every troubleshooting pod this portal has left running, anywhere.

    A pod that has been asked to go is left out. The delete does not wait —
    it returns as soon as the API server has the request — so for the second
    or two a pod spends Terminating it is still in the list, and the page that
    came back from a delete showed the chip again, ✕ and all, as though the
    click had not worked. Its deletionTimestamp is the cluster saying "this is
    going", which is the honest answer to "what is still here".
    """
    base = base_args(cluster)
    if not base:
        return []
    sel = ",".join(f"{k}={v}" for k, v in NETSHOOT_LABELS.items())
    r = subprocess.run(
        base + ["get", "pods", "-A", "-l", sel, "-o",
                "jsonpath={range .items[*]}{.metadata.namespace}{'\\t'}"
                "{.metadata.name}{'\\t'}{.status.phase}{'\\t'}"
                "{.metadata.deletionTimestamp}{'\\n'}{end}"],
        capture_output=True, text=True, timeout=20)
    out = []
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and not parts[3].strip():
            out.append({"namespace": parts[0], "name": parts[1],
                        "phase": parts[2]})
    return out


# ── a shell held open, so the second command is not another handshake ──
# Measured against a real cluster over a VPN: `kubectl exec … -- echo x` costs
# 2.0s, of which the process itself is 0.03s and a single API round trip is
# 0.96s. Naming the container saves nothing — the cost is the exec POST and its
# stream upgrade, paid again for every command. Type four things and you have
# waited eight seconds for eight seconds of nothing.
#
# So the connection is made once. One `kubectl exec -i … -- sh` is started per
# terminal, commands are written to its stdin, and the answer is read back
# between markers. The first command still pays the handshake; the rest pay
# only the data.
#
# WHY A MARKER AND NOT A TIMEOUT
#     There is no framing on a pipe, so "the output has finished" has to be
#     something the shell itself says. The command is followed by an echo of a
#     random token and `$?`, so the reader knows both that it is done and what
#     the exit status was — a timeout would guess, and guess wrong on any
#     command that pauses.
#
# NOT EVERY CONTAINER HAS A SHELL
#     Distroless images have no /bin/sh, which is most of a modern cluster. A
#     session that cannot start is not an error: the caller falls back to
#     exec_in, one command at a time, and the terminal says which mode it is in.
# WHY THE OUTPUT IS STREAMED AND NOT RETURNED
#     Holding the answer until the command finishes makes a terminal that lies
#     about two different things. `ping` and `tail -f` never finish, so they sit
#     on "running…" until a deadline kills them; and a command that takes two
#     seconds shows nothing for two seconds even though its first line was ready
#     immediately. A terminal is judged on when the first character appears, so
#     the reader below yields as the bytes arrive and the caller decides whether
#     to collect them (run) or forward them (stream).
#
#     That is also what makes stopping possible. Abandoning the generator kills
#     the session, which closes the exec stream, which is what ends the command
#     inside the container — there is no other way to interrupt it, because
#     without a TTY there is no signal to send.
SESSION_IDLE = 900.0        # a terminal left open between commands stays warm
SESSION_MAX = 12
STREAM_MAX = 900.0          # a single streaming command's ceiling
CHUNK_QUIET = 0.12          # how long a line with no newline waits before it shows
_sessions: dict = {}
_sess_lock = threading.Lock()


def _overlap(buf: str, token: str) -> int:
    """How much of the buffer's tail could be the start of the marker.

    Output is flushed as it arrives, and the marker can land mid-line — after
    `printf ok`, for instance. Flushing a tail that turns out to have been the
    first half of the marker would print it to the user and, worse, leave the
    reader waiting for a marker it has already thrown away.
    """
    for k in range(min(len(buf), len(token) - 1), 0, -1):
        if token.startswith(buf[-k:]):
            return k
    return 0


def _plain(text: str) -> str:
    """A terminal ends its lines with CR LF; a browser wants LF."""
    return text.replace("\r\n", "\n")


def _kubectl_argv(cluster: dict, namespace: str, pod: str,
                  container: str = "", want_tty: bool = True,
                  shell: str = "sh") -> list:
    base = base_args(cluster)
    if not base:
        return []
    argv = base + ["exec", "-i", pod, "-n", namespace]
    if want_tty:
        argv.append("-t")
    if container:
        argv += ["-c", container]
    if shell == "sh":
        # `sh`, not `bash`: bash is the one that is missing.
        return argv + ["--", "sh"]
    # An interactive session wants bash where there is one — its line editing,
    # history and TAB completion are the reasons a person recognises a terminal
    # as a terminal, and none of them are things this end should be emulating.
    return argv + ["--", "sh", "-c", INTERACTIVE_SHELL]


# `exec` and not `&&`: the shell that ends up in the container must BE the
# session leader, so that ^C reaches the program it is running rather than an
# intermediate sh. `-i` so it prints a prompt and turns on job control.
INTERACTIVE_SHELL = ("if command -v bash >/dev/null 2>&1; then exec bash -i; "
                     "else exec sh -i; fi")


# ── the interactive terminal ───────────────────────────────────
# A different thing from everything above, and deliberately so. The session up
# there runs ONE command, frames its output with a marker and reports its exit
# status, which is what makes an audit line possible — and which cannot express
# `nslookup`, where the program takes the keyboard and answers at its own
# prompt, or `top`, or `vi`, or a password prompt.
#
# So this one does not interpret anything. Bytes typed in the browser go to the
# container's terminal; bytes the container writes go back. The shell does the
# echoing, the line editing, the history and the completion, because the shell
# is the thing that has always done them.
#
# WHAT IS LOST, AND WHAT REPLACES IT
#     There is no longer a command boundary to audit, because there is no
#     longer a command — there is a stream of keystrokes. `pty_audit_line`
#     rebuilds the lines from that stream so the log still answers "what did
#     they type", and marks a line the container never echoed as hidden rather
#     than recording it: a prompt that turns echo off is asking for a secret,
#     and a secret is the one thing this must not write down.
PTY_IDLE = 1800.0           # a terminal nobody has touched for half an hour


class _Pty:
    """A raw interactive shell in one container. Bytes in, bytes out."""

    def __init__(self, argv: list, rows: int = 24, cols: int = 100,
                 raw_master: bool = True, env: dict | None = None):
        master, slave = os.openpty()
        _set_winsize(slave, rows, cols)
        # WHY raw_master IS OPTIONAL, AND OFF FOR SSH
        #     On macOS tty.setraw(master) also clears OPOST on the *slave* — the
        #     master and slave share termios state here. kubectl does not care:
        #     it negotiates the container's own pty. `ssh -tt` DOES care: it
        #     copies the local tty's modes into the remote pty request, so a raw
        #     slave makes the remote shell stop turning \n into \r\n — every
        #     prompt then lands on the same line, marching right, and no later
        #     resize un-wraps it. The host terminal passes raw_master=False and
        #     lets ssh put the slave in raw mode itself once it is connected.
        if raw_master:
            try:
                tty.setraw(master)
            except termios.error:
                pass
        # env is passed for the SSH password path (SSH_ASKPASS and friends); the
        # pod terminal passes none and inherits the portal's, as before.
        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave,
            close_fds=True, start_new_session=True, env=env)
        os.close(slave)
        self.fd = master
        self.opened = time.time()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def read(self, timeout: float = 0.2) -> bytes:
        """Whatever the container has said, or b"" if it has said nothing.
        Raises EOFError once the shell is gone."""
        if not select.select([self.fd], [], [], timeout)[0]:
            if not self.alive():
                raise EOFError
            return b""
        try:
            data = os.read(self.fd, 65536)
        except OSError:                 # a pty reports the far end as EIO
            raise EOFError from None
        if not data:
            raise EOFError
        return data

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def resize(self, rows: int, cols: int) -> None:
        """kubectl reads its own terminal's size and forwards it to the API
        server, but only when something tells it to look — and it is not in
        this pty's foreground process group, so the kernel's SIGWINCH does not
        reach it. Hence the explicit signal."""
        _set_winsize(self.fd, rows, cols)
        try:
            os.kill(self.proc.pid, signal.SIGWINCH)
        except OSError:
            pass

    def close(self) -> None:
        for shut in (self.proc.kill, lambda: os.close(self.fd)):
            try:
                shut()
            except Exception:                                  # noqa: BLE001
                pass
        try:
            self.proc.wait(timeout=2)
        except Exception:                                      # noqa: BLE001
            pass


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    rows = max(4, min(int(rows or 24), 300))
    cols = max(20, min(int(cols or 100), 500))
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


class SessionCast:
    """Records a terminal's OUTPUT to an asciinema v2 cast, for replay.

    WHY A CAST AND NOT A LOG
        The audit trail already answers "what commands did they run". A cast
        answers the other question — "what did the box show them" — and answers
        it as a recording you watch back at the original speed: the error that
        scrolled past, the menu they picked from, the diff a script printed
        before it acted. That is the difference between a command log and a
        session recording of the kind a PAM/bastion keeps.

    THE FORMAT IS asciinema v2, ON PURPOSE
        One JSON header line, then one `[elapsed, "o", text]` line per chunk. It
        is what `asciinema play file.cast` reads, what asciinema.org accepts, and
        what the portal's own replay page parses with the xterm it already ships
        — no player library to bundle, and the file is useful off the portal too.

    OUTPUT ONLY, DELIBERATELY
        Keystrokes are never written here. A password typed at a prompt with echo
        turned off is invisible in the output stream (the host does not echo it),
        so a recording of the output cannot leak it — whereas a recording of the
        keystrokes would hold it in full. The commands come from pty_audit_line,
        which already redacts the un-echoed ones.
    """

    def __init__(self, path: str, rows: int, cols: int, meta: dict | None = None):
        self.path = path
        self.start = time.time()
        self.out_bytes = 0
        header = {"version": 2, "width": int(cols or 100),
                  "height": int(rows or 24), "timestamp": int(self.start),
                  "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
        if meta:
            header["envmap"] = meta          # our own note; players ignore unknown keys
        self._fh = open(path, "w", buffering=1, encoding="utf-8")
        self._fh.write(json.dumps(header) + "\n")

    def _event(self, kind: str, data: str) -> None:
        if not self._fh:
            return
        try:
            self._fh.write(json.dumps([round(time.time() - self.start, 6),
                                       kind, data]) + "\n")
        except (ValueError, OSError):
            pass

    def output(self, text: str) -> None:
        if not text:
            return
        self.out_bytes += len(text.encode("utf-8", "replace"))
        self._event("o", text)

    def resize(self, rows: int, cols: int) -> None:
        self._event("r", f"{int(cols)}x{int(rows)}")

    def close(self) -> float:
        """Close the file and return the session's length in seconds."""
        secs = time.time() - self.start
        fh, self._fh = self._fh, None
        if fh:
            try:
                fh.close()
            except OSError:
                pass
        return secs


def pty_open(cluster: dict, namespace: str, pod: str, container: str = "",
             rows: int = 24, cols: int = 100, allow_write: bool = False):
    """An interactive shell in this container. Gated exactly as exec_in is."""
    if not allow_write:
        raise Refused(read_only_why())
    for label, v in (("namespace", namespace), ("pod", pod),
                     ("container", container)):
        if v and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", v):
            raise Refused(f"'{v}' is not a valid {label} name")
    if not namespace or not pod:
        raise Refused("a namespace and a pod are needed")
    argv = _kubectl_argv(cluster, namespace, pod, container, True, "interactive")
    if not argv:
        raise Refused("this cluster has no kubeconfig or context set")
    try:
        return _Pty(argv, rows, cols)
    except OSError as e:
        raise Refused(f"could not start a terminal: {e}") from None


# What the container was saying immediately before somebody started typing,
# when what it was saying was "give me a secret". Both were measured against a
# real session before this shape was arrived at: the first version asked only
# whether the line had been echoed, which recorded a password in full (the
# PROMPT is output, so the line counted as echoed) and hid an ordinary command
# (two lines arriving in one paste have no echo between them).
SECRET_PROMPT = re.compile(
    r"(pass(word|phrase)?|secret|token|api[ _-]?key|pin|otp|mfa|2fa|"
    r"credential)[^\n]{0,24}[:?]\s*$", re.I)


_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[]P^_].*?(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1f]")


class pty_audit_line:
    """Rebuilds typed lines out of a keystroke stream, for the audit log.

    There is no command boundary in a terminal — there is a stream of
    keystrokes — so this is what keeps the answer to "what did they run".
    Backspace and Ctrl+U are applied rather than recorded, because the log
    should hold the command as the person finished writing it.

    A secret must never reach the log, and the signal for one is that the host
    did not echo it back. An interactive shell echoes each CHARACTER as it is
    typed, so by the time Enter is pressed the line's echo has ALREADY streamed
    back and sits in the output seen since the line began — `seen` is reset when
    a line starts, so it holds exactly this line's echo and nothing else. If the
    line's text is in there, it was echoed and is recorded; if not (a no-echo
    password prompt), only its length is kept. Latency is covered too: the check
    keeps running after Enter, so an echo still in flight over a VPN is caught
    when it lands. A prompt that names what it wants ("password:") is hidden at
    once, without waiting.

    (The earlier version reset `seen` at Enter and then waited for the command to
    reappear in later OUTPUT — but a shell never re-prints the command after
    running it, so every real command was recorded as hidden. This judges the
    echo from what arrived DURING typing, which is where it actually is.)
    """

    LIMIT = 400
    HOLD = 1.2              # how long a line waits for its own echo
    PROBE = 8               # enough of it to recognise, short enough not to wrap

    def __init__(self):
        self.buf = ""
        self.tail = ""          # the last thing the container said
        self.asked = ""         # …as it was when the current line began
        self.seen = ""          # output since the current line was finished
        self.waiting: list = []

    def saw_output(self, text: str = "") -> None:
        clean = _ANSI.sub("", text)
        self.tail = (self.tail + clean)[-400:]
        self.seen = (self.seen + clean)[-4000:]
        for held in self.waiting:
            if held["probe"] and held["probe"] in self.seen:
                held["echoed"] = True

    def typed(self, text: str) -> list:
        """Keystrokes in; whatever is now certain, out."""
        for ch in text:
            if ch in ("\r", "\n"):
                self._hold()
            elif ch in ("\x7f", "\b"):
                self.buf = self.buf[:-1]
            elif ch == "\x15":                                  # Ctrl+U
                self.buf = ""
            elif ch == "\x03":
                part = self.buf.strip()[:80]
                self.waiting.append(
                    {"line": f"^C{' while typing ' + part if part else ''}",
                     "probe": "", "echoed": True, "at": time.time(),
                     "chars": 0, "asked": ""})
                self.buf = ""
            elif ch >= " ":
                if not self.buf:
                    # A line begins: remember the prompt it began at, and start a
                    # fresh window so `seen` collects THIS line's echo and no
                    # earlier output — that is what tells a command from a
                    # password.
                    self.asked = self.tail
                    self.seen = ""
                self.buf = (self.buf + ch)[:self.LIMIT * 2]
        return self.due()

    @staticmethod
    def _prompt_of(text: str) -> str:
        """The last non-empty line of what was on screen — the actual prompt,
        without the carriage returns and earlier lines that make `tail` unreadable."""
        for line in reversed(text.replace("\r", "\n").split("\n")):
            if line.strip():
                return line.strip()[-80:]
        return ""

    def _hold(self) -> None:
        line = self.buf.strip()
        self.buf = ""
        if not line:
            return
        prompt = self._prompt_of(self.asked)
        probe = line[:self.PROBE]
        # A prompt that names what it wants is a password field — hidden at once.
        secret = bool(SECRET_PROMPT.search(prompt))
        # Otherwise: was the line echoed as it was typed? `seen` since this line
        # began holds its echo if the host echoed it. Not resetting `seen` here
        # keeps the check live for an echo still in flight (see saw_output).
        echoed = (not secret) and bool(probe) and probe in self.seen
        self.waiting.append({"line": line[:self.LIMIT], "chars": len(line),
                             "probe": "" if secret else probe,
                             "echoed": echoed, "at": time.time(),
                             "asked": prompt})

    def due(self, now: float | None = None) -> list:
        """Lines whose fate is settled: echoed back, or silent for long enough."""
        now = time.time() if now is None else now
        out, still = [], []
        for held in self.waiting:
            if held["echoed"]:
                out.append(held["line"])
            elif now - held["at"] >= self.HOLD:
                where = f" at {held['asked']!r}" if held["asked"] else ""
                out.append(f"<hidden — {held['chars']} characters typed"
                           f"{where}>")
            else:
                still.append(held)
        self.waiting = still
        return out

    def close(self) -> list:
        """Everything still waiting, when the terminal is going away."""
        return self.due(now=time.time() + self.HOLD)


# WHY THE SHELL GETS A TERMINAL
#     Measured against a real pod: `ping -c 4` sent its header immediately and
#     then nothing at all for thirteen seconds, delivering every reply line at
#     once when it exited. That is not this reader — `for i in 1 2 3; do echo;
#     sleep 1; done` arrived at 257ms, 1260ms and 2267ms through the same code.
#     It is the C library: stdout to a pipe is block-buffered, stdout to a
#     terminal is line-buffered, and almost every diagnostic tool a person
#     reaches for in a troubleshooting pod is written in C.
#
#     `stdbuf` would fix it for one command, and is not in netshoot. A terminal
#     fixes it for every command — and brings the other thing a terminal has:
#     Ctrl+C. A pty's line discipline turns byte 0x03 into SIGINT for whatever
#     is running, so a command can be stopped without killing the shell.
#
#     kubectl only asks for a remote pty when its OWN stdin is one, so the
#     portal opens a pty pair here and gives kubectl the far end.
class _Session:
    """One `sh` running inside one container, fed a command at a time."""

    def __init__(self, argv: list, want_tty: bool = True):
        self.tty = bool(want_tty)
        self.echoes = False     # set at startup; see session_for
        self.interrupted_at = 0.0
        if self.tty:
            master, slave = os.openpty()
            try:
                # Raw on this side, so ^C and CR are bytes we forward rather
                # than something the local line discipline acts on. The pty at
                # the container's end is the one doing the interpreting.
                tty.setraw(slave)
                tty.setraw(master)
            except termios.error:
                pass
            self.proc = subprocess.Popen(
                argv, stdin=slave, stdout=slave, stderr=slave,
                close_fds=True, start_new_session=True)
            os.close(slave)
            self.fd = self.wfd = master
        else:
            # Binary, unbuffered. Line buffering would hold back a prompt or a
            # progress line that carries no newline, which is exactly the
            # output a streaming terminal exists to show promptly.
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=0)
            self.fd = self.proc.stdout.fileno()
            self.wfd = self.proc.stdin.fileno()
        self.lock = threading.Lock()
        self.used = time.time()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        # A pty's master is a bare descriptor and is closed as one; a pipe
        # belongs to a Python file object, and closing the descriptor out from
        # under it leaves the object believing it is open — the next process to
        # be given that number then has it closed underneath it.
        shutters = ([lambda: os.close(self.fd)] if self.tty else
                    [self.proc.stdin.close, self.proc.stdout.close])
        for shut in [self.proc.kill] + shutters:
            try:
                shut()
            except Exception:                                  # noqa: BLE001
                pass
        try:
            # Reaped here, not left to chance: alive() is what decides whether
            # the next command reuses this session, and a killed-but-unwaited
            # process still answers poll() with None.
            self.proc.wait(timeout=2)
        except Exception:                                      # noqa: BLE001
            pass

    def interrupt(self) -> bool:
        """Ctrl+C, if there is a terminal to deliver it to.

        Deliberately does not take the lock: the command being interrupted is
        holding it, which is the entire point.
        """
        if not (self.tty and self.alive()):
            return False
        try:
            os.write(self.wfd, b"\x03")
        except OSError:
            return False
        # The reader has to know, because interrupting costs it its marker —
        # see frames().
        self.interrupted_at = time.time()
        return True

    def frames(self, command: str, timeout: float):
        """("out", text) as it is produced, then ("exit", code).

        Ends instead with ("timeout", "") or ("gone", "") — both of which mean
        the session is finished and the next command opens a new one.
        """
        # The marker is assembled by the shell from two halves that are never
        # adjacent in what we send. A terminal echoes its input, so a marker
        # written out whole would come back in the echo and be read as the
        # command finishing before it had started.
        key = secrets.token_hex(6)
        token = f"__dne_{key}__"
        # `2>&1` keeps the two streams in the order the command produced them,
        # which is what a terminal shows and what a reader expects.
        marker = f"printf '%s%s%s\\n' '__dne' '_{key}__' \"$?\"\n"
        sent = f"{command} 2>&1\n" + marker
        # One command at a time down one pipe. Waiting for the lock instead of
        # saying so is what a hang looks like from the outside, and the caller
        # can do something about "still running" — it cannot do anything about
        # silence.
        if not self.lock.acquire(timeout=1.0):
            yield ("busy", "")
            return
        try:
            self.used, self.interrupted_at = time.time(), 0.0
            try:
                os.write(self.wfd, sent.encode("utf-8", "replace"))
            except OSError:
                self.close()
                yield ("gone", "")
                return
            # What a shell with echo still on will send straight back at us.
            pending_echo = sent.replace("\n", "\r\n") if self.echoes else ""
            done, resent, beat = False, False, time.time()
            try:
                buf, deadline, quiet = "", time.time() + timeout, time.time()
                while True:
                    if time.time() - beat > 1.0:
                        # A command can be silent for minutes (`sleep`, a `tail
                        # -f` on a quiet log). Something has to come out of here
                        # anyway, or the caller cannot notice that whoever asked
                        # for this has closed the page and gone.
                        beat = time.time()
                        yield ("tick", "")
                    if self.interrupted_at and not resent and \
                            time.time() - self.interrupted_at > 0.3:
                        # A terminal flushes its input queue when it processes
                        # ^C, and the marker line was sitting in that queue
                        # waiting to be read. Without this the command stops and
                        # the reader waits for a status that nobody will ever
                        # print. Send it again, and hold the shell to a short
                        # deadline: if that does not come back either, the
                        # interrupt did not take and the session is finished.
                        resent = True
                        deadline = min(deadline, time.time() + 4)
                        try:
                            os.write(self.wfd, marker.encode("utf-8", "replace"))
                        except OSError:
                            pass
                    left = deadline - time.time()
                    if left <= 0:
                        yield ("timeout", "")
                        return
                    ready, _, _ = select.select([self.fd], [], [],
                                                min(0.2, left))
                    if ready:
                        try:
                            data = os.read(self.fd, 65536)
                        except OSError:
                            # A pty reports the far end closing as EIO rather
                            # than as end of file.
                            data = b""
                        if not data:                   # the shell went away
                            if buf:
                                yield ("out", _plain(buf))
                            yield ("gone", "")
                            return
                        buf += data.decode("utf-8", "replace")
                        self.used = quiet = time.time()
                    if pending_echo:
                        same = 0
                        while (same < len(buf) and same < len(pending_echo)
                               and buf[same] == pending_echo[same]):
                            same += 1
                        buf, pending_echo = buf[same:], pending_echo[same:]
                        if buf and pending_echo:
                            pending_echo = ""   # diverged: it was real output
                    at = buf.find(token)
                    if at >= 0:
                        if at:
                            yield ("out", _plain(buf[:at]))
                        rest, waited = buf[at + len(token):], 0.0
                        # the exit status may not have arrived with the marker
                        while "\n" not in rest and waited < 2.0:
                            if select.select([self.fd], [], [], 0.2)[0]:
                                more = os.read(self.fd, 4096)
                                if not more:
                                    break
                                rest += more.decode("utf-8", "replace")
                            waited += 0.2
                        digits = rest.split("\n", 1)[0].strip()
                        done = True
                        yield ("exit", int(digits) if digits.isdigit() else 0)
                        return
                    # Never flush past something that could be the marker, nor
                    # a lone CR whose LF is still on its way.
                    safe = len(buf) - max(_overlap(buf, token),
                                          1 if buf.endswith("\r") else 0)
                    cut = buf.rfind("\n", 0, safe) + 1
                    if not cut and safe and time.time() - quiet > CHUNK_QUIET:
                        cut = safe          # a line with no newline yet: show it
                    if cut:
                        yield ("out", _plain(buf[:cut]))
                        buf = buf[cut:]
                        beat = time.time()
            finally:
                # Left mid-command — a timeout, or a reader that walked away
                # while `ping` was still running. The stream is now out of step
                # with the marker protocol and the command is still going, so
                # the only honest thing to do is end the session.
                if not done:
                    self.close()
        finally:
            self.lock.release()

    def run(self, command: str, timeout: float) -> dict:
        """The whole answer, for callers that have nowhere to stream it."""
        out, code, busy = [], None, False
        for kind, val in self.frames(command, timeout):
            if kind == "out":
                out.append(val)
            elif kind == "exit":
                code = val
            elif kind == "busy":
                busy = True
        return {"code": 124 if code is None else code, "busy": busy,
                "out": "".join(out).rstrip("\n"), "timeout": code is None}


def _reap() -> None:
    now = time.time()
    for key, s in list(_sessions.items()):
        if not s.alive() or now - s.used > SESSION_IDLE:
            s.close()
            _sessions.pop(key, None)


def _start_session(cluster: dict, namespace: str, pod: str, container: str,
                   want_tty: bool):
    """A proven shell, or None. Nothing is handed out untested: a container
    with no /bin/sh exits at once and would otherwise fail on the user's first
    command, and an API server that will not upgrade to a terminal must fall
    back rather than hang."""
    argv = _kubectl_argv(cluster, namespace, pod, container, want_tty)
    if not argv:
        return None
    try:
        s = _Session(argv, want_tty)
    except Exception:                                          # noqa: BLE001
        return None
    # Quiet the prompt and the echo before anything a person types reaches it.
    # An interactive shell on a terminal prints PS1 and repeats its input, and
    # both would land in the output as though the container had said them.
    probe = s.run("PS1=''; stty -echo 2>/dev/null; printf ok", 12)
    if probe["timeout"] or "ok" not in probe["out"]:
        s.close()
        return None
    if want_tty:
        # Whether `stty` took is a fact about this image, not something to
        # assume: busybox has it, distroless has nothing, and a shell still
        # echoing needs its echo stripped out of every answer.
        again = s.run("printf ok", 12)
        s.echoes = "printf" in again["out"]
    return s


def session_for(cluster: dict, namespace: str, pod: str, container: str = ""):
    """An open shell in this container, or None when it has no shell."""
    with _sess_lock:
        _reap()
        key = (cluster.get("id"), namespace, pod, container)
        s = _sessions.get(key)
        if s and s.alive():
            return s
        if len(_sessions) >= SESSION_MAX:
            oldest = min(_sessions, key=lambda k: _sessions[k].used)
            _sessions.pop(oldest).close()
        # A terminal first, because that is what makes output arrive as it is
        # produced; a plain pipe if this cluster will not give us one.
        s = (_start_session(cluster, namespace, pod, container, True)
             or _start_session(cluster, namespace, pod, container, False))
        if s is None:
            return None
        _sessions[key] = s
        return s


def close_session(cluster: dict, namespace: str, pod: str,
                  container: str = "") -> None:
    with _sess_lock:
        s = _sessions.pop((cluster.get("id"), namespace, pod, container), None)
    if s:
        s.close()


# ── running a command inside a pod ─────────────────────────────
# `exec` is on BLOCKED_VERBS above and stays there: that list governs what an
# operator may type into the console, where a shell inside a container would be
# an unbounded, unauditable session. This is the other thing — one command,
# named arguments, a deadline, no TTY, and the whole of it written to the audit
# log. The distinction is the point: the console refuses `kubectl exec …`
# because nobody can say afterwards what was run; this records exactly that.
#
# It is still the most powerful thing in this module. Code runs in the
# container as whatever that pod's service account is, so it is gated the same
# way every write is — the cluster must be marked for management — and never
# offered on a cluster that is not.
EXEC_TIMEOUT = 25
EXEC_CAP = 200_000

# A shell is how you get a pipeline, a redirect or a second command, so the
# command is split into argv and handed over as one process. Somebody who wants
# `sh -c` can ask for it by name and it is recorded that way.
def _exec_check(namespace: str, pod: str, command: str, container: str,
                allow_write: bool) -> list:
    """The argv, or Refused. Shared so streaming cannot be the laxer door."""
    if not allow_write:
        raise Refused(read_only_why())
    for label, v in (("namespace", namespace), ("pod", pod),
                     ("container", container)):
        if v and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", v):
            raise Refused(f"'{v}' is not a valid {label} name")
    if not namespace or not pod:
        raise Refused("a namespace and a pod are needed")
    argv = shlex.split(command.strip())
    if not argv:
        raise Refused("nothing to run")
    return argv


def _exec_once(cluster: dict, namespace: str, pod: str, argv: list,
               container: str, timeout: float) -> dict:
    """One `kubectl exec` per command — the fallback when the image has no
    shell to hold open, and the whole handshake every time."""
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    full = base + ["exec", pod, "-n", namespace]
    if container:
        full += ["-c", container]
    full += ["--", *argv]
    started = time.time()
    try:
        r = subprocess.run(full, capture_output=True, text=True,
                           timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", (f"no answer within {timeout:g}s — this runs one "
                              f"command and waits; it is not a session"), 124
    except FileNotFoundError:
        raise Refused("kubectl is not on the PATH")
    return {"argv": argv, "kind": "exec", "code": code, "ok": code == 0,
            "stdout": out[:EXEC_CAP], "stderr": err[-8000:],
            "took": round(time.time() - started, 2),
            "session": False, "display": " ".join(argv)}


def exec_in(cluster: dict, namespace: str, pod: str, command: str,
            container: str = "", allow_write: bool = False,
            timeout: int = EXEC_TIMEOUT) -> dict:
    """Run one command inside a container and return what it printed."""
    argv = _exec_check(namespace, pod, command, container, allow_write)
    # An open shell in this container turns 2.0s into the round trip for the
    # data alone. Falls back below when the image has no shell to hold open.
    sess = session_for(cluster, namespace, pod, container)
    if sess is None:
        return _exec_once(cluster, namespace, pod, argv, container, timeout)
    started = time.time()
    got = sess.run(command.strip(), timeout)
    return {"argv": argv, "kind": "exec", "code": got["code"],
            "ok": got["code"] == 0, "stdout": got["out"][:EXEC_CAP],
            "stderr": ("" if not got["timeout"] else
                       f"no answer within {timeout}s — the session was "
                       f"closed; the next command opens a new one"),
            "took": round(time.time() - started, 2),
            "session": True, "display": " ".join(argv)}


# ── a ConfigMap or Secret key, changed on the cluster ──────────
# WHY THIS IS A FUNCTION AND NOT AN ENTRY IN ACTIONS
#     Everything in ACTIONS builds its argv from a fixed handful of Kubernetes
#     names, each of which is checked against the shape Kubernetes allows. A
#     config VALUE is none of those things: it is free text — a URL with an
#     ampersand in it, a JSON blob, a certificate with newlines. Passing that
#     through a table whose contract is "names only" is how a quoting bug
#     becomes a command.
#
#     So the value never goes near argv. It goes into a JSON patch built by
#     json.dumps and handed to kubectl on stdin, which cannot be misread as an
#     argument no matter what is in it.
#
# WHY MERGE AND NOT APPLY
#     `apply` needs the whole object and would delete any key not in what is
#     sent; a merge patch touches the named key and leaves the rest alone. This
#     editor changes one key at a time, and the cost of getting that wrong is
#     somebody else's configuration disappearing.
DATA_KINDS = ("configmap", "secret")
KEY_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")


def _data_patch(kind: str, key: str, value, delete: bool) -> str:
    """The merge patch for one key. `None` as a value removes it."""
    if kind == "secret" and not delete:
        # `data` and base64 rather than `stringData`: stringData is write-only
        # sugar the API server folds into data, so a merge patch through it
        # cannot express a REMOVAL — and removing a key is half of this editor.
        value = base64.b64encode(str(value).encode()).decode()
    return json.dumps({"data": {key: None if delete else value}})


def set_data_key(cluster: dict, kind: str, name: str, namespace: str,
                 key: str, value: str, allow_write: bool = False,
                 timeout: int = TIMEOUT) -> dict:
    """Write one key into a ConfigMap or Secret. Removes it when delete=True."""
    return _data_write(cluster, kind, name, namespace, key, value, False,
                       allow_write, timeout)


def delete_data_key(cluster: dict, kind: str, name: str, namespace: str,
                    key: str, allow_write: bool = False,
                    timeout: int = TIMEOUT) -> dict:
    return _data_write(cluster, kind, name, namespace, key, "", True,
                       allow_write, timeout)


def _data_write(cluster: dict, kind: str, name: str, namespace: str, key: str,
                value: str, delete: bool, allow_write: bool,
                timeout: int) -> dict:
    kind = (kind or "").lower()
    if kind not in DATA_KINDS:
        raise Refused(f"{kind or 'that'} has no data section to edit — only "
                      f"{' and '.join(DATA_KINDS)} do")
    for label, v in (("namespace", namespace), ("name", name)):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", v or ""):
            raise Refused(f"'{v}' is not a valid {label}")
    if not KEY_SHAPE.fullmatch(key or ""):
        # Kubernetes' own rule for a data key. Refused here rather than by the
        # API server so the message names the field instead of quoting a schema.
        raise Refused(f"'{key}' is not a valid key — letters, digits, dots, "
                      f"dashes and underscores only")
    if not allow_write:
        raise Refused(read_only_why("this changes a live resource"))
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    patch = _data_patch(kind, key, value, delete)
    argv = ["patch", kind, name, "-n", namespace, "--type", "merge",
            "--patch-file", "/dev/stdin"]
    started = time.time()
    try:
        r = subprocess.run(base + argv, input=patch, capture_output=True,
                           text=True, timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", f"timed out after {timeout}s", 124
    return {"argv": argv, "kind": "write", "code": code,
            "stdout": out[:OUTPUT_CAP], "stderr": err[-8000:],
            "ok": code == 0 and not FAILED_ANYWAY.search(
                (err or "") + "\n" + (out or "")),
            "took": round(time.time() - started, 2),
            # The value is deliberately absent: this string is what gets
            # audited, and a Secret's value must not end up in the audit log.
            "display": f"kubectl patch {kind} {name} -n {namespace} "
                       + (f"(remove {key})" if delete else f"({key})")}


# ── one object's YAML, read and applied ────────────────────────
# WHY THIS IS THE MOST GUARDED THING IN THIS FILE
#     Every other write here is a fixed verb on a named object: restart that,
#     scale this to three. An applied document can do anything the API server
#     allows — change an image, drop a volume, remove a probe, replace a whole
#     spec — and it is typed by hand.
#
#     So it is bounded three ways rather than trusted:
#
#       * the SAME OBJECT. The submitted document's kind, name and namespace must
#         match the one the editor was opened on. The button says "edit this
#         deployment", not "apply arbitrary YAML to my cluster", and without this
#         those are the same feature.
#       * a DRY RUN first. `--dry-run=server` runs the whole admission path and
#         changes nothing, so a typo is a message rather than an outage.
#       * the ordinary gates. Management area, the cluster's own tick, and a
#         typed cluster name on production — the same three the console goes
#         through, applied by the caller.
def read_yaml(cluster: dict, kind: str, name: str, namespace: str,
              timeout: int = TIMEOUT) -> dict:
    """One object as YAML, with the server's own bookkeeping taken out."""
    for label, v in (("namespace", namespace), ("name", name), ("kind", kind)):
        if v and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", v):
            raise Refused(f"'{v}' is not a valid {label}")
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    argv = ["get", kind, name, "-o", "yaml", "--show-managed-fields=false"]
    if namespace:
        argv += ["-n", namespace]
    try:
        r = subprocess.run(base + argv, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"no answer within {timeout}s", "text": ""}
    if r.returncode:
        said = (r.stderr or r.stdout).strip().splitlines()
        return {"error": re.sub(r"^Error from server \(([^)]+)\): ", r"\1: ",
                                said[0] if said else "kubectl failed"),
                "text": ""}
    return {"error": "", "text": _without_status(r.stdout)}


def _without_status(doc: str) -> str:
    """The document without its `status:` block.

    Status is what the cluster reports back, not anything anybody can set — a
    third of a Deployment's YAML and every line of it read-only. Leaving it in
    means the reader scrolls past forty lines they cannot change to reach the two
    they can, and then applies them back for no reason.

    Cut by indentation rather than parsed: this has to hand back the operator's
    own document, comments and key order intact, and a YAML round trip through a
    parser does not promise that.
    """
    out, dropping = [], False
    for line in doc.splitlines():
        if dropping:
            # the block ends at the next line that starts a top-level key
            if line[:1] not in (" ", "\t", "") or line.startswith("---"):
                dropping = False
            else:
                continue
        if line == "status:" or line.startswith("status:"):
            dropping = True
            continue
        out.append(line)
    return "\n".join(out).rstrip() + "\n"


def _identity(doc: str) -> tuple:
    """(kind, name, namespace) as the submitted document declares them."""
    import yaml as _yaml
    try:
        got = _yaml.safe_load(doc)
    except Exception as e:                                    # noqa: BLE001
        raise Refused(f"that is not valid YAML: {str(e).splitlines()[0][:160]}")
    if not isinstance(got, dict):
        raise Refused("that is not a Kubernetes object")
    meta = got.get("metadata") or {}
    return ((got.get("kind") or "").lower(), meta.get("name") or "",
            meta.get("namespace") or "")


def apply_yaml(cluster: dict, kind: str, name: str, namespace: str, doc: str,
               dry_run: bool = False, allow_write: bool = False,
               timeout: int = TIMEOUT) -> dict:
    """Apply an edited document, refusing anything that is not the same object."""
    got_kind, got_name, got_ns = _identity(doc)
    # `deploy` on the command line is `Deployment` in the document, so the
    # comparison is on the prefix rather than on equality.
    if not got_kind.startswith(kind.lower().rstrip("s")[:4]) \
            and not kind.lower().startswith(got_kind[:4]):
        raise Refused(f"this editor was opened on a {kind}, and that document "
                      f"is a {got_kind or 'document with no kind'}")
    if got_name != name:
        raise Refused(f"this editor was opened on '{name}', and that document "
                      f"is called '{got_name or '(nothing)'}'")
    if (got_ns or "") != (namespace or ""):
        raise Refused(f"this editor was opened in namespace "
                      f"'{namespace or '(none)'}', and that document says "
                      f"'{got_ns or '(none)'}'")
    if not (dry_run or allow_write):
        raise Refused(read_only_why("applying a document changes it"))
    base = base_args(cluster)
    if not base:
        raise Refused("this cluster has no kubeconfig or context set")
    argv = ["apply", "-f", "-"] + (["--dry-run=server"] if dry_run else [])
    started = time.time()
    try:
        r = subprocess.run(base + argv, input=doc, capture_output=True,
                           text=True, timeout=timeout)
        out, err, code = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", f"timed out after {timeout}s", 124
    return {"argv": argv, "kind": "write", "code": code,
            "stdout": out[:OUTPUT_CAP], "stderr": err[-8000:],
            "ok": code == 0 and not FAILED_ANYWAY.search(
                (err or "") + "\n" + (out or "")),
            "took": round(time.time() - started, 2),
            "dry_run": dry_run,
            # The document is deliberately absent: this is what gets audited, and
            # a Secret's data must not end up in the audit log.
            "display": ("kubectl apply" + (" --dry-run=server" if dry_run else "")
                        + f" {kind}/{name}"
                        + (f" -n {namespace}" if namespace else ""))}
