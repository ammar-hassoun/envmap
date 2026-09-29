"""Cluster access: service accounts, RBAC and the kubeconfig that uses them.

WHAT THIS DOES
    Creates a ServiceAccount in the cluster, binds it to a role, mints a token
    for it, and assembles a kubeconfig file the holder can use. It also lists
    and revokes the accounts it created, so what has been handed out stays
    visible.

WHY A SERVICE ACCOUNT AND NOT A CERTIFICATE
    A client certificate cannot be revoked without rotating the cluster CA. A
    ServiceAccount token can be revoked by deleting the account, and its
    lifetime is set when it is minted. For access handed to a person or a tool
    that may later need taking away, that is the difference that matters.

THE TOKEN IS SHOWN ONCE
    The portal does not store it. It is minted, written into the kubeconfig that
    gets downloaded, and forgotten — losing it means minting another, which is
    the correct trade. The audit log records that a token was issued, its
    lifetime and its scope, never its value.

PERMISSIONS
    The presets bind Kubernetes' own aggregated roles (view, edit, admin,
    cluster-admin) rather than inventing a role vocabulary — they are what a
    cluster already documents and what an operator already knows. "Custom"
    builds a role from the verbs and resources given, so least privilege is
    possible without hand-writing YAML.
"""
import json
import re
import subprocess
from pathlib import Path

import yaml

from .kube import base_args, reachable

TIMEOUT = 15
LABEL = "app.kubernetes.io/created-by=config-portal"
LABEL_KEY = "app.kubernetes.io/created-by"

# Kubernetes' own user-facing roles, described in the words of what they let
# someone do rather than by their name.
PRESETS = {
    "view": {
        "role": "view", "label": "Read-only",
        "note": "read most things, but not Secrets and nothing that writes",
    },
    "edit": {
        "role": "edit", "label": "Read and write",
        "note": "create, change and delete workloads; cannot change RBAC",
    },
    "admin": {
        "role": "admin", "label": "Namespace admin",
        "note": "everything within its namespaces, including RBAC there",
    },
    "cluster-admin": {
        "role": "cluster-admin", "label": "Cluster admin",
        "note": "unrestricted — the same power as the kubeconfig you are using",
    },
    "custom": {
        "role": "", "label": "Custom",
        "note": "exactly the verbs and resources you list, and nothing else",
    },
}

VERBS = ["get", "list", "watch", "create", "update", "patch", "delete",
         "deletecollection"]

NAME_OK = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?")


class AccessError(Exception):
    """Something the portal will not or could not do, with the reason."""


def _kubectl(cluster: dict, *args, timeout: int = TIMEOUT):
    base = base_args(cluster)
    if not base:
        raise AccessError("this cluster has no kubeconfig or context set")
    # Access management runs several kubectl calls per action, so a dead
    # cluster answers once, from the shared cached probe, instead of once per
    # call at full timeout.
    ok, why = reachable(cluster)
    if not ok:
        raise AccessError(f"cluster unreachable — {why}")
    try:
        r = subprocess.run(base + list(args), capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AccessError(f"kubectl gave no answer within {timeout}s")
    return r.returncode, r.stdout, r.stderr.strip()


def _check_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not name or not NAME_OK.fullmatch(name) or len(name) > 200:
        raise AccessError("the name must be lowercase letters, digits and "
                          "hyphens, starting and ending with a letter or digit")
    return name


def cluster_endpoint(cluster: dict) -> dict:
    """The server URL and CA data from the cluster's stored kubeconfig.

    Read from the file rather than asked of kubectl: it is the same information,
    and a kubeconfig the portal writes has to match the one it already trusts.
    """
    path = cluster.get("kubeconfig_file")
    if not path or not Path(path).exists():
        raise AccessError("this cluster has no stored kubeconfig to copy the "
                          "API server address and CA from")
    doc = yaml.safe_load(Path(path).read_text()) or {}
    ctx_name = cluster.get("context")
    ctx = next((c for c in doc.get("contexts", [])
                if c.get("name") == ctx_name), None)
    want = (ctx or {}).get("context", {}).get("cluster") if ctx else None
    entry = next((c for c in doc.get("clusters", [])
                  if not want or c.get("name") == want), None)
    if not entry:
        raise AccessError("could not find this context's cluster entry in the "
                          "stored kubeconfig")
    c = entry.get("cluster", {})
    return {
        "name": entry.get("name", "cluster"),
        "server": c.get("server", ""),
        "ca_data": c.get("certificate-authority-data", ""),
        "insecure": bool(c.get("insecure-skip-tls-verify")),
    }


def build_kubeconfig(cluster: dict, user: str, token: str,
                     namespace: str = "") -> str:
    """A standalone kubeconfig for one service account token."""
    ep = cluster_endpoint(cluster)
    entry = {"server": ep["server"]}
    if ep["ca_data"]:
        entry["certificate-authority-data"] = ep["ca_data"]
    elif ep["insecure"]:
        # carried over rather than silently dropped: a kubeconfig that cannot
        # verify the API server has to say so
        entry["insecure-skip-tls-verify"] = True
    ctx = {"cluster": ep["name"], "user": user}
    if namespace:
        ctx["namespace"] = namespace
    doc = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": ep["name"], "cluster": entry}],
        "users": [{"name": user, "user": {"token": token}}],
        "contexts": [{"name": f"{user}@{ep['name']}", "context": ctx}],
        "current-context": f"{user}@{ep['name']}",
        "preferences": {},
    }
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def create(cluster: dict, name: str, preset: str, namespaces: list,
           sa_namespace: str = "default", duration: str = "8760h",
           verbs: list | None = None, resources: list | None = None,
           cluster_wide_ok: bool = False) -> dict:
    """Create a service account, bind it, and mint a token.

    Every step is reported, including the ones that were already done, so a
    half-finished attempt can be understood rather than guessed at.
    """
    name = _check_name(name)
    sa_ns = _check_name(sa_namespace or "default")
    if preset not in PRESETS:
        raise AccessError("choose a permission level")
    scope_all = not namespaces
    # a blank namespace field means the whole cluster, which is a much bigger
    # grant than most people intend when they leave a box empty — so it has to
    # be asked for, not defaulted into
    if scope_all and not cluster_wide_ok:
        raise AccessError("leaving namespaces blank grants this user the "
                          "permission across the entire cluster. Tick "
                          "“cluster-wide, on purpose” if that is what you want, "
                          "or list the namespaces it should be limited to.")
    if preset == "admin" and scope_all:
        raise AccessError("“Namespace admin” needs at least one namespace — for "
                          "cluster-wide power use Cluster admin, deliberately")
    if not re.fullmatch(r"\d+[smh]", duration or ""):
        raise AccessError("lifetime must look like 24h, 720h or 30m")
    if preset == "custom":
        verbs = [v for v in (verbs or []) if v in VERBS]
        resources = [r.strip() for r in (resources or []) if r.strip()]
        if not verbs or not resources:
            raise AccessError("a custom permission needs at least one verb and "
                              "one resource")
    for ns in list(namespaces or []) + [sa_ns]:
        _check_name(ns)

    steps = []

    def step(what: str, *args):
        code, out, err = _kubectl(cluster, *args)
        ok = code == 0 or "already exists" in err
        steps.append({"what": what, "ok": ok,
                      "detail": (err or out).strip()[:300] or "done",
                      "existed": "already exists" in err})
        if not ok:
            raise AccessError(f"{what} failed: {err[:300]}")

    step(f"service account {sa_ns}/{name}",
         "create", "serviceaccount", name, "-n", sa_ns)
    step("label it as created here",
         "label", "serviceaccount", name, "-n", sa_ns, LABEL, "--overwrite")

    role = PRESETS[preset]["role"]
    if preset == "custom":
        role = f"{name}-role"
        args = ["create", "clusterrole", role]
        args += [f"--verb={','.join(verbs)}", f"--resource={','.join(resources)}"]
        step(f"cluster role {role}", *args)
        step("label the role", "label", "clusterrole", role, LABEL, "--overwrite")

    if scope_all:
        step(f"cluster-wide binding to {role}",
             "create", "clusterrolebinding", f"{name}-binding",
             f"--clusterrole={role}", f"--serviceaccount={sa_ns}:{name}")
        step("label the binding", "label", "clusterrolebinding",
             f"{name}-binding", LABEL, "--overwrite")
    else:
        for ns in namespaces:
            ns = _check_name(ns)
            step(f"binding to {role} in {ns}",
                 "create", "rolebinding", f"{name}-binding", "-n", ns,
                 f"--clusterrole={role}", f"--serviceaccount={sa_ns}:{name}")
            step(f"label the binding in {ns}", "label", "rolebinding",
                 f"{name}-binding", "-n", ns, LABEL, "--overwrite")

    code, out, err = _kubectl(cluster, "create", "token", name, "-n", sa_ns,
                              f"--duration={duration}")
    if code != 0:
        raise AccessError(
            "the account and its permissions were created, but minting a token "
            f"failed: {err[:300]}. On Kubernetes older than 1.24, create a "
            "Secret of type kubernetes.io/service-account-token instead.")
    token = out.strip()
    steps.append({"what": f"token valid for {duration}", "ok": True,
                  "detail": "issued — shown once, not stored", "existed": False})

    return {
        "name": name, "sa_namespace": sa_ns, "preset": preset, "role": role,
        "namespaces": namespaces or [], "duration": duration, "steps": steps,
        "kubeconfig": build_kubeconfig(cluster, name, token,
                                      namespaces[0] if namespaces else ""),
        # for the audit entry: what was granted, never the token
        "summary": (f"{name} · {PRESETS[preset]['label']} · "
                    f"{'cluster-wide' if scope_all else ', '.join(namespaces)} · "
                    f"{duration}"),
    }


def reissue(cluster: dict, name: str, sa_namespace: str,
            duration: str = "8760h") -> dict:
    """Mint a fresh token for an account that already exists.

    A lost kubeconfig cannot be recovered — the portal never stored the token —
    so the honest equivalent is a new token for the same account, carrying the
    same permissions. The previous token keeps working until it expires:
    Kubernetes has no way to revoke one token of a service account, only the
    account itself. That is said plainly in the UI rather than implied.
    """
    name, sa_ns = _check_name(name), _check_name(sa_namespace)
    if not re.fullmatch(r"\d+[smh]", duration or ""):
        raise AccessError("lifetime must look like 24h, 720h or 30m")
    code, out, err = _kubectl(cluster, "get", "serviceaccount", name, "-n", sa_ns,
                              "-o", "name")
    if code != 0:
        raise AccessError(f"{sa_ns}/{name} does not exist here: {err[:200]}")

    # report the permissions this account actually has, read back from the
    # cluster rather than remembered — bindings may have changed since it was made
    found = listing(cluster)
    me = next((u for u in found.get("users", [])
               if u["name"] == name and u["namespace"] == sa_ns), {})
    scope = ([f"{r} cluster-wide" for r in me.get("cluster_roles", [])]
             + [f"{r} in {ns}" for ns, r in me.get("scoped", [])])

    code, out, err = _kubectl(cluster, "create", "token", name, "-n", sa_ns,
                              f"--duration={duration}")
    if code != 0:
        raise AccessError(f"could not mint a token: {err[:300]}")
    first_ns = next((ns for ns, _r in me.get("scoped", [])), "")
    return {
        "name": name, "sa_namespace": sa_ns, "preset": "", "role": "",
        "namespaces": [first_ns] if first_ns else [],
        "duration": duration, "reissued": True,
        "permissions": scope,
        "steps": [{"what": f"new token for {sa_ns}/{name}, valid {duration}",
                   "ok": True, "detail": "issued — shown once, not stored",
                   "existed": False},
                  {"what": "the previous token stays valid until it expires",
                   "ok": True, "detail": "revoke the user to invalidate it",
                   "existed": False}],
        "kubeconfig": build_kubeconfig(cluster, name, out.strip(), first_ns),
        "summary": (f"{name} · new token · {', '.join(scope) or 'no bindings'} · "
                    f"{duration}"),
    }


def listing(cluster: dict) -> dict:
    """Service accounts this portal created, with what they are bound to."""
    try:
        code, out, err = _kubectl(cluster, "get", "serviceaccounts", "-A",
                                  "-l", LABEL, "-o", "json")
        if code != 0:
            return {"error": err[:300], "users": []}
        sas = json.loads(out or "{}").get("items", [])
        code, out, _ = _kubectl(cluster, "get", "clusterrolebindings",
                                "-l", LABEL, "-o", "json")
        crbs = json.loads(out or "{}").get("items", []) if code == 0 else []
        code, out, _ = _kubectl(cluster, "get", "rolebindings", "-A",
                                "-l", LABEL, "-o", "json")
        rbs = json.loads(out or "{}").get("items", []) if code == 0 else []
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "users": []}

    def subjects_match(b, sa):
        return any(s.get("kind") == "ServiceAccount"
                   and s.get("name") == sa["metadata"]["name"]
                   and s.get("namespace") == sa["metadata"]["namespace"]
                   for s in b.get("subjects") or [])

    users = []
    for sa in sas:
        meta = sa["metadata"]
        cluster_wide = [b["roleRef"]["name"] for b in crbs if subjects_match(b, sa)]
        scoped = [(b["metadata"]["namespace"], b["roleRef"]["name"])
                  for b in rbs if subjects_match(b, sa)]
        users.append({
            "name": meta["name"], "namespace": meta["namespace"],
            "created": (meta.get("creationTimestamp") or "")[:10],
            "cluster_roles": cluster_wide,
            "scoped": scoped,
            "orphan": not cluster_wide and not scoped,
        })
    return {"error": "", "users": sorted(users, key=lambda u: u["name"])}


def revoke(cluster: dict, name: str, sa_namespace: str) -> dict:
    """Delete the account, its bindings and any role created for it.

    Deleting the ServiceAccount is what actually invalidates the token, so that
    happens even if tidying up the bindings fails.
    """
    name, sa_ns = _check_name(name), _check_name(sa_namespace)
    done = []
    for what, args in (
        ("service account", ("delete", "serviceaccount", name, "-n", sa_ns)),
        ("cluster role binding", ("delete", "clusterrolebinding",
                                  f"{name}-binding", "--ignore-not-found")),
        ("custom cluster role", ("delete", "clusterrole", f"{name}-role",
                                 "--ignore-not-found")),
    ):
        code, out, err = _kubectl(cluster, *args)
        done.append({"what": what, "ok": code == 0,
                     "detail": (err or out).strip()[:200] or "done"})
    # namespaced bindings can exist in several namespaces
    code, out, _ = _kubectl(cluster, "get", "rolebindings", "-A", "-l", LABEL,
                            "-o", "json")
    if code == 0:
        for b in json.loads(out or "{}").get("items", []):
            if any(s.get("name") == name for s in b.get("subjects") or []):
                ns = b["metadata"]["namespace"]
                c2, o2, e2 = _kubectl(cluster, "delete", "rolebinding",
                                      b["metadata"]["name"], "-n", ns,
                                      "--ignore-not-found")
                done.append({"what": f"role binding in {ns}", "ok": c2 == 0,
                             "detail": (e2 or o2).strip()[:200] or "done"})
    return {"steps": done, "ok": all(d["ok"] for d in done)}
