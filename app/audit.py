"""A cluster security audit that installs nothing, anywhere.

WHY THIS EXISTS
    The usual answer is a scanner you deploy — kube-bench as a Job on each node,
    or an operator that runs continuously. Both are prerequisites, and a portal
    that needs one installed before it can say anything is a portal that says
    nothing on a cluster you were handed a kubeconfig for an hour ago.

    So this asks the Kubernetes API the same questions instead: a control plane
    that runs as static pods exposes its flags in the pod spec, every kubelet
    publishes its configuration on a read-only endpoint, and RBAC, Pod Security,
    network policy and workload hardening are all API objects by definition.

    So: read-only credentials, nothing deployed, nothing to maintain, and it works
    on a cluster you have only been handed a kubeconfig for.

WHAT IT CANNOT SEE, AND SAYS SO
    File permissions and ownership on the node (CIS 1.1.x, 4.1.x) are invisible
    through the API. So is the content of an audit policy file, or whether the
    admin kubeconfig on disk is 0600. Where a check cannot be answered this way,
    the finding says "not visible through the API" rather than passing it — a
    green tick nobody verified is worse than an honest gap, and that gap is the
    price of installing nothing.

HOW A CHECK IS WRITTEN
    A function that takes the gathered snapshot and yields findings. Adding one
    is a function and an entry in CHECKS; there is no framework to learn. Every
    finding carries the object it is about, the evidence that produced it, and
    what to do — a finding without a remediation is a complaint, not a report.
"""
import html
import io
import json
import re
import subprocess
from datetime import datetime, timezone

from . import csvsafe
from .fleet import _pmap
from .kube import base_args, reachable

TIMEOUT = 25
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Namespaces Kubernetes and its add-ons own. Workload checks still run over them,
# but their findings are marked so a team can tell "our problem" from "the
# distribution's choice" — a CNI genuinely needs host networking.
SYSTEM_NS = ("kube-system", "kube-public", "kube-node-lease")

# Dangerous Linux capabilities, in the words the container runtime uses.
RISKY_CAPS = ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
              "DAC_READ_SEARCH", "NET_RAW", "SYS_BOOT", "ALL")


def _kubectl_json(cluster: dict, *args, timeout: int = TIMEOUT):
    base = base_args(cluster)
    # the audit reads nine collections; on a dead cluster the shared probe
    # answers for all of them at once
    if not base or not reachable(cluster)[0]:
        return None
    try:
        r = subprocess.run(base + list(args) + ["-o", "json"],
                           capture_output=True, text=True, timeout=timeout)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:                                         # noqa: BLE001
        return None


def _raw(cluster: dict, path: str, timeout: int = 15):
    base = base_args(cluster)
    if not base or not reachable(cluster)[0]:
        return None
    try:
        r = subprocess.run(base + ["get", "--raw", path],
                           capture_output=True, text=True, timeout=timeout)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:                                         # noqa: BLE001
        return None


def _items(doc):
    return (doc or {}).get("items") or []


# ── gathering ──────────────────────────────────────────────────
def snapshot(cluster: dict) -> dict:
    """One read of everything the checks need, run together."""
    reads = {
        "nodes": ("get", "nodes"),
        "pods": ("get", "pods", "-A"),
        "namespaces": ("get", "namespaces"),
        "clusterroles": ("get", "clusterroles"),
        "clusterrolebindings": ("get", "clusterrolebindings"),
        "roles": ("get", "roles", "-A"),
        "rolebindings": ("get", "rolebindings", "-A"),
        "netpols": ("get", "networkpolicies", "-A"),
        "services": ("get", "services", "-A"),
    }
    keys = list(reads)
    got = _pmap(lambda k: (k, _kubectl_json(cluster, *reads[k], timeout=40)),
                keys, workers=min(6, len(keys)))
    snap = {k: v for k, v in (g for g in got if g)}
    if snap.get("nodes") is None:
        return {"error": "this cluster did not answer"}

    # every kubelet publishes its running configuration; that is where the node
    # half of the benchmark lives without touching the node
    names = [n["metadata"]["name"] for n in _items(snap.get("nodes"))]
    cfgs = _pmap(lambda n: (n, _raw(cluster, f"/api/v1/nodes/{n}/proxy/configz")),
                 names, workers=min(5, max(1, len(names))))
    snap["kubelets"] = {n: (c or {}).get("kubeletconfig")
                        for n, c in (x for x in cfgs if x)}
    snap["error"] = ""
    return snap


def _cp_args(snap: dict, component: str) -> dict:
    """The flags a control-plane component was started with.

    Read from the static pod's command, which is how a self-hosted control plane
    is visible through the API. A managed control plane is not: the caller shows
    that as "not visible" rather than inventing a verdict.
    """
    for p in _items(snap.get("pods")):
        name = p["metadata"].get("name", "")
        if not name.startswith(component):
            continue
        for c in p.get("spec", {}).get("containers", []) or []:
            argv = (c.get("command") or []) + (c.get("args") or [])
            flags = {}
            for a in argv:
                if not a.startswith("--"):
                    continue
                k, _, v = a[2:].partition("=")
                flags[k] = v if _ else "true"
            if flags:
                return {"pod": name, "flags": flags}
    return {}


def _f(check, severity, obj, evidence, fix, ns="", visible=True):
    return {"check": check, "severity": severity, "object": obj,
            "evidence": evidence, "remediation": fix, "namespace": ns,
            "visible": visible}


# ── where each finding came from ───────────────────────────────
# Every row carries the read that produced it and the field that was looked at,
# so "where is this coming from?" is answered on the row rather than in a
# document nobody has open. Matched on the check name's prefix.
SOURCES = (
    ("kubelet:", "kubectl get --raw /api/v1/nodes/<node>/proxy/configz",
     "the kubelet's own running configuration"),
    ("kube-apiserver:", "kubectl get pod -n kube-system kube-apiserver-<node>",
     "spec.containers[].command — the flags it was started with"),
    ("kube-controller-manager:",
     "kubectl get pod -n kube-system kube-controller-manager-<node>",
     "spec.containers[].command"),
    ("kube-scheduler:", "kubectl get pod -n kube-system kube-scheduler-<node>",
     "spec.containers[].command"),
    ("etcd:", "kubectl get pod -n kube-system etcd-<node>",
     "spec.containers[].command"),
    ("container:", "kubectl get pods -A",
     "spec.containers[].securityContext / resources / image"),
    ("pod:", "kubectl get pods -A",
     "spec.hostNetwork / hostPID / volumes / serviceAccountName"),
    ("namespace:", "kubectl get namespaces · kubectl get networkpolicies -A",
     "metadata.labels['pod-security.kubernetes.io/enforce'], and whether any "
     "NetworkPolicy exists in a namespace that runs pods"),
    ("rbac:", "kubectl get clusterroles · kubectl get clusterrolebindings",
     "rules[].verbs / rules[].resources / roleRef / subjects"),
    ("service:", "kubectl get services -A",
     "spec.type, spec.ports[].nodePort, status.loadBalancer"),
)


def source_of(check: str) -> dict:
    for prefix, cmd, field in SOURCES:
        if check.startswith(prefix):
            return {"command": cmd, "field": field}
    return {"command": "kubectl get …", "field": ""}


# The full list of reads the audit makes, shown on the page so anyone can run
# them by hand and get the same answer. Nothing else is contacted.
COMMANDS = [
    ("kubectl get nodes", "node names, versions and conditions"),
    ("kubectl get pods -A",
     "every workload's security context, and the control plane's own flags "
     "where it runs as static pods"),
    ("kubectl get namespaces", "Pod Security labels"),
    ("kubectl get clusterroles / clusterrolebindings", "who can do what"),
    ("kubectl get roles -A / rolebindings -A", "namespaced grants"),
    ("kubectl get networkpolicies -A", "which namespaces restrict pod traffic"),
    ("kubectl get services -A", "what is published outside the cluster"),
    ("kubectl get --raw /api/v1/nodes/<node>/proxy/configz",
     "each kubelet's live configuration — the node half of the benchmark, "
     "without touching the node"),
]


# ── control plane ──────────────────────────────────────────────
# Each check carries the Kubernetes default that applies when the flag is absent.
# Without that, "not set" reads as "wrong" — and a flag whose default is already
# safe (--service-account-lookup, etcd --auto-tls) would be reported as a finding
# on a correctly configured cluster. A false positive in a security report is
# worse than a missing check: it teaches people to skim.
#   flag, want, severity, problem, remediation, safe_when_unset
CP_CHECKS = {
    "kube-apiserver": [
        ("anonymous-auth", "false", "CRITICAL",
         "anonymous requests reach the API server",
         "set --anonymous-auth=false on the API server", False),
        ("authorization-mode", "RBAC", "CRITICAL",
         "RBAC is not in the authorization chain",
         "set --authorization-mode=Node,RBAC", False),
        ("audit-log-path", "*", "HIGH",
         "the API server keeps no audit log",
         "set --audit-log-path and an --audit-policy-file", False),
        ("encryption-provider-config", "*", "HIGH",
         "Secrets are stored in etcd unencrypted",
         "set --encryption-provider-config and rewrite the Secrets", False),
        ("profiling", "false", "LOW",
         "the profiling endpoint is enabled (it defaults to on)",
         "set --profiling=false unless you are debugging", False),
        # --service-account-lookup defaults to true, so absence is fine
        ("service-account-lookup", "true", "MEDIUM",
         "revoked service-account tokens stay valid until they expire",
         "set --service-account-lookup=true", True),
        ("enable-admission-plugins", "NodeRestriction", "HIGH",
         "NodeRestriction is not enabled, so a kubelet can change objects "
         "belonging to other nodes",
         "add NodeRestriction to --enable-admission-plugins", False),
    ],
    "kube-controller-manager": [
        ("use-service-account-credentials", "true", "MEDIUM",
         "controllers share one identity, so RBAC cannot separate them",
         "set --use-service-account-credentials=true", False),
        ("profiling", "false", "LOW",
         "the profiling endpoint is enabled (it defaults to on)",
         "set --profiling=false", False),
    ],
    "kube-scheduler": [
        ("profiling", "false", "LOW",
         "the profiling endpoint is enabled (it defaults to on)",
         "set --profiling=false", False),
    ],
    "etcd": [
        ("client-cert-auth", "true", "CRITICAL",
         "etcd accepts clients without a certificate",
         "set --client-cert-auth=true", False),
        ("peer-client-cert-auth", "true", "HIGH",
         "etcd peers are not mutually authenticated",
         "set --peer-client-cert-auth=true", False),
        # --auto-tls defaults to false, which is what we want
        ("auto-tls", "false", "HIGH",
         "etcd is using self-signed automatic certificates",
         "set --auto-tls=false and issue real certificates", True),
    ],
}

# A flag whose job has been taken over by a configuration file. The file's
# content is not visible through the API, so the check becomes "configured
# elsewhere" rather than pass or fail.
SUPERSEDED = {
    "authorization-mode": ("authorization-config",
                           "authorization is configured by "
                           "--authorization-config; its content is a file this "
                           "audit cannot read"),
    "enable-admission-plugins": ("admission-control-config-file",
                                 "admission is configured by "
                                 "--admission-control-config-file, whose content "
                                 "this audit cannot read"),
}


def _control_plane(snap: dict) -> list:
    out = []
    for component, checks in CP_CHECKS.items():
        found = _cp_args(snap, component)
        if not found:
            out.append(_f(
                f"{component}: configuration", "INFO", component,
                "not visible through the API — this component does not run as a "
                "pod here (a managed control plane, or a distribution that runs "
                "it outside Kubernetes)",
                "check it on the machine, or with your provider's tooling",
                visible=False))
            continue
        flags = found["flags"]
        for flag, want, sev, problem, fix, safe_unset in checks:
            have = flags.get(flag)

            if have is None:
                super_flag, why = SUPERSEDED.get(flag, ("", ""))
                if super_flag and flags.get(super_flag):
                    out.append(_f(f"{component}: --{flag}", "INFO", found["pod"],
                                  why, "review that file, ideally from git",
                                  ns="kube-system", visible=False))
                    continue
                if safe_unset:
                    continue          # the Kubernetes default already satisfies it
                out.append(_f(f"{component}: --{flag}", sev, found["pod"],
                              f"{problem} · (not set)", fix, ns="kube-system"))
                continue

            if want == "*":
                ok = bool(have)
            elif want in ("true", "false"):
                ok = str(have).lower() == want
            else:
                ok = want.lower() in str(have).lower()
            if not ok:
                out.append(_f(f"{component}: --{flag}", sev, found["pod"],
                              f"{problem} · --{flag}={have}", fix,
                              ns="kube-system"))
    return out


# ── kubelets ───────────────────────────────────────────────────
def _kubelets(snap: dict) -> list:
    out = []
    for node, cfg in (snap.get("kubelets") or {}).items():
        if not cfg:
            out.append(_f("kubelet: configuration", "INFO", node,
                          "the kubelet's configz endpoint could not be read — "
                          "this identity may not have nodes/proxy",
                          "grant get on nodes/proxy, or check the node directly",
                          visible=False))
            continue
        auth = cfg.get("authentication", {}) or {}
        authz = cfg.get("authorization", {}) or {}
        if (auth.get("anonymous") or {}).get("enabled"):
            out.append(_f("kubelet: anonymous authentication", "CRITICAL", node,
                          "anonymous requests are accepted on port 10250",
                          "set authentication.anonymous.enabled=false"))
        if str(authz.get("mode", "")).lower() == "alwaysallow":
            out.append(_f("kubelet: authorization mode", "CRITICAL", node,
                          "authorization mode is AlwaysAllow, so any "
                          "authenticated caller can do anything",
                          "set authorization.mode=Webhook"))
        if cfg.get("readOnlyPort"):
            out.append(_f("kubelet: read-only port", "HIGH", node,
                          f"read-only port {cfg['readOnlyPort']} is open and "
                          "needs no credentials",
                          "set readOnlyPort=0"))
        if not (auth.get("x509") or {}).get("clientCAFile"):
            out.append(_f("kubelet: client CA", "HIGH", node,
                          "no client CA is configured, so client certificates "
                          "are not verified",
                          "set authentication.x509.clientCAFile"))
        if str(cfg.get("streamingConnectionIdleTimeout", "")) in ("0", "0s"):
            out.append(_f("kubelet: streaming idle timeout", "MEDIUM", node,
                          "exec and port-forward connections never time out",
                          "set streamingConnectionIdleTimeout=5m"))
        if cfg.get("protectKernelDefaults") is not True:
            out.append(_f("kubelet: protectKernelDefaults", "MEDIUM", node,
                          "the kubelet will change kernel parameters it "
                          "disagrees with",
                          "set protectKernelDefaults=true"))
        if not (cfg.get("rotateCertificates") or cfg.get("serverTLSBootstrap")):
            out.append(_f("kubelet: certificate rotation", "LOW", node,
                          "client certificates are not rotated automatically",
                          "set rotateCertificates=true"))
        if cfg.get("makeIPTablesUtilChains") is False:
            out.append(_f("kubelet: iptables chains", "LOW", node,
                          "makeIPTablesUtilChains is false",
                          "leave makeIPTablesUtilChains at its default of true"))
    return out


# ── workloads ──────────────────────────────────────────────────
def _workloads(snap: dict) -> list:
    out = []
    for p in _items(snap.get("pods")):
        meta, spec = p["metadata"], p.get("spec", {})
        ns, name = meta.get("namespace", ""), meta.get("name", "")
        system = ns in SYSTEM_NS
        owner = next((o.get("kind", "") for o in
                      meta.get("ownerReferences", []) or []), "Pod")
        where = f"{ns}/{name}"
        pod_sc = spec.get("securityContext", {}) or {}

        if spec.get("hostNetwork"):
            out.append(_f("pod: host network", "LOW" if system else "HIGH", where,
                          "shares the node's network namespace",
                          "remove hostNetwork unless the workload is a CNI or "
                          "an ingress that needs it", ns))
        if spec.get("hostPID") or spec.get("hostIPC"):
            out.append(_f("pod: host PID/IPC", "LOW" if system else "HIGH", where,
                          "shares the node's process or IPC namespace",
                          "remove hostPID and hostIPC", ns))
        for v in spec.get("volumes", []) or []:
            hp = (v.get("hostPath") or {}).get("path")
            if hp and not system:
                out.append(_f("pod: hostPath volume", "HIGH", where,
                              f"mounts {hp} from the node",
                              "use a PersistentVolumeClaim, a ConfigMap or a "
                              "projected volume instead", ns))
                break
        if spec.get("automountServiceAccountToken") is not False and \
                spec.get("serviceAccountName", "default") == "default" and not system:
            out.append(_f("pod: default service account", "MEDIUM", where,
                          "runs as the namespace's default service account with "
                          "its token mounted",
                          "give the workload its own ServiceAccount, or set "
                          "automountServiceAccountToken: false", ns))

        for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            sc = c.get("securityContext", {}) or {}
            cn = f"{where}/{c.get('name','')}"
            if sc.get("privileged"):
                out.append(_f("container: privileged", "LOW" if system else "CRITICAL",
                              cn, "runs privileged, which is root on the node",
                              "remove privileged: true and grant only the "
                              "capabilities actually needed", ns))
            if sc.get("allowPrivilegeEscalation") is not False:
                out.append(_f("container: privilege escalation", "MEDIUM", cn,
                              "allowPrivilegeEscalation is not set to false",
                              "set allowPrivilegeEscalation: false", ns))
            run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if run_as_non_root is not True and run_as_user in (None, 0):
                out.append(_f("container: runs as root", "HIGH" if not system else "LOW",
                              cn, "nothing stops this container running as uid 0",
                              "set runAsNonRoot: true, or runAsUser to a "
                              "non-zero uid", ns))
            if sc.get("readOnlyRootFilesystem") is not True and not system:
                out.append(_f("container: writable root filesystem", "LOW", cn,
                              "the root filesystem is writable",
                              "set readOnlyRootFilesystem: true and mount an "
                              "emptyDir where the process needs to write", ns))
            caps = ((sc.get("capabilities") or {}).get("add") or [])
            risky = [c2 for c2 in caps if str(c2).upper() in RISKY_CAPS]
            if risky:
                out.append(_f("container: added capabilities", "HIGH", cn,
                              f"adds {', '.join(risky)}",
                              "drop these, or replace them with the narrower "
                              "capability the process needs", ns))
            if not ((sc.get("capabilities") or {}).get("drop")) and not system:
                out.append(_f("container: capabilities not dropped", "LOW", cn,
                              "no capabilities are dropped",
                              "drop ALL and add back only what is needed", ns))
            res = c.get("resources", {}) or {}
            if not res.get("limits") and not system:
                out.append(_f("container: no resource limits", "MEDIUM", cn,
                              "no cpu or memory limit, so one workload can "
                              "starve the node",
                              "set resources.limits for cpu and memory", ns))
            image = c.get("image", "")
            if image and (":" not in image.rsplit("/", 1)[-1]
                          or image.endswith(":latest")):
                out.append(_f("container: unpinned image", "MEDIUM", cn,
                              f"image {image} has no tag or uses :latest",
                              "pin a version, ideally by digest", ns))
            if c.get("imagePullPolicy") == "Always" and image.endswith(":latest"):
                pass    # already covered by the unpinned-image finding
    return out


# ── namespaces, network, RBAC ───────────────────────────────────
def _governance(snap: dict) -> list:
    out = []
    running = {p["metadata"].get("namespace") for p in _items(snap.get("pods"))}
    netpol_ns = {n["metadata"].get("namespace") for n in _items(snap.get("netpols"))}

    for ns in _items(snap.get("namespaces")):
        name = ns["metadata"].get("name", "")
        labels = ns["metadata"].get("labels", {}) or {}
        enforce = labels.get("pod-security.kubernetes.io/enforce")
        if name in SYSTEM_NS:
            continue
        if not enforce:
            out.append(_f("namespace: no Pod Security level", "MEDIUM", name,
                          "no pod-security.kubernetes.io/enforce label, so "
                          "anything may be admitted here",
                          "label the namespace baseline or restricted", name))
        elif enforce == "privileged":
            out.append(_f("namespace: Pod Security privileged", "HIGH", name,
                          "enforce=privileged admits any pod",
                          "move to baseline, then restricted", name))
        if name in running and name not in netpol_ns:
            out.append(_f("namespace: no NetworkPolicy", "MEDIUM", name,
                          "runs workloads and has no NetworkPolicy, so all "
                          "pod-to-pod traffic is allowed",
                          "add a default-deny ingress policy and open what is "
                          "needed", name))

    # RBAC: who can do everything, and who can read every Secret
    for b in _items(snap.get("clusterrolebindings")):
        role = (b.get("roleRef") or {}).get("name", "")
        if role != "cluster-admin":
            continue
        subjects = [f'{s.get("kind","")}/{s.get("name","")}'
                    for s in b.get("subjects") or []]
        builtin = b["metadata"].get("name") == "cluster-admin" and any(
            s.get("name") == "system:masters" for s in b.get("subjects") or [])
        if builtin or not subjects:
            continue
        out.append(_f("rbac: cluster-admin granted", "HIGH",
                      b["metadata"].get("name", ""),
                      "binds cluster-admin to " + ", ".join(subjects[:4]),
                      "grant a narrower role, or bind it per namespace"))

    for r in _items(snap.get("clusterroles")):
        name = r["metadata"].get("name", "")
        if name.startswith("system:") or name in ("cluster-admin", "admin",
                                                  "edit", "view"):
            continue
        for rule in r.get("rules") or []:
            verbs = [str(v) for v in (rule.get("verbs") or [])]
            res = [str(x) for x in (rule.get("resources") or [])]
            if "*" in verbs and "*" in res:
                out.append(_f("rbac: wildcard cluster role", "HIGH", name,
                              "grants every verb on every resource",
                              "list the verbs and resources it actually needs"))
                break
            if "secrets" in res and ({"get", "list"} & set(verbs) or "*" in verbs):
                out.append(_f("rbac: reads every Secret", "MEDIUM", name,
                              "can read Secrets across the cluster",
                              "scope it to a namespace with a Role, or to named "
                              "secrets with resourceNames"))
                break
            if {"escalate", "bind", "impersonate"} & set(verbs):
                out.append(_f("rbac: escalation verbs", "HIGH", name,
                              f"grants {', '.join(sorted({'escalate','bind','impersonate'} & set(verbs)))}",
                              "remove these unless the role is a controller that "
                              "provably needs them"))
                break

    for s in _items(snap.get("services")):
        spec, meta = s.get("spec", {}), s["metadata"]
        if spec.get("type") == "LoadBalancer":
            ing = (s.get("status", {}).get("loadBalancer") or {}).get("ingress") or []
            addr = ", ".join(i.get("ip") or i.get("hostname", "") for i in ing)
            out.append(_f("service: exposed by load balancer", "LOW",
                          f'{meta.get("namespace")}/{meta.get("name")}',
                          f"reachable at {addr or 'a pending address'}",
                          "confirm this is meant to be reachable, and that the "
                          "load balancer is on an internal network",
                          meta.get("namespace", "")))
        elif spec.get("type") == "NodePort":
            ports = ",".join(str(p.get("nodePort")) for p in spec.get("ports") or []
                             if p.get("nodePort"))
            out.append(_f("service: node port", "MEDIUM",
                          f'{meta.get("namespace")}/{meta.get("name")}',
                          f"open on every node at {ports}",
                          "prefer an ingress or an internal load balancer",
                          meta.get("namespace", "")))
    return out


# ── what this method cannot answer ─────────────────────────────
NOT_VISIBLE = [
    ("file permissions on the control-plane manifests and keys",
     "CIS 1.1.x — ownership and mode of /etc/kubernetes/**",
     "read them on the node, or run kube-bench there"),
    ("kubelet and proxy file permissions",
     "CIS 4.1.x — mode of the kubelet config and kubeconfig files",
     "read them on the node"),
    ("the content of the audit policy",
     "the API exposes that a policy file is set, not what is in it",
     "review the file, or template it from git"),
    ("etcd data-directory permissions and on-disk encryption at rest",
     "invisible without access to the machine",
     "check on the node; the audit does verify that an encryption provider is "
     "configured"),
]


CHECKS = (
    ("Control plane", _control_plane),
    ("Kubelets", _kubelets),
    ("Workloads", _workloads),
    ("Governance", _governance),
)


def report(cluster: dict) -> dict:
    """Audit this cluster through its API alone."""
    snap = snapshot(cluster)
    if snap.get("error"):
        return {"error": snap["error"], "findings": [], "totals": {}}

    findings, groups = [], {}
    for label, fn in CHECKS:
        try:
            got = fn(snap) or []
        except Exception as e:                                # noqa: BLE001
            got = [_f(f"{label}: check failed", "INFO", label,
                      f"{type(e).__name__}: {e}",
                      "this is a bug in the audit, not a finding about the "
                      "cluster", visible=False)]
        for f in got:
            f["group"] = label
        groups[label] = len(got)
        findings += got

    for f in findings:
        f["source"] = source_of(f["check"])
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["group"],
                                 f["object"]))
    totals = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    by_ns: dict = {}
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM") and f["namespace"]:
            by_ns[f["namespace"]] = by_ns.get(f["namespace"], 0) + 1
    return {
        "error": "", "findings": findings, "totals": totals,
        "total": len(findings), "groups": groups,
        "worst_namespaces": sorted(by_ns.items(), key=lambda kv: -kv[1])[:8],
        "not_visible": NOT_VISIBLE,
        "commands": COMMANDS,
        "counted": {
            "nodes": len(_items(snap.get("nodes"))),
            "pods": len(_items(snap.get("pods"))),
            "namespaces": len(_items(snap.get("namespaces"))),
            "kubelets_read": sum(1 for v in (snap.get("kubelets") or {}).values() if v),
        },
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def rows(rep: dict) -> tuple[list, list]:
    """Flat rows for a report. The source columns are included on purpose: a
    finding you cannot trace is a finding somebody will argue with."""
    header = ["group", "check", "severity", "object", "namespace", "evidence",
              "remediation", "read from", "field"]
    out = [[f["group"], f["check"], f["severity"], f["object"], f["namespace"],
            f["evidence"], f["remediation"],
            f.get("source", {}).get("command", ""),
            f.get("source", {}).get("field", "")]
           for f in rep.get("findings") or []]
    return header, out


# ── reports out ────────────────────────────────────────────────
def as_csv(header: list, rows: list) -> str:
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def as_html(title: str, subtitle: str, summary: list, header: list,
            rows: list) -> str:
    """A self-contained report page.

    Styling is inlined rather than linked: this file gets emailed and attached to
    tickets, and a report that only renders inside the portal is not a report.
    """
    def esc(v):
        return html.escape(str(v if v is not None else ""))

    sev_class = {"CRITICAL": "c", "HIGH": "h", "MEDIUM": "m", "LOW": "l",
                 "FAIL": "c", "WARN": "m", "INFO": "l", "PASS": "p"}
    tiles = "".join(
        f'<div class="tile"><div class="n {sev_class.get(str(k).upper(), "")}">'
        f'{esc(v)}</div><div class="l">{esc(k)}</div></div>' for k, v in summary)
    head = "".join(f"<th>{esc(h)}</th>" for h in header)
    body = []
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            cls = sev_class.get(str(v).upper(), "") if header[i] in (
                "severity", "state") else ""
            cells.append(f'<td class="{cls}">{esc(v)}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(title)}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        margin:0; padding:32px; background:#fff; color:#111; }}
 h1 {{ font-size:22px; margin:0 0 4px; }}
 .sub {{ color:#666; margin:0 0 22px; font-size:13px; }}
 .tiles {{ display:flex; gap:12px; flex-wrap:wrap; margin:0 0 24px; }}
 .tile {{ border:1px solid #e3e3e3; border-radius:10px; padding:12px 18px;
         min-width:104px; }}
 .tile .n {{ font-size:24px; font-weight:700; }}
 .tile .l {{ font-size:11px; text-transform:uppercase; letter-spacing:.06em;
            color:#666; }}
 table {{ border-collapse:collapse; width:100%; font-size:12.5px; }}
 th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid #ececec;
         vertical-align:top; }}
 th {{ background:#fafafa; font-size:11px; text-transform:uppercase;
      letter-spacing:.05em; color:#555; position:sticky; top:0; }}
 td.c {{ color:#b00020; font-weight:600; }}
 td.h {{ color:#c1531b; font-weight:600; }}
 td.m {{ color:#8a6d00; }}
 td.l {{ color:#3a6ea5; }}
 td.p {{ color:#137333; }}
 .n.c {{ color:#b00020; }} .n.h {{ color:#c1531b; }} .n.m {{ color:#8a6d00; }}
 .n.l {{ color:#3a6ea5; }} .n.p {{ color:#137333; }}
 footer {{ margin-top:26px; color:#888; font-size:11.5px; }}
 @media print {{ body {{ padding:0; }} th {{ position:static; }} }}
</style></head><body>
<h1>{esc(title)}</h1>
<p class="sub">{esc(subtitle)}</p>
<div class="tiles">{tiles}</div>
<table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>
<footer>{len(rows)} row(s). Read through the Kubernetes API by the config
portal — no scanner was installed in the cluster. Each row names the read and the
field it came from, so any finding can be checked by hand.</footer>
</body></html>"""
