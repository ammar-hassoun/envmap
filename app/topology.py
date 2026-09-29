"""Build a live architecture picture of one environment from cluster + git config."""
import json
import re
import subprocess

from . import repo
from .kube import base_args

DATA_NS_HINTS = {
    "redis": "Redis", "minio": "MinIO", "elk": "Elasticsearch",
    "elasticsearch": "Elasticsearch", "kafka": "Kafka", "temporal": "Temporal",
    "postgres": "PostgreSQL", "postgresql": "PostgreSQL", "mongodb": "MongoDB",
    "harbor": "Harbor", "monitoring": "Prometheus/Grafana",
}
INTERNAL_SUFFIXES = (".svc.cluster.local", ".svc", ".local")

# Namespaces that are cluster plumbing, not the application: skipped so the
# drawing shows what the environment RUNS, not the CNI and the ingress controller.
# Everything else that the cluster runs is shown, even if the env's values files
# never declared its namespace — an undeclared workload is exactly the drift a
# picture should surface, not hide.
SYSTEM_NS = {
    "kube-system", "kube-public", "kube-node-lease", "kube-flannel",
    "cert-manager", "ingress-nginx", "traefik", "metallb-system",
    "local-path-storage", "longhorn-system", "kubernetes-dashboard",
    "calico-system", "calico-apiserver", "tigera-operator", "gatekeeper-system",
    "argocd", "flux-system", "sealed-secrets", "openebs", "rook-ceph", "velero",
}


def _is_system_ns(ns: str) -> bool:
    return ns in SYSTEM_NS or ns.startswith("kube-")


def _kubectl(cluster, *args):
    base = base_args(cluster)
    if not base:
        return None
    r = subprocess.run(base + list(args) + ["-o", "json", "--request-timeout=15s"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _is_internal(host: str) -> bool:
    return (host.endswith(INTERNAL_SUFFIXES)
            or host in ("localhost", "127.0.0.1")
            or re.fullmatch(r"10\.\d+\.\d+\.\d+", host) is not None
            or re.fullmatch(r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", host) is not None
            or re.fullmatch(r"192\.168\.\d+\.\d+", host) is not None)


def _classify(host: str, value: str) -> str:
    v = f"{host} {value}".lower()
    if any(k in v for k in ("postgres", "jdbc", "mysql", ":9032", ":5432")):
        return "database"
    if "redis" in v:
        return "cache"
    if any(k in v for k in ("kafka", ":9092")):
        return "queue"
    return "provider"


def collect(pid, rgid, env, cluster, namespaces) -> dict:
    ns_set = set(namespaces)
    out = {"cluster": cluster.get("name", ""), "namespaces": sorted(ns_set),
           "nodes": {"total": 0, "ready": 0, "cp": 0, "workers": 0},
           "vips": [], "ingress": [], "workloads": [], "data": [],
           "external": [], "error": None}

    nodes = _kubectl(cluster, "get", "nodes")
    if nodes is None:
        out["error"] = (f"cannot reach cluster '{cluster.get('name')}' — check its "
                        "kubeconfig and context in project settings")
        return out
    for n in nodes.get("items", []):
        labels = n["metadata"].get("labels", {})
        is_cp = any("control-plane" in k or "master" in k for k in labels)
        ready = any(c["type"] == "Ready" and c["status"] == "True"
                    for c in n.get("status", {}).get("conditions", []))
        out["nodes"]["total"] += 1
        out["nodes"]["ready"] += 1 if ready else 0
        out["nodes"]["cp" if is_cp else "workers"] += 1

    for s in (_kubectl(cluster, "get", "svc", "-A") or {}).get("items", []):
        if s["spec"].get("type") == "LoadBalancer":
            for ing in (s.get("status", {}).get("loadBalancer", {}).get("ingress") or []):
                if ing.get("ip"):
                    out["vips"].append({"name": s["metadata"]["name"],
                                        "namespace": s["metadata"]["namespace"],
                                        "ip": ing["ip"]})

    routes = _kubectl(cluster, "get", "ingressroute", "-A")
    if routes:
        seen = set()
        for ir in routes.get("items", []):
            for r in ir["spec"].get("routes", []):
                backends = [svc.get("name", "") for svc in r.get("services", [])
                            if svc.get("namespace", ir["metadata"]["namespace"]) in ns_set
                            or ir["metadata"]["namespace"] in ns_set]
                if not backends:
                    continue
                for host in re.findall(r"Host\(`([^`]+)`\)", r.get("match", "")):
                    key = (host, tuple(backends))
                    if key not in seen:
                        seen.add(key)
                        out["ingress"].append({"host": host, "backends": backends})

    for d in (_kubectl(cluster, "get", "deployments,statefulsets", "-A")
              or {}).get("items", []):
        ns = d["metadata"]["namespace"]
        desired = d["spec"].get("replicas", 0)
        ready = d.get("status", {}).get("readyReplicas", 0) or 0
        entry = {"name": d["metadata"]["name"], "namespace": ns,
                 "ready": ready, "desired": desired,
                 "healthy": desired == 0 or ready == desired, "kind": d["kind"]}
        if ns in ns_set:
            out["workloads"].append(entry)
            continue
        # not a declared namespace: a known data service → the Data lane; any
        # other real (non-system) workload → still a workload, marked undeclared
        # so the picture shows everything the cluster runs, not only what git named
        hinted = next((label for hint, label in DATA_NS_HINTS.items()
                       if ns == hint or ns.startswith(hint)), None)
        if hinted:
            entry["label"] = hinted
            out["data"].append(entry)
        elif not _is_system_ns(ns):
            entry["undeclared"] = True
            out["workloads"].append(entry)

    own_hosts = {i["host"] for i in out["ingress"]}
    ext: dict[str, dict] = {}
    for fname in repo.all_files(pid, rgid, env):
        try:
            data = repo.load_service(pid, rgid, env, fname)
        except Exception:
            continue
        for value in {**data["service_config"], **data["platform_config"]}.values():
            for m in re.finditer(
                    r"(?:https?://|jdbc:\w+://)([A-Za-z0-9_.\-]+)(:\d+)?", str(value)):
                host, port = m.group(1), (m.group(2) or "")
                if _is_internal(host) or host in own_hosts:
                    continue
                node = ext.setdefault(host + port, {
                    "host": host + port, "kind": _classify(host, str(value)),
                    "used_by": set()})
                node["used_by"].add(repo.display(pid, fname))
    out["external"] = sorted(
        ({**v, "used_by": sorted(v["used_by"])} for v in ext.values()),
        key=lambda x: (x["kind"], x["host"]))

    by_label: dict[str, dict] = {}
    for d in out["data"]:
        lbl = d.get("label", d["namespace"])
        cur = by_label.setdefault(lbl, {"label": lbl, "count": 0,
                                        "healthy": True, "namespaces": []})
        cur["count"] += 1
        cur["healthy"] = cur["healthy"] and d["healthy"]
        # kept so the diagram's box can open the pods behind it — a label like
        # "Temporal" is one namespace in practice, but grouping is by label and
        # nothing says it has to be
        if d["namespace"] not in cur["namespaces"]:
            cur["namespaces"].append(d["namespace"])
    out["data"] = sorted(by_label.values(), key=lambda x: x["label"])

    # problems first so a truncated column keeps what matters and the eye lands
    # on them: not-ready, then drift (in cluster, not in git), then declared —
    # each block grouped by namespace and name.
    out["workloads"].sort(key=lambda w: (w["healthy"], not w.get("undeclared"),
                                         w["namespace"], w["name"]))
    out["ingress"].sort(key=lambda i: i["host"])
    return out
