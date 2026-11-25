"""One cluster as a scene: everything the 3D view draws, in one compact answer.

WHY THIS IS NOT THE CLUSTER PAGE'S `pods` PART
    That part feeds a table: a name, a phase, a restart count. A picture of the
    cluster needs three things the table never did: what each pod is ALLOWED
    (its requests and limits), what it is CONNECTED to, and what it IS (a
    database, a broker, somebody's own service). All three come out of the same
    `pods -A` document, so it is read once here and reduced on the spot. The
    whole object is never cached: a cluster's pod list is megabytes, the scene
    of it is a few hundred bytes a pod.

WHAT A "CONNECTION" IS, AND WHICH ONES ARE FACTS
    Three are stated by the cluster and are simply true:
      * a Service's selector matches a pod's labels;
      * a route (Ingress, or Traefik's IngressRoute) names a Service;
      * a pod mounts a PersistentVolumeClaim.
    The fourth is INFERRED: a workload whose configuration names a Service.
    Kubernetes does not record who calls whom, so `_links` reads the plain
    values a pod is configured with (its env, its arguments, the ConfigMaps it
    loads) and looks for a Service's DNS name in them. It is a NAME match, the
    scene says so wherever it draws one, and it can miss: a host kept in a
    Secret is never read, and a name built at run time is invisible.

NOTHING A POD IS CONFIGURED WITH LEAVES THIS MODULE
    A plain env value is where a password ends up when somebody did not use a
    Secret. The scan looks at values and hands back only WHERE a name was found
    (the variable's name, or the ConfigMap's key), never the value itself.
"""
import re
import time
from datetime import datetime

from . import cluster as clusterview
from .fleet import _cpu_to_milli, _mem_to_mib, _pmap
from .topology import _is_system_ns

# A cluster this size still opens; past it the picture is a fog and the
# browser is drawing a frame every 16ms. The unhealthy pods sort first, so a
# cut never hides the ones somebody came to see, and the scene says it was cut.
MAX_PODS = 2500
# One ConfigMap larger than this is a dashboard, a CA bundle or a script, not a
# list of hosts, and reading megabytes of it buys nothing.
MAX_CONFIG_BYTES = 262144

# What a pod IS, from its image and its workload's name: (key, label, glyph,
# family, needles). The order matters: the first match wins, so the specific
# names come before the general ones (an ingress controller built on nginx is
# an ingress controller). A needle matches a whole word of the name, never a
# run of letters inside one: `nats` must not claim `donations-api`.
TECH = [
    ("kafka", "Kafka", "📨", "queue", ("kafka", "redpanda", "strimzi")),
    ("zookeeper", "ZooKeeper", "🦓", "queue", ("zookeeper",)),
    ("rabbitmq", "RabbitMQ", "🐇", "queue", ("rabbitmq",)),
    ("nats", "NATS", "✉️", "queue", ("nats", "pulsar", "activemq")),
    ("temporal", "Temporal", "⏱️", "workflow", ("temporal", "temporalio")),
    ("postgres", "PostgreSQL", "🐘", "db",
     ("postgres", "postgresql", "cloudnative-pg", "cnpg", "pgbouncer",
      "pgpool", "timescaledb", "spilo", "patroni")),
    ("mysql", "MySQL", "🐬", "db", ("mysql", "mariadb", "percona")),
    ("mongodb", "MongoDB", "🍃", "db", ("mongo", "mongodb")),
    ("couchbase", "Couchbase", "🛋️", "db", ("couchbase",)),
    ("cassandra", "Cassandra", "👁️", "db", ("cassandra", "scylla")),
    ("clickhouse", "ClickHouse", "🏠", "db", ("clickhouse",)),
    ("database", "Database", "🛢️", "db",
     ("mssql", "oracle", "cockroach", "cockroachdb", "influxdb", "db2")),
    ("etcd", "etcd", "🗝️", "db", ("etcd",)),
    ("redis", "Redis", "⚡", "cache",
     ("redis", "valkey", "keydb", "dragonfly", "memcached")),
    ("search", "Search", "🔎", "db", ("elasticsearch", "opensearch", "solr")),
    ("minio", "Object storage", "🪣", "storage", ("minio", "seaweedfs")),
    ("storage", "Storage", "💽", "storage",
     ("longhorn", "rook", "ceph", "cephcsi", "openebs", "csi", "nfs",
      "local-path-provisioner", "provisioner", "velero")),
    ("vault", "Vault", "🔐", "security", ("vault", "openbao")),
    ("identity", "Identity", "🔑", "security",
     ("keycloak", "dex", "oauth2-proxy", "authentik")),
    ("certs", "Certificates", "📜", "security",
     ("cert-manager", "sealed-secrets", "external-secrets")),
    ("metrics", "Metrics", "🔥", "observability",
     ("prometheus", "alertmanager", "thanos", "victoria-metrics",
      "metrics-server", "kube-state-metrics", "node-exporter")),
    ("dashboards", "Dashboards", "📊", "observability",
     ("grafana", "kibana")),
    ("logs", "Log shipping", "🪵", "observability",
     ("fluentd", "fluent-bit", "fluentbit", "filebeat", "logstash",
      "promtail", "loki", "vector")),
    ("tracing", "Tracing", "🔭", "observability",
     ("jaeger", "tempo", "otel", "opentelemetry-collector")),
    ("ingress", "Ingress controller", "🚦", "network",
     ("ingress-nginx", "nginx-ingress", "ingress", "traefik", "haproxy",
      "envoy", "istio", "istiod", "kong", "contour")),
    ("dns", "DNS", "🧭", "system", ("coredns", "kube-dns", "node-local-dns")),
    ("network", "Cluster network", "🕸️", "system",
     ("flannel", "calico", "cilium", "kube-proxy", "weave", "kube-router",
      "metallb", "kube-vip")),
    ("controlplane", "Control plane", "🧠", "system",
     ("kube-apiserver", "kube-controller-manager", "kube-scheduler")),
    ("gitops", "GitOps", "🐙", "delivery",
     ("argocd", "argo-cd", "argoproj", "flux", "fluxcd")),
    ("delivery", "Build and delivery", "🏗️", "delivery",
     ("jenkins", "gitlab-runner", "harbor", "nexus", "sonarqube", "tekton")),
]
_TECH_RE = [(key, re.compile(
    r"(?:^|[^a-z0-9])(?:" + "|".join(re.escape(n) for n in needles)
    + r")(?:[^a-z]|$)")) for key, _l, _g, _f, needles in TECH]
TECH_FACTS = {key: {"label": label, "glyph": glyph, "family": family}
              for key, label, glyph, family, _n in TECH}

# The faces. `tone` is the colour a face is lit with and what the totals count;
# `mood` is the expression. They are separate because two moods share a tone:
# a pod that cannot be scheduled and one that is not ready are both amber, and
# they are not the same picture.
MOODS = {
    "happy": "ok", "hot": "warn", "worried": "warn", "sleeping": "warn",
    "hatching": "info", "leaving": "info", "crying": "bad", "dizzy": "bad",
    "done": "idle",
}
# A healthy pod using this much of a limit it was given is about to be
# throttled (cpu) or killed (memory), and that is worth a different face.
HOT = 0.9


def tech_of(images: list, *names: str) -> str:
    """Which known piece of infrastructure this is, or "" for somebody's own
    service. The image says it best: a workload called `orders-db` is
    PostgreSQL because it runs `postgres:16`, not because of its name."""
    paths = []
    for image in images or []:
        # The repository without registry, digest or tag. The registry has to
        # go: a private one is very often `harbor.<somebody>` or `nexus.…`,
        # and every image pulled through it would read as Harbor.
        segs = (image or "").split("@", 1)[0].lower().split("/")
        if len(segs) > 1 and ("." in segs[0] or ":" in segs[0]
                              or segs[0] == "localhost"):
            segs = segs[1:]
        segs[-1] = segs[-1].split(":", 1)[0]
        paths.append(segs)
    # The image's own name first, then the workload's, and the organisation it
    # is published under last: `grafana/promtail` ships logs, and read whole it
    # is claimed by the first word in it.
    seen = ([segs[-1] for segs in paths] + [(n or "").lower() for n in names]
            + ["/".join(segs) for segs in paths])
    for text in seen:
        if not text:
            continue
        for key, rx in _TECH_RE:
            if rx.search(text):
                return key
    return ""


def _resources(spec: dict) -> dict:
    """What the pod asked for and what it may not exceed, summed over its
    containers. A figure no container declares is None, never 0: "no limit" is
    a real and different answer from "a limit of nothing"."""
    total = {"cpu_req": 0.0, "cpu_lim": 0.0, "mem_req": 0.0, "mem_lim": 0.0}
    seen = dict.fromkeys(total, 0)
    cons = spec.get("containers") or []
    for c in cons:
        res = c.get("resources") or {}
        req, lim = res.get("requests") or {}, res.get("limits") or {}
        for key, src, conv in (("cpu_req", req.get("cpu"), _cpu_to_milli),
                               ("cpu_lim", lim.get("cpu"), _cpu_to_milli),
                               ("mem_req", req.get("memory"), _mem_to_mib),
                               ("mem_lim", lim.get("memory"), _mem_to_mib)):
            if src:
                total[key] += conv(src)
                seen[key] += 1
    out = {k: (round(v) if seen[k] else None) for k, v in total.items()}
    # A limit that only some containers carry does not bound the pod: the
    # sidecar without one can still take the node's memory.
    out["lim_partial"] = bool(cons) and any(
        0 < seen[k] < len(cons) for k in ("cpu_lim", "mem_lim"))
    return out


# A crash loop, read between two crashes. For the minute a crash-looping
# container is up, everything the cluster says about its pod is good news:
# Running, ready 1/1, no waiting reason. `_pod_problem` reports those words
# faithfully, so the pod read "healthy" with tens of thousands of restarts
# behind it, and a view whose goal is "every pod healthy" could be won by
# looking at the right second.
#
# The kubelet forgets a container's back-off once it has run ten minutes without
# falling over. So "its last run ended inside that window, lasted less than that
# window, and was not one of its first" is the kubelet's own definition of a
# loop, applied to the run before this one. A pod that ran for a month and was
# killed for memory five minutes ago is NOT one: its last run was long.
CRASH_WINDOW = 600
CRASH_MIN = 3
CRASH_LOOP = "Crash loop"


def _ts(stamp) -> float | None:
    try:
        return datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _last_exit(pod: dict, now: float) -> dict | None:
    """How the most recent run of this pod's most-restarted container ended:
    the reason and exit code the kubelet kept, how long ago, and how long that
    run lasted. None when nothing has ever ended. It is what a pod can honestly
    say about why it is not running, before anybody reads its log."""
    st = pod.get("status") or {}
    best = None
    for c in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
        t = (c.get("lastState") or {}).get("terminated") or {}
        end = _ts(t.get("finishedAt"))
        if end is None:
            continue
        begin = _ts(t.get("startedAt"))
        row = {"container": c.get("name", ""), "reason": t.get("reason") or "",
               "code": t.get("exitCode"), "ago": max(0, int(now - end)),
               "ran": max(0, int(end - begin)) if begin is not None else None,
               "restarts": c.get("restartCount", 0)}
        if best is None or row["restarts"] > best["restarts"]:
            best = row
    return best


def _crashing(last: dict | None) -> bool:
    return bool(last and last["restarts"] >= CRASH_MIN
                and last["ago"] < CRASH_WINDOW
                and last["ran"] is not None and last["ran"] < CRASH_WINDOW)


def _mood(pod: dict, problem: str, hot: bool) -> str:
    st = pod.get("status") or {}
    if problem == "Terminating":
        return "leaving"
    if st.get("phase") == "Succeeded":
        return "done"
    if not problem:
        return "hot" if hot else "happy"
    if problem == "Pending":
        # Scheduled and not running yet: its containers are being created. A
        # pod that is NOT scheduled says so in `problem` (Unschedulable).
        return "hatching"
    if problem in ("Unschedulable", "SchedulingGated"):
        return "sleeping"
    if problem == "NotReady":
        return "worried"
    if problem in ("CrashLoopBackOff", CRASH_LOOP):
        return "dizzy"
    return "crying"


def _owner_kind(owners: list, workload: str) -> str:
    """What kind of thing the workload is, as a person names it. A Deployment's
    pods are owned by a ReplicaSet, and `_workload_of` has already looked
    through that to the Deployment's name: the kind has to follow, or the card
    reads "ReplicaSet payments-api", an object that does not exist."""
    ref = next((o for o in owners if o.get("name")), None)
    if not ref:
        return ""
    kind = ref.get("kind") or ""
    return "Deployment" if kind == "ReplicaSet" and ref["name"] != workload else kind


# Who put a workload there, read off the workload itself. A pod asked "who
# manages you" must answer from a mark somebody's tool left, never from a guess:
# "GitOps" said of a thing applied by hand is the one wrong answer that sends a
# person to edit Git and wonder why nothing changes.
_OWN_KINDS = ("ReplicaSet", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")


def _managed_by(meta: dict, argo_apps: set = frozenset()) -> dict:
    """{by, tool, detail}: `by` is gitops, helm, operator, direct, node or
    unknown. Only the PRESENCE of an annotation is read. kubectl's
    last-applied annotation holds the whole manifest, env values and all, and
    none of it leaves this function."""
    lab, ann = meta.get("labels") or {}, meta.get("annotations") or {}
    track = ann.get("argocd.argoproj.io/tracking-id") or ""
    if track or lab.get("argocd.argoproj.io/instance"):
        return {"by": "gitops", "tool": "Argo CD",
                "detail": track.split(":", 1)[0] or lab.get("argocd.argoproj.io/instance", "")}
    for key in ("kustomize.toolkit.fluxcd.io/name", "helm.toolkit.fluxcd.io/name"):
        if lab.get(key):
            return {"by": "gitops", "tool": "Flux", "detail": lab[key]}
    # Argo CD's older default marks a thing with the SAME label every Helm
    # chart sets, so the label alone proves nothing: it counts only when an
    # Application of that name exists on this cluster.
    inst = lab.get("app.kubernetes.io/instance") or ""
    if inst and inst in argo_apps:
        return {"by": "gitops", "tool": "Argo CD", "detail": inst}
    owner = next((o for o in meta.get("ownerReferences") or []
                  if o.get("controller")), None)
    if owner and owner.get("kind") == "Node":
        return {"by": "node", "tool": "the machine itself", "detail": owner.get("name", "")}
    if owner and owner.get("kind") not in _OWN_KINDS:
        return {"by": "operator", "tool": owner.get("kind", ""), "detail": owner.get("name", "")}
    if lab.get("app.kubernetes.io/managed-by") == "Helm" or ann.get("meta.helm.sh/release-name"):
        return {"by": "helm", "tool": "Helm", "detail": ann.get("meta.helm.sh/release-name", "")}
    if "kubectl.kubernetes.io/last-applied-configuration" in ann:
        return {"by": "direct", "tool": "kubectl apply", "detail": ""}
    return {"by": "unknown", "tool": "", "detail": ""}


def _managers(cluster: dict) -> dict:
    """{"<namespace>/<workload>": verdict} for everything that owns pods."""
    doc = clusterview._get(cluster, "deployments,statefulsets,daemonsets,cronjobs,jobs", "-A")
    apps = {a.get("name", "") for a in
            (clusterview.part(cluster, "argocd") or {}).get("apps") or []}
    out, cron = {}, {}
    for w in clusterview._items(doc):
        meta = w.get("metadata") or {}
        key = f'{meta.get("namespace", "")}/{meta.get("name", "")}'
        out[key] = _managed_by(meta, apps)
        if w.get("kind") == "CronJob":
            cron[key] = out[key]
    # a Job a CronJob made is managed by whoever manages the CronJob
    for w in clusterview._items(doc):
        meta = w.get("metadata") or {}
        boss = next((o for o in meta.get("ownerReferences") or []
                     if o.get("kind") == "CronJob"), None)
        got = boss and cron.get(f'{meta.get("namespace", "")}/{boss.get("name", "")}')
        if got:
            out[f'{meta.get("namespace", "")}/{meta.get("name", "")}'] = got
    return out


def _config_refs(spec: dict) -> tuple[set, set]:
    """(ConfigMaps this pod loads, claims it mounts), by name."""
    maps, claims = set(), set()
    for v in spec.get("volumes") or []:
        if (v.get("configMap") or {}).get("name"):
            maps.add(v["configMap"]["name"])
        if (v.get("persistentVolumeClaim") or {}).get("claimName"):
            claims.add(v["persistentVolumeClaim"]["claimName"])
        for src in (v.get("projected") or {}).get("sources") or []:
            if (src.get("configMap") or {}).get("name"):
                maps.add(src["configMap"]["name"])
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        for ef in c.get("envFrom") or []:
            if (ef.get("configMapRef") or {}).get("name"):
                maps.add(ef["configMapRef"]["name"])
        for e in c.get("env") or []:
            ref = ((e.get("valueFrom") or {}).get("configMapKeyRef") or {})
            if ref.get("name"):
                maps.add(ref["name"])
    return maps, claims


def _plain_config(spec: dict) -> list:
    """[(where, text)] for every plain value the pod spec itself carries."""
    out = []
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        for e in c.get("env") or []:
            if e.get("value"):
                out.append((e.get("name") or "env", str(e["value"])))
        for word in (c.get("args") or []) + (c.get("command") or []):
            out.append(("its start command", str(word)))
    return out


_HOSTISH = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")


def _named_service(token: str, own_ns: str, by_ns: dict):
    """The Service a host name in a config value refers to, or None.

    Only the names Kubernetes DNS serves are recognised:
    `svc`, `svc.ns`, `svc.ns.svc[.<domain>]`, and a StatefulSet pod's own
    `pod.svc.ns.svc[.<domain>]`. A bare `svc` resolves only inside the
    namespace of the pod asking, exactly as it does through that pod's search
    list, so it is looked up there and nowhere else.
    """
    parts = token.strip(".").split(".")
    if len(parts) == 1:
        return by_ns.get(own_ns, {}).get(parts[0])
    if len(parts) >= 3 and parts[2] == "svc":
        return by_ns.get(parts[1], {}).get(parts[0])
    if len(parts) >= 4 and parts[3] == "svc":
        return by_ns.get(parts[2], {}).get(parts[1])
    if len(parts) == 2:
        return by_ns.get(parts[1], {}).get(parts[0])
    return None


def _links(sources: dict, services: list, config_doc) -> list:
    """Which workload's configuration names which Service.

    `sources` is {workload id: {"ns", "plain": [(where, text)], "maps": {names}}}.
    One link per (workload, service), carrying the first place the name was
    found so the scene can say why it drew the line.
    """
    by_ns: dict = {}
    for s in services:
        by_ns.setdefault(s["ns"], {})[s["name"]] = s["id"]
    data: dict = {}
    for cm in clusterview._items(config_doc):
        meta = cm.get("metadata") or {}
        body = cm.get("data") or {}
        if sum(len(str(v)) for v in body.values()) > MAX_CONFIG_BYTES:
            continue
        data[(meta.get("namespace", ""), meta.get("name", ""))] = body
    out = []
    for wid, src in sources.items():
        found: dict = {}
        texts = list(src["plain"])
        for name in sorted(src["maps"]):
            for key, value in (data.get((src["ns"], name)) or {}).items():
                texts.append((f"ConfigMap {name} / {key}", str(value)))
        for where, text in texts:
            for token in set(_HOSTISH.findall(text.lower())):
                sid = _named_service(token, src["ns"], by_ns)
                if sid and sid not in found:
                    found[sid] = where
        out += [{"from": wid, "to": sid, "via": where[:80]}
                for sid, where in sorted(found.items())]
    return out


def _part_scene(cluster: dict) -> dict:
    pods_doc, metrics = _pmap(lambda f: f(), [
        lambda: clusterview._get(cluster, "pods", "-A"),
        lambda: clusterview._raw(cluster, "/apis/metrics.k8s.io/v1beta1/pods"),
    ], workers=2)
    if pods_doc is None:
        # "Could not ask" must never draw as an empty, and therefore healthy,
        # cluster. The page shows this in words over an empty stage.
        return {"error": "unreachable", "pods": [], "nodes": [], "services": [],
                "routes": [], "claims": [], "links": [], "namespaces": [],
                "techs": {}, "totals": {}}
    nodes_part, storage, network = _pmap(
        lambda n: clusterview.part(cluster, n), ["nodes", "storage", "network"],
        workers=3)
    cid = cluster.get("id") or cluster.get("context", "")
    managers = clusterview._cached(cid, "scenemgr", False, lambda: _managers(cluster))
    use = {}
    for m in clusterview._items(metrics):
        meta = m.get("metadata") or {}
        cons = m.get("containers") or []
        use[(meta.get("namespace"), meta.get("name"))] = (
            sum(_cpu_to_milli((c.get("usage") or {}).get("cpu")) for c in cons),
            sum(_mem_to_mib((c.get("usage") or {}).get("memory")) for c in cons))

    pods, labels, sources, mounts, now = [], {}, {}, {}, time.time()
    for p in clusterview._items(pods_doc):
        meta, st, spec = p["metadata"], p.get("status") or {}, p.get("spec") or {}
        ns, name = meta["namespace"], meta["name"]
        pid = f"{ns}/{name}"
        cs = st.get("containerStatuses") or []
        problem = clusterview._pod_problem(p)
        last = _last_exit(p, now)
        # only where the cluster's own words found nothing wrong (or only "not
        # ready"): a pod that already names its problem keeps that name
        if problem in ("", "NotReady") and _crashing(last):
            problem = CRASH_LOOP
        res = _resources(spec)
        cpu, mem = use.get((ns, name), (None, None))
        hot = bool((cpu and res["cpu_lim"] and cpu >= HOT * res["cpu_lim"])
                   or (mem and res["mem_lim"] and mem >= HOT * res["mem_lim"]))
        mood = _mood(p, problem, hot)
        images = sorted({c.get("image") or "" for c in spec.get("containers") or []})
        workload = clusterview._workload_of(meta.get("ownerReferences") or [])
        wid = f"{ns}/{workload or name}"
        pods.append({
            "id": pid, "ns": ns, "name": name, "node": spec.get("nodeName", ""),
            "phase": st.get("phase", "Unknown"), "problem": problem,
            "mood": mood, "tone": MOODS[mood],
            "ready": f"{sum(1 for c in cs if c.get('ready'))}/{len(cs)}",
            "restarts": sum(c.get("restartCount", 0) for c in cs),
            "age": clusterview._age(meta.get("creationTimestamp", "")),
            "workload": workload, "wl": wid,
            "kind": _owner_kind(meta.get("ownerReferences") or [], workload),
            "images": [i.split("/")[-1] for i in images],
            "tech": tech_of(images, workload or name),
            "cpu": round(cpu) if cpu is not None else None,
            "mem": round(mem) if mem is not None else None,
            "qos": st.get("qosClass", ""), "ip": st.get("podIP", ""),
            # the workload's own verdict, or the pod's when nothing owns it
            "mgr": (managers.get(wid) if workload else None) or _managed_by(meta),
            "last_exit": last and {k: last[k] for k in ("reason", "code", "ago", "ran")},
            **res,
        })
        labels[pid] = (ns, meta.get("labels") or {})
        maps, claims = _config_refs(spec)
        for claim in claims:
            mounts.setdefault(f"{ns}/{claim}", []).append(pid)
        src = sources.setdefault(wid, {"ns": ns, "plain": [], "maps": set()})
        # every replica carries the same configuration; reading one is enough
        if not src["plain"]:
            src["plain"] = _plain_config(spec)
        src["maps"] |= maps

    # worst first, so a cut keeps what somebody came to look at
    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3, "idle": 4}
    pods.sort(key=lambda p: (order[p["tone"]], p["ns"], p["name"]))
    truncated = max(0, len(pods) - MAX_PODS)
    pods = pods[:MAX_PODS]
    kept = {p["id"] for p in pods}

    services = []
    for s in (network or {}).get("services") or []:
        sel = s.get("selector") or {}
        backs = [pid for pid, (ns, lab) in labels.items()
                 if pid in kept and sel and ns == s["namespace"]
                 and all(lab.get(k) == v for k, v in sel.items())]
        services.append({
            "id": f'{s["namespace"]}/{s["name"]}', "ns": s["namespace"],
            "name": s["name"], "type": s.get("type", ""),
            "ports": s.get("ports") or [], "published": bool(s.get("published")),
            "external": s.get("external") or [], "pods": sorted(backs),
            # with no pods: "selects, and found none" is broken, while
            # "selects nothing" is a Service pointing outside the cluster
            "selects": bool(sel),
        })
    known = {s["id"] for s in services}

    routes = []
    for r in (network or {}).get("routes") or []:
        # a route's backend is `name` or `name:port`, in the route's namespace
        backs = sorted({f'{r["namespace"]}/{b.split(":", 1)[0]}'
                        for b in r.get("services") or []})
        routes.append({
            "id": f'{r["namespace"]}/{r["kind"]}/{r["name"]}',
            "ns": r["namespace"], "name": r["name"], "kind": r.get("kind", ""),
            "hosts": r.get("hosts") or [], "tls": bool(r.get("tls")),
            "services": [b for b in backs if b in known],
        })

    claims = [{
        "id": f'{c["namespace"]}/{c["name"]}', "ns": c["namespace"],
        "name": c["name"], "status": c.get("status", ""),
        "bound": bool(c.get("bound")), "size": c.get("size", ""),
        "sc": c.get("sc", ""),
        "pods": sorted(pid for pid in mounts.get(
            f'{c["namespace"]}/{c["name"]}', []) if pid in kept),
    } for c in (storage or {}).get("claims") or []]

    # The inferred links change when configuration does, not when a pod
    # restarts, and finding them costs a read of every ConfigMap: they keep
    # their own, longer lifetime (cluster.PART_TTL) instead of the scene's.
    links = clusterview._cached(cid, "scenelinks", False, lambda: _links(
        sources, services, clusterview._get(cluster, "configmaps", "-A")))
    owners = {}
    for p in pods:
        owners.setdefault(p["wl"], set()).add(p["id"])
    backing = {s["id"]: set(s["pods"]) for s in services}
    # A workload naming its own Service is not a connection worth a line.
    links = [l for l in links if l["from"] in owners and l["to"] in backing
             and not (backing[l["to"]] and backing[l["to"]] <= owners[l["from"]])]

    per_node, spaces = {}, {}
    for p in pods:
        per_node[p["node"]] = per_node.get(p["node"], 0) + 1
        row = spaces.setdefault(p["ns"], {"name": p["ns"], "pods": 0, "bad": 0,
                                          "system": _is_system_ns(p["ns"])})
        row["pods"] += 1
        row["bad"] += p["tone"] == "bad"
    nodes = [{
        "name": n["name"], "ready": n["ready"], "roles": n["roles"],
        "schedulable": n["schedulable"], "pressure": n["pressure"],
        "version": n["version"], "ip": n["ip"], "age": n["age"],
        "cpu_pct": n["cpu_pct"], "mem_pct": n["mem_pct"],
        "cpu_cap": round(n["cpu_cap"]), "mem_cap": round(n["mem_cap"]),
        "pods": per_node.get(n["name"], 0), "pods_cap": n["pods_cap"],
    } for n in (nodes_part or {}).get("nodes") or []]

    totals = {tone: sum(1 for p in pods if p["tone"] == tone)
              for tone in ("ok", "warn", "bad", "info", "idle")}
    totals.update(pods=len(pods), nodes=len(nodes),
                  nodes_ready=sum(1 for n in nodes if n["ready"]),
                  services=len(services), claims=len(claims),
                  routes=len(routes), links=len(links),
                  unlimited=sum(1 for p in pods if p["cpu_lim"] is None
                                and p["mem_lim"] is None
                                and p["tone"] != "idle"))
    used = {p["tech"] for p in pods if p["tech"]}
    return {
        "error": "", "at": int(time.time()), "truncated": truncated,
        "metrics": metrics is not None,
        "nodes": nodes, "pods": pods, "services": services, "routes": routes,
        "claims": claims, "links": links,
        "namespaces": sorted(spaces.values(),
                             key=lambda r: (r["system"], -r["pods"], r["name"])),
        "techs": {k: v for k, v in TECH_FACTS.items() if k in used},
        "totals": totals,
    }


def collect(cluster: dict, refresh: bool = False) -> dict:
    """The scene for one cluster, from the cluster page's own part cache."""
    cid = cluster.get("id") or cluster.get("context", "")
    return clusterview._cached(cid, "scene", refresh,
                               lambda: _part_scene(cluster))
