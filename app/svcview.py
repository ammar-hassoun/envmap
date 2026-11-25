"""One microservice, as the two places its configuration actually lives.

WHY THIS EXISTS
    The service page grew out of a values.yaml editor, so it was organised the
    way a YAML file is: a flat list of every key in the file, and a dropdown
    asking which section of the file a new key should go in. That asks the
    reader to hold the file's structure in their head in order to change a
    setting — and the file's structure is an implementation detail of a Helm
    chart, not a thing anybody came to the page to think about.

    What people actually hold in their head is: this service has a ConfigMap, a
    Secret, a Deployment, a Service and an Ingress; and each of those exists in
    two places that can disagree — the GitOps repository, which is the
    intention, and the cluster, which is the fact.

    So that is what this module builds: one service, two sides, six kinds. The
    YAML file is still the storage, but it stops being the organising idea.

THE TWO SIDES ARE NOT INTERCHANGEABLE
    Writing to the repository is a proposal: it lands in a working copy, gets
    committed, and takes effect when the controller syncs. Writing to the
    cluster is immediate and, on anything GitOps owns, temporary — the next sync
    puts it back. Both are legitimate; a probe timeout you need changed in the
    next ninety seconds is a cluster write, and the same change that should
    survive is a repository write.

    The page therefore never blurs them into one "save". Each side says plainly
    what it is, and the cluster side says when the repository will overrule it.

WHICH RESOURCES BELONG TO A SERVICE
    Kubernetes has no answer to this — there is no "service" object grouping a
    Deployment with its ConfigMap. So it is inferred, in falling order of
    confidence: names the values file itself declares, then the standard
    `app.kubernetes.io` labels, then a name match. What is left over is reported
    as unclaimed rather than hidden, because the failure mode of guessing is a
    resource nobody can find from the page that should own it.
"""
from __future__ import annotations

import re

from . import repo

# The kinds a service is made of, in the order somebody troubleshooting reads
# them: what it is running, how it is reached, what it is configured with.
#
# `live_edit` marks the two whose data a person may change on the cluster from
# here. It is not a permission — that is rbac and the cluster's own tick — it is
# a statement about which kinds have a key/value data section at all. Patching a
# Deployment's env from a key/value box would mean writing a JSON pointer into a
# container array, which is a different feature wearing this one's clothes.
KINDS = (
    # (key, label, icon). There was a fourth field saying whether the portal's
    # own key/value editor could write that kind live; that editor went with the
    # service page, and a flag nothing reads is a claim nobody checks.
    ("deployment",   "Deployment",   "layers"),
    ("service",      "Service",      "hexagon"),
    ("ingress",      "Ingress",      "globe"),
    ("configmap",    "ConfigMap",    "settings"),
    ("secret",       "Secret",       "key-round"),
    ("sealedsecret", "SealedSecret", "lock"),
    ("other",        "Chart values", "scroll-text"),
)

# The labels that say what a resource is part of.
#
# `app.kubernetes.io/instance` is the RELEASE — unique per deployed thing — and
# is the one that means ownership. `app.kubernetes.io/name` is the APPLICATION,
# which for a team with one chart and many services is the CHART name and is
# identical across all of them: on the real cluster every workload carries
# `name: acme-payment-gateway` with `instance: preprod-<service>`, so
# matching on `name` made one service claim every other service's Deployment,
# Service and ConfigMap in the namespace.
#
# It is still a good signal where a chart is per-service, which is the common
# case. So it is used only when the cluster shows it is not shared — see
# _shared_app_names().
_OWNER_LABELS = ("app.kubernetes.io/instance", "app", "k8s-app", "service")
_APP_NAME_LABEL = "app.kubernetes.io/name"
_INSTANCE_LABEL = "app.kubernetes.io/instance"


def _shared_app_names(items: list) -> set:
    """`app.kubernetes.io/name` values that cover more than one release.

    Derived from what is in the namespace rather than assumed either way: a
    value carried by two different instances is a chart name, and cannot decide
    which service a resource belongs to. One carried by a single instance is
    that service's own name and is as good as any other label.
    """
    seen: dict = {}
    for item in items:
        labels = ((item.get("metadata") or {}).get("labels") or {})
        app = labels.get(_APP_NAME_LABEL)
        if app:
            seen.setdefault(app, set()).add(labels.get(_INSTANCE_LABEL, ""))
    return {app for app, instances in seen.items() if len(instances) > 1}

# What kubectl calls a kind, mapped to ours. Kubernetes answers `kind: Deployment`
# in the JSON, so this is a lookup from that rather than from the CLI spelling.
_FROM_K8S = {
    "deployment": "deployment", "statefulset": "deployment",
    "daemonset": "deployment", "cronjob": "deployment", "job": "deployment",
    "service": "service",
    "ingress": "ingress", "ingressroute": "ingress",
    "configmap": "configmap",
    "secret": "secret",
    "sealedsecret": "sealedsecret",
}


def _norm(name: str) -> str:
    """A name with the punctuation teams disagree about taken out.

    `payment-gateway`, `payment_gateway` and `paymentGateway` are one service
    with three spellings, and which one appears in a label is a coin toss.
    """
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _same(a: str, b: str) -> bool:
    return bool(a and b) and _norm(a) == _norm(b)


# Separators a release name is built with. Kubernetes names allow `-` and `.`;
# chart authors reach for `_` anyway.
_SEP = "-_."


# The two directions are NOT the same statement, which is the whole subtlety.
#
#   suffix — `preprod-payza-worker` for `payza-worker`. Something was put
#            in FRONT: an environment or a namespace. Same release.
#   prefix — `bo-frontend-v02` for `bo-frontend`. Something was added AFTER: a
#            variant. A DIFFERENT release, deployed alongside, and treating it
#            as the same had `bo-frontend-values.yaml` claiming v02's Deployment,
#            Service and Ingress on two real clusters.
#
# So a release label may only carry a prefix, and a derived resource name may
# only carry a suffix (`base-config`). Both on the RAW names: _norm() strips the
# punctuation and with it the boundary, and `preprod-shopcart` then "ends
# with" `-cart` because `shopcart` does once the hyphen is gone — which put
# another service's workload under cart.
def _has_suffix(value: str, against: str) -> bool:
    """`value` is something + separator + `against`."""
    v, a = (value or "").lower(), (against or "").lower()
    return bool(v and a) and v != a and v.endswith(a) \
        and v[-len(a) - 1:-len(a)] in _SEP


def _has_prefix(value: str, against: str) -> bool:
    """`value` is `against` + separator + something."""
    v, a = (value or "").lower(), (against or "").lower()
    return bool(v and a) and v != a and v.startswith(a) \
        and v[len(a):len(a) + 1] in _SEP


_SHARED_HINTS = ("pull-secret", "pullsecret", "regcred", "image-pull")


def _declared_names(meta: dict) -> dict:
    """{name: why} for every resource this values file says the service has.

    The file is the authority, and it was barely being read: only `name` and
    `secretName`, with everything else inferred from the SERVICE name — which
    came from the filename. `pay-za-worker-values.yaml` looked for
    `pay-za-worker*` while the chart declares `payza-worker`, so the
    ConfigMap holding that service's entire configuration was filed under
    "nothing links these to this service".
    """
    out = {}
    declared = meta.get("declares") or {}
    for kind, why in (("service", "named as its Service"),
                      ("configmap", "named as its ConfigMap"),
                      ("secret", "named as its Secret")):
        for name in declared.get(kind) or []:
            if any(hint in name.lower() for hint in _SHARED_HINTS):
                continue
            out.setdefault(name, why)
    for name in (declared.get("base"), meta.get("name"), meta.get("secret_name")):
        if name:
            out.setdefault(name, "named in the values file")
    return out


def _declared_base(meta: dict) -> str:
    """The name the chart deploys under, which is what its resources are prefixed
    with. Falls back to nothing rather than to the filename — a wrong prefix
    claims other services' objects."""
    return ((meta.get("declares") or {}).get("base")
            or meta.get("name") or "")


# Kinds whose name must match EXACTLY. A chart deploys one workload, one
# Service, one Ingress, and they are named for the release — so `bo-frontend`
# and `bo-frontend-v02` are two services, not one and its variant. Prefix
# matching there had the v01 file claiming v02's Deployment and vice versa.
#
# The data kinds keep the prefix rule, because `base-config` and `base-secret`
# are the convention a chart follows when it is not naming them outright.
_EXACT_KINDS = {"deployment", "service", "ingress"}


def _claims(item: dict, kind: str, service: str, declared: dict, base: str = "",
            shared_apps: set = frozenset(),
            declared_kinds: set = frozenset()) -> str:
    """Why this resource is thought to belong to the service, or "" if it is not.

    The reason is returned rather than a boolean so the page can say which rule
    matched — a resource claimed by a name prefix is a weaker statement than one
    the values file named, and somebody chasing a missing ConfigMap needs to
    know which of those they are looking at.
    """
    meta = item.get("metadata") or {}
    name = meta.get("name") or ""
    # The file's own word first. It is the only signal that is a statement
    # rather than a resemblance.
    if name in declared:
        return declared[name]
    labels = meta.get("labels") or {}
    # Matched against the DECLARED name as well as the file's, because the two
    # differ often enough to matter and the deployed labels follow the chart.
    keys = list(_OWNER_LABELS)
    app = labels.get(_APP_NAME_LABEL)
    if app and app not in shared_apps:
        keys.append(_APP_NAME_LABEL)
    # The declared name alone when the file gives one. Falling back to the
    # filename here too is what left `bo-frontend-values02.yaml` claiming the
    # v01 Deployment: its filename reduces to `bo-frontend`, which is a
    # different service that exists in the same namespace.
    candidates = [base] if base else [service]
    for key in keys:
        value = labels.get(key, "")
        for against in candidates:
            if not (value and against):
                continue
            if _same(value, against):
                return f"{key} label"
            # A release name usually carries the environment with it —
            # `preprod-payza-worker` for `payza-worker`. Only for the
            # instance label, and only as a whole segment, so `worker` cannot
            # claim `preprod-other-worker`.
            # Only a prefix on the release name. A suffix is a variant, and a
            # variant is another service.
            if key == _INSTANCE_LABEL and _has_suffix(value, against):
                return f"{key} label"
    # An Ingress belongs to whatever it SENDS TRAFFIC TO, whatever it is called.
    # `api-backoffice` routing to `bff-backoffice:8080` is that service's ingress
    # by any reading, and it was landing in "also in this namespace" because the
    # two names do not resemble each other. Read from the object rather than
    # guessed: the backend service name is in the spec.
    if kind == "ingress":
        for svc in _backend_services(item):
            for against in candidates:
                if against and _same(svc, against):
                    return f"routes to {svc}"
    # Where the file HAS named this kind, that naming is exhaustive — for NAMES.
    # `bo-frontend-values.yaml` declaring configMap.name means the ConfigMap
    # called `bo-frontend-config-v02` is the other file's, however much it looks
    # like this one's.
    #
    # Labels are checked above this line and deliberately not subject to it: a
    # label is the cluster's own statement about what a resource belongs to,
    # where a name is a resemblance. A chart that creates a second Secret and
    # labels it properly is still telling the truth.
    if kind in declared_kinds:
        return ""
    for against in candidates:
        how = "the name it deploys under" if base else "same name"
        if not against:
            continue
        if _same(name, against):
            return how
        # `base-config`, `base-secret` — a separated segment, not any string
        # that happens to begin with the same letters.
        if kind not in _EXACT_KINDS and _has_prefix(name, against):
            return f"{against}-… name prefix"
    return ""


def _backend_services(item: dict) -> list:
    """The Service names an Ingress or IngressRoute sends traffic to.

    Both shapes, because a cluster running Traefik has both: an Ingress keeps
    them under `spec.rules[].http.paths[].backend.service.name`, and an
    IngressRoute under `spec.routes[].services[].name`.
    """
    spec = item.get("spec") or {}
    out = []
    for rule in spec.get("rules") or []:
        for path in ((rule.get("http") or {}).get("paths") or []):
            name = (((path.get("backend") or {}).get("service") or {})
                    .get("name") or "")
            if name and name not in out:
                out.append(name)
    default = (((spec.get("defaultBackend") or {}).get("service")) or {})
    if default.get("name") and default["name"] not in out:
        out.append(default["name"])
    for rule in spec.get("routes") or []:
        for svc in rule.get("services") or []:
            if svc.get("name") and svc["name"] not in out:
                out.append(svc["name"])
    return out


def _summarise(item: dict) -> list:
    """The two or three facts about a resource worth reading in a list.

    Deliberately not a describe: this is the row you scan to decide whether to
    open something, and a wall of YAML there is what made the cluster page's own
    listings unreadable before they were cut down to this.
    """
    kind = (item.get("kind") or "").lower()
    spec = item.get("spec") or {}
    out = []
    if kind in ("deployment", "statefulset"):
        st = item.get("status") or {}
        want = spec.get("replicas", 0)
        have = st.get("readyReplicas") or 0
        out.append(f"{have}/{want} ready")
        containers = ((spec.get("template") or {}).get("spec")
                      or {}).get("containers") or []
        for c in containers[:2]:
            image = c.get("image") or ""
            out.append(image.rsplit("/", 1)[-1] if "/" in image else image)
    elif kind == "service":
        out.append(spec.get("type") or "ClusterIP")
        out += [str(p.get("port")) for p in (spec.get("ports") or [])[:3]]
    elif kind in ("ingress", "ingressroute"):
        hosts = [r.get("host") for r in (spec.get("rules") or []) if r.get("host")]
        out += hosts[:2]
        if spec.get("tls"):
            out.append("TLS")
    elif kind in ("configmap", "secret", "sealedsecret"):
        data = item.get("data") or {}
        if kind == "sealedsecret":
            data = ((spec.get("encryptedData")) or item.get("data") or {})
        out.append(f"{len(data)} key" + ("" if len(data) == 1 else "s"))
        if kind == "secret" and item.get("type"):
            out.append(item["type"].rsplit("/", 1)[-1])
    return [str(o) for o in out if o]


# What a group of one kind adds up to, in the words of the thing itself.
#
# The cards used to carry "read-only here" and "key/value editable" — the
# PORTAL talking about its own capabilities, in a place where the reader is
# trying to find out what their service is made of. Whether a thing can be
# edited is already said by the button on its row, and said better, because
# there it is a verb you can press rather than a disclaimer you have to
# interpret. So the card says what is inside instead, which is what makes it
# possible to pick the right one without opening all of them.
_NOUNS = {"deployment": ("workload", "workloads"),
          "service": ("service", "services"),
          "ingress": ("route", "routes"),
          "configmap": ("map", "maps"),
          "secret": ("secret", "secrets"),
          "sealedsecret": ("sealed secret", "sealed secrets")}


def _group_note(kind: str, rows: list) -> str:
    """The one line under a kind's name on its card."""
    n = len(rows)
    one, many = _NOUNS.get(kind, ("resource", "resources"))
    fact = ""
    if kind == "deployment":
        ready = sum(r.get("ready_now", 0) for r in rows)
        want = sum(r.get("ready_want", 0) for r in rows)
        fact = f"{ready}/{want} pods ready" if want else ""
    elif kind == "service":
        ports = sum(r.get("port_count", 0) for r in rows)
        fact = f"{ports} port" + ("" if ports == 1 else "s") if ports else ""
    elif kind == "ingress":
        hosts = [h for r in rows for h in r.get("hosts", [])]
        if hosts:
            fact = hosts[0] + (f" and {len(hosts) - 1} more"
                               if len(hosts) > 1 else "")
    else:
        keys = sum(len(r.get("data_keys") or []) for r in rows)
        fact = f"{keys} key" + ("" if keys == 1 else "s")
    if n == 1:
        # One of something: the count adds nothing the card's own name does not
        # already say, so only the fact is worth the line.
        return fact or one
    return f"{n} {many}" + (f" · {fact}" if fact else "")


# Who will put this object back if you change it by hand.
#
# The Secret a service uses is very often NOT a secret anybody created: the
# sealed-secrets controller decrypts a SealedSecret from git and writes it. On
# the cluster it looks like an ordinary Secret — same kind, same data, nothing
# in the listing to say otherwise — so the page invited people to edit a value
# that the controller rewrites on its next pass, from a source they were not
# shown. The edit succeeds, reports success, and is silently reverted.
#
# Read from ownerReferences, which is Kubernetes' own answer rather than a
# guess: the controller sets itself as the owner so that deleting the
# SealedSecret garbage-collects the Secret. The annotation is a second signal
# for the case where the Secret was adopted rather than created.
def owner_of(meta: dict) -> str:
    """"ArgoCD", "SealedSecret", the owning kind, or "" — whichever applies."""
    for ref in (meta.get("ownerReferences") or []):
        kind = (ref.get("kind") or "").strip()
        if kind:
            return kind
    annotations = meta.get("annotations") or {}
    if any(k.startswith("sealedsecrets.bitnami.com/") for k in annotations):
        return "SealedSecret"
    if ((meta.get("labels") or {}).get("argocd.argoproj.io/instance")
            or annotations.get("argocd.argoproj.io/tracking-id")):
        return "ArgoCD"
    return ""


def _countable(item: dict) -> dict:
    """The few numbers a group's card adds up. Read once, here, rather than
    parsed back out of the display strings _summarise() produced."""
    kind = (item.get("kind") or "").lower()
    spec = item.get("spec") or {}
    if kind in ("deployment", "statefulset", "daemonset"):
        return {"ready_now": (item.get("status") or {}).get("readyReplicas") or 0,
                "ready_want": spec.get("replicas") or 0}
    if kind == "service":
        return {"port_count": len(spec.get("ports") or [])}
    if kind in ("ingress", "ingressroute"):
        return {"hosts": [r.get("host") for r in (spec.get("rules") or [])
                          if r.get("host")]}
    return {}


def cluster_side(cluster: dict, namespace: str, service: str, meta: dict,
                 refresh: bool = False) -> dict:
    """What this service currently is on the cluster, grouped by kind."""
    from . import cluster as clusterview
    if not (cluster and namespace):
        return {"error": "", "groups": [], "total": 0, "unclaimed": [],
                "refused": [],
                "why": ("no cluster is mapped to this environment"
                        if not cluster else
                        "this values file does not say which namespace")}
    got = clusterview.service_bundle(cluster, namespace, refresh)
    if got.get("error"):
        return {"error": got["error"], "groups": [], "total": 0,
                "unclaimed": [], "why": "", "refused": got.get("refused") or []}

    declared = _declared_names(meta or {})
    base = _declared_base(meta or {})
    shared_apps = _shared_app_names(got.get("items") or [])
    # Which kinds the file named outright, so a naming can be treated as the
    # complete answer for that kind rather than one example of it.
    stated = (meta or {}).get("declares") or {}
    declared_kinds = {k for k in ("service", "configmap", "secret")
                      if stated.get(k)}
    # A declared Secret name is also the SealedSecret's name — the controller
    # writes the Secret from it, so naming one names both.
    if stated.get("secret"):
        declared_kinds.add("sealedsecret")
    buckets: dict = {k: [] for k, _l, _i in KINDS}
    unclaimed = []
    for item in got.get("items") or []:
        kind = _FROM_K8S.get((item.get("kind") or "").lower())
        if not kind:
            continue
        m = item.get("metadata") or {}
        why = _claims(item, kind, service, declared, base, shared_apps,
                      declared_kinds)
        row = {"name": m.get("name", ""), "namespace": m.get("namespace", ""),
               "k8s_kind": item.get("kind", ""), "claim": why,
               "facts": _summarise(item),
               **_countable(item),
               # Argo writes this onto everything it owns, so it is the cluster's
               # own answer to "will a sync undo what I change here" — inferred
               # from the object rather than asked of Argo or the sealing
               # controller, which would be two more connections this page does
               # not need.
               "owner": owner_of(m),
               "gitops": bool(owner_of(m)),
               # `data_keys`, never `keys`: Jinja resolves `row.keys` to the
               # DICT'S OWN .keys METHOD before it looks for an item of that
               # name, so `row.keys|length` is a TypeError on a bound method and
               # the page is a 500. Same trap as a context variable shadowing a
               # Jinja global — it does not look like a name collision because
               # one of the two names is invisible.
               "data_keys": sorted((item.get("data")
                                    or ((item.get("spec") or {})
                                        .get("encryptedData")) or {}).keys()),
               }
        (buckets[kind] if why else unclaimed).append(row)
        if not why:
            unclaimed[-1]["kind"] = kind

    groups = []
    for key, label, icon in KINDS:
        rows = buckets[key]
        if not rows:
            continue
        rows.sort(key=lambda r: r["name"])
        groups.append({"kind": key, "label": label, "icon": icon, "rows": rows,
                       "count": len(rows),
                       "note": _group_note(key, rows)})
    # Kinds the cluster would not answer for. Reported rather than folded into a
    # single failure: "Deployments and Services are here, ConfigMaps and Secrets
    # are Forbidden for these credentials" is actionable, and "could not read
    # namespace" is not.
    refused = [r for r in (got.get("refused") or [])
               # A CRD nobody installed is absence, not a refusal to report: a
               # cluster without sealed-secrets or Traefik is the normal case.
               if "the server doesn't have a resource type" not in r["why"]
               and "could not find the requested resource" not in r["why"]]
    return {"error": "", "groups": groups,
            "total": sum(g["count"] for g in groups),
            "unclaimed": sorted(unclaimed, key=lambda r: (r["kind"], r["name"])),
            "why": "", "refused": refused}
