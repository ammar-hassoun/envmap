#!/usr/bin/env python3
"""Which cluster resources belong to a service, and the dotted path writer.

WHY THIS EXISTS
    This tested a page that no longer exists — a service's GitOps side beside
    its live side, with a key/value editor. The page was retired for a window
    (`_values_dialog.html`), and its half of this file went with it. What is
    left is the part that was never about the page, and it is the part where
    being wrong is expensive:

    1. **A resource claimed by the wrong service, or by none.** There is no
       Kubernetes object saying which Deployment goes with which ConfigMap, so
       `cluster_side` infers ownership from names and labels. Inference that is
       too eager shows one service another's Secret; too shy and the ConfigMap
       somebody is looking for is missing from the only view that should have
       it. Both directions are checked, including the namespace's own unrelated
       objects, and including the real trap: a chart whose
       `app.kubernetes.io/name` is identical across every service, where
       matching on it had one service claim all fourteen resources.

    2. **A refusal that costs more than itself.** The six kinds were one
       comma-separated kubectl call, so a service account that could not list
       secrets lost the Deployments too and the view said "could not read
       namespace". Each kind is asked for separately and reports its own
       refusal, with kubectl's reason kept.

    3. **A dotted path that writes the wrong shape.** `resources.limits.cpu` on
       a file with neither `resources` nor `limits` has to create both, indented
       the way that file is indented — and the file has to still parse
       afterwards. A YAML writer that produces something plausible-looking and
       invalid is the worst outcome here, because it lands in git. Still
       reachable: `actions.py`'s `config_add` verb is the caller now.

    `cluster_side` is read by /clusters/related, which is why it outlived the
    page it was written for.

    ./.venv/bin/python tests/test_svcview.py
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("svcview-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import repo, store, svcview, values, yamledit         # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0

FILE = """namespace: pay-dev
fullnameOverride: payza-worker
serviceName: payza-worker-service
envFrom:
  configMaps:
    - payza-worker-config
imagePullSecrets:
  - name: azure-pull-secret
replicaCount: 2
image:
  repository: registry.example.com/team/pay
  tag: "1.4.2"
resources:
  limits:
    cpu: 500m
service:
  type: ClusterIP
  port: 8080
ingress:
  enabled: true
  hosts:
    - host: pay.example.com
configMap:
  name: payza-worker-config
config:
  API_URL: https://api.example.com
  TIMEOUT: "30"
secret:
  secretName: payza-worker-secret
  SealedSecret:
    DB_PASSWORD: AgBv1x9kciphertext
somethingNobodyMapped: yes
"""


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def setup() -> tuple:
    pid = store.add_project("Sides", "🧪")
    rgid = store.add_region(pid, "region-one")
    root = store.repo_dir(pid, rgid)
    envdir = root / "dev"
    envdir.mkdir(parents=True, exist_ok=True)
    (envdir / "pay-values.yaml").write_text(FILE)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # no url on purpose: these fixtures plant files by hand, and a fake
    # url would make the absorb migration move the tree mid-test
    store.set_region_repo(pid, rgid, {"protocol": "https", "values_path": ""})
    return pid, rgid, "dev", "pay-values.yaml"


def main() -> int:
    import re as _re
    pid, rgid, env, fname = setup()

    print("the values file's own declarations reach the view")
    # The cases below hand-build this dict, so without a check here the wiring
    # from load_service to the claiming could be cut and every one of them would
    # still pass — which it did, until this was added.
    # .get throughout: a missing key should be a FAILING CHECK, not a traceback
    # — a crash reads as a broken test rather than as the thing it caught.
    said = repo.load_service(pid, rgid, env, fname)["meta"].get("declares") or {}
    check(f"the base it deploys under ({said.get('base')!r})",
          said.get("base") == "payza-worker")
    check(f"its Service ({said.get('service')})",
          said.get("service") == ["payza-worker-service"])
    # Named twice in the file — `configMap.name` and `envFrom.configMaps` — and
    # that is one resource, not two.
    check(f"its ConfigMap, once ({said.get('configmap')})",
          said.get("configmap") == ["payza-worker-config"])
    check(f"and its Secrets, pull secret included at this level "
          f"({said.get('secret')})",
          said.get("secret") == ["payza-worker-secret", "azure-pull-secret"])

    print("which cluster resources belong to this service")
    # The file is the authority now. It was barely read — `name` and
    # `secretName` only, with the rest inferred from a service name taken from
    # the FILENAME — so `pay-za-worker-values.yaml` hunted for
    # `pay-za-worker*` while its chart declares `payza-worker`, and the
    # ConfigMap holding that service's whole configuration was filed under
    # "nothing links these to this service".
    meta_pay = {"name": "pay", "secret_name": "pay-secret",
                "declares": {"base": "payza-worker",
                             "service": ["payza-worker-service"],
                             "configmap": ["payza-worker-config"],
                             "secret": ["payza-worker-secret",
                                        "azure-pull-secret"]}}
    declared = svcview._declared_names(meta_pay)
    base = svcview._declared_base(meta_pay)
    check(f"the declared base is used, not the filename ({base})",
          base == "payza-worker")
    # A pull secret is shared plumbing; claiming it puts the same row under
    # every service in the namespace and says it belongs to each.
    check("a shared pull secret is not claimed as this service's",
          "azure-pull-secret" not in declared)

    kinds = {"service", "configmap", "secret", "sealedsecret"}
    cases = [
        # (k8s kind, our kind, name, labels, claimed?, why)
        ("ConfigMap", "configmap", "payza-worker-config", {}, True,
         "the file names it"),
        ("Service", "service", "payza-worker-service", {}, True,
         "the file names it"),
        ("Deployment", "deployment", "payza-worker", {}, True,
         "the name it deploys under"),
        ("Deployment", "deployment", "anything",
         {"app.kubernetes.io/instance": "preprod-payza-worker"}, True,
         "release label with the environment on it"),
        ("Secret", "secret", "other", {"app": "PAYZA-WORKER"}, True,
         "label, different case"),
        # somebody else's
        ("ConfigMap", "configmap", "kube-root-ca.crt", {}, False,
         "the namespace's own"),
        ("ConfigMap", "configmap", "payza-worker-config-v02", {}, False,
         "another file declares this one"),
        ("Deployment", "deployment", "payza-worker-v02", {}, False,
         "a different release, not a variant of this one"),
        ("Secret", "secret", "billing-secret", {"app": "billing"}, False,
         "another service"),
    ]
    for k8s, kind, name, labels, want, why in cases:
        item = {"kind": k8s, "metadata": {"name": name, "labels": labels}}
        got = svcview._claims(item, kind, "pay", declared, base,
                              declared_kinds=kinds)
        check(f"{k8s}/{name} ({why}) — claimed={bool(got)}, wanted={want}"
              + (f" [{got}]" if got else ""), bool(got) == want)

    print("a prefix and a suffix are not the same statement")
    # Both measured on real clusters, and they pull in opposite directions:
    #   `preprod-payza-worker` is `payza-worker` with an ENVIRONMENT in
    #   front — the same release.
    #   `bo-frontend-v02` is `bo-frontend` with a VARIANT after it — a different
    #   release, deployed alongside, which the v01 file was claiming.
    for value, against, suffix, prefix, why in (
            ("preprod-payza-worker", "payza-worker", True, False,
             "an environment in front"),
            ("bo-frontend-v02", "bo-frontend", False, True, "a variant after"),
            # and the boundary has to survive: normalising the punctuation away
            # made `shopcart` end with `cart`
            ("preprod-shopcart", "cart", False, False,
             "a different service that merely ends the same"),
            ("bo-frontend-config", "bo-frontend", False, True,
             "a derived resource name"),
    ):
        check(f"{value!r} vs {against!r} suffix={suffix} ({why})",
              svcview._has_suffix(value, against) is suffix)
        check(f"{value!r} vs {against!r} prefix={prefix} ({why})",
              svcview._has_prefix(value, against) is prefix)
    # ...and through the claiming, which is where the direction matters
    v02 = {"kind": "Deployment",
           "metadata": {"name": "bo-frontend-v02",
                        "labels": {"app.kubernetes.io/instance": "bo-frontend-v02"}}}
    check("a variant release is not claimed by the base service",
          svcview._claims(v02, "deployment", "bo-frontend", {},
                          "bo-frontend") == "")
    env_prefixed = {"kind": "Deployment",
                    "metadata": {"name": "whatever",
                                 "labels": {"app.kubernetes.io/instance":
                                            "preprod-bo-frontend"}}}
    check("but the same release in a named environment is",
          svcview._claims(env_prefixed, "deployment", "bo-frontend", {},
                          "bo-frontend") != "")

    print("a chart name shared by every service cannot decide ownership")
    # Measured on the real cluster: every workload carries
    # `app.kubernetes.io/name: acme-payment-gateway` — the CHART — with
    # `instance: preprod-<service>` telling them apart. Matching on `name` had
    # one service claiming all fourteen of the namespace's resources.
    fleet = [{"metadata": {"labels": {"app.kubernetes.io/name": "the-chart",
                                      "app.kubernetes.io/instance": f"preprod-{n}"}}}
             for n in ("a", "b", "c")]
    shared = svcview._shared_app_names(fleet)
    check(f"a name across several releases is recognised as the chart ({shared})",
          shared == {"the-chart"})
    solo = [{"metadata": {"labels": {"app.kubernetes.io/name": "just-me",
                                     "app.kubernetes.io/instance": "preprod-just-me"}}}]
    check("and one used by a single release is still that service's own",
          svcview._shared_app_names(solo) == set())
    chartish = {"kind": "Deployment",
                "metadata": {"name": "someone-else",
                             "labels": {"app.kubernetes.io/name": "the-chart"}}}
    check("so a chart-wide name claims nothing",
          svcview._claims(chartish, "deployment", "the-chart",
                          {}, "the-chart", {"the-chart"}) == "")
    check("while the same label, unshared, still claims",
          svcview._claims(chartish, "deployment", "the-chart",
                          {}, "the-chart", set()) != "")

    print("the live side, assembled over a fake cluster read")
    # The cluster read is replaced rather than mocked away: the grouping, the
    # claiming and the unclaimed list all have to run on shapes kubectl really
    # produces, which is where the field names get remembered wrongly.
    from app import cluster as clusterview
    real = clusterview.service_bundle
    clusterview.service_bundle = lambda c, ns, refresh=False: {"error": "", "items": [
        # Named as the chart DECLARES, not as the filename suggests — the two
        # differ on real charts and that difference is the whole feature.
        {"kind": "Deployment", "metadata": {"name": "payza-worker",
         "namespace": ns},
         "spec": {"replicas": 2, "template": {"spec": {"containers": [
             {"image": "registry.example.com/team/pay:1.4.2"}]}}},
         "status": {"readyReplicas": 2}},
        {"kind": "Service", "metadata": {"name": "payza-worker-service",
         "namespace": ns},
         "spec": {"type": "ClusterIP", "ports": [{"port": 8080}]}},
        {"kind": "ConfigMap", "metadata": {"name": "payza-worker-config",
         "namespace": ns},
         "data": {"API_URL": "https://api.example.com", "TIMEOUT": "30"}},
        {"kind": "Secret", "metadata": {"name": "payza-worker-secret",
         "namespace": ns,
         "labels": {"argocd.argoproj.io/instance": "pay"}},
         "type": "Opaque", "data": {"DB_PASSWORD": "cw=="}},
        {"kind": "ConfigMap", "metadata": {"name": "kube-root-ca.crt",
         "namespace": ns}, "data": {"ca.crt": "-----BEGIN"}},
    ]}
    try:
        meta = repo.load_service(pid, rgid, env, fname)["meta"]
        two = {"live": svcview.cluster_side(
            {"id": "c1", "context": "x"}, meta.get("namespace") or "",
            repo.display(pid, fname), meta)}
    finally:
        clusterview.service_bundle = real

    live = {g["kind"]: g for g in two["live"]["groups"]}
    check(f"the live side found kinds ({sorted(live)})", len(live) == 4)
    check("the Deployment reads back its readiness and image",
          live["deployment"]["rows"][0]["facts"] == ["2/2 ready", "pay:1.4.2"])
    # The card's own line. One of a kind states only the fact — the count adds
    # nothing the card's name has not already said.
    check(f"one ConfigMap reads as its key count ({live['configmap']['note']})",
          live["configmap"]["note"] == "2 keys")
    check(f"one Deployment reads as its readiness ({live['deployment']['note']})",
          live["deployment"]["note"] == "2/2 pods ready")
    check(f"one Service reads as its ports ({live['service']['note']})",
          live["service"]["note"] == "1 port")
    # The warning that stops somebody making a change a controller silently
    # undoes — and, for a Secret, the more important half: the values were not
    # set on the cluster at all. The sealing controller decrypted a SealedSecret
    # from git and wrote them here, so the page showed a Secret that looks
    # hand-made and is not, and offered to edit values that get overwritten from
    # a source the reader was never shown.
    check(f"an owned resource names its owner "
          f"({live['secret']['rows'][0]['owner']})",
          live["secret"]["rows"][0]["owner"] == "ArgoCD")
    check("one that is not, is not",
          live["configmap"]["rows"][0]["owner"] == "")
    for meta, want, why in (
            ({"ownerReferences": [{"kind": "SealedSecret", "name": "w"}]},
             "SealedSecret", "written by the sealing controller"),
            ({"annotations": {"sealedsecrets.bitnami.com/managed": "true"}},
             "SealedSecret", "adopted by the sealing controller"),
            ({"labels": {"argocd.argoproj.io/instance": "pay"}},
             "ArgoCD", "tracked by Argo"),
            ({"ownerReferences": [{"kind": "Deployment", "name": "pay"}]},
             "Deployment", "made by a workload"),
            ({}, "", "nobody — genuinely set on the cluster"),
    ):
        check(f"a Secret {why} reports {want or 'no owner'} "
              f"(got {svcview.owner_of(meta)!r})",
              svcview.owner_of(meta) == want)
    check(f"the namespace's own objects are held aside, not shown as the "
          f"service's ({[r['name'] for r in two['live']['unclaimed']]})",
          [r["name"] for r in two["live"]["unclaimed"]] == ["kube-root-ca.crt"])
    # `data_keys`, not `keys`: a dict field called `keys` is unreachable from a
    # template, because Jinja answers `row.keys` with dict.keys. That shipped as
    # a 500 on the real page — tests/test_shadowing.py now refuses the whole
    # class, and this names the field so a rename cannot pass silently.
    check("a ConfigMap's keys come back for the editor",
          live["configmap"]["rows"][0]["data_keys"] == ["API_URL", "TIMEOUT"])
    check("and not under a name a template cannot read",
          "keys" not in live["configmap"]["rows"][0])

    print("the namespace is read one kind at a time")
    # The half the stub above cannot see. Everything below it tests how a refusal
    # is REPORTED; this tests that a refusal is survivable at all — the six kinds
    # were one comma-separated kubectl call, so a single Forbidden lost the lot.
    asked = []

    def per_kind(cluster, *args, timeout=None):
        kind = args[0]
        asked.append(kind)
        if kind in ("configmap", "secret"):
            return None, f'Forbidden: {kind}s is forbidden: User "sa" cannot list'
        if kind in ("sealedsecret", "ingressroute"):
            return None, "the server doesn't have a resource type"
        return {"items": [{"kind": kind.title(), "metadata": {"name": kind}}]}, ""

    real_get = clusterview._get_why
    clusterview._get_why = per_kind
    try:
        clusterview.forget("c1", "bundle:pay-dev")
        got = clusterview._bundle_rows({"id": "c1", "context": "x"}, "pay-dev")
    finally:
        clusterview._get_why = real_get
    check(f"every kind is asked for separately ({len(asked)})", len(asked) >= 6)
    check("one call per kind, not one call for all of them",
          all("," not in k for k in asked))
    check(f"the kinds that answered are kept ({len(got['items'])})",
          len(got["items"]) == 4)
    check("and it is not reported as a failed read", got["error"] == "")
    refused_kinds = {r["kind"] for r in got["refused"]}
    check(f"the ones that refused are named ({sorted(refused_kinds)})",
          {"configmap", "secret"} <= refused_kinds)

    print("a kind the credentials cannot read costs only itself")
    # Measured on a real cluster: the registered service account could not list
    # configmaps or secrets in the namespace, and because all six kinds were one
    # comma-separated kubectl call, the WHOLE read failed. The page said "could
    # not read namespace" and showed nothing — hiding the Deployments and
    # Services it could see, and hiding kubectl's own sentence, which names the
    # verb, the resource and the identity and is the only thing that tells
    # somebody which role binding to fix.
    clusterview.service_bundle = lambda c, ns, refresh=False: {
        "error": "", "refused": [
            {"kind": "configmap", "why": 'Forbidden: configmaps is forbidden: '
             'User "system:serviceaccount:kube-system:ro" cannot list resource '
             '"configmaps" in API group "" in the namespace "pay-dev"'},
            {"kind": "secret", "why": "Forbidden: secrets is forbidden"},
            # A CRD nobody installed is absence, not a refusal worth reporting.
            {"kind": "sealedsecret",
             "why": "the server doesn't have a resource type sealedsecrets"},
        ],
        "items": [
            {"kind": "Deployment", "metadata": {"name": "payza-worker",
             "namespace": ns},
             "spec": {"replicas": 1, "template": {"spec": {"containers": [
                 {"image": "r/pay:1"}]}}}, "status": {"readyReplicas": 1}},
        ]}
    try:
        meta = repo.load_service(pid, rgid, env, fname)["meta"]
        partial = {"live": svcview.cluster_side(
            {"id": "c1"}, meta.get("namespace") or "",
            repo.display(pid, fname), meta)}
    finally:
        clusterview.service_bundle = real
    kinds = [g["kind"] for g in partial["live"]["groups"]]
    check(f"what could be read is still shown ({kinds})", kinds == ["deployment"])
    check("and the read is not reported as a failure",
          partial["live"]["error"] == "")
    refused = {r["kind"] for r in partial["live"]["refused"]}
    check(f"the refused kinds are named ({sorted(refused)})",
          refused == {"configmap", "secret"})
    check("an absent CRD is not called a refusal", "sealedsecret" not in refused)
    check("and kubectl's own reason is kept, identity and all",
          "cannot list resource" in partial["live"]["refused"][0]["why"]
          and "serviceaccount" in partial["live"]["refused"][0]["why"])
    # Nothing readable at all IS a cluster-level failure, and the reason still
    # has to survive — "could not read namespace" was the whole complaint.
    clusterview.service_bundle = lambda c, ns, refresh=False: {
        "error": "Forbidden: pods is forbidden", "items": [],
        "refused": [{"kind": "deployment", "why": "Forbidden: pods is forbidden"}]}
    try:
        none_at_all = {"live": svcview.cluster_side(
            {"id": "c1"}, "pay-dev", repo.display(pid, fname),
            {"namespace": "pay-dev"})}
    finally:
        clusterview.service_bundle = real
    check(f"a total refusal says why ({none_at_all['live']['error'][:34]})",
          "Forbidden" in none_at_all["live"]["error"])

    print("an unreachable cluster leaves the repo side usable")
    clusterview.service_bundle = lambda c, ns, refresh=False: {
        "error": "could not read namespace pay-dev", "items": []}
    try:
        broken = {"live": svcview.cluster_side(
            {"id": "c1"}, "pay-dev", repo.display(pid, fname),
            {"namespace": "pay-dev"})}
    finally:
        clusterview.service_bundle = real
    check("the live side says why", "could not read" in broken["live"]["error"])
    none = {"live": svcview.cluster_side(None, "pay-dev",
                                        repo.display(pid, fname),
                                        {"namespace": "pay-dev"})}
    check("no mapped cluster is explained rather than shown as an error",
          "no cluster is mapped" in none["live"]["why"] and not none["live"]["error"])
    nons = {"live": svcview.cluster_side({"id": "c1"}, "", 
                                        repo.display(pid, fname), {})}
    check("nor is a values file with no namespace",
          "namespace" in nons["live"]["why"])

    print("a dotted path, instead of choosing a section from a list")
    path = repo.values_path(pid, rgid, env, fname)
    before = path.read_text()
    for raw, want_lines in (
            ("priorityClassName", ["priorityClassName: high"]),
            ("config.NEW_KEY", ["  NEW_KEY: high"]),
            # `resources:` is already in the file, so only what is missing
            # below it is written — and at the depth the file already uses.
            ("resources.requests.memory", ["  requests:", "    memory: high"]),
            # nothing of this one exists, so the whole chain is created
            ("podAnnotations.team.owner", ["podAnnotations:", "  team:",
                                           "    owner: high"]),
    ):
        path.write_text(before)
        did = repo.add_value(pid, rgid, env, fname, "", raw, "high")
        text = path.read_text()
        # It has to still be a document. A writer that produces something
        # plausible and invalid is worse than one that refuses.
        parsed = yamledit.parse(text)
        added = [ln for ln in text.splitlines()
                 if ln not in before.splitlines()]
        check(f"{raw} → {added}", added == want_lines)
        check(f"{raw} said what it did ({did})", raw in did)
        node = parsed
        for step in values.split_path(raw):
            node = node[step]
        check(f"{raw} reads back as the value written ({node})", node == "high")
    path.write_text(before)

    print("and the paths it refuses")
    for raw, expect in (("config.API_URL.deeper", "already holds a value"),
                        ("replicaCount", "already exists"),
                        ("config..TIMEOUT", "resources.limits.cpu"),
                        ("", "resources.limits.cpu")):
        try:
            repo.add_value(pid, rgid, env, fname, "", raw, "x")
            check(f"{raw!r} was refused", False)
        except ValueError as e:
            check(f"{raw!r} → {str(e)[:44]}", expect in str(e))
    check("and nothing was written while refusing", path.read_text() == before)
    # A key with a real dot in it — Kubernetes annotations have them — must be
    # expressible, or the escape hatch is a file edit by hand.
    path.write_text(before)
    repo.add_value(pid, rgid, env, fname, "", r"config.my\.dotted\.key", "v")
    check("an escaped dot stays one key name",
          "my.dotted.key" in yamledit.parse(path.read_text())["config"])
    path.write_text(before)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
