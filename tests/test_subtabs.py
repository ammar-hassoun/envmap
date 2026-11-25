#!/usr/bin/env python3
"""The cluster page driven with real rows: its sub-tabs, and the state that
travels between them.

WHY THIS EXISTS
    Workloads used to hold a `<select>` and an Apply button. Four tabs now carry
    a strip of sub-tabs instead, and a strip has two failure modes that a page
    rendering without an exception will not show you:

      1. **A count that is not of the rows below it.** The dropdown counted every
         kind in the cluster while the table showed one namespace, so
         "Deployment (24)" sat above three rows. The counts are computed in the
         route now, from the rows in view, and this is the check that keeps them
         there.

      2. **A tab that selects nothing.** `?wkind=Nonesuch` — a bookmark from
         before a kind was removed, or a hand-edited URL — must fall back to
         everything. Selecting it literally means an empty table under a tab
         claiming rows, which reads as a cluster that has lost its workloads.

    And one that is quieter: a section that is empty must still be offered. A
    tab that vanishes when there are no routes leaves the reader unable to tell
    "none" from "never looked".

    The same fixture then holds the page to two promises it makes elsewhere:

      * **The namespace survives a tab change.** The bar at the top says so in
        as many words. Every tab link dropped it, so choosing preprod and moving
        from Workloads to Pods silently widened the page back to the whole
        cluster — with the picker still reading preprod, which is worse than
        losing the filter visibly.

      * **Every resource can be opened.** A row for a Service, a route, a
        certificate, a claim, a class or a node is an object in a cluster, and
        the reason to look at one is usually to read or fix its YAML.

    ./.venv/bin/python tests/test_subtabs.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("subtabs-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cluster as clusterview                         # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# Two namespaces on purpose: the count fault only appears when the namespace in
# view holds fewer rows than the cluster does.
WORKLOADS = (
    [{"kind": "Deployment", "namespace": "pay", "name": f"pay-{i}", "want": 1,
      "have": 1, "ok": True, "empty": False, "images": [], "tags": [],
      "age": "3d", "suspended": False} for i in range(3)]
    + [{"kind": "Deployment", "namespace": "other", "name": "elsewhere",
        "want": 1, "have": 1, "ok": True, "empty": False, "images": [],
        "tags": [], "age": "9d", "suspended": False}]
    + [{"kind": "StatefulSet", "namespace": "pay", "name": "pay-db", "want": 3,
        "have": 2, "ok": False, "empty": False, "images": [], "tags": [],
        "age": "80d", "suspended": False}]
    + [{"kind": "CronJob", "namespace": "pay", "name": "pay-sweep", "want": 0,
        "have": 0, "ok": True, "empty": False, "schedule": "*/5 * * * *",
        "last": "4m", "images": [], "tags": [], "age": "1y",
        "suspended": False}])

PARTS = {
    "namespaces": {"error": "", "namespaces": ["pay", "other"]},
    "nodes": {"error": "", "versions": ["v1.34.1"], "metrics": True, "nodes": [
        {"name": "talos-01", "ready": True, "roles": ["worker"],
         "schedulable": True, "taints": [], "pressure": [],
         "version": "v1.34.1", "os": "Talos", "kernel": "6.6", "runtime": "cri-o",
         "arch": "amd64", "ip": "10.0.0.5", "age": "40d",
         "cpu_cap": 8000, "mem_cap": 16384, "cpu_use": 800, "mem_use": 3276,
         "disk_cap": 100000, "disk_alloc": 90000, "disk_use": 20000,
         "disk_pct": 20, "disk_pressure": False,
         "cpu_pct": 10, "mem_pct": 20, "pods_cap": 110},
        {"name": "talos-02", "ready": True, "roles": ["worker"],
         "schedulable": True, "taints": [], "pressure": [],
         "version": "v1.34.1", "os": "Talos", "kernel": "6.6", "runtime": "cri-o",
         "arch": "amd64", "ip": "10.0.0.6", "age": "40d",
         "cpu_cap": 8000, "mem_cap": 16384, "cpu_use": 800, "mem_use": 3276,
         "disk_cap": 100000, "disk_alloc": 90000, "disk_use": 20000,
         "disk_pct": 20, "disk_pressure": False,
         "cpu_pct": 10, "mem_pct": 20, "pods_cap": 110}]},
    "workloads": {"error": "", "workloads": WORKLOADS},
    # bo-frontend and bo-frontend-v02 on purpose: a "name contains" filter finds
    # the second one's pods when asked for the first, and that is the fault the
    # workload filter exists to avoid. Two nodes for the same reason.
    "pods": {"error": "", "metrics": True, "pods": [
        {"name": "pay-db-0", "namespace": "pay", "node": "talos-01",
         "phase": "Running", "problem": "", "healthy": True, "ready": "1/1",
         "restarts": 0, "age": "3d", "images": ["db:1"], "owner": "StatefulSet",
         "workload": "pay-db", "cpu": None, "mem": None, "qos": "Burstable"},
        {"name": "bo-frontend-6d4b8f9c7d-aaa", "namespace": "pay",
         "node": "talos-01", "phase": "Running", "problem": "", "healthy": True,
         "ready": "1/1", "restarts": 0, "age": "3d", "images": ["fe:1"],
         "owner": "ReplicaSet", "workload": "bo-frontend", "cpu": None,
         "mem": None, "qos": "Burstable"},
        {"name": "bo-frontend-v02-7f9b6c5d4-bbb", "namespace": "pay",
         "node": "talos-02", "phase": "Running", "problem": "", "healthy": True,
         "ready": "1/1", "restarts": 0, "age": "3d", "images": ["fe:2"],
         "owner": "ReplicaSet", "workload": "bo-frontend-v02", "cpu": None,
         "mem": None, "qos": "Burstable"},
        {"name": "elsewhere-1", "namespace": "other", "node": "talos-02",
         "phase": "Running", "problem": "", "healthy": True, "ready": "1/1",
         "restarts": 0, "age": "9d", "images": ["x:1"], "owner": "ReplicaSet",
         "workload": "elsewhere", "cpu": None, "mem": None,
         "qos": "Burstable"}]},
    "events": {"error": "", "events": [
        {"type": "Warning", "reason": "BackOff", "namespace": "pay",
         "object": "Pod/pay-db-0", "obj_kind": "pod", "obj_name": "pay-db-0",
         "message": "back-off restarting", "count": 7, "age": "2m"}],
        "groups": [{"reason": "BackOff", "namespace": "pay", "count": 7,
                    "objects": ["pay-db-0"], "sample": "back-off restarting"}]},
    "storage": {"error": "", "claims": [
        {"name": "pay-data", "namespace": "pay", "status": "Bound",
         "bound": True, "size": "20Gi", "sc": "local-path",
         "modes": ["RWO"], "age": "80d", "volume": "pvc-abc"}],
        "classes": [{"name": "local-path", "default": True,
                     "provisioner": "rancher.io/local-path",
                     "reclaim": "Delete"}],
        "total_gib": 20.0, "volumes": 2, "released": ["pvc-orphan"],
        # a bound volume and one nobody is using: the Released one was a name in
        # a warning strip and nowhere else, so it was the one object on the tab
        # that could not be opened
        "pvs": [
            {"name": "pvc-orphan", "status": "Released", "bound": False,
             "stuck": True, "size": "20Gi", "gib": 20.0, "sc": "local-path",
             "reclaim": "Retain", "claim": "", "modes": ["RWO"],
             "reason": "its claim was deleted", "age": "90d"},
            {"name": "pvc-live", "status": "Bound", "bound": True,
             "stuck": False, "size": "50Gi", "gib": 50.0, "sc": "local-path",
             "reclaim": "Delete", "claim": "pay/pay-data", "modes": ["RWO"],
             "reason": "", "age": "118d"}]},
    # network deliberately has services but NO routes: an empty section still
    # has to be reachable, which is the whole reason the tab is not conditional
    # A published service, an internal one, and one in another namespace: the
    # ClusterIP rows are what the tab used to drop on the floor.
    "network": {"error": "", "hosts": ["api.example.com"], "services": [
        {"name": "pay-api", "namespace": "pay", "type": "LoadBalancer",
         "external": ["10.0.0.9"], "published": True, "pending": False,
         "cluster_ip": "10.96.1.4", "ports": ["443/TCP"]},
        {"name": "pay-internal", "namespace": "pay", "type": "ClusterIP",
         "external": [], "published": False, "pending": False,
         "cluster_ip": "10.96.9.9", "ports": ["8080"]},
        {"name": "other-svc", "namespace": "other", "type": "ClusterIP",
         "external": [], "published": False, "pending": False,
         "cluster_ip": "10.96.2.2", "ports": ["80"]}],
        "routes": [{"kind": "IngressRoute", "api": "ingressroute",
                    "namespace": "pay", "name": "pay-route", "tls": True,
                    "hosts": ["api.example.com"], "tls_hosts": [],
                    "class": "websecure",
                    # which Service the host is served by — the other half of
                    # what an ingress says, and it was not on the page
                    "services": ["pay-api:443"]}]},
    # and cert-manager is absent, which is a different answer from "installed
    # with nothing in it" — the tab has to be able to say which
    "certs": {"error": "", "present": True, "certs": [
        {"name": "api-tls", "namespace": "pay", "days": 40, "ready": True,
         "reason": "", "dns": ["api.example.com"], "issuer": "letsencrypt"}]},
    "crds": {"error": "", "crds": [
        {"name": "ingressroutes.traefik.io", "group": "traefik.io",
         "kind": "IngressRoute", "plural": "ingressroutes", "short": ["ir"],
         "scope": "Namespaced", "namespaced": True, "versions": ["v1alpha1"],
         "stored": "v1alpha1", "established": True, "by": "traefik",
         "age": "200d"},
        {"name": "sealedsecrets.bitnami.com", "group": "bitnami.com",
         "kind": "SealedSecret", "plural": "sealedsecrets", "short": [],
         "scope": "Namespaced", "namespaced": True, "versions": ["v1alpha1"],
         "stored": "v1alpha1", "established": False, "by": "", "age": "200d"}],
        "groups": [
            {"group": "bitnami.com", "count": 1, "by": "", "rows": [
                {"name": "sealedsecrets.bitnami.com", "group": "bitnami.com",
                 "kind": "SealedSecret", "plural": "sealedsecrets", "short": [],
                 "scope": "Namespaced", "namespaced": True,
                 "versions": ["v1alpha1"], "stored": "v1alpha1",
                 "established": False, "by": "", "age": "200d"}]},
            {"group": "traefik.io", "count": 1, "by": "traefik", "rows": [
                {"name": "ingressroutes.traefik.io", "group": "traefik.io",
                 "kind": "IngressRoute", "plural": "ingressroutes",
                 "short": ["ir"], "scope": "Namespaced", "namespaced": True,
                 "versions": ["v1alpha1"], "stored": "v1alpha1",
                 "established": True, "by": "traefik", "age": "200d"}]}]},
    "netshoots": {"netshoots": []},
}


def stab_hrefs(body: str) -> list:
    """Every sub-tab link the page actually drew, unescaped."""
    return [h.replace("&amp;", "&") for h in
            re.findall(r'<a class="stab[^"]*"\s+href="([^"]+)"', body)]


def ymkinds(body: str) -> list:
    """Every kind the page offers a YAML window for, in order."""
    return re.findall(r'data-ymkind="([^"]*)"', body)


def opens(body: str, kind: str, name: str) -> bool:
    """Whether the page carries a yaml AND a describe button for one object."""
    y = re.search(r'data-podyaml[^>]*data-ymkind="' + kind
                  + r'"[^>]*data-pod="' + name + r'"', body, re.S)
    d = re.search(r'data-poddesc[^>]*data-dskind="' + kind
                  + r'"[^>]*data-pod="' + name + r'"', body, re.S)
    return bool(y and d)


def stab(body: str, label: str) -> str:
    """The one sub-tab anchor whose label is `label`, or ''."""
    for m in re.finditer(r'<a class="(stab[^"]*)"(.*?)</a>', body, re.S):
        if f">{label}</span>" in m.group(2):
            return m.group(1) + m.group(2)
    return ""


def flat(body: str) -> str:
    """The page with its line breaks collapsed — a sentence in a template is
    wrapped to fit the file, so it is not one string in the markup."""
    return re.sub(r"\s+", " ", body)


def rows_of(body: str, after: str) -> str:
    """The markup of the first table that follows the heading `after`."""
    at = body.find(after)
    if at < 0:
        return ""
    start = body.find("<table", at)
    return body[start:body.find("</table>", start)] if start > -1 else ""


def main() -> int:
    from fastapi.testclient import TestClient
    from app import auth, db, main as appmain, store

    email, pw = "subtabs@test.invalid", "Sub-Tabs-Not-A-Dropdown-9"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    pid = store.add_project("Sub")
    cid = store.add_cluster(pid, "c1", "apiVersion: v1\n", "ctx1")

    # The route's only door to a cluster. Replaced rather than mocked deeper: the
    # point is what the page does with parts that HAVE arrived.
    clusterview.gathered = lambda sel, want, refresh=False: {
        "parts": {k: v for k, v in PARTS.items() if k in want or k == "netshoots"},
        "pending": [], "errors": []}

    client = TestClient(appmain.app, raise_server_exceptions=False)
    base = f"/clusters?project={pid}&cluster={cid}"
    with client:
        client.post("/login", data={"email": email, "password": pw},
                    follow_redirects=False)
        u = auth.by_email(email)
        client.post("/mfa", data={"code": auth._totp_at(
            u["totp_secret"], int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

        def page(path: str) -> str:
            r = client.get(base + path, follow_redirects=False)
            check(f"{path or '(default)'} → HTTP {r.status_code}",
                  r.status_code == 200)
            return r.text

        print("the workloads dropdown is gone, and a strip is in its place")
        body = page("&tab=workloads")
        check("no <select> for the kind", 'name="wkind"' not in body)
        # The dropdown's own cost: pick a kind, then press Apply. Two clicks to
        # do what a tab does in one, and every other count hidden until opened.
        check("no Apply button left behind",
              not re.search(r'<form[^>]*class="pipefilters"', body))
        check("there is a sub-tab strip", 'class="subtabs"' in body)
        for label, count in (("All kinds", 6), ("Deployment", 4),
                             ("StatefulSet", 1), ("CronJob", 1)):
            tab = stab(body, label)
            check(f"{label} is a sub-tab", bool(tab))
            check(f"and counts {count} ({label})",
                  f'class="n">{count}<' in tab)
        check("nothing is selected but everything",
              "stab on" in stab(body, "All kinds")
              and "stab on" not in stab(body, "Deployment"))
        check("and the table holds every kind",
              all(n in body for n in ("pay-0", "elsewhere", "pay-db",
                                      "pay-sweep")))

        print("a kind selects itself, and only its rows")
        body = page("&tab=workloads&wkind=StatefulSet")
        check("its tab is the selected one",
              "stab on" in stab(body, "StatefulSet"))
        check("and All kinds is not", "stab on" not in stab(body, "All kinds"))
        table = rows_of(body, "StatefulSets")
        check("the table names the kind in its heading", bool(table))
        check("its row is there", "pay-db" in table)
        check("and no other kind's is",
              "pay-sweep" not in table and "pay-0" not in table)
        # 110px per row spent repeating the tab that is already selected.
        check("the Kind column is not repeated down the page",
              ">Kind<" not in table)
        check("but it is there when every kind is",
              ">Kind<" in rows_of(page("&tab=workloads"), "Workloads"))

        print("the counts are of the rows in view, not of the cluster")
        # The dropdown's fault: "Deployment (24)" over a table of three.
        body = page("&tab=workloads&ns=pay")
        check("Deployment counts 3, not 4",
              'class="n">3<' in stab(body, "Deployment"))
        check("All kinds counts 5, not 6",
              'class="n">5<' in stab(body, "All kinds"))
        check("the other namespace's row is not in the table",
              "elsewhere" not in body)
        # ...and the namespace has to survive the click, or choosing a kind
        # silently widens the page back to the whole cluster.
        check("and every sub-tab keeps the namespace",
              "&amp;ns=pay&amp;wkind=Deployment" in body)

        print("a kind that is not here selects nothing")
        body = page("&tab=workloads&wkind=Nonesuch")
        check("All kinds is selected instead",
              "stab on" in stab(body, "All kinds"))
        check("and the rows are all there rather than none",
              "pay-db" in body and "pay-sweep" in body)

        print("an action comes back to the sub-tab it was pressed in")
        # A restart that returns to "All kinds" in every namespace has moved the
        # row you were watching off the screen, which is when somebody restarts
        # the wrong thing next.
        body = page("&tab=workloads&ns=pay&wkind=StatefulSet")
        backs = re.findall(r'name="back" value="([^"]*)"', body)
        check(f"the form comes back here ({backs[:1]})",
              bool(backs) and all("tab=workloads" in b and "ns=pay" in b
                                  and "wkind=StatefulSet" in b for b in backs))

        print("network, storage and events open on one section at a time")
        body = page("&tab=network")
        check("services first", "pay-api" in body)
        check("and its tab is selected", "stab on" in stab(body, "Services"))
        # The fault the tab shipped with: a ClusterIP service is most of a
        # cluster, and every one of them was dropped before it reached the page.
        check("an internal service is there too, not only the published one",
              "pay-internal" in body)
        check("and the tab counts all of them",
              'class="n">3<' in stab(body, "Services"))
        check("the ingresses card is not also on the page",
              'card-h">Ingresses' not in body)
        body = page("&tab=network&sec=routes")
        check("ingresses open on their own",
              "pay-route" in body and 'card-h">Services' not in body)
        # An empty section is still offered and still says what nothing means.
        # Reached through the namespace filter, which is how it now happens.
        body = page("&tab=network&sec=routes&ns=other")
        check("a section with nothing in it says so rather than going blank",
              "nothing is routed by host name" in body)
        # Dimmed, but never the tab you are standing on: a greyed-out selected
        # tab reads as broken rather than as empty.
        check("the selected tab is not dimmed, even when it is the empty one",
              "quiet" not in stab(body, "Ingresses"))
        check("but an empty tab you are not on is dimmed rather than withdrawn",
              "quiet" in stab(page("&tab=network&ns=other"), "Ingresses"))
        body = page("&tab=network&sec=certs")
        check("certificates open on their own", "api-tls" in body)
        body = page("&tab=network&sec=not-a-section")
        check("a section that does not exist falls back to the first",
              "pay-api" in body and "stab on" in stab(body, "Services"))

        print("an empty list says WHICH kind of empty it is")
        # Two reasons for no certificates, and they are not the same answer:
        # cert-manager absent, or installed and holding none. The fixture is
        # mutated between requests because that is the only difference.
        was = PARTS["certs"]
        PARTS["certs"] = {"error": "", "present": False, "certs": []}
        check("an absent cert-manager is named as absent",
              "cert-manager is not installed" in flat(page("&tab=network&sec=certs")))
        PARTS["certs"] = {"error": "", "present": True, "certs": []}
        check("and an installed one holding nothing is told apart from it",
              "installed but holds no" in flat(page("&tab=network&sec=certs")))
        PARTS["certs"] = was

        body = page("&tab=events")
        check("events open on the grouping", "BackOff" in body
              and "stab on" in stab(body, "Warnings, grouped"))
        check("and not on the raw list too",
              'card-h">Recent events' not in body)
        body = page("&tab=events&sec=recent")
        check("the raw list opens on its own",
              "back-off restarting" in body
              and "stab on" in stab(body, "Recent events"))

        body = page("&tab=storage")
        check("storage opens on the claims", "pay-data" in body
              and "stab on" in stab(body, "Volume claims"))
        check("the totals stay above the strip whichever is open",
              "GiB claimed" in body)
        body = page("&tab=storage&sec=classes")
        check("the classes open on their own", "rancher.io/local-path" in body
              and "pay-data" not in body)
        check("and the totals are still there", "GiB claimed" in body)

        print("a workload row leads to its own pods, and offers their logs")
        body = page("&tab=workloads")
        # Scaling by hand on a cluster ArgoCD owns is undone at the next sync, so
        # the replica box invited a change that would not last. Logs is what
        # anybody actually wants from a workload row.
        check("the replica box is gone", 'name="replicas"' not in body)
        check("and so is Scale", ">Scale<" not in body)
        check("logs is there instead", 'data-podlog' in body
              and body.count("&gt;logs&lt;") + body.count(">logs<") >= 1)
        check("and it asks kubectl for the workload, not for a guessed pod",
              'data-pod="deployment/pay-0"' in body
              or 'data-pod="statefulset/pay-db"' in body)
        # The name is a link to the pods that BELONG to it.
        link = re.search(r'<a class="wname"\s+href="([^"]+)"', body)
        check(f"the name is a link ({link and link.group(1)[-42:]})",
              link is not None and "tab=pods" in link.group(1)
              and "workload=" in link.group(1))

        print("pods can be narrowed to one workload, and to one node")
        # The whole point of matching on ownerReference: `bo-frontend` must not
        # drag in `bo-frontend-v02`, which is exactly what a name filter does.
        body = page("&tab=pods&ns=pay&workload=bo-frontend")
        check("its own pod is listed", "bo-frontend-6d4b8f9c7d-aaa" in body)
        check("and the similarly-named workload's is NOT",
              "bo-frontend-v02-7f9b6c5d4-bbb" not in body)
        check("the filter says what it is filtering to",
              "pods of" in body and "bo-frontend" in body)
        check("and offers a way out of it",
              re.search(r'class="pf">.*?<a href="[^"]*tab=pods[^"]*"', body, re.S)
                  is not None)
        body = page("&tab=pods&node=talos-02")
        check("a node's pods are the ones scheduled on it",
              "bo-frontend-v02-7f9b6c5d4-bbb" in body
              and "bo-frontend-6d4b8f9c7d-aaa" not in body)
        check("and it says which node", "on" in body and "talos-02" in body)
        # A text search must not throw away the filter that got you here.
        body = page("&tab=pods&node=talos-02&q=bo")
        check("searching inside a node keeps the node",
              'name="node" value="talos-02"' in body)
        check("and narrows within it",
              "bo-frontend-v02-7f9b6c5d4-bbb" in body and "elsewhere-1" not in body)
        # Both at once, because a deployment spread over ten nodes is exactly when
        # somebody wants "this workload, on that machine".
        body = page("&tab=pods&workload=bo-frontend-v02&node=talos-02")
        check("both filters can be on together",
              body.count('class="pf"') == 2
              and "bo-frontend-v02-7f9b6c5d4-bbb" in body)

        print("a node in the strip goes to the pods on it")
        body = page("&tab=pods")
        strip = re.search(r'<a class="ns-row[^"]*"\s+href="([^"]+)"', body)
        check(f"the strip row links to its own pods ({strip and strip.group(1)[-30:]})",
              strip is not None and "tab=pods" in strip.group(1)
              and "node=" in strip.group(1))
        # It went to the Nodes tab, which is the same table for every node and
        # says nothing about the one that was clicked.
        check("not to the Nodes tab", "tab=nodes" not in (strip.group(1) if strip else ""))
        nodes = page("&tab=nodes")
        check("and the Nodes table's own name does the same",
              re.search(r'<a class="wname" href="[^"]*node=talos-01', nodes) is not None)

        print("a volume is a row with a status, not a name in a warning")
        # A Released volume was a bare name in a strip under the claims table —
        # the one object on the tab that could not be opened, described, or read
        # the class of. And a strip of names is not a list you can act on.
        body = page("&tab=storage&sec=volumes")
        check("the volumes are their own section", "pvc-live" in body)
        check("a stuck one is in the same list", "pvc-orphan" in body)
        check("with its status", ">Released<" in body)
        check("and the reason it is stuck", "its claim was deleted" in body)
        check("and it can be opened like anything else",
              opens(body, "pv", "pvc-orphan"))
        # Sorted so the one that needs somebody is first.
        check("the stuck one is first",
              body.index("pvc-orphan") < body.index("pvc-live"))
        # ...and the old warning strip is a pointer to that row, not a list of
        # names, and only where the row is not already on screen.
        claims = page("&tab=storage")
        check("the claims tab points at it rather than listing it",
              "sec=volumes" in claims and "still holding" in claims)
        check("and the volumes tab does not repeat the warning strip",
              'class="flash err"' not in body)

        print("an ingress says which service serves the host")
        body = page("&tab=network&sec=routes")
        check("the column is there", ">Service<" in body)
        check("and it names the backend", "pay-api:443" in body)
        # Renamed from "Routes": every object in it is an Ingress or an
        # IngressRoute, and "routes" is also what Traefik calls something else.
        check("the tab is called Ingresses", "Ingresses" in body
              and 'card-h">Routes' not in body)

        print("the CRDs are a tab of their own, grouped by API group")
        body = page("&tab=crds")
        check("each definition is listed", "IngressRoute" in body
              and "SealedSecret" in body)
        check("grouped by the API group they arrive under",
              'class="grouphead"' in body and "traefik.io" in body)
        check("with what installed them where that is known", "traefik" in body)
        check("a definition that is not established says so",
              "not established" in body)
        check("and each one can be opened",
              opens(body, "crd", "sealedsecrets.bitnami.com"))
        # A CRD is cluster-scoped: asking for one with a namespace is not a
        # command kubectl accepts.
        check("with no namespace, because a CRD has none",
              'data-ymkind="crd" data-ns=""' in body)

        print("the audit's severities are the filter, and the table fits")
        # The audit is read through clusterview.part("audit") rather than through
        # gathered(), so it needs its own fixture or the tab renders no table at
        # all — and a check that passes against an empty page proves nothing.
        was_part = clusterview.part
        finding = lambda sev, name: {                              # noqa: E731
            "severity": sev, "check": f"{name} check", "group": "workloads",
            "object": f"pay/{name}", "evidence": f"{name} is wrong",
            "remediation": f"fix {name}",
            "source": {"command": f"kubectl get {name}", "field": ".spec"}}
        clusterview.part = lambda sel, what, refresh=False: (
            {"error": "", "at": "just now",
             "totals": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0,
                        "INFO": 0},
             "counted": {"pods": 3, "nodes": 2, "namespaces": 2,
                         "kubelets_read": 2},
             "groups": {"workloads": 3}, "worst_namespaces": [],
             "commands": [("kubectl get pods -A", "to read the pods")],
             "not_visible": [("etcd", "it is not in the API", "read the node")],
             "findings": [finding("CRITICAL", "one"), finding("HIGH", "two"),
                          finding("HIGH", "three")]}
            if what == "audit" else was_part(sel, what, refresh))
        try:
            body = page("&tab=scan")
            check("each severity tile is a link", 'class="sevtile' in body
              and re.search(r'<a class="sevtile[^"]*"\s+href="[^"]*sev=', body)
              is not None)
            check("the findings table does not need sideways scrolling",
                  'class="jenkins fixed-t"' in body)
            # Six min-width columns came to 1175px, and the two you had to scroll to
            # reach were the fix and where the finding came from.
            check("what to do is in the same cell as what was found",
                  "What was found, and what to do" in body)
            check("and the provenance is still on the row",
                  "read from" in body)
            # The filter itself: two HIGH findings and one CRITICAL, so asking
            # for HIGH has to leave the critical one out.
            hi = page("&tab=scan&sev=HIGH")
            check("picking a severity narrows the findings",
                  "two check" in hi and "one check" not in hi)
            check("and says which tile is in force", "sevtile" in hi
                  and "picked" in hi)
            check("a severity that does not exist is ignored rather than obeyed",
                  "one check" in page("&tab=scan&sev=nonsense"))
        finally:
            clusterview.part = was_part

        print("a workload's related resources are a page of their own")
        # The button next to a workload's actions. A page rather than a window:
        # a workload is five to fifteen objects across six kinds, each with its
        # own actions, and that is a list in its own right.
        wl = page("&tab=workloads")
        rel = re.search(r'href="(/clusters/related\?[^"]+)"', wl)
        check(f"every workload row offers it ({rel and rel.group(1)[:44]})",
              rel is not None)
        check("and it says which workload it is for",
              rel is not None and "name=" in rel.group(1)
              and "namespace=" in rel.group(1))
        # The matcher is the service page's, so it needs the namespace bundle.
        was_part = clusterview.part
        clusterview.part = lambda selx, what, refresh=False: (
            {"error": "", "metrics": True, "pods": [
                {"name": "bff-pod-1", "namespace": "pay", "node": "talos-01",
                 "phase": "Running", "problem": "", "healthy": True,
                 "ready": "1/1", "restarts": 0, "age": "3d", "images": ["b:1"],
                 "owner": "ReplicaSet", "workload": "bff", "cpu": None,
                 "mem": None, "qos": "Burstable"},
                {"name": "someone-elses-pod", "namespace": "pay",
                 "node": "talos-01", "phase": "Running", "problem": "",
                 "healthy": True, "ready": "1/1", "restarts": 0, "age": "3d",
                 "images": ["x:1"], "owner": "ReplicaSet",
                 "workload": "other-thing", "cpu": None, "mem": None,
                 "qos": "Burstable"}]}
            if what == "pods" else was_part(selx, what, refresh))
        was_bundle = clusterview.service_bundle
        clusterview.service_bundle = lambda cl, nsx, refresh=False: {
            "error": "", "refused": [{"kind": "secret", "why": "Forbidden"}],
            "items": [
                {"kind": "Deployment",
                 "metadata": {"name": "bff", "namespace": nsx},
                 "spec": {"replicas": 1}, "status": {"readyReplicas": 1}},
                {"kind": "Service", "metadata": {"name": "bff", "namespace": nsx},
                 "spec": {"type": "ClusterIP", "ports": [{"port": 8080}]}},
                {"kind": "ConfigMap",
                 "metadata": {"name": "bff-config", "namespace": nsx},
                 "data": {"A": "1", "B": "2"}},
                # named nothing like the workload, but it routes to its Service —
                # which makes it the workload's ingress by any reading
                {"kind": "Ingress",
                 "metadata": {"name": "api-front", "namespace": nsx},
                 "spec": {"rules": [{"host": "api.example.com", "http": {
                     "paths": [{"backend": {"service": {"name": "bff"}}}]}}]}},
                {"kind": "ConfigMap",
                 "metadata": {"name": "somebody-elses", "namespace": nsx},
                 "data": {"x": "1"}}]}
        try:
            # A manage-enabled cluster: shell and the write verbs are gated on
            # it, and this file's main fixture cluster deliberately is not.
            mrw = store.add_cluster(pid, "related-rw", "apiVersion: v1\n", "ctx7")
            store.update_cluster(pid, mrw, manage="1")
            r = client.get(f"/clusters/related?project={pid}&cluster={mrw}"
                           "&namespace=pay&name=bff&kind=deployment",
                           follow_redirects=False)
            check(f"the page renders ({r.status_code})", r.status_code == 200)
            got = r.text
            for name, why in (("bff-config", "a ConfigMap by name prefix"),
                              ("bff", "the Service of the same name")):
                check(f"it finds {why}", name in got)
            check("an ingress is claimed by what it ROUTES to, not by its name",
                  "api-front" in got and "routes to bff" in got)
            check("every row can be opened as YAML",
                  got.count("data-podyaml") >= 4)
            check("and described", got.count("data-poddesc") >= 4)
            # What is in the namespace and did NOT match is offered rather than
            # hidden: "these are here and I could not tie them to it" is the
            # useful half of the answer when something is missing.
            check("what did not match is still shown, separately",
                  "somebody-elses" in got and "did not match" in got)
            # A kind the credentials cannot read is named, not folded into a
            # single failure.
            check("a kind that was refused says which and why",
                  "secret" in got and "Forbidden" in got)
            # The pods are ON the page now. They are part of what the workload
            # is, and they are the half people come for — sending the reader to
            # another page for that made this an index rather than an answer.
            check("the pods are on the page", "bff-pod-1" in got
                  and 'glyph' not in got.split("Pods")[0][-30:])
            check("and the button that used to send you away is gone",
                  "Its pods" not in got and "in the pods table" not in got)
            check("a pod that is not this workload's is not here",
                  "someone-elses-pod" not in got)
            # Every kind gets the actions it HAS: a pod can be shelled into and
            # deleted, a Deployment restarted and rolled back, a ConfigMap
            # neither.
            check("a pod row offers logs, describe, yaml, shell and delete",
                  "data-podlog" in got and "data-poddesc" in got
                  and 'data-ymkind="pod"' in got and "inspect=shell" in got
                  and 'value="delete-pod"' in got)
            check("a deployment row offers restart and roll back",
                  'value="restart"' in got and 'value="undo"' in got)
            # ...and exactly one of each, so a ConfigMap has not quietly grown a
            # Restart button.
            check(f"only the workload has them ({got.count(chr(34) + 'restart' + chr(34))})",
                  got.count('value="restart"') == 1
                  and got.count('value="undo"') == 1)
            check("and it still links to that workload's pods elsewhere",
                  "tab=pods" in got)
            # The production lock is the same one the cluster page uses, or this
            # page is a way around it. Held by where the code comes from: both
            # pages import _cluster_actions.html and neither defines the macros
            # itself, so the lock cannot hold on one and not the other.
            check("the confirm and the lock are on this page too",
                  "function confirmAct" in got and "function unlock" in got)
            shared = (ROOT / "templates" / "_cluster_actions.html").read_text()
            check("the machinery is defined once", "macro act_button" in shared
                  and "prodconfirm" in shared and "function unlock" in shared)
            for tpl in ("clusters.html", "cluster_related.html"):
                src = (ROOT / "templates" / tpl).read_text()
                check(f"{tpl} imports it rather than copying it",
                      "_cluster_actions.html" in src
                      and "macro act_button" not in src
                      and "function unlock" not in src)
            check("and every action comes back to this page",
                  got.count('name="back" value="/clusters/related') >= 2)
        finally:
            clusterview.service_bundle = was_bundle
            clusterview.part = was_part

        print("every link the strip draws actually opens")
        # This is the check that was missing, and it cost a user two broken tabs:
        # every request in this file was a URL the TEST built, so a strip whose
        # own hrefs were malformed passed everything. The separator between the
        # base and the parameter was assumed to be `&`, which is right only for a
        # base that already carries a query string.
        for tab in ("workloads", "network", "storage", "events"):
            body = page(f"&tab={tab}")
            links = stab_hrefs(body)
            check(f"the {tab} strip drew links ({len(links)})", len(links) >= 2)
            for href in links:
                got = client.get(href, follow_redirects=False)
                check(f"following {href.split('&', 2)[-1]} → HTTP {got.status_code}",
                      got.status_code == 200)

        print("the namespace comes with you when you change tab")
        # The bar at the top of the page says the choice "survives the tab you
        # move to". Every tab link dropped it, so preprod → Workloads → Pods
        # silently widened back to the whole cluster while the picker still read
        # preprod. Checked on the strip itself, for every tab, because one link
        # written by hand is how it broke.
        body = page("&tab=pods&ns=pay")
        links = re.findall(r'<a href="([^"]+)"\s+class="vtab', body)
        check(f"the strip has a link per tab ({len(links)})",
              len(links) == len(clusterview.TABS))
        keep = [l for l in links if "ns=pay" in l]
        check(f"and every one of them keeps the namespace ({len(keep)})",
              len(keep) == len(links))
        check("the picker's clear link is still there to widen it deliberately",
              "nsbar-clear" in body)
        # ...and the tabs that hold a namespaced list have to honour it, or the
        # filter is a label rather than a filter.
        check("pods are narrowed", "pay-db-0" in body and "elsewhere-1" not in body)
        wide = page("&tab=pods")
        check("and not narrowed when nothing is chosen", "elsewhere-1" in wide)
        check("workloads are narrowed",
              "elsewhere" not in page("&tab=workloads&ns=pay"))
        check("services are narrowed",
              "other-svc" not in page("&tab=network&ns=pay"))
        check("claims are narrowed",
              "pay-data" in page("&tab=storage&ns=pay"))
        check("events are narrowed",
              "back-off restarting" not in page("&tab=events&sec=recent&ns=other"))
        # Storage classes are cluster-scoped: there is nothing to narrow them by,
        # so they stay whole and the header has to say that rather than looking
        # like a filter that did not work.
        classes = page("&tab=storage&sec=classes&ns=pay")
        check("a cluster-scoped list stays whole", "local-path" in classes)
        check("and says why the filter does not apply to it",
              "cluster-wide" in flat(classes))

        print("a control that is not allowed is disabled, never absent")
        # Troubleshoot vanished on a read-only cluster while every other
        # management control on the same page rendered disabled with its reason.
        # A button that is simply gone reads as a button that broke.
        ro = store.add_cluster(pid, "read-only-one", "apiVersion: v1\n", "ctx9")
        rob = client.get(f"/clusters?project={pid}&cluster={ro}&tab=pods").text
        at = rob.find('id="tsBtn"')
        check("the button is still on a read-only cluster's page", at > -1)
        frag = re.sub(r"\s+", " ", rob[at:at + 320])
        check(f"and disabled ({frag[:40]})", "disabled" in frag)
        check("with the reason and where to change it",
              "read-only" in frag and "Settings" in frag)
        # The modal it opens does not belong on a page that cannot use it, and the
        # script has to survive the button existing without it.
        check("the dialog it opens is not carried on that page",
              'id="tsDlg"' not in rob)
        # A cluster of its own for the other half: the fixture cluster above is
        # deliberately NOT manage-enabled, which is what every other check in
        # this file reads.
        rw = store.add_cluster(pid, "manageable-one", "apiVersion: v1\n", "ctx8")
        store.update_cluster(pid, rw, manage="1")
        wb = client.get(f"/clusters?project={pid}&cluster={rw}&tab=pods").text
        check("a cluster that allows management gets the live button",
              'id="tsBtn"' in wb and 'id="tsDlg"' in wb)
        check("and it is not disabled there",
              "disabled" not in re.sub(r"\s+", " ",
                                       wb[wb.find('id="tsBtn"'):][:140]))

        print("closing the kubectl console comes back where it was opened from")
        # The console is a page, not a window over one, so closing it navigates —
        # and it navigated to Overview with no namespace, throwing away both the
        # tab you were on and the filter you had set. Every way out of it (the
        # close link, the ✕ dot that clicks that link, typing `exit`, and Esc)
        # goes through one destination now.
        body = page("&tab=pods&ns=pay")
        shell_link = next((h for h in
                           re.findall(r'<a href="([^"]+)"\s+class="vtab', body)
                           if "tab=shell" in h), "")
        check(f"the shell tab link says where it came from ({shell_link[-30:]})",
              "from_tab=pods" in shell_link and "ns=pay" in shell_link)
        shell = page(shell_link.replace("&amp;", "&").replace(
            f"/clusters?project={pid}&cluster={cid}", ""))
        # One destination, and the namespace is in it.
        raw = set(re.findall(r'const KSH_BACK = ("[^"]+")', shell))
        check(f"the console has one place to go back to ({raw})", len(raw) == 1)
        back = json.loads(raw.pop()) if raw else ""
        check(f"which is the tab it came from ({back[-34:]})", "tab=pods" in back)
        check("with the namespace kept", "ns=pay" in back)
        check("the close link points at it, so a middle-click works too",
              f'href="{back.replace("&", "&amp;")}"' in shell)
        # Nothing may still hardcode Overview: that was the bug, in three places.
        check("and no exit path goes to Overview behind its back",
              "&tab=overview" not in shell.replace("&amp;", "&")
              .split("const KSH_BACK")[-1])
        # Opened from the top bar there is no `from_tab`, so the fallback is this
        # cluster's Overview — but it still has to carry the namespace.
        plain = page("&tab=shell&ns=pay")
        plainback = re.search(r'const KSH_BACK = ("[^"]+")', plain)
        plainurl = json.loads(plainback.group(1)) if plainback else ""
        check(f"opened from anywhere, it keeps the namespace ({plainurl[-24:]})",
              "ns=pay" in plainurl and "tab=overview" in plainurl)

        print("every resource on the page can be opened")
        # A row is an object in a cluster, and the reason to look at one is
        # usually to read or fix its YAML. These were the six that had no way in.
        check("a service opens", opens(page("&tab=network"), "service", "pay-api"))
        check("a route opens as the CRD kubectl knows, not the label",
              opens(page("&tab=network&sec=routes"), "ingressroute", "pay-route"))
        check("a certificate opens",
              opens(page("&tab=network&sec=certs"), "certificate", "api-tls"))
        check("a volume claim opens", opens(page("&tab=storage"), "pvc", "pay-data"))
        check("a storage class opens, with no namespace to give it",
              opens(page("&tab=storage&sec=classes"), "storageclass", "local-path"))
        check("a node opens", opens(page("&tab=nodes"), "node", "talos-01"))
        # An Event is a record that expires; what a reader wants from a warning is
        # the object it is about.
        check("an event opens the object it is about",
              opens(page("&tab=events&sec=recent"), "pod", "pay-db-0"))
        # ...and the two that were already there must not have been disturbed.
        check("a pod still opens", opens(page("&tab=pods"), "pod", "pay-db-0"))
        check("a workload still opens",
              opens(page("&tab=workloads"), "statefulset", "pay-db"))

    print("which workload a pod belongs to is read off its owner")
    # The page checks above are driven by a fixture that supplies `workload`
    # ready-made, so they cannot see this being derived wrongly. It is the part
    # that has to be exact: a ReplicaSet's name is its Deployment's plus a hash,
    # and getting that wrong is how bo-frontend claims bo-frontend-v02's pods.
    for owners, want, why in (
            ([{"kind": "ReplicaSet", "name": "bo-frontend-6d4b8f9c7d"}],
             "bo-frontend", "a replica set's hash comes off"),
            ([{"kind": "ReplicaSet", "name": "bo-frontend-v02-7f9b6c5d4"}],
             "bo-frontend-v02", "and only the hash — the -v02 stays"),
            ([{"kind": "StatefulSet", "name": "pay-db"}], "pay-db",
             "a StatefulSet owns its pods under its own name"),
            ([{"kind": "DaemonSet", "name": "node-exporter"}], "node-exporter",
             "so does a DaemonSet"),
            ([{"kind": "Job", "name": "sweep-28123"}], "sweep-28123",
             "and a Job, whose name ends in digits that are not a hash"),
            ([{"kind": "ReplicaSet", "name": "nohyphenhash"}], "nohyphenhash",
             "a name with nothing to strip is left alone"),
            ([], "", "and a bare pod belongs to nothing")):
        got = clusterview._workload_of(owners)
        check(f"{why} ({got!r})", got == want)
    # "" must never behave like a wildcard: a bare pod under a workload filter is
    # a pod that does not match, not one that matches everything.
    check("a bare pod is not swept up by a filter",
          clusterview._workload_of([]) != "bo-frontend")

    print("the diagram is a way into the cluster, not a picture beside it")
    from app import diagram
    topo = {"cluster": "c", "namespaces": ["pay"],
            "nodes": {"total": 2, "ready": 2, "cp": 0, "workers": 2},
            "vips": [{"ip": "10.0.6.16", "namespace": "traefik", "name": "traefik"}],
            "ingress": [{"host": "api.example.com", "backends": ["bff"]}],
            "workloads": [
                {"name": "bff", "namespace": "pay", "ready": 1, "desired": 1,
                 "healthy": True, "kind": "Deployment"},
                {"name": "gw", "namespace": "pay", "ready": 3, "desired": 5,
                 "healthy": False, "kind": "Deployment"}],
            "data": [{"label": "Temporal", "count": 6, "healthy": True,
                      "namespaces": ["temporal"]}],
            "external": [{"host": "sandbox.example.com", "kind": "provider",
                          "used_by": ["gw"]}]}
    art = diagram.render(topo, base="/clusters?project=p1&cluster=c1")
    # Every box is addressable and every edge names its two ends: that pairing is
    # what lets the drawing light one path at a time, and it is the whole
    # interaction. Without the ids it is a static picture again.
    check(f"every box carries an id ({art.count('data-id=')})",
          art.count("data-id=") >= 6)
    check("every edge names both of its ends",
          art.count("data-a=") == art.count("data-b=") >= 4)
    check("and the ids the edges name are boxes that exist",
          all(f'data-id="{i}"' in art for i in
              re.findall(r'data-a="([^"]+)"', art)))
    # A workload box opens ITS pods, through the same filter the table uses.
    check("a workload box opens its own pods",
          "tab=pods&amp;ns=pay&amp;workload=gw" in art
          or "tab=pods&ns=pay&workload=gw" in art)
    check("an in-cluster dependency opens the namespace behind it",
          "ns=temporal" in art)
    # A third-party host has no page here, and a box that pretends to lead
    # somewhere is worse than one that plainly does not.
    check("a third-party host stays inert",
          "sandbox.example.com" in art
          and "sandbox.example.com</text></a>" not in art)
    check("the state of a workload is a dot, not only a border colour",
          'class="dot"' in art)
    check("hovering is what lights a path, so the rules are in the drawing",
          ".dg-lit" in art and "mouseenter" in art)
    check("and it is keyboard reachable", 'tabindex="0"' in art
          and "focusin" in art)
    # A page with no cluster to link into draws the same picture, inert.
    plain = diagram.render(topo)
    check("without a base URL nothing is a link", "<a href" not in plain)
    check("but it is still the same drawing",
          plain.count('class="dbox"') == art.count('class="dbox"'))

    print("the network part keeps every service, not only the published ones")
    # The page fixture above supplies services ready-made, so it cannot see what
    # the collector drops. This drives _part_network itself: kubectl's own answer
    # in, rows out. The dropped ClusterIP was the user-visible fault — "where are
    # my services" — and it was one `continue`.
    def fake_get(cluster, *args, **kw):
        what = args[0] if args else ""
        if what == "svc":
            return {"items": [
                {"metadata": {"name": "front", "namespace": "pay"},
                 "spec": {"type": "LoadBalancer", "clusterIP": "10.96.0.1",
                          "ports": [{"port": 443, "protocol": "TCP"}]},
                 "status": {"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}},
                {"metadata": {"name": "waiting", "namespace": "pay"},
                 "spec": {"type": "LoadBalancer", "clusterIP": "10.96.0.2",
                          "ports": [{"port": 80}]},
                 "status": {"loadBalancer": {}}},
                {"metadata": {"name": "inside", "namespace": "pay"},
                 "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.3",
                          "ports": [{"port": 8080}]}, "status": {}},
                {"metadata": {"name": "headless", "namespace": "pay"},
                 "spec": {"type": "ClusterIP", "clusterIP": "None",
                          "ports": [{"port": 5432}]}, "status": {}},
                {"metadata": {"name": "nodeport", "namespace": "pay"},
                 "spec": {"type": "NodePort", "clusterIP": "10.96.0.4",
                          "ports": [{"port": 80, "nodePort": 31000}]},
                 "status": {}}]}
        if what == "ingressroute":
            return {"items": [
                {"metadata": {"name": "r1", "namespace": "pay"},
                 "spec": {"routes": [
                     {"match": "Host(`api.example.com`)",
                      "services": [{"name": "front", "port": 443}]}],
                          "entryPoints": ["websecure"], "tls": {}}}]}
        if what == "ingress":
            return {"items": [
                {"metadata": {"name": "in1", "namespace": "pay"},
                 "spec": {"rules": [{"host": "www.example.com", "http": {
                     "paths": [{"backend": {"service": {
                         "name": "inside", "port": {"number": 8080}}}}]}}],
                          "defaultBackend": {"service": {"name": "fallback"}}}}]}
        return {"items": []}

    was_get = clusterview._get
    clusterview._get = fake_get
    try:
        got = clusterview._part_network({"id": "c1"})
    finally:
        clusterview._get = was_get
    names = [s["name"] for s in got["services"]]
    check(f"every service survives the read ({names})", len(names) == 5)
    check("including a plain ClusterIP", "inside" in names)
    check("and a headless one", "headless" in names)
    published = {s["name"] for s in got["services"] if s["published"]}
    check(f"published means reachable from outside ({sorted(published)})",
          published == {"front", "nodeport"})
    check("a load balancer with no address yet is pending, not published",
          next(s for s in got["services"] if s["name"] == "waiting")["pending"]
          and "waiting" not in published)
    check(f"the published ones sort first ({names[:2]})",
          set(names[:2]) == {"front", "nodeport"})
    # ...and the load balancer somebody is waiting on leads the rest, ahead of
    # the internal services: it is the row with something happening to it.
    check(f"then the pending load balancer ({names[2]})", names[2] == "waiting")
    # Which Service each ingress sends traffic to, read from the object. The host
    # is only half of what an ingress says, and the other half took opening the
    # YAML to find. Both shapes, because a cluster running Traefik has both.
    byname = {r["name"]: r for r in got["routes"]}
    check(f"an Ingress names its backend service "
          f"({byname.get('in1', {}).get('services')})",
          "inside:8080" in (byname.get("in1", {}).get("services") or []))
    check("including a default backend",
          "fallback:default" in (byname.get("in1", {}).get("services") or []))
    check(f"and an IngressRoute names its own "
          f"({byname.get('r1', {}).get('services')})",
          "front:443" in (byname.get("r1", {}).get("services") or []))

    # The route's kubectl kind travels with it, or its yaml button asks the API
    # server for something called "ingressroute" spelled as the label.
    check(f"a route carries the kind kubectl knows "
          f"({byname.get('r1', {}).get('api')})",
          byname.get("r1", {}).get("api") == "ingressroute")
    check("and the label a person reads stays separate",
          byname.get("r1", {}).get("kind") == "IngressRoute")
    check("an Ingress carries its own, which is not the CRD's",
          byname.get("in1", {}).get("api") == "ingress")

    print("a cluster-scoped object is asked for without a namespace")
    # The rows for a node and a storage class carry an empty namespace, and
    # `kubectl get storageclass local-path -n ''` is not a command. Checked at the
    # argv, because the alternative is finding out from a live cluster.
    import subprocess as _sp
    from app import kmanage
    seen = {}

    class Fake:
        returncode, stdout, stderr = 0, "apiVersion: v1\nkind: StorageClass\n", ""

    def spy(argv, **kw):
        seen["argv"] = argv
        return Fake()

    was_run, kmanage.subprocess.run = kmanage.subprocess.run, spy
    try:
        cl = {"id": "c1", "kubeconfig_file": "/dev/null", "context": "ctx1"}
        kmanage.read_yaml(cl, "storageclass", "local-path", "")
        wide = list(seen["argv"])
        kmanage.read_yaml(cl, "service", "pay-api", "pay")
        narrow = list(seen["argv"])
    finally:
        kmanage.subprocess.run = was_run
    check(f"no -n for a cluster-scoped kind ({' '.join(wide[-4:])})",
          "-n" not in wide and "storageclass" in wide and "local-path" in wide)
    check(f"and -n for a namespaced one ({' '.join(narrow[-4:])})",
          narrow[narrow.index("-n") + 1] == "pay")

    print("the strip is a component, styled once")
    css = re.sub(r"/\*.*?\*/", "",
                 (ROOT / "templates" / "base.html").read_text()
                 + (ROOT / "static" / "app.css").read_text(),
                 flags=re.S)
    for rule in (".subtabs", ".stab", ".stab.on", ".stab.quiet", ".stab .n"):
        check(f"{rule} has a rule of its own",
              re.search(re.escape(rule) + r"\s*[,{]", css) is not None)
    # A rail under a rail reads as one strip that wrapped, and then neither
    # selected tab can be found. The two levels have to look like two levels.
    subtabs = re.search(r"\.subtabs\s*\{([^}]*)\}", css)
    check("the sub-strip is not a second underlined rail",
          subtabs is not None and "border-bottom:1px" not in subtabs.group(1))

    print("a tab whose sections are one section draws no strip")
    # An estate with nothing deployed would otherwise get a strip holding one
    # tab reading "All kinds 0", which is furniture, not a choice.
    one = appmain.templates.env.from_string(
        '{% import "_bits.html" as bits %}'
        "{{ bits.subtabs('/x', 'k', '', tabs) }}")
    check("nothing is drawn for one item",
          one.render(tabs=clusterview.kind_tabs([])).strip() == "")
    check("but two draw a strip", "subtabs" in one.render(
        tabs=clusterview.kind_tabs([{"kind": "Deployment"}])))

    print("the workloads tab no longer pays for a read it does not show")
    # The applications table moved to the GitOps page; the read stayed behind.
    check("argocd is not gathered for workloads",
          "argocd" not in clusterview.NEEDS["workloads"])
    check("and the overview, which does show it, still asks",
          "argocd" in clusterview.NEEDS["overview"])

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
