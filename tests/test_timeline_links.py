#!/usr/bin/env python3
"""A Timeline row opens inside EnvMap, never in the system it came from.

Asked for on 25 November 2026: "when I click on something in the timeline,
for example the pipeline, it should take me to the pipeline inside EnvMap,
not the Jenkins page — and this applies to all items in the timeline".

Before this, a build's title was Jenkins' own address, a deployment's Argo
CD's, an alert's Grafana's and a scan's DefectDojo's, all opening in a new
tab; commits, portal actions and cluster events linked nowhere; and a
certificate linked to /certs/<id>, a page that does not exist.

Checks, every source driven through its real fetcher with its system faked:
  1. each row's link is a page of this portal, with what that page needs to
     show that one item (the pipeline's own row, the application, the
     cluster's events in that namespace, the audit log narrowed to it, …)
  2. the system's own page is kept as the row's second link, named after the
     system ("Jenkins ↗"), and only an http(s) address is ever offered there
  3. the rendered page: every title opens in this tab, inside the portal;
     only the system links open a new tab
  4. every one of those links answers, and the certificate one in particular
     (the old /certs/<id> does not)

    ./.venv/bin/python tests/test_timeline_links.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("tllinks-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

FAILED: list[str] = []


def check(what: str, ok) -> None:
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        FAILED.append(what)


def parts(url: str) -> tuple[str, dict]:
    u = urllib.parse.urlsplit(url)
    return u.path, dict(urllib.parse.parse_qsl(u.query))


def main() -> int:
    from fastapi.testclient import TestClient
    from app import (auth, certs, ci, cluster as clusterview, db, git_ops,
                     gitops, main as portal, monitoring, security, store,
                     timeline, workflows)

    now = datetime.now()
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    dead = "http://127.0.0.1:9"            # a closed port: refused at once

    cid_ci = store.add_conn("ci", "", {"type": "jenkins", "name": "jenkins-main",
                                       "base_url": dead})
    cid_go = store.add_conn("gitops", "", {"type": "argocd", "name": "argo-prod",
                                           "base_url": dead})
    cid_mon = store.add_conn("mon", "", {"type": "alertmanager", "name": "am-prod",
                                         "base_url": dead})
    cid_sec = store.add_conn("sec", "", {"type": "defectdojo", "name": "dojo",
                                         "base_url": dead})
    cid_wf = store.add_conn("wf", "", {"type": "temporal", "name": "temporal-1",
                                       "base_url": dead})
    cid_af = store.add_conn("wf", "", {"type": "airflow", "name": "airflow-1",
                                       "base_url": dead})

    ci.fetch = lambda c, refresh=False: {"jobs": [{
        "name": "payments · deploy", "number": 412, "status": "failed",
        "branch": "main", "started_at": stamp, "ref": "payments/deploy#412",
        "url": "https://jenkins.example.com/job/payments/job/deploy/412/",
        "health": 80, "duration": "4m 2s", "views": [], "branches": ["main"],
        "last_success": {"when": "2 hours ago", "number": 411},
        "last_failure": {"when": "5 minutes ago", "number": 412}}],
        "views": []}
    gitops.apps = lambda c, refresh=False: [{
        "name": "billing-api", "dest": "billing", "revision": "a1b2c3d",
        "op_phase": "Succeeded", "op_message": "", "when": stamp,
        "url": "https://argo.example.com/applications/billing-api",
        "sync": "Synced", "health": "Healthy", "project": "default",
        "repo": "", "path": ""}]
    monitoring.alerts = lambda c, refresh=False: [{
        "name": "KubePodCrashLooping", "severity": "critical", "at": stamp,
        "summary": "pod crash looping", "source": "prod",
        "url": "https://grafana.example.com/alerting/list"}]
    security.scans = lambda c, refresh=False: [{
        "name": "ZAP Scan", "iso": stamp, "product": "web", "engagement": "weekly",
        "url": "https://dojo.example.com/test/77"}]
    temporal = {"groups": [{
        "name": "orders", "href": f"/workflows/{cid_wf}/orders", "rows": [{
            "name": "OrderSaga", "state": "Failed", "at": stamp, "kind": "OrderSaga",
            "href": f"/workflows/{cid_wf}/orders/run?id=w1&run=r1",
            "url": "https://temporal.example.com/namespaces/orders/workflows/w1"}],
        "running": 0, "failed": 1}], "unit": "namespace", "running": 0, "failed": 1}
    airflow = {"groups": [{"name": "DAGs", "note": "", "rows": [{
        "name": "nightly_etl", "kind": "etl", "state": "Failed", "when": "5m",
        "at": stamp, "extra": "@daily",
        "url": "https://airflow.example.com/dags/nightly_etl/grid"}],
        "running": 0, "failed": 1}], "unit": "DAG", "running": 0, "failed": 1}
    workflows.overview = lambda c, refresh=False: (
        airflow if c.get("type") == "airflow" else temporal)

    def everywhere(part, refresh=False):
        row = {"pid": "p-shop", "project": "Shop", "cid": "c-prod", "cluster": "prod",
               "error": ""}
        if part == "events":
            return [{**row, "events": [{
                "type": "Warning", "reason": "BackOff", "namespace": "payments",
                "object": "pod/pay-1", "message": "back-off restarting", "count": 3,
                "when": stamp}]}]
        if part == "argocd":
            return [{**row, "present": True, "apps": [{
                "name": "ledger", "dest": "ledger", "revision": "f00d", "phase": "Succeeded",
                "sync": "Synced", "health": "Healthy", "when": stamp}]}]
        return []
    clusterview.everywhere = everywhere
    timeline._any_cluster = lambda: True      # the fake clusters above are its only ones
    real_orders = certs.orders
    certs.orders = lambda: [{"id": "ord-9", "name": "api.example.com", "ca": "Lets",
                             "status": "ready", "updated_at": stamp, "note": ""}]
    auth.audit({"email": "ops@test.local"}, "cluster-drain", "node-3", "before patching")

    email, pw = "tl@test.local", "Timeline-Opens-At-Home-42"
    uid = auth.create_user(email, "Tl", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    me = auth.get_user(uid) if hasattr(auth, "get_user") else {"id": uid, "role": "admin",
                                                                  "email": email}

    timeline.invalidate()
    got = timeline.collect(me, hours=2)
    by = {}
    for e in got["events"]:
        by.setdefault(e["kind"], []).append(e)
    print("Every row opens inside EnvMap")
    check(f"every source answered: {sorted(by)}",
          {"build", "deploy", "event", "alert", "flow", "scan", "cert", "action"} <= set(by))
    check("no row links outside the portal",
          all(e["url"].startswith("/") for e in got["events"] if e["url"]))
    check("every row has a link", all(e["url"] for e in got["events"]))

    b = by["build"][0]
    path, q = parts(b["url"])
    check(f"a build opens its pipeline on the Pipelines page: {b['url']}",
          path == "/pipelines" and q == {"provider": "jenkins", "conn": cid_ci,
                                         "q": "payments · deploy",
                                         "open": "payments/deploy#412"})
    check("and Jenkins is the second link", b["ext"].startswith("https://jenkins.example.com/")
          and b["ext_label"] == "Jenkins")

    regd = next(e for e in by["deploy"] if e["what"] == "billing-api")
    check(f"a deployment opens its application on the GitOps page: {regd['url']}",
          parts(regd["url"]) == ("/gitops/app", {"conn": cid_go, "name": "billing-api"})
          and regd["ext"].startswith("https://argo.example.com/") and regd["ext_label"] == "Argo CD")
    clus = next(e for e in by["deploy"] if e["what"] == "ledger")
    check(f"one read off a cluster opens what it deployed: {clus['url']}",
          parts(clus["url"]) == ("/clusters", {"project": "p-shop", "cluster": "c-prod",
                                               "tab": "workloads", "ns": "ledger"})
          and not clus["ext"])
    ev = by["event"][0]
    check(f"a cluster event opens the cluster's events in its namespace: {ev['url']}",
          parts(ev["url"]) == ("/clusters", {"project": "p-shop", "cluster": "c-prod",
                                             "tab": "events", "ns": "payments"}))
    al = by["alert"][0]
    check(f"an alert opens the firing list narrowed to it: {al['url']}",
          parts(al["url"]) == ("/monitoring", {"platform": "alertmanager", "conn": cid_mon,
                                               "sec": "firing", "q": "KubePodCrashLooping"})
          and al["ext_label"] == "Alertmanager")
    fl = next(e for e in by["flow"] if e["what"] == "OrderSaga")
    dag = next(e for e in by["flow"] if e["what"] == "nightly_etl")
    check(f"an Airflow DAG, which has no page here, is marked in its engine's list: {dag['url']}",
          parts(dag["url"]) == ("/workflows", {"sec": "namespaces",
                                               "open": f"{cid_af}/nightly_etl"})
          and dag["ext_label"] == "Apache Airflow")
    check(f"a workflow run opens its run page: {fl['url']}",
          fl["url"] == f"/workflows/{cid_wf}/orders/run?id=w1&run=r1"
          and fl["ext"].startswith("https://temporal.example.com/") and fl["ext_label"] == "Temporal")
    sc = by["scan"][0]
    check(f"a scan opens the platform's recent scans: {sc['url']}",
          parts(sc["url"]) == ("/security", {"platform": "defectdojo", "conn": cid_sec,
                                             "tab": "scans"})
          and sc["ext_label"] == "DefectDojo")
    ce = by["cert"][0]
    check(f"a certificate opens its order: {ce['url']}",
          parts(ce["url"]) == ("/certs", {"id": "ord-9"}))
    ac = next(e for e in by["action"] if e["what"] == "cluster-drain")
    day = now.strftime("%Y-%m-%d")
    check(f"a portal action opens the audit log narrowed to it: {ac['url']}",
          parts(ac["url"]) == ("/admin/audit", {"action": "cluster-drain",
                                                "user": "ops@test.local",
                                                "since": day, "until": day}))

    print("A commit opens its environment's GitOps repository")
    real = store.cluster_for_env
    store.cluster_for_env = lambda pid, rgid, env: {"id": "c-prod"}
    check("on the cluster serving it",
          parts(timeline._config_page("p-shop", "eu", "prod"))
          == ("/clusters", {"project": "p-shop", "cluster": "c-prod", "tab": "config",
                            "env": "prod"}))
    store.cluster_for_env = lambda pid, rgid, env: None
    check("or on the environment's own page when none is mapped",
          timeline._config_page("p-shop", "eu", "pre prod") == "/p/p-shop/eu/pre%20prod?stay=1")
    store.cluster_for_env = real

    print("Only safe addresses")
    e = timeline._ev(now, "build", "x", url="https://jenkins.example.com/x",
                     ext="javascript:alert(1)")
    check("an outside address is never the row's own link", e["url"] == "")
    check("and a script address is never the system link", e["ext"] == "")

    print("The page")
    c = TestClient(portal.app, raise_server_exceptions=False)
    with c:
        c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
               follow_redirects=False)
        timeline.invalidate()
        page = c.get("/timeline?hours=2").text
        titles = re.findall(r'<div class="tl-title">\s*<a href="([^"]*)"([^>]*)>', page)
        check(f"every title is a link inside the portal ({len(titles)})",
              len(titles) >= 9 and all(h.startswith("/") for h, _ in titles))
        check("and opens in this tab", not any("_blank" in rest for _h, rest in titles))
        exts = re.findall(r'<a class="tl-ext" href="([^"]*)" target="_blank" rel="noopener"\s*'
                          r'title="[^"]*">([^<]*)</a>', page)
        check(f"the systems' own pages are the second links: {[t for _h, t in exts]}",
              {"Jenkins ↗", "Argo CD ↗", "Alertmanager ↗", "Temporal ↗", "DefectDojo ↗"}
              <= {t for _h, t in exts})
        # the pages themselves read the real order list: the fake above has
        # only the fields the timeline reads
        certs.orders = real_orders
        for e in got["events"]:
            if e["kind"] in ("deploy",) and e["url"].startswith("/gitops/app"):
                continue        # reads the controller itself; covered by its own tests
            r = c.get(e["url"].replace("&amp;", "&"), follow_redirects=False)
            check(f"{e['kind']}: {e['url'][:70]} answers ({r.status_code})",
                  r.status_code in (200, 303))
        wf = c.get(dag["url"]).text
        check("and the Workflows page has that row to mark",
              f'data-wfrow="{cid_af}/nightly_etl"' in wf and "wf-target" in wf)
        check("the certificate page is /certs?id=, and the old /certs/<id> was never one",
              c.get("/certs?id=ord-9").status_code == 200
              and c.get("/certs/ord-9").status_code in (404, 405))

    print("OK" if not FAILED else f"{len(FAILED)} FAILED")
    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
