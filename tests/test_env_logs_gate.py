#!/usr/bin/env python3
"""A pod's logs read through an ENVIRONMENT still belong to its cluster.

WHY THIS EXISTS
    The environment pages live under /p/, which the Configuration area
    governs, and they reach into the cluster serving the environment: a pod's
    log page, its live log stream, its container list, and the pods and drawing
    tabs. None of that asked for Clusters, so a role given only the values
    files — or one pinned to OTHER clusters — read this cluster's logs through
    the environment beside it, while the cluster's own pages refused the same
    logs.

    So the same reads are asked for here three ways: by a role holding only
    Configuration (refused: it lacks the whole area), by a role pinned to one
    cluster (that cluster's environment opens, the other's is refused), and by
    an administrator (both open). Every reader is a spy that records whether it
    was reached — a refusal that still read the log first is no refusal.

    ./.venv/bin/python tests/test_env_logs_gate.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("envlogs-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, kube, logs, main, rbac, repo, store, topology  # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P = store.add_project("Envs")
RG = store.add_region(P, "Main")
A = store.add_cluster(P, "alpha", "apiVersion: v1\n", "ctx-a")
B = store.add_cluster(P, "beta", "apiVersion: v1\n", "ctx-b")
store.map_env_cluster(P, RG, "dev", A)
store.map_env_cluster(P, RG, "qa", B)

READ: list = []


def _reader(name, answer):
    def fn(cluster, *a, **k):
        READ.append((name, (cluster or {}).get("name")))
        return answer
    return fn


logs.containers_of = _reader("containers_of", ["main"])
logs.snapshot = _reader("snapshot", "a line of log")
logs.stream = _reader("stream", iter([logs.sse("log", ["a line of log"])]))
kube.get_pods = _reader("get_pods", {"pods": [], "error": ""})


def _drawn(pid, rgid, env, cluster, namespaces):
    READ.append(("topology", (cluster or {}).get("name")))
    return {"error": "drawn"}


topology.collect = _drawn
# The pods tab asks the values files which namespaces the environment uses;
# answering here keeps the fixture free of a checkout.
repo.namespaces = lambda pid, rgid, env: ["default"]


def signed_in(email: str, role: str = "user", areas=(), clusters=()):
    uid = auth.create_user(email, "U", "Passw0rd!xY-envs", role=role)
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    if areas:
        rbac.set_for_user(uid, [rbac.save("", email, "", list(areas), [],
                                          list(clusters))])
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Passw0rd!xY-envs"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def denials() -> int:
    return (db.one("SELECT COUNT(*) AS n FROM audit WHERE action = "
                   "'scope_denied'") or {"n": 0})["n"]


def doors(env: str) -> list:
    base = f"/p/{P}/{RG}/{env}"
    return [f"{base}/logs/default/web-1", f"{base}/containers/default/web-1",
            f"{base}/logstream/default/web-1"]


def main_test() -> int:
    cfg = signed_in("config-only@test.invalid", areas=["config"])
    pin = signed_in("pinned-alpha@test.invalid",
                    areas=["config", "clusters"], clusters=[A])
    admin = signed_in("admin-envs@test.invalid", role="admin")

    print("Configuration alone does not read a cluster's logs")
    READ.clear()
    before = denials()
    for path in doors("dev"):
        r = cfg.get(path, follow_redirects=False)
        check(f"{path.split('/')[5]} → {r.status_code}", r.status_code == 403)
        check(f"{path.split('/')[5]} says the area is what is missing",
              "Clusters" in r.text and "outside" not in r.text)
    check(f"and nothing was read from the cluster ({READ})", READ == [])
    check("each refusal is audited", denials() == before + 3)
    r = cfg.get(doors("dev")[1], follow_redirects=False)
    check("the container list refuses as JSON",
          r.json().get("error") == "your roles do not include Clusters")

    print("a role pinned to one cluster reads that environment, not the other")
    READ.clear()
    for path in doors("dev"):
        r = pin.get(path, follow_redirects=False)
        check(f"{path.split('/')[5]} for its own cluster → {r.status_code}",
              r.status_code == 200)
    check(f"and the reads went to that cluster ({READ})",
          READ and all(c == "alpha" for _n, c in READ))
    READ.clear()
    for path in doors("qa"):
        r = pin.get(path, follow_redirects=False)
        check(f"{path.split('/')[5]} for the other cluster → {r.status_code}",
              r.status_code == 403)
    check(f"without reading it ({READ})", READ == [])

    print("an administrator reads both")
    READ.clear()
    for env in ("dev", "qa"):
        for path in doors(env):
            r = admin.get(path, follow_redirects=False)
            check(f"{env} {path.split('/')[5]} → {r.status_code}",
                  r.status_code == 200)
    check(f"from both clusters ({sorted(set(READ))})",
          {c for _n, c in READ} == {"alpha", "beta"})

    print("the environment page's pods and drawing say so in place")
    for tab, reader in (("pods", "get_pods"), ("diagram", "topology")):
        READ.clear()
        r = cfg.get(f"/p/{P}/{RG}/dev?stay=1&tab={tab}", follow_redirects=False)
        check(f"the {tab} tab still renders its page ({r.status_code})",
              r.status_code == 200)
        check(f"and says why it shows nothing ({tab})",
              "your roles do not include Clusters" in r.text)
        check(f"without reading the cluster ({READ})", READ == [])
        r = pin.get(f"/p/{P}/{RG}/qa?stay=1&tab={tab}", follow_redirects=False)
        check(f"a pinned role sees the other cluster's {tab} refused in place",
              "outside what your roles may reach" in r.text and READ == [])
        r = pin.get(f"/p/{P}/{RG}/dev?stay=1&tab={tab}", follow_redirects=False)
        check(f"and its own cluster's {tab} read ({READ})",
              READ == [(reader, "alpha")])

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
