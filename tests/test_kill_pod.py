#!/usr/bin/env python3
"""Killing one pod so that it does not come back (`kmanage.kill_pod`).

WHY THIS EXISTS
    Deleting a pod that something owns is a restart: the owner starts another.
    "Kill" promises more than that, and the promise is kept by telling the
    owner to keep one fewer. That is a change to a WORKLOAD made from a button
    on a POD, so what must hold is what nobody would see by pressing it once:

      1. **Only the pod that was named goes.** A ReplicaSet picks what to let
         go of by its own ranking, so the pod is marked cheapest first and
         deleted by name last; and the scale is conditional on the count that
         was read, so two kills at once cannot take two.
      2. **A pod its owner no longer counts takes nobody with it.** One that is
         already shutting down, or has stopped, is not one of the n: scaling
         down for it would remove a second, healthy pod.
      3. **An owner that cannot be told "one fewer" is refused, in words, with
         nothing changed.** A DaemonSet, a Job, an operator's object or the
         machine itself would start the pod again: a kill that comes back is a
         restart with the wrong name. A StatefulSet gives up only its last.
      4. **A step that fails leaves no trace that decides something later.**
         The mark that says "remove this one first" is taken off again when
         the scale is refused.
      5. **A pod's own document never reaches the result.** It can hold a
         password in a plain env value, and the result goes to the audit log,
         the page and an assistant.
      6. **It goes through the same gates as every other action.**

    The cluster is answered at `kmanage._kubectl`, so every command the action
    would run is seen with its real arguments, in order.

    ./.venv/bin/python tests/test_kill_pod.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("kill-pod-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import aitools, auth, db, kmanage, rbac, store        # noqa: E402

bad = 0
SECRET = "hunter2-do-not-leak"
NS = "shop"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def owned(kind: str = "", name: str = "") -> list:
    return [{"kind": kind, "name": name, "controller": True}] if kind else []


def pod(name: str, kind: str = "", owner: str = "", phase: str = "Running",
        leaving: bool = False) -> dict:
    meta = {"name": name, "namespace": NS, "ownerReferences": owned(kind, owner)}
    if leaving:
        meta["deletionTimestamp"] = "2026-11-21T10:00:00Z"
    return {"metadata": meta, "status": {"phase": phase},
            "spec": {"containers": [{"name": "c", "env": [{"name": "DB_PASSWORD", "value": SECRET}]}]}}


def workload(name: str, replicas, kind: str = "", owner: str = "", start=None) -> dict:
    spec = {} if replicas is None else {"replicas": replicas}
    if start is not None:
        spec["ordinals"] = {"start": start}
    return {"metadata": {"name": name, "namespace": NS, "ownerReferences": owned(kind, owner)}, "spec": spec}


class Cluster:
    """Answers kubectl the way a cluster would, and remembers what was asked."""

    def __init__(self, **objs):
        self.objs = {tuple(k.split("/", 1)): v for k, v in objs.items()}
        self.ran, self.fail = [], {}

    def writes(self) -> list:
        return [a for a in self.ran if a[0] != "get"]

    def __call__(self, base, argv, timeout, stdin=""):
        self.ran.append(list(argv))
        show = "kubectl " + " ".join(argv)
        verb = argv[0]
        if verb in self.fail:
            return {"display": show, "code": 1, "stdout": "", "stderr": self.fail[verb]}
        if verb == "get":
            doc = self.objs.get((argv[1], argv[2]))
            if doc is None:
                return {"display": show, "code": 1, "stdout": "",
                        "stderr": f'Error from server (NotFound): {argv[1]} "{argv[2]}" not found'}
            return {"display": show, "code": 0, "stdout": json.dumps(doc), "stderr": ""}
        if verb == "scale":
            kind, name = argv[1].split("/", 1)
            doc = self.objs[(kind, name)]
            want = int(next(a for a in argv if a.startswith("--current-replicas=")).split("=")[1])
            if doc["spec"].get("replicas", 1) != want:
                return {"display": show, "code": 1, "stdout": "",
                        "stderr": f"error: Expected replicas to be {want}, was {doc['spec'].get('replicas', 1)}"}
            doc["spec"]["replicas"] = int(next(a for a in argv if a.startswith("--replicas=")).split("=")[1])
            return {"display": show, "code": 0, "stdout": f"{argv[1]} scaled", "stderr": ""}
        return {"display": show, "code": 0, "stdout": "done", "stderr": ""}


def kill(cluster: Cluster, name: str):
    """(result, refusal): one of them is None."""
    kmanage._kubectl = cluster
    try:
        return kmanage.kill_pod({"id": "c1"}, {"namespace": NS, "name": name}), None
    except kmanage.Refused as e:
        return None, str(e)


def test_kill() -> None:
    kmanage.base_args = lambda c: ["kubectl", "--context", "x"]
    kmanage.reachable = lambda c: (True, "")

    print("a pod of a Deployment")
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9"),
                   "replicaset/web-7d9": workload("web-7d9", 3, "Deployment", "web"),
                   "deployment/web": workload("web", 3)})
    res, no = kill(c, "web-7d9-aaa")
    w = c.writes()
    check("it goes through", no is None and res["ok"] and res["code"] == 0)
    check("three changes, in this order: the mark, the scale, the delete by name",
          [a[0] for a in w] == ["annotate", "scale", "delete"])
    check("the mark names this pod as the cheapest to remove",
          w[0][:3] == ["annotate", "pod", "web-7d9-aaa"] and f"{kmanage.KILL_COST}=-2147483647" in w[0]
          and "--overwrite" in w[0] and w[0][w[0].index("-n") + 1] == NS)
    check("the Deployment is scaled, not its ReplicaSet, from the count that was read to one fewer",
          w[1][1] == "deployment/web" and "--current-replicas=3" in w[1] and "--replicas=2" in w[1]
          and w[1][w[1].index("-n") + 1] == NS)
    check("the pod is deleted by name, without waiting, and a pod already gone is not an error",
          w[2][:3] == ["delete", "pod", "web-7d9-aaa"] and "--ignore-not-found" in w[2] and "--wait=false" in w[2])
    check("the first line says what happened, with the numbers",
          res["stdout"].splitlines()[0].startswith("web-7d9-aaa is gone for good: Deployment web now keeps 2 pods instead of 3."))
    check("and that what manages it may put it back", "may still put the count back" in res["stdout"].splitlines()[0])
    check("what is audited is the three commands that changed something",
          res["display"].count("kubectl ") == 3 and "scale deployment/web" in res["display"] and "get " not in res["display"])
    check("the pod's own document, and a password in it, is nowhere in the result", SECRET not in json.dumps(res))
    check("the command a preview shows is the one it ends with", res["argv"] == w[2])

    print("the last pod of a workload, and a ReplicaSet on its own")
    c = Cluster(**{"pod/one-5c-x": pod("one-5c-x", "ReplicaSet", "one-5c"),
                   "replicaset/one-5c": workload("one-5c", 1, "Deployment", "one"),
                   "deployment/one": workload("one", 1)})
    res, no = kill(c, "one-5c-x")
    check("a workload of one is left keeping none, and the sentence is singular where it should be",
          res["ok"] and "--replicas=0" in c.writes()[1] and "now keeps 0 pods instead of 1" in res["stdout"])
    c = Cluster(**{"pod/two-a": pod("two-a", "ReplicaSet", "two"), "replicaset/two": workload("two", 2)})
    res, no = kill(c, "two-a")
    check("a ReplicaSet nothing owns is the thing that is scaled",
          res["ok"] and c.writes()[1][1] == "replicaset/two" and "keeps 1 pod instead of 2" in res["stdout"])
    c = Cluster(**{"pod/d-1-a": pod("d-1-a", "ReplicaSet", "d-1"),
                   "replicaset/d-1": workload("d-1", None, "Deployment", "d"), "deployment/d": workload("d", None)})
    res, no = kill(c, "d-1-a")
    check("a count the API left out is one", res["ok"] and "--current-replicas=1" in c.writes()[1])

    print("a pod nothing owns")
    c = Cluster(**{"pod/bare": pod("bare")})
    res, no = kill(c, "bare")
    check("is deleted, and that is all", res["ok"] and [a[0] for a in c.writes()] == ["delete"]
          and "nothing owned it" in res["stdout"])

    print("a pod its owner no longer counts")
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9", leaving=True),
                   "replicaset/web-7d9": workload("web-7d9", 3, "Deployment", "web"), "deployment/web": workload("web", 3)})
    res, no = kill(c, "web-7d9-aaa")
    check("one already shutting down is refused, and nothing is scaled for it",
          res is None and "already shutting down" in no and not c.writes())
    for phase in ("Failed", "Succeeded"):
        c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9", phase=phase),
                       "replicaset/web-7d9": workload("web-7d9", 3, "Deployment", "web"), "deployment/web": workload("web", 3)})
        res, no = kill(c, "web-7d9-aaa")
        check(f"one that has stopped ({phase}) is deleted, and the count is left alone",
              res["ok"] and [a[0] for a in c.writes()] == ["delete"] and c.objs[("deployment", "web")]["spec"]["replicas"] == 3
              and "its owner's count is as it was" in res["stdout"])
    c = Cluster(**{"pod/job-1-x": pod("job-1-x", "Job", "job-1", phase="Succeeded")})
    res, no = kill(c, "job-1-x")
    check("a finished pod of a Job is cleared by a delete: the Job does not start it again",
          no is None and res["ok"] and [a[0] for a in c.writes()] == ["delete"])
    c = Cluster(**{"pod/db-0": pod("db-0", "StatefulSet", "db", phase="Failed"), "statefulset/db": workload("db", 3)})
    res, no = kill(c, "db-0")
    check("a stopped pod of a StatefulSet is NOT cleared that way: it would be started again",
          res is None and "only db-2 can be killed" in no and not c.writes())
    c = Cluster(**{"pod/z-1-a": pod("z-1-a", "ReplicaSet", "z-1"),
                   "replicaset/z-1": workload("z-1", 0, "Deployment", "z"), "deployment/z": workload("z", 0)})
    res, no = kill(c, "z-1-a")
    check("a workload already told to keep none is not scaled below nothing",
          res["ok"] and [a[0] for a in c.writes()] == ["delete"])

    print("a StatefulSet")
    c = Cluster(**{"pod/db-2": pod("db-2", "StatefulSet", "db"), "pod/db-0": pod("db-0", "StatefulSet", "db"),
                   "statefulset/db": workload("db", 3)})
    res, no = kill(c, "db-2")
    check("its last pod is killed by the scale alone: no mark, no delete",
          res["ok"] and [a[0] for a in c.writes()] == ["scale"] and c.writes()[0][1] == "statefulset/db"
          and "--current-replicas=3" in c.writes()[0] and "--replicas=2" in c.writes()[0])
    check("and it says the volume claim is kept", "volume claim is kept" in res["stdout"])
    c.ran.clear()
    res, no = kill(c, "db-0")
    check("any other is refused, naming the one that can go, with nothing changed",
          res is None and "only db-1 can be killed" in no and not c.writes())
    c = Cluster(**{"pod/q-7": pod("q-7", "StatefulSet", "q"), "pod/q-5": pod("q-5", "StatefulSet", "q"),
                   "statefulset/q": workload("q", 3, start=5)})
    check("where the ordinals do not start at nothing, the last is counted from where they start",
          kill(c, "q-7")[0]["ok"] and "only q-6 can be killed" in (kill(c, "q-5")[1] or ""))

    print("what cannot be told to keep one fewer")
    for kind, word in (("DaemonSet", "every machine"), ("Job", "still running this pod"),
                       ("Node", "runs this pod itself"), ("Cluster", "belongs to the Cluster pg")):
        c = Cluster(**{"pod/p": pod("p", kind, "pg")})
        res, no = kill(c, "p")
        check(f"a pod of a {kind} is refused in words, with nothing changed",
              res is None and word in no and not c.writes())
        check(f"and the reason is the one any caller is given ({kind})", no == kmanage.kill_refusal(kind, "pg"))
    c = Cluster(**{"pod/r-1-a": pod("r-1-a", "ReplicaSet", "r-1"), "replicaset/r-1": workload("r-1", 3, "Rollout", "r")})
    res, no = kill(c, "r-1-a")
    check("a ReplicaSet that belongs to something other than a Deployment is refused, naming it",
          res is None and "the Rollout r" in no and not c.writes())
    check("what can be killed has no reason against it",
          all(kmanage.kill_refusal(k, "x") == "" for k in ("", "Deployment", "ReplicaSet", "StatefulSet")))

    print("a step that fails")
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9"),
                   "replicaset/web-7d9": workload("web-7d9", 3, "Deployment", "web"), "deployment/web": workload("web", 3)})

    def raced(base, argv, timeout, stdin=""):
        if argv[0] == "annotate" and not argv[-1].endswith("-"):
            c.objs[("deployment", "web")]["spec"]["replicas"] = 2          # somebody else got there first
        return Cluster.__call__(c, base, argv, timeout, stdin)
    kmanage._kubectl = raced
    try:
        res = kmanage.kill_pod({"id": "c1"}, {"namespace": NS, "name": "web-7d9-aaa"})
    except kmanage.Refused as e:
        res = {"ok": True, "stdout": str(e)}
    w = c.writes()
    check("a count that changed since it was read stops the kill: nothing is deleted",
          res["ok"] is False and [a[0] for a in w] == ["annotate", "scale", "annotate"]
          and c.objs[("deployment", "web")]["spec"]["replicas"] == 2)
    check("and the mark is taken off the pod again", w[-1][:3] == ["annotate", "pod", "web-7d9-aaa"]
          and w[-1][-1] == f"{kmanage.KILL_COST}-")
    check("it says the pod is still there, and why", "is still there" in res["stdout"].splitlines()[0]
          and "Expected replicas to be 3" in res["stderr"])
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9"),
                   "replicaset/web-7d9": workload("web-7d9", 3, "Deployment", "web"), "deployment/web": workload("web", 3)})
    c.fail["annotate"] = "Error from server (Forbidden): pods is forbidden"
    res, no = kill(c, "web-7d9-aaa")
    check("a pod that cannot be marked is not scaled for", res["ok"] is False and [a[0] for a in c.writes()] == ["annotate"]
          and "nothing was changed" in res["stdout"])
    c = Cluster()
    res, no = kill(c, "ghost")
    check("a pod that cannot be read changes nothing, and kubectl's own sentence is kept",
          res["ok"] is False and not c.writes() and "NotFound" in res["stderr"] and "nothing was changed" in res["stdout"])
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9")})
    res, no = kill(c, "web-7d9-aaa")
    check("an owner that cannot be read changes nothing", res["ok"] is False and not c.writes())
    kmanage.reachable = lambda c: (False, "no route to host")
    c = Cluster(**{"pod/bare": pod("bare")})
    res, no = kill(c, "bare")
    check("a cluster that does not answer is said at once, and nothing is asked of it",
          res is None and "unreachable" in no and not c.ran)
    kmanage.reachable = lambda c: (True, "")


def test_gates() -> None:
    print("the same gates as every other action")
    c = Cluster(**{"pod/bare": pod("bare")})
    kmanage._kubectl = c
    spec = kmanage.ACTIONS["kill-pod"]
    check("it is in the catalogue, destructive, and takes a namespace and a name",
          spec["destructive"] and tuple(spec["needs"]) == ("namespace", "name")
          and any(a["action"] == "kill-pod" and a["destructive"] for a in aitools.action_catalogue()))
    check("its note says what may put the pod back, and what it refuses",
          "ArgoCD may put it back" in spec["note"] and "DaemonSet" in spec["note"])
    for what, args, write in (("a cluster that does not allow management", {"namespace": NS, "name": "bare"}, False),
                              ("a name that is not a Kubernetes name", {"namespace": NS, "name": "bare; rm -rf /"}, True),
                              ("no name", {"namespace": NS, "name": ""}, True)):
        try:
            kmanage.act({"id": "c1"}, "kill-pod", args, allow_write=write)
            got = "ran"
        except kmanage.Refused:
            got = "refused"
        check(f"{what} is refused before anything is asked of the cluster", got == "refused" and not c.ran)
    res = kmanage.act({"id": "c1"}, "kill-pod", {"namespace": NS, "name": "bare"}, allow_write=True)
    check("allowed, it runs", res["ok"] and [a[0] for a in c.writes()] == ["delete"])

    # the whole path a person's click takes: roles, the cluster's own tick, and the audit line
    pid = store.add_project("Kill", icon="x")
    cid = store.add_cluster(pid, "mine", "apiVersion: v1\nkind: Config\n", "mine")
    uid = auth.create_user("killer@test.invalid", "K", "Passw0rd!xY-kill", role="user")
    rbac.set_for_user(uid, [rbac.save("", "killer", "", ["clusters", "manage"], [], [cid])])
    me = auth.by_id(uid)
    c = Cluster(**{"pod/web-7d9-aaa": pod("web-7d9-aaa", "ReplicaSet", "web-7d9"),
                   "replicaset/web-7d9": workload("web-7d9", 2, "Deployment", "web"), "deployment/web": workload("web", 2)})
    kmanage._kubectl = c
    kmanage.writable = lambda sel: False
    try:
        aitools.execute(me, pid, cid, "kill-pod", {"namespace": NS, "name": "web-7d9-aaa"})
        got = "ran"
    except aitools.Denied:
        got = "refused"
    check("through the executor, a cluster without its management tick is refused", got == "refused" and not c.ran)
    kmanage.writable = lambda sel: True
    out = aitools.execute(me, pid, cid, "kill-pod", {"namespace": NS, "name": "web-7d9-aaa"}, ip="10.0.0.9")
    check("with it, the kill goes through and the answer is the sentence, not kubectl's last word",
          out["ok"] and out["summary"].startswith("web-7d9-aaa is gone for good: Deployment web now keeps 1 pod instead of 2"))
    row = db.one("SELECT action, target, detail FROM audit WHERE action = 'cluster_kill-pod' ORDER BY id DESC LIMIT 1")
    check("and it is audited against the pod, with the commands that ran",
          bool(row) and "shop/web-7d9-aaa" in row["target"] and "scale deployment/web" in row["detail"]
          and "annotate pod web-7d9-aaa" in row["detail"])
    c = Cluster(**{"pod/p": pod("p", "DaemonSet", "fluentd")})
    kmanage._kubectl = c
    try:
        aitools.execute(me, pid, cid, "kill-pod", {"namespace": NS, "name": "p"})
        got = ""
    except aitools.Denied as e:
        got = str(e)
    row = db.one("SELECT detail FROM audit WHERE action = 'cluster_action_refused' ORDER BY id DESC LIMIT 1")
    check("a refusal reaches the person in its own words, and is audited as a refusal",
          "DaemonSet fluentd" in got and bool(row) and "kill-pod" in row["detail"] and not c.writes())


def main() -> int:
    test_kill()
    test_gates()
    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
