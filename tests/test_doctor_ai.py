#!/usr/bin/env python3
"""The 3D view's doctor run by the portal itself (app/doctor_ai.py).

WHY THIS EXISTS
    The doctor is a model loop that can lead to real changes on a cluster and
    in Git. What must hold, whatever the model says:

      1. **Nothing changes without the caller's own yes, given in the view.**
         Not anybody else watching, not a "yes" when production asks for the
         cluster's name, not silence.
      2. **The model holds no tool that changes anything.** It proposes; the
         portal asks; the portal runs it through the same guarded functions as
         the buttons.
      3. **"Healed" is the cluster's word.** A healed the cluster does not
         confirm is not said as healed.
      4. **What goes to the model is scrubbed**: secret-looking values in a
         values file are hidden, and every result passes `_no_secrets`.
      5. **Calling needs nothing outside the game** once a Claude account is
         connected, and says how to connect one when it is not.

    The model is a script: `assistant._post` is replaced by a function that
    answers each request with the next scripted turn and records what it was
    sent. The cluster is answered at the functions the doctor reads.

    ./.venv/bin/python tests/test_doctor_ai.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("doctor-ai-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import (actions, aitools, aiuser, assistant, auth, db, doctor,  # noqa: E402
                 doctor_ai, kmanage, main, rbac, scene, store)
from app import cluster as clusterview                         # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── a cluster, as the doctor reads it ─────────────────────────
def pod_row(name, tone="bad", problem="OOMKilled", workload="web", kind="Deployment", mgr=None):
    return {"id": f"shop/{name}", "ns": "shop", "name": name, "phase": "Running",
            "problem": "" if tone == "ok" else problem, "tone": tone, "ready": "1/1" if tone == "ok" else "0/1",
            "restarts": 3, "age": "2d", "last_exit": {"reason": problem, "code": 137, "ago": 30, "ran": 12},
            "kind": kind, "workload": workload, "wl": f"shop/{workload}", "mgr": mgr or {"by": "direct"},
            "images": ["web:1"], "node": "n1", "qos": "Burstable", "cpu": 10, "mem": 90,
            "cpu_lim": 100, "mem_lim": 100}


ROWS = {"now": [pod_row("web-abc-111"), pod_row("api-0", tone="ok", workload="api", kind="StatefulSet")]}
scene.collect = lambda sel, refresh=False: {"pods": ROWS["now"]}
clusterview.describe = lambda sel, kind, name, ns: {"text": "Events:\n  Warning  OOMKilling  the kernel killed it", "error": ""}
clusterview.pod_logs = lambda sel, ns, name, container="", tail=400, previous=False: {
    "text": ("before: " if previous else "") + "loading model 742 MiB\nKilled", "error": ""}
clusterview.forget = lambda *a, **k: None

RAN, ACTED = [], []


def fake_propose(user, project, cluster, action, args):
    if action not in kmanage.ACTIONS:
        raise aitools.Denied("unknown")
    return {"action": action, "label": kmanage.ACTIONS[action]["label"], "destructive": True,
            "command": "kubectl " + " ".join(kmanage.ACTIONS[action]["build"]({**args, "replicas": args.get("replicas") or "1"})),
            "prod": PROD["on"], "confirm_required": "shop-prod" if PROD["on"] else ""}


def fake_execute(user, project, cluster, action, args, confirm="", ip=""):
    ACTED.append((action, args.get("name"), confirm, user.get("email")))
    return {"ok": True, "code": 0, "command": f"kubectl {action} {args.get('name')}", "label": action,
            "summary": "done", "stdout": "", "stderr": ""}


PROD = {"on": False}
aitools.propose, aitools.execute = fake_propose, fake_execute
aitools.is_prod = lambda project, cluster: PROD["on"]


# ── the model, as a script ─────────────────────────────────────
class Script:
    def __init__(self, turns):
        self.turns, self.sent, self.n = list(turns), [], 0

    def __call__(self, url, headers, body, skip_tls, timeout=60):
        self.sent.append(json.loads(json.dumps(body)))
        self.headers = headers
        if not self.turns:
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "That is all."}]}
        t = self.turns.pop(0)
        return t if isinstance(t, dict) else {"stop_reason": "tool_use", "content": [
            {"type": "tool_use", "id": f"t{self.n}-{i}", "name": n, "input": a} for i, (n, a) in enumerate(t)]}


def use(*calls):
    return list(calls)


def run_visit(script, user, cid="c-1", answers=(), pod="shop/web-abc-111", line=""):
    """One visit, start to finish. `answers` is [(who, text)], each said as soon
    as the doctor asks something."""
    assistant._post = script
    doctor.forget()
    doctor.watching(cid)
    stop = threading.Event()
    pending = list(answers)

    def answerer():
        seen = 0
        while not stop.is_set() and pending:
            for n in doctor.feed(cid, seen)["notes"]:
                seen = max(seen, n["n"])
                if n["state"] == "asking" and not n["pod"]:
                    for who, text in list(pending):
                        pending.pop(0)
                        doctor.tell(cid, who, text)
                        if who == user["email"]:
                            break
            time.sleep(0.05)
    helper = threading.Thread(target=answerer, daemon=True)
    helper.start()
    doctor_ai._run(user, "p-1", cid, {"id": cid, "name": "shop-dev"}, pod, line, stop)
    stop.set()
    return doctor.feed(cid, 0)["notes"]


def main_test() -> int:
    store.add_project("Shop", icon="x")
    uid = auth.create_user("dr@test.invalid", "Dr", "Passw0rd!xY-doctor", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", "dr", "", ["clusters", "manage", "config"], [], [])])
    me = auth.by_id(uid)
    doctor_ai.ASK_WAIT, doctor_ai.IDLE_WAIT, doctor_ai.AWAY = 3.0, 0.5, 60.0

    print("who can have one")
    ok, why = doctor_ai.available(me)
    check("with no Claude account, it says where to connect one", not ok and "account page" in why)
    aiuser.save(uid, provider="anthropic", model="", token="sk-ant-test-key-0123456789")
    check("with one, the doctor can come", doctor_ai.available(me) == (True, ""))

    print("a visit, and a change put to the person")
    ACTED.clear()
    script = Script([
        use(("say", {"text": "Why do you keep falling over?", "pod": "shop/web-abc-111", "state": "asking"}),
            ("examine", {"pod": "shop/web-abc-111"})),
        use(("pod_says", {"pod": "shop/web-abc-111", "text": "I was killed for memory. Help me."}),
            ("propose_cluster_action", {"action": "delete-pod", "pod": "shop/web-abc-111", "why": "A fresh start may help."})),
        use(("say", {"text": "You are healed.", "pod": "shop/web-abc-111", "state": "healed"})),
        use(("finish", {"summary": "Done for now."})),
    ])
    # somebody else watching answers first, and says the opposite: only the
    # caller's own answer may decide, in either direction
    notes = run_visit(script, me, answers=[("someone@else.invalid", "No"), (me["email"], "Yes, do it")])
    voices = [(n["voice"], n["state"]) for n in notes]
    check("the doctor arrives by itself, asks the pod, and the pod answers in its own voice",
          voices[0] == ("doctor", "arrived") and ("doctor", "asking") in voices and ("pod", "") in voices)
    check("the change runs once, on the CALLER's yes, as the caller",
          ACTED == [("delete-pod", "web-abc-111", "", me["email"])])
    asked = [n for n in notes if n["state"] == "asking" and not n["pod"]]
    check("the question is put to the person with the command it will run, and a yes and a no to pick",
          asked and "kubectl delete pod web-abc-111" in asked[0]["text"] and asked[0]["choices"] == ["Yes, do it", "No"])
    first = script.sent[0]
    check("the model is sent the unwell pods and who called, with tools that change nothing",
          "shop/web-abc-111" in first["messages"][0]["content"] and "Dr" in first["messages"][0]["content"]
          and not {t["name"] for t in first["tools"]} & {"execute", "run", "delete", "config_set", "config_commit"})
    check("it runs as Claude Opus 5.5 when the account names no model, at high effort, with the refusal fallback",
          first["model"] == "claude-opus-5-5" and first["output_config"] == {"effort": "high"}
          and first.get("fallbacks") == "default" and script.headers.get("anthropic-beta") == "server-side-fallback-2026-07-01")
    results = [b for m in script.sent[1]["messages"] if m["role"] == "user" and isinstance(m["content"], list) for b in m["content"]]
    check("what it examined came back as the pod's facts, events and logs",
          any("OOMKilling" in str(b.get("content")) and "Killed" in str(b.get("content")) for b in results))
    healed = [n for n in notes if n["text"] == "You are healed."]
    check("a pod the cluster still shows failing is not said as healed", healed and healed[0]["state"] == "examining")
    told = [b for m in script.sent[3]["messages"] if isinstance(m["content"], list) for b in m["content"]
            if b.get("type") == "tool_result" and "NOT as healed" in str(b.get("content"))]
    check("and the model is told why", bool(told))
    check("the visit ends, said in the view, and nobody is left visiting", notes[-1]["state"] == "done" and not doctor_ai.busy("c-1"))
    trail = [a["action"] for a in auth.read_audit(limit=50)]
    check("the visit, the approval and the change are in the audit log",
          {"doctor_visit", "doctor_change_approved", "doctor_change_run", "doctor_visit_ended"} <= set(trail))

    print("no, silence and production")
    ACTED.clear()
    run_visit(Script([use(("propose_cluster_action", {"action": "restart", "pod": "shop/web-abc-111", "why": "x"})),
                      use(("finish", {"summary": "ok"}))]), me,
              answers=[("someone@else.invalid", "Yes, do it"), (me["email"], "No")])
    check("somebody else's yes is not the caller's", ACTED == [])
    run_visit(Script([use(("propose_cluster_action", {"action": "restart", "pod": "shop/web-abc-111", "why": "x"})),
                      use(("finish", {"summary": "ok"}))]), me, answers=[(me["email"], "No")])
    check("a no changes nothing", ACTED == [])
    run_visit(Script([use(("propose_cluster_action", {"action": "restart", "pod": "shop/web-abc-111", "why": "x"})),
                      use(("finish", {"summary": "ok"}))]), me, answers=[])
    check("silence changes nothing", ACTED == [])
    PROD["on"] = True
    run_visit(Script([use(("propose_cluster_action", {"action": "restart", "pod": "shop/web-abc-111", "why": "x"})),
                      use(("propose_cluster_action", {"action": "restart", "pod": "shop/web-abc-111", "why": "x"})),
                      use(("finish", {"summary": "ok"}))]), me,
              answers=[(me["email"], "Yes, do it"), (me["email"], "shop-prod")])
    PROD["on"] = False
    check("on production a yes is not enough: the cluster's name typed is, and it is what the action is sent",
          ACTED == [("restart", "web", "shop-prod", me["email"])])

    print("a change in Git")
    CALLED = []
    real_run = actions.run
    actions.run = lambda user, name, args, ip="", may_change=True: (
        CALLED.append((name, json.loads(json.dumps(args)))) or {"summary": "pushed abc123 to main", "doc": None})
    doctor_ai._settings_of = lambda v, row: {"pid": "p-1", "rgid": "rg-1", "env": "dev", "region": "TZ",
                                             "service": "web", "fname": "web-values.yaml"}
    doctor_ai._read_settings = lambda v, w: {"file": "apps/TZ/dev/web-values.yaml", "branch": "main",
                                             "values": [{"at": "image␟tag", "value": "1e5bfe834f17952901d158176a7fd823276b68f8"}],
                                             "yaml": "image:\n  tag: \"1e5b\"\nconfigMap:\n  data:\n    DB_PASSWORD: \"hunter2\"\n    BLOB: " + "A" * 120}
    aitools.push_name = lambda project, region, env: ""
    ROWS["now"] = [pod_row("web-abc-111", mgr={"by": "gitops", "tool": "Argo CD", "detail": "web"})]
    script = Script([use(("read_settings", {"pod": "shop/web-abc-111"})),
                     use(("propose_git_change", {"changes": [{"pod": "shop/web-abc-111", "path": ["configMap", "data", "DB_PASSWORD"], "value": "x"}],
                                                 "message": "m", "why": "w"})),
                     use(("propose_git_change", {"changes": [{"pod": "shop/web-abc-111", "path": ["image", "tag"], "value": "10a63877081dc5c1013e74a0389bee1eadca26b7"}],
                                                 "message": "put the image back", "why": "Yesterday's build fails at start."})),
                     use(("finish", {"summary": "ok"}))])
    notes = run_visit(script, me, answers=[(me["email"], "Yes, do it")])
    settings = [b for m in script.sent[1]["messages"] if isinstance(m["content"], list) for b in m["content"] if b.get("type") == "tool_result"]
    check("a values file reaches the model with its password and blobs hidden, and its image tag readable",
          settings and "hunter2" not in str(settings) and "A" * 100 not in str(settings)
          and "(hidden)" in str(settings) and "1e5b" in str(settings))
    check("a change to a secret is refused before anybody is asked",
          "touches a secret" in str(script.sent[2]["messages"][-1]["content"]))
    q = [n for n in notes if n["state"] == "asking" and not n["pod"]]
    check("the question shows the file and the value it changes, old to new",
          q and "web-values.yaml: image.tag …d823276b68f8 → …ee1eadca26b7" in q[0]["text"] and "commit to main as you" in q[0]["text"])
    check("on yes, the value is set and committed with the model's message, as the person",
          [c[0] for c in CALLED] == ["config_set", "config_commit"]
          and CALLED[0][1]["changes"] == [{"path": ["image", "tag"], "value": "10a63877081dc5c1013e74a0389bee1eadca26b7"}]
          and CALLED[1][1]["message"] == "put the image back")
    actions.run = real_run

    print("bounds")
    doctor_ai.AWAY = 0.0
    notes = run_visit(Script([use(("wait", {"seconds": 10}))]), me)
    doctor_ai.AWAY = 60.0
    check("with nobody watching the doctor leaves, and says so", notes[-1]["text"] == "Nobody is watching any more, so I am leaving.")
    notes = run_visit(Script([{"stop_reason": "refusal", "content": []}]), me)
    check("a declined request ends the visit in words, not in silence", notes[-1]["state"] == "failed")
    check("after a fallback, what the declined model said before it is not sent back except its text",
          doctor_ai._echo([{"type": "thinking"}, {"type": "text", "text": "a"}, {"type": "tool_use"},
                           {"type": "fallback"}, {"type": "thinking"}, {"type": "tool_use"}])
          == [{"type": "text", "text": "a"}, {"type": "fallback"}, {"type": "thinking"}, {"type": "tool_use"}])

    print("from the game")
    real_start = doctor_ai._run
    doctor_ai._run = lambda *a: time.sleep(0.3)
    pid = store.add_project("Game", icon="x")
    cid = store.add_cluster(pid, "game", "apiVersion: v1\nkind: Config\n", "game")
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": "dr@test.invalid", "password": "Passw0rd!xY-doctor"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
    got = c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid, "pod": "shop/x"}).json()
    again = c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid}).json()
    check("pressing H sends Claude, and a second press says Claude is already there",
          got["doctor"] == "portal" and got["arrival"] == "started" and again["arrival"] == "here")
    time.sleep(0.4)
    said = c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid, "say": "help please"}).json()
    check("speaking with no visit under way brings one", said["arrival"] == "started")
    aiuser.forget(uid)
    none = c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid}).json()
    check("with no Claude account the game is told how to connect one, and no visit starts",
          none["doctor"] == "mcp" and "account page" in none["how"] and "arrival" not in none)
    doctor_ai._run = real_start

    print("connecting Claude on the account page")
    page = c.get("/me").text
    check("the account page offers Claude, the doctor, with a key field that is never kept in the browser",
          'action="/me/doctor"' in page and 'id="drtoken"' in page
          and 'data-nosave' in page[page.index('id="drtoken"') - 200:page.index('id="drtoken"') + 200])
    c.post("/me/doctor", data={"token": "sk-ant-another-key-987654321", "model": ""}, follow_redirects=False)
    acct = aiuser.get(uid)
    check("connecting stores an Anthropic account with Claude Opus 5.5 by default",
          acct.get("provider") == "anthropic" and acct.get("model") == "claude-opus-5-5")
    check("and the key is never shown again", "sk-ant-another-key-987654321" not in c.get("/me").text)
    c.post("/me/doctor", data={"disconnect": "1"}, follow_redirects=False)
    check("disconnecting forgets it", not aiuser.get(uid).get("token"))

    print("the page's script")
    src = (ROOT / "static" / "cluster3d.js").read_text()
    check("the game says Claude is on the way, and never tells a person to leave it to call one",
          "Claude is on the way." in src and "Tell your AI client: be the doctor" not in src)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
