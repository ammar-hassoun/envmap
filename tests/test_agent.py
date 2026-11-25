#!/usr/bin/env python3
"""The assistant looking more than once — and stopping when it should.

WHY THIS EXISTS
    The assistant used to run exactly one catalogue query per question, which
    answers "list the pods" and cannot answer "why is this broken" — that needs
    the second look to depend on what the first one said. The loop here is what
    makes the difference, and everything worth testing about it is invisible
    from reading an answer:

      * it can look twice, and the second look is a real query through the same
        permission checks the pages use
      * a refusal comes back as text the model can act on rather than an
        exception that throws away the work already done
      * it STOPS. A model that keeps asking for one more look is the normal
        failure of this shape, and unbounded it is somebody's API server being
        read in a loop for as long as the request is open
      * when it stops it is told why, and still answers. Withdrawing the tools
        silently reads to a model as a malfunction and produces an apology
      * results are scrubbed and shrunk: a tool result is text going to a model,
        so it is the second way a credential could leave, and forty rows of six
        will not fill the window before the answer is written

    No network and no cluster: the provider is a script of replies, which is
    the only way to test "what happens on the seventh look" at all.

    ./.venv/bin/python tests/test_agent.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("agent-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import agent, answers, assistant, auth, store         # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    uid = auth.create_user("agent@test.invalid", "A", "Passw0rd!xY",
                           role="admin")
    me = auth.by_id(uid)
    pid = store.add_project("Agent")
    cid = store.add_cluster(pid, "AgentCluster", "apiVersion: v1\n", "ctx")
    store.update_cluster(pid, cid, manage="1")
    assistant.save(enabled=True, provider="anthropic",
                   model="claude-sonnet-4-5", token="k")

    real_run, real_post = answers.run, assistant._post
    answers.run = lambda u, n, q, f="": {
        "query": n, "count": 72, "columns": ["pod", "status"],
        "rows": [{"pod": f"p{i}", "status": "Running"} for i in range(72)],
        "note": n}

    try:
        print("the catalogue is one tool with an enum, not one tool each")
        tools = agent.tools_for(me)
        names = [t["name"] for t in tools]
        check(f"read is offered ({names})", "read" in names)
        enum = tools[0]["input_schema"]["properties"]["query"]["enum"]
        check(f"every query this person may run is in the enum ({len(enum)})",
              set(enum) == {c["name"] for c in answers.capabilities(me)})
        check("and proposing is offered to somebody who may manage",
              "propose_action" in names)

        print("a result is shrunk, and says how much it is not showing")
        doc = json.loads(agent.call_tool(me, "read", {"query": "pods"}))
        check(f"rows are capped ({doc['showing']})",
              doc["showing"] == agent.ROWS_BACK)
        # The count must be the REAL one: a model that believes it saw
        # everything will say "all 40 pods are healthy" about an estate of 300.
        check(f"but the count is the true one ({doc['matched']})",
              doc["matched"] == 72)

        print("a refusal is an answer, not an exception")
        answers.run = lambda u, n, q, f="": (_ for _ in ()).throw(
            PermissionError("clusters"))
        said = agent.call_tool(me, "read", {"query": "pods"})
        check(f"it comes back as text ({said[:40]})", said.startswith("refused"))
        answers.run = lambda u, n, q, f="": {
            "query": n, "count": 1, "columns": ["a"], "rows": [{"a": 1}]}

        print("it looks more than once when one look is not enough")
        script = [
            [{"type": "tool_use", "id": "1", "name": "read",
              "input": {"query": "pods", "about": "unhealthy"}}],
            [{"type": "tool_use", "id": "2", "name": "read",
              "input": {"query": "events", "about": "dev"}}],
            [{"type": "text", "text": "OOMKilled — the memory limit is the cause."}],
        ]
        seen = []

        def scripted(url, head, body, skip):
            seen.append(body)
            return {"content": script[len(seen) - 1]}
        assistant._post = scripted
        steps = []
        res = agent.run(me, [{"role": "user", "text": "why is it restarting"}],
                        on_step=steps.append)
        check(f"two looks were taken ({res['steps']})", res["steps"] == 2)
        check(f"each was narrated ({steps})", len(steps) == 2
              and all(s.startswith("reading") for s in steps))
        check("and the answer is the model's own",
              "OOMKilled" in res["answer"])

        print("a proposal is captured, and still runs nothing")
        ran = {"n": 0}
        from app import kmanage
        real_act = kmanage.act
        kmanage.act = lambda *a, **k: ran.__setitem__("n", ran["n"] + 1)
        script2 = [
            [{"type": "tool_use", "id": "1", "name": "propose_action",
              "input": {"action": "restart", "project": pid, "cluster": cid,
                        "kind": "deployment", "namespace": "dev",
                        "name": "web"}}],
            [{"type": "text", "text": "Proposed."}],
        ]
        seen.clear()
        assistant._post = lambda u, h, b, s: (
            seen.append(b), {"content": script2[len(seen) - 1]})[1]
        res = agent.run(me, [{"role": "user", "text": "restart it"}])
        check(f"the proposal carries the real command "
              f"({[p['command'] for p in res['proposals']]})",
              any("rollout restart" in p["command"] for p in res["proposals"]))
        # The whole safety property: proposing is not doing.
        check(f"and nothing was executed ({ran['n']} calls to act)",
              ran["n"] == 0)
        kmanage.act = real_act

        print("it stops, is told why, and answers anyway")
        calls = {"n": 0, "system": "", "had_tools": None}

        def greedy(url, head, body, skip):
            calls["n"] += 1
            calls["system"] = body.get("system", "")
            calls["had_tools"] = "tools" in body
            # The fake refuses to play along for ever. Without this, a loop that
            # stopped withdrawing its tools would HANG the suite rather than
            # fail it — which is how an unbounded loop gets shipped: nobody
            # waits out a hanging test, they kill it and re-run.
            if calls["n"] > agent.STEPS + 3:
                raise AssertionError(
                    f"the loop never stopped: {calls['n']} calls to the model "
                    f"for a cap of {agent.STEPS}")
            if calls["had_tools"]:
                return {"content": [{"type": "tool_use", "id": str(calls["n"]),
                                     "name": "read",
                                     "input": {"query": "pods"}}]}
            return {"content": [{"type": "text", "text": "I checked what I could."}]}
        assistant._post = greedy
        try:
            res = agent.run(me, [{"role": "user", "text": "loop"}])
        except AssertionError as e:
            check(str(e), False)
            res = {"steps": -1, "answer": ""}
        check(f"it stopped at the cap ({res['steps']} of {agent.STEPS})",
              res["steps"] == agent.STEPS)
        check(f"the model was called once more to answer ({calls['n']})",
              calls["n"] == agent.STEPS + 1)
        check("the tools were withdrawn on that last call",
              calls["had_tools"] is False)
        check("and it was told why, so it answers instead of apologising",
              "look-ups" in calls["system"])
        check(f"an answer came back anyway ({res['answer'][:30]})",
              bool(res["answer"].strip()))
    finally:
        answers.run, assistant._post = real_run, real_post

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
