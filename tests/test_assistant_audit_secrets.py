#!/usr/bin/env python3
"""The assistant's secret filter covers every path text takes to a model, and
agent-mode questions are audited (S16).

`assistant._no_secrets` refuses — never redacts — text carrying a stored
credential. It guarded the in-product briefing and every agent tool result,
and two paths went around it:

  * the summary rows: /assistant/summarise builds a prompt FROM live query
    output, and that prompt was never checked;
  * MCP: every tool result goes to somebody else's AI client, and none was
    checked — the estate briefing included.

A credential is planted the way one really leaks: a CI connection whose stored
"last check" status echoes the URL it failed against, token and all. The
`connections` query (open to everyone signed in) then carries it. Both paths
must refuse, the model must never be called, and the value must appear nowhere
in what either path hands back — with the clean twin of each proving the path
really reaches the model when there is nothing to refuse.

Agent mode (/assistant/agent) was the one assistant path that left no record of
being asked; it is now audited like /assistant/stream, failed or answered.

Run:  PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_assistant_audit_secrets.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("assistant-s16-test-")
# The assistant is now opt-in (PORTAL_ASSISTANT, off by default). This suite
# exercises its agent-mode audit and secret filter, so it turns the feature on.
os.environ["PORTAL_ASSISTANT"] = "1"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import agent, assistant, auth, db, main, mcp, store   # noqa: E402

SECRET = "PLANTED-TOKEN-7f3a9c41e2d8"
LEAKED = f"401 token={SECRET} rejected by https://ci.example.com/api"
CLEAN = "ok: 12 jobs"
bad = 0


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


def _admin() -> tuple[dict, TestClient]:
    email, pw = "s16@test.local", "Secret-Filter-Pass-42"
    uid = auth.create_user(email, "S16", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return auth.by_id(uid), c


def _audit(action: str) -> list[tuple[str, str]]:
    return [(r["target"] or "", r["detail"] or "") for r in db.q(
        "SELECT target, detail FROM audit WHERE action = ? ORDER BY id",
        (action,))]


def main_test() -> int:
    me, c = _admin()
    cid = store.add_conn("ci", "", {"type": "jenkins", "name": "Planted CI",
                                    "base_url": "https://ci.example.com",
                                    "user": "bot", "token": SECRET,
                                    "status": CLEAN})
    check("the planted token is one the filter watches",
          ("token", SECRET) in assistant.secret_watch(me))

    # A local provider, with its stream replaced by a recorder: the network is
    # never touched, and the recorder says whether the model was reached.
    assistant.save(enabled=True, provider="ollama",
                   base_url="http://127.0.0.1:9", model="test-model")
    asked: list[str] = []

    def recorder(cfg, system, turns):
        asked.append(system)
        yield "ok"

    real_stream = assistant.STREAMS["ollama"]
    assistant.STREAMS["ollama"] = recorder
    try:
        # ── 1. summary rows, through the real route ───────────────────────
        def summarise() -> str:
            r = c.post("/assistant/summarise",
                       json={"question": "list connections",
                             "query": "connections", "focus": ""})
            return r.text

        body = summarise()
        check(f"clean rows reach the model (control), got {body[:120]!r}",
              len(asked) == 1 and '"text": "ok"' in body)

        store.update_conn("ci", "", cid, status=LEAKED)
        asked.clear()
        body = summarise()
        check("a stored token in the rows is refused, not summarised",
              "event: error" in body and "refusing to send" in body)
        check("the refusal names the field and blames the query, not the "
              f"briefing builder: {body[:240]!r}",
              "stored token" in body and "the query" in body)
        check("and the model was never called", asked == [])
        check("and the value appears nowhere in the response", SECRET not in body)

        # ── 2. MCP results ────────────────────────────────────────────────
        store.update_conn("ci", "", cid, status=CLEAN)
        got = mcp.call(me, "connections", {})
        check(f"a clean MCP answer is returned (control): {str(got)[:120]}",
              not got.get("isError") and "Planted CI" in json.dumps(got))

        store.update_conn("ci", "", cid, status=LEAKED)
        for tool in ("connections", "estate"):
            got = mcp.call(me, tool, {})
            check(f"MCP {tool}: the stored token never reaches the client",
                  SECRET not in json.dumps(got))
        got = mcp.call(me, "connections", {})
        check("MCP connections: the answer is withheld as a tool failure",
              got.get("isError") and
              got["content"][0]["text"].startswith("withheld:"))
        check("and nothing structured rides along with the refusal",
              "structuredContent" not in got)
        held = _audit("mcp_secret_withheld")
        check(f"the withheld answer is audited, got {held}",
              any(t == "connections" for t, _ in held))
        check("and the audit line names the field, never the value",
              held and all(SECRET not in d for _, d in held)
              and any("token" in d for _, d in held))
    finally:
        assistant.STREAMS["ollama"] = real_stream

    # ── 3. agent mode is audited, however it ends ─────────────────────────
    # The configured provider is not Anthropic, so the real loop refuses: the
    # question must still be on the record.
    before = len(_audit("assistant_agent"))
    c.get("/assistant/agent", params={"q": "why is ci down"})
    rows = _audit("assistant_agent")
    check(f"a failed agent question is audited, got {rows[before:]}",
          len(rows) == before + 1 and rows[-1][0] == "why is ci down"
          and rows[-1][1].startswith("failed"))

    real_run = agent.run

    def fake_run(user, turns, on_step=None, stop=None):
        on_step("reading the connections")
        on_step("reading the pipelines")
        return {"answer": "the token expired", "steps": [], "proposals": []}

    agent.run = fake_run
    try:
        c.get("/assistant/agent", params={"q": "what failed overnight"})
    finally:
        agent.run = real_run
    rows = _audit("assistant_agent")
    check(f"an answered agent question is audited with its steps, "
          f"got {rows[-1:]}",
          rows and rows[-1] == ("what failed overnight",
                                "answered after 2 step(s)"))
    c.__exit__(None, None, None)

    print("  summary rows and MCP answers refuse a stored credential; agent "
          "questions are audited")
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main_test())
