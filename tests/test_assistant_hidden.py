#!/usr/bin/env python3
"""The in-portal assistant is off by default (PORTAL_ASSISTANT); MCP stays on.

While the assistant is off its Ask panel is not rendered, its /assistant
endpoints do not exist (including /assistant/ask, otherwise an always-open
path), /me/assistant and /settings/assistant are closed, and the Assistant
card is gone from the Settings hub. MCP is a separate area and is untouched
either way. assistant.enabled() reads the environment on each call, so this
drives both states through the real middleware and routes in one process.

    ./.venv/bin/python tests/test_assistant_hidden.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("assistant-hidden-test-")
os.environ.pop("PORTAL_ASSISTANT", None)                       # start disabled
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import assistant, auth, db, main                      # noqa: E402

bad = 0
PW = "Assistant-Hidden-42"
ASSIST_CARD = "The model that answers questions about this estate"
MCP_CARD = "AI clients (MCP)"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def admin_client():
    from fastapi.testclient import TestClient
    uid = auth.create_user("admin@test.local", "Admin", PW)
    db.run("UPDATE users SET role='admin', mfa_enrolled=1, totp_secret=? "
           "WHERE id=?", ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "admin@test.local", "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def main_test() -> int:
    c = admin_client()

    print("off by default: the assistant does not exist, MCP does")
    os.environ.pop("PORTAL_ASSISTANT", None)
    check("enabled() is False by default", assistant.enabled() is False)
    check("/assistant/agent.json -> 404",
          c.get("/assistant/agent.json", follow_redirects=False).status_code == 404)
    check("/assistant/ask -> 404 (an otherwise always-open path)",
          c.post("/assistant/ask", follow_redirects=False).status_code == 404)
    check("/me/assistant -> 404",
          c.post("/me/assistant", data={}, follow_redirects=False).status_code == 404)
    r = c.get("/settings/assistant", follow_redirects=False)
    check(f"/settings/assistant redirects away, got {r.status_code}",
          r.status_code in (302, 303))
    hub = c.get("/settings", follow_redirects=False).text
    check("the Assistant card is gone from the Settings hub", ASSIST_CARD not in hub)
    check("the MCP card is still on the Settings hub", MCP_CARD in hub)
    check("the Ask widget is not rendered on a page",
          "askLaunch" not in c.get("/", follow_redirects=False).text)
    check("the per-user assistant section is gone from the account page",
          "your own model account" not in c.get("/me", follow_redirects=False).text)

    print("on with PORTAL_ASSISTANT=1: it comes back, MCP unchanged")
    os.environ["PORTAL_ASSISTANT"] = "1"
    check("enabled() is True with the env set", assistant.enabled() is True)
    check("/assistant/agent.json is reachable for an admin (not 404)",
          c.get("/assistant/agent.json", follow_redirects=False).status_code != 404)
    check("/settings/assistant opens (200)",
          c.get("/settings/assistant", follow_redirects=False).status_code == 200)
    hub = c.get("/settings", follow_redirects=False).text
    check("the Assistant card is back", ASSIST_CARD in hub)
    check("the MCP card is still there", MCP_CARD in hub)
    check("the Ask widget renders",
          "askLaunch" in c.get("/", follow_redirects=False).text)

    os.environ.pop("PORTAL_ASSISTANT", None)
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
