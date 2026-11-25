#!/usr/bin/env python3
"""The doctor on a Claude subscription, where Claude Code is not installed.

WHY THIS EXISTS
    Reported 22 November 2026 from dev: pressing H in a cluster's 3D view
    showed "The doctor is thinking…" for ever. The portal starts Claude Code
    for the doctor (`doctor_cli`), and in a cluster there is none and nobody
    signed in to it, so every call waited for an AI client somewhere else that
    never came. Now a person connects their own subscription (the token
    `claude setup-token` prints) on their account page, and an installation
    that allows it has the portal fetch Claude Code from Anthropic's release
    server, checked against Anthropic's checksum, and run it as that person.

    Anthropic's server is played here by a local one, so nothing is downloaded.

    ./.venv/bin/python tests/test_doctor_subscription.py
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("doctor-sub-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient                      # noqa: E402
from app import aiuser, auth, claude_code, db, doctor_cli, env, main, mcp, rbac  # noqa: E402

bad = 0
TOKEN = "sk-ant-oat01-" + "Zq9" * 30
BINARY = b"#!/bin/sh\necho stand-in\n"
SERVED = {"sum": hashlib.sha256(BINARY).hexdigest()}


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")
    else:
        print(f"  ok   {what}")


class Release(http.server.BaseHTTPRequestHandler):
    """Anthropic's release server, as far as the portal asks it anything."""
    def do_GET(self):                                          # noqa: N802
        plat = claude_code.plat()
        body = {"/stable": b"9.9.9\n",
                "/9.9.9/manifest.json": json.dumps({"platforms": {plat: {
                    "checksum": SERVED["sum"], "size": len(BINARY)}}}).encode(),
                f"/9.9.9/{plat}/claude": BINARY}.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        self.wfile.write(body or b"")

    def log_message(self, *a):
        pass


def until(cond, secs=10.0) -> bool:
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def main_test() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Release)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    claude_code.BASE = f"http://127.0.0.1:{srv.server_address[1]}"
    mcp.save_config(enabled=True)

    uid = auth.create_user("sub@test.invalid", "Sub", "Passw0rd!xY-doctor", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", "Walker", "", ["clusters", "manage"], [], [])])
    me = auth.by_id(uid)
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": me["email"], "password": "Passw0rd!xY-doctor"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
           follow_redirects=False)

    print("an installation that does not run Claude Code")
    env.DOCTOR_CLI, env.DOCTOR_CLI_FETCH = "", False
    r = c.post("/me/doctor", data={"token": TOKEN}, follow_redirects=False)
    check("a subscription token is refused, saying why, and nothing is kept",
          "err=" in r.headers.get("location", "") and "doctorClaudeCode" in r.headers.get("location", "")
          and not doctor_cli.signin_of(uid))
    check("and the account page asks for an API key only", "claude setup-token" not in c.get("/me").text)

    print("an installation that fetches Claude Code")
    env.DOCTOR_CLI_FETCH = True
    page = c.get("/me").text
    check("the account page offers the subscription, and says how to get its token",
          "claude setup-token" in page and "Claude Code sign-in" in page and "It is not the Claude API" in page
          and 'name="model"' not in page)
    ok, why = doctor_cli.available(me)
    check(f"before anything is connected, a call says what to connect ({why[:50]})",
          not ok and "sign Claude Code in to your Claude subscription" in why)

    r = c.post("/me/doctor", data={"token": "sk-ant-api03-" + "k" * 90}, follow_redirects=False)
    check("an API key is refused here: the doctor is Claude Code, not the API",
          "err=" in r.headers.get("location", "") and "not%20an%20API%20key" in r.headers.get("location", "")
          and (aiuser.get(uid) or {}).get("provider") != "anthropic")

    SERVED["sum"] = "0" * 64                                    # a download that is not what Anthropic published
    r = c.post("/me/doctor", data={"token": TOKEN[:20] + "\n" + TOKEN[20:]}, follow_redirects=False)
    check("the token, even wrapped onto two lines, connects the subscription",
          "msg=" in r.headers.get("location", "") and doctor_cli.signin_of(uid) == TOKEN)
    raw = (env.DATA_DIR / "portal.db").read_bytes() if (env.DATA_DIR / "portal.db").exists() else b""
    check("it is kept sealed, never in the clear", raw and TOKEN.encode() not in raw)
    check("and it is not mistaken for an API key", (aiuser.get(uid) or {}).get("token", "") != TOKEN)
    until(lambda: claude_code.status()["state"] in ("failed", "ready"))
    check("a download that does not match Anthropic's checksum is thrown away, never kept",
          claude_code.status()["state"] == "failed" and not claude_code.path()
          and not list(claude_code.home().glob("*/claude*")))
    ok, why = doctor_cli.available(me)
    check(f"and the call says so, and tries again ({why[:60]})", not ok and "could not fetch" in why)

    SERVED["sum"] = hashlib.sha256(BINARY).hexdigest()
    until(lambda: claude_code.status()["state"] == "ready")
    got = claude_code.path()
    check(f"what matches is kept on the data volume, runnable ({got[-30:]})",
          got.endswith("9.9.9/claude") and os.access(got, os.X_OK)
          and pathlib.Path(got).read_bytes() == BINARY)
    ok, why = doctor_cli.available(me)
    check(f"and the doctor comes for this person ({why})", ok)

    print("a call starts Claude Code, never the API")
    from app import doctor_ai, scene, store
    pid = store.add_project("Game", icon="x")
    cid = store.add_cluster(pid, "game", "apiVersion: v1\nkind: Config\n", "game")
    scene.collect = lambda cl: {"pods": [], "error": ""}
    went = []
    keep = (doctor_ai.available, doctor_ai.start, doctor_cli.start)
    doctor_ai.available = lambda u: (True, "")                 # as if an API key were stored too
    doctor_ai.start = lambda *a, **k: went.append("api") or "started"
    doctor_cli.start = lambda *a, **k: went.append("cli") or "started"
    got = c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid, "pod": ""}).json()
    doctor_ai.available, doctor_ai.start, doctor_cli.start = keep
    check(f"with an API key stored as well, the call goes to Claude Code ({went}, {got.get('doctor')})",
          went == ["cli"] and got.get("doctor") == "portal")

    home = str(env.DATA_DIR / "visit-home")
    run = doctor_cli._env(me, home)
    check("the process is signed in as them, lives in the visit's own directory and is not updated in place",
          run.get("CLAUDE_CODE_OAUTH_TOKEN") == TOKEN and run.get("HOME") == home
          and run.get("DISABLE_AUTOUPDATER") == "1")
    other = auth.by_id(auth.create_user("other@test.invalid", "Other", "Passw0rd!xY-doctor", role="user"))
    check("nobody else's call runs on that subscription",
          not doctor_cli.available(other)[0] and "CLAUDE_CODE_OAUTH_TOKEN" not in doctor_cli._env(other, home))

    print("taking it back")
    c.post("/me/doctor", data={"disconnect": "1"}, follow_redirects=False)
    check("Disconnect forgets the subscription", not doctor_cli.signin_of(uid) and not doctor_cli.available(me)[0])
    doctor_cli.signin_save(uid, TOKEN)
    admin = auth.create_user("root@test.invalid", "Root", "Passw0rd!xY-doctor", role="admin")
    main.mcp.drop_for_user  # the account-deletion path below calls both
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", admin))
    src = (ROOT / "app" / "main.py").read_text()
    check("deleting the account forgets it too",
          "mcp.drop_for_user(uid)\n    doctor_cli.signin_forget(uid)" in src)

    print("the view says who it is waiting for")
    view = (ROOT / "static" / "cluster3d.js").read_text()
    check("a call waiting for an AI client elsewhere is not shown as a doctor thinking",
          "doc.via === 'mcp'" in view and "Waiting for an AI client connected over MCP to answer." in view
          and view.count("doc.via = d.doctor || doc.via;") == 2)
    srv.shutdown()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
