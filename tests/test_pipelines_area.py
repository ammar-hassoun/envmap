#!/usr/bin/env python3
"""A run's stages and logs are governed by Pipelines, not by Configuration.

`/pipelines/stages`, `/pipelines/logs` and `/pipelines/logs/body` each asked
`rbac.may_project` about the connection's project — and that function
defaults to the Configuration area. So a role granting Pipelines and nothing
else was refused every stage strip and every build log on the page it could
open, while the project scope actually consulted was Configuration's: a role
confined to ANOTHER project's pipelines read this project's logs as long as
it could edit this project's values.

Driven through the real middleware and routes, with the CI provider stood in
for so that what is checked is who may ask, not whether a provider answers.

    ./.venv/bin/python tests/test_pipelines_area.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pipearea-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, ci, db, main, rbac, store                # noqa: E402

bad = 0
PW = "Pipelines-Area-42"
asked: list[str] = []
JOB = {"id": "console", "name": "Console output", "status": "failed",
       "duration": "", "url": ""}


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _stub_provider() -> None:
    """Answer as a provider would, and record that it was asked."""
    def stages(conn, ref, refresh=False):
        asked.append("stages")
        return {"stages": [{"name": "build", "status": "failed"}],
                "failed": {"name": "build"}, "note": ""}

    def log_shell(conn, ref, job=""):
        asked.append("log_shell")
        return {"jobs": [JOB], "job": JOB, "note": ""}

    def log(conn, ref, job="", refresh=False):
        asked.append("log")
        return {"jobs": [JOB], "job": JOB, "lines": ["npm ERR! the build broke"],
                "stamps": [], "truncated": False, "first_error": 0, "note": ""}

    ci.stages, ci.log_shell, ci.log = stages, log_shell, log


def signed_in(email: str, roles):
    from fastapi.testclient import TestClient
    uid = auth.create_user(email, "CI", PW)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    rbac.set_for_user(uid, list(roles))
    c = TestClient(main.app)
    c.post("/login", data={"email": email, "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def reads(c, cid: str) -> dict:
    """What each of the three routes answers this person, by name."""
    ref = "https://jenkins.example.com/job/web/42/"
    q = f"conn={cid}&ref={ref}"
    return {
        "stages": c.get(f"/pipelines/stages?{q}", follow_redirects=False),
        "logs": c.get(f"/pipelines/logs?{q}", follow_redirects=False),
        "body": c.get(f"/pipelines/logs/body?{q}", follow_redirects=False),
    }


def main_test() -> int:
    _stub_provider()
    here = store.add_project("Storefront")
    there = store.add_project("Warehouse")
    cid = store.add_conn("ci", here, {"name": "Storefront CI", "type": "jenkins",
                                      "base_url": "https://jenkins.example.com"})

    pipes = rbac.save("", "CI reader", "", ["pipelines"], [], [])
    config = rbac.save("", "Config editor", "", ["config"], [], [])
    pipes_here = rbac.save("", "Storefront CI", "", ["pipelines"], [here], [])
    pipes_there = rbac.save("", "Warehouse CI", "", ["pipelines"], [there], [])
    config_here = rbac.save("", "Storefront config", "", ["config"], [here], [])

    print("a Pipelines-only role reads a run's stages and logs")
    del asked[:]
    got = reads(signed_in("pipes@test.local", [pipes]), cid)
    for name, r in got.items():
        check(f"{name}: answered, got {r.status_code}", r.status_code == 200)
    check("the stage strip came back", got["stages"].json().get("stages"))
    check("the log page names the job", "Console output" in got["logs"].text)
    check("and the log text arrived", "the build broke" in got["body"].text)
    check(f"the provider was asked each time, got {asked}",
          asked == ["stages", "log_shell", "log"])

    print("a Configuration-only role does not")
    del asked[:]
    got = reads(signed_in("config@test.local", [config]), cid)
    for name, r in got.items():
        check(f"{name}: refused, got {r.status_code}", r.status_code == 403)
    check(f"and the provider was never asked, got {asked}", not asked)

    print("the project scope consulted is Pipelines'")
    del asked[:]
    got = reads(signed_in("here@test.local", [pipes_here]), cid)
    check("Pipelines confined to this project reads it",
          all(r.status_code == 200 for r in got.values()))
    # The sharp case: the old check consulted Configuration's scope, so editing
    # this project's values let a role confined to another project's
    # pipelines read this one's logs.
    del asked[:]
    got = reads(signed_in("there@test.local", [pipes_there, config_here]), cid)
    for name, r in got.items():
        check(f"{name}: Pipelines for another project is refused, even with "
              f"Configuration here, got {r.status_code}", r.status_code == 403)
    check(f"and nothing was asked of the provider, got {asked}", not asked)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
