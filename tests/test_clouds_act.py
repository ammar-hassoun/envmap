#!/usr/bin/env python3
"""Cloud actions and SSM / Cloud Assistant commands need the escalating
"Cloud accounts: act" grant, not just "Cloud accounts" (S14).

"Cloud accounts" is inventory and diagrams — reading. Changing what an account
runs (power, tags, snapshots, security groups, IAM/RAM users and keys, ECR,
elastic IPs, the Alibaba VNC console session) and running a root command on an
instance are the acting half, and a user manager could grant the reading area.
This proves:

  * a reader (clouds, no clouds_act) is REFUSED at every acting route, the
    refusal is audited, and the provider is never called;
  * the acting controls are hidden from that reader on the pages;
  * a holder of clouds_act gets the controls and the call goes through;
  * the AWS console link — which only deep-links into AWS's own console and
    opens nothing — stays readable under "Cloud accounts".

Run:  PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_clouds_act.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("clouds-act-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, cloud, db, main, rbac, store             # noqa: E402

bad = 0


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


def _user(email: str, areas: list[str]) -> str:
    uid = auth.create_user(email, "Cloud Tester", "Clouds-Are-Gated-42",
                           role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    rid = rbac.save("", f"role-{email}", "", areas, [], [])
    rbac.set_for_user(uid, [rid])
    return uid


def _client(email: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Clouds-Are-Gated-42"},
           follow_redirects=False)
    # A code is good once (auth.verify_totp_once); this harness signs the
    # same account in several times inside one 30-second step, so it
    # forgets the last use first -- the test-only escape, never the app's.
    auth.forget_totp_use(auth.by_email(email)["id"])
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def _loc(r) -> str:
    return urllib.parse.unquote(r.headers.get("location", ""))


def _cloud_actions(blob: str) -> list[str]:
    rows = db.connect().execute(
        "SELECT action, detail FROM audit WHERE action LIKE 'cloud_%' "
        "ORDER BY id").fetchall()
    return [f"{a[0]} {a[1]}" for a in rows]


def _seed_inv(acc_id: str, group: dict) -> None:
    cloud._inv[cloud._inv_key({"id": acc_id}, "")] = (time.time(), {
        "groups": [group], "notes": [], "region": "me-central-1", "total": 1,
        "billing": {}, "security": {}})


def main_test() -> int:
    # Two accounts and the provider wired to a stub that records every call.
    ali = store.add_conn("cloud", "", {"type": "alibaba", "name": "Ali Test",
                                       "key_id": "k", "secret": "s",
                                       "region": "me-central-1"})
    aws = store.add_conn("cloud", "", {"type": "aws", "name": "AWS Test",
                                       "key_id": "AKIA", "secret": "s",
                                       "region": "us-east-1"})
    sent: list = []

    def stub(conn, action, version, host, region, extra=None):
        sent.append(action)
        if action == "DescribeRegions":
            return 200, {"Regions": {"Region": [
                {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                 "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
        if action == "DescribeInstanceVncUrl":
            return 200, {"VncUrl": "wss://vnc.example.com/ws?t=1"}
        if action == "RunCommand":
            return 200, {"InvokeId": "inv-1"}
        return 200, {}

    real = cloud._alibaba_rpc
    cloud._alibaba_rpc = stub
    compute = {"key": "compute", "label": "ECS instances", "icon": "🖥",
               "rows": [{"id": "i-9", "name": "web", "kind": "ecs.t6",
                         "extra": "10.0.0.9", "state": "Running"}]}
    try:
        reader = "reader@test.local"
        actor = "actor@test.local"
        _user(reader, ["clouds"])
        _user(actor, ["clouds", "clouds_act"])

        # ── 1. a reader is refused at every acting route ──────────────────
        rc = _client(reader)
        sent.clear()
        r = rc.post("/clouds/action", follow_redirects=False,
                    data={"account": ali, "region": "me-central-1",
                          "action": "ecs.stop", "InstanceId": "i-9",
                          "confirm": "CONFIRM", "back": "/clouds"})
        check(f"action POST is refused, got {r.status_code}", r.status_code == 303)
        check(f"and says which grant: {_loc(r)}", "Cloud accounts: act" in _loc(r))
        check("and the provider was NOT called", sent == [])

        r = rc.get(f"/clouds/shell/{ali}/i-9?region=me-central-1",
                   follow_redirects=False)
        check(f"the command console GET is refused, got {r.status_code}",
              r.status_code == 303 and "Cloud accounts: act" in _loc(r))
        r = rc.post(f"/clouds/shell/{ali}/i-9", follow_redirects=False,
                    data={"script": "whoami", "region": "me-central-1",
                          "confirm": "RUN"})
        check(f"running a command is refused, got {r.status_code}",
              r.status_code == 303 and "Cloud accounts: act" in _loc(r))
        check("and no command was ever submitted", "RunCommand" not in sent)

        r = rc.get(f"/clouds/console/{ali}/i-9?region=me-central-1",
                   follow_redirects=False)
        check(f"the Alibaba VNC console is refused, got {r.status_code}",
              r.status_code == 303 and "Cloud accounts: act" in _loc(r))
        check("and no VNC session was issued",
              "DescribeInstanceVncUrl" not in sent)

        acts = _cloud_actions("")
        for want in ("cloud_action_denied", "cloud_command_denied",
                     "cloud_console_denied"):
            check(f"the refusal {want} is audited",
                  any(a.startswith(want) for a in acts))

        # A refusal must be READ, not just carried in a URL: the account
        # overview renders no `err`, so one sent there vanished. Each lands on
        # a page that shows it.
        for how, r in (
                ("the command console", rc.get(
                    f"/clouds/shell/{ali}/i-9?region=me-central-1",
                    follow_redirects=False)),
                ("running a command", rc.post(
                    f"/clouds/shell/{ali}/i-9", follow_redirects=False,
                    data={"script": "id", "region": "me-central-1",
                          "confirm": "RUN"})),
                ("the VNC console", rc.get(
                    f"/clouds/console/{ali}/i-9?region=me-central-1",
                    follow_redirects=False)),
                ("an action", rc.post(
                    "/clouds/action", follow_redirects=False,
                    data={"account": ali, "region": "me-central-1",
                          "action": "ecs.reboot", "InstanceId": "i-9",
                          "confirm": "CONFIRM",
                          "back": f"/clouds/r/{ali}/compute/i-9"}))):
            page = rc.get(r.headers.get("location", "/")).text
            flash = page[page.find('class="flash err"'):][:400]
            check(f"refusing {how} SHOWS the reason where it lands",
                  'class="flash err"' in page and "Cloud accounts: act" in flash)

        # ── 2. the controls are hidden from the reader ────────────────────
        _seed_inv(ali, compute)
        page = rc.get(f"/clouds/r/{ali}/compute?region=me-central-1").text
        check("the action form is not on the resource list",
              'action="/clouds/action"' not in page)
        check("and the reason is shown instead", "Actions are hidden" in page)
        page = rc.get(f"/clouds/r/{ali}/compute/i-9?region=me-central-1").text
        check("the action form is not on the detail page",
              'action="/clouds/action"' not in page)
        check("the Run-a-command button is hidden",
              "Run a command" not in page)
        check("the Console button is hidden",
              f"/clouds/console/{ali}/i-9" not in page)
        rc.__exit__(None, None, None)

        # ── 3. the AWS console link stays readable (no act, no issuance) ──
        rc = _client(reader)
        sent.clear()
        r = rc.get(f"/clouds/console/{aws}/i-7?region=us-east-1",
                   follow_redirects=False)
        check(f"the AWS console link is NOT refused, got {r.status_code}",
              r.status_code == 200)
        check("the AWS console deep link is on the page",
              "console.aws.amazon.com" in r.text)
        check("and opening it issued nothing on the provider", sent == [])
        acts = _cloud_actions("")
        check("a read of the AWS console is not audited as a denial",
              not any("i-7" in a and "denied" in a for a in acts))
        rc.__exit__(None, None, None)

        # ── 4. the holder of clouds_act gets the controls and the call ────
        ac = _client(actor)
        sent.clear()
        r = ac.post("/clouds/action", follow_redirects=False,
                    data={"account": ali, "region": "me-central-1",
                          "action": "sg.delete", "SecurityGroupId": "sg-1",
                          "confirm": "sg-1", "back": "/clouds"})
        check(f"the action is accepted, got {r.status_code} {_loc(r)}",
              r.status_code == 303 and "err=" not in _loc(r))
        check("and the provider actually ran the delete",
              "DeleteSecurityGroup" in sent)
        acts = _cloud_actions("")
        check("the action is audited (not as a denial)",
              any(a.startswith("cloud_action ") and "DeleteSecurityGroup" in a
                  for a in acts))

        _seed_inv(ali, compute)
        page = ac.get(f"/clouds/r/{ali}/compute?region=me-central-1").text
        check("the action form IS shown to the actor",
              'action="/clouds/action"' in page)
        check("and the hidden-reason note is gone", "Actions are hidden" not in page)
        page = ac.get(f"/clouds/r/{ali}/compute/i-9?region=me-central-1").text
        check("the actor sees the Run-a-command button", "Run a command" in page)

        r = ac.get(f"/clouds/shell/{ali}/i-9?region=me-central-1",
                   follow_redirects=False)
        check(f"the actor may open the command console, got {r.status_code}",
              r.status_code == 200)

        sent.clear()
        page = ac.get(f"/clouds/console/{ali}/i-9?region=me-central-1").text
        check("the actor is issued the VNC session",
              "DescribeInstanceVncUrl" in sent
              and "ecs.console.aliyun.com/vnc" in page)
        ac.__exit__(None, None, None)

        print("  cloud actions and root commands need Cloud accounts: act; "
              "reading and the AWS console link stay with Cloud accounts")
    finally:
        cloud._alibaba_rpc = real

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main_test())
