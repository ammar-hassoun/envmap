#!/usr/bin/env python3
"""Actions against a cloud account: what runs, what is refused, what is recorded.

These are the cases that matter for a page that can stop a production instance
or delete an access key. The provider is stubbed — the point is not that Alibaba
answers, it is that nothing reaches Alibaba without a confirmation, that the
parameters sent are exactly the declared ones, and that the attempt is on the
record either way.
"""
from __future__ import annotations

import base64
import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("cloudops-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cloud, cloudops                                 # noqa: E402

ACCOUNT = {"id": "acc-1", "type": "alibaba", "name": "Test Cloud",
           "key_id": "k", "secret": "s", "region": "me-central-1", "pid": ""}
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    calls: list[tuple] = []

    def stub(conn, action, version, host, region, extra=None):
        calls.append((action, host, dict(extra or {})))
        if action == "DeleteSecurityGroup":
            return 403, {"Code": "Forbidden.RAM", "Message": "not authorized"}
        if action == "CreateAccessKey":
            return 200, {"AccessKey": {"AccessKeyId": "LTAI-new",
                                       "AccessKeySecret": "sh-sh-sh"}}
        if action == "RunCommand":
            return 200, {"InvokeId": "inv-1"}
        if action == "DescribeInvocationResults":
            out = base64.b64encode(b"openvpn active\n").decode()
            return 200, {"Invocation": {"InvocationResults": {
                "InvocationResult": [{"InvocationStatus": "Success",
                                      "ExitCode": 0, "Output": out,
                                      "FinishedTime": "2026-07-30T10:00:00Z"}]}}}
        if action == "DescribeSecurityGroupAttribute":
            return 200, {"SecurityGroupId": "sg-1", "SecurityGroupName": "vpn",
                         "VpcId": "vpc-1", "RegionId": "me-central-1",
                         "Permissions": {"Permission": [
                             {"IpProtocol": "TCP", "PortRange": "22/22",
                              "SourceCidrIp": "0.0.0.0/0", "Direction": "ingress",
                              "Policy": "Accept", "Description": "ssh"}]}}
        if action == "GetUser":
            return 200, {"User": {"UserName": "devops", "UserId": "1",
                                  "CreateDate": "2026-01-01T00:00:00Z"}}
        if action == "ListPoliciesForUser":
            return 200, {"Policies": {"Policy": [
                {"PolicyName": "AliyunECSReadOnlyAccess", "PolicyType": "System",
                 "AttachDate": "2026-02-02T00:00:00Z"}]}}
        if action == "ListAccessKeys":
            raise TimeoutError("The handshake operation timed out")
        return 200, {}

    real = cloud._alibaba_rpc
    cloud._alibaba_rpc = stub
    try:
        # ── the confirmation, which is the whole safety model ─────────────
        check("an ordinary action asks for a word",
              cloudops.confirm_word("ecs.stop", {"InstanceId": "i-1"}) == "CONFIRM")
        check("a removal asks for the resource's own id",
              cloudops.confirm_word("sg.delete", {"SecurityGroupId": "sg-9"})
              == "sg-9")
        check("a removal of a user asks for the user name",
              cloudops.confirm_word("ram.delete_user", {"UserName": "bob"})
              == "bob")

        # ── the preview an operator reads before saying yes ───────────────
        line = cloudops.preview("sg.authorize", {
            "SecurityGroupId": "sg-1", "IpProtocol": "tcp",
            "PortRange": "22/22", "SourceCidrIp": "0.0.0.0/0"})
        check("the preview names the call and its parameters",
              line.startswith("AuthorizeSecurityGroup(")
              and "0.0.0.0/0" in line and "22/22" in line)

        # ── a missing required parameter is refused before any call ───────
        before = len(calls)
        try:
            cloudops.run(ACCOUNT, "sg.authorize", {"SecurityGroupId": "sg-1"},
                         "me-central-1")
            check("a missing parameter is refused", False)
        except cloudops.OpError as e:
            check("a missing parameter is refused with its label",
                  "protocol" in str(e) and "source CIDR" in str(e))
        check("nothing was sent for an incomplete action", len(calls) == before)

        # ── only declared parameters are sent ────────────────────────────
        cloudops.run(ACCOUNT, "ecs.start",
                     {"InstanceId": "i-1", "Sneaky": "rm -rf",
                      "ForceStop": "true"}, "me-central-1")
        action, host, sent = calls[-1]
        check("the declared action is called", action == "StartInstance")
        check("a region-scoped product is called in its region",
              host == "ecs.me-central-1.aliyuncs.com")
        check("an undeclared field is not forwarded", "Sneaky" not in sent)
        check("a field belonging to another action is not forwarded",
              "ForceStop" not in sent)
        check("the declared one is", sent == {"InstanceId": "i-1"})

        # ── account-wide products keep their own host ────────────────────
        cloudops.run(ACCOUNT, "ram.create_user",
                     {"UserName": "bob", "DisplayName": "Bob"}, "me-central-1")
        action, host, sent = calls[-1]
        check("RAM is account-wide, not regional", host == "ram.aliyuncs.com")
        check("optional parameters pass through when given",
              sent == {"UserName": "bob", "DisplayName": "Bob"})

        # ── an empty optional parameter is omitted, not sent blank ───────
        cloudops.run(ACCOUNT, "ram.create_user",
                     {"UserName": "bob", "DisplayName": "", "Email": ""},
                     "me-central-1")
        check("blank optionals are dropped", calls[-1][2] == {"UserName": "bob"})

        # ── a provider refusal is reported, with the remedy ──────────────
        try:
            cloudops.run(ACCOUNT, "sg.delete", {"SecurityGroupId": "sg-1"},
                         "me-central-1")
            check("a 403 is raised as an error", False)
        except cloudops.OpError as e:
            check("a 403 explains the permission, not just the code",
                  "not authorized" in str(e) and "lacks read permission" in str(e))

        # ── a created key is returned once and never stored ──────────────
        got = cloudops.run(ACCOUNT, "ram.create_key", {"UserName": "bob"},
                           "me-central-1")
        check("the new key id and secret come back",
              got["data"]["AccessKeyId"] == "LTAI-new"
              and got["data"]["AccessKeySecret"] == "sh-sh-sh")
        check("the message says the secret is shown once",
              "once" in got["message"])

        # ── a provider with no implementation is refused outright ────────
        # AWS is implemented now, so the refusal is about providers that are not:
        # an Azure account must not silently take an Alibaba call.
        for kind in ("azure", "gcp", "other"):
            try:
                cloudops.run({**ACCOUNT, "type": kind}, "ecs.start",
                             {"InstanceId": "i-1"}, "x")
                check(f"a {kind} account is refused", False)
            except cloudops.OpError as e:
                check(f"a {kind} account is refused, naming the provider",
                      kind in str(e))
        # and an Alibaba action key does not exist on an AWS account
        try:
            cloudops.run({**ACCOUNT, "type": "aws"}, "ecs.start",
                         {"InstanceId": "i-1"}, "eu-west-1")
            check("an Alibaba action is not available on AWS", False)
        except cloudops.OpError as e:
            check("an Alibaba action is not available on AWS",
                  "unknown action" in str(e))

        # ── running a command ───────────────────────────────────────────
        got = cloudops.run_command(ACCOUNT, "i-1", "systemctl status openvpn",
                                   "me-central-1")
        action, host, sent = calls[-1]
        check("a command goes to Cloud Assistant", action == "RunCommand")
        check("the script is base64 and marked as such",
              base64.b64decode(sent["CommandContent"]).decode()
              == "systemctl status openvpn"
              and sent["ContentEncoding"] == "Base64")
        check("the instance is named", sent["InstanceId.1"] == "i-1")
        check("an invoke id comes back", got["invoke_id"] == "inv-1")
        try:
            cloudops.run_command(ACCOUNT, "", "ls", "me-central-1")
            check("a command with no instance is refused", False)
        except cloudops.OpError:
            check("a command with no instance is refused", True)

        res = cloudops.command_result(ACCOUNT, "inv-1", "me-central-1")
        check("the output is decoded", res["output"].strip() == "openvpn active")
        check("a finished command reads as done",
              res["done"] and res["status"] == "Success" and res["exit"] == 0)

        # ── detail: fields, a table, and an extra that fails ─────────────
        det = cloudops.detail(ACCOUNT, "secgroups", "sg-1", "me-central-1")
        check("detail reads the fields", ("name", "vpn") in det["fields"])
        check("detail reads the rules table",
              det["table"]["label"] == "rules"
              and det["table"]["rows"][0]["source"] == "0.0.0.0/0")

        det = cloudops.detail(ACCOUNT, "ram_users", "devops", "me-central-1")
        labels = {e["label"]: e for e in det["extras"]}
        check("an extra that works is listed",
              labels["attached policies"]["rows"][0][0]
              == "AliyunECSReadOnlyAccess")
        check("an extra that times out says so rather than vanishing",
              "timed out" in labels["access keys"]["note"]
              and labels["access keys"]["rows"] == [])

        det = cloudops.detail(ACCOUNT, "nonsense", "x", "me-central-1")
        check("an unknown group is reported, not crashed",
              "no detail view" in det["error"])

        # ── the form knows the id already ────────────────────────────────
        check("an instance page prefills its own id",
              cloudops.prefill_for("compute", "i-9")["InstanceId"] == "i-9")
        check("a user page prefills the user name",
              cloudops.prefill_for("ram_users", "bob")["UserName"] == "bob")

        # ── the console link ────────────────────────────────────────────
        def vnc_stub(conn, action, version, host, region, extra=None):
            calls.append((action, host, dict(extra or {})))
            if action == "DescribeInstanceVncUrl":
                return 200, {"VncUrl": "wss://vncproxy.example.com/ws?token=abc"}
            return 200, {}
        cloud._alibaba_rpc = vnc_stub
        link = cloudops.vnc_link(ACCOUNT, "i-1", "me-central-1")
        check("the console link goes to Alibaba's own console",
              link.startswith("https://ecs.console.aliyun.com/vnc/index.htm?"))
        check("it carries the session URL and the instance",
              "vncUrl=" in link and "instanceId=i-1" in link
              and "regionId=me-central-1" in link)
        check("no password is put in the URL — it would land in history and logs",
              "password" not in link.lower() and "passwd" not in link.lower())
        check("setting the VNC password is a separate, confirmed action",
              "ecs.vnc_password" in cloudops.ALI_ACTIONS
              and cloudops.ALI_ACTIONS["ecs.vnc_password"]["danger"] == "care")

        def stopped(conn, action, version, host, region, extra=None):
            return 403, {"Code": "IncorrectInstanceStatus",
                         "Message": "The current status of the resource is invalid."}
        cloud._alibaba_rpc = stopped
        try:
            cloudops.vnc_link(ACCOUNT, "i-1", "me-central-1")
            check("a stopped instance is explained", False)
        except cloudops.OpError as e:
            check("a stopped instance says it has to be running",
                  "has to be running" in str(e))
        cloud._alibaba_rpc = stub

        # ── deletions that must not exist at all ────────────────────────
        for absent in ("rds.delete", "vpc.delete", "subnet.delete",
                       "ecs.delete", "disk.delete"):
            check(f"there is no {absent} action for Alibaba",
                  absent not in cloudops.ALI_ACTIONS)
        for absent in ("rds.delete", "vpc.delete", "subnet.delete",
                       "ec2.terminate", "ebs.delete", "s3.delete_bucket"):
            check(f"there is no {absent} action for AWS",
                  absent not in cloudops.AWS_ACTIONS)
    finally:
        cloud._alibaba_rpc = real

    bad_routes = check_routes()
    print("OK" if not (bad + bad_routes) else f"{bad + bad_routes} FAILED")
    return bad + bad_routes


def check_routes() -> int:
    """The route around the action: confirmation enforced, attempt audited."""
    from fastapi.testclient import TestClient
    from app import auth, db, main, store

    class _FakeRequest:
        """Enough of a request for ctx() to be called directly."""
        class state:
            user = None

    problems = 0
    email, pw = "ops@test.local", "Ops-Routes-Are-Safe-42"
    uid = auth.create_user(email, "Ops", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    acc_id = store.add_conn("cloud", "", {"type": "alibaba", "name": "Test Cloud",
                                          "key_id": "k", "secret": "s",
                                          "region": "me-central-1"})
    sent: dict = {}

    def stub(conn, action, version, host, region, extra=None):
        if action == "DescribeRegions":
            return 200, {"Regions": {"Region": [
                {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                 "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
        if action.startswith(("Create", "Delete", "Stop", "Start")):
            sent["call"] = (action, dict(extra or {}))
        return 200, {}

    real = cloud._alibaba_rpc
    cloud._alibaba_rpc = stub
    c = TestClient(main.app)
    try:
        with c:
            c.post("/login", data={"email": email, "password": pw},
                   follow_redirects=False)
            c.post("/mfa", data={"code": auth._totp_at(
                "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
                follow_redirects=False)

            def post(**extra):
                return c.post("/clouds/action",
                              data={"account": acc_id, "region": "me-central-1",
                                    "back": "/clouds", **extra},
                              follow_redirects=False)

            r = post(action="ecs.stop", InstanceId="i-1", confirm="")
            if "call" in sent or "err=" not in r.headers.get("location", ""):
                print("  FAIL an empty confirmation must refuse")
                problems += 1
            r = post(action="ecs.stop", InstanceId="i-1", confirm="confirm")
            if "call" in sent:
                print("  FAIL the confirmation must be exact, not case-insensitive")
                problems += 1
            r = post(action="sg.delete", SecurityGroupId="sg-1", confirm="CONFIRM")
            if "call" in sent:
                print("  FAIL a removal must not accept the generic word")
                problems += 1
            r = post(action="sg.delete", SecurityGroupId="sg-1", confirm="sg-1")
            if sent.get("call", ("", {}))[0] != "DeleteSecurityGroup":
                print(f"  FAIL the correct id must run it, got {sent.get('call')}")
                problems += 1
            r = post(action="nope.nope", confirm="CONFIRM")
            import urllib.parse as _up
            if "unknown action" not in _up.unquote(r.headers.get("location", "")):
                print("  FAIL an unknown action must be reported")
                problems += 1

            rows = db.connect().execute(
                "SELECT action, detail FROM audit WHERE action LIKE 'cloud_%'"
            ).fetchall()
            blob = " ".join(f"{a[0]} {a[1]}" for a in rows)
            if "DeleteSecurityGroup" not in blob:
                print("  FAIL the call that ran must be in the audit log")
                problems += 1
            # a refused confirmation never reaches the provider, so it is not
            # audited as an action — but the one that ran must be, with its
            # parameters, and that is what the log above proves

            # ── CSV export ───────────────────────────────────────────
            cloud._inv[cloud._inv_key({"id": acc_id}, "")] = (time.time(), {
                "groups": [{"key": "subnets", "label": "Subnets", "icon": "x",
                            "rows": [{"id": "vsw-1", "name": "private-a",
                                      "kind": "10.0.1.0/24", "state": "Available",
                                      "extra": "252 free", "zone": "me-central-1a"}]}],
                "notes": [], "region": "me-central-1", "total": 1})
            r = c.get(f"/clouds/export/{acc_id}/subnets.csv")
            body = r.text.strip().split("\n")
            if r.headers.get("content-type", "").split(";")[0] != "text/csv":
                print("  FAIL the export must be served as CSV")
                problems += 1
            if "attachment" not in (r.headers.get("content-disposition") or ""):
                print("  FAIL the export must download rather than render")
                problems += 1
            if len(body) != 2 or "vsw-1" not in body[1] or "252 free" not in body[1]:
                print(f"  FAIL the export must carry the rows shown: {body}")
                problems += 1
            if c.get(f"/clouds/export/{acc_id}/nonsense.csv").status_code != 404:
                print("  FAIL an unknown group must 404 rather than export nothing")
                problems += 1

            # ── the shadowing trap ───────────────────────────────────
            # base.html defines a macro called "link". A context value under
            # that name is shadowed inside every block, so the console button
            # rendered as "<Macro 'link'>", navigated to a URL containing that
            # text, and Alibaba answered "The specified InstanceId does not
            # exist" — three symptoms, one cause, none of them pointing at it.
            try:
                main.ctx(_FakeRequest(), link="https://example.com/x")
                print("  FAIL a context key shadowed by a base macro must be refused")
                problems += 1
            except RuntimeError as e:
                if "shadowed" not in str(e):
                    print(f"  FAIL the refusal must say why: {e}")
                    problems += 1
            if "link" not in main.SHADOWED:
                print("  FAIL the guard must read base.html's macro names")
                problems += 1

            # and the console page must carry a real link, not a macro
            def vnc(conn, action, version, host, region, extra=None):
                if action == "DescribeInstanceVncUrl":
                    return 200, {"VncUrl": "wss://vnc.example.com/ws?t=1"}
                if action == "DescribeRegions":
                    return 200, {"Regions": {"Region": [
                        {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                         "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
                return 200, {}
            cloud._alibaba_rpc = vnc
            page = c.get(f"/clouds/console/{acc_id}/i-42?region=me-central-1").text
            if "<Macro" in page:
                print("  FAIL a macro leaked into the console page")
                problems += 1
            if "ecs.console.aliyun.com/vnc" not in page:
                print("  FAIL the console page must carry the session link")
                problems += 1
            if "instanceId=i-42" not in page.replace("&amp;", "&"):
                print("  FAIL the link must name the instance it was asked for")
                problems += 1

            # ── search must follow you through the section ────────────
            # It lived on the account overview alone, so following a result
            # meant losing the thing that found it.
            import json as _json
            cloud._inv[cloud._inv_key({"id": acc_id}, "")] = (time.time(), {
                "groups": [{"key": "compute", "label": "ECS instances",
                            "icon": "🖥", "rows": [
                                {"id": "i-9", "name": "web", "kind": "ecs.t6",
                                 "extra": "10.0.0.9", "state": "Running"}]}],
                "notes": [], "region": "me-central-1", "total": 1,
                "billing": {}, "security": {}})
            for path, label in (
                    (f"/clouds?account={acc_id}", "account"),
                    (f"/clouds/r/{acc_id}/compute", "resource list"),
                    (f"/clouds/r/{acc_id}/compute/i-9", "resource detail"),
                    (f"/clouds/bills?account={acc_id}", "bills"),
                    (f"/clouds/console/{acc_id}/i-9", "console"),
                    (f"/clouds/shell/{acc_id}/i-9", "command runner")):
                page = c.get(path).text
                idx = re.search(r"const INDEX = (\[.*);\n", page)
                if 'id="cs"' not in page:
                    print(f"  FAIL {label} has no search box")
                    problems += 1
                    continue
                if not idx:
                    print(f"  FAIL {label} has a box but no index to search")
                    problems += 1
                    continue
                if not _json.loads(idx.group(1)):
                    print(f"  FAIL {label} carries an empty index")
                    problems += 1
                if page.index('id="cs"') > idx.start():
                    print(f"  FAIL {label} runs the script before the box exists")
                    problems += 1

            # an external URL in "back" must not be honoured
            r = c.post("/clouds/action",
                       data={"account": acc_id, "action": "ecs.start",
                             "InstanceId": "i-1", "confirm": "CONFIRM",
                             "back": "https://evil.example.com/x"},
                       follow_redirects=False)
            if r.headers.get("location", "").startswith("https://evil"):
                print("  FAIL an off-site redirect target must be ignored")
                problems += 1
    finally:
        cloud._alibaba_rpc = real
    print(f"  routes: {'ok' if not problems else str(problems) + ' failed'}")
    return problems


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
