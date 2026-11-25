#!/usr/bin/env python3
"""The provisioning wizard's RBAC (S15).

Before this, /provision/* was governed by NOTHING — area_for_path returned None,
so anybody signed in could reach it — and the routes that add/remove Proxmox
hosts, upload/delete datastore files and generate a credential-storing stack
rode the read-only `terraform` area. The post-provision playbook also ran with
no `ansible_run` check. This proves:

  * /provision is now governed by `terraform` (a user without it is refused by
    the middleware, before any handler runs);
  * a `terraform` reader may READ the provisioning pages but is refused at every
    acting route (host add/edit/remove/add-many/test, ISO upload/delete, VM
    action/edit, create, stage, stage-probe) — those need `terraform_apply`;
  * arming a post-provision playbook needs `ansible_run`: refused at create time
    when the spec carries one, and at apply time for a stack that has one,
    rather than silently skipping it.

No Proxmox is reached: every acting check happens before the provider call, so a
refusal is a clean 403 and a user who passes the gate fails later for a
different reason (never the permission one).

Run:  PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_provision_rbac.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("provision-rbac-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, provision, rbac, terraform     # noqa: E402

bad = 0


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


def _enrol(email: str, areas: list[str] | None, admin: bool = False) -> str:
    uid = auth.create_user(email, "P", "Provision-Pass-Word-42",
                           role="admin" if admin else "user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0 WHERE id=?",
           ("TESTSECRET", uid))
    if areas is not None:
        rid = rbac.save("", f"role-{email}", "", areas, [], [], [])
        rbac.set_for_user(uid, [rid])
    return uid


def _client(email: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": "Provision-Pass-Word-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


# The acting routes, by the kind of body they take. The value is the request
# args; every one of these must be refused for a reader and reach the provider
# (i.e. NOT a permission 403) for an apply holder.
JSON_ROUTES = {
    "/provision/host/remove": {"connection": "x"},
    "/provision/host/test": {"endpoint": "https://pve:8006", "username": "u"},
    "/provision/host/add": {"endpoint": "https://pve:8006", "username": "u"},
    "/provision/host/edit": {"sid": "x"},
    "/provision/host/add-many": {"hosts": [{"endpoint": "https://pve:8006"}]},
    "/provision/iso/delete": {"connection": "x", "node": "n", "volid": "v"},
    "/provision/vm/action": {"connection": "x", "node": "n", "vmid": "9",
                             "action": "start"},
    "/provision/vm/edit": {"connection": "x", "node": "n", "vmid": "9",
                           "changes": {"cores": 2}},
    "/provision/create": {"os": "alma10", "nodes": [{"hostname": "h"}]},
    "/provision/stage": {"connection": "x", "nodes": ["n"], "os": "alma10"},
    "/provision/stage-probe": {"connection": "x", "node": "n"},
}
# A GET read route every provisioning reader must be allowed through.
READ_ROUTE = "/provision/hosts?connection=x"


def main_test() -> int:
    _enrol("boss@p", None, admin=True)
    _enrol("reader@p", ["terraform"])           # read provisioning, not apply
    _enrol("applier@p", ["terraform", "terraform_apply"])   # no ansible_run
    _enrol("nobody@p", ["clusters"])            # no terraform at all

    # ── 1. the middleware now governs the prefix ──────────────────────────
    nb = _client("nobody@p")
    r = nb.get(READ_ROUTE, follow_redirects=False)
    check(f"a user without Terraform is refused /provision, got {r.status_code}",
          r.status_code == 403)
    nb.__exit__(None, None, None)

    reader = _client("reader@p")
    applier = _client("applier@p")

    # ── 2. a reader may READ but not ACT ──────────────────────────────────
    r = reader.get(READ_ROUTE)
    check(f"a reader may read the hosts list, got {r.status_code}",
          r.status_code == 200)
    # it will say ok:false (no real Proxmox) — the point is the gate let it in
    check("and that read passed the gate (not a permission refusal)",
          '"error": "your role may not read' not in r.text)

    for path, body in JSON_ROUTES.items():
        r = reader.post(path, json=body, follow_redirects=False)
        check(f"{path}: a reader is refused, got {r.status_code}",
              r.status_code == 403)
        check(f"{path}: and told it needs Terraform: apply",
              "Terraform: apply" in r.text)
    # The dialog prints the server's sentence, so it must name what was
    # refused — "may not run terraform" to somebody who pressed Add host sends
    # them after the wrong thing.
    r = reader.post("/provision/host/add", json=JSON_ROUTES["/provision/host/add"])
    check(f"the refusal names the act, got {r.json().get('error')!r}",
          "not add a Proxmox host" in r.json().get("error", ""))

    # ── 2b. and the page offers a reader those controls DISABLED, with why ──
    def ctl(page: str, ident: str) -> str:
        """The opening tag of the element with this id."""
        at = page.find(f'id="{ident}"')
        return page[page.rfind("<", 0, at):page.find(">", at) + 1] if at > 0 else ""

    for who, client, off in (("reader", reader, True), ("apply holder", applier, False)):
        over = client.get("/terraform").text
        hosts = client.get("/terraform?sec=hosts").text
        for page, ident in ((over, "provisionBtn"), (over, "talosTile"),
                            (hosts, "hostAdd")):
            tag = ctl(page, ident)
            check(f"{who}: #{ident} is on the page", bool(tag))
            check(f"{who}: #{ident} is {'disabled' if off else 'live'}: {tag[:90]}",
                  ("disabled" in tag) == off)
        if off:
            check("the disabled control says why",
                  "change anything from them" in ctl(over, "provisionBtn"))
        recipe = over[over.find("data-recipe"):over.find(">", over.find("data-recipe"))]
        check(f"{who}: a recipe tile is {'disabled' if off else 'live'}",
              ("disabled" in recipe) == off)
        # the JS-built host and image buttons read one constant
        check(f"{who}: the page script {'withholds' if off else 'allows'} the "
              "host and image buttons",
              ('const PROV_OFF = ""' in over) != off)

    # ── 3. an apply holder gets PAST the gate everywhere ──────────────────
    for path, body in JSON_ROUTES.items():
        r = applier.post(path, json=body, follow_redirects=False)
        check(f"{path}: an apply holder is NOT refused for permission "
              f"(got {r.status_code} {r.text[:80]})",
              not (r.status_code == 403 and "Terraform: apply" in r.text))

    # ── 4. arming a post-provision playbook needs ansible_run ─────────────
    # create with a playbook in the spec: the apply holder (no ansible_run) is
    # refused with the Ansible reason, before any stack is generated.
    r = applier.post("/provision/create",
                     json={"os": "alma10", "nodes": [{"hostname": "h"}],
                           "ansible_playbook": "pb-1"}, follow_redirects=False)
    check(f"create with a playbook is refused without ansible_run, "
          f"got {r.status_code}", r.status_code == 403)
    check("and the refusal names Ansible: run playbooks",
          "Ansible: run playbooks" in r.text)

    # apply of a stack that already carries a playbook: same gate, at run time.
    sid = terraform.save_stack("", {"name": "pb stack", "provider": "proxmox",
                                    "body": 'resource "null_resource" "x" {}',
                                    "env": "staging"}, "boss@p")
    provision.set_ansible(sid, "pb-1", "PRIVATE-KEY-MATERIAL", "almalinux")
    r = applier.post("/terraform/run", data={"sid": sid, "action": "apply",
                     "confirm": ""}, follow_redirects=False)
    check(f"applying a playbook-bearing stack is refused without ansible_run, "
          f"got {r.status_code}", r.status_code == 403)
    check("and the refusal names Ansible: run playbooks",
          "Ansible: run playbooks" in r.text)
    # the stack's playbook must NOT have been armed by that refused apply
    check("and the refused apply armed nothing",
          not provision.post_ansible_status(sid).get("running"))

    # a user WITH both apply and ansible_run passes this gate (it then fails for
    # a different reason — the apply switch is off / confirm — never permission)
    _enrol("full@p", ["terraform", "terraform_apply", "ansible_run"])
    full = _client("full@p")
    r = full.post("/terraform/run", data={"sid": sid, "action": "apply",
                  "confirm": ""}, follow_redirects=False)
    check(f"with ansible_run the apply is not refused for permission "
          f"(got {r.status_code} {r.text[:80]})",
          not (r.status_code == 403 and "Ansible: run playbooks" in r.text))
    full.__exit__(None, None, None)
    reader.__exit__(None, None, None)
    applier.__exit__(None, None, None)

    print("  /provision is governed by Terraform; acting needs terraform_apply; "
          "a post-provision playbook needs ansible_run")
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main_test())
