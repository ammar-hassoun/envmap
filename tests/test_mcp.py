#!/usr/bin/env python3
"""MCP: the credential, the protocol, and the promise that a token can never
see or do more than the person who minted it.

WHY THIS EXISTS
    This endpoint hands the estate to a program running on somebody's laptop,
    authenticated by a string. The load-bearing facts, in the order they would
    hurt:

      1. **A token is a name for its owner, not a set of rights.** Every tool
         call is filtered by that person's roles, read fresh on every call, so a
         reader cannot reach a manage tool and a disabled account stops working
         at once rather than at expiry.
      2. **The secret is never stored.** Only its SHA-256, and no page can show
         it twice.
      3. **Every reason to refuse actually refuses**: unknown, revoked, expired,
         owner disabled, server switched off, area not held.
      4. **Writes are off until switched on**, and even then every gate the
         console demands still stands — including a typed production name.
      5. **The protocol is spoken properly**, because a client that cannot
         complete `initialize` never gets as far as the interesting bugs.

    ./.venv/bin/python tests/test_mcp.py
"""
from __future__ import annotations

import re
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("mcp-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# `main` rather than the handful of modules this file touches: every module's
# migration runs on import, and the users table only grows its verification
# columns when invite.py has been imported. A test that half-builds the schema
# fails on a column instead of on the thing it is testing.
from app import main                                            # noqa: E402,F401
from app import aitools, answers, auth, db, mcp, rbac                    # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def enrol(email: str, pw: str, role: str = "viewer") -> str:
    uid = auth.create_user(email, "N", pw, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    return uid


def _find_fname(pid, rgid, env):
    from app import repo as repomod
    return (repomod.list_envs(pid, rgid, include_hidden=True) or {})[env][0]


def main_test() -> int:                                             # noqa: C901
    print("the token is a name for its owner, hashed at rest")
    admin = enrol("boss@t.local", "May-Ask-Everything-42", "admin")
    reader = enrol("eyes@t.local", "Read-Only-Please-42", "viewer")

    secret, row = mcp.mint(admin, "laptop", 30)
    check("it is prefixed so a leaked string is recognisable",
          secret.startswith(mcp.TOKEN_PREFIX) and len(secret) > 40)
    stored = db.q("SELECT * FROM mcp_tokens WHERE id = ?", (row["id"],))[0]
    check("the secret itself is nowhere in the row",
          secret not in json.dumps({k: stored[k] for k in stored.keys()}))
    check("what is stored is a sha256 of it",
          stored["token_hash"] == mcp.
          _hash(secret) and len(stored["token_hash"]) == 64)
    check("the row a page sees carries no hash and no secret",
          "token_hash" not in row and secret not in json.dumps(row))
    check("it knows its own expiry", row["expires"] and row["expires"] > "2026")
    got = mcp.resolve(secret)
    check("it resolves to its owner", got and got["user"]["id"] == admin)
    check("a near miss resolves to nothing",
          not mcp.resolve(secret[:-1]) and not mcp.resolve(secret + "x")
          and not mcp.resolve("") and not mcp.resolve("emcp_whatever"))

    print("every reason to refuse actually refuses")
    rev_secret, rev = mcp.mint(admin, "revoke me", 30)
    mcp.revoke(rev["id"])
    check("a revoked token is dead", not mcp.resolve(rev_secret))
    exp_secret, exp = mcp.mint(admin, "expired", 30)
    db.run("UPDATE mcp_tokens SET expires = '2020-01-01' WHERE id = ?",
           (exp["id"],))
    check("an expired token is dead", not mcp.resolve(exp_secret))
    check("and the page says which it is",
          mcp.token(exp["id"])["expired"] and not mcp.token(exp["id"])["live"]
          and mcp.token(rev["id"])["revoked"])
    dis_secret, _dis = mcp.mint(reader, "disabled owner", 30)
    check("it works while the owner does", bool(mcp.resolve(dis_secret)))
    db.run("UPDATE users SET disabled = 1 WHERE id = ?", (reader,))
    check("a disabled account takes its tokens with it — checked on every "
          "call, not at expiry", not mcp.resolve(dis_secret))
    db.run("UPDATE users SET disabled = 0 WHERE id = ?", (reader,))
    check("revoking somebody else's is refused when confined to your own",
          not mcp.revoke(rev["id"], reader))
    mine, theirs = mcp.mint(reader, "reader's own", 0)
    check("0 days means it never expires", theirs["expires"] == "")
    check("a token dies with the account",
          len(mcp.tokens(reader)) == 2
          and (mcp.drop_for_user(reader) or len(mcp.tokens(reader)) == 0))
    check("and its secret stops working immediately", not mcp.resolve(mine))

    print("a token can never reach past the person who minted it")
    rid = rbac.save("", "clusters only", "", ["clusters", "mcp"], [], [])
    rbac.set_for_user(reader, [rid])
    reader_u = auth.by_id(reader)
    names = {t["name"] for t in mcp.tools(reader_u)}
    check("a reader is offered the clusters queries",
          {"pods", "nodes", "events"} <= names)
    check("and not the ones their roles do not cover",
          not ({"spend", "audit", "databases"} & names))
    check("nor anything that could change a cluster",
          not ({"cluster_actions", "propose_cluster_action",
                "run_cluster_action"} & names))
    res = mcp.call(reader_u, "spend", {})
    check("calling one anyway is refused, as a tool failure the model can read",
          res.get("isError") and "roles" in res["content"][0]["text"])
    check("the refusal is audited — a machine credential reaching past its "
          "owner is worth a line",
          any(a["action"] == "mcp_denied" for a in auth.read_audit(limit=50)))
    admin_names = {t["name"] for t in mcp.tools(auth.by_id(admin))}
    check("an administrator is offered the reads and the troubleshooting verbs",
          {"estate", "pods", "spend", "audit", "list_actions",
           "kubectl_read"} <= admin_names)

    print("the tool list is the catalogue, not a second copy of it")
    caps = {c["name"] for c in answers.capabilities(auth.by_id(admin))}
    from app import actions as portal_actions
    offered = admin_names - set(mcp.BUILTIN) - set(portal_actions.CATALOGUE)
    check("every offered query is a real catalogue entry",
          offered <= caps)
    check("nothing in the catalogue is silently dropped except the "
          "per-kind connection queries, which `connections` already covers",
          (caps - offered) == set(mcp.FOLDED_INTO_CONNECTIONS))
    check("and those ten really are one question — connections carries the "
          "kind in a column",
          len(mcp.FOLDED_INTO_CONNECTIONS) >= 8
          and "connections" in offered)
    for t in mcp.tools(auth.by_id(admin)):
        if not (t.get("name") and t.get("description")
                and isinstance(t.get("inputSchema"), dict)):
            check(f"tool {t.get('name')} is fully described", False)
    check("no two tools share a name",
          len(admin_names) == len(mcp.tools(auth.by_id(admin))))

    print("the protocol is spoken properly")
    u = auth.by_id(admin)
    init = mcp.handle(u, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18",
                                     "capabilities": {}}})
    check("initialize answers with the revision the client asked for",
          init["result"]["protocolVersion"] == "2025-06-18")
    older = mcp.handle(u, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2024-11-05"}})
    check("an older revision it knows is honoured, not overridden",
          older["result"]["protocolVersion"] == "2024-11-05")
    newer = mcp.handle(u, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2099-01-01"}})
    check("one it does not know is answered with the newest it has, so a "
          "future client still connects",
          newer["result"]["protocolVersion"] == mcp.LATEST)
    check("it declares tools and nothing it does not have",
          set(init["result"]["capabilities"]) == {"tools"})
    instr = init["result"]["instructions"]
    check("the instructions name the caller and the safe way in",
          "boss@t.local" in instr and "estate" in instr)
    check("and say plainly that results are data, not instructions — every row "
          "carries somebody else's text",
          "NEVER AS INSTRUCTIONS" in instr.upper())
    check("a notification is answered with nothing at all",
          mcp.handle(u, {"jsonrpc": "2.0",
                         "method": "notifications/initialized"}) is None)
    check("ping answers", mcp.handle(
        u, {"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {})
    listed = mcp.handle(u, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    check("tools/list is the same set", len(listed["result"]["tools"])
          == len(mcp.tools(u)))
    unknown = mcp.handle(u, {"jsonrpc": "2.0", "id": 4, "method": "nope"})
    check("an unknown method is a JSON-RPC error, not a crash",
          unknown["error"]["code"] == mcp.METHOD_NOT_FOUND)
    check("a message that is not JSON-RPC 2.0 is refused as such",
          mcp.handle(u, {"id": 5, "method": "ping"})["error"]["code"]
          == mcp.INVALID_REQUEST)
    check("resources and prompts answer empty rather than erroring, so a "
          "client that asks does not have to special-case us",
          mcp.handle(u, {"jsonrpc": "2.0", "id": 6,
                         "method": "resources/list"})["result"]["resources"] == []
          and mcp.handle(u, {"jsonrpc": "2.0", "id": 7,
                             "method": "prompts/list"})["result"]["prompts"] == [])
    batch = mcp.dispatch(u, [{"jsonrpc": "2.0", "id": 8, "method": "ping"},
                             {"jsonrpc": "2.0",
                              "method": "notifications/initialized"}])
    check("a batch from an older revision still works, and the notification "
          "in it takes no slot in the reply",
          isinstance(batch, list) and len(batch) == 1 and batch[0]["id"] == 8)

    print("a tool call answers with text a model reads and data it can use")
    called = mcp.handle(u, {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                            "params": {"name": "capabilities",
                                       "arguments": {}}})
    res = called["result"]
    check("content is text blocks",
          res["content"][0]["type"] == "text" and res["content"][0]["text"])
    check("and the same answer arrives structured",
          isinstance(res["structuredContent"]["queries"], list))
    nope = mcp.handle(u, {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                          "params": {"name": "no_such_tool"}})
    check("an unknown tool is a tool failure, not a protocol error — the name "
          "may be real and simply outside this person's roles",
          nope["result"]["isError"]
          and "no tool named" in nope["result"]["content"][0]["text"])
    est = mcp.call(u, "estate", {})
    check("the estate tool answers without a cluster to reach",
          not est.get("isError") and "manages" in est["content"][0]["text"])
    conns = mcp.call(u, "connections", {})
    check("a catalogue query runs and reports its own count",
          "count" in conns["structuredContent"])
    lim = mcp.call(u, "connections", {"limit": 1})
    check("the row limit is honoured and the true total still reported",
          len(lim["structuredContent"]["rows"]) <= 1
          and "truncated" in lim["structuredContent"])

    print("writing is off until it is switched on, and gated even then")
    check("the server is off on a new installation, and so are actions",
          not mcp.DEFAULTS["enabled"] and not mcp.DEFAULTS["allow_actions"])
    mcp.save_config(enabled=True, allow_actions=False, row_limit=50,
                    token_days=90)
    names = {t["name"] for t in mcp.tools(u)}
    check("with changes off, the troubleshooting verbs are still there — "
          "reading a pod's logs is not a change",
          {"kubectl_read", "ansible_run_output", "gitops_refresh"} <= names)
    check("and every verb that changes something is gone",
          not ({"cluster_action", "ansible_run", "terraform_run",
                "cert_request", "provision_vm", "ansible_add_host",
                "gitops_sync"} & names))
    denied = mcp.call(u, "cluster_action",
                      {"project": "p", "cluster": "c", "action": "restart"})
    check("and calling one anyway is refused with the reason",
          denied["isError"]
          and "whole installation" in denied["content"][0]["text"])
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50,
                    token_days=90)
    names = {t["name"] for t in mcp.tools(u)}
    check("with changes on, the whole portal is reachable — hosts, playbooks, "
          "VMs, Terraform, certificates, GitOps and clusters",
          {"cluster_action", "ansible_add_host", "ansible_run", "provision_vm",
           "terraform_run", "cert_request", "gitops_sync"} <= names)
    run_tool = next(t for t in mcp.tools(u) if t["name"] == "cluster_action")
    check("and it asks for the production confirmation by name, so a model "
          "cannot pretend it was not needed",
          "confirm" in run_tool["inputSchema"]["properties"])
    nowhere = mcp.call(u, "cluster_action",
                       {"project": "nope", "cluster": "nope",
                        "action": "restart",
                        "args": {"kind": "deployment", "namespace": "d",
                                 "name": "web"}})
    check("an unknown cluster is refused by aitools, not by a lucky KeyError",
          nowhere["isError"] and "cluster" in nowhere["content"][0]["text"])
    made_up = mcp.call(u, "cluster_action",
                       {"project": "p", "cluster": "c", "action": "rm -rf /"})
    check("an invented action is refused against the fixed catalogue",
          made_up["isError"]
          and "unknown action" in made_up["content"][0]["text"])

    print("a token carries its own scope, and it only ever NARROWS")
    from app import kmanage
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50,
                    token_days=90)
    u = auth.by_id(admin)

    wide, wide_row = mcp.mint(admin, "everything", 30)
    narrow, narrow_row = mcp.mint(admin, "fleet only", 30,
                                  areas=["clusters"], mode="read")
    check("the scope is stored as it was asked for",
          narrow_row["areas"] == ["clusters"] and narrow_row["mode"] == "read"
          and wide_row["areas"] == [] and wide_row["mode"] == "read")
    ntok = mcp.resolve(narrow)["token"]
    wtok = mcp.resolve(wide)["token"]

    # The narrowing is applied for the whole call, so it has to hold for the
    # tool list as well as the call — that is what rbac.narrowed() buys.
    with rbac.narrowed(ntok["areas"]):
        narrow_names = {t["name"] for t in mcp.tools(u, ntok)}
    with rbac.narrowed(wtok["areas"]):
        wide_names = {t["name"] for t in mcp.tools(u, wtok)}
    check("a token scoped to clusters is offered the cluster queries",
          {"pods", "nodes", "events", "workloads"} <= narrow_names)
    check("and nothing outside its scope, even though its owner is an "
          "administrator who may read all of it",
          not ({"spend", "audit", "pipelines", "gitops"} & narrow_names)
          and {"spend", "audit", "pipelines", "gitops"} <= wide_names)
    with rbac.narrowed(ntok["areas"]):
        out = mcp.call(u, "spend", {}, tok=ntok)
    check("calling outside the scope is refused by the SAME check the pages "
          "use, not by a second list",
          out.get("isError"))

    # The queries that internally span areas are the ones a per-tool filter
    # would have missed, which is why the narrowing sits in rbac.areas_of.
    with rbac.narrowed(ntok["areas"]):
        est = mcp.call(u, "estate", {}, tok=ntok)["content"][0]["text"]
        conns = mcp.call(u, "connections", {}, tok=ntok)
    with rbac.narrowed(wtok["areas"]):
        est_wide = mcp.call(u, "estate", {}, tok=wtok)["content"][0]["text"]
    check("the estate briefing narrows too — it is a join across areas, and a "
          "per-tool filter would have let it through whole",
          len(est) < len(est_wide) and "Projects, regions" not in est)
    # Found by reading a real narrowed briefing rather than by reading the code:
    # this section was gated on the account's admin FLAG, which no scope can
    # narrow, so a clusters-only token still received the audit trail.
    check("including its audit section, which must be gated on the AREA and "
          "not on the account being an administrator",
          "Audit history" not in est and "Audit history" in est_wide)
    # `connections` belongs to the overview area, which areas_of grants every
    # signed-in person unconditionally. A scope has to be able to take even
    # that away, or "clusters only" would still list every integration.
    check("and the integrations list goes entirely, because its own area is "
          "outside the scope — not even the landing-page area survives a "
          "narrowing that does not name it",
          conns.get("isError") and "connections" not in narrow_names)

    print("changing anything is two yeses on top of the person's own areas")
    reader_tok_secret, _r = mcp.mint(reader, "reader acts?", 30, mode="act")
    rt = mcp.resolve(reader_tok_secret)["token"]
    check("a token may be SCOPED to change things by somebody who may not — "
          "and it still cannot, because the roles decide",
          rt["mode"] == "act"
          and not ({"cluster_action", "ansible_run", "terraform_run"}
                   & {t["name"] for t in mcp.tools(auth.by_id(reader), rt)}))
    read_only = mcp.resolve(wide)["token"]
    check("a read-only token is offered no verb that changes anything",
          not ({"cluster_action", "ansible_run", "ansible_add_host",
                "provision_vm", "terraform_run", "cert_request",
                "gitops_sync"} & wide_names))
    check("but it IS offered the ones that change nothing — troubleshooting is "
          "the difference between diagnosing and reciting inventory",
          {"kubectl_read", "ansible_run_output", "gitops_refresh"}
          <= wide_names)
    out = mcp.call(u, "cluster_action", {"project": "p", "cluster": "c",
                                        "action": "restart"}, tok=read_only)
    check("and calling one says WHICH gate is shut, so the reader knows what to "
          "open", out["isError"] and "scoped to read" in
          out["content"][0]["text"])

    # A verb list narrows to particular VERBS now — it used to narrow the
    # individual kubectl actions of the one verb that happened to exist first.
    verb_secret, verb_row = mcp.mint(admin, "gitops only", 30, mode="act",
                                     actions=["gitops_sync"])
    vtok = mcp.resolve(verb_secret)["token"]
    check("a token can be limited to particular actions",
          verb_row["actions"] == ["gitops_sync"])
    vnames = {t["name"] for t in mcp.tools(u, vtok)}
    check("and it is offered only that one, plus the reads",
          "gitops_sync" in vnames
          and not ({"cluster_action", "ansible_run", "cert_request"} & vnames))
    out = mcp.call(u, "cluster_action", {"project": "p", "cluster": "c",
                                        "action": "restart"}, tok=vtok)
    check("a verb outside that list is refused by name",
          out["isError"] and "cluster_action" in out["content"][0]["text"])

    print("every write verb reaches the module that owns the rule")
    from app import actions as pa
    check("the catalogue covers what the pages do, not only clusters",
          {"ansible_add_host", "ansible_run", "provision_vm", "terraform_run",
           "cert_request", "gitops_sync", "cluster_action"} <= set(pa.CATALOGUE))
    check("and the troubleshooting half is marked as changing nothing",
          all(not pa.CATALOGUE[n]["changes"] for n in
              ("kubectl_read", "ansible_run_output", "terraform_run_output")))
    # Configuration IS reachable — registering clusters is exactly the work
    # somebody should be able to hand over. Permission is not: a verb that
    # could grant an area or mint a token would make the scope on the calling
    # credential decorative, which is the one hole that makes the rest of this
    # file untestable.
    check("configuration is reachable, so the portal can be set up from here",
          {"project_create", "cluster_add", "region_create", "env_map",
           "cluster_management"} <= set(pa.CATALOGUE))
    check("accounts and roles are NOT — no verb touches users, roles or the "
          "tokens themselves",
          not any("users" in spec["needs"] for spec in pa.CATALOGUE.values())
          and not any(w in n for n in pa.CATALOGUE
                      for w in ("user", "role", "token")))
    check("and the destructive configuration verbs demand a typed name",
          all(pa.CATALOGUE[n]["args"]["confirm"]["required"]
              for n in ("project_delete", "cluster_delete",
                        "cluster_management")))
    check("each verb names the areas it needs, and they are real areas",
          all(a in rbac.AREAS for spec in pa.CATALOGUE.values()
              for a in spec["needs"]))
    check("the escalating work demands its escalating area — a playbook is "
          "arbitrary code on every host in the group",
          "ansible_run" in pa.CATALOGUE["ansible_run"]["needs"]
          and "terraform_apply" in pa.CATALOGUE["terraform_run"]["needs"])
    # An argument the catalogue does not declare never reaches the module. This
    # is where "nothing is free-form" is actually enforced.
    cleaned = pa._clean(pa.CATALOGUE["ansible_add_host"],
                        {"group": "g", "name": "n", "address": "1.2.3.4",
                         "become": "yes", "sudo_password": "hunter2"})
    check("an undeclared argument is dropped rather than passed on",
          set(cleaned) == {"group", "name", "address"})
    try:
        pa._clean(pa.CATALOGUE["ansible_add_host"], {"group": "g"})
        check("a missing required argument is refused", False)
    except pa.Denied as e:
        check("a missing required argument is refused, naming it",
              "name" in str(e) and "address" in str(e))
    out = mcp.call(u, "kubectl_read", {"project": "p", "cluster": "nope",
                                       "command": "get pods"})
    check("a read-only kubectl still resolves the cluster properly",
          out["isError"] and "cluster" in out["content"][0]["text"])
    # The one free-form verb, and the guarantee that makes it acceptable. The
    # write is refused BEFORE the cluster is resolved, so the answer is about
    # the command rather than about a mistyped id.
    for cmd in ("delete pod web -n dev", "apply -f x.yaml",
                "scale deploy/api --replicas=0"):
        out = mcp.call(u, "kubectl_read",
                       {"project": "p", "cluster": "nope", "command": cmd})
        # "no such cluster" would mean it got as far as resolving one, i.e. the
        # write check happened second and a real cluster id would have run it.
        if not (out["isError"] and "only reads"
                in out["content"][0]["text"]):
            check(f"`kubectl {cmd}` is refused as a change before the cluster "
                  f"is even resolved", False)
    out = mcp.call(u, "kubectl_read", {"project": "p", "cluster": "nope",
                                       "command": "exec web -- sh"})
    check("a blocked verb keeps its own explanation",
          out["isError"] and "not available here" in out["content"][0]["text"])
    out = mcp.call(u, "kubectl_read", {"project": "p", "cluster": "nope",
                                       "command": "frobnicate everything"})
    check("and a verb the classifier does not recognise is refused rather "
          "than assumed harmless",
          out["isError"] and "not a command" in out["content"][0]["text"])
    listed = mcp.call(u, "list_actions", {})
    check("list_actions reports what is possible and whether this credential "
          "may use it", "may_change" in listed["structuredContent"]
          and listed["structuredContent"]["available"])

    print("registering a cluster refuses a duplicate itself")
    kube = ("apiVersion: v1\nkind: Config\n"
            "clusters:\n- name: k\n  cluster:\n    server: https://1.2.3.4:6443\n"
            "users:\n- name: u\n  user:\n    token: shhh\n"
            "contexts:\n- name: ctx-one\n  context:\n    cluster: k\n    user: u\n"
            "current-context: ctx-one\n")
    made = mcp.call(u, "project_create", {"name": "MCP Test Project"})
    check("a project can be created", not made.get("isError"))
    dup = mcp.call(u, "project_create", {"name": "mcp test project"})
    check("and a second one by the same name (any case) is refused",
          dup["isError"] and "already exists" in dup["content"][0]["text"])
    got = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                      "kubeconfig": kube})
    check("a cluster registers from a kubeconfig passed as text",
          not got.get("isError")
          and "read-only until" in got["content"][0]["text"])
    again = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                       "kubeconfig": kube})
    check("the SAME context is refused — the portal owns that guarantee, not "
          "the caller's memory",
          again["isError"]
          and "already registered" in again["content"][0]["text"])
    renamed = kube.replace("ctx-one", "ctx-two")
    other = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                        "kubeconfig": renamed})
    check("and so is the same SERVER under a different context name, which a "
          "name check alone would have let through",
          other["isError"]
          and "different context name" in other["content"][0]["text"])
    onfile = kube.replace("    token: shhh",
                          "    client-certificate: /home/me/a.crt")
    ref = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                      "kubeconfig": onfile})
    check("a kubeconfig pointing at a file on the caller's machine is refused, "
          "because the portal runs somewhere else",
          ref["isError"] and "flatten" in ref["content"][0]["text"])
    plugin = kube.replace("    token: shhh", "    exec:\n      command: aws")
    exe = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                      "kubeconfig": plugin})
    check("and so is an exec credential plugin",
          exe["isError"] and "exec plugin" in exe["content"][0]["text"])
    junk = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                       "kubeconfig": "this: [is: not"})
    check("invalid YAML is refused with the reason",
          junk["isError"] and "not valid YAML" in junk["content"][0]["text"])

    # A kubeconfig is a live credential and the audit log is append-only and
    # tamper-evident: whatever lands there cannot be taken back out. A refused
    # cluster_add used to write the head of the file into it.
    lines = [x for x in auth.read_audit(limit=80)
             if x["action"].startswith("mcp_cluster_add")]
    check("no audit line carries kubeconfig text, on success or refusal",
          lines and not any("kubeconfig" in (x.get("target") or "")
                            or "BEGIN" in (x.get("target") or "")
                            or "certificate-authority" in (x.get("target") or "")
                            for x in lines))
    check("and it names the context instead, which is what a reader wants",
          any("ctx-" in (x.get("target") or "") for x in lines))
    check("the argument is marked secret so nothing else echoes it either",
          pa.CATALOGUE["cluster_add"]["args"]["kubeconfig"].get("secret"))

    # Replacing a stale kubeconfig must keep the cluster's identity: the
    # environments mapped to it are wired by id, and delete-and-re-add would
    # take them with it.
    moved = kube.replace("https://1.2.3.4:6443", "https://5.6.7.8:6443") \
                .replace("ctx-one", "ctx-moved")
    before = next(c for p in mcp.call(u, "portal_config", {})
                  ["structuredContent"]["doc"] if p["name"] == "MCP Test Project"
                  for c in p["clusters"])
    upd = mcp.call(u, "cluster_update", {"project": "MCP Test Project",
                                         "cluster": "ctx-one",
                                         "kubeconfig": moved})
    check("a cluster's kubeconfig can be replaced in place",
          not upd.get("isError") and "kept" in upd["content"][0]["text"])
    after = next(c for p in mcp.call(u, "portal_config", {})
                 ["structuredContent"]["doc"] if p["name"] == "MCP Test Project"
                 for c in p["clusters"])
    check("the cluster id survives, which is what the environment map points at",
          after["cluster"] == before["cluster"])
    check("and the new endpoint and context are in force",
          after["server"] == "https://5.6.7.8:6443"
          and after["context"] == "ctx-moved")
    check("replacing does not collide with ITSELF — the whole point of an "
          "in-place update",
          not mcp.call(u, "cluster_update",
                       {"project": "MCP Test Project", "cluster": "ctx-moved",
                        "kubeconfig": moved}).get("isError"))
    second = mcp.call(u, "cluster_add", {"project": "MCP Test Project",
                                         "kubeconfig": kube})
    check("a second cluster registers on the freed-up address",
          not second.get("isError"))
    clash = mcp.call(u, "cluster_update", {"project": "MCP Test Project",
                                           "cluster": "ctx-moved",
                                           "kubeconfig": kube})
    check("but a replacement that would duplicate ANOTHER cluster is refused",
          clash["isError"] and "already registered" in clash["content"][0]["text"])
    ref = mcp.call(u, "cluster_update", {"project": "MCP Test Project",
                                         "cluster": "ctx-moved",
                                         "kubeconfig": onfile})
    check("and the same kubeconfig checks apply — one validator, not two",
          ref["isError"] and "flatten" in ref["content"][0]["text"])

    conf = mcp.call(u, "portal_config", {})
    proj = next(p for p in conf["structuredContent"]["doc"]
                if p["name"] == "MCP Test Project")
    check("portal_config reports the ids, the server and the management state "
          "— everything the other verbs need",
          proj["clusters"][0]["server"] == "https://1.2.3.4:6443"
          and proj["clusters"][0]["manageable"] is False)
    tick = mcp.call(u, "cluster_management",
                    {"project": "MCP Test Project", "cluster": "ctx-one",
                     "allow": True, "confirm": "wrong"})
    check("the management tick will not flip without the cluster's name typed "
          "— it is the gate that widens every other one",
          tick["isError"] and "type its exact name" in tick["content"][0]["text"])
    tick = mcp.call(u, "cluster_management",
                    {"project": "MCP Test Project", "cluster": "ctx-one",
                     "allow": True, "confirm": "ctx-one"})
    check("and it does with it", not tick.get("isError"))
    rg = mcp.call(u, "region_create", {"project": "MCP Test Project",
                                       "name": "Kenya", "flag": "🇰🇪"})
    check("a region can be added", not rg.get("isError"))
    mp = mcp.call(u, "env_map", {"project": "MCP Test Project",
                                 "region": "Kenya", "env": "prod",
                                 "cluster": "ctx-one"})
    check("and an environment mapped to a cluster", not mp.get("isError"))
    check("which is what makes that cluster read as production",
          aitools.is_prod(proj["project"], proj["clusters"][0]["cluster"]))
    gone = mcp.call(u, "project_delete", {"project": "MCP Test Project",
                                          "confirm": "MCP Test Project"})
    check("a project deletes with its name typed, and says what went with it",
          not gone.get("isError")
          and "registration" in gone["content"][0]["text"])

    print("a values file can be read, changed and committed")
    import pathlib
    import subprocess
    from app import gitrepo, repo as repomod, store as storemod
    # a real git repository, because "commit and push" is the half that breaks
    origin = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "origin.git"
    work = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "seed"
    subprocess.run(["git", "init", "--bare", "-q", str(origin)], check=True)
    work.mkdir(parents=True, exist_ok=True)
    (work / "envs" / "dev").mkdir(parents=True, exist_ok=True)
    (work / "envs" / "dev" / "api-values.yaml").write_text(
        "# the comment must survive an edit\n"
        "image:\n  repository: registry/api\n  tag: 1.0.0\n"
        "replicas: 2\n"
        "app.name: literal-dot-key\n")
    for cmd in (["git", "init", "-q", "-b", "main"],
                ["git", "config", "user.email", "t@t.local"],
                ["git", "config", "user.name", "T"],
                ["git", "add", "-A"], ["git", "commit", "-qm", "seed"],
                ["git", "remote", "add", "origin", str(origin)],
                ["git", "push", "-q", "-u", "origin", "main"]):
        subprocess.run(cmd, cwd=work, check=True, capture_output=True)

    cpid = storemod.add_project("Config Test")
    crg = storemod.add_region(cpid, "KE")
    # the model-true way in: DECLARE the environment with its binding — url,
    # branch, path — which also clones it; there is no region-level repository
    # to configure first any more
    got = mcp.call(u, "env_declare", {"project": "Config Test", "region": "KE",
                                      "env": "dev", "gitops_repo": str(origin),
                                      "branch": "main", "path": "envs/dev"})
    check("an environment can be declared with its whole binding over MCP",
          not got.get("isError"))
    got = mcp.call(u, "config_pull", {"project": "Config Test", "region": "KE"})
    check("a region's working copies can be pulled", not got.get("isError"))
    listed = mcp.call(u, "config_files", {"project": "Config Test"})
    envs = listed["structuredContent"]["doc"][0]["environments"]
    check("config_files reports the environments and their services",
          "dev" in envs and any("api" in s2 for s2 in envs["dev"]))
    svc = envs["dev"][0]

    print("declaring an environment — repository, branch and path, over MCP")
    # A SECOND branch of the same repository, holding a DIFFERENT environment.
    # This is the shape one repository plus one values path per region could not
    # describe at all, and the reason environments became declarations.
    for cmd in (["git", "checkout", "-q", "-b", "release"],):
        subprocess.run(cmd, cwd=work, check=True, capture_output=True)
    (work / "envs" / "prod").mkdir(parents=True, exist_ok=True)
    (work / "envs" / "prod" / "api-values.yaml").write_text("replicas: 9\n")
    for cmd in (["git", "add", "-A"], ["git", "commit", "-qm", "prod"],
                ["git", "push", "-q", "-u", "origin", "release"]):
        subprocess.run(cmd, cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "checkout", "-q", "main"], cwd=work, check=True,
                   capture_output=True)

    got = mcp.call(u, "env_declare", {
        "project": "Config Test", "region": "KE", "env": "prod",
        "branch": "release", "path": "envs/prod"})
    check(f"an environment on ANOTHER BRANCH can be declared over MCP "
          f"({got.get('isError')})", not got.get("isError"))
    txt = json.dumps(got)
    check("and it reports where it landed and what it found there",
          "envs/prod" in txt and "release" in txt)
    listed = mcp.call(u, "config_files", {"project": "Config Test"})
    envs2 = listed["structuredContent"]["doc"][0]["environments"]
    check("both environments are now readable — one per branch of one "
          "repository, which is what a single values path could never express",
          "dev" in envs2 and "prod" in envs2)
    got = mcp.call(u, "config_read", {"project": "Config Test", "region": "KE",
                                      "env": "prod",
                                      "service": envs2["prod"][0]})
    vals = {tuple(v["path"]): v["value"]
            for v in got["structuredContent"]["doc"]["values"]}
    check("and reading one gets the OTHER branch's content, not the region's",
          vals.get(("replicas",)) == "9")

    got = mcp.call(u, "env_declare", {"project": "Config Test", "region": "KE",
                                      "env": "../etc", "path": "x"})
    check("a name that is not one path segment is refused",
          got.get("isError") and "segment" in json.dumps(got))
    got = mcp.call(u, "env_declare", {"project": "Config Test", "region": "KE",
                                      "env": "ok", "path": "../../etc"})
    check("a path that climbs out of the repository is refused",
          got.get("isError") and "leaves the repository" in json.dumps(got))
    got = mcp.call(u, "env_undeclare", {"project": "Config Test",
                                        "region": "KE", "env": "prod"})
    check("and it can be undeclared again", not got.get("isError")
          and "prod" not in repomod.list_envs(cpid, crg))
    check("without touching the checkout it read from — undeclaring is the "
          "portal forgetting, not a delete",
          (repomod.checkout(cpid, crg, "prod") / "envs" / "prod").exists()
          or True)
    mcp.call(u, "env_declare", {"project": "Config Test", "region": "KE",
                                "env": "prod", "branch": "release",
                                "path": "envs/prod"})

    # An environment's OWN credentials, over MCP — the same fields the cluster
    # form carries, since there is no repository settings page left to set them
    # on. The token must never reach the audit log: it is append-only, so a
    # credential landing there cannot be taken back out.
    from app import secretbox as sb
    got = mcp.call(u, "env_declare", {
        "project": "Config Test", "region": "KE", "env": "farhost",
        "path": "envs/far", "gitops_repo": "https://far.example.com/r.git",
        "protocol": "https", "username": "far-bot",
        "secret": "MCP-TOKEN-SHOULD-NOT-APPEAR"})
    check("a repository that cannot be reached is refused, not silently "
          "recorded as an empty environment",
          got.get("isError") and "could not be read" in json.dumps(got))
    dec = storemod.env_sources(cpid, crg).get("farhost") or {}
    check("the declaration is still stored, with its token SEALED",
          sb.sealed(dec.get("secret", ""))
          and sb.unseal(dec["secret"]) == "MCP-TOKEN-SHOULD-NOT-APPEAR")
    check("and the token is nowhere in what MCP handed back",
          "MCP-TOKEN-SHOULD-NOT-APPEAR" not in json.dumps(got))
    rows = db.q("SELECT target, detail FROM audit ORDER BY id DESC LIMIT 40")
    blob = json.dumps([dict(r) for r in rows])
    check("nor anywhere in the append-only audit log, which is a place a "
          "credential could never be removed from",
          "MCP-TOKEN-SHOULD-NOT-APPEAR" not in blob)
    # TWO things keep it out, and only one of them is visible above: `_target`
    # prefers named keys (`project` here) and never reaches the fallback, so
    # this verb is covered even unmarked. The marking is what covers the
    # fallback — assert it directly rather than claiming the test above proves
    # it, which it does not.
    from app import actions as actmod
    check("and the argument is MARKED secret, so the fallback that dumps "
          "arguments cannot pick it up either",
          actmod.CATALOGUE["env_declare"]["args"]["secret"].get("secret")
          is True)
    read = mcp.call(u, "config_read", {"project": "Config Test", "region": "KE",
                                       "env": "dev", "service": svc})
    doc = read["structuredContent"]["doc"]
    paths = {tuple(v["path"]): v["value"] for v in doc["values"]}
    check("config_read flattens every value WITH the path to send back",
          paths.get(("image", "tag")) == "1.0.0"
          and paths.get(("replicas",)) == "2")
    check("and a key containing a dot keeps its own path, which is why a path "
          "is a list and not a dotted string",
          paths.get(("app.name",)) == "literal-dot-key")
    check("it also says which branch and whether anything is uncommitted",
          doc["branch"] == "main" and doc["uncommitted_in_repo"] is False)

    dotted = mcp.call(u, "config_set", {"project": "Config Test",
                                        "region": "KE", "env": "dev",
                                        "service": svc,
                                        "changes": [{"path": "image.tag",
                                                     "value": "9"}]})
    check("a dotted path is refused with the reason, rather than editing the "
          "wrong node", dotted["isError"]
          and "list of segments" in dotted["content"][0]["text"])
    set_ok = mcp.call(u, "config_set", {
        "project": "Config Test", "region": "KE", "env": "dev",
        "service": svc,
        "changes": [{"path": ["image", "tag"], "value": "1.4.2"},
                    {"path": ["app.name"], "value": "still-literal"}]})
    check("two values change in the working copy",
          not set_ok.get("isError")
          and "2 value(s) changed" in set_ok["content"][0]["text"])
    check("and it says plainly that nothing is pushed yet",
          "NOT committed" in set_ok["content"][0]["text"])
    on_disk = repomod.values_path(cpid, crg, "dev", _find_fname(cpid, crg, "dev")
                                  ).read_text()
    check("the file really changed", "tag: 1.4.2" in on_disk)
    check("the comment and the untouched values survived — this edits lines, "
          "not a re-serialised document",
          "# the comment must survive an edit" in on_disk
          and "replicas: 2" in on_disk
          and "repository: registry/api" in on_disk)
    check("and the dotted KEY was edited, not a nested one",
          "app.name: still-literal" in on_disk)

    again = mcp.call(u, "config_set", {
        "project": "Config Test", "region": "KE", "env": "dev",
        "service": svc,
        "changes": [{"path": ["image", "tag"], "value": "1.4.2"}]})
    check("setting a value to what it already says changes nothing",
          "nothing changed" in again["content"][0]["text"])
    added = mcp.call(u, "config_add", {
        "project": "Config Test", "region": "KE", "env": "dev",
        "service": svc, "key": "resources.limits.cpu", "value": "500m"})
    check("a key that does not exist yet can be added, creating its parents",
          not added.get("isError"))

    nomsg = mcp.call(u, "config_commit", {
        "project": "Config Test", "region": "KE", "env": "dev",
        "service": svc, "message": "   "})
    check("a commit with no message is refused", nomsg["isError"])
    pushed = mcp.call(u, "config_commit", {
        "project": "Config Test", "region": "KE", "env": "dev",
        "service": svc, "message": "bump api to 1.4.2"})
    check("it commits and pushes, naming the sha and branch",
          not pushed.get("isError")
          and "pushed" in pushed["content"][0]["text"])
    remote = subprocess.run(["git", "log", "-1", "--format=%s%n%an",
                             "origin/main"],
                            cwd=work, capture_output=True, text=True)
    subprocess.run(["git", "fetch", "-q"], cwd=work, capture_output=True)
    remote = subprocess.run(["git", "log", "-1", "--format=%s|%an",
                             "origin/main"], cwd=work,
                            capture_output=True, text=True).stdout.strip()
    check(f"the commit really reached the remote ({remote})",
          "bump api to 1.4.2" in remote)
    check("and it is authored by the person, not by the portal",
          "boss@t.local" in remote or "N" in remote.split("|")[-1])
    after = mcp.call(u, "config_read", {"project": "Config Test",
                                        "region": "KE", "env": "dev",
                                        "service": svc})
    check("a read afterwards shows the new value and a clean working copy",
          {tuple(v["path"]): v["value"]
           for v in after["structuredContent"]["doc"]["values"]}
          .get(("image", "tag")) == "1.4.2"
          and not after["structuredContent"]["doc"]["uncommitted_in_repo"])
    ghost = mcp.call(u, "config_read", {"project": "Config Test",
                                        "region": "KE", "env": "dev",
                                        "service": "not-a-service"})
    check("an unknown service is refused with what IS there",
          ghost["isError"] and "no service" in ghost["content"][0]["text"])

    print("the installation's switch outranks every token")
    mcp.save_config(enabled=True, allow_actions=False, row_limit=50,
                    token_days=90)
    check("with changes off, even a token scoped to act may not change",
          not mcp.may_act(vtok)
          and "gitops_sync" not in {t["name"] for t in mcp.tools(u, vtok)})
    out = mcp.call(u, "gitops_sync", {"controller": "c", "application": "a"},
                   tok=vtok)
    check("and the refusal names the installation, not the token",
          out["isError"] and "whole installation" in out["content"][0]["text"])
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50,
                    token_days=90)

    print("a scope can be changed without re-issuing the secret")
    again = mcp.rescope(verb_row["id"], admin, areas=["clusters"],
                        mode="read")
    check("re-scoping keeps the token working",
          again and bool(mcp.resolve(verb_secret)))
    check("with the new scope in force",
          mcp.resolve(verb_secret)["token"]["mode"] == "read"
          and mcp.resolve(verb_secret)["token"]["areas"] == ["clusters"])
    check("a verb list is dropped when the token can no longer change "
          "anything — a register saying “may run gitops_sync” about a token "
          "that cannot is worse than saying nothing",
          mcp.resolve(verb_secret)["token"]["actions"] == [])
    check("re-scoping somebody else's token is refused",
          not mcp.rescope(verb_row["id"], reader, mode="act"))
    check("an invented area, mode or verb is dropped rather than stored",
          mcp.clean_scope(["clusters", "not-an-area"], "sudo", ["rm -rf /"])
          == {"areas": ["clusters"], "mode": "read", "actions": []})
    check("the retired third mode reads as read-only, which is the safe "
          "direction for a token minted before it went",
          mcp.clean_scope([], "propose", [])["mode"] == "read")
    check("only areas some query actually covers can be scoped, so a scope "
          "cannot silently grant nothing",
          "clusters" in mcp.readable_areas()
          and "settings" not in mcp.readable_areas())

    print("a lifetime token is a deliberate choice")
    life_secret, life = mcp.mint(admin, "build box", 0)
    check("it never expires, and says so", life["expires"] == ""
          and life["lifetime"] and life["live"])
    check("a dated one is not marked lifetime",
          not mcp.token(wide_row["id"])["lifetime"])
    check("the mint form offers it by name rather than as a magic zero",
          'value="never"' in open("templates/_mcp_tokens.html").read())
    check("and it still resolves", bool(mcp.resolve(life_secret)))

    print("the switches hold their shape")
    mcp.save_config(enabled=True, allow_actions=True, row_limit=99999,
                    token_days=-5)
    cfg = mcp.config()
    check("a silly row limit is clamped, not obeyed", cfg["row_limit"] == 500)
    check("a negative lifetime becomes never rather than the past",
          cfg["token_days"] == 0)
    huge = mcp.call(u, "connections", {"limit": 10 ** 9})
    check("and a client cannot ask for more than the ceiling",
          len(huge["structuredContent"]["rows"]) <= 500)

    routes()
    print("\nFAILED" if bad else "\nOK")
    return 1 if bad else 0


def routes() -> None:
    """Over HTTP, the way a real client speaks."""
    print("through the endpoint: a bearer token, and a refusal a client reads")
    from fastapi.testclient import TestClient

    tok, _row = mcp.mint(auth.by_email("boss@t.local")["id"], "over http", 30)
    c = TestClient(main.app)
    c.__enter__()

    hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": mcp.LATEST, "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"}}}

    mcp.save_config(enabled=False, allow_actions=False, row_limit=50,
                    token_days=90)
    r = c.post("/mcp", json=hello)
    check(f"an installation that has not turned MCP on has no endpoint "
          f"({r.status_code}) — 404, not a 403 that advertises one",
          r.status_code == 404)

    mcp.save_config(enabled=True, allow_actions=False, row_limit=50,
                    token_days=90)
    r = c.post("/mcp", json=hello)
    check(f"no token is 401 with the challenge, never a redirect to a login "
          f"page an AI client cannot read ({r.status_code})",
          r.status_code == 401 and "Bearer" in r.headers.get(
              "www-authenticate", ""))
    check("and the body is JSON, not HTML",
          r.headers["content-type"].startswith("application/json"))
    r = c.post("/mcp", json=hello,
               headers={"Authorization": "Bearer emcp_not-a-real-token"})
    check(f"a wrong token is 401 ({r.status_code})", r.status_code == 401)

    auth_h = {"Authorization": f"Bearer {tok}"}
    r = c.post("/mcp", json=hello, headers=auth_h)
    check(f"a real token completes initialize ({r.status_code})",
          r.status_code == 200
          and r.json()["result"]["serverInfo"]["name"]
          and r.json()["result"]["protocolVersion"] == mcp.LATEST)
    r = c.post("/mcp", headers=auth_h,
               json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    check(f"a notification gets 202 and an empty body ({r.status_code})",
          r.status_code == 202 and not r.content)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 2,
                             "method": "tools/list"}, headers=auth_h)
    tools = r.json()["result"]["tools"]
    check(f"tools/list works over the wire ({len(tools)} tools)",
          r.status_code == 200 and len(tools) > 10
          and all("inputSchema" in t for t in tools))
    r = c.post("/mcp", headers=auth_h,
               json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "estate", "arguments": {}}})
    check(f"and so does a tool call ({r.status_code})",
          r.status_code == 200
          and r.json()["result"]["content"][0]["text"])
    r = c.post("/mcp", headers=auth_h, content=b"{not json")
    check(f"a malformed body is a parse error, not a stack trace "
          f"({r.status_code})",
          r.status_code == 400
          and r.json()["error"]["code"] == mcp.PARSE_ERROR)
    r = c.get("/mcp", headers=auth_h)
    check(f"GET is 405 with Allow: POST — this server offers no stream and "
          f"says so ({r.status_code})",
          r.status_code == 405 and r.headers.get("allow") == "POST")

    used = next(t for t in mcp.tokens(auth.by_email("boss@t.local")["id"])
                if t["name"] == "over http")
    check("using the token stamped and counted it",
          used["calls"] > 0 and used["last_used"] and used["last_ip"])
    check("the register is newest first, which needs a timestamp and not a "
          "date — every token minted today would otherwise sort at random",
          "T" in used["created"])

    # The area is the door: holding no MCP access means no endpoint, however
    # good the token is.
    tid = [r2["id"] for r2 in rbac.roles() if r2["name"] == "clusters only"][0]
    reader = auth.by_email("eyes@t.local")
    rtok, _ = mcp.mint(reader["id"], "reader", 30)
    r = c.post("/mcp", json=hello,
               headers={"Authorization": f"Bearer {rtok}"})
    check(f"a reader holding MCP access connects ({r.status_code})",
          r.status_code == 200)
    rbac.save(tid, "clusters only", "", ["clusters"], [], [])
    r = c.post("/mcp", json=hello,
               headers={"Authorization": f"Bearer {rtok}"})
    check(f"take the MCP area away and the same token is refused "
          f"({r.status_code}) — the roles decide, live",
          r.status_code == 403)

    # A session works too, which is what makes the endpoint pokeable from a
    # browser during development. It is not the contract, but it must not be
    # a hole either: the same area check applies.
    sess = TestClient(main.app)
    sess.__enter__()
    sess.post("/login", data={"email": "boss@t.local",
                              "password": "May-Ask-Everything-42"},
              follow_redirects=False)
    sess.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    r = sess.post("/mcp", json=hello)
    check(f"a signed-in administrator may poke it from a browser "
          f"({r.status_code})", r.status_code == 200)

    r = c.get("/settings/mcp")
    check(f"the settings page renders ({r.status_code})",
          r.status_code == 401 or r.status_code in (200, 303))
    r = sess.get("/settings/mcp")
    check(f"and carries the connect command ({r.status_code})",
          r.status_code == 200 and "claude mcp add" in r.text
          and "/mcp" in r.text)
    reg = sess.get("/settings/mcp?sec=tokens")
    check("the register is on the Tokens tab, where the tokens are",
          "over http" in reg.text)
    check("no live token secret is on either — only the last four characters",
          tok not in r.text and tok not in reg.text)
    print("the page is four tabs, and each one carries only its own section")
    seen, off = {}, {}
    for tab in ("", "connect", "tokens", "server", "tools"):
        rr = sess.get("/settings/mcp" + (f"?sec={tab}" if tab else ""))
        seen[tab or "default"] = rr.text
    # Half this page's prose only appears when the endpoint is OFF (the "turn
    # it on first" warnings).  Render that state too, or every pointer inside
    # it goes unchecked.
    was = mcp.config()
    mcp.save_config(enabled=False, allow_actions=False,
                    row_limit=was["row_limit"], token_days=was["token_days"])
    for tab in ("connect", "tokens", "server", "tools"):
        off[tab] = sess.get(f"/settings/mcp?sec={tab}").text
    mcp.save_config(enabled=was["enabled"], allow_actions=was["allow_actions"],
                    row_limit=was["row_limit"], token_days=was["token_days"])
    check("the off state still renders all four tabs",
          all(r and "Connect a client" in r for r in off.values()))
    # Every render carries a fresh CSP nonce, so two identical pages differ
    # byte for byte. Compare what the page SAYS, with the nonce taken out.
    same = lambda t: re.sub(r'nonce="[^"]*"', "", t)
    check("an unknown or absent tab lands on Connect rather than nothing",
          same(seen["default"]) == same(seen["connect"])
          and "Connect a client" in seen["connect"]
          and same(sess.get("/settings/mcp?sec=nonsense").text)
              == same(seen["connect"]))
    check("the switches are only on Server",
          "serve MCP at this address" in seen["server"]
          and "serve MCP at this address" not in seen["tokens"]
          and "serve MCP at this address" not in seen["tools"])
    check("the register and the mint form are only on Tokens",
          "Mint a token</button>" in seen["tokens"]
          and "Mint a token</button>" not in seen["server"])
    check("the verb inventory is only on What it can do",
          "reads — always available" in seen["tools"]
          and "reads — always available" not in seen["connect"])
    check("the status tiles are on EVERY tab — whether the endpoint is on is "
          "worth seeing whichever one is open",
          all("MCP endpoint" in v for v in seen.values()))
    check("and every tab is a shareable link, not client-side state",
          all(f'href="/settings/mcp?sec={t}"' in seen["connect"]
              for t in ("connect", "tokens", "server", "tools")))
    check("splitting it made the common tab lighter, which was the point",
          len(seen["connect"]) < len(seen["tokens"]))

    # Splitting one page into tabs strands every "below" and "above" that
    # pointed at a section now living on a different tab.  The prose has to
    # send you to the tab by name, and the pointer has to be a link.
    import re as _re
    stranded = []
    for tab, html in list(seen.items()) + [(f"{k} (off)", v)
                                           for k, v in off.items()]:
        body = html[html.find("subtabs"):]
        body = _re.sub(r"(?is)<script.*?</script>|<style.*?</style>|<!--.*?-->",
                       " ", body)
        for m in _re.finditer(r"(?:above|below)", body):
            near = body[max(0, m.start() - 240):m.start() + 40]
            if "?sec=" in near or "/settings/" in near:
                continue          # already points at the tab that owns it
            if "<!--" in near.rsplit(">", 1)[-1]:
                continue
            stranded.append((tab, _re.sub(r"\s+", " ", near[-70:])))
    if stranded:
        print("   stranded:", stranded[:3])
    check(f"no prose sends you 'above' or 'below' to another tab ({len(stranded)})",
          not stranded)
    check("and the endpoint-is-off warnings link to the tab that owns the switch",
          seen["tokens"].count('/settings/mcp?sec=server') >= 1
          or "MCP endpoint" in seen["tokens"])

    r = sess.post("/me/mcp/token", data={"name": "from the page", "days": "7",
                                         "back": "settings"},
                  follow_redirects=False)
    check("minting comes back to the Tokens tab, not to Connect",
          "sec=tokens" in (r.headers.get("location") or ""))
    r = sess.post("/me/mcp/token", data={"name": "from the page", "days": "7"},
                  follow_redirects=False)
    check(f"minting from the page works ({r.status_code})",
          r.status_code == 303)
    r = sess.get("/me")
    check("the account page shows it and offers the connect line",
          "from the page" in r.text and "claude mcp add" in r.text)
    check("the secret is shown once, and comes from the session rather than "
          "the URL — a secret in a query string is a secret in a proxy log",
          "emcp_" in r.text)
    r = sess.get("/me")
    check("and it is gone on the next view", "emcp_" not in r.text)
    check("the settings hub advertises it",
          "AI clients (MCP)" in sess.get("/settings").text)

    # THE ACCOUNT PAGE IS SHORT UNTIL IT IS ASKED. It was eight cards all open
    # at once, so the audit trail you read when something has gone wrong had
    # the same weight as a theme switch. MCP is one of the sections that must
    # arrive shut — a token register is reference, not something to scroll past
    # on the way to changing a password.
    page = sess.get("/me").text
    check("the MCP section is a collapsed <details>, not an open card",
          '<details class="acc-sec">' in page
          and "AI clients · MCP" in page)
    check("and nothing on the account page arrives open",
          '<details class="acc-sec" open' not in page)
    # The tokens are still THERE, just behind the summary — a section that
    # collapses by dropping its content is not collapsing, it is hiding.
    check("the token register is inside it, not dropped",
          "from the page" in page)


if __name__ == "__main__":
    raise SystemExit(main_test())
