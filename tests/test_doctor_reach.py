#!/usr/bin/env python3
"""The doctor reaches what the cluster depends on: DNS, findings, certificates.

WHY THIS EXISTS
    Reported 22 November 2026 from dev: Claude, as the 3D view's doctor, said it
    could see "clusters, pods and config, but not" the rest, and the person
    asked for it to "see whatever EnvMap can see, GitOps, pipelines, SonarQube,
    DNS, certificates, and manage and edit all of those". GitOps, pipelines,
    certificates and values files were already verbs. DNS and the edge, the
    security platforms' findings, and renewing a certificate were not, so a pod
    broken by a DNS record or a failed quality gate was beyond the doctor.

    Each new verb wraps what its page calls and keeps its page's rules: the
    connection's project scope, the Edge page's typed confirm word, the audit
    line. The providers are played here; nothing is reached.

    ./.venv/bin/python tests/test_doctor_reach.py
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("doctor-reach-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import actions, auth, certs, db, doctor_brief, edge, mcp, rbac, security, store  # noqa: E402

bad = 0


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")
    else:
        print(f"  ok   {what}")


def refused(fn) -> str:
    try:
        fn()
    except actions.Denied as e:
        return str(e) or "refused"
    return ""


def main_test() -> int:
    mine, theirs = store.add_project("Shop", icon="x"), store.add_project("Bank", icon="x")

    def person(mail, areas, projects=()):
        uid = auth.create_user(mail, mail.split("@")[0], "Passw0rd!xY-reach", role="user")
        rbac.set_for_user(uid, [rbac.save("", mail, "", areas, list(projects), [])])
        return auth.by_id(uid)

    me = person("doc@test.invalid", ["clusters", "edge", "security", "certs"], [mine])
    nobody = person("guest@test.invalid", ["clusters"])

    zones = {"c-mine": "shop.example.com", "c-theirs": "bank.example.com"}
    store.all_edge = lambda: [{"id": "c-mine", "name": "shop-cf", "type": "cloudflare", "pid": mine},
                              {"id": "c-theirs", "name": "bank-cf", "type": "cloudflare", "pid": theirs}]
    edge.inventory = lambda c, refresh=False: {"error": "", "groups": [
        {"key": "dns", "label": "DNS", "rows": [
            {"name": f"api.{zones[c['id']]}", "type": "A", "extra": "10.0.0.5", "zone": zones[c["id"]]},
            {"name": f"www.{zones[c['id']]}", "type": "CNAME", "extra": "edge", "zone": zones[c["id"]]}]}]}
    ran = []
    edge.run = lambda c, key, params: ran.append((c["id"], key, params)) or {"message": f"{key} done"}

    print("DNS and the edge")
    got = actions.run(me, "dns", {})["doc"]
    names = [c["connection"] for c in got["connections"]]
    check(f"the dns tool reads the connections in the person's projects, and only those ({names})",
          names == ["shop-cf"])
    rows = got["connections"][0]["groups"][0]["rows"]
    check("with their records, and the changes the provider allows and the fields each takes",
          any(r["name"] == "api.shop.example.com" for r in rows)
          and any(x["action"] == "dns_update" or x["group"] == "dns" for x in got["connections"][0]["changes"]))
    narrow = actions.run(me, "dns", {"name": "www"})["doc"]["connections"][0]["groups"][0]["rows"]
    check("and narrows to a name", [r["name"] for r in narrow] == ["www.shop.example.com"])

    key = next(k for k, v in edge.ACTIONS.items() if v["provider"] == "cloudflare" and v["group"] == "dns")
    fields = {p["name"]: "x" for p in edge.ACTIONS[key]["params"]}
    fields.update({"zone": "shop.example.com"})
    want = edge.confirm_word(key, {p["name"]: str(fields.get(p["name"], "")).strip()
                                   for p in edge.ACTIONS[key]["params"]})
    why = refused(lambda: actions.run(me, "dns_change", {"connection": "shop-cf", "action": key, "params": fields}))
    check(f"a DNS change without the person's confirm word changes nothing and names the word ({why[:60]})",
          not ran and want.lower() in why.lower())
    check("nor with a wrong one",
          refused(lambda: actions.run(me, "dns_change", {"connection": "shop-cf", "action": key,
                                                         "params": fields, "confirm": "nope"})) and not ran)
    actions.run(me, "dns_change", {"connection": "shop-cf", "action": key, "params": fields, "confirm": want})
    check("with it, the Edge page's own action runs, on that connection, with those fields",
          len(ran) == 1 and ran[0][0] == "c-mine" and ran[0][1] == key)
    line = db.one("SELECT * FROM audit WHERE action = 'edge_action' ORDER BY rowid DESC LIMIT 1")
    check("and it is audited as the page audits it", line is not None)
    check("a connection in somebody else's project cannot be changed",
          refused(lambda: actions.run(me, "dns_change", {"connection": "bank-cf", "action": key,
                                                         "params": fields, "confirm": want})) and len(ran) == 1)
    check("and a person without Edge & DNS is refused both",
          refused(lambda: actions.run(nobody, "dns", {})) and refused(
              lambda: actions.run(nobody, "dns_change", {"connection": "shop-cf", "action": key,
                                                         "params": fields, "confirm": want})))

    print("security findings")
    store.all_sec = lambda: [{"id": "s1", "name": "sonar", "type": "sonarqube", "pid": mine},
                             {"id": "s2", "name": "dojo", "type": "defectdojo", "pid": theirs}]
    asked = []
    security.findings = lambda c, **k: asked.append((c["id"], k)) or {"total": 1, "rows": [
        {"id": 7, "title": "SQL injection", "severity": "critical", "component": "api",
         "file": "src/db.py", "line": 42, "secret_field_nobody_needs": "x"}]}
    got = actions.run(me, "security_findings", {"severity": "critical", "limit": "5"})
    plat = got["doc"]["platforms"]
    check("findings come from the platforms in the person's projects, worst first, as asked",
          [p["connection"] for p in plat] == ["sonar"] and asked[0][1].get("sev") == "critical"
          and asked[0][1].get("limit") == 5)
    check("with what a doctor needs and nothing else",
          plat[0]["findings"] == [{"id": 7, "title": "SQL injection", "severity": "critical",
                                   "component": "api", "file": "src/db.py", "line": 42}])

    print("renewing a certificate")
    certs.orders = lambda: [{"id": "o1", "name": "api.shop.example.com", "domains": ["api.shop.example.com"]}]
    renewed = []
    certs.renew = lambda oid, uid, same_key=True: renewed.append((oid, uid, same_key)) or "o2"
    got = actions.run(me, "cert_renew", {"order": "api.shop.example.com"})
    check("a certificate is renewed by one of its names, keeping its key unless told",
          renewed == [("o1", me["id"], True)] and "o2" in got.get("detail", ""))

    print("what the doctor is handed")
    mcp.save_config(enabled=True, allow_actions=True)        # "let a token change things", as dev has it
    secret, tok = mcp.mint(me["id"], "doctor", days=1, mode="act")
    offered = [t["name"] for t in mcp.tools(me, mcp.token(tok["id"]))]
    allowed, never = doctor_brief.tool_lists(True, offered)
    P = doctor_brief.PREFIX
    check(f"the new tools are offered to the person over MCP ({[t for t in offered if t in ('dns', 'dns_change', 'security_findings', 'cert_renew')]})",
          {"dns", "dns_change", "security_findings", "cert_renew"} <= set(offered))
    check("the doctor reads DNS and findings without asking, and may change DNS and renew once the person agrees",
          {P + "dns", P + "security_findings", P + "dns_change", P + "cert_renew"} <= set(allowed))
    _, look = doctor_brief.tool_lists(False, offered)
    check("a look-only doctor may not even ask for them", {P + "dns_change", P + "cert_renew"} <= set(look))
    brief = doctor_brief.CHANGE_RULE
    check("and its brief sends it past the pod: GitOps, pipelines, findings, DNS, certificates",
          all(w in brief for w in ("dns_change", "cert_renew", "security_findings", "pipelines", "gitops",
                                   "A POD IS OFTEN SICK BECAUSE OF SOMETHING OUTSIDE IT")))
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
