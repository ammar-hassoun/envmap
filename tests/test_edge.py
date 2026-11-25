#!/usr/bin/env python3
"""Edge and DNS: Cloudflare and the others, against stubbed APIs.

The layer in front of everything else, so the cases that matter are the ones that
change live traffic: a purge, development mode left on, a TLS mode moved down, a
DNS record added or deleted. Each has to be confirmed and recorded, and a deletion
has to ask for the record's own id rather than a word.

Cloudflare's API is stubbed with the shapes it really returns, including the
awkward ones: settings as a flat list of id/value objects, errors as a list, and
success carried in the body rather than only in the status code.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("edge-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import edge                                           # noqa: E402

CF = {"id": "e-1", "type": "cloudflare", "name": "Cloudflare", "token": "cf-token",
      "username": "acct-9", "pid": ""}
bad = 0
calls: list = []


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def ok(result):
    return {"success": True, "errors": [], "result": result}


def fake_call(url, headers, skip_tls=False, method="GET", body=None):
    calls.append({"url": url, "method": method, "body": body,
                  "auth": headers.get("Authorization", "")
                          or headers.get("AccessKey", "")})
    path = url.split("/client/v4")[-1] if "/client/v4" in url else url

    if path == "/user/tokens/verify":
        return 200, ok({"status": "active"})
    if path.startswith("/zones?per_page=1"):
        return 200, {"success": True, "result": [], "result_info": {"total_count": 2}}
    if path.startswith("/zones?per_page=50"):
        return 200, ok([
            {"id": "z1", "name": "example.com", "status": "active",
             "paused": False, "type": "full",
             "plan": {"name": "Pro"},
             "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
             "modified_on": "2026-07-01T00:00:00Z"},
            {"id": "z2", "name": "staging.example.com", "status": "active",
             "paused": True, "type": "partial", "plan": {"name": "Free"},
             "name_servers": [], "modified_on": "2026-06-01T00:00:00Z"}])
    if "/dns_records?per_page" in path:
        zone = path.split("/zones/")[1].split("/")[0]
        if zone == "z2":
            return 200, ok([])
        return 200, ok([
            {"id": "r1", "name": "example.com", "type": "A",
             "content": "203.0.113.10", "proxied": True},
            {"id": "r2", "name": "direct.example.com", "type": "A",
             "content": "203.0.113.11", "proxied": False}])
    if path.endswith("/settings"):
        zone = path.split("/zones/")[1].split("/")[0]
        return 200, ok([
            {"id": "ssl", "value": "flexible" if zone == "z1" else "full_strict"},
            {"id": "min_tls_version", "value": "1.2"},
            {"id": "always_use_https", "value": "on"},
            {"id": "cache_level", "value": "aggressive"},
            {"id": "development_mode", "value": "on" if zone == "z1" else "off"},
            {"id": "security_level", "value": "medium"},
            {"id": "security_header",
             "value": {"strict_transport_security": {"enabled": True}}}])
    if "/ssl/certificate_packs" in path:
        return 200, ok([{"id": "cp1", "type": "universal", "status": "active",
                         "hosts": ["example.com", "*.example.com"],
                         "certificate_authority": "lets_encrypt",
                         "certificates": [{"expires_on": "2026-09-30T00:00:00Z"}]}])
    if "/cfd_tunnel" in path:
        return 200, ok([{"id": "t1", "name": "office", "status": "healthy",
                         "connections": [{"origin_ip": "10.0.0.9"}],
                         "created_at": "2026-01-01T00:00:00Z"}])
    if "/workers/scripts" in path:
        return 200, ok([{"id": "router", "modified_on": "2026-05-01T00:00:00Z",
                         "routes": []}])
    if "/r2/buckets" in path:
        return 200, ok({"buckets": [{"name": "uploads", "location": "weur",
                                     "creation_date": "2025-11-02T00:00:00Z"}]})
    # ── writes ──
    if path.endswith("/purge_cache"):
        return 200, ok({"id": "z1"})
    if "/settings/development_mode" in path or path.endswith("/settings/ssl"):
        return 200, ok({"id": "x", "value": (body or {}).get("value")})
    if "/dns_records" in path and method in ("POST", "PUT", "DELETE"):
        return 200, ok({"id": "r9"})
    if "/firewall/access_rules/rules" in path:
        return 200, ok({"id": "f1"})
    return 200, ok([])


def main() -> int:
    real = edge._call
    edge._call = fake_call
    edge.invalidate()
    try:
        # ── the connection check ──────────────────────────────────────────
        good, why = edge.test(CF)
        check("a working token is accepted", good and "active" in why)
        check("it says how many zones are visible", "2 zone" in why)
        check("the token goes in an Authorization header, not a query string",
              calls and calls[0]["auth"].startswith("Bearer cf-token"))

        # ── what it reads ────────────────────────────────────────────────
        inv = edge.inventory(CF, refresh=True)
        by = {g["key"]: g for g in inv["groups"]}
        check("zones are listed", [r["name"] for r in by["zones"]["rows"]]
              == ["example.com", "staging.example.com"])
        check("a paused zone says paused rather than active",
              by["zones"]["rows"][1]["state"] == "paused")
        check("DNS records are listed across zones", len(by["dns"]["rows"]) == 2)
        rec = by["dns"]["rows"][0]
        check("a record carries what an edit form needs, not just what a table shows",
              {"zone_id", "type", "content", "ttl", "proxied", "proxiable",
               "short"} <= set(rec))
        check("the name is shortened against its zone, since the zone is the heading",
              rec["short"] == "@" and rec["name"] == "example.com")
        check("a subdomain keeps only its own part",
              by["dns"]["rows"][1]["short"] == "direct")
        check("a proxied record is distinguished from a direct one",
              {r["state"] for r in by["dns"]["rows"]} == {"proxied", "dns only"})
        check("certificates carry their expiry",
              by["certs"]["rows"][0]["extra"] == "2026-09-30")
        check("tunnels, Workers and R2 are read when an account id is given",
              {"tunnels", "workers", "r2"} <= set(by))
        check("an R2 bucket is read out of its wrapper object",
              by["r2"]["rows"][0]["name"] == "uploads")

        tls = {t["zone"]: t for t in inv["tls"]}
        check("the TLS position is read per zone",
              tls["example.com"]["ssl"] == "flexible"
              and tls["staging.example.com"]["ssl"] == "full_strict")
        check("development mode being left on is visible",
              tls["example.com"]["dev_mode"] == "on")
        check("HSTS is read out of its nested setting",
              tls["example.com"]["hsts"] is True)

        # without an account id, the account-wide things are explained
        no_acct = edge.inventory({**CF, "id": "e-2", "username": ""},
                                 refresh=True)
        check("no account id is explained rather than showing empty tables",
              any("account-wide" in n for n in no_acct["notes"])
              and not any(g["key"] == "tunnels" for g in no_acct["groups"]))

        # ── which actions are offered where ──────────────────────────────
        zone_acts = {a["key"] for a in edge.for_group("zones", "cloudflare")}
        dns_acts = {a["key"] for a in edge.for_group("dns", "cloudflare")}
        check("the zone page offers purging and posture changes",
              {"cf.purge_all", "cf.purge_urls", "cf.dev_mode", "cf.ssl_mode",
               "cf.block_ip"} == zone_acts)
        check("the DNS page offers record changes",
              {"cf.record_create", "cf.record_update", "cf.record_delete"}
              == dns_acts)
        check("a Bunny action is not offered on a Cloudflare connection",
              not any(a["key"].startswith("bunny.")
                      for a in edge.for_group("pullzones", "cloudflare")))
        check("deleting a record asks for the word Delete",
              edge.confirm_word("cf.record_delete",
                                {"zone": "z1", "record": "r1",
                                 "name": "api.example.com"}) == "Delete")
        check("everything else asks for a word",
              edge.confirm_word("cf.purge_all", {"zone": "z1"}) == "CONFIRM")

        # ── the calls those actions make ─────────────────────────────────
        calls.clear()
        edge.run(CF, "cf.purge_all", {"zone": "z1"})
        check("purging everything says so explicitly",
              calls[-1]["body"] == {"purge_everything": True}
              and calls[-1]["method"] == "POST")

        edge.run(CF, "cf.purge_urls",
                 {"zone": "z1", "files": "https://a/x.js, https://a/y.css"})
        check("a URL purge sends a list, not a string",
              calls[-1]["body"] == {"files": ["https://a/x.js", "https://a/y.css"]})

        edge.run(CF, "cf.dev_mode", {"zone": "z1", "value": "off"})
        check("development mode is patched, not posted",
              calls[-1]["method"] == "PATCH"
              and calls[-1]["body"] == {"value": "off"})

        edge.run(CF, "cf.record_create",
                 {"zone": "z1", "type": "CNAME", "name": "www",
                  "content": "example.com", "ttl": "1", "proxied": "true",
                  "comment": "for the redirect"})
        body = calls[-1]["body"]
        check("a new record carries its type, name and value",
              body["type"] == "CNAME" and body["name"] == "www"
              and body["content"] == "example.com")
        check("proxied is a boolean and TTL a number",
              body["proxied"] is True and body["ttl"] == 1)
        check("the reason is passed through as a comment",
              body["comment"] == "for the redirect")

        edge.run(CF, "cf.record_delete", {"zone": "z1", "record": "r1"})
        check("deleting a record uses DELETE on that record",
              calls[-1]["method"] == "DELETE" and calls[-1]["url"].endswith("/r1"))

        edge.run(CF, "cf.block_ip",
                 {"zone": "z1", "value": "203.0.113.0/24", "mode": "challenge",
                  "notes": "scraper"})
        body = calls[-1]["body"]
        check("a CIDR is sent as a range and a bare address as an ip",
              body["configuration"]["target"] == "ip_range")
        edge.run(CF, "cf.block_ip", {"zone": "z1", "value": "203.0.113.7",
                                     "mode": "block"})
        check("a single address is sent as an ip",
              calls[-1]["body"]["configuration"]["target"] == "ip")

        # ── refusals ─────────────────────────────────────────────────────
        try:
            edge.run(CF, "cf.record_create", {"zone": "z1", "type": "A"})
            check("a missing parameter is refused", False)
        except edge.EdgeError as e:
            check("a missing parameter is refused, naming the fields",
                  "name" in str(e) and "value" in str(e))
        try:
            edge.run(CF, "bunny.purge", {"zone": "1"})
            check("another provider's action is refused", False)
        except edge.EdgeError as e:
            check("another provider's action is refused, saying why",
                  "bunny" in str(e) and "cloudflare" in str(e))
        try:
            edge.run(CF, "cf.nonsense", {})
            check("an unknown action is refused", False)
        except edge.EdgeError as e:
            check("an unknown action is refused", "unknown" in str(e))

        # a failure carried in the body, which Cloudflare does with a 200
        def refuses(url, headers, skip_tls=False, method="GET", body=None):
            return 200, {"success": False,
                         "errors": [{"code": 10000,
                                     "message": "Authentication error"}]}
        edge._call = refuses
        try:
            edge.run(CF, "cf.purge_all", {"zone": "z1"})
            check("a failure reported in the body is not treated as success", False)
        except edge.EdgeError as e:
            check("a failure in the body is caught and explained",
                  "Authentication error" in str(e) and "permission" in str(e))
        edge._call = fake_call
    finally:
        edge._call = real
        edge.invalidate()

    bad_routes = check_routes()
    print("OK" if not (bad + bad_routes) else f"{bad + bad_routes} FAILED")
    return bad + bad_routes


def check_routes() -> int:
    """The page and the action route around it."""
    from fastapi.testclient import TestClient
    from app import auth, db, main, store

    problems = 0
    email, pw = "edge@test.local", "Edge-Pages-Work-42"
    uid = auth.create_user(email, "Edge", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    cid = store.add_conn("edge", "", {"type": "cloudflare", "name": "Cloudflare",
                                      "token": "cf-token", "username": "acct-9"})
    real = edge._call
    edge._call = fake_call
    edge.invalidate()
    c = TestClient(main.app)
    try:
        with c:
            c.post("/login", data={"email": email, "password": pw},
                   follow_redirects=False)
            c.post("/mfa", data={"code": auth._totp_at(
                "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
                follow_redirects=False)

            hub = c.get("/edge").text
            if "Cloudflare" not in hub:
                print("  FAIL the hub does not list the connection")
                problems += 1
            page = c.get(f"/edge?conn={cid}").text
            for want, why in (("example.com", "the zones"),
                              ("TLS and cache, per zone", "the TLS table"),
                              ("flexible", "a weak TLS mode, visible"),
                              ("/edge/action", "the action forms")):
                if want not in page:
                    print(f"  FAIL the page is missing {why}")
                    problems += 1
            dns = c.get(f"/edge?conn={cid}&group=dns").text
            if "direct.example.com" not in dns:
                print("  FAIL the DNS group does not list records")
                problems += 1
            if "cf.record_delete" not in dns:
                print("  FAIL the DNS group does not offer record actions")
                problems += 1

            csv_out = c.get(f"/edge/export/{cid}/dns.csv")
            if csv_out.headers.get("content-type", "").split(";")[0] != "text/csv":
                print("  FAIL the export is not CSV")
                problems += 1
            if "direct.example.com" not in csv_out.text:
                print("  FAIL the export does not carry the rows")
                problems += 1

            # the confirmation, which is the whole safety model
            r = c.post("/edge/action",
                       data={"conn": cid, "action": "cf.record_delete",
                             "zone": "z1", "record": "r1", "confirm": "CONFIRM"},
                       follow_redirects=False)
            if "err=" not in r.headers.get("location", ""):
                print("  FAIL a removal accepted the generic word")
                problems += 1
            r = c.post("/edge/action",
                       data={"conn": cid, "action": "cf.record_delete",
                             "zone": "z1", "record": "r1", "confirm": "Delete"},
                       follow_redirects=False)
            if "msg=" not in r.headers.get("location", ""):
                print(f"  FAIL Delete did not confirm it: {r.headers.get('location')}")
                problems += 1

            # ── the DNS view is a manager, not a table ───────────────
            dns_page = c.get(f"/edge?conn={cid}&group=dns").text
            for want, why in (
                    ('class="card dnscard"', "records grouped by zone"),
                    ('class="dns-edit"', "an edit control on each line"),
                    ('class="dns-del"', "a delete control on each line"),
                    ('id="dnsAdd"', "the add-record dialog"),
                    ('name="record" value="r1"', "the record id carried for editing"),
                    ('name="zone" value="z1"', "the zone id carried for editing"),
                    ('class="dns-proxy on"', "a proxied record marked as such")):
                if want not in dns_page:
                    print(f"  FAIL the DNS view is missing {why}")
                    problems += 1
            if dns_page.count('class="dns-row"') != 2:
                print("  FAIL one line per record")
                problems += 1

            # editing through the inline form, with only the row's own ids
            r = c.post("/edge/action",
                       data={"conn": cid, "group": "dns",
                             "action": "cf.record_update", "zone": "z1",
                             "record": "r1", "type": "A", "name": "example.com",
                             "content": "203.0.113.99", "ttl": "1",
                             "proxied": "true", "confirm": "CONFIRM"},
                       follow_redirects=False)
            if "msg=" not in r.headers.get("location", ""):
                print(f"  FAIL an inline edit did not save: {r.headers.get('location')}")
                problems += 1

            # a deletion is confirmed by typing Delete, and nothing else will do
            for typed, should_run in (("", False), ("yes", False),
                                      ("r1", False), ("example.com", False),
                                      ("Delete", True), ("delete", True),
                                      ("DELETE", True)):
                r = c.post("/edge/action",
                           data={"conn": cid, "group": "dns",
                                 "action": "cf.record_delete", "zone": "z1",
                                 "record": "r1", "name": "example.com",
                                 "confirm": typed}, follow_redirects=False)
                ran = "msg=" in r.headers.get("location", "")
                if ran != should_run:
                    print(f"  FAIL confirm={typed!r} "
                          f"{'was refused' if should_run else 'was accepted'}")
                    problems += 1

            # the icons must be drawn, not typed: a font glyph is at the mercy of
            # whatever the interface font does with it
            if "✎" in dns_page or "🗑" in dns_page:
                print("  FAIL the row controls are still font characters")
                problems += 1
            if dns_page.count("<svg viewBox=\"0 0 16 16\"") < 4:
                print("  FAIL the row controls are not drawn icons")
                problems += 1
            if "/edge/action" not in dns_page:
                print("  FAIL the DNS view has no way to change anything")
                problems += 1
            if 'value="cf.record_update"' not in dns_page:
                print("  FAIL the inline edit form is not on the DNS view")
                problems += 1
            if dns_page.count("Change a DNS record") or dns_page.count("class=\"adv\"") > 0:
                print("  FAIL the DNS view still carries the duplicate accordion")
                problems += 1
            if 'aria-label="Delete example.com"' not in dns_page:
                print("  FAIL an icon-only control has no label for a screen reader")
                problems += 1

            rows = db.connect().execute(
                "SELECT action, detail FROM audit WHERE action LIKE 'edge_%'"
            ).fetchall()
            blob = " ".join(f"{a[0]} {a[1]}" for a in rows)
            if "cf.record_delete" not in blob:
                print("  FAIL the change that ran is not in the audit log")
                problems += 1
    finally:
        edge._call = real
        edge.invalidate()
    print(f"  routes: {'ok' if not problems else str(problems) + ' failed'}")
    return problems


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
