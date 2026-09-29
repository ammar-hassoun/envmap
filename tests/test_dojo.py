#!/usr/bin/env python3
"""The in-portal DefectDojo finding detail — the CVE read HERE, not in Dojo.

WHY THIS EXISTS
    The findings table used to link every title out to DefectDojo; reading a
    CVE meant opening a second product. security.finding() now pulls the whole
    document (description, mitigation, impact, references, CVSS, every
    CVE/GHSA/CWE id, flags, notes) and the page renders it above the list.
    Pinned here against a faked API, so the field mapping cannot drift:

      1. finding() maps the full payload — refs deduped and linked (NVD for
         CVE, GitHub for GHSA, MITRE for CWE), flags from the booleans, notes
         from their own endpoint (and their absence is not an error).
      2. Only DefectDojo has the document — other platforms return None and
         the table keeps linking out.
      3. The route renders the detail card, keeps the list under it, links the
         row titles INTO the portal, and survives a bad finding id.

    ./.venv/bin/python tests/test_dojo.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("dojo-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, security, store                      # noqa: E402
import app.main as appmain                                     # noqa: E402

bad = 0


def check(label, ok):
    global bad
    print(("  ok  " if ok else "FAIL  ") + label)
    if not ok:
        bad += 1


RAW = {
    "id": 101, "title": "RCE in demo-parser", "severity": "Critical",
    "active": True, "verified": True, "duplicate": False,
    "cve": "CVE-2024-0001", "cwe": 502,
    "vulnerability_ids": [{"vulnerability_id": "CVE-2024-0001"},
                          {"vulnerability_id": "GHSA-aaaa-bbbb-cccc"}],
    "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvssv3_score": 9.8, "epss_score": 0.92,
    "description": ("**Fixed version**: 2.4.1\n\n"
                    "- A crafted payload reaches eval() in the parser\n"
                    "- The worker runs it verbatim\n\n"
                    "```\ncurl --socks5-hostname target\n```\n"
                    "<script>alert(1)</script>\n"
                    "See https://example.org/advisory-1."),
    "mitigation": "Upgrade demo-parser to 2.4.1 or later.",
    "impact": "Remote code execution on the worker.",
    "references": "https://example.org/advisory-1",
    "component_name": "demo-parser", "component_version": "2.3.0",
    "file_path": "src/parse.py", "line": 88,
    "date": "2026-08-01", "sla_days_remaining": -4,
    "tags": ["backend"],
    "related_fields": {"test": {
        "test_type": {"name": "Trivy Scan"}, "branch_tag": "main",
        "engagement": {"name": "release-42", "product": {
            "id": 7, "name": "demo-backend",
            "prod_type": {"name": "Payments"}}}}},
}


RAW_CLOSED = {**RAW, "id": 102, "title": "Patched RCE in demo-parser",
              "severity": "High", "active": False, "verified": False,
              "is_mitigated": True, "mitigated": "2026-08-10T00:00:00Z"}


def fake_get(url: str, headers: dict, verify: bool = True):
    path = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(path.query))
    p = path.path
    if p.endswith("/findings/101/"):
        return RAW
    if p.endswith("/findings/101/notes/"):
        return {"results": [{"author": {"username": "sec-team"},
                             "date": "2026-08-02T09:30:00Z",
                             "entry": "patch scheduled for the next release"}]}
    if p.endswith("/findings/"):
        grouped = "test__engagement__product__prod_type" in q
        if q.get("limit") == "1":                 # a count probe
            if "severity" in q:
                if q.get("is_mitigated") == "true" or q.get("active") == "false":
                    return {"count": 1}           # per-severity, closed slice
                return {"count": 2 if grouped else 3}
            if q.get("is_mitigated") == "true":
                return {"count": 8 if grouped else 2}
            if q.get("risk_accepted") == "true":
                return {"count": 0 if grouped else 1}
            if q.get("false_p") == "true":
                return {"count": 0 if grouped else 4}
            if q.get("out_of_scope") == "true":
                return {"count": 0 if grouped else 0}
            if q.get("active") == "false":
                return {"count": 11 if grouped else 7}
            if q.get("active") == "true":
                return {"count": 55 if grouped else 15}
            return {"count": 66 if grouped else 22}   # no active filter: all
        if grouped and q.get("risk_accepted") == "true":
            return {"count": 0, "results": []}    # the 3 live in OTHER groups
        if q.get("is_mitigated") == "true" or q.get("active") == "false":
            return {"count": 1, "results": [RAW_CLOSED]}
        return {"count": 1, "results": [RAW]}     # the open list page
    if p.endswith("/products/"):
        if q.get("limit") == "1":
            return {"count": 1}
        return {"count": 1, "results": [
            {"id": 7, "name": "demo-backend", "prod_type": 1,
             "findings_count": 3}]}
    if p.endswith("/product_types/"):
        return {"count": 1, "results": [{"id": 1, "name": "Payments"}]}
    if p.endswith("/engagements/"):
        return {"count": 0, "results": []}
    raise AssertionError(f"unexpected URL {url}")


def main_test():
    security._get = fake_get
    cid = store.add_sec("", {"type": "defectdojo", "name": "dojo",
                             "base_url": "http://dojo.local", "token": "t"})
    conn = store.get_conn("sec", "", cid)
    conn["id"] = cid

    print("the module maps the whole document")
    fd = security.finding(conn, 101)
    check("title/severity/status from the row mapper",
          fd["title"] == "RCE in demo-parser" and fd["severity"] == "critical"
          and fd["status"] == "verified")
    check("refs deduped, CWE appended, each linked to its registry",
          [r["id"] for r in fd["refs"]] == ["CVE-2024-0001",
                                            "GHSA-aaaa-bbbb-cccc", "CWE-502"]
          and fd["refs"][0]["url"].startswith("https://nvd.nist.gov/")
          and fd["refs"][1]["url"].startswith("https://github.com/advisories/")
          and "cwe.mitre.org" in fd["refs"][2]["url"])
    check("flags from the booleans", fd["flags"] == ["active", "verified"])
    check("the long texts arrive", "eval()" in fd["description"]
          and fd["mitigation"].startswith("Upgrade")
          and fd["impact"] and fd["references"])
    check("cvss vector + score + epss",
          fd["cvss"].startswith("CVSS:3.1") and fd["cvss_score"] == 9.8
          and fd["epss"] == 0.92)
    check("component, place and date", fd["component"] == "demo-parser 2.3.0"
          and fd["file"] == "src/parse.py" and fd["line"] == 88
          and fd["date"] == "2026-08-01")
    check("notes from their own endpoint", fd["notes"]
          and fd["notes"][0]["who"] == "sec-team"
          and "patch scheduled" in fd["notes"][0]["text"])
    check("other platforms return None (they keep linking out)",
          security.finding({"type": "sonarqube"}, 101) is None)

    print("the lifecycle: open, closed and why — exact counts per status")
    stc = security.status_counts(conn)
    check("every status counted, duplicates excluded",
          stc == {"": 15, "closed": 7, "mitigated": 2, "accepted": 1,
                  "false": 4, "out": 0, "all": 22})
    got_m = security.findings(conn, status="mitigated")
    check("a mitigated listing asks the API for the inactive world",
          got_m["rows"] and got_m["rows"][0]["title"].startswith("Patched")
          and got_m["rows"][0]["status"] == "mitigated")
    check("the default stays exactly what it always was — open",
          security.findings(conn)["rows"][0]["id"] == 101)
    stg = security.status_counts(conn, group="Payments")
    check("the counts honour the product-type scope — the numbers a tab shows "
          "are the rows its click opens (the Risk-accepted-3-but-empty bug)",
          stg == {"": 55, "closed": 11, "mitigated": 8, "accepted": 0,
                  "false": 0, "out": 0, "all": 66})
    check("the severity tiles scope with the page too — group",
          set(security.sev_counts(conn, group="Payments").values()) == {2})
    check("…and with the status being viewed (tiles above a Closed list count "
          "closed, not open)",
          set(security.sev_counts(conn, status="mitigated").values()) == {1})

    print("the page renders the detail card above the list")
    from fastapi.testclient import TestClient
    uid = auth.create_user("dojo@test.local", "D", "Dojo-Detail-42", "admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("DOJODETAILSECRET234567AA", uid))
    c = TestClient(appmain.app, raise_server_exceptions=False)
    c.post("/login", data={"email": "dojo@test.local",
                           "password": "Dojo-Detail-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "DOJODETAILSECRET234567AA", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    base = f"/security?platform=defectdojo&conn={cid}&tab=findings"
    r = c.get(f"{base}&finding=101")
    check(f"renders ({r.status_code})", r.status_code == 200)
    body = r.text
    check("the description is readable in the portal", "eval()" in body)
    check("mitigation and impact too", "Upgrade demo-parser" in body
          and "Remote code execution" in body)
    print("  …and the scanner's markdown renders instead of showing raw")
    check("**bold** became bold", "<b>Fixed version</b>" in body)
    check("bullets became a list",
          "<li>A crafted payload reaches eval() in the parser</li>" in body)
    check("a code fence became a block",
          "<pre>curl --socks5-hostname target</pre>" in body)
    check("a bare link became an anchor with its trailing dot left in prose",
          '<a href="https://example.org/advisory-1"' in body)
    check("markup in the text stays TEXT — escape-first",
          "&lt;script&gt;alert(1)&lt;/script&gt;" in body
          and "<script>alert(1)" not in body)
    from app.main import _mdlite
    check("headings render small", "<h5>Impact</h5>" in str(_mdlite("# Impact")))
    check("the CVE links to NVD",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" in body)
    check("the note shows", "patch scheduled" in body)
    check("Dojo stays one click away, not required",
          "Open in DefectDojo" in body)
    check("the list stays under the card and its titles link IN, not out",
          f"&finding=101" in body.replace(f"{base}&finding=101", "", 1))
    r = c.get(f"{base}&finding=abc")
    check("a bad id degrades to a message, the list survives",
          r.status_code == 200 and "not a number" in r.text)
    r = c.get(base)                              # the negative control
    check("without &finding there is no detail card",
          r.status_code == 200 and "eval()" not in r.text)

    print("the page carries the lifecycle")
    body = c.get(base).text
    check("the status strip is there with exact counts",
          "Mitigated" in body and "Risk accepted" in body
          and "status=closed" in body and "False positives" in body)
    body = c.get(f"{base}&status=mitigated").text
    check("the Mitigated view lists the closed finding, marked as such",
          "Patched RCE in demo-parser" in body and "mitigated" in body)
    body = c.get(f"{base}&group=Payments").text
    check("under a product-type tab the strip counts THAT type only",
          "55" in body and "66" in body)
    body = c.get(f"{base}&status=mitigated").text
    check("the tiles above a Mitigated list say so — no wrong-label numbers",
          "all mitigated" in body)
    landing = c.get(f"/security?platform=defectdojo&conn={cid}").text
    check("the landing chart row shows the lifecycle and the busiest products",
          "How findings stand" in landing and "Closed, and why" in landing
          and "Most affected products" in landing
          and "demo-backend" in landing)

    print("speed: the cache serves stale instantly and refreshes behind the scenes")
    import threading as _th
    dummy = {"id": "speed-test"}
    key = "speed-test::part::x"
    check("first look blocks and fills",
          security._cached(dummy, "part", "x", False, lambda: "v1") == "v1")
    security._CACHE[key] = (time.time() - security.CACHE_TTL - 1, "v1")
    started = _th.Event()

    def slow_produce():
        started.set()
        time.sleep(0.15)
        return "v2"
    t0 = time.monotonic()
    got_now = security._cached(dummy, "part", "x", False, slow_produce)
    waited = time.monotonic() - t0
    check("a stale hit answers IMMEDIATELY with the stale value",
          got_now == "v1" and waited < 0.1)
    check("…and a background refresh really started", started.wait(2))
    for _ in range(60):                      # let the refresh land
        if security._CACHE.get(key, (0, None))[1] == "v2":
            break
        time.sleep(0.05)
    check("the refresh replaced it behind the scenes",
          security._cached(dummy, "part", "x", False, lambda: "v3") == "v2")
    check("the Refresh button still blocks for NOW",
          security._cached(dummy, "part", "x", True, lambda: "v4") == "v4")

    print("speed: a cold findings view pays the slowest part, not the sum")
    calls = {"n": 0}
    real = security._get

    def slow_get(url, headers, verify=True):
        calls["n"] += 1
        time.sleep(0.08)
        return fake_get(url, headers, verify)
    security._get = slow_get
    try:
        security.invalidate()
        t0 = time.monotonic()
        r = c.get(base)
        wall = time.monotonic() - t0
        floor = calls["n"] * 0.08            # what one-after-another would cost
        check(f"renders ({r.status_code}) with {calls['n']} API calls",
              r.status_code == 200 and calls["n"] >= 10)
        check(f"parallel: {wall:.2f}s wall vs {floor:.2f}s sequential floor",
              wall < floor * 0.75)
    finally:
        security._get = real
        security.invalidate()

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
