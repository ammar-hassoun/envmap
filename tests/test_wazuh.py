#!/usr/bin/env python3
"""Wazuh as a security platform, against a stub of its API.

WHY A STUB AND NOT A LIVE WAZUH
    The two things most likely to break here are shape assumptions, and they
    are both invisible against a healthy server: that everything arrives inside
    data.affected_items, and that a version which no longer serves
    vulnerabilities from the API degrades to "unavailable" rather than to zero.
    Zero is the dangerous answer — it reads as "nothing wrong".

    ./.venv/bin/python tests/test_wazuh.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("wazuh-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import security                                       # noqa: E402

bad = 0
# 000 is the manager: it answers like an agent and is not one.
AGENTS = [
    {"id": "000", "name": "manager", "status": "active", "group": ["default"]},
    {"id": "001", "name": "web-01", "status": "active", "group": ["web"],
     "lastKeepAlive": "2026-08-03T06:00:00Z", "os": {"name": "Ubuntu"},
     "version": "v4.7.2"},
    {"id": "002", "name": "db-01", "status": "disconnected", "group": ["db"],
     "lastKeepAlive": "2026-07-28T01:00:00Z", "os": {"name": "RHEL"},
     "version": "v4.7.2"},
    {"id": "003", "name": "old-01", "status": "never_connected",
     "group": ["web"]},
]
VULNS = {
    "001": [{"severity": "Critical", "cve": "CVE-2026-1", "title": "openssl",
             "name": "openssl", "detection_time": "2026-08-01T00:00:00Z",
             "condition": "Active"},
            {"severity": "Medium", "cve": "CVE-2026-2", "title": "curl",
             "name": "curl", "detection_time": "2026-08-02T00:00:00Z",
             "condition": "Active"}],
    "002": [{"severity": "High", "cve": "CVE-2026-3", "title": "kernel",
             "name": "kernel", "detection_time": "2026-07-20T00:00:00Z",
             "condition": "Active"}],
}
SERVE_VULNS = True          # flipped to emulate 4.8, where the API dropped them
NO_TOKEN = False            # flipped to emulate a user without authenticate


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                                          # noqa: N802
        p = self.path
        if p.startswith("/security/user/authenticate"):
            return self._send({} if NO_TOKEN else {"data": {"token": "jwt"}})
        if p.startswith("/manager/info"):
            return self._send({"data": {"affected_items": [{"version": "v4.7.2"}]}})
        if p.startswith("/agents?"):
            return self._send({"data": {"affected_items": AGENTS,
                                        "total_affected_items": len(AGENTS)}})
        if p.startswith("/vulnerability/"):
            if not SERVE_VULNS:
                return self._send({"error": "not here any more"}, 404)
            aid = p.split("/")[2].split("?")[0]
            return self._send({"data": {"affected_items": VULNS.get(aid, [])}})
        return self._send({"error": "unknown"}, 404)


def main() -> int:
    global SERVE_VULNS, NO_TOKEN
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conn = {"base_url": f"http://127.0.0.1:{srv.server_address[1]}",
            "username": "reader", "token": "secret", "skip_tls": True}

    print("it is registered as a platform the UI can offer")
    check("wazuh is in PROVIDERS", "wazuh" in security.PROVIDERS)
    check("and has a normalised fetcher", "wazuh" in security._FULL)
    check("it asks for a user and a password, not a static key",
          security.PROVIDERS["wazuh"]["needs"] == ["base_url", "username", "token"])

    print("a healthy 4.7 server")
    got = security._wazuh(conn)
    check(f"severities are aggregated, got {got['totals']}",
          got["totals"] == {"critical": 1, "high": 1, "medium": 1,
                            "low": 0, "info": 0})
    names = [r["name"] for r in got["products"]]
    check(f"the manager is not listed as an agent, got {names}",
          "manager" not in names)
    # a host that stopped reporting is the finding, and its data is the stalest
    check(f"agents that stopped reporting come first, got {names}",
          names == ["old-01", "db-01", "web-01"])
    check("the connection state is what shows as the chip",
          [r["criticality"] for r in got["products"]]
          == ["never_connected", "disconnected", "active"])
    check(f"findings carry their CVE, got {len(got['findings'])}",
          len(got["findings"]) == 3
          and all(f["cve"].startswith("CVE-") for f in got["findings"]))
    check("severity words are mapped to this portal's own five",
          {f["severity"] for f in got["findings"]} <= set(security.SEVERITIES))
    check("an agent that never checked in reports no scan",
          len(got["scans"]) == 2)
    check("the note says which agents are down", "not reporting" in got["note"])

    print("a 4.8 server, where vulnerabilities left the API")
    # The dangerous outcome is zero, because zero reads as "nothing wrong".
    SERVE_VULNS = False
    security.invalidate()
    got = security._wazuh(conn)
    check("totals are still zero, unavoidably",
          sum(got["totals"].values()) == 0)
    check("but every agent is marked as NOT having known severities",
          all(r["sev_known"] is False for r in got["products"]))
    check("and the note says why, and where to look instead",
          "indexer" in got["note"])
    check("the agents themselves are still reported",
          len(got["products"]) == 3)
    SERVE_VULNS = True

    print("a user who cannot authenticate")
    NO_TOKEN = True
    security.invalidate()
    try:
        security._wazuh(conn)
        check("a missing token raises rather than returning empty", False)
    except security.SecError as e:
        check(f"it says what to fix, got {str(e)[:40]!r}",
              "permission" in str(e) or "token" in str(e))
    NO_TOKEN = False

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
