#!/usr/bin/env python3
"""Time every page's SERVER-SIDE render, on a copy of real data.

    PORTAL_DATA_DIR=/tmp/speed-data ./.venv/bin/python tests/_speedprobe.py

WHY SERVER-SIDE AND NOT A BROWSER
    A browser number mixes render, transfer, parse and paint, and the pane's
    viewport reporting is unreliable — measured twice already in this repo. The
    question here is "what does this route COST us", and TestClient answers it
    with nothing else in the way. Transfer cost is a separate axis, so the
    probe also reports the HTML size: 150kB re-parsed per navigation was the
    entire perceived lag once before, which is why app.css exists.

WHY IT IS NOT A TEST
    It measures wall-clock, so it cannot assert. A timing assertion on shared
    hardware fails for reasons that have nothing to do with the code — this
    repo already has one test that flakes under load (test_certs). This is a
    tool for a person to read, run before and after a change, and it lives in
    tests/ with an underscore so no runner picks it up.

HONESTY
    Every route that reaches a cluster, a git remote or an API is marked LIVE:
    with no VPN those numbers are timeouts, not costs, and comparing them to
    each other is meaningless. Cold and warm are reported separately because
    almost everything here caches (`_swr`), and the warm number is what
    somebody clicking around actually feels.
"""
from __future__ import annotations

import os
import pathlib
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ.setdefault("PORTAL_SCHEDULER", "0")
import _sandbox                                                # noqa: E402,F401
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main                                 # noqa: E402

# name, path, reaches-the-network
#
# The flag decides which rows are averaged as "local", so getting it wrong
# makes the summary line lie. Timeline and the expiry radar LOOK local — they
# read the portal's own database — but each fans out across every cluster for
# some of its sources, and with no VPN those are the whole cost. Measured per
# source, cold: timeline's build 1095ms, deploy 8153ms, event 18024ms, flow
# 8994ms, scan 13027ms against commit/alert/cert at 0ms; expiry's certificate
# 16985ms against everything else under 6ms. Both were once listed as local,
# and the summary duly reported "slowest local page: timeline 1518ms" — which
# was neither local nor, as it turned out, a real cost (see gather.py).
PAGES = [
    ("landing",          "/",                              False),
    ("timeline",         "/timeline",                       True),
    ("expiry radar",     "/expiry",                         True),
    ("compare",          "/compare",                       False),
    ("clusters list",    "/clusters?sec=all",              True),
    ("clusters overview", "/clusters",                     True),
    ("fleet pods",       "/pods",                          True),
    ("fleet nodes",      "/nodes",                         True),
    ("gitops repos",     "/repos",                         False),
    ("pipelines",        "/pipelines",                     True),
    ("edge & dns",       "/edge",                           True),
    ("certificates",     "/certs",                          True),
    ("gitops",           "/gitops",                         True),
    ("workflows",        "/workflows",                      True),
    ("security",         "/security",                       True),
    ("logs",             "/logs",                           True),
    ("monitoring",       "/monitoring",                     True),
    ("ansible",          "/ansible",                        False),
    ("provisioning",     "/terraform",                      False),
    ("databases",        "/db",                             True),
    ("assets",           "/assets",                         False),
    ("search (empty)",   "/search?q=",                      False),
    ("search (hit)",     "/search?q=api",                   False),
    ("settings hub",     "/settings",                       False),
    ("settings clusters", "/settings/clusters",             False),
    ("settings projects", "/settings/projects",             False),
    ("settings mcp",     "/settings/mcp",                   False),
    ("settings mcp tokens", "/settings/mcp?sec=tokens",     False),
    ("settings users",   "/admin/users",                    False),
    ("audit log",        "/admin/audit",                    False),
    ("about",            "/about",                          False),
]


def main_probe() -> int:
    # Re-runnable on the same data directory: the point of this tool is to be
    # run before and after a change, and the first version created its account
    # unconditionally and died on the second run with a UNIQUE violation.
    row = db.one("SELECT id FROM users WHERE email = ?", ("speed@probe.local",))
    uid = row[0] if row else auth.create_user(
        "speed@probe.local", "Probe", "Speed-Probe-Pw-42", role="admin")
    auth.set_password(uid, "Speed-Probe-Pw-42")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, role='admin', "
           "disabled='' WHERE id=?", ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "speed@probe.local",
                           "password": "Speed-Probe-Pw-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    def once(path):
        t = time.perf_counter()
        r = c.get(path, follow_redirects=True)
        return (time.perf_counter() - t) * 1000, r.status_code, len(r.content)

    rows = []
    for name, path, live in PAGES:
        try:
            cold, code, size = once(path)
            warm = statistics.median(once(path)[0] for _ in range(3))
        except Exception as e:                                 # noqa: BLE001
            rows.append((name, path, live, None, None, None, str(e)[:60]))
            continue
        rows.append((name, path, live, cold, warm, size, code))

    print(f"\n{'page':22} {'cold':>9} {'warm':>9} {'HTML':>9}  status")
    print("-" * 66)
    for name, path, live, cold, warm, size, code in sorted(
            rows, key=lambda r: -(r[4] or 0)):
        if cold is None:
            print(f"{name:22} {'ERROR':>9} {'':>9} {'':>9}  {code}")
            continue
        mark = " LIVE" if live else ""
        print(f"{name:22} {cold:8.0f}ms {warm:8.0f}ms {size/1024:8.0f}K  "
              f"{code}{mark}")
    local = [r for r in rows if not r[2] and r[4]]
    print("-" * 66)
    print(f"local pages only: median warm "
          f"{statistics.median(r[4] for r in local):.0f}ms, "
          f"slowest {max(local, key=lambda r: r[4])[0]} "
          f"{max(r[4] for r in local):.0f}ms")
    print("LIVE = reaches a cluster/API; with no VPN those are timeouts, not "
          "costs.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_probe())
