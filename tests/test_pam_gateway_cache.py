#!/usr/bin/env python3
"""A Privileged Access tab never waits on the gateway -- pam.gateway_status.

WHY THIS EXISTS
    Reported from a PAM-only production install: "very slow moving between the
    tabs". Every tab is a full render, and every render asked whether guacd
    answers (a TCP connect with a one-second timeout) twice, and when it did
    not, asked the Kubernetes API for the pod's own Deployment with a
    fifteen-second timeout. Measured with guacd behind a firewall that drops:
    2,046 ms a tab, against 25 ms with guacd answering.

    Proved here, with the network faked so the timings are the code's:
      * the first look pays for the probe once; the tabs after it do not
      * a stale answer is refreshed in the BACKGROUND -- the tab that finds it
        stale is still fast, and the refresh does land
      * saving the gateway settings forgets the answer, so the next look is
        about the new address
      * a "no" is asked again, fresh, before a desktop connection is refused
      * the Deployment lookup behind the "why" uses the short diagnosis
        timeout, not the fifteen seconds an action gets

    ./.venv/bin/python tests/test_pam_gateway_cache.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pamgw-test-")
os.environ.setdefault("PORTAL_PAM", "1")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, pam, selfupdate                # noqa: E402

bad = 0
SLOW = 0.6          # what one silent probe costs here


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


probes = []
answers = {"up": False}


def fake_connect(addr, timeout=None):
    probes.append(addr)
    if answers["up"]:
        class _S:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return _S()
    time.sleep(SLOW)                   # a firewall that drops, not refuses
    raise OSError("timed out")


deploy_calls = []


def fake_state():
    deploy_calls.append(time.monotonic())
    time.sleep(SLOW)                   # an API server that is slow to answer
    return {"how": "unknown", "why": "could not ask"}


def timed_get(c: TestClient, url: str) -> float:
    t0 = time.perf_counter()
    r = c.get(url)
    assert r.status_code == 200, r.status_code
    return time.perf_counter() - t0


REAL_STATE = selfupdate.gateway_state


def main_test() -> int:
    pam.socket.create_connection = fake_connect
    selfupdate.gateway_state = fake_state
    pam.save_config(enabled=True, allow_connect=True, guacd_host="127.0.0.1",
                    guacd_port=4822)
    uid = auth.create_user("gw@pam.test", "G", "Gateway-Cache-Pass-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, email_verified=1 "
           "WHERE id=?", ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "gw@pam.test",
                           "password": "Gateway-Cache-Pass-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    print("the first look pays once, the tabs after it do not")
    getattr(pam, "forget_gateway", lambda: None)()
    probes.clear(); deploy_calls.clear()
    first = timed_get(c, "/pam?sec=targets")
    check(f"the first render asks the gateway once ({len(probes)} probe, "
          f"{len(deploy_calls)} Deployment lookup)",
          len(probes) == 1 and len(deploy_calls) == 1)
    tabs = [timed_get(c, f"/pam?sec={t}")
            for t in ("sessions", "active", "sops", "targets")]
    check(f"four more tabs take {max(tabs) * 1000:.0f} ms at most, not "
          f"{(2 * SLOW + SLOW) * 1000:.0f}", max(tabs) < SLOW / 2)
    check("and asked nothing new", len(probes) == 1 and len(deploy_calls) == 1)

    print("a stale answer is refreshed behind the reader")
    pam.GATEWAY_TTL = 0.3
    time.sleep(0.4)
    t = timed_get(c, "/pam?sec=targets")
    check(f"the tab that finds it stale is still fast ({t * 1000:.0f} ms)",
          t < SLOW / 2)
    deadline = time.monotonic() + 5
    while len(probes) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    check("and the refresh lands in the background", len(probes) >= 2)
    pam.GATEWAY_TTL = 15.0

    print("saving the settings forgets the answer")
    time.sleep(SLOW * 2.5)             # let the background refresh finish
    answers["up"] = True
    pam.save_config(guacd_port=4823)
    before = len(probes)
    ok, why = pam.gateway_status()
    check(f"the next look asks about the new address ({ok}, {why!r})",
          ok and why == "" and len(probes) == before + 1)

    print("a cached 'no' is asked again before a connection is refused")
    answers["up"] = False
    getattr(pam, "forget_gateway", lambda: None)()
    check("the gateway is down", not pam.guacd_reachable())
    answers["up"] = True
    check("the cache still says so", not pam.guacd_reachable())
    check("but a fresh look sees it is back",
          pam.guacd_reachable(fresh=True))

    print("the diagnosis does not wait fifteen seconds")
    seen = {}
    real_api, real_in = selfupdate._api, selfupdate.in_cluster

    def fake_api(path, method="GET", body=None, ctype="", timeout=None):
        seen["timeout"] = timeout
        raise OSError("no route to the API server")
    selfupdate._api = fake_api
    selfupdate.in_cluster = lambda: True
    got = REAL_STATE()
    check(f"the Deployment lookup uses the short timeout ({seen.get('timeout')} s, "
          f"not {selfupdate.TIMEOUT})",
          seen.get("timeout") == selfupdate.DIAG_TIMEOUT < selfupdate.TIMEOUT)
    check("and says it could not tell", got.get("how") == "unknown")
    selfupdate._api, selfupdate.in_cluster = real_api, real_in

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
