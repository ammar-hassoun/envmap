#!/usr/bin/env python3
"""Every Bitbucket request must use _bb_auth, not Basic with an absent user.

WHY THIS EXISTS
    _bb_auth() was added so an access token — which carries no user and must be
    sent as Bearer — could be used. The listing path was converted and the
    others were not, so the connection tested green, the pipeline list rendered,
    and then opening a run's log returned 401. Fixing the helper was never
    enough on its own: what mattered was that every call site reached it.

    A blank username makes the old code send `Basic base64(":token")`, which is
    a credential with no user in it. Bitbucket rejects that with 401, and the
    portal could only report what it was told: "check the token and its scopes".
    The token was fine.

    So this walks the real functions with a real userless connection and asserts
    on the header that goes out, rather than trusting a grep for _basic.

    ./.venv/bin/python tests/test_bbauth.py
"""
from __future__ import annotations

import base64
import os
import pathlib
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("bbauth-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ci                                             # noqa: E402

bad = 0
sent: list[tuple[str, dict]] = []

# An access token connection: repo, token, and deliberately no username.
TOKEN = "ATCTT-access-token"
CONN = {"type": "bitbucket", "repo": "example/mock-partners", "token": TOKEN}
REF = "example/mock-partners#{7f8ba2be-9f10-47a6-bb26-c0f4a5f9106f}"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def fake_get(url, headers, verify=True):
    sent.append((url, headers))
    # shapes each caller expects, minimal but not empty — an empty list would
    # let a path return early and never make its request
    if "/steps/" in url or url.endswith("/steps/?pagelen=50"):
        return {"values": [{"uuid": "{step-1}", "name": "build",
                            "state": {"name": "COMPLETED",
                                      "result": {"name": "FAILED"}},
                            "duration_in_seconds": 12}]}
    return {"values": []}


def fake_get_text(url, headers, verify=True):
    sent.append((url, headers))
    return "+ npm ci\nnpm ERR! code E401\n"


def bearer_only(label: str) -> None:
    """Assert the last captured request authenticated as a Bearer token."""
    url, headers = sent[-1]
    auth = headers.get("Authorization", "")
    check(f"{label}: sent no Authorization header at all", bool(auth))
    check(f"{label}: expected Bearer, got {auth.split(' ')[0]!r} — "
          f"{url.split('bitbucket.org')[-1][:48]}",
          auth.startswith("Bearer "))
    check(f"{label}: the token itself is not the one stored",
          auth == f"Bearer {TOKEN}")
    # the specific historical failure: Basic with an empty user
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
        except Exception:                                      # noqa: BLE001
            decoded = "?"
        check(f"{label}: sent a userless Basic credential {decoded!r}", False)


def main() -> int:
    ci._get, ci._get_text = fake_get, fake_get_text            # type: ignore

    print("the pipeline list — the path that was already converted")
    ci._bitbucket(dict(CONN))
    check("it made at least one request", bool(sent))
    bearer_only("listing")

    print("the step strip of one run — opening a failed pipeline")
    jobs = ci.run_jobs(dict(CONN), REF)
    bearer_only("run_jobs")
    check(f"it still parsed the steps, got {len(jobs)}", len(jobs) == 1)

    print("the log of one step — where the 401 was actually seen")
    text = ci._fetch_log(dict(CONN), REF, "{step-1}")
    bearer_only("_fetch_log")
    check("the log came back", "npm ERR!" in text)

    print("the run's uuid reaches the URL, braces and all")
    url = sent[-1][0]
    check(f"uuid missing from {url}", "7f8ba2be-9f10-47a6-bb26-c0f4a5f9106f" in url)

    print("an app password is still Basic — the fix must not break the other kind")
    sent.clear()
    ci._bitbucket({**CONN, "username": "someone@example.com"})
    url, headers = sent[-1]
    auth = headers.get("Authorization", "")
    check(f"expected Basic for a username+token pair, got {auth[:12]!r}",
          auth.startswith("Basic "))
    check("and it carries the username",
          "someone@example.com" in base64.b64decode(auth[6:]).decode())

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
