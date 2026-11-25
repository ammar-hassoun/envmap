"""Where a test is allowed to write.

WHY THIS EXISTS
    Every test here defaults to a temporary directory but honours
    PORTAL_DATA_DIR so a run can be pointed somewhere on purpose. That courtesy
    cost a real account its second factor: a harness ran with the variable set
    to a live data directory and wrote its fixed TOTP secret, "TESTSECRET",
    over a genuine enrolment. Nothing failed and nothing was logged. The
    authenticator app on somebody's phone simply stopped matching, and the only
    symptom was "the code is wrong even though it is correct" — which is
    indistinguishable from clock drift, a mistyped digit, or a portal bug.

    A test fixture must not be able to do that. So the directory is checked
    before anything is written to it, and one that already holds accounts is
    refused rather than used.

WHY "HOLDS ACCOUNTS" IS THE TEST
    Not the path, and not a name pattern: those can be worked around by
    accident, and a developer's scratch directory is a perfectly good place to
    run against. What matters is whether real people are in it. A fresh
    database has no users, so a legitimate target is either an empty directory
    or one this suite made earlier — both pass, and the one case that would
    destroy something does not.
"""
from __future__ import annotations

import os
import pathlib
import sqlite3
import sys
import tempfile


def _has_accounts(db_path: pathlib.Path) -> int:
    if not db_path.exists():
        return 0
    try:
        c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return c.execute("SELECT count(*) FROM users").fetchone()[0]
        finally:
            c.close()
    except sqlite3.Error:
        # no users table yet, or not a database this suite understands
        return 0


def data_dir(prefix: str) -> str:
    """A directory this test may create and destroy things in.

    Uses PORTAL_DATA_DIR when it is safe, a fresh temporary directory when it
    is unset, and exits loudly when it points somewhere with real accounts in
    it — because carrying on would be the failure, not the refusal.
    """
    want = (os.environ.get("PORTAL_DATA_DIR") or "").strip()
    if not want:
        return tempfile.mkdtemp(prefix=prefix)

    here = pathlib.Path(want).expanduser().resolve()
    n = _has_accounts(here / "portal.db")
    if n:
        sys.exit(
            f"\nRefusing to run: PORTAL_DATA_DIR points at {here}, which "
            f"already holds {n} account{'s' if n != 1 else ''}.\n"
            f"These tests create users and overwrite TOTP secrets, so running "
            f"here would break real sign-ins\nwithout reporting anything. Run "
            f"with PORTAL_DATA_DIR unset, or point it at an empty directory:\n"
            f"    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python {sys.argv[0]}\n")
    return str(here)
