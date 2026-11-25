#!/usr/bin/env python3
"""The database console's read-only rail cannot be escaped by a multi-statement
query (S13).

The bypass was `SELECT 1; COMMIT; <write>`: the leading SELECT satisfied the
keyword check, the whole string was sent in one round trip, the COMMIT ended
the server's READ ONLY transaction, and the trailing write ran in autocommit —
outside the guarantee. Two halves are tested:

  * the classifier (`split_statements` / `is_txn_control` / `read_mode_refusal`)
    with no database at all — every bypass shape, and the single reads that must
    still be allowed so the fix does not cry wolf;
  * a real engine, when a local PostgreSQL binary is present, started throwaway
    with initdb/pg_ctl (NEVER the demo containers) — proving the write never
    lands however it is disguised.

Run:  PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_db_readonly_multistatement.py
"""
from __future__ import annotations

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("dbro-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import dbconn                                          # noqa: E402

bad = 0


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


# ── 1. the splitter ────────────────────────────────────────────────────────
def test_split() -> None:
    # (sql, pg, expected number of statements)
    cases = [
        ("SELECT 1; COMMIT; INSERT INTO t VALUES (1)", True, 3),
        ("SELECT 1", True, 1),
        ("SELECT 1;", True, 1),
        ("  ;; SELECT 1 ;; ", True, 1),          # stray separators drop out
        ("SELECT ';'", True, 1),                 # ; inside a string literal
        ("SELECT ';' ; DROP TABLE t", True, 2),
        ("SELECT 'a''b;c'", True, 1),            # doubled quote, not a close
        ("SELECT $$a;b$$", True, 1),             # dollar-quoted body
        ("SELECT $tag$x;y$tag$; COMMIT", True, 2),
        ("SELECT 1 -- ; not a split\n", True, 1),      # line comment
        ("SELECT 1 /* ; nested /* ; */ still */", True, 1),   # nested block
        ("SELECT `weird;col` FROM t", False, 1),       # MySQL backtick id
        ("SELECT 'a\\';b'", False, 1),           # MySQL backslash-escaped quote
        ("SELECT e'a\\';b'", True, 1),           # PostgreSQL E'' honours it too
        ("", True, 0),
        ("   ", True, 0),
        ("-- just a comment\n", True, 0),
    ]
    for sql, pg, want in cases:
        got = dbconn.split_statements(sql, pg)
        check(f"split({sql!r}, pg={pg}) -> {want} not {len(got)}: {got}",
              len(got) == want)


# ── 2. transaction-control detection ───────────────────────────────────────
def test_txn_control() -> None:
    for yes in ("COMMIT", "commit", "  ROLLBACK", "BEGIN", "begin work",
                "START TRANSACTION", "START TRANSACTION READ WRITE", "ABORT",
                "END", "SAVEPOINT a", "RELEASE SAVEPOINT a",
                "SET TRANSACTION READ WRITE",
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
                "/* c */ COMMIT"):
        check(f"{yes!r} is transaction-control", dbconn.is_txn_control(yes))
    for no in ("SELECT 1", "SELECT commit FROM t", "WITH x AS (SELECT 1) "
               "SELECT * FROM x", "SET statement_timeout = 0", "BEGINNER",
               "UPDATE t SET x = 1"):
        check(f"{no!r} is not transaction-control",
              not dbconn.is_txn_control(no))


# ── 3. the read-mode gate ──────────────────────────────────────────────────
def test_refusal() -> None:
    # Allowed in read mode: a single read, including one with a semicolon
    # safely inside a string or a dollar-quote.
    for ok in ("SELECT 42", "select 42", "WITH x AS (SELECT 1) SELECT * FROM x",
               "SHOW server_version", "EXPLAIN SELECT 1", "TABLE t",
               "VALUES (1),(2)", "SELECT ';' AS semi", "SELECT $$a;b$$",
               "SELECT 1;"):
        check(f"read mode allows {ok!r}: {dbconn.read_mode_refusal(ok)!r}",
              dbconn.read_mode_refusal(ok) == "")

    # The S13 bypass and its relatives, refused with the multi-statement reason.
    for sql in ("SELECT 1; COMMIT; INSERT INTO t VALUES (1)",
                "SELECT 1; COMMIT",
                "SELECT 1; DELETE FROM t",
                "SELECT 1; SELECT 2"):
        why = dbconn.read_mode_refusal(sql)
        check(f"read mode refuses {sql!r}", why != "")
        check(f"and says why for {sql!r}: {why!r}",
              "one statement at a time" in why)

    # A single transaction-control statement, refused with its own reason.
    why = dbconn.read_mode_refusal("COMMIT")
    check("a lone COMMIT is refused", why != "")
    check(f"with the transaction-control reason: {why!r}",
          "transaction-control" in why)

    # A single write, refused with the switch-to-write-mode reason (unchanged).
    why = dbconn.read_mode_refusal("DELETE FROM customers")
    check("a single DELETE is refused", "read-only mode" in why)
    check("and points at write mode", "write mode" in why)

    # Nothing to run.
    check("an empty read is nothing to run",
          dbconn.read_mode_refusal("   ") == "nothing to run")


# ── 4. a real PostgreSQL, when one is to hand ──────────────────────────────
def _pg_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    # Homebrew keeps versioned binaries off PATH; check the usual roots.
    for root in ("/opt/homebrew/opt", "/usr/local/opt",
                 "/usr/lib/postgresql", "/usr/pgsql"):
        base = pathlib.Path(root)
        if not base.is_dir():
            continue
        for cand in sorted(base.glob(f"**/bin/{name}"), reverse=True):
            if os.access(cand, os.X_OK):
                return str(cand)
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_engine_pg() -> None:
    initdb, pg_ctl = _pg_bin("initdb"), _pg_bin("pg_ctl")
    if not (initdb and pg_ctl):
        print("  SKIP  no local initdb/pg_ctl — the engine section did not run")
        return
    root = tempfile.mkdtemp(prefix="dbro-pg-")
    data = os.path.join(root, "d")
    port = _free_port()
    # Pin the locale: this test runs in harnesses where LANG/LC_* are unset,
    # and initdb refuses to guess one.
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        r = subprocess.run([initdb, "-D", data, "-U", "probe", "--auth=trust",
                            "-E", "UTF8", "--locale=C", "--no-instructions"],
                           capture_output=True, text=True, env=env)
        if r.returncode:
            print(f"  SKIP  initdb failed ({r.stderr.strip()[:80]}) — engine "
                  f"section did not run")
            return
        r = subprocess.run(
            [pg_ctl, "-D", data, "-w", "-l", os.path.join(root, "log"),
             "-o", f"-p {port} -c listen_addresses=127.0.0.1 "
                   f"-c unix_socket_directories={root}", "start"],
            capture_output=True, text=True, env=env)
        if r.returncode:
            print("  SKIP  pg_ctl start failed — engine section did not run")
            return
        server = {"id": "pg-test", "type": "postgres", "host": "127.0.0.1",
                  "port": str(port)}
        creds = {"user": "probe", "password": ""}
        con = dbconn.Console("pg-test", "u", creds["user"], creds["password"],
                             server)
        try:
            con.write = True
            con.run("CREATE TABLE victim (i int)")
            con.write = False

            def count() -> int:
                out = con.run("SELECT count(*) AS n FROM victim")
                return out["rows"][0][0]

            check("the victim table starts empty", count() == 0)

            # The bypass, as a user would type it, against a real server.
            try:
                con.run("SELECT 1; COMMIT; INSERT INTO victim VALUES (1)")
                fail("the multi-statement bypass was NOT refused")
            except dbconn.DBError as e:
                check(f"the bypass is refused with the right reason: {e}",
                      "one statement at a time" in str(e))
            check("and NOTHING was written through the read-only rail",
                  count() == 0)

            # The write still can't ride in via START/COMMIT either.
            for sql in ("BEGIN; INSERT INTO victim VALUES (2); COMMIT",
                        "SELECT 1; INSERT INTO victim VALUES (3)"):
                try:
                    con.run(sql)
                except dbconn.DBError:
                    pass
            check("no disguised write landed", count() == 0)

            # A write hidden inside ONE statement is still caught by the server.
            try:
                con.run("WITH g AS (INSERT INTO victim VALUES (9) RETURNING *) "
                        "SELECT * FROM g")
                fail("a single-statement write was not refused")
            except dbconn.DBError as e:
                check(f"the server refuses the read-only write: {e}",
                      "read-only" in str(e).lower())
            check("still empty after the hidden write", count() == 0)

            # A legitimate single read with a semicolon in a string works.
            out = con.run("SELECT ';' AS semi, 7 AS n")
            check("a semicolon inside a string is a normal read",
                  out["rows"] and out["rows"][0][1] == 7)

            # Write mode genuinely writes (the switch is deliberate).
            con.write = True
            con.run("INSERT INTO victim VALUES (1)")
            con.write = False
            check("write mode could write", count() == 1)
            print("  a real PostgreSQL never saw the trailing write, and write "
                  "mode still works")
        finally:
            con.close()
    finally:
        subprocess.run([pg_ctl, "-D", data, "-m", "immediate", "stop"],
                       capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    test_split()
    test_txn_control()
    test_refusal()
    test_engine_pg()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main())
