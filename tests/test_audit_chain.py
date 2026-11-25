#!/usr/bin/env python3
"""The audit log is tamper-evident, and its page filters in SQL.

WHY THIS EXISTS
    The audit trail is the record that says who did what. If it can be edited or
    trimmed without trace, it is decoration, not evidence. Each row is HMAC-linked
    to the one before it (keyed by the portal secret) and a one-row head anchors
    the tip and count. The load-bearing facts:

      1. An untouched log verifies; editing, deleting or reordering ANY row breaks
         the chain from that point.
      2. Deleting the NEWEST rows — which leaves the surviving chain internally
         consistent — is still caught, by the head anchor's count.
      3. The reader filters in SQL: a narrow action older than the page window is
         found (it used to be filtered in Python within the window and missed),
         and paging uses a real OFFSET.
      4. The page gates on the `audit` area, shows the integrity badge, and its
         tiles count exactly what their links then list.

    ./.venv/bin/python tests/test_audit_chain.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("audit-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db                                       # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _seed(n: int, action: str = "login") -> None:
    for i in range(n):
        auth.audit({"email": f"u{i}@t"}, action, f"target-{i}", f"detail {i}",
                   "10.0.0.1")


def main() -> int:
    print("an untouched chain verifies from genesis")
    _seed(20)
    v = auth.verify_audit()
    check("the whole chain is intact", v["ok"] and v["break_id"] is None
          and v["head_ok"])
    check("the head count matches the row count",
          v["total"] == db.one("SELECT COUNT(*) AS n FROM audit")["n"])

    print("editing a row breaks the chain at that row")
    ids = [r["id"] for r in db.q("SELECT id FROM audit ORDER BY id")]
    mid = ids[len(ids) // 2]
    keep = db.one("SELECT detail FROM audit WHERE id=?", (mid,))["detail"]
    db.run("UPDATE audit SET detail='EDITED' WHERE id=?", (mid,))
    v = auth.verify_audit()
    check("an edit is detected at the edited row",
          not v["ok"] and v["break_id"] == mid)
    db.run("UPDATE audit SET detail=? WHERE id=?", (keep, mid))   # restore
    check("restoring the byte restores the chain", auth.verify_audit()["ok"])

    print("deleting a middle row breaks the chain at the next row")
    ids = [r["id"] for r in db.q("SELECT id FROM audit ORDER BY id")]
    victim, nxt = ids[5], ids[6]
    row = db.one("SELECT * FROM audit WHERE id=?", (victim,))
    db.run("DELETE FROM audit WHERE id=?", (victim,))
    v = auth.verify_audit()
    check("a deleted middle row is caught at its successor",
          not v["ok"] and v["break_id"] == nxt)
    # put it back exactly (id preserved) so the chain is whole again
    db.run("INSERT INTO audit (id, at, user, action, target, detail, ip, hash) "
           "VALUES (?,?,?,?,?,?,?,?)",
           (row["id"], row["at"], row["user"], row["action"], row["target"],
            row["detail"], row["ip"], row["hash"]))
    check("reinserting the row byte-for-byte heals the chain",
          auth.verify_audit()["ok"])

    print("reordering two rows breaks the chain")
    a, b = db.q("SELECT * FROM audit ORDER BY id LIMIT 2")
    db.run("UPDATE audit SET detail=? WHERE id=?", (b["detail"], a["id"]))
    db.run("UPDATE audit SET detail=? WHERE id=?", (a["detail"], b["id"]))
    check("swapping two rows' content is caught", not auth.verify_audit()["ok"])
    db.run("UPDATE audit SET detail=? WHERE id=?", (a["detail"], a["id"]))
    db.run("UPDATE audit SET detail=? WHERE id=?", (b["detail"], b["id"]))
    check("undoing the swap heals the chain", auth.verify_audit()["ok"])

    print("deleting the newest rows is caught by the head anchor")
    newest = db.one("SELECT MAX(id) AS m FROM audit")["m"]
    saved = db.one("SELECT * FROM audit WHERE id=?", (newest,))
    db.run("DELETE FROM audit WHERE id=?", (newest,))
    v = auth.verify_audit()
    # the surviving chain is internally consistent, so this is ONLY caught by head
    check("a tail truncation fails head_ok even with an intact body",
          not v["ok"] and not v["head_ok"] and v["break_id"] is None)
    db.run("INSERT INTO audit (id, at, user, action, target, detail, ip, hash) "
           "VALUES (?,?,?,?,?,?,?,?)",
           (saved["id"], saved["at"], saved["user"], saved["action"],
            saved["target"], saved["detail"], saved["ip"], saved["hash"]))
    check("restoring the tail row heals head_ok", auth.verify_audit()["ok"])

    reader()
    page_routes()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


def reader() -> None:
    print("the reader filters in SQL, so nothing is missed by the window")
    # a marker action written FIRST (oldest), then buried under newer rows
    auth.audit({"email": "z@t"}, "zzz_marker", "needle", "the one to find")
    _seed(40)
    found = auth.read_audit(limit=5, action="zzz_marker")
    check("a narrow action older than the window is still found",
          len(found) == 1 and found[0]["target"] == "needle")
    check("count_audit counts the same filter",
          auth.count_audit(action="zzz_marker") == 1)
    # group predicates + severity agree
    auth.audit({"email": "z@t"}, "pod_shell", "box", "shell")
    auth.audit({"email": "z@t"}, "cluster_action_refused", "box", "no")
    check("the refused group catches a *_refused action",
          auth.count_audit(group="refused") >= 1)
    check("the privileged group catches a shell",
          auth.count_audit(group="privileged") >= 1)
    check("severity tones a refusal danger and a shell warn",
          auth.audit_severity("cluster_action_refused") == "danger"
          and auth.audit_severity("pod_shell") == "warn"
          and auth.audit_severity("login") == "ok")
    # a real OFFSET yields distinct pages
    p1 = auth.read_audit(limit=10, offset=0)
    p2 = auth.read_audit(limit=10, offset=10)
    check("paging with OFFSET returns different rows",
          {r["id"] for r in p1}.isdisjoint({r["id"] for r in p2}))


def page_routes() -> None:
    print("the page gates on the audit area, shows the badge and honest tiles")
    from fastapi.testclient import TestClient

    from app import main

    def enrol(email, pw, role):
        uid = auth.create_user(email, "N", pw, role=role)
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
               "email_verified=1 WHERE id=?", ("TESTSECRET", uid))

    def login(c, e, p):
        c.post("/login", data={"email": e, "password": p}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

    enrol("admin@t", "Admin-Pass-Word-42", "admin")
    enrol("nobody@t", "No-Audit-Please-42", "user")
    admin = TestClient(main.app); admin.__enter__(); login(admin, "admin@t", "Admin-Pass-Word-42")
    plain = TestClient(main.app); plain.__enter__(); login(plain, "nobody@t", "No-Audit-Please-42")

    r = admin.get("/admin/audit")
    check(f"an admin sees the audit page ({r.status_code})",
          r.status_code == 200 and "Audit log" in r.text
          and "Chain verified" in r.text and "ex-tiles" in r.text)
    r = plain.get("/admin/audit")
    check("a user without the audit area is denied",
          r.status_code == 403 and "Chain verified" not in r.text)

    v = admin.get("/admin/audit/verify?full=1").json()
    check("the verify endpoint confirms the chain", v.get("ok") is True)
    r = plain.get("/admin/audit/verify")
    check("the verify endpoint is gated too", r.status_code == 403)

    # a tile's number equals the rows its group filter lists
    n = auth.count_audit(group="refused")
    r = admin.get("/admin/audit?group=refused&size=1000")
    shown = r.text.count('class="aud-row')
    check("the refused view lists exactly the refused count",
          n == shown and (n == 0 or "matches" in r.text or "match" in r.text))


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
