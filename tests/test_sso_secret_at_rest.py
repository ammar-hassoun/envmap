#!/usr/bin/env python3
"""The Entra client secret is not in the database file.

Microsoft sign-in's settings were written to the settings table in the clear,
client secret included — the one value that lets anybody holding it complete
the OpenID code exchange as this portal's application. Every copy of
portal.db (the pre-upgrade snapshot, a support export, a backup) carried it.
The store already seals two settings rows for exactly this reason (smtp, the
assistant's key), and the sso row now joins them, with the same one-time
migration for a row written before.

What is checked, and why each:
  * the raw row, and the whole file, no longer hold the secret — not merely
    "the column looks encrypted", which the secretbox test learned is a lie
    SQLite tells when the old plaintext sits in freed pages;
  * Microsoft sign-in still gets it decrypted, driven through the real
    callback with the token endpoint stood in for;
  * saving the settings form without retyping the secret keeps it, because
    the form never echoes it back;
  * an install upgrading with a plaintext row is migrated, file and all, and
    a plaintext row the migration has not reached yet still reads.

    ./.venv/bin/python tests/test_sso_secret_at_rest.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ssoseal-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import auth, db, main, sso, store                     # noqa: E402

bad = 0
SECRET = "ENTRA-SECRET-7c41~not-in-the-file"
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PW = "Sso-Secret-Admin-42"
DATA = pathlib.Path(os.environ["PORTAL_DATA_DIR"])


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def raw_row(dbfile: pathlib.Path) -> str:
    c = sqlite3.connect(f"file:{dbfile}?mode=ro", uri=True)
    try:
        got = c.execute("SELECT value FROM settings WHERE key = 'sso'").fetchone()
        return got[0] if got else ""
    finally:
        c.close()


def file_bytes(dbfile: pathlib.Path) -> bytes:
    """The database as anybody copying the directory would get it — the main
    file and, in WAL mode, the log beside it."""
    out = b""
    for p in (dbfile, dbfile.with_name(dbfile.name + "-wal")):
        if p.exists():
            out += p.read_bytes()
    return out


def admin_client():
    from fastapi.testclient import TestClient
    uid = auth.create_user("sso-admin@test.local", "CI", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "sso-admin@test.local", "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


class _Reply:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


def _id_token(claims: dict) -> str:
    def part(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


def signs_in_with_the_secret(seen: list) -> bool:
    """Drive /login/microsoft and the callback, with Microsoft's token endpoint
    replaced by something that records what it was sent."""
    from fastapi.testclient import TestClient
    auth.create_sso_user("person@test.local", "Person")
    c = TestClient(main.app)
    r = c.get("/login/microsoft", follow_redirects=False)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(
        r.headers.get("location", "")).query)
    state, nonce = q.get("state", [""])[0], q.get("nonce", [""])[0]

    def fake_urlopen(req, timeout=None):
        seen.append((req.full_url, (req.data or b"").decode()))
        return _Reply(json.dumps({"id_token": _id_token({
            "aud": CLIENT, "exp": time.time() + 600, "nonce": nonce,
            "tid": TENANT, "email": "person@test.local", "name": "Person",
            "oid": "o-1"})}).encode())

    real = sso.urlguard.urlopen
    sso.urlguard.urlopen = fake_urlopen
    try:
        r = c.get(f"/auth/microsoft/callback?code=the-code&state={state}",
                  follow_redirects=False)
    finally:
        sso.urlguard.urlopen = real
    # The callback's own verdict: a refused exchange lands on /login with the
    # reason, a completed one goes home and is audited as a Microsoft sign-in.
    return (r.status_code == 303 and r.headers.get("location") == "/"
            and auth.count_audit(action="login_microsoft") == 1)


def main_test() -> int:
    dbfile = DATA / "portal.db"
    c = admin_client()

    print("saved through the form, the secret is not in the file")
    r = c.post("/admin/sso", data={"enabled": "1", "tenant": TENANT,
                                   "client_id": CLIENT,
                                   "client_secret": SECRET},
               follow_redirects=False)
    check(f"the form saves, got {r.status_code}", r.status_code == 303)
    row = raw_row(dbfile)
    check("the row is sealed", row.startswith("enc.v1."))
    check("and does not carry the secret", SECRET not in row)
    check("nor the rest of the settings in the clear", TENANT not in row)
    check("the whole file does not hold it",
          SECRET.encode() not in file_bytes(dbfile))

    print("Microsoft sign-in still gets it, decrypted")
    check("the configuration reads it back",
          sso.config()["client_secret"] == SECRET and sso.ready())
    seen: list = []
    check("a sign-in through the real callback completes",
          signs_in_with_the_secret(seen))
    posted = urllib.parse.parse_qs(seen[-1][1]) if seen else {}
    check(f"and the token endpoint was sent the secret itself, not a sealed "
          f"blob: {posted.get('client_secret')}",
          posted.get("client_secret") == [SECRET]
          and seen[-1][0].startswith("https://login.microsoftonline.com/"))

    print("saving the form without retyping the secret keeps it")
    r = c.post("/admin/sso", data={"enabled": "1", "tenant": TENANT,
                                   "client_id": CLIENT, "client_secret": "",
                                   "auto_create": "on"},
               follow_redirects=False)
    check("the save went through and changed what it was given",
          r.status_code == 303 and sso.config()["auto_create"])
    check("the secret survived it", sso.config()["client_secret"] == SECRET)
    check("still sealed", raw_row(dbfile).startswith("enc.v1.")
          and SECRET not in raw_row(dbfile))
    r = c.post("/admin/sso", data={"keep": "1"}, follow_redirects=False)
    check("and turning the switch off keeps it too",
          not sso.config()["enabled"] and sso.config()["client_secret"] == SECRET)

    print("a row the migration has not reached yet still reads")
    # One replica of a newer version reading a row an older one just wrote, in
    # the clear: unseal passes anything without the prefix straight through.
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('sso', ?)",
           (json.dumps({"enabled": True, "tenant": TENANT, "client_id": CLIENT,
                        "client_secret": "PLAIN-" + SECRET}),))
    store.invalidate()
    check("a plaintext row is read as it is",
          sso.config()["client_secret"] == "PLAIN-" + SECRET)

    print("an older database is migrated, and the old pages go with it")
    old = pathlib.Path(tempfile.mkdtemp(prefix="ssoseal-old-")) / "portal.db"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
    # A row larger than a page, so the rewrite RELOCATES it: its overflow pages
    # go to the free list with the old bytes still in them, and only the
    # VACUUM gets rid of those. Measured on 2 October 2026: a small row — and
    # sixty padding rows around one — is rewritten in place, the plaintext goes
    # whether or not the file is vacuumed, and the check below passed with the
    # VACUUM deleted. This shape fails it.
    con.execute("INSERT INTO settings VALUES ('sso', ?)",
                (json.dumps({"enabled": True, "tenant": TENANT,
                             "client_id": CLIENT, "client_secret": SECRET,
                             "note": "y" * 6000}),))
    con.commit()
    con.close()
    check("the fixture really holds the secret in the clear",
          SECRET.encode() in old.read_bytes())
    # A process of its own, the way an upgrade meets the file: the first start
    # of the new version runs the migration.
    p = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]);"
         "from app import db, sso, store;"
         "print(sso.config()['client_secret']); db.close()", str(ROOT)],
        env={**os.environ, "PORTAL_DATA_DIR": str(old.parent),
             "PORTAL_SCHEDULER": "0"},
        capture_output=True, text=True, timeout=120)
    check(f"the upgraded portal reads the secret back, got "
          f"{p.stdout.strip().splitlines()[-1:] or p.stderr[-300:]}",
          p.returncode == 0 and p.stdout.strip().endswith(SECRET))
    check("the migrated row is sealed", raw_row(old).startswith("enc.v1."))
    check("and no copy of the secret survives anywhere in the file",
          SECRET.encode() not in file_bytes(old))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
