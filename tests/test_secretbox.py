#!/usr/bin/env python3
"""Credentials are not in the database file.

Not "are encrypted in the column" — not in the file. The distinction is the
whole test: sealing a value with an UPDATE leaves the old plaintext in the
pages SQLite marks free, so a database that reads as fully encrypted through
SQL still hands over every token to anybody who runs strings on it. That is
how the first version of this passed its own check and was wrong.

    ./.venv/bin/python tests/test_secretbox.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sqlite3
import sys
import tempfile

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("secretbox-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import db, mailer, secretbox, store                   # noqa: E402

bad = 0
TOKEN = "TOKEN-b7f2c1a9-not-in-the-file"
SMTP_PW = "SMTPPASS-4e1d-not-in-the-file"
LIC = "LICENCEKEY-9c3a-not-in-the-file"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    print("sealing and unsealing")
    check("a sealed value does not contain the plaintext",
          TOKEN not in secretbox.seal(TOKEN))
    check("and it is marked so it can be recognised",
          secretbox.sealed(secretbox.seal(TOKEN)))
    check("it round-trips", secretbox.unseal(secretbox.seal(TOKEN)) == TOKEN)
    check("sealing twice does not double-wrap",
          secretbox.unseal(secretbox.seal(secretbox.seal(TOKEN))) == TOKEN)
    check("empty stays empty", secretbox.seal("") == "")
    # a database written before this existed must keep working, or the upgrade
    # is a portal that cannot read its own settings
    check("plaintext passes through untouched",
          secretbox.unseal("a-value-from-an-older-version")
          == "a-value-from-an-older-version")
    # a wrong key must not take down every page that lists connections
    check("an undecryptable value reads as unset, not as an exception",
          secretbox.unseal("enc.v1.gAAAAABrubbish") == "")

    print("nothing readable reaches the file")
    store.add_conn("sec", "", {"name": "Scanner", "type": "defectdojo",
                               "base_url": "https://x.example", "token": TOKEN})
    mailer.save(host="smtp.example.com", from_addr="a@b.c", password=SMTP_PW)
    # The assistant's model token: a sealed setting, and the third kind of
    # secret this database holds. It replaced the licence key when licensing
    # was removed -- the point of the test is that NOTHING readable reaches
    # the file, so it needs three unrelated secrets, not a particular one.
    store._set_setting("assistant", {"provider": "openai", "token": LIC})
    db.close()

    raw = (pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "portal.db").read_bytes()
    for label, needle in (("a connection token", TOKEN),
                          ("the smtp password", SMTP_PW),
                          ("the assistant token", LIC)):
        check(f"{label} is not in portal.db", needle.encode() not in raw)

    print("and the portal still reads them back")
    check("the connection token", store.all_conns("sec")[0]["token"] == TOKEN)
    check("the smtp password", mailer.settings()["password"] == SMTP_PW)
    check("the assistant token",
          store._setting("assistant").get("token") == LIC)
    check("non-secret fields are untouched",
          store.all_conns("sec")[0]["name"] == "Scanner")

    print("an older database is migrated, and the old pages go with it")
    # The case that matters: a file written before any of this existed. It is
    # not enough to seal the column — VACUUM has to run, or the plaintext the
    # UPDATE replaced is still in the file.
    old = pathlib.Path(tempfile.mkdtemp()) / "portal.db"
    c = sqlite3.connect(old)
    c.execute("CREATE TABLE conns (id TEXT PRIMARY KEY, kind TEXT NOT NULL, "
              "pid TEXT NOT NULL DEFAULT '', ord INTEGER, data TEXT)")
    c.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
    # Enough rows that an UPDATE relocates pages rather than rewriting one in
    # place. With a single tiny row SQLite overwrites it where it sits and the
    # plaintext vanishes whether or not the file is vacuumed — which made the
    # first version of this test pass with VACUUM removed, while a real
    # database with nine connections still leaked every token.
    for i in range(60):
        c.execute("INSERT INTO conns VALUES (?,'sec','',?,?)",
                  (f"c{i}", i, '{"name": "Old %d", "token": "%s-%d", '
                   '"note": "%s"}' % (i, TOKEN, i, "x" * 400)))
    c.execute("INSERT INTO settings VALUES ('smtp', ?)",
              ('{"host": "h", "password": "' + SMTP_PW + '"}',))
    c.commit()
    c.close()
    check("the fixture really does hold plaintext",
          TOKEN.encode() in old.read_bytes())

    os.environ["PORTAL_DATA_DIR"] = str(old.parent)
    for mod in ("app.db", "app.store", "app.paths", "app.env"):
        sys.modules.pop(mod, None)
    import importlib
    paths = importlib.import_module("app.paths")
    importlib.reload(paths)
    db2 = importlib.reload(importlib.import_module("app.db"))
    store2 = importlib.reload(importlib.import_module("app.store"))
    secretbox.reset()
    store2.load()
    db2.close()

    after = old.read_bytes()
    check("no token survives anywhere in the migrated file",
          TOKEN.encode() not in after)
    check("and so is the smtp password", SMTP_PW.encode() not in after)
    rows = sqlite3.connect(old).execute("SELECT data FROM conns").fetchall()
    check(f"and every row is sealed ({len(rows)} of them)",
          rows and all(r[0].startswith("enc.v1.") for r in rows))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
