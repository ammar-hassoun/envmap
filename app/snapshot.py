"""A copy of the database, taken before a new version can change it.

WHY THIS EXISTS
    Migrations here are additive and run automatically at startup, which is
    what makes `helm upgrade` a one-liner. It also means the first thing a new
    build does is rewrite the schema of the only copy of a customer's data.
    There is no down-migration, so `helm rollback` puts old code against a new
    schema — probably survivable, never tested, and not something to discover
    on somebody else's cluster at four in the afternoon.

    So: before the migrations for a version that has not run against this
    database before, take a copy.

WHY ON VERSION CHANGE RATHER THAN EVERY START
    A pod restarts for all sorts of reasons — a node drain, a liveness blip, an
    OOM kill. Copying a database on each of those fills the volume with
    identical files and buries the one copy that matters. The version that last
    opened this database is recorded in it; a copy is taken when that differs
    from the version now starting, which is exactly the upgrade case.

WHY sqlite3's OWN BACKUP API
    Not `cp`. The database runs in WAL mode, so a file copy taken while
    anything is writing can land mid-transaction and produce a file that opens
    but is missing the last commits — the worst kind of backup, the one that
    looks fine. The backup API copies pages under a read lock and produces a
    consistent database.
"""
from __future__ import annotations

import datetime as dt
import sqlite3

from . import env

# Enough to cover a bad upgrade and the one before it, without letting a volume
# fill with copies of a database nobody will ever roll back that far.
KEEP = 5


def _dir():
    return env.DATA_DIR / "backups"


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def taken() -> list[dict]:
    """Newest first, for the deployment page."""
    out = []
    for f in sorted(_dir().glob("portal-*.db"), reverse=True):
        try:
            st = f.stat()
        except OSError:
            continue
        # portal-<iso>-from-<version>.db
        rest = f.stem[len("portal-"):]
        frm = rest.split("-from-", 1)[1] if "-from-" in rest else ""
        out.append({
            "name": f.name, "size": _fmt(st.st_size), "from_version": frm,
            "when": dt.datetime.fromtimestamp(st.st_mtime)
                      .strftime("%Y-%m-%d %H:%M"),
            "path": str(f),
        })
    return out


def _prune() -> None:
    for f in sorted(_dir().glob("portal-*.db"), reverse=True)[KEEP:]:
        try:
            f.unlink()
        except OSError:
            pass


def before_migrations(conn: sqlite3.Connection) -> str:
    """Copy the database if a different version last wrote it. Returns the path.

    Called with the connection the migrations are about to run on, before they
    run. Any failure is swallowed deliberately: a portal that will not start
    because it could not write a backup is a worse outcome than one that starts
    without one, and the reason is returned so the caller can log it.
    """
    conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    row = conn.execute("SELECT v FROM meta WHERE k = 'version'").fetchone()
    was = (row[0] if row else "") or ""
    now = env.VERSION or ""

    made = ""
    # A first run has nothing worth copying — the database is empty — and an
    # unchanged version is a restart, not an upgrade.
    if was and was != now:
        try:
            _dir().mkdir(parents=True, exist_ok=True)
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in was)
            target = _dir() / f"portal-{stamp}-from-{safe}.db"
            with sqlite3.connect(target) as out:
                conn.backup(out)          # consistent under WAL, unlike a copy
            target.chmod(0o600)
            made = str(target)
            _prune()
        except (sqlite3.Error, OSError) as e:
            return f"!{e}"

    if was != now:
        conn.execute("INSERT INTO meta (k, v) VALUES ('version', ?) "
                     "ON CONFLICT(k) DO UPDATE SET v = excluded.v", (now,))
    return made
