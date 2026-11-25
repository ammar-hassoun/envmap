"""The portal's database: one SQLite file, shared by every module that needs it.

WHY SQLITE, AND WHY ONE FILE
    Four storage mechanisms (a settings document, a users document, an append-only
    audit file, a metrics ring buffer) meant four failure modes, four backup
    stories and — in the case of read-modify-write on JSON — a lost update
    whenever two writers overlapped. One database with transactions removes the
    class of bug entirely.

    SQLite rather than a server: the whole dataset is tens of kilobytes plus an
    inventory, WAL gives concurrent readers alongside a writer, and it is in the
    standard library so the portal still installs with pip alone. The portal is
    already pinned to one volume by its git working copies and its kubeconfig
    files, so a networked database would add an operational burden without
    buying horizontal scale.

STAYING PORTABLE
    Every statement here is standard SQL that Postgres also accepts, so moving
    is a driver change rather than a rewrite. Two rules make that true:
      * no SQLite-only functions in queries — date arithmetic is done in Python
        and passed as a parameter (see assets.warranty cut-offs)
      * `?` placeholders only, translated in one place if the driver ever changes
    The PRAGMA statements below are SQLite setup, not query syntax, and simply
    do not run on another engine.
"""
import os
import sqlite3
import threading

from .paths import DATA

FILE = DATA / "portal.db"
_local = threading.local()
_init_lock = threading.Lock()
_ready = False

# Every table the portal owns. Kept together so a migration is one obvious
# place to look, and additive so an older file gains columns without losing rows.
SCHEMA = [
    # One row, one number: incremented on every settings write. Each process
    # compares it against the revision its cached document was built from —
    # one indexed read per load() — so N replicas sharing a database agree
    # within a request instead of within a cache lifetime. This is the row
    # that makes `replicas: 2` honest.
    """CREATE TABLE IF NOT EXISTS rev (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        n INTEGER NOT NULL DEFAULT 0)""",

    """CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        name TEXT,
        password TEXT,
        role TEXT,
        totp_secret TEXT,
        mfa_enrolled INTEGER DEFAULT 0,
        disabled INTEGER DEFAULT 0,
        created TEXT,
        last_login TEXT)""",
    # `hash` chains each row to the one before it (an HMAC over the row plus the
    # previous hash, keyed by the portal secret) so the log is tamper-evident:
    # editing, deleting or reordering any row breaks the chain from that point.
    # See auth.py for the appender and verifier; existing databases gain the
    # column and are sealed by auth._audit_migrate.
    """CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        user TEXT,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        ip TEXT,
        hash TEXT NOT NULL DEFAULT '')""",
    # One row: the current chain tip and the row count. Deleting the newest
    # entries leaves the surviving chain internally consistent, so this anchor is
    # what makes tail-truncation detectable (the count and tip no longer match).
    """CREATE TABLE IF NOT EXISTS audit_head (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        hash TEXT NOT NULL DEFAULT '',
        n INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action)",
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
]


def connect() -> sqlite3.Connection:
    """A connection for this thread. SQLite objects must not cross threads."""
    global _ready
    c = getattr(_local, "conn", None)
    if c is None:
        fresh = not FILE.exists()
        c = sqlite3.connect(FILE, timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")     # readers never block on a write
        c.execute("PRAGMA busy_timeout=15000")
        c.execute("PRAGMA foreign_keys=ON")
        if fresh:
            os.chmod(FILE, 0o600)               # holds password hashes and secrets
        with _init_lock:
            if not _ready:
                for stmt in SCHEMA:
                    c.execute(stmt)
                _ready = True
        _local.conn = c
    if not _migrated:
        # a module may register its tables after this thread first connected
        _run_migrators(c)
    return c


# Modules that own their own tables register a migrator here rather than adding
# them to SCHEMA, because a table with generated columns (the inventory) needs
# code to build its DDL. Each runs once, on the first connection.
_migrators: list = []
_migrated = False


def register(migrator) -> None:
    """Let a module create and upgrade its own tables inside this database."""
    _migrators.append(migrator)
    global _migrated
    _migrated = False


def q(sql: str, params=()) -> list:
    return connect().execute(sql, params).fetchall()


def one(sql: str, params=()):
    return connect().execute(sql, params).fetchone()


def run(sql: str, params=()) -> None:
    connect().execute(sql, params)


class tx:
    """Transaction context. Several statements that must all land or none.

    Used for anything that would otherwise be a read-modify-write race: the very
    problem that made a JSON document unsafe once more than one writer existed.
    """

    def __enter__(self):
        self.c = connect()
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, exc_type, *_):
        self.c.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def _run_migrators(c: sqlite3.Connection) -> None:
    global _migrated
    with _init_lock:
        if _migrated:
            return
        # Before anything alters the schema: if a different version last wrote
        # this database, copy it. Migrations here are additive and automatic,
        # which means the first thing a new build does is rewrite the only copy
        # of somebody's data, and there is no down-migration to undo it.
        # Imported here rather than at module scope because snapshot reads env,
        # and env must not be pulled in before the data directory is settled.
        try:
            from . import snapshot
            made = snapshot.before_migrations(c)
            if made.startswith("!"):
                print(f"[db] could not take a pre-upgrade backup: {made[1:]}")
            elif made:
                print(f"[db] database copied to {made} before upgrading")
        except Exception as e:                                # noqa: BLE001
            # never fatal: a portal that will not start because a backup failed
            # is a worse outcome than one that starts without a backup
            print(f"[db] pre-upgrade backup skipped: {e}")
        for m in _migrators:
            m(c)
        _migrated = True


def close() -> None:
    c = getattr(_local, "conn", None)
    if c is not None:
        c.close()
        _local.conn = None
