"""Database servers: registered without credentials, opened with them.

WHY A REGISTERED SERVER HOLDS NO USERNAME AND NO PASSWORD
    Every other connection in this portal stores a token, because the portal
    reads those systems on a schedule with nobody watching. A database is not
    that. A stored database password is a credential that outlives the person
    who typed it, is shared by everyone with a portal login, and turns one
    stolen session into permanent access to production data.

    So a registered server is a host, a port and a name — enough to list, not
    enough to reach. The operator supplies a username and password when they
    open the console; those live in memory, keyed to their session, and are
    gone when the session ends or the process restarts. Nothing to steal from
    the database file, and no credential the portal can use on its own.

    The cost is honest and worth naming: there is no background collection for
    databases, no scheduled inventory, no alerting. A page shows what it can
    see at the moment somebody is looking at it, with their own permissions.

WHY A CONSOLE KEEPS ITS CONNECTION OPEN
    Measured against a database 50 ms away, opening a connection cost 627 ms —
    TCP, then TLS, then authentication, each its own round trip. The first
    version opened three of them per page and ran the overview as thirteen
    separate statements, so changing tab took 3.1 seconds.

    A console now holds its connections open for as long as it is signed in,
    at most FANOUT of them (one per database, least recently used closed
    first), and the overview is one statement instead of thirteen. Changing
    tab costs one round trip, or none when the answer is still fresh.

    Holding server-side connections is a real cost and is bounded on purpose:
    they close when the operator signs out, when the console goes an hour
    unused, and when the portal stops.

HOW READ-ONLY IS ENFORCED
    Not by inspecting the SQL. Parsing statements to decide whether they write
    is a losing game — comments, dollar-quoting, CTEs that end in a DELETE, a
    function that writes as a side effect. Both engines can be told to refuse
    writes themselves:

        PostgreSQL    BEGIN READ ONLY
        MySQL         START TRANSACTION READ ONLY

    The server rejects the write, so the guarantee holds no matter what was
    typed. A keyword check runs first as well, purely to give a clear message
    before a statement is sent rather than a driver error afterwards.

    Write mode is the same code path without the read-only transaction, and is
    switched on per session by an explicit act that is written to the audit log
    along with every statement run inside it.

TESTING A SERVER WITHOUT CREDENTIALS
    A connection can still be verified: both protocols say something before
    they ask who you are. PostgreSQL answers an SSLRequest with a single byte
    telling you whether TLS is offered; MySQL opens with a greeting packet that
    carries the server version. That is enough to prove something on that port
    speaks the protocol, which is what "test" is really being asked.
"""
from __future__ import annotations

import re
import secrets
import socket
import ssl
import struct
import threading
import time

TIMEOUT = 10                # probing and connecting
QUERY_TIMEOUT = 30          # a statement, enforced by the server
MAX_ROWS = 500              # rows returned to a browser
IDLE = 60 * 60              # a console unused this long is forgotten
FANOUT = 4                  # open connections one console may hold at once
FRESH = 20                  # seconds an overview or database list stays fresh
PAGE = 100                  # rows per page when browsing a table

PROVIDERS = {
    "postgres": {
        "label": "PostgreSQL",
        "icon": "🐘",
        "url_hint": "db.example.com",
        "needs": ["host"],
        "auth": "nothing stored — each operator signs in with their own "
                "database account when they open the console",
        "fields": {"host": "Host or address", "port": "Port (5432)",
                   "database": "Default database (optional)"},
        "note": "Registered by host and port only. No username and no password "
                "are kept: whoever opens the console types their own, they are "
                "held for that session and never written to disk. Works with "
                "anything speaking the PostgreSQL protocol — Aurora, Cloud SQL, "
                "Timescale, CockroachDB.",
        "reads": "databases, schemas, tables, roles, activity",
        "default_port": 5432,
    },
    "mysql": {
        "label": "MySQL / MariaDB",
        "icon": "🐬",
        "url_hint": "db.example.com",
        "needs": ["host"],
        "auth": "nothing stored — each operator signs in with their own "
                "database account when they open the console",
        "fields": {"host": "Host or address", "port": "Port (3306)",
                   "database": "Default database (optional)"},
        "note": "Registered by host and port only. No username and no password "
                "are kept: whoever opens the console types their own, they are "
                "held for that session and never written to disk. MariaDB, "
                "Percona and RDS all speak the same protocol.",
        "reads": "schemas, tables, users, processes",
        "default_port": 3306,
    },
    # Not a SQL server, and it does not open a SQL console. It is registered
    # here because "a database this estate runs" is where an operator looks for
    # it, and because the registration, the reachability test and the
    # credentials-at-the-console rule are identical. `engine` is what tells the
    # rest of the portal to hand it to app/cbase.py instead of Console.
    "couchbase": {
        "label": "Couchbase",
        "icon": "🛋",
        "engine": "couchbase",
        "url_hint": "cb01.example.com",
        "needs": ["host"],
        "auth": "nothing stored — each operator signs in with their own "
                "Couchbase account when they open the console",
        "fields": {"host": "Host or address", "port": "Admin port (8091)",
                   "query_port": "Query port (8093, for SQL++)"},
        "note": "Managed over the REST API, so no SDK is installed and no "
                "credentials are kept: whoever opens the console types their "
                "own Couchbase account. Shows the cluster and its nodes, "
                "buckets and their statistics, XDCR, indexes, and runs SQL++. "
                "Creating a bucket needs write mode; flush and delete are "
                "deliberately not offered here. Server 4.x is supported — "
                "scopes, collections and cluster users appear only on the "
                "versions that have them, and say so on the ones that do not.",
        "reads": "cluster, nodes, buckets, XDCR, indexes, SQL++",
        "default_port": 8091,
    },
}

# Offered by the editor's completion. Not a dialect reference — the words an
# operator types often enough that finishing them is worth the keystrokes.
KEYWORDS = [
    "SELECT", "FROM", "WHERE", "GROUP BY", "ORDER BY", "HAVING", "LIMIT",
    "OFFSET", "JOIN", "LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "FULL JOIN",
    "CROSS JOIN", "ON", "AS", "AND", "OR", "NOT", "IN", "EXISTS", "BETWEEN",
    "LIKE", "ILIKE", "IS NULL", "IS NOT NULL", "CASE", "WHEN", "THEN", "ELSE",
    "END", "WITH", "UNION", "UNION ALL", "INTERSECT", "EXCEPT", "DISTINCT",
    "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "NULLIF", "CAST",
    "EXTRACT", "NOW", "CURRENT_DATE", "CURRENT_TIMESTAMP", "DATE_TRUNC",
    "ROW_NUMBER", "RANK", "DENSE_RANK", "OVER", "PARTITION BY", "LATERAL",
    "INSERT INTO", "VALUES", "UPDATE", "SET", "DELETE FROM", "RETURNING",
    "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "CREATE INDEX", "TRUNCATE",
    "BEGIN", "COMMIT", "ROLLBACK", "EXPLAIN", "EXPLAIN ANALYZE", "ANALYZE",
    "VACUUM", "GRANT", "REVOKE", "ASC", "DESC",
]


class DBError(Exception):
    """Anything the operator should read as a sentence, not a stack trace."""


def invalidate() -> None:
    """Part of the connection contract. Nothing about a database is cached
    across consoles: every page is a live query with the viewer's own
    credentials, and what little is cached lives on the console itself."""


def port_of(conn: dict) -> int:
    try:
        p = int(str(conn.get("port") or "").strip())
    except ValueError:
        p = 0
    return p or PROVIDERS.get(conn.get("type", ""), {}).get("default_port", 0)


def label(conn: dict) -> str:
    return f"{conn.get('host', '?')}:{port_of(conn)}"


# ── reachability, with no credentials ──────────────────────────
def _probe_postgres(host: str, port: int) -> str:
    """Ask whether TLS is offered. The reply is one byte and needs no login."""
    with socket.create_connection((host, port), TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(struct.pack("!ii", 8, 80877103))     # SSLRequest
        reply = s.recv(1)
    if reply == b"S":
        return "PostgreSQL protocol, TLS offered"
    if reply == b"N":
        return "PostgreSQL protocol, TLS not offered"
    if reply == b"E":
        raise DBError("the server refused the connection before authentication")
    raise DBError("that port did not answer as PostgreSQL")


def _probe_mysql(host: str, port: int) -> str:
    """Read the greeting. MySQL sends its version before asking anything."""
    with socket.create_connection((host, port), TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        head = s.recv(4)
        if len(head) < 4:
            raise DBError("that port closed the connection without a greeting")
        length = head[0] | (head[1] << 8) | (head[2] << 16)
        body = s.recv(min(length, 512))
    if not body or body[0] == 0xFF:
        raise DBError("the server refused the connection — often too many "
                      "failed attempts from this address")
    version = body[1:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return f"MySQL protocol, server reports {version}" if version else "MySQL protocol"


def test(conn: dict) -> tuple[bool, str]:
    host = (conn.get("host") or "").strip()
    port = port_of(conn)
    if not host:
        return False, "no host"
    if not port:
        return False, "no port"
    # Imported here, not at module scope: cbase imports this module for the
    # error type and the port helper, and doing it the other way round at
    # import time is a cycle.
    if conn.get("type") == "couchbase":
        from . import cbase
        return cbase.test(conn)
    try:
        if conn.get("type") == "postgres":
            note = _probe_postgres(host, port)
        elif conn.get("type") == "mysql":
            note = _probe_mysql(host, port)
        else:
            return False, "unknown database type"
    except DBError as e:
        return False, str(e)
    except socket.timeout:
        return False, f"no answer from {host}:{port} within {TIMEOUT}s"
    except OSError as e:
        return False, f"cannot reach {host}:{port} — {e.strerror or e}"
    except Exception as e:                                     # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    return True, f"reachable — {note}. Credentials are asked for at the console."


# ── connecting ─────────────────────────────────────────────────
def connect(conn: dict, creds: dict, database: str = ""):
    """A live DBAPI connection. The caller closes it.

    TLS is opportunistic on both engines: encrypted when the server offers it,
    plain when it does not. Certificates are not verified, and that is stated
    rather than dressed up — the portal has nowhere to put a CA bundle for a
    database yet, and claiming verification it does not do would be worse than
    the honest note on the settings page. These are connections to a server
    inside the customer's own network, made by an operator who is looking at
    the result.
    """
    host, port = (conn.get("host") or "").strip(), port_of(conn)
    dbname = (database or conn.get("database") or "").strip()
    kind = conn.get("type")
    try:
        if kind == "postgres":
            import psycopg
            return psycopg.connect(
                host=host, port=port, user=creds["user"],
                password=creds["password"], dbname=dbname or "postgres",
                connect_timeout=TIMEOUT, autocommit=True, sslmode="prefer",
                application_name="config-portal")
        if kind == "mysql":
            return _mysql_connect(host, port, dbname, creds)
    except DBError:
        raise
    except Exception as e:                                     # noqa: BLE001
        raise DBError(_friendly(e)) from e
    raise DBError("unknown database type")


def _mysql_connect(host: str, port: int, dbname: str, creds: dict):
    """PyMySQL has no "prefer": TLS is either demanded or not attempted. So
    demand it, and fall back once if the server has none — which is what
    sslmode=prefer does for PostgreSQL, spelled out."""
    import pymysql
    common = dict(host=host, port=port, user=creds["user"],
                  password=creds["password"], database=dbname or None,
                  connect_timeout=TIMEOUT, read_timeout=QUERY_TIMEOUT + 5,
                  autocommit=True, charset="utf8mb4")
    plain = ssl.create_default_context()
    plain.check_hostname = False
    plain.verify_mode = ssl.CERT_NONE
    try:
        return pymysql.connect(ssl=plain, **common)
    except Exception as e:                                     # noqa: BLE001
        # Only a TLS-shaped failure is worth a second attempt. Retrying a
        # rejected password without encryption would send it again in clear.
        if "ssl" not in str(e).lower() and "tls" not in str(e).lower():
            raise DBError(_friendly(e)) from e
    try:
        return pymysql.connect(**common)
    except Exception as e:                                     # noqa: BLE001
        raise DBError(_friendly(e)) from e


def _friendly(e: Exception) -> str:
    """Driver errors say true things in an unhelpful register."""
    text = str(e).strip() or type(e).__name__
    low = text.lower()
    if "password authentication failed" in low or "access denied" in low:
        return "the username or password was not accepted"
    if "does not exist" in low and "database" in low:
        return text.split("\n")[0]
    if "timeout" in low or "timed out" in low:
        return "the server did not answer in time"
    if "connection refused" in low:
        return "nothing is listening on that host and port"
    if "no pg_hba.conf entry" in low:
        return ("the server is refusing connections from this address for that "
                "user — its pg_hba.conf has no matching rule")
    return text.split("\n")[0][:300]


def _dead(e: Exception) -> bool:
    """Whether this looks like the connection went away rather than the
    statement being wrong. Only these are worth reconnecting for."""
    name = type(e).__name__
    if name in ("InterfaceError", "OperationalError", "AdminShutdown",
                "ConnectionTimeout", "BrokenPipeError"):
        return True
    low = str(e).lower()
    return any(s in low for s in ("server closed", "connection already closed",
                                  "connection is closed", "lost connection",
                                  "broken pipe", "gone away", "eof detected"))


def _uptime(seconds) -> str:
    """224 days 02:36:08 is a wall of digits in a tile. 224d 2h is a duration."""
    try:
        secs = int(float(seconds or 0))
    except (TypeError, ValueError):
        return ""
    if secs <= 0:
        return ""
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {rem // 60}m"
    return f"{rem // 60}m"


# ── the console ────────────────────────────────────────────────
class Console:
    """One operator, one server, for as long as they are signed in.

    Holds the credentials, the open connections and the small amount that is
    worth not asking twice. Every method is serialised by one lock: two
    requests from the same browser must not share a cursor, and the cost of
    the lock is nothing next to the round trip it guards.
    """

    def __init__(self, cid: str, uid: str, user: str, password: str,
                 server: dict):
        self.cid, self.uid, self.user = cid, uid, user
        self._password = password
        self.server = dict(server)
        self.write = False
        self.opened = self.used = time.time()
        self.history: list[dict] = []
        self._lock = threading.RLock()
        self._conns: dict[str, object] = {}       # database -> connection
        self._order: list[str] = []               # least recently used first
        self._cache: dict[str, tuple[float, object]] = {}
        self._timed: set[str] = set()

    # ── connections ────────────────────────────────────────────
    @property
    def creds(self) -> dict:
        return {"user": self.user, "password": self._password}

    def _key(self, database: str) -> str:
        return (database or self.server.get("database") or "").strip()

    def _conn(self, database: str):
        key = self._key(database)
        c = self._conns.get(key)
        if c is not None:
            return c
        c = connect(self.server, self.creds, key)
        self._conns[key] = c
        self._order.append(key)
        while len(self._order) > FANOUT:
            self._drop(self._order[0])
        return c

    def _drop(self, key: str) -> None:
        c = self._conns.pop(key, None)
        self._timed.discard(key)
        if key in self._order:
            self._order.remove(key)
        if c is not None:
            try:
                c.close()
            except Exception:                                  # noqa: BLE001
                pass

    def _touch(self, key: str) -> None:
        if key in self._order:
            self._order.remove(key)
            self._order.append(key)

    def cursor(self, database: str = ""):
        """A cursor on the held connection, reconnecting once if it died.

        Reusing a connection means inheriting whatever state the last statement
        left. A statement that failed inside a transaction leaves PostgreSQL
        refusing everything until a rollback, so every path here ends in one.
        """
        key = self._key(database)
        try:
            c = self._conn(database)
            self._touch(key)
            return c, c.cursor()
        except DBError:
            raise
        except Exception as e:                                 # noqa: BLE001
            if not _dead(e):
                raise DBError(_friendly(e)) from e
        self._drop(key)
        try:
            c = self._conn(database)
            return c, c.cursor()
        except DBError:
            raise
        except Exception as e:                                 # noqa: BLE001
            raise DBError(_friendly(e)) from e

    def _settle(self, c) -> None:
        try:
            c.rollback()
        except Exception:                                      # noqa: BLE001
            pass

    def close(self) -> None:
        with self._lock:
            for key in list(self._conns):
                self._drop(key)
            self._cache.clear()
            self._password = ""

    def open_connections(self) -> int:
        return len(self._conns)

    # ── caching ────────────────────────────────────────────────
    def _cached(self, key: str, make, fresh: float = FRESH, force: bool = False):
        hit = self._cache.get(key)
        if hit and not force and time.time() - hit[0] < fresh:
            return hit[1]
        got = make()
        self._cache[key] = (time.time(), got)
        return got

    def forget(self, prefix: str = "") -> None:
        with self._lock:
            for k in [k for k in self._cache if not prefix or k.startswith(prefix)]:
                self._cache.pop(k, None)

    # ── the things the pages ask for ───────────────────────────
    def overview(self, database: str = "", force: bool = False) -> dict:
        with self._lock:
            return self._cached(f"ov:{self._key(database)}",
                                lambda: self._overview(database), force=force)

    def databases(self, force: bool = False) -> list[dict]:
        with self._lock:
            return self._cached("dbs", self._databases, force=force)

    def tables(self, database: str, force: bool = False) -> list[dict]:
        with self._lock:
            return self._cached(f"tb:{self._key(database)}",
                                lambda: self._tables(database), force=force)

    def schema_map(self, database: str, force: bool = False) -> dict:
        with self._lock:
            return self._cached(f"sm:{self._key(database)}",
                                lambda: self._schema_map(database),
                                fresh=300, force=force)

    def roles(self) -> list[dict]:
        with self._lock:
            return self._roles()

    def activity(self) -> list[dict]:
        with self._lock:
            return self._activity()

    def locks(self) -> list[dict]:
        with self._lock:
            return self._locks()

    def table(self, database: str, schema: str, name: str) -> dict:
        with self._lock:
            return self._table(database, schema, name)

    def rows(self, database: str, schema: str, name: str, page: int = 1,
             order: str = "", desc: bool = False) -> dict:
        with self._lock:
            return self._rows(database, schema, name, page, order, desc)

    def run(self, sql: str, database: str = "", limit: int = MAX_ROWS,
            explain: bool = False) -> dict:
        with self._lock:
            out = self._run(sql, database, limit, explain)
        self.remember(sql, database, out)
        return out

    def _hint(self, message: str, database: str) -> str:
        """"relation does not exist" is technically true and unhelpfully so.

        Nine times out of ten the table is there under a different case:
        PostgreSQL folded the unquoted name to lower case and looked for
        something nobody created. If a table exists whose name matches apart
        from case, say so and say what to type instead.
        """
        low = message.lower()
        if "does not exist" not in low and "doesn't exist" not in low:
            return message
        m = re.search(r'"([^"]+)"', message)
        if not m:
            return message
        wanted = m.group(1).split(".")[-1].strip().lower()
        try:
            known = self._cache.get(f"sm:{self._key(database)}")
            tables = (known[1] if known else self.schema_map(database))["tables"]
        except Exception:                                      # noqa: BLE001
            return message
        for t in tables:
            if t["name"].lower() == wanted and t["name"] != wanted:
                return (f'{message} — but "{t["name"]}" does. This server folds '
                        f'an unquoted name to lower case, so it has to be typed '
                        f'as {t["insert"]}.')
        return message

    def _explained(self, sql: str) -> str:
        """Wrap a statement in the right EXPLAIN for this engine.

        ANALYZE is what makes a plan worth reading — estimated rows next to
        actual rows is how you see the planner being wrong. It also *runs* the
        statement, so it is only used where a write cannot happen: in read-only
        mode the transaction forbids one. With write mode on, the plan is the
        estimate alone rather than executing an UPDATE to describe it.
        """
        if self.server.get("type") == "postgres":
            if self.write:
                return f"EXPLAIN (VERBOSE, FORMAT TEXT) {sql}"
            return f"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT TEXT) {sql}"
        return f"EXPLAIN FORMAT=TREE {sql}"

    def remember(self, sql: str, database: str, out: dict | None,
                 error: str = "") -> None:
        """The last statements this console ran. In memory with everything
        else, so it disappears at sign-out — a query history is a record of
        what somebody was looking at, and it should not outlive them."""
        with self._lock:
            self.history.insert(0, {
                "sql": sql.strip(), "database": database, "at": time.time(),
                "ms": (out or {}).get("ms", 0), "error": error,
                "rows": len((out or {}).get("rows", [])) if out else 0})
            del self.history[40:]

    # ── implementations ────────────────────────────────────────
    def _open_txn(self, cur, database: str, pg: bool, write: bool) -> None:
        """Start the transaction the statement will run in, in as few round
        trips as the engine allows.

        Against a database 50 ms away each of these is 50 ms, and the first
        version spent four of them on setup before the query itself had been
        sent. PostgreSQL takes the mode on BEGIN and accepts both statements in
        one send; MySQL cannot, so its statement timeout is set once per
        connection instead of once per query.
        """
        if pg:
            cur.execute(("BEGIN" if write else "BEGIN READ ONLY") +
                        f"; SET LOCAL statement_timeout = {QUERY_TIMEOUT * 1000}")
            return
        key = self._key(database)
        if key not in self._timed:
            try:
                cur.execute("SET SESSION max_execution_time = %s",
                            (QUERY_TIMEOUT * 1000,))
            except Exception:                                  # noqa: BLE001
                pass          # MariaDB spells it differently; not worth failing
            self._timed.add(key)
        cur.execute("START TRANSACTION" if write
                    else "START TRANSACTION READ ONLY")

    def _q(self, database: str, sql: str, args=None, read_only: bool = True):
        """One statement, one round trip, always leaving the connection clean."""
        c, cur = self.cursor(database)
        try:
            # No arguments means no argument parsing. Passing an empty tuple
            # still puts the driver into placeholder mode, and a catalogue
            # query full of LIKE 'pg\\_%' is then read as a broken format
            # string — which is exactly how the one-statement overview came to
            # fail silently into the slow path.
            cur.execute(sql, args) if args else cur.execute(sql)
            return cur.fetchall() if cur.description else []
        except Exception as e:                                 # noqa: BLE001
            self._settle(c)
            if _dead(e):
                self._drop(self._key(database))
            raise DBError(_friendly(e)) from e
        finally:
            self._settle(c)

    _PG_OVERVIEW = """
        SELECT version(), current_database(), current_user,
          (SELECT count(*) FROM pg_database WHERE NOT datistemplate),
          (SELECT count(*) FROM pg_roles),
          (SELECT count(*) FROM pg_namespace
             WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'),
          (SELECT count(*) FROM pg_class c JOIN pg_namespace n
             ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p')
             AND n.nspname NOT IN ('pg_catalog','information_schema')),
          (SELECT count(*) FROM pg_stat_activity),
          (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'),
          pg_size_pretty(pg_database_size(current_database())),
          extract(epoch FROM now() - pg_postmaster_start_time())::bigint,
          pg_is_in_recovery(),
          (SELECT date_trunc('second', max(now() - query_start))::text
             FROM pg_stat_activity WHERE state = 'active')"""

    _MY_OVERVIEW = """
        SELECT version(), database(), current_user(),
          (SELECT count(*) FROM information_schema.schemata WHERE schema_name
             NOT IN ('information_schema','performance_schema','mysql','sys')),
          (SELECT count(DISTINCT user) FROM mysql.user),
          (SELECT count(*) FROM information_schema.schemata WHERE schema_name
             NOT IN ('information_schema','performance_schema','mysql','sys')),
          (SELECT count(*) FROM information_schema.tables
             WHERE table_type = 'BASE TABLE' AND table_schema
             NOT IN ('information_schema','performance_schema','mysql','sys')),
          (SELECT count(*) FROM information_schema.processlist),
          @@max_connections,
          (SELECT concat(round(sum(data_length+index_length)/1024/1024, 1), ' MB')
             FROM information_schema.tables WHERE table_schema
             NOT IN ('information_schema','performance_schema','mysql','sys')),
          (SELECT variable_value FROM performance_schema.global_status
             WHERE variable_name = 'Uptime'),
          @@read_only,
          (SELECT concat(max(time), ' s') FROM information_schema.processlist
             WHERE command <> 'Sleep')"""

    _FIELDS = ("version", "current", "user", "databases", "roles", "schemas",
               "tables", "connections", "max_connections", "size", "_uptime",
               "replica", "longest")

    # ── export ─────────────────────────────────────────────────
    def export_targets(self, database: str) -> dict:
        """What can be exported: the schemas, and the tables inside them."""
        out: dict = {}
        for t in self.schema_map(database)["tables"]:
            out.setdefault(t["schema"], []).append(t["name"])
        return {k: sorted(v) for k, v in sorted(out.items())}

    def _ddl_pg(self, database: str, schema: str, table: str) -> list[str]:
        cols = self._q(database, """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod),
                   a.attnotnull,
                   pg_get_expr(d.adbin, d.adrelid)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
            WHERE n.nspname = %s AND c.relname = %s
              AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY a.attnum""", (schema, table))
        if not cols:
            return [], []
        lines = []
        for name, typ, notnull, default in cols:
            piece = f"  {ident('postgres', name)} {typ}"
            if default is not None:
                piece += f" DEFAULT {default}"
            if notnull:
                piece += " NOT NULL"
            lines.append(piece)
        # pg_get_constraintdef renders the constraint exactly as the server
        # would, which is far safer than reassembling one from catalogue rows
        cons = self._q(database, """
            SELECT conname, pg_get_constraintdef(ct.oid)
            FROM pg_constraint ct
            JOIN pg_class c ON c.oid = ct.conrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relname = %s
            ORDER BY ct.contype DESC, conname""", (schema, table))
        later = []
        for name, definition in cons:
            # A foreign key inline means the referenced table must already
            # exist, which makes the whole dump order-dependent — and tables
            # come out alphabetically, not topologically. Held back and added
            # at the end, where every table exists whatever the order.
            if definition.upper().startswith("FOREIGN KEY"):
                later.append(
                    f"ALTER TABLE {qualified('postgres', schema, table)} "
                    f"ADD CONSTRAINT {ident('postgres', name)} {definition};")
                continue
            lines.append(f"  CONSTRAINT {ident('postgres', name)} {definition}")
        body = ",\n".join(lines)
        out = [f"CREATE TABLE {qualified('postgres', schema, table)} (\n{body}\n);"]
        # indexes come after, and the ones backing a constraint are already
        # covered by the constraint itself
        idx = self._q(database, """
            SELECT indexdef FROM pg_indexes
            WHERE schemaname = %s AND tablename = %s
              AND indexname NOT IN (
                SELECT conname FROM pg_constraint ct
                JOIN pg_class c ON c.oid = ct.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s)
            ORDER BY indexname""", (schema, table, schema, table))
        out += [f"{d};" for (d,) in idx]
        return out, later

    def _ddl_my(self, database: str, schema: str, table: str) -> list[str]:
        # MySQL will hand over the exact statement it would use itself, which
        # beats anything reassembled from information_schema
        got = self._q(database, f"SHOW CREATE TABLE "
                                f"{qualified('mysql', schema, table)}")
        if not got or len(got[0]) < 2:
            return [], []
        # left exactly as MySQL wrote it: an unqualified name is what makes
        # `mysql targetdb < dump.sql` restore where you point it
        return [f"{got[0][1]};"], []

    def ddl(self, database: str, schema: str, table: str):
        """(statements to run now, statements to run after every table)."""
        pg = self.server.get("type") == "postgres"
        try:
            return self._ddl_pg(database, schema, table) if pg \
                else self._ddl_my(database, schema, table)
        except DBError as e:
            return [f"-- could not read the definition of {schema}.{table}: {e}"], []

    def _sequences_pg(self, database: str, schemas) -> tuple[list, list]:
        """(create statements, setval statements) for the schemas being dumped.

        A serial column's default is nextval() on a sequence, so a dump without
        the sequences produces a CREATE TABLE that refuses to run — which is
        how the first version of this failed the moment it was restored rather
        than merely read.
        """
        if not schemas:
            return [], []
        marks = ", ".join(["%s"] * len(schemas))
        try:
            rows = self._q(database, f"""
                SELECT schemaname, sequencename, start_value, increment_by,
                       last_value
                FROM pg_sequences WHERE schemaname IN ({marks})
                ORDER BY 1, 2""", tuple(schemas))
        except DBError as e:
            return [f"-- could not read the sequences: {e}"], []
        create, restore = [], []
        for sch, name, start, step, last in rows:
            full = qualified("postgres", sch, name)
            create.append(f"CREATE SEQUENCE IF NOT EXISTS {full} "
                          f"START WITH {start} INCREMENT BY {step};")
            if last is not None:
                # true: the next value must come after this one, not equal it
                restore.append(f"SELECT setval('{full}', {last}, true);")
        return create, restore

    def _stream(self, database: str, schema: str, table: str):
        """Rows, in batches, inside the console's read-only transaction.

        fetchmany rather than fetchall: a table of a few million rows must not
        be assembled in memory before the first byte reaches the browser.
        """
        kind = self.server.get("type")
        pg = kind == "postgres"
        with self._lock:
            c, cur = self.cursor(database)
            try:
                self._open_txn(cur, database, pg, write=False)
                cur.execute(f"SELECT * FROM {qualified(kind, schema, table)}")
                names = [d[0] for d in (cur.description or [])]
                while True:
                    got = cur.fetchmany(BATCH)
                    if not got:
                        break
                    yield names, got
            except Exception as e:                             # noqa: BLE001
                raise DBError(_friendly(e)) from e
            finally:
                self._settle(c)

    def export_all(self, data: bool = True, drop: bool = False):
        """Every database on the server, one dump at a time.

        Yields (filename, chunks) so the caller can put each in its own file
        rather than concatenating them. One combined .sql would mean editing
        SQL by hand to restore a single database out of it, and on a server
        where one database is 290 MB it would mean a file nobody can open.

        A database that cannot be read does not stop the rest: it comes out as
        a short file saying why, which is a far more useful thing to find in
        the archive than a missing name nobody notices.
        """
        pg = self.server.get("type") == "postgres"
        for entry in self.databases():
            name = entry.get("name") or ""
            if not name:
                continue
            # PostgreSQL always has these and nobody wants them backed up; on
            # MySQL the system schemas are already filtered out of the listing
            if pg and name in ("template0", "template1", "rdsadmin"):
                continue
            safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in name)
            yield f"{safe}.sql", self._one_db(name, data, drop, pg)

    def _one_db(self, name: str, data: bool, drop: bool, pg: bool):
        """One database's dump, or the reason there isn't one."""
        try:
            if pg:
                yield from self.export(name, data=data, drop=drop)
            else:
                # a MySQL "database" is a schema of the connection we hold
                yield from self.export("", schema=name, data=data, drop=drop)
        except DBError as e:
            yield (f"-- {name} could not be read: {e}\n"
                   f"-- The account this console is signed in as may not be "
                   f"able to connect to it.\n")

    def export(self, database: str, schema: str = "", tables=None,
               data: bool = True, drop: bool = False):
        """The dump, a chunk of text at a time.

        A generator so the response streams: the browser starts saving while
        the database is still being read, and nothing is held whole in memory.
        """
        kind = self.server.get("type")
        pg = kind == "postgres"
        lit = _lit_pg if pg else _lit_my
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        chosen = self.export_targets(database)
        if schema:
            chosen = {schema: chosen.get(schema, [])}
        if tables:
            want = set(tables)
            chosen = {s: [t for t in ts if f"{s}.{t}" in want or t in want]
                      for s, ts in chosen.items()}
            chosen = {s: ts for s, ts in chosen.items() if ts}

        n_tables = sum(len(v) for v in chosen.values())
        yield (f"-- {label(self.server)} · {database or self.server.get('database','')}\n"
               f"-- exported {stamp} by {self.user} through the portal\n"
               f"-- {n_tables} table(s), {'structure and data' if data else 'structure only'}\n"
               "--\n"
               "-- A logical export, not a physical backup. It does NOT include\n"
               "-- roles, grants, triggers, functions or extensions, and it is\n"
               "-- read table by table rather than from a\n"
               "-- single frozen snapshot, so rows written while it ran may be\n"
               "-- inconsistent between tables. For a restorable backup of a\n"
               "-- production server, use pg_dump or mysqldump on the server.\n\n")
        if not n_tables:
            yield "-- nothing matched the selection\n"
            return
        if not pg:
            yield "SET FOREIGN_KEY_CHECKS=0;\n\n"

        deferred: list[str] = []
        seq_restore: list[str] = []
        if pg:
            create, seq_restore = self._sequences_pg(database, sorted(chosen))
            if create:
                yield "-- sequences the column defaults below depend on\n"
                yield "\n".join(create) + "\n"

        for sch in sorted(chosen):
            for tbl in chosen[sch]:
                full = _target(kind, sch, tbl)
                yield f"\n-- ─────────── {sch}.{tbl}\n"
                if drop:
                    yield f"DROP TABLE IF EXISTS {full};\n"
                statements, later = self.ddl(database, sch, tbl)
                deferred += later
                for statement in statements:
                    yield statement + "\n"
                if not data:
                    continue
                try:
                    n = 0
                    for names, batch in self._stream(database, sch, tbl):
                        cols = ", ".join(ident(kind, c) for c in names)
                        values = ",\n  ".join(
                            "(" + ", ".join(lit(v) for v in row) + ")"
                            for row in batch)
                        yield f"INSERT INTO {full} ({cols}) VALUES\n  {values};\n"
                        n += len(batch)
                    yield f"-- {n} row(s)\n"
                except DBError as e:
                    # one unreadable table must not abandon the whole export
                    yield f"-- could not read rows from {sch}.{tbl}: {e}\n"
        if seq_restore:
            yield ("\n-- sequences moved past the rows just inserted, so the "
                   "next\n-- insert does not collide with an existing key\n")
            yield "\n".join(seq_restore) + "\n"
        if deferred:
            yield ("\n-- foreign keys, added once every table exists so the "
                   "order\n-- the tables were written in cannot matter\n")
            yield "\n".join(deferred) + "\n"
        if not pg:
            yield "\nSET FOREIGN_KEY_CHECKS=1;\n"
        yield f"\n-- end of export, {stamp}\n"


    def _overview(self, database: str) -> dict:
        """One statement rather than thirteen. If the account cannot see one of
        the subqueries the whole thing fails, so fall back to asking separately
        — slower, but it degrades a field at a time instead of the page."""
        pg = self.server.get("type") == "postgres"
        try:
            row = self._q(database, self._PG_OVERVIEW if pg else self._MY_OVERVIEW)[0]
            out = dict(zip(self._FIELDS, row))
        except DBError:
            out = self._overview_piecemeal(database)
        out["engine"] = PROVIDERS[self.server["type"]]["label"]
        out["version"] = (str(out.get("version") or "").split(" on ")[0])[:90]
        out["uptime"] = _uptime(out.pop("_uptime", 0))
        out["replica"] = bool(out.get("replica"))
        out["current"] = out.get("current") or self._key(database)
        return out

    def _overview_piecemeal(self, database: str) -> dict:
        pg = self.server.get("type") == "postgres"
        whole = (self._PG_OVERVIEW if pg else self._MY_OVERVIEW).strip()
        # split the one statement back into its parts, so there is one list of
        # expressions to maintain rather than two that can drift
        parts, depth, cur = [], 0, ""
        for ch in whole[len("SELECT"):]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        parts.append(cur)
        out = {}
        for name, expr in zip(self._FIELDS, parts):
            try:
                got = self._q(database, f"SELECT {expr.strip()}")
                out[name] = got[0][0] if got else None
            except DBError:
                out[name] = None
        return out

    def _databases(self) -> list[dict]:
        if self.server.get("type") == "postgres":
            rows = self._q("", """
                SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba),
                  CASE WHEN has_database_privilege(d.datname, 'CONNECT')
                       THEN pg_size_pretty(pg_database_size(d.datname))
                       ELSE '—' END,
                  pg_encoding_to_char(d.encoding)
                FROM pg_database d WHERE NOT d.datistemplate ORDER BY 1""")
        else:
            rows = self._q("", """
                SELECT s.schema_name, '',
                  coalesce(concat(round(sum(t.data_length+t.index_length)
                    /1024/1024, 1), ' MB'), '0 MB'),
                  s.default_character_set_name
                FROM information_schema.schemata s
                LEFT JOIN information_schema.tables t
                  ON t.table_schema = s.schema_name
                WHERE s.schema_name NOT IN ('information_schema',
                  'performance_schema','mysql','sys')
                GROUP BY s.schema_name, s.default_character_set_name ORDER BY 1""")
        return [{"name": r[0], "owner": r[1] or "", "size": r[2] or "",
                 "encoding": r[3] or ""} for r in rows]

    def _tables(self, database: str) -> list[dict]:
        """Tables and views, largest first. Row counts are the planner's
        estimate, not count(*) — an exact count on a large table is a scan, and
        a listing page should not start one."""
        if self.server.get("type") == "postgres":
            rows = self._q(database, """
                SELECT n.nspname, c.relname,
                  CASE WHEN c.reltuples < 0 THEN 0 ELSE c.reltuples::bigint END,
                  pg_size_pretty(pg_total_relation_size(c.oid)),
                  pg_total_relation_size(c.oid),
                  CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialised'
                       WHEN 'p' THEN 'partitioned' WHEN 'f' THEN 'foreign'
                       ELSE 'table' END
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind IN ('r','p','v','m','f')
                  AND n.nspname NOT IN ('pg_catalog','information_schema')
                ORDER BY 5 DESC, 2 LIMIT 2000""")
        else:
            rows = self._q(database, """
                SELECT table_schema, table_name, coalesce(table_rows, 0),
                  concat(round((data_length+index_length)/1024/1024, 1), ' MB'),
                  coalesce(data_length+index_length, 0),
                  CASE table_type WHEN 'VIEW' THEN 'view' ELSE 'table' END
                FROM information_schema.tables
                WHERE table_schema = %s ORDER BY 5 DESC, 2 LIMIT 2000""",
                           (self._key(database),))
        kind = self.server.get("type")
        return [{"schema": r[0], "name": r[1], "rows": int(r[2] or 0),
                 "size": r[3] or "", "kind": r[5],
                 "q": qualified(kind, r[0], r[1])} for r in rows]

    def _schema_map(self, database: str) -> dict:
        """Every table and its columns, in one statement, for the editor's
        completion. Kept longer than the other caches: it is the largest answer
        here and the one least likely to change while somebody types."""
        if self.server.get("type") == "postgres":
            rows = self._q(database, """
                SELECT n.nspname, c.relname, a.attname,
                       format_type(a.atttypid, a.atttypmod)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_attribute a ON a.attrelid = c.oid
                  AND a.attnum > 0 AND NOT a.attisdropped
                WHERE c.relkind IN ('r','p','v','m','f')
                  AND n.nspname NOT IN ('pg_catalog','information_schema')
                ORDER BY 1, 2, a.attnum LIMIT 40000""")
        else:
            rows = self._q(database, """
                SELECT table_schema, table_name, column_name, column_type
                FROM information_schema.columns WHERE table_schema = %s
                ORDER BY table_schema, table_name, ordinal_position
                LIMIT 40000""", (self._key(database),))
        kind = self.server.get("type")
        tables: dict[tuple, list] = {}
        for schema, table, col, typ in rows:
            tables.setdefault((schema, table), []).append(
                {"name": col, "type": typ, "insert": ident(kind, col)})
        # `qualified` is what is shown, `insert` is what is typed into the
        # editor. They differ exactly when the name needs quoting, and offering
        # a completion that cannot run is worse than offering none.
        return {"tables": [{"qualified": f"{sch}.{tbl}", "schema": sch,
                            "name": tbl, "columns": cols,
                            "insert": qualified(kind, sch, tbl),
                            "insert_name": ident(kind, tbl)}
                           for (sch, tbl), cols in tables.items()],
                "keywords": KEYWORDS}

    def _roles(self) -> list[dict]:
        if self.server.get("type") == "postgres":
            rows = self._q("", """
                SELECT rolname, rolsuper, rolcreatedb, rolcanlogin,
                  coalesce(rolvaliduntil::text, '')
                FROM pg_roles ORDER BY rolsuper DESC, rolname LIMIT 300""")
            return [{"name": r[0], "super": bool(r[1]), "createdb": bool(r[2]),
                     "login": bool(r[3]), "until": r[4]} for r in rows]
        rows = self._q("", """
            SELECT user, host, super_priv = 'Y', create_priv = 'Y',
              account_locked = 'N', coalesce(password_expired, '')
            FROM mysql.user ORDER BY super_priv DESC, user LIMIT 300""")
        return [{"name": f"{r[0]}@{r[1]}", "super": bool(r[2]),
                 "createdb": bool(r[3]), "login": bool(r[4]),
                 "until": "expired" if r[5] == "Y" else ""} for r in rows]

    def _activity(self) -> list[dict]:
        if self.server.get("type") == "postgres":
            rows = self._q("", """
                SELECT pid, coalesce(usename,''), coalesce(datname,''),
                  coalesce(state,''), coalesce(client_addr::text,'local'),
                  coalesce(date_trunc('second', now()-query_start)::text,''),
                  coalesce(left(query, 300), ''),
                  coalesce(wait_event_type || ':' || wait_event, '')
                FROM pg_stat_activity WHERE pid <> pg_backend_pid()
                ORDER BY query_start NULLS LAST LIMIT 200""")
        else:
            rows = self._q("", """
                SELECT id, user, coalesce(db,''), command, host,
                  concat(time, ' s'), coalesce(left(info, 300), ''), state
                FROM information_schema.processlist
                WHERE id <> connection_id() ORDER BY time DESC LIMIT 200""")
        return [{"pid": r[0], "user": r[1], "db": r[2], "state": r[3],
                 "client": r[4], "for": r[5], "query": (r[6] or "").strip(),
                 "waiting": r[7] or ""} for r in rows]

    def _locks(self) -> list[dict]:
        """Who is blocking whom. The question a locked-up database raises, and
        the one that is tedious to answer by hand in either engine."""
        if self.server.get("type") == "postgres":
            rows = self._q("", """
                SELECT w.pid, coalesce(w.usename,''), coalesce(w.datname,''),
                  coalesce(date_trunc('second', now()-w.query_start)::text,''),
                  coalesce(left(w.query,200),''),
                  b.pid, coalesce(b.usename,''), coalesce(left(b.query,200),''),
                  coalesce(w.wait_event_type || ':' || w.wait_event, '')
                FROM pg_stat_activity w
                JOIN LATERAL unnest(pg_blocking_pids(w.pid)) AS bp(pid) ON true
                JOIN pg_stat_activity b ON b.pid = bp.pid
                WHERE cardinality(pg_blocking_pids(w.pid)) > 0 LIMIT 100""")
            return [{"pid": r[0], "user": r[1], "db": r[2], "for": r[3],
                     "query": r[4], "by_pid": r[5], "by_user": r[6],
                     "by_query": r[7], "waiting": r[8]} for r in rows]
        rows = self._q("", """
            SELECT r.trx_mysql_thread_id, r.trx_query, b.trx_mysql_thread_id,
                   b.trx_query, w.requesting_engine_lock_id
            FROM performance_schema.data_lock_waits w
            JOIN information_schema.innodb_trx r
              ON r.trx_id = w.requesting_engine_transaction_id
            JOIN information_schema.innodb_trx b
              ON b.trx_id = w.blocking_engine_transaction_id LIMIT 100""")
        return [{"pid": r[0], "user": "", "db": "", "for": "",
                 "query": r[1] or "", "by_pid": r[2], "by_user": "",
                 "by_query": r[3] or "", "waiting": "lock"} for r in rows]

    def _table(self, database: str, schema: str, name: str) -> dict:
        """Everything about one table: columns, keys, indexes, constraints."""
        pg = self.server.get("type") == "postgres"
        if pg:
            cols = self._q(database, """
                SELECT a.attname, format_type(a.atttypid, a.atttypmod),
                  a.attnotnull,
                  coalesce(pg_get_expr(d.adbin, d.adrelid), ''),
                  coalesce(col_description(a.attrelid, a.attnum), ''),
                  EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = a.attrelid
                          AND i.indisprimary AND a.attnum = ANY(i.indkey))
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid
                  AND d.adnum = a.attnum
                WHERE n.nspname = %s AND c.relname = %s
                  AND a.attnum > 0 AND NOT a.attisdropped
                ORDER BY a.attnum""", (schema, name))
            columns = [{"name": r[0], "type": r[1], "nullable": not r[2],
                        "default": r[3], "comment": r[4], "pk": bool(r[5])}
                       for r in cols]
            indexes = [{"name": r[0], "definition": r[1], "size": r[2]}
                       for r in self._q(database, """
                SELECT i.relname, pg_get_indexdef(x.indexrelid),
                       pg_size_pretty(pg_relation_size(x.indexrelid))
                FROM pg_index x
                JOIN pg_class i ON i.oid = x.indexrelid
                JOIN pg_class t ON t.oid = x.indrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = %s AND t.relname = %s
                ORDER BY i.relname""", (schema, name))]
            constraints = [{"name": r[0], "definition": r[1], "kind": r[2]}
                           for r in self._q(database, """
                SELECT con.conname, pg_get_constraintdef(con.oid),
                  CASE con.contype WHEN 'p' THEN 'primary key'
                       WHEN 'f' THEN 'foreign key' WHEN 'u' THEN 'unique'
                       WHEN 'c' THEN 'check' ELSE con.contype::text END
                FROM pg_constraint con
                JOIN pg_class c ON c.oid = con.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s
                ORDER BY con.contype, con.conname""", (schema, name))]
            meta = self._q(database, """
                SELECT pg_size_pretty(pg_total_relation_size(c.oid)),
                  CASE WHEN c.reltuples < 0 THEN 0 ELSE c.reltuples::bigint END,
                  coalesce(obj_description(c.oid), ''),
                  CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialised'
                       WHEN 'p' THEN 'partitioned' ELSE 'table' END
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s""", (schema, name))
        else:
            cols = self._q(database, """
                SELECT column_name, column_type, is_nullable = 'YES',
                  coalesce(column_default, ''), coalesce(column_comment, ''),
                  column_key = 'PRI'
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position""", (schema, name))
            columns = [{"name": r[0], "type": r[1], "nullable": bool(r[2]),
                        "default": r[3], "comment": r[4], "pk": bool(r[5])}
                       for r in cols]
            indexes = [{"name": r[0], "definition": r[1], "size": ""}
                       for r in self._q(database, """
                SELECT index_name, concat(if(non_unique = 0, 'UNIQUE ', ''),
                       '(', group_concat(column_name ORDER BY seq_in_index), ')')
                FROM information_schema.statistics
                WHERE table_schema = %s AND table_name = %s
                GROUP BY index_name, non_unique ORDER BY index_name""",
                                        (schema, name))]
            constraints = [{"name": r[0], "definition": r[1], "kind": r[2]}
                           for r in self._q(database, """
                SELECT k.constraint_name,
                  concat('(', group_concat(k.column_name ORDER BY
                    k.ordinal_position), ') REFERENCES ',
                    coalesce(max(k.referenced_table_name), ''), ' (',
                    coalesce(group_concat(k.referenced_column_name ORDER BY
                      k.ordinal_position), ''), ')'),
                  'foreign key'
                FROM information_schema.key_column_usage k
                WHERE k.table_schema = %s AND k.table_name = %s
                  AND k.referenced_table_name IS NOT NULL
                GROUP BY k.constraint_name""", (schema, name))]
            meta = self._q(database, """
                SELECT concat(round((data_length+index_length)/1024/1024,1),' MB'),
                  coalesce(table_rows, 0), coalesce(table_comment, ''),
                  if(table_type = 'VIEW', 'view', 'table')
                FROM information_schema.tables
                WHERE table_schema = %s AND table_name = %s""", (schema, name))
        if not columns:
            raise DBError(f"{schema}.{name} is not there, or not visible to "
                          f"{self.user}")
        m = meta[0] if meta else ("", 0, "", "table")
        return {"schema": schema, "name": name, "columns": columns,
                "q": qualified(self.server.get("type"), schema, name),
                "indexes": indexes, "constraints": constraints,
                "size": m[0], "rows": int(m[1] or 0), "comment": m[2],
                "kind": m[3], "ddl": _ddl(pg, schema, name, columns, constraints)}

    def _rows(self, database: str, schema: str, name: str, page: int,
              order: str, desc: bool) -> dict:
        """A page of a table. Identifiers are quoted from what the server
        itself reported, never interpolated from the URL: the column to sort by
        is matched against the real column list and dropped if it is not one."""
        page = max(1, int(page or 1))
        cols = [c["name"] for c in self._table(database, schema, name)["columns"]]
        q = _quote(self.server.get("type"))
        target = f"{q(schema)}.{q(name)}"
        clause = ""
        if order and order in cols:
            clause = f" ORDER BY {q(order)}{' DESC' if desc else ''}"
        sql = (f"SELECT * FROM {target}{clause} "
               f"LIMIT {PAGE + 1} OFFSET {(page - 1) * PAGE}")
        c, cur = self.cursor(database)
        started = time.time()
        try:
            self._open_txn(cur, database,
                           self.server.get("type") == "postgres", False)
            cur.execute(sql)
            names = [d[0] for d in (cur.description or [])]
            got = cur.fetchall()
        except Exception as e:                                 # noqa: BLE001
            self._settle(c)
            raise DBError(_friendly(e)) from e
        finally:
            self._settle(c)
        more = len(got) > PAGE
        return {"columns": names, "rows": [list(r) for r in got[:PAGE]],
                "page": page, "more": more, "order": order, "desc": desc,
                "ms": int((time.time() - started) * 1000),
                "schema": schema, "table": name, "all_columns": cols}

    def _run(self, sql: str, database: str, limit: int,
             explain: bool = False) -> dict:
        sql = (sql or "").strip().rstrip(";").strip()
        if not sql:
            raise DBError("nothing to run")
        # The mode check is on what was typed, not on the EXPLAIN wrapper —
        # otherwise every statement would look like a read because EXPLAIN is
        # one, and a read-only console would happily plan a DELETE.
        if not self.write and not looks_like_read(sql):
            raise DBError("this console is in read-only mode. Switch it to "
                          "write mode to run a statement that changes data — "
                          "the switch is recorded, and so is every statement "
                          "run after it.")
        pg = self.server.get("type") == "postgres"
        sent = self._explained(sql) if explain else sql
        c, cur = self.cursor(database)
        started = time.time()
        try:
            self._open_txn(cur, database, pg, self.write and not explain)
            try:
                try:
                    cur.execute(sent)
                except Exception:                              # noqa: BLE001
                    # FORMAT=TREE only arrived in MySQL 8.0.16, and older
                    # servers and MariaDB answer the plain form instead
                    if not (explain and not pg):
                        raise
                    self._settle(c)
                    self._open_txn(cur, database, pg, False)
                    sent = f"EXPLAIN {sql}"
                    cur.execute(sent)
                cols = [d[0] for d in (cur.description or [])]
                rows, more = [], False
                if cols:
                    got = cur.fetchmany(limit + 1)
                    more = len(got) > limit
                    rows = [list(r) for r in got[:limit]]
                affected = -1 if cols else (cur.rowcount if cur.rowcount is not None else -1)
                if self.write and not explain:
                    c.commit()
                else:
                    c.rollback()
            except Exception as e:                             # noqa: BLE001
                self._settle(c)
                if _dead(e):
                    self._drop(self._key(database))
                raise DBError(self._hint(_friendly(e), database)) from e
            out = {"columns": cols, "rows": rows, "truncated": more,
                   "affected": affected, "plan": "",
                   "ms": int((time.time() - started) * 1000),
                   "wrote": bool(self.write and not explain and affected >= 0)}
            if explain:
                # A plan is one long piece of text, not a table of one-column
                # rows. Both engines hand it over a line at a time.
                out["plan"] = "\n".join(str(r[0]) for r in rows if r)
                out["columns"], out["rows"] = [], []
            return out
        finally:
            if not self.write:
                self._settle(c)


def _quote(kind: str):
    if kind == "mysql":
        return lambda s: "`" + str(s).replace("`", "``") + "`"
    return lambda s: '"' + str(s).replace('"', '""') + '"'


# A name that is not all-lowercase, or that collides with a keyword, has to be
# quoted or the server will not find it. PostgreSQL folds an unquoted
# identifier to lower case, so a table created as "Admins" is reachable only as
# "Admins" — SELECT * FROM public.Admins looks for public.admins and fails.
# This bit the completion: it offered the true name and the query it produced
# could not run.
_PLAIN = re.compile(r"^[a-z_][a-z0-9_$]*$")
_RESERVED = {
    "all", "and", "any", "array", "as", "asc", "both", "case", "cast", "check",
    "collate", "column", "constraint", "default", "desc", "distinct", "do",
    "else", "end", "except", "false", "for", "foreign", "from", "grant",
    "group", "having", "in", "initially", "intersect", "into", "is", "join",
    "leading", "like", "limit", "not", "null", "offset", "on", "only", "or",
    "order", "placing", "primary", "references", "returning", "select", "some",
    "symmetric", "table", "then", "to", "trailing", "true", "union", "unique",
    "user", "using", "variadic", "when", "where", "window", "with",
}


def needs_quoting(name: str) -> bool:
    n = str(name or "")
    return not _PLAIN.match(n) or n in _RESERVED


def ident(kind: str, name: str) -> str:
    """A name as it must be typed to work — quoted only when it has to be, so
    ordinary lower-case names stay readable."""
    return _quote(kind)(name) if needs_quoting(name) else str(name)


def qualified(kind: str, schema: str, name: str) -> str:
    return f"{ident(kind, schema)}.{ident(kind, name)}"


def _ddl(pg: bool, schema: str, name: str, columns: list, constraints: list) -> str:
    """A CREATE TABLE assembled from what the server reported.

    Neither engine hands out the original text — MySQL's SHOW CREATE TABLE
    comes closest but needs a second round trip and a different parse per
    engine. This is built from the catalogue, so it says what the table is now
    rather than what somebody typed, which is usually the more useful answer.
    """
    q = (lambda s: '"' + s + '"') if pg else (lambda s: "`" + s + "`")
    lines = []
    for c in columns:
        bit = f"  {q(c['name'])} {c['type']}"
        if not c["nullable"]:
            bit += " NOT NULL"
        if c["default"]:
            bit += f" DEFAULT {c['default']}"
        lines.append(bit)
    for con in constraints:
        lines.append(f"  CONSTRAINT {q(con['name'])} {con['definition']}")
    body = ",\n".join(lines)
    return f"CREATE TABLE {q(schema)}.{q(name)} (\n{body}\n);"


# ── the credential vault ───────────────────────────────────────
# In memory, never on disk, never in the session cookie. The cookie carries a
# random ticket; this maps a ticket to the console it unlocks. A restart empties
# it, which is the intended behaviour and not a bug to work around: nobody
# should be able to use a database account nobody has typed since the portal
# started.
_VAULT: dict[str, Console] = {}
_vault_lock = threading.Lock()

# Unique to this process. The browser keeps a ticket in its cookie but the
# credentials it names live only here, so a restart invalidates every ticket
# ever issued. Stamping the session with this lets the console tell "the portal
# restarted" apart from "you signed out" or "it went an hour unused" — three
# very different things that all used to show the same unexplained login box.
BOOT = secrets.token_hex(8)


def _reap(now: float) -> None:
    for t in [t for t, s in _VAULT.items() if now - s.used > IDLE]:
        _VAULT.pop(t).close()


def open_console(cid: str, uid: str, user: str, password: str,
                 server: dict | None = None) -> str:
    """Hold one operator's credentials for one server. Returns the ticket."""
    ticket = secrets.token_urlsafe(24)
    now = time.time()
    with _vault_lock:
        _reap(now)
        _VAULT[ticket] = Console(cid, uid, user, password, server or {"id": cid})
    return ticket


def console(ticket: str, cid: str, uid: str) -> Console | None:
    """The open console, or None. Bound to both the server and the person: a
    ticket lifted from one session is useless in another."""
    now = time.time()
    with _vault_lock:
        _reap(now)
        s = _VAULT.get(ticket or "")
        if not s or s.cid != cid or s.uid != uid:
            return None
        s.used = now
        return s


def session_of(s: Console) -> dict:
    """A console as a plain dict, for templates and for the checks that only
    care about who and what, not about the connections underneath."""
    return {"cid": s.cid, "uid": s.uid, "user": s.user, "write": s.write,
            "opened": s.opened, "used": s.used,
            "connections": s.open_connections()}


def session(ticket: str, cid: str, uid: str) -> dict | None:
    s = console(ticket, cid, uid)
    return session_of(s) if s else None


def set_write(ticket: str, on: bool) -> None:
    with _vault_lock:
        if ticket in _VAULT:
            _VAULT[ticket].write = bool(on)


def close_console(ticket: str) -> None:
    with _vault_lock:
        s = _VAULT.pop(ticket or "", None)
    if s:
        s.close()


def forget_server(cid: str) -> None:
    """Deleting a registered server drops every open console against it."""
    with _vault_lock:
        gone = [_VAULT.pop(t) for t, s in list(_VAULT.items()) if s.cid == cid]
    for s in gone:
        s.close()


def open_count(cid: str = "") -> int:
    now = time.time()
    with _vault_lock:
        _reap(now)
        return sum(1 for s in _VAULT.values() if not cid or s.cid == cid)


# ── running a statement ────────────────────────────────────────
# Cheap first check so a refused write reads as a sentence rather than as a
# driver exception. The server decides for real: see the module header.
_READS = re.compile(
    r"^\s*(?:--[^\n]*\n|/\*.*?\*/|\s)*"
    r"(select|with|show|explain|describe|desc|analyze\s+select|table|values)\b",
    re.I | re.S)


def looks_like_read(sql: str) -> bool:
    return bool(_READS.match(sql or ""))


# ── one-shot helpers ───────────────────────────────────────────
# A console without a session, for callers that have credentials in hand and
# want one answer: the tests, and anything that should not hold a connection.
def _once(conn: dict, creds: dict) -> Console:
    return Console(conn.get("id", ""), "", creds["user"], creds["password"], conn)


def overview(conn: dict, creds: dict, database: str = "") -> dict:
    c = _once(conn, creds)
    try:
        return c.overview(database)
    finally:
        c.close()


def databases(conn: dict, creds: dict) -> list[dict]:
    c = _once(conn, creds)
    try:
        return c.databases()
    finally:
        c.close()


def tables(conn: dict, creds: dict, database: str) -> list[dict]:
    c = _once(conn, creds)
    try:
        return c.tables(database)
    finally:
        c.close()


def roles(conn: dict, creds: dict) -> list[dict]:
    c = _once(conn, creds)
    try:
        return c.roles()
    finally:
        c.close()


def activity(conn: dict, creds: dict) -> list[dict]:
    c = _once(conn, creds)
    try:
        return c.activity()
    finally:
        c.close()


def run(conn: dict, creds: dict, sql: str, database: str = "",
        write: bool = False) -> dict:
    c = _once(conn, creds)
    c.write = write
    try:
        return c.run(sql, database)
    finally:
        c.close()


# ── taking a copy out ──────────────────────────────────────────────────────
# WHY THIS IS WRITTEN IN PYTHON RATHER THAN SHELLING OUT
#     pg_dump and mysqldump produce better output than this ever will, and
#     neither is present in the portal's image — it ships a Python runtime and
#     bytecode, not a database toolbox. Requiring them would mean the button
#     works on the maintainer's laptop and not in the container anybody
#     actually runs, which is the worst of the options. So the dump is built
#     from catalogue queries, which work identically wherever the portal runs
#     and need nothing installed.
#
# WHAT THIS IS AND IS NOT
#     It is a logical export: CREATE TABLE, the constraints and indexes, and
#     INSERT statements. It is not a physical backup, it does not capture
#     roles, grants, sequences owned outside a table, triggers, functions or
#     extensions, and it is taken statement by statement rather than from one
#     frozen snapshot. Said plainly in the file's own header, because a backup
#     somebody trusts and should not is worse than no backup.
#
# EVERYTHING HERE IS READ-ONLY
#     The export runs in the same READ ONLY transaction as every other query
#     this console makes. It cannot alter the source no matter what is asked
#     of it.
BATCH = 500                 # rows fetched, and rows per INSERT statement


def _target(kind: str, schema: str, table: str) -> str:
    """How a table is named inside a dump file.

    PostgreSQL: schema-qualified. Schemas live inside a database, one dump can
    span several, and the schema is part of where the table belongs.

    MySQL: bare. A "schema" there IS a database, so a dump only ever covers
    one, and mysqldump writes unqualified names so that
    `mysql targetdb < dump.sql` puts them wherever you point it. Qualifying
    them looked tidier and was actively dangerous: the CREATE came out bare
    while the INSERTs carried the source database, so restoring into a new
    database created empty tables there and wrote the rows straight back into
    the database being backed up.
    """
    return (qualified("postgres", schema, table) if kind == "postgres"
            else ident("mysql", table))


def _lit_pg(v) -> str:
    """A PostgreSQL literal. Standard strings, so doubling the quote is all."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "'\\x" + bytes(v).hex() + "'::bytea"
    return "'" + str(v).replace("'", "''") + "'"


def _lit_my(v) -> str:
    """A MySQL literal. Backslash is an escape character here, unlike above."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "0x" + bytes(v).hex() if v else "''"
    out = str(v).replace("\\", "\\\\").replace("'", "\\'")
    return "'" + out.replace("\n", "\\n").replace("\r", "\\r")\
                    .replace("\x00", "\\0") + "'"
