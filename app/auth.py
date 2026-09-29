"""Local accounts: email as username, scrypt password hashing, TOTP (Google
Authenticator) as a mandatory second factor, and an append-only audit log.

Accounts and the audit trail are rows in the portal database (see db.py), which
is what makes concurrent writes safe and audit filtering an index lookup instead
of a file scan. Passwords are never stored, only scrypt hashes; TOTP secrets are
stored because verification requires them. Data from an earlier release still in
data/users.json or data/audit.jsonl is imported once on first start.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import threading
import time

from . import db, secretbox, store

USERS = store.DATA / "users.json"
AUDIT = store.DATA / "audit.jsonl"
SECRET_KEY_FILE = store.DATA / "session.key"

SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_SKEW = 1          # accept one step either side of now
# The authenticator-app label comes from the deployment's brand, not from
# this source file. Changing it never invalidates an enrolled secret — it is
# only the name shown beside the code.


# ── session signing key ────────────────────────────────────────
def session_secret() -> str:
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text().strip()
    key = secrets.token_urlsafe(48)
    SECRET_KEY_FILE.write_text(key)
    os.chmod(SECRET_KEY_FILE, 0o600)
    return key


# ── persistence ────────────────────────────────────────────────
# Accounts and the audit trail live in the portal database, not in JSON files.
# The reason is correctness rather than size: a JSON document is read whole and
# written whole, so two people saving at once silently lose one of the edits —
# and accounts are exactly where that must never happen. Migration from the old
# files happens once, automatically, below.
_ROW_BOOLS = ("mfa_enrolled", "disabled")


def _u(row) -> dict | None:
    """A database row as the plain dict the rest of the portal already expects."""
    if row is None:
        return None
    d = dict(row)
    for b in _ROW_BOOLS:
        d[b] = bool(d.get(b))
    for k in ("name", "password", "role", "totp_secret", "created", "last_login",
              "email_verified", "invited_at", "invited_by"):
        d[k] = d.get(k) or ""
    return d


def users() -> dict:
    return {r["id"]: _u(r) for r in
            db.q("SELECT * FROM users ORDER BY email COLLATE NOCASE")}


def any_users() -> bool:
    return (db.one("SELECT COUNT(*) AS n FROM users") or {"n": 0})["n"] > 0


def by_email(email: str) -> dict | None:
    # stored lower-cased on write, so this is an index hit rather than a scan
    return _u(db.one("SELECT * FROM users WHERE email = ?",
                     ((email or "").strip().lower(),)))


def by_id(uid: str) -> dict | None:
    return _u(db.one("SELECT * FROM users WHERE id = ?", (uid,)))


# ── tamper-evident audit chain ─────────────────────────────────
# Every audit row is linked to the one before it: hash = HMAC-SHA256(key, prev ‖
# row). The key is a domain-separated derivative of the portal secret, which on
# Kubernetes lives in a Secret apart from the database volume — so a stolen
# portal.db cannot be edited and re-chained to hide activity without also holding
# the key. Editing, deleting, reordering or inserting any row breaks the chain
# from that point; a separate one-row `audit_head` anchors the tip and count, so
# deleting the newest rows is caught too. Lose the key and the chain stops
# verifying — the same honest trade secretbox makes with sealed credentials.
_AUDIT_GENESIS = "config-portal-audit-genesis-v1"
_audit_lock = threading.Lock()


def _audit_key() -> bytes:
    return hashlib.sha256(b"portal-audit-chain-v1|" + secretbox.key()).digest()


def _audit_link(prev: str, at, user, action, target, detail, ip) -> str:
    payload = json.dumps([at, user, action, target, detail, ip],
                         separators=(",", ":"), ensure_ascii=False)
    msg = (prev + "\n" + payload).encode("utf-8")
    return hmac.new(_audit_key(), msg, hashlib.sha256).hexdigest()


def _audit_tip(c) -> str:
    row = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return row["hash"] if row and row["hash"] else _AUDIT_GENESIS


def _append_audit(c, at, user, action, target, detail, ip) -> str:
    """Insert one chained row and advance the head. Assumes a write transaction
    is already open on `c` (the caller serializes with `_audit_lock`)."""
    h = _audit_link(_audit_tip(c), at, user, action, target, detail, ip)
    c.execute("INSERT INTO audit (at, user, action, target, detail, ip, hash) "
              "VALUES (?,?,?,?,?,?,?)", (at, user, action, target, detail, ip, h))
    c.execute("INSERT INTO audit_head (id, hash, n) VALUES (1, ?, 1) "
              "ON CONFLICT(id) DO UPDATE SET hash = excluded.hash, n = n + 1", (h,))
    return h


def _audit_migrate(c) -> None:
    """Seal an existing log as the trusted baseline: add the `hash` column and
    the head anchor if missing, then chain any rows written before this feature.
    After one pass every row is hashed and this does nothing but a cheap count."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(audit)")}
    if "hash" not in cols:
        c.execute("ALTER TABLE audit ADD COLUMN hash TEXT NOT NULL DEFAULT ''")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_head (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        hash TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0)""")
    total = c.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]
    missing = c.execute("SELECT COUNT(*) AS n FROM audit WHERE hash = ''"
                        ).fetchone()["n"]
    if missing:
        prev = _AUDIT_GENESIS
        for r in c.execute("SELECT id, at, user, action, target, detail, ip "
                           "FROM audit ORDER BY id").fetchall():
            prev = _audit_link(prev, r["at"], r["user"] or "", r["action"],
                               r["target"] or "", r["detail"] or "", r["ip"] or "")
            c.execute("UPDATE audit SET hash = ? WHERE id = ?", (prev, r["id"]))
        c.execute("INSERT INTO audit_head (id, hash, n) VALUES (1, ?, ?) ON "
                  "CONFLICT(id) DO UPDATE SET hash = excluded.hash, n = excluded.n",
                  (prev, total))
    elif not c.execute("SELECT 1 FROM audit_head WHERE id = 1").fetchone():
        tip = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        c.execute("INSERT INTO audit_head (id, hash, n) VALUES (1, ?, ?)",
                  (tip["hash"] if tip else "", total))


db.register(_audit_migrate)


def verify_audit(limit: int = 0) -> dict:
    """Walk the chain and report the first break. `limit`>0 checks only the most
    recent N rows for a fast page badge, trusting the row just before the window
    as the anchor; limit=0 verifies the whole log from genesis. `head_ok`
    compares the stored tip and count, so a tail truncation is caught even when
    the surviving chain is internally consistent."""
    c = db.connect()
    total = c.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]
    head = c.execute("SELECT hash, n FROM audit_head WHERE id = 1").fetchone()
    tip = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    tip_hash = tip["hash"] if tip else ""
    head_ok = bool(head) and head["hash"] == tip_hash and head["n"] == total
    if limit and limit > 0:
        rows = list(reversed(c.execute(
            "SELECT id, at, user, action, target, detail, ip, hash FROM audit "
            "ORDER BY id DESC LIMIT ?", (limit + 1,)).fetchall()))
    else:
        rows = c.execute("SELECT id, at, user, action, target, detail, ip, hash "
                         "FROM audit ORDER BY id").fetchall()
    break_id, break_at, checked = None, "", 0
    if rows:
        min_id = c.execute("SELECT MIN(id) AS m FROM audit").fetchone()["m"]
        windowed = bool(limit) and rows[0]["id"] != min_id
        prev = rows[0]["hash"] if windowed else _AUDIT_GENESIS
        for r in (rows[1:] if windowed else rows):
            h = _audit_link(prev, r["at"], r["user"] or "", r["action"],
                            r["target"] or "", r["detail"] or "", r["ip"] or "")
            checked += 1
            if h != r["hash"]:
                break_id, break_at = r["id"], r["at"]
                break
            prev = h
    return {"ok": break_id is None and head_ok, "checked": checked, "total": total,
            "break_id": break_id, "break_at": break_at, "head_ok": head_ok}


def _migrate_from_files() -> None:
    """One-time import of users.json and audit.jsonl.

    Runs when the database has no users but the old files exist. The files are
    renamed rather than deleted, so a failed upgrade can still be inspected.
    """
    try:
        if USERS.exists() and not any_users():
            data = json.loads(USERS.read_text() or "{}").get("users") or {}
            with db.tx() as c:
                for uid, u in data.items():
                    c.execute(
                        "INSERT OR IGNORE INTO users (id, email, name, password, "
                        "role, totp_secret, mfa_enrolled, disabled, created, "
                        "last_login) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (uid, (u.get("email") or "").strip().lower(),
                         u.get("name") or "", u.get("password") or "",
                         u.get("role") or "user", u.get("totp_secret") or "",
                         1 if u.get("mfa_enrolled") else 0,
                         1 if u.get("disabled") else 0,
                         u.get("created") or "", u.get("last_login") or ""))
            USERS.rename(USERS.with_suffix(".json.migrated"))
        if AUDIT.exists():
            lines = [l for l in AUDIT.read_text().splitlines() if l.strip()]
            if lines and not db.one("SELECT 1 FROM audit LIMIT 1"):
                with db.tx() as c:
                    for line in lines:
                        try:
                            r = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        # chained on the way in, so imported history is sealed
                        # by the same key as everything written afterwards
                        _append_audit(c, r.get("at", ""), r.get("user", ""),
                                      r.get("action", ""), r.get("target", ""),
                                      r.get("detail", ""), r.get("ip", ""))
                AUDIT.rename(AUDIT.with_suffix(".jsonl.migrated"))
    except Exception:
        # never let a migration problem stop the portal from starting; the old
        # files are still on disk and the tables are simply empty
        pass


_migrate_from_files()


# ── passwords ──────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, salt_hex, want = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **SCRYPT)
        return hmac.compare_digest(dk.hex(), want)
    except Exception:
        return False


def password_problem(pw: str) -> str:
    if len(pw or "") < 10:
        return "password must be at least 10 characters"
    if pw.lower() == pw or pw.upper() == pw:
        return "password must mix upper and lower case"
    if not any(c.isdigit() for c in pw):
        return "password must contain a digit"
    return ""


# ── TOTP (RFC 6238) ────────────────────────────────────────────
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    now = int(time.time() // TOTP_STEP)
    return any(hmac.compare_digest(_totp_at(secret, now + drift), code)
               for drift in range(-TOTP_SKEW, TOTP_SKEW + 1))


def totp_uri(email: str, secret: str) -> str:
    """Keep this URI as short as possible.

    Every character raises the QR version, and a denser grid means smaller
    modules that phone cameras struggle to read off a screen. So: the email
    alone as the label (no repeated issuer prefix), a short issuer, and no
    digits/period params since 6/30 are the defaults every app assumes.
    """
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(email, safe='@')}"
            f"?secret={secret}&issuer={quote(store.brand()['short'])}")


QR_MODULE_PX = 6          # device-independent pixels per QR module
QR_BORDER = 4             # quiet-zone modules (spec minimum is 4)


def totp_qr(uri: str) -> tuple[str, int]:
    """Return (data-URI PNG, css_pixel_size) for the enrolment QR.

    Two things decide whether a phone can read this off a screen:

    * polarity — dark modules on white; authenticator apps do not reliably
      scan inverted codes, so this deliberately ignores the dark theme.
    * pixel alignment — every module must occupy a whole number of pixels.
      A PNG rendered at exactly QR_MODULE_PX per module and displayed at its
      natural size gives hard black/white edges. Scaling an SVG to some other
      size makes modules land on fractional pixels, which greys the edges;
      decoders tolerate that but phone cameras often do not.
    """
    import base64
    import io

    import segno
    qr = segno.make(uri, error="l")
    modules = qr.symbol_size(border=QR_BORDER)[0]
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=QR_MODULE_PX, border=QR_BORDER,
            dark="#000000", light="#ffffff")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}", modules * QR_MODULE_PX


# ── users ──────────────────────────────────────────────────────
def create_user(email: str, name: str, password: str, role: str = "user") -> str:
    email = (email or "").strip().lower()
    uid = f"u-{secrets.token_hex(4)}"
    try:
        db.run("INSERT INTO users (id, email, name, password, role, totp_secret, "
               "mfa_enrolled, disabled, created, last_login) "
               "VALUES (?,?,?,?,?,?,0,0,?,'')",
               (uid, email, (name or "").strip() or email,
                hash_password(password), role, "",
                time.strftime("%Y-%m-%d %H:%M:%S")))
    except sqlite3.IntegrityError as e:
        # the UNIQUE index decides, not a read-then-check: two simultaneous
        # sign-ups for the same address cannot both succeed
        raise ValueError("a user with that email already exists") from e
    return uid


def create_locked_user(email: str, name: str, sentinel: str,
                       role: str = "user") -> str:
    """An account with a sentinel in the password column instead of a hash.

    For accounts that cannot be signed into with a password at all: one that
    only ever arrives through single sign-on, and one that has been invited but
    not yet claimed. The sentinel is written literally on purpose — passing it
    through create_user would hash it, and the sentinel would quietly become a
    working password that anybody who has read this file could type. Left
    unhashed, verify_password fails closed on it forever.
    """
    if not sentinel.startswith("!"):
        raise ValueError("a locked account's sentinel must start with !")
    email = (email or "").strip().lower()
    uid = f"u-{secrets.token_hex(4)}"
    try:
        db.run("INSERT INTO users (id, email, name, password, role, totp_secret, "
               "mfa_enrolled, disabled, created, last_login) "
               "VALUES (?,?,?,?,?,?,0,0,?,'')",
               (uid, email, (name or "").strip() or email,
                sentinel, role, "",
                time.strftime("%Y-%m-%d %H:%M:%S")))
    except sqlite3.IntegrityError as e:
        # the UNIQUE index decides, not a read-then-check
        raise ValueError("a user with that email already exists") from e
    return uid


def create_sso_user(email: str, name: str, role: str = "user") -> str:
    """An account that can only ever arrive through single sign-on.

    mfa stays unenrolled because the identity provider enforces its own; the
    login flow marks these sessions verified.
    """
    return create_locked_user(email, name, SSO_SENTINEL, role)


# Sentinels that are deliberately not hashes, so verify_password fails closed.
# Matched exactly rather than by the leading "!": an invited account also has a
# sentinel, and treating it as single sign-on would offer the wrong sign-in
# route to somebody who simply has not chosen a password yet.
SSO_SENTINEL = "!microsoft"


def is_sso_user(u: dict) -> bool:
    return (u.get("password") or "") == SSO_SENTINEL


def update_user(uid: str, **fields) -> None:
    allowed = {"email", "name", "password", "role", "totp_secret",
               "mfa_enrolled", "disabled", "last_login",
               # written when an invitation is issued and when it is accepted
               "email_verified", "invited_at", "invited_by"}
    data = {k: v for k, v in fields.items() if k in allowed}
    if not data:
        return
    if "email" in data:
        data["email"] = (data["email"] or "").strip().lower()
    for b in _ROW_BOOLS:
        if b in data:
            data[b] = 1 if data[b] else 0
    sets = ", ".join(f"{k} = ?" for k in data)
    db.run(f"UPDATE users SET {sets} WHERE id = ?", list(data.values()) + [uid])


def delete_user(uid: str) -> None:
    db.run("DELETE FROM users WHERE id = ?", (uid,))


def set_password(uid: str, password: str) -> None:
    update_user(uid, password=hash_password(password))


def begin_mfa_enrolment(uid: str) -> str:
    """Issue a fresh secret; it only becomes active once a code is confirmed."""
    secret = new_totp_secret()
    update_user(uid, totp_secret=secret, mfa_enrolled=False)
    return secret


def confirm_mfa(uid: str, code: str) -> bool:
    u = by_id(uid)
    if not u or not u.get("totp_secret"):
        return False
    if verify_totp(u["totp_secret"], code):
        update_user(uid, mfa_enrolled=True)
        return True
    return False


def reset_mfa(uid: str) -> None:
    update_user(uid, totp_secret="", mfa_enrolled=False)


def git_author(user: dict) -> str:
    """Commit identity for this user."""
    name = (user.get("name") or user.get("email") or "Config Portal").strip()
    return f"{name} <{user.get('email') or 'config-portal@localhost'}>"


# ── audit log ──────────────────────────────────────────────────
def audit(user: dict | None, action: str, target: str = "",
          detail: str = "", ip: str = "") -> None:
    """Append one chained entry. The row is HMAC-linked to the one before it
    (see the audit-chain section above), under a lock and a write transaction so
    concurrent writers cannot fork the chain. A write failure is swallowed — an
    audit write must never break the action it is recording."""
    try:
        at = time.strftime("%Y-%m-%dT%H:%M:%S")
        email = (user or {}).get("email", "anonymous")
        detail = (detail or "")[:400]
        with _audit_lock:
            c = db.connect()
            own = not c.in_transaction         # join a caller's tx if one is open
            if own:
                c.execute("BEGIN IMMEDIATE")
            try:
                _append_audit(c, at, email, action, target, detail, ip)
                if own:
                    c.execute("COMMIT")
            except Exception:
                if own:
                    c.execute("ROLLBACK")
                raise
    except Exception:
        pass


# Coarse groups for the audit dashboard. Each is a SQL predicate over `action`
# (the tile filters and the per-row tone read from the same definitions, so what
# a tile counts is exactly what clicking it lists). `tone` maps to the house
# status palette; `refused` is the security-interesting outcome axis.
AUDIT_GROUPS = {
    "signin": ("Sign-in", "info", "key-round",
               "action IN ('login','logout','login_microsoft',"
               "'login_microsoft_denied','login_microsoft_failed','login_failed',"
               "'user_autocreated_microsoft','db_signin_failed') "
               "OR action LIKE 'mfa%' OR action LIKE 'password%'"),
    "access": ("Access & RBAC", "accent", "users",
               "action LIKE 'user_%' OR action LIKE 'role_%' "
               "OR action LIKE 'invite%' OR action = 'bootstrap_admin' "
               "OR action = 'profile_renamed'"),
    "privileged": ("Privileged", "warn", "shield",
                   "action LIKE 'pam_%' OR action IN ('pod_exec','pod_shell',"
                   "'ansible_host_shell') OR action LIKE 'cluster_user_%' "
                   "OR action LIKE 'netshoot_%' OR action LIKE 'self_update%' "
                   "OR action LIKE 'live_key_%'"),
    "infra": ("Infrastructure", "info", "server",
              "action LIKE 'kubectl_%' OR action LIKE 'cluster_%' "
              "OR action LIKE 'ansible_%' OR action LIKE 'gitops_%' "
              "OR action LIKE 'commit_%' OR action LIKE 'cloud_%' "
              "OR action LIKE 'edge_%' OR action = 'yaml_applied'"),
    "refused": ("Refused / failed", "danger", "triangle-alert",
                "action LIKE '%_refused' OR action LIKE '%_failed' "
                "OR action LIKE '%_denied'"),
}


def _audit_where(q="", action="", user="", group="", since="", until=""):
    clauses, args = [], []
    if q:
        like = f"%{q}%"
        clauses.append("(user LIKE ? OR action LIKE ? OR target LIKE ? "
                       "OR detail LIKE ? OR ip LIKE ?)")
        args += [like, like, like, like, like]
    if action:
        clauses.append("action = ?"); args.append(action)
    if user:
        clauses.append("user = ?"); args.append(user)
    if group in AUDIT_GROUPS:
        clauses.append("(" + AUDIT_GROUPS[group][3] + ")")
    if since:
        clauses.append("at >= ?"); args.append(since)
    if until:
        clauses.append("at <= ?"); args.append(until)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), args


def read_audit(limit: int = 250, q: str = "", action: str = "", user: str = "",
               group: str = "", since: str = "", until: str = "",
               offset: int = 0) -> list[dict]:
    """Newest-first entries. Every filter is applied in SQL (so a narrow action
    older than `limit` rows is still found — it used to be filtered in Python
    within the capped window and silently missed) with a real OFFSET for paging."""
    where, args = _audit_where(q, action, user, group, since, until)
    rows = db.q(f"SELECT id, at, user, action, target, detail, ip FROM audit"
                f"{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                tuple(args) + (max(1, limit), max(0, offset)))
    return [dict(r) for r in rows]


def count_audit(q: str = "", action: str = "", user: str = "", group: str = "",
                since: str = "", until: str = "") -> int:
    where, args = _audit_where(q, action, user, group, since, until)
    return (db.one(f"SELECT COUNT(*) AS n FROM audit{where}", tuple(args))
            or {"n": 0})["n"]


def audit_facets() -> dict:
    """The distinct actions and actors present, for the filter dropdowns."""
    return {
        "actions": [r["action"] for r in
                    db.q("SELECT DISTINCT action FROM audit ORDER BY action")],
        "users": [r["user"] for r in db.q(
            "SELECT DISTINCT user FROM audit WHERE user <> '' ORDER BY user")],
    }


def audit_severity(action: str) -> str:
    """The tone for one row: refusals/failures read danger, privileged actions
    warn, everything else neutral. Mirrors the AUDIT_GROUPS predicates so the
    table and the tiles agree."""
    a = action or ""
    if a.endswith(("_refused", "_failed", "_denied")):
        return "danger"
    if (a.startswith(("pam_", "netshoot_", "self_update", "live_key_"))
            or a in ("pod_exec", "pod_shell", "ansible_host_shell")
            or a.startswith("cluster_user_")):
        return "warn"
    return "ok"
