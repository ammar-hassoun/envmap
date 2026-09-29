"""One-time links: an invitation, and a password reset.

WHAT IS SHARED AND WHY
    Both are the same dangerous object — a string that, held by anybody, lets
    them set the password on an account. Expiry, single use, revocation on
    reissue and storing only a hash have to be right for both, and getting them
    right twice in two places is how they end up differing. So there is one
    table and one code path, with a ``kind`` saying which it is.

WHAT IS NOT SHARED
    An invitation is sent to an address, so opening it proves the person holds
    that address, and accepting one marks the email verified. A reset link is
    handed over by an administrator — through chat, in person, however they
    reach the person — so it proves nothing about the address and must not
    claim to. A reset therefore never sets email_verified, and it never signs
    anybody in: the new password still has to pass the authenticator at the
    sign-in page, or a reset link would be a way around the second factor.

WHY AN INVITATION RATHER THAN A PASSWORD THE ADMINISTRATOR CHOOSES
    An administrator who types a password for somebody else then has to send
    it to them, which in practice means a chat message — and from that moment
    it is a password two people know and one of them cannot change. An invite
    inverts it: the account is created with no password at all, and the person
    who opens the link chooses one nobody else has ever seen.

    Opening the link verifies the address **only if the portal was the thing
    that sent it**. That distinction was got wrong once and is worth spelling
    out: when an administrator copies the link into a chat window, the person
    who opens it has proved they can read that chat, not that they hold the
    mailbox — so anybody can be invited "as" any address. The delivery method
    is therefore recorded on the invitation, and the verified stamp is written
    only for the ones this portal actually posted.

WHY ONLY A HASH OF THE TOKEN IS STORED
    The link is a credential: whoever holds it becomes that user. Stored in
    the clear, anybody who could read the database — a backup, a support
    export, a stray copy of portal.db — could take over every account that had
    not yet been claimed. So it is hashed, and only the hash is kept.

    The consequence is deliberate and worth stating plainly: the link cannot be
    shown a second time. A lost invite is reissued, not recovered, and
    reissuing invalidates the one before it.

    The hash is a plain SHA-256 rather than scrypt. That is not the shortcut it
    looks like: a token is 32 bytes from the system random source, so there is
    no dictionary to run and nothing for a slow KDF to slow down. A password is
    hashed slowly because people choose passwords; this is not one.

WHAT AN INVITE DOES NOT DO
    It does not grant anything by itself. Roles are assigned to the account
    when it is created, so an unopened invite is an account that cannot yet be
    signed into, and revoking one leaves an account nobody can sign into
    either — visible in the list, not silently gone.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import sqlite3

from . import auth, db

# The password column of an account nobody has claimed. It is not a hash, so
# verify_password fails closed on it forever — there is no password to guess.
PENDING = "!invite"

KIND_INVITE = "invite"
KIND_RESET = "reset"

# Long enough to survive a weekend and a person on leave, short enough that a
# link forwarded into a group chat a year ago is not still a way in.
TTL_DAYS = 7

# A reset is answered while somebody is waiting, so it does not need days. A
# shorter window also limits how long a link sitting in a chat thread is live.
RESET_TTL_DAYS = 1


def _migrate(c: sqlite3.Connection) -> None:
    c.execute("""CREATE TABLE IF NOT EXISTS invites (
        id TEXT PRIMARY KEY,
        uid TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        created TEXT, expires TEXT,
        created_by TEXT,
        used TEXT DEFAULT '',
        revoked INTEGER DEFAULT 0)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_invites_uid ON invites(uid)")
    cols = {r["name"] for r in c.execute("PRAGMA table_info(invites)")}
    if "kind" not in cols:
        c.execute("ALTER TABLE invites ADD COLUMN kind TEXT DEFAULT 'invite'")
    # 'email' when the portal sent it, 'manual' when a person carried it. Only
    # the first can be said to verify anything. Existing rows predate the
    # sending code, so they were all carried by hand.
    if "delivered" not in cols:
        c.execute("ALTER TABLE invites ADD COLUMN delivered TEXT DEFAULT 'manual'")
    # Whether redeeming this link also clears the authenticator. Recorded on
    # the link rather than decided when it is opened, because the two kinds of
    # reset differ and the difference has to survive until somebody clicks:
    # an administrator issuing one has identified the person some other way, a
    # self-service one has only proved somebody can read an inbox.
    if "clear_mfa" not in cols:
        c.execute("ALTER TABLE invites ADD COLUMN clear_mfa INTEGER DEFAULT 0")
    # Somebody who has forgotten their password cannot be handed a link by the
    # portal — there is no mail here, and showing it to whoever typed the
    # address would let anyone reset anyone's password. So the request is
    # recorded for an administrator to answer.
    c.execute("""CREATE TABLE IF NOT EXISTS reset_requests (
        id TEXT PRIMARY KEY,
        uid TEXT, email TEXT NOT NULL,
        at TEXT, ip TEXT, handled TEXT DEFAULT '')""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_invites_hash "
              "ON invites(token_hash)")
    # additive, like every other migration here: an older database gains the
    # columns and loses nothing
    have = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
    for col in ("email_verified", "invited_at", "invited_by"):
        if col not in have:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")


db.register(_migrate)


def _now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hash(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


# ── creating ───────────────────────────────────────────────────────────────
def create_user(email: str, name: str, role: str = "user") -> str:
    """An account with no password, waiting to be claimed.

    create_locked_user, not create_user: the latter hashes what it is handed,
    which would turn the sentinel below into a password that works.
    """
    return auth.create_locked_user(email, name, PENDING, role=role)


def is_pending(u: dict | None) -> bool:
    return bool(u) and (u.get("password") or "") == PENDING


def issue(uid: str, by: str = "", ttl_days: int = 0,
          kind: str = KIND_INVITE, delivered: str = "manual",
          clear_mfa: bool = False) -> str:
    """A fresh link for this account. Any earlier unused one stops working.

    Returned once and never stored, so the caller has to show it now. Only
    links of the same kind are replaced: issuing a reset must not quietly
    cancel an invitation that has not been opened yet.
    """
    if ttl_days <= 0:
        ttl_days = RESET_TTL_DAYS if kind == KIND_RESET else TTL_DAYS
    db.run("UPDATE invites SET revoked = 1 WHERE uid = ? AND kind = ? "
           "AND used = '' AND revoked = 0", (uid, kind))
    token = secrets.token_urlsafe(32)
    expires = (dt.datetime.now() + dt.timedelta(days=ttl_days)
               ).strftime("%Y-%m-%d %H:%M:%S")
    db.run("INSERT INTO invites (id, uid, token_hash, created, expires, "
           "created_by, used, revoked, kind, delivered, clear_mfa) "
           "VALUES (?,?,?,?,?,?,'',0,?,?,?)",
           (f"inv-{secrets.token_hex(4)}", uid, _hash(token), _now(), expires,
            by, kind, delivered, 1 if clear_mfa else 0))
    if kind == KIND_INVITE:
        auth.update_user(uid, invited_at=_now(), invited_by=by)
    return token


def mark_delivery(uid: str, kind: str, how: str) -> None:
    """Record how the newest link of this kind actually reached the person.

    Separate from issue() because whether the mail went out is only known
    after trying, and a relay that fails must downgrade the invitation to
    hand-carried rather than leave it claiming it was posted.
    """
    row = db.one("SELECT id FROM invites WHERE uid = ? "
                 "AND COALESCE(kind, 'invite') = ? ORDER BY created DESC LIMIT 1",
                 (uid, kind))
    if row:
        db.run("UPDATE invites SET delivered = ? WHERE id = ?",
               ("email" if how == "email" else "manual", row["id"]))


def link(base: str, token: str, kind: str = KIND_INVITE) -> str:
    where = "reset" if kind == KIND_RESET else "invite"
    return f"{(base or '').rstrip('/')}/{where}/{token}"


# ── redeeming ──────────────────────────────────────────────────────────────
def check(token: str, kind: str = "") -> dict:
    """{"ok": bool, "why": str, "user": dict|None, "invite": dict|None}.

    Every refusal says which one it is, because "this link does not work" sends
    somebody back to the person who sent it with nothing useful to report.
    """
    row = db.one("SELECT * FROM invites WHERE token_hash = ?", (_hash(token),))
    if not row:
        return {"ok": False, "why": "This link is not valid.",
                "user": None, "invite": None}
    inv = dict(row)
    inv["kind"] = inv.get("kind") or KIND_INVITE
    # an invitation opened at the reset URL, or the reverse, is not a link that
    # "nearly works" — the page it lands on would say the wrong things about
    # what is happening to the account
    if kind and inv["kind"] != kind:
        return {"ok": False, "why": "This link is not valid.",
                "user": None, "invite": None}
    user = auth.by_id(inv["uid"])
    if not user:
        return {"ok": False, "why": "The account this invitation was for has "
                                    "been removed.", "user": None, "invite": inv}
    if inv["used"]:
        return {"ok": False, "why": "This link has already been used. "
                                    "Sign in instead, or ask for a new one.",
                "user": user, "invite": inv}
    if inv["revoked"]:
        return {"ok": False, "why": "This link was replaced by a newer one. "
                                    "Use the most recent one you were sent.",
                "user": user, "invite": inv}
    if inv["expires"] and inv["expires"] < _now():
        return {"ok": False, "why": f"This link expired on "
                                    f"{inv['expires'][:10]}. Ask for a new one.",
                "user": user, "invite": inv}
    if user.get("disabled"):
        return {"ok": False, "why": "This account is disabled.",
                "user": user, "invite": inv}
    return {"ok": True, "why": "", "user": user, "invite": inv}


def accept(token: str, password: str, kind: str = "") -> dict:
    """Claim the account: set the password, verify the address, spend the link.

    Re-checks rather than trusting the caller's earlier check — the page may
    have sat open while the invitation was revoked.
    """
    got = check(token, kind)
    if not got["ok"]:
        raise ValueError(got["why"])
    if (problem := auth.password_problem(password)):
        raise ValueError(problem)
    uid = got["user"]["id"]
    auth.set_password(uid, password)
    # Verification requires two things at once: an invitation (a reset link is
    # sent to somebody who already has the account) and delivery by this portal
    # (a link carried by hand proves only that it was carried). Either missing
    # and the stamp is not written — an unverified account says so on the users
    # page rather than carrying a claim nobody earned.
    if (got["invite"]["kind"] == KIND_INVITE
            and (got["invite"].get("delivered") or "manual") == "email"):
        auth.update_user(uid, email_verified=_now())
    # A lost password and a lost phone usually arrive together, so an
    # administrator issuing a reset clears the authenticator with it and the
    # person enrols again at the next sign-in.
    #
    # A self-service reset does NOT, and that is the whole point of the split:
    # if reading somebody's inbox cleared their second factor too, the inbox
    # would be the only factor and MFA would be decoration. The link says which
    # kind it is before it is used.
    if got["invite"].get("clear_mfa"):
        auth.reset_mfa(uid)
    db.run("UPDATE invites SET used = ? WHERE id = ?", (_now(), got["invite"]["id"]))
    db.run("UPDATE reset_requests SET handled = ? WHERE uid = ? AND handled = ''",
           (_now(), uid))
    return auth.by_id(uid)


def revoke(iid: str) -> None:
    db.run("UPDATE invites SET revoked = 1 WHERE id = ?", (iid,))


# ── reading ────────────────────────────────────────────────────────────────
def outstanding(uid: str, kind: str = KIND_INVITE) -> dict | None:
    """The live link of this kind for this account, if there is one."""
    row = db.one("SELECT * FROM invites WHERE uid = ? "
                 "AND COALESCE(kind, 'invite') = ? AND used = '' "
                 "AND revoked = 0 AND expires > ? ORDER BY created DESC LIMIT 1",
                 (uid, kind, _now()))
    return dict(row) if row else None


# ── somebody who has forgotten their password ──────────────────────────────
def request_reset(email: str, ip: str = "") -> None:
    """Record that a reset was asked for. Says nothing back, on purpose.

    The caller must show the same page whether or not the address exists.
    Anything else turns this form into a way to find out who has an account.
    """
    email = (email or "").strip().lower()
    if not email:
        return
    u = auth.by_email(email)
    # an address nobody has is still recorded: repeated requests for one are
    # worth an administrator seeing, and dropping them silently hides that
    db.run("INSERT INTO reset_requests (id, uid, email, at, ip, handled) "
           "VALUES (?,?,?,?,?,'')",
           (f"rq-{secrets.token_hex(4)}", (u or {}).get("id", ""), email,
            _now(), ip))


def reset_requests() -> list[dict]:
    return [dict(r) for r in db.q(
        "SELECT * FROM reset_requests WHERE handled = '' ORDER BY at DESC")]


def dismiss_request(rid: str) -> None:
    db.run("UPDATE reset_requests SET handled = ? WHERE id = ?", (_now(), rid))


def state(user: dict) -> dict:
    """Where this account is between invited and working, in words.

    One place decides this so the list, the badge and the audit line cannot
    disagree about what "pending" means.
    """
    if user.get("disabled"):
        return {"key": "disabled", "label": "disabled",
                "note": "cannot sign in"}
    if is_pending(user):
        live = outstanding(user["id"])
        if live:
            return {"key": "invited", "label": "invited",
                    "note": f"link valid until {live['expires'][:10]}"}
        return {"key": "stalled", "label": "invite expired",
                "note": "no working link — issue a new one"}
    if not user.get("mfa_enrolled"):
        return {"key": "no-mfa", "label": "setting up",
                "note": "password set, authenticator not yet added"}
    if not user.get("email_verified"):
        # working account, unproven address: the invitation was handed over
        # rather than posted, so nothing here has tested the mailbox
        return {"key": "unverified", "label": "active",
                "note": "address not verified — the invitation was not emailed"}
    return {"key": "active", "label": "active",
            "note": "address verified " + (user.get("email_verified") or "")[:10]}
