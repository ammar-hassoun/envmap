"""Each person's own model account, kept apart from the deployment's.

WHY PER USER AT ALL
    The assistant has always had one configuration for the whole install: an
    administrator saves a key, and everybody's questions are billed to it and
    carried by it. That is the right default and a poor ceiling. A team wants
    its own spend on its own account, an engineer wants a better model than the
    Ollama the chart installed, and nobody wants to hand their key to the person
    who happens to administer the portal.

    So a person may connect their own. It wins for their questions only; anybody
    who has not connected one keeps using the deployment's, and an install where
    nobody connects anything behaves exactly as it did before.

WHAT "CONNECT YOUR CLAUDE ACCOUNT" CAN AND CANNOT MEAN
    Not the flow the editors use. Those attach a Claude.ai subscription through
    Anthropic's own OAuth, which Anthropic does not offer to third-party
    products — there is no way for this portal to spend somebody's Claude
    subscription, and any UI implying otherwise would be a lie the first billing
    question exposes. What a person connects here is their own API key from
    console.anthropic.com, billed to them. The wording in the UI says so.

HOW IT IS STORED
    Sealed, in its own table, one row per user. Sealed because it is a
    credential and the settings table this used to live in is deliberately NOT
    sealed — that table holds branding and layout, and encrypting all of it
    would make the database unreadable at 2am for no gain. A key does not belong
    in it. The deployment's own key is moved under the same seal by store's
    SEALED_SETTINGS.

    A key is never sent back to a browser. The UI is told whether one is set and
    what its last four characters are, which is enough to recognise it and
    useless to anybody who steals the page.
"""
from __future__ import annotations

import datetime as dt

from . import db, secretbox


def _migrate(c) -> None:
    c.execute("""CREATE TABLE IF NOT EXISTS ai_accounts (
        uid TEXT PRIMARY KEY,
        provider TEXT NOT NULL DEFAULT '',
        base_url TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        token TEXT NOT NULL DEFAULT '',
        skip_tls INTEGER NOT NULL DEFAULT 0,
        created TEXT NOT NULL DEFAULT '')""")


db.register(_migrate)


def get(uid: str) -> dict:
    """This person's own account, decrypted. {} when they have not connected."""
    if not uid:
        return {}
    row = db.one("SELECT * FROM ai_accounts WHERE uid = ?", (uid,))
    if not row:
        return {}
    out = dict(row)
    out["token"] = secretbox.unseal(out.get("token") or "")
    out["skip_tls"] = bool(out.get("skip_tls"))
    return out


def save(uid: str, provider: str, model: str, token: str = "",
         base_url: str = "", skip_tls: bool = False) -> None:
    """Connect or update an account.

    An empty token means "leave the stored one alone", so somebody changing
    only their model does not have to paste the key again — the same bargain
    the deployment settings page already makes.
    """
    keep = get(uid)
    tok = (token or "").strip() or keep.get("token", "")
    db.run(
        "INSERT OR REPLACE INTO ai_accounts "
        "(uid, provider, base_url, model, token, skip_tls, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (uid, (provider or "").strip(), (base_url or "").strip(),
         (model or "").strip(), secretbox.seal(tok), 1 if skip_tls else 0,
         keep.get("created") or dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


def forget(uid: str) -> None:
    db.run("DELETE FROM ai_accounts WHERE uid = ?", (uid,))


def shown(uid: str) -> dict:
    """What the page may say about it. Never the key itself."""
    got = get(uid)
    if not got:
        return {"connected": False}
    tok = got.get("token") or ""
    return {
        "connected": True,
        "provider": got.get("provider", ""),
        "model": got.get("model", ""),
        "base_url": got.get("base_url", ""),
        "skip_tls": got.get("skip_tls", False),
        # enough to recognise which key it is, useless to anybody else
        "hint": ("…" + tok[-4:]) if len(tok) > 4 else ("set" if tok else ""),
        "created": got.get("created", ""),
    }
