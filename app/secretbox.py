"""Credentials encrypted before they reach the database.

WHAT THIS PROTECTS AGAINST, AND WHAT IT DOES NOT
    Every connection this portal holds carries a credential: an Argo CD token,
    a cloud key, a BMC password, an SMTP password. They were stored as plain
    text in portal.db, which meant every copy of that file was a copy of all of
    them — and this portal makes copies. The pre-upgrade snapshot writes one to
    disk on every version change. A support export is another. So is whatever
    ends up in somebody's Downloads folder after a customer is asked to send
    their database.

    Encryption moves the secret out of those copies and into a key. What it
    cannot do is protect a machine somebody already owns: with the volume, the
    key file sits beside the database, and with the process, the key is in
    memory. Said plainly because the opposite claim is the one that gets
    believed.

WHERE THE KEY LIVES
    PORTAL_SECRET_KEY if it is set, which is the arrangement worth having: on
    Kubernetes it lives in a Secret, the database on a PersistentVolume, and a
    leaked volume is then not a leaked credential.

    Otherwise a key file in the data directory, mode 0600, generated on first
    use. That is weaker — same volume as the database — but it still protects
    every copy of portal.db taken without the whole directory, which is most of
    them, and it means an existing install gets the benefit without being
    reconfigured first.

WHY VALUES CARRY A PREFIX
    A sealed value is "enc.v1.<token>". Anything without that prefix is
    returned as it is, so a database written by an older version keeps working
    and is re-sealed the next time it is saved. There is no migration step to
    forget to run, and no moment where the portal cannot read its own data.

WHY LOSING THE KEY IS NOT A DISASTER
    Every one of these is a credential for a system somewhere else, not data
    the portal owns. Lose the key and the connections need their tokens pasted
    again — annoying, not fatal. That is the trade being made: no key escrow,
    no recovery, and a much smaller blast radius when a database walks.
"""
from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken

from . import env

PREFIX = "enc.v1."
KEY_FILE = "secret.key"

_key: bytes | None = None


def _from_env() -> bytes | None:
    raw = (os.environ.get("PORTAL_SECRET_KEY") or "").strip()
    if not raw:
        return None
    # accept either a Fernet key as-is or any 32 bytes of base64
    try:
        Fernet(raw.encode())
        return raw.encode()
    except (ValueError, TypeError):
        pass
    try:
        material = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:                                          # noqa: BLE001
        material = raw.encode()
    if len(material) < 32:
        raise ValueError("PORTAL_SECRET_KEY must be at least 32 bytes")
    return base64.urlsafe_b64encode(material[:32])


def _from_file() -> bytes:
    path = env.DATA_DIR / KEY_FILE
    try:
        got = path.read_bytes().strip()
        if got:
            return got
    except OSError:
        pass
    key = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    # written 0600 before anything goes in it, not after
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def key() -> bytes:
    global _key
    if _key is None:
        _key = _from_env() or _from_file()
    return _key


def reset() -> None:
    """Forget the cached key. For tests that move the data directory."""
    global _key
    _key = None


def sealed(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value: str) -> str:
    """Encrypt, unless it is empty or already sealed."""
    if not value or not isinstance(value, str) or sealed(value):
        return value
    return PREFIX + Fernet(key()).encrypt(value.encode()).decode()


def unseal(value: str) -> str:
    """Decrypt if sealed, pass through if not.

    A value that will not decrypt returns empty rather than raising: that is
    what a changed or lost key looks like, and one unreadable token must not
    take down every page that lists connections. The field then reads as unset,
    which is the truth — the portal no longer knows it.
    """
    if not sealed(value):
        return value
    try:
        return Fernet(key()).decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        return ""


def where() -> str:
    """Which key is in force, for the deployment page to state."""
    return ("PORTAL_SECRET_KEY" if _from_env()
            else f"{env.DATA_DIR / KEY_FILE} (same volume as the database — "
                 f"set PORTAL_SECRET_KEY to separate them)")
