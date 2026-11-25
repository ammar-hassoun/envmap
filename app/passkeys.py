"""Sign in with a fingerprint, a face, or a security key — WebAuthn.

WHAT A PASSKEY ACTUALLY IS, because the word hides the important part
    The biometric never leaves the device and this portal never sees it. What
    is registered here is a PUBLIC KEY; the private half lives in the laptop's
    secure enclave or on a security key and is released only after the device
    has satisfied itself that the right person is present. Touch ID is how the
    device is convinced, not how the portal is. So "we store fingerprints" is
    exactly wrong, and worth saying out loud to whoever asks.

WHY IT REPLACES BOTH FACTORS AND NOT JUST THE PASSWORD
    A platform passkey verified by biometric is already two factors: the device
    is something you have and the fingerprint is something you are. Demanding a
    TOTP code afterwards would be a third, and would make the fast path slower
    than the slow one — which is how a security feature ends up switched off.
    So `verify_login` returns a fully authenticated session, and it insists on
    USER VERIFICATION to earn that: an authenticator that only proves presence
    (a tap, no biometric or PIN) is refused at registration, because a passkey
    that skips the second factor must not be able to skip the second factor.

WHY PASSWORD AND TOTP STAY
    This is the control plane for somebody's whole estate. A laptop in a river
    on a Sunday must not be the reason nobody can reach it. Passkeys are purely
    ADDITIVE: every account keeps its password and its authenticator app, the
    login page keeps both routes, and removing your last passkey is not a lock
    you can turn on yourself by accident.

THE TWO THINGS THAT MAKE THIS FAIL IN SOMEBODY ELSE'S CLUSTER
    Both are about identity of the SITE, and both are silent when wrong, so
    `readiness()` reports them in words on the page rather than letting the
    browser throw a `SecurityError` at somebody.

    1. **It needs HTTPS.** WebAuthn is a secure-context API. `localhost` is
       exempt by specification — which is why the laptop instance works — and
       everything else needs TLS. A customer on plain HTTP cannot use this and
       should be told, not left clicking a button that does nothing.
    2. **The RP ID is the domain, and it is remembered inside the passkey.** A
       credential registered at `envmap.example.com` will not work at
       `portal.example.com` or at an IP. It is derived from the request host,
       which is right on a laptop and behind a well-behaved ingress alike; when
       the proxy does not set X-Forwarded-Host, the derived host is wrong and
       an admin sets it explicitly. Same shape, and the same reason, as the
       SSO redirect override.
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import secrets
from urllib.parse import urlparse

import webauthn
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import db, env, store

# How long a challenge is worth. Short because it only has to survive one
# gesture, and a challenge that outlives the page it was minted for is a replay
# window nobody is watching.
CHALLENGE_TTL = 300


def _migrate(c) -> None:
    c.execute("""CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        uid TEXT NOT NULL,
        cred_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        name TEXT NOT NULL DEFAULT '',
        rp_id TEXT NOT NULL DEFAULT '',
        created TEXT NOT NULL DEFAULT '',
        last_used TEXT NOT NULL DEFAULT '')""")
    c.execute("CREATE INDEX IF NOT EXISTS passkeys_uid ON passkeys(uid)")


db.register(_migrate)


# ── where the site says it is ──────────────────────────────────
#
# THERE IS NOTHING TO CONFIGURE, and that is the design rather than an omission.
# The address is derived from the request, which is right on a laptop and right
# behind any ingress that forwards the host — that is every install anybody has.
# An admin settings card existed here for one paragraph's worth of pathological
# proxy and was removed: a feature whose whole appeal is "no setup" must not
# open with a form.
#
# The escape hatch is an environment variable, not a page. An installation
# behind a proxy that does not forward the real host sets PORTAL_PASSKEY_RPID
# (and PORTAL_PASSKEY_ORIGIN if the scheme is wrong too) in its values file,
# the same way it already sets PORTAL_BASE_URL. Nobody sees it, nobody has to
# know it exists, and the readiness message names it if it is ever needed.
def _host_of(url: str) -> str:
    """The bare host, ASCII-encoded.

    IDNA matters and is easy to miss: a browser computes the RP ID and the
    origin from the PUNYCODE form of a non-ASCII host, so a portal at
    `müller.example.com` must be told `xn--mller-kva.example.com` or nothing
    matches and every passkey is refused. `urlparse().hostname` already
    lowercases; this adds the encoding.
    """
    try:
        host = (urlparse(url).hostname or "").strip()
    except ValueError:
        return ""
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # An unencodable host is not something to guess at — hand it back and
        # let readiness() report it rather than inventing an RP ID.
        return host


def _is_ip(host: str) -> bool:
    """Whether this host is an IP literal rather than a name."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def where(base_url: str) -> tuple[str, str]:
    """(rp_id, origin) for this request — derived, unless the env says otherwise.

    The origin must match character for character what the browser puts in
    clientDataJSON, so it carries the scheme and any non-default port. The RP
    ID is the bare host: a port in it is rejected by the browser, and that
    mistake reads as "passkeys just do not work here", so it is stripped here
    rather than trusted from anywhere.
    """
    raw = (env.PASSKEY_ORIGIN or base_url).rstrip("/")
    # A host, never a URL: a browser refuses an RP ID carrying a scheme or a
    # port, and answers that mistake with silence.
    rp_id = _host_of(env.PASSKEY_RPID) or env.PASSKEY_RPID or _host_of(raw)
    # The ORIGIN is compared character for character against what the browser
    # put in clientDataJSON, so its host must be encoded the same way the RP ID
    # is — otherwise an IDN portal fails the origin check even with the RP ID
    # right. Rebuilt rather than string-replaced so the port survives.
    origin = raw
    try:
        u = urlparse(raw)
        if u.hostname and not u.hostname.isascii():
            host = _host_of(raw)
            origin = f"{u.scheme}://{host}" + (f":{u.port}" if u.port else "")
    except ValueError:
        pass
    return rp_id, origin


def readiness(base_url: str) -> dict:
    """Whether a passkey can work here at all, in words a person can act on."""
    rp_id, origin = where(base_url)
    scheme = (urlparse(origin).scheme or "").lower()
    host = _host_of(origin)
    local = host in ("localhost", "127.0.0.1", "::1")
    if not host:
        return {"ok": False, "rp_id": "", "origin": origin,
                "why": "the portal cannot tell what address it is reached at — "
                       "an admin can set it under Users & audit"}
    # AN RP ID MUST BE A DOMAIN, and an IP address is not one. The
    # specification is explicit, so a portal reached at https://10.0.0.5 has
    # working TLS, passes every other check, and is refused by the browser with
    # a SecurityError and nothing in any log. 127.0.0.1 is exempt for the same
    # reason localhost is. There is no override for this: it is not a
    # configuration mistake, it is an address a passkey cannot be scoped to.
    if _is_ip(host) and not local:
        return {"ok": False, "rp_id": rp_id, "origin": origin,
                "why": f"passkeys need a domain name and this portal is "
                       f"reached at the IP address {host}. A passkey is tied "
                       f"to a domain, which an address cannot be — give the "
                       f"portal a hostname and they start working."}
    if not host.isascii():
        return {"ok": False, "rp_id": rp_id, "origin": origin,
                "why": f"the host {host} could not be encoded to the ASCII "
                       f"form browsers compare against — set "
                       f"PORTAL_PASSKEY_RPID to its punycode name."}
    if scheme != "https" and not local:
        return {"ok": False, "rp_id": rp_id, "origin": origin,
                "why": f"passkeys need HTTPS and this portal is reached over "
                       f"{scheme or 'an unknown scheme'} at {host}. Browsers "
                       f"refuse the API outside a secure context; localhost is "
                       f"the only exception."}
    return {"ok": True, "rp_id": rp_id, "origin": origin, "why": ""}


# ── storage ────────────────────────────────────────────────────
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def _row(r) -> dict:
    return {"id": r[0], "uid": r[1], "cred_id": r[2], "public_key": r[3],
            "sign_count": r[4], "name": r[5], "rp_id": r[6],
            "created": r[7], "last_used": r[8]}


def for_user(uid: str) -> list[dict]:
    return [_row(r) for r in db.q(
        "SELECT id,uid,cred_id,public_key,sign_count,name,rp_id,created,"
        "last_used FROM passkeys WHERE uid=? ORDER BY created", (uid,))]


def by_cred(cred_id: str) -> dict | None:
    r = db.one("SELECT id,uid,cred_id,public_key,sign_count,name,rp_id,created,"
               "last_used FROM passkeys WHERE cred_id=?", (cred_id,))
    return _row(r) if r else None


def count() -> int:
    r = db.one("SELECT COUNT(*) FROM passkeys")
    return int(r[0]) if r else 0


def device_name(user_agent: str) -> str:
    """What to call this passkey, read off the browser that made it.

    There was a text box for this. It is one more field between somebody and
    the one thing they came to do, for a string the browser can supply — and
    "MacBook · Safari" is more use in a list six months later than whatever
    gets typed into an empty box at speed.
    """
    ua = user_agent or ""
    plat = ("iPhone" if "iPhone" in ua else "iPad" if "iPad" in ua
            else "Mac" if "Macintosh" in ua or "Mac OS" in ua
            else "Windows" if "Windows" in ua
            else "Android" if "Android" in ua
            else "Linux" if "Linux" in ua else "")
    # Order matters: every Chrome says Safari, Edge says both, and Chrome on
    # iOS says neither under its own name.
    brow = ("Edge" if "Edg/" in ua else "Chrome" if "Chrome" in ua
            else "Firefox" if "Firefox" in ua
            else "Safari" if "Safari" in ua else "")
    return " · ".join(x for x in (plat, brow) if x) or "this device"


def drop(uid: str, pid: str) -> bool:
    if not db.one("SELECT 1 FROM passkeys WHERE id=? AND uid=?", (pid, uid)):
        return False
    db.run("DELETE FROM passkeys WHERE id=? AND uid=?", (pid, uid))
    return True


def drop_all(uid: str) -> None:
    """Every passkey for one account — used when the account is deleted, and
    when an admin resets somebody who has lost every device."""
    db.run("DELETE FROM passkeys WHERE uid=?", (uid,))


# ── the challenge, kept in the session ─────────────────────────
def _issue(session, kind: str, challenge: bytes, **extra) -> None:
    session["pk_challenge"] = {"kind": kind, "c": _b64(challenge),
                               "at": dt.datetime.now(dt.UTC).timestamp(),
                               **extra}


def _claim(session, kind: str) -> tuple[bytes, dict]:
    """The challenge this response must answer, removed as it is read.

    Single use and typed: a registration challenge must not be spendable as a
    login one, and a challenge that can be replayed is the whole attack this
    protocol exists to stop.
    """
    got = session.pop("pk_challenge", None)
    if not got or got.get("kind") != kind:
        raise ValueError("that sign-in attempt has expired — try again")
    if dt.datetime.now(dt.UTC).timestamp() - got.get("at", 0) > CHALLENGE_TTL:
        raise ValueError("that took too long — try again")
    return _unb64(got["c"]), got


# ── registration ───────────────────────────────────────────────
def register_options(user: dict, base_url: str, session) -> str:
    """What the browser needs to mint a passkey for this account, as JSON."""
    ready = readiness(base_url)
    if not ready["ok"]:
        raise ValueError(ready["why"])
    challenge = secrets.token_bytes(32)
    opts = webauthn.generate_registration_options(
        rp_id=ready["rp_id"],
        rp_name=store.brand().get("name") or "DevOps EnvMap",
        # The account is identified by its immutable id, never the address: an
        # email can change and a passkey bound to the old one would belong to
        # nobody.
        user_id=user["id"].encode(),
        user_name=user.get("email", ""),
        user_display_name=user.get("name") or user.get("email", ""),
        authenticator_selection=AuthenticatorSelectionCriteria(
            # DISCOVERABLE, so the sign-in page needs no email typed first —
            # which is the entire point of the feature as asked for. `preferred`
            # rather than `required` so an older security key with no room for
            # resident keys can still be used, just with the email typed.
            resident_key=ResidentKeyRequirement.PREFERRED,
            # REQUIRED, not preferred. This credential is going to stand in for
            # a password AND an authenticator app, so the device has to prove a
            # person was verified — not merely that something was tapped.
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        # So the browser says "you already have one of these" instead of
        # silently making a second credential for the same device.
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=_unb64(p["cred_id"]))
            for p in for_user(user["id"])],
        challenge=challenge,
    )
    _issue(session, "register", challenge, uid=user["id"])
    return options_to_json(opts)


def verify_registration(user: dict, credential, base_url: str, session,
                        name: str = "") -> dict:
    """Check what the browser produced and store the public half."""
    ready = readiness(base_url)
    if not ready["ok"]:
        raise ValueError(ready["why"])
    challenge, held = _claim(session, "register")
    if held.get("uid") != user["id"]:
        raise ValueError("that enrolment belongs to a different sign-in")
    got = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=ready["rp_id"],
        expected_origin=ready["origin"],
        require_user_verification=True,
    )
    cred_id = _b64(got.credential_id)
    if by_cred(cred_id):
        raise ValueError("that device already has a passkey here")
    pid = "pk-" + secrets.token_hex(6)
    now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
    db.run("INSERT INTO passkeys (id,uid,cred_id,public_key,sign_count,name,"
           "rp_id,created,last_used) VALUES (?,?,?,?,?,?,?,?,'')",
           (pid, user["id"], cred_id, _b64(got.credential_public_key),
            int(got.sign_count or 0), (name.strip() or "this device")[:60],
            ready["rp_id"], now))
    return {"id": pid, "name": name.strip() or "this device"}


# ── signing in ─────────────────────────────────────────────────
def login_options(base_url: str, session, email: str = "") -> str:
    """A challenge to sign. With no email this is usernameless: the browser
    offers whichever passkeys it holds for this site, which is the one-gesture
    sign-in. With an email it narrows to that account's credentials, for an
    authenticator that cannot store a discoverable one."""
    ready = readiness(base_url)
    if not ready["ok"]:
        raise ValueError(ready["why"])
    allow = None
    if email:
        from . import auth
        u = auth.by_email(email.strip().lower())
        # Deliberately NOT an error when the account is unknown: answering
        # differently for a real address than a fake one turns this endpoint
        # into a way to enumerate who has an account here. An unknown address
        # gets a normal challenge that will simply fail to be satisfied.
        allow = [PublicKeyCredentialDescriptor(id=_unb64(p["cred_id"]))
                 for p in for_user(u["id"])] if u else []
    challenge = secrets.token_bytes(32)
    opts = webauthn.generate_authentication_options(
        rp_id=ready["rp_id"],
        challenge=challenge,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    _issue(session, "login", challenge)
    return options_to_json(opts)


def verify_login(credential, base_url: str, session) -> dict:
    """Check a signed challenge. Returns the passkey row it belongs to.

    The caller looks the user up from `uid` and starts the session; this
    function decides only whether the signature is good, and raises otherwise.
    """
    ready = readiness(base_url)
    if not ready["ok"]:
        raise ValueError(ready["why"])
    challenge, _held = _claim(session, "login")
    raw_id = credential.get("rawId") or credential.get("id")
    row = by_cred(_b64(webauthn.base64url_to_bytes(raw_id))) if raw_id else None
    if not row:
        raise ValueError("that passkey is not registered here")
    got = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=ready["rp_id"],
        expected_origin=ready["origin"],
        credential_public_key=_unb64(row["public_key"]),
        credential_current_sign_count=row["sign_count"],
        # The whole basis for skipping the password AND the code. Without it a
        # tapped key would be one factor wearing the badge of two.
        require_user_verification=True,
    )
    now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
    # A counter that goes backwards means the credential was cloned — but many
    # authenticators (Apple's among them) never implement one and report zero
    # for ever, so zero is not evidence of anything and must not be treated as
    # such. py_webauthn raises on a real regression; this only records.
    db.run("UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?",
           (int(got.new_sign_count or 0), now, row["id"]))
    return {**row, "last_used": now}
