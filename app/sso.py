"""Sign in with Microsoft: OpenID Connect against Entra ID, next to local accounts.

WHY BOTH
    Local accounts always work — they are what bootstraps the portal, what an
    admin falls back to when the tenant is misconfigured, and what a deployment
    without Entra uses forever. Microsoft sign-in is an *addition* an admin
    turns on in the running portal; nothing about the chart or the environment
    changes. If it is off or broken, the login page is exactly what it was.

THE FLOW (authorization code, confidential client)
    /login/microsoft            → redirect to the tenant's authorize endpoint,
                                  carrying a random state and nonce kept in the
                                  session
    /auth/microsoft/callback    → check state, exchange the code for tokens by
                                  POSTing to the token endpoint with the client
                                  secret, read the identity from the id_token

TRUST MODEL, STATED HONESTLY
    The id_token's signature is NOT verified here. That is deliberate and safe
    *in this flow only*: the token is not accepted from the browser — it comes
    back in the body of our own direct TLS response from
    login.microsoftonline.com, in exchange for a code plus this app's client
    secret. Trusting that channel is the same act as trusting the JWKS document
    we would have fetched over it. What still must be checked, and is: the
    audience is this app, the tenant is the configured one, the token is not
    expired, and the nonce is the one this session generated. If a later change
    ever accepts an id_token from anywhere else (implicit flow, a header, a
    form), signature verification becomes mandatory — do not skip this comment.

WHO GETS IN
    A Microsoft identity maps to a portal user by email. By default only
    *existing* users can sign in this way — turning the integration on must not
    quietly hand every mailbox in the tenant an account. Auto-provisioning is a
    separate switch, and it creates plain "user" accounts; roles are still
    granted by an admin in the portal.

    SSO-created accounts get an unusable password sentinel, so the password
    form can never be a second door into them (verify_password fails closed on
    anything that is not a real scrypt hash).

MFA
    Entra enforces the organisation's own MFA policy before we ever see the
    callback, so a Microsoft sign-in does not additionally demand the portal's
    TOTP. Local accounts keep it, unchanged.
"""
import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from . import store
from . import urlguard

TIMEOUT = 12
SENTINEL = "!microsoft"          # never a valid scrypt hash → password login impossible


# ── configuration, stored like branding ────────────────────────
def config() -> dict:
    c = store._setting("sso")
    return {
        "enabled": bool(c.get("enabled")),
        "tenant": (c.get("tenant") or "").strip(),
        "client_id": (c.get("client_id") or "").strip(),
        "client_secret": c.get("client_secret") or "",
        "auto_create": bool(c.get("auto_create")),
        # set only when the derived URL is wrong (no proxy headers): the exact
        # redirect URI must match what is registered in Entra, character for
        # character, or Microsoft refuses the round trip
        "redirect_override": (c.get("redirect_override") or "").strip(),
    }


def save(**fields) -> None:
    keep = config()
    # an empty secret on save means "keep the stored one" — the form never
    # echoes the secret back, so an untouched field must not erase it
    if not (fields.get("client_secret") or "").strip():
        fields["client_secret"] = keep["client_secret"]
    store._set_setting("sso", {**keep, **fields})


def ready() -> bool:
    c = config()
    return c["enabled"] and bool(c["tenant"] and c["client_id"]
                                 and c["client_secret"])


# ── endpoints of the configured tenant ─────────────────────────
def _authority(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{urllib.parse.quote(tenant)}"


def test(tenant: str) -> tuple[bool, str]:
    """Fetch the tenant's discovery document — proves the tenant id/domain is
    real before anyone is sent there to sign in."""
    if not tenant:
        return False, "enter the tenant ID (or verified domain) first"
    url = f"{_authority(tenant)}/v2.0/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(urlguard.check(url),
                                    timeout=TIMEOUT) as r:
            doc = json.loads(r.read().decode())
        issuer = doc.get("issuer", "")
        return True, f"tenant found — issuer {issuer}"
    except urllib.error.HTTPError as e:
        return False, f"Microsoft answered {e.code} — check the tenant ID"
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


# ── the two legs of the flow ───────────────────────────────────
def begin(redirect_uri: str) -> tuple[str, str, str]:
    """(authorize_url, state, nonce). State foils cross-site request forgery on
    the callback; nonce ties the id_token to this browser session."""
    c = config()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    q = urllib.parse.urlencode({
        "client_id": c["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
    })
    return f"{_authority(c['tenant'])}/oauth2/v2.0/authorize?{q}", state, nonce


class SsoError(Exception):
    """Shown to the person on the login page — keep it plain and specific."""


def complete(code: str, redirect_uri: str, nonce: str) -> dict:
    """Exchange the code, validate the claims, return the identity.

    Returns {"email", "name", "oid"} or raises SsoError with the reason.
    """
    c = config()
    body = urllib.parse.urlencode({
        "client_id": c["client_id"],
        "client_secret": c["client_secret"],
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
    }).encode()
    req = urllib.request.Request(
        urlguard.check(f"{_authority(c['tenant'])}/oauth2/v2.0/token"),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            tokens = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("error_description", "")
        except Exception:                                     # noqa: BLE001
            detail = ""
        raise SsoError("Microsoft rejected the sign-in: "
                       + (detail.split("\n")[0][:200] or f"HTTP {e.code}"))
    except Exception as e:                                    # noqa: BLE001
        raise SsoError(f"could not reach Microsoft: {type(e).__name__}")

    claims = _claims(tokens.get("id_token", ""))

    # the checks that matter (see the trust-model note at the top)
    if claims.get("aud") != c["client_id"]:
        raise SsoError("the token was issued for a different application")
    if claims.get("exp", 0) < time.time() - 60:
        raise SsoError("the sign-in took too long — please try again")
    if claims.get("nonce") != nonce:
        raise SsoError("the sign-in did not start in this browser — please "
                       "try again")
    # Tenant pinning: the exchange above went to the *configured tenant's*
    # token endpoint, so a single-tenant authority can only answer for itself.
    # The explicit check matters when the authority is multi-tenant
    # ("common" / "organizations") — there, any tenant's account reaches the
    # callback, and tid is the only thing saying whose. A GUID-configured
    # tenant is compared directly; a domain-configured one relies on the
    # endpoint pinning, which is exact.
    tid = claims.get("tid", "")
    if _looks_like_guid(c["tenant"]) and tid != c["tenant"]:
        raise SsoError("the account belongs to a different tenant")

    email = (claims.get("email") or claims.get("preferred_username") or "") \
        .strip().lower()
    if "@" not in email:
        raise SsoError("Microsoft returned no email address for this account")
    return {"email": email,
            "name": (claims.get("name") or "").strip() or email,
            "oid": claims.get("oid", "")}


def _looks_like_guid(s: str) -> bool:
    parts = s.split("-")
    return len(s) == 36 and len(parts) == 5 \
        and all(all(ch in "0123456789abcdefABCDEF" for ch in p) for p in parts)


def _claims(id_token: str) -> dict:
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:                                         # noqa: BLE001
        raise SsoError("Microsoft returned a token this portal could not read")
