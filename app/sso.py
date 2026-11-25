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
# MICROSOFT'S SHARED ENDPOINTS ARE NOT A TENANT. `common`, `organizations` and
# `consumers` answer for every directory there is (or every personal
# account), so a sign-in sent there is pinned to nothing -- and the email claim
# is whatever the account's own directory says. With a multi-tenant app
# registration, anybody could make a free Entra tenant, give one of its
# accounts the address of an EnvMap administrator, and sign in as them (the
# 2023 "nOAuth" class). Refused when saved and again at sign-in, because a
# row can be older than this rule.
SHARED_AUTHORITIES = frozenset({"common", "organizations", "consumers"})


def shared_authority(tenant: str) -> bool:
    return (tenant or "").strip().strip("/").lower() in SHARED_AUTHORITIES
SENTINEL = "!microsoft"          # never a valid scrypt hash → password login impossible


# ── configuration, stored like branding ────────────────────────
# ONE OR MANY TENANTS. A tenant is a directory people sign in FROM; the app
# registration is what they sign in TO. Most installs use one registration for
# every tenant (made "multitenant" in Azure, each tenant's admin consenting
# once), so the client id and secret live at the top and a tenant entry
# borrows them. A tenant whose admin would rather register the portal in their
# own directory gives that entry its own client id and secret instead.
#
# The row used to hold a single `tenant`. config() reads that shape as a
# one-entry list, so an upgraded install changes nothing until somebody adds a
# second tenant, and the first save writes the new shape.
def config() -> dict:
    c = store._setting("sso")
    tenants = c.get("tenants")
    if tenants is None:
        legacy = (c.get("tenant") or "").strip()
        tenants = [{"id": "t-1", "tenant": legacy}] if legacy else []
    tenants = [_entry(t) for t in tenants if (t.get("tenant") or "").strip()]
    return {
        "enabled": bool(c.get("enabled")),
        "tenants": tenants,
        # the first tenant, for anything still asking the one-tenant question
        "tenant": tenants[0]["tenant"] if tenants else "",
        "client_id": (c.get("client_id") or "").strip(),
        "client_secret": c.get("client_secret") or "",
        "auto_create": bool(c.get("auto_create")),
        # set only when the derived URL is wrong (no proxy headers): the exact
        # redirect URI must match what is registered in Entra, character for
        # character, or Microsoft refuses the round trip
        "redirect_override": (c.get("redirect_override") or "").strip(),
    }


def _entry(t: dict) -> dict:
    tenant = (t.get("tenant") or "").strip()
    return {
        "id": (t.get("id") or "").strip() or new_entry_id(),
        "label": (t.get("label") or "").strip(),
        "tenant": tenant,
        # the directory's GUID. Typed directly, or looked up from a verified
        # domain when the tenant was saved (resolve()); "" when that lookup
        # has not succeeded yet
        "tid": (t.get("tid") or "").strip().lower()
        or (tenant.lower() if _looks_like_guid(tenant) else ""),
        "domains": [d for d in (t.get("domains") or []) if d],
        "client_id": (t.get("client_id") or "").strip(),
        "client_secret": t.get("client_secret") or "",
    }


def new_entry_id() -> str:
    return "t-" + secrets.token_hex(4)


def label(t: dict) -> str:
    return t.get("label") or t.get("tenant") or "Microsoft"


def creds(cfg: dict, t: dict) -> tuple[str, str]:
    """(client id, secret) a sign-in from this tenant uses: its own app
    registration when it has one, the shared one otherwise."""
    if t.get("client_id"):
        return t["client_id"], t.get("client_secret") or ""
    return cfg["client_id"], cfg["client_secret"]


def usable(cfg: dict) -> list:
    """The tenants a person can actually start a sign-in with."""
    return [t for t in cfg["tenants"] if all(creds(cfg, t))]


def save(**fields) -> None:
    store._set_setting("sso", merged(**fields))


def merged(**fields) -> dict:
    """What save() would store — so a form can be checked with problem()
    against the secrets it is about to keep, before anything is written."""
    keep = config()
    # an empty secret on save means "keep the stored one" — the form never
    # echoes the secret back, so an untouched field must not erase it
    if not (fields.get("client_secret") or "").strip():
        fields["client_secret"] = keep["client_secret"]
    if "tenants" in fields:
        # ...and the same per tenant, matched by the entry's id, never by its
        # position: removing the first row must not hand its secret to the next
        stored = {t["id"]: t for t in keep["tenants"]}
        out = []
        for t in fields["tenants"]:
            t = _entry(t)
            old = stored.get(t["id"]) or {}
            if not t["client_secret"].strip() and t["client_id"] \
                    and t["client_id"] == old.get("client_id"):
                t["client_secret"] = old.get("client_secret") or ""
            if not t["tid"] and t["tenant"] == old.get("tenant"):
                t["tid"] = old.get("tid") or ""
            out.append(t)
        fields["tenants"] = out
    out = {**keep, **fields}
    out.pop("tenant", None)             # the list is the only source now
    return out


def ready() -> bool:
    c = config()
    return c["enabled"] and bool(usable(c))


DOMAIN_RE = __import__("re").compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def parse_domains(text: str) -> tuple[list, list]:
    """(domains, the words that are not one). Commas, spaces or new lines; a
    leading @ is forgiven because that is how people write an email domain."""
    good, badw = [], []
    for w in __import__("re").split(r"[\s,;]+", text or ""):
        w = w.strip().lower().lstrip("@").rstrip(".")
        if not w:
            continue
        (good if DOMAIN_RE.match(w) else badw).append(w)
    return list(dict.fromkeys(good)), badw


def problem(cfg: dict) -> str:
    """Why this configuration must not be saved as it is, or "".

    WITH MORE THAN ONE TENANT, EVERY TENANT NAMES ITS EMAIL DOMAINS. A portal
    account is found by email, and the email claim is whatever the account's
    own directory says — an administrator of ANY trusted tenant can give one of
    their accounts somebody else's address. With one tenant that was the
    tenant trusting itself; with two it is one organisation able to sign in as
    the other's people. The domain list is what keeps each tenant to its own
    addresses, so it is required the moment there is a second one.
    """
    ts = cfg["tenants"]
    if cfg["enabled"] and not ts:
        return "add at least one tenant to enable Microsoft sign-in"
    seen_t, seen_d = {}, {}
    for t in ts:
        name = label(t)
        key = (t["tid"] or t["tenant"]).lower()
        if shared_authority(t["tenant"]):
            return (f"{name}: “{t['tenant']}” is Microsoft's endpoint for "
                    "every directory, so it would let any organisation's "
                    "accounts sign in — enter your tenant ID or a verified "
                    "domain")
        if key in seen_t:
            return f"{name}: that tenant is already in the list as {seen_t[key]}"
        seen_t[key] = name
        if len(ts) > 1 and not t["domains"]:
            return (f"{name}: list the email domains its people sign in with "
                    "— required once there is more than one tenant")
        for d in t["domains"]:
            if d in seen_d and seen_d[d] != name:
                return f"{d} is listed under both {seen_d[d]} and {name}"
            seen_d[d] = name
        if t["client_id"] and not t["client_secret"]:
            return f"{name}: its own application needs its client secret"
        if cfg["enabled"] and not t["client_id"] \
                and not (cfg["client_id"] and cfg["client_secret"]):
            return (f"{name} uses the shared application, so its client ID "
                    "and secret are needed")
    return ""


# ── endpoints of a tenant ──────────────────────────────────────
def _authority(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{urllib.parse.quote(tenant)}"


def resolve(tenant: str) -> tuple[bool, str]:
    """(True, the directory's GUID) or (False, why). A GUID is its own answer;
    a verified domain is looked up in the tenant's discovery document, whose
    issuer names the directory."""
    if not tenant:
        return False, "enter the tenant ID (or verified domain) first"
    if shared_authority(tenant):
        return False, (f"“{tenant}” is Microsoft's endpoint for every "
                       "directory, not yours — enter your tenant ID or a "
                       "verified domain")
    if _looks_like_guid(tenant):
        return True, tenant.lower()
    url = f"{_authority(tenant)}/v2.0/.well-known/openid-configuration"
    try:
        with urlguard.urlopen(urlguard.check(url),
                                    timeout=TIMEOUT) as r:
            doc = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return False, f"Microsoft answered {e.code} — check the tenant ID"
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    parts = (doc.get("issuer") or "").rstrip("/").split("/")
    tid = parts[-2] if len(parts) >= 2 and parts[-1] == "v2.0" else ""
    if not _looks_like_guid(tid):
        return False, "Microsoft's answer did not name the directory"
    return True, tid.lower()


def test(tenant: str) -> tuple[bool, str]:
    """Prove the tenant id/domain is real before anyone is sent there."""
    ok, got = resolve(tenant)
    return ok, (f"tenant found — directory {got}" if ok else got)


# ── the two legs of the flow ───────────────────────────────────
def pick(entry_id: str = "") -> dict | None:
    """The tenant a sign-in is for: the one named, or the only one there is.
    With several and none named there is no right guess, so None."""
    cfg = config()
    ts = usable(cfg)
    if entry_id:
        return next((t for t in ts if t["id"] == entry_id), None)
    return ts[0] if len(ts) == 1 else None


def begin(redirect_uri: str, entry_id: str = "") -> tuple[str, str, str]:
    """(authorize_url, state, nonce). State foils cross-site request forgery on
    the callback; nonce ties the id_token to this browser session."""
    c = config()
    t = pick(entry_id)
    if not t:
        raise SsoError("choose which organisation to sign in with")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    q = urllib.parse.urlencode({
        "client_id": creds(c, t)[0],
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
    })
    return f"{_authority(t['tenant'])}/oauth2/v2.0/authorize?{q}", state, nonce


class SsoError(Exception):
    """Shown to the person on the login page — keep it plain and specific."""


def complete(code: str, redirect_uri: str, nonce: str,
             entry_id: str = "") -> dict:
    """Exchange the code, validate the claims, return the identity.

    `entry_id` is the tenant the sign-in BEGAN with, carried in the session —
    never anything the callback's query string says. Returns {"email", "name",
    "oid", "tid", "tenant"} or raises SsoError with the reason.
    """
    c = config()
    t = pick(entry_id)
    if not t:
        raise SsoError("that organisation is no longer set up for sign-in "
                       "here — please start again")
    if shared_authority(t["tenant"]):
        raise SsoError(f"{label(t)} is set to Microsoft's shared endpoint, "
                       "which any organisation can sign in through — ask an "
                       "admin to enter the tenant ID")
    # THE DIRECTORY IS CONFIRMED BEFORE ANY SIGN-IN IS ACCEPTED. A tenant typed
    # as a domain gets its GUID on save, but a save whose lookup failed kept
    # going ("the endpoint still pins it"), and then the comparison below was
    # skipped for good. It is looked up again now, and a sign-in whose
    # directory cannot be named is refused rather than trusted.
    want_tid = t["tid"]
    if not want_tid:
        ok, got = resolve(t["tenant"])
        if not ok:
            raise SsoError(f"the directory for {label(t)} could not be "
                           f"confirmed ({got}) — please try again later")
        want_tid = got
    client_id, client_secret = creds(c, t)
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
    }).encode()
    req = urllib.request.Request(
        urlguard.check(f"{_authority(t['tenant'])}/oauth2/v2.0/token"),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urlguard.urlopen(req, timeout=TIMEOUT) as r:
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
    if claims.get("aud") != client_id:
        raise SsoError("the token was issued for a different application")
    if claims.get("exp", 0) < time.time() - 60:
        raise SsoError("the sign-in took too long — please try again")
    if claims.get("nonce") != nonce:
        raise SsoError("the sign-in did not start in this browser — please "
                       "try again")
    # Tenant pinning: the exchange above went to THIS tenant's token endpoint,
    # so a single-tenant authority can only answer for itself. The directory
    # GUID is compared as well whenever it is known — typed, or looked up from
    # the domain on save — because a multitenant registration is exactly the
    # case where an endpoint alone is not the whole story.
    tid = (claims.get("tid") or "").lower()
    if tid != want_tid:
        raise SsoError("the account belongs to a different tenant")

    email = (claims.get("email") or claims.get("preferred_username") or "") \
        .strip().lower()
    if "@" not in email:
        raise SsoError("Microsoft returned no email address for this account")
    # Each tenant answers only for its own addresses (see problem()). Enforced
    # here as well as on save, because the row can be older than the rule.
    domain = email.rsplit("@", 1)[1]
    if t["domains"] and domain not in t["domains"]:
        raise SsoError(f"{email} is not an address {label(t)} signs in with")
    if not t["domains"] and len(c["tenants"]) > 1:
        raise SsoError(f"{label(t)} has no email domains set, so its "
                       "sign-ins are refused — ask an admin to add them")
    return {"email": email,
            "name": (claims.get("name") or "").strip() or email,
            "oid": claims.get("oid", ""), "tid": tid, "tenant": label(t)}


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
