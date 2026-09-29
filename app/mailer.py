"""Sending mail, so that "we verified their address" can be true.

WHY THIS EXISTS
    The invitation flow claimed to verify an email address. It did not, and
    could not: the portal printed a link, an administrator copied it into a
    chat window, and whoever opened it had proved they could read that chat —
    not that they hold the mailbox. Anybody can be invited "as" any address.

    Verification means the portal sent something to the address and the person
    came back with it. That needs a way to send. So either the portal delivers
    the link itself and the address is genuinely verified, or it does not and
    the account is honestly marked as unverified. What must not happen is the
    third thing, which is what was shipped: a verified stamp nobody earned.

WHY IT DEGRADES RATHER THAN REFUSES
    Plenty of installs have no SMTP relay to hand, and an invitation that
    cannot be issued at all is worse than one an administrator passes over
    manually. So with no relay configured the link is still produced and shown
    once, exactly as before — the difference is that the account then reads
    "address not verified", and says why.

WHERE THE PASSWORD LIVES
    In the settings table, beside the API tokens for every other connection
    this portal holds. That is consistent rather than ideal, and worth knowing:
    anybody who can read portal.db can read this password, so it should be a
    relay account that can do nothing but send.
"""
from __future__ import annotations

import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from . import store

# A wrong host must not hold a request open: an administrator clicking Invite
# should get an answer either way, quickly.
TIMEOUT = 12

SECURITY = {
    "starttls": "STARTTLS on the submission port (587) — the usual choice",
    "ssl": "Implicit TLS (465)",
    "none": "No encryption — only sensible for a relay on localhost",
}

DEFAULTS = {"host": "", "port": "587", "security": "starttls", "username": "",
            "password": "", "from_addr": "", "from_name": "",
            # the address links in emails point at. PORTAL_BASE_URL wins over
            # it; this exists so an install can be corrected without a restart
            "base_url": ""}


def settings() -> dict:
    got = {**DEFAULTS, **(store._setting("smtp") or {})}
    got["port"] = str(got.get("port") or "587")
    if got.get("security") not in SECURITY:
        got["security"] = "starttls"
    return got


def save(**fields) -> None:
    """Write the fields given. An empty password keeps the stored one.

    A settings form cannot show a password back, so it posts an empty box every
    time — writing that through would erase the password whenever anybody
    saved the form to change the port.
    """
    now = settings()
    for key, value in fields.items():
        if key not in DEFAULTS:
            continue
        if key == "password" and value == "":
            continue
        now[key] = value
    store._set_setting("smtp", {k: now[k] for k in DEFAULTS})


def public_base() -> str:
    """The address to build emailed links from, or "" if nobody has said.

    Never the request's Host header — see env.BASE_URL for why that is not a
    safe default when the reset form is open to anonymous callers.
    """
    from . import env
    got = (env.BASE_URL or settings().get("base_url") or "").strip()
    return got.rstrip("/")


def configured() -> bool:
    s = settings()
    return bool(s["host"] and s["from_addr"])


def sender() -> str:
    s = settings()
    addr = s["from_addr"]
    return formataddr((s["from_name"], addr)) if s["from_name"] else addr


_ADDR = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def deliverable(address: str) -> bool:
    """Whether this is worth handing to a relay at all."""
    return bool(_ADDR.match((parseaddr(address or "")[1] or "").strip()))


def send(to: str, subject: str, body: str) -> None:
    """Send one plain-text message. Raises with something readable on failure."""
    s = settings()
    if not configured():
        raise ValueError("no mail relay is configured")
    if not deliverable(to):
        raise ValueError(f"{to or 'that'} is not a valid email address")

    msg = EmailMessage()
    msg["From"] = sender()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    port = int(s["port"] or (465 if s["security"] == "ssl" else 587))
    try:
        if s["security"] == "ssl":
            server = smtplib.SMTP_SSL(s["host"], port, timeout=TIMEOUT,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(s["host"], port, timeout=TIMEOUT)
        with server:
            server.ehlo()
            if s["security"] == "starttls":
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if s["username"]:
                server.login(s["username"], s["password"])
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise ValueError(f"the relay rejected the sign-in: "
                         f"{_reason(e)}") from e
    except smtplib.SMTPException as e:
        raise ValueError(f"the relay refused the message: {_reason(e)}") from e
    except (OSError, ssl.SSLError) as e:
        raise ValueError(f"could not reach {s['host']}:{port} — {e}") from e


def _reason(e: Exception) -> str:
    got = getattr(e, "smtp_error", b"") or str(e).encode()
    if isinstance(got, bytes):
        got = got.decode("utf-8", "replace")
    return " ".join(got.split())[:200]


# ── the messages themselves ────────────────────────────────────────────────
# Plain text, deliberately. An HTML invitation from a system nobody recognises
# is what a phishing filter is built to catch, and there is nothing here that
# needs formatting.
def invitation(name: str, link: str, brand: str, days: int) -> tuple[str, str]:
    hello = f"Hello {name}," if name else "Hello,"
    return (f"Your {brand} account", f"""{hello}

An account has been created for you on {brand}.

Open this link to set your password and add an authenticator app:

{link}

The link works once and expires in {days} days. If you were not expecting
this, ignore it — nothing happens until the link is opened.
""")


def reset(name: str, link: str, brand: str, days: int,
          clear_mfa: bool = False) -> tuple[str, str]:
    hello = f"Hello {name}," if name else "Hello,"
    # Which of these two paragraphs appears matters to the reader: one of them
    # means "have your phone ready", the other means "you are getting a new
    # authenticator entry and the old one stops working".
    about_mfa = (
        "Your authenticator app will also be reset. After choosing a password\n"
        "you will be asked to scan a new code, and the old entry in your\n"
        "authenticator app stops working — delete it."
        if clear_mfa else
        "Your authenticator app is not affected — you will still need a code\n"
        "from it to sign in.")
    return (f"Reset your {brand} password", f"""{hello}

Somebody asked to reset the password on your {brand} account.

Open this link to choose a new one:

{link}

The link works once and expires in {days} day{'s' if days != 1 else ''}.
{about_mfa}
If you did not ask for this, ignore it and nothing changes.
""")
