"""The Content-Security-Policy, and the per-request nonce it is keyed on.

WHY THIS EXISTS. Recorded as SEC-8 while fixing SEC-7, and it is the reason
that finding mattered: a stored `javascript:` URL in a Privileged Access
target, an operator's name interpolated into a `title` by `logos._lettermark`,
a connection name in an `aria-label` — each was a way to put markup on a page,
and each became CODE EXECUTION in an admin's session because nothing stopped
the browser running it. This product holds kubeconfigs, git tokens, sealing
keys and brokered SSH credentials; script running in a reader's session
reaches all of it. The individual holes were patched. This is the amplifier
underneath them, and it is what turns the next one into a bug rather than an
incident.

WHY A NONCE AND NOT `unsafe-inline`. A policy of `script-src 'unsafe-inline'`
is the easy first pass and it does not close this: `unsafe-inline` permits an
inline `<script>` AND an `on*` attribute, and there is no directive that
separates them. An injected `onmouseover=` runs under it exactly as before. A
NONCE is what distinguishes the two — the browser runs an inline script
carrying this request's nonce and refuses every event attribute, because an
attribute has nowhere to put one. That is the whole mechanism, and it is why
all 112 inline handlers had to go: the policy cannot be worth anything while
the product depends on the thing it must forbid.

WHAT IS DELIBERATELY STILL OPEN. `style-src` keeps `unsafe-inline`. There are
2,857 inline `style=` attributes here and they are the presentation layer, not
a second execution surface — CSS injection can deface a page and, with
attribute selectors, read some attribute values, which is real and is a long
way from running code with somebody's session. Closing it is a separate job
against a separate risk. Saying so plainly matters more than a policy that
looks total: this hardens one class of attack, it is not a promise about all
of them.

`connect-src 'self'` IS THE HALF THAT PAYS OFF FIRST. Script that cannot run
is the goal; script that runs and cannot phone home is the fallback, and the
two fail independently. A page here holds cluster credentials and session
tokens, so the exfiltration channel is worth shutting whether or not the
script gate holds.
"""
from __future__ import annotations

import contextvars
import secrets

# A request's nonce, read by the `csp_nonce()` template global. It is a
# contextvar rather than something on `request.state` because four pages build
# their context by hand (Compare, Search, the wizard, the denied page) and have
# already lost a sidebar global exactly that way — and here the failure would
# be every inline script on those pages silently refusing to run.
_NONCE: contextvars.ContextVar[str] = contextvars.ContextVar("csp_nonce", default="")

DIRECTIVES = (
    ("default-src", "'self'"),
    # No 'unsafe-inline' and no 'unsafe-eval'. Both are affordable because
    # every script this product serves is same-origin (no CDN) and nothing it
    # vendors calls eval or `new Function` — xterm.js, noVNC, pako and
    # guacamole-common were all checked rather than assumed.
    ("script-src", "'self' 'nonce-{nonce}'"),
    ("style-src", "'self' 'unsafe-inline'"),
    # `data:` for the brand mark and the favicon, which are rendered inline;
    # `blob:` because several windows build an image or a download in memory.
    ("img-src", "'self' data: blob:"),
    ("font-src", "'self' data:"),
    # Same-origin XHR, fetch AND the six WebSocket routes — a `wss://` back to
    # the page's own origin satisfies 'self'.
    ("connect-src", "'self'"),
    ("media-src", "'self' blob:"),
    ("worker-src", "'self' blob:"),
    ("object-src", "'none'"),
    # This portal is never framed by anything. Clickjacking a page that holds
    # "delete this cluster" is worth refusing outright.
    ("frame-ancestors", "'none'"),
    ("frame-src", "'none'"),
    # `<base>` injection retargets every relative script URL on the page, so
    # it is a way around 'self' that costs nothing to close.
    ("base-uri", "'self'"),
    ("form-action", "'self'"),
)

# Sent alongside, because each is one line and answers a question the policy
# does not. `frame-ancestors` supersedes X-Frame-Options in every browser that
# reads it; the older header stays for anything that does not.
COMPANIONS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def new_nonce() -> str:
    """Start a request: mint a nonce and make it the one templates will read."""
    value = secrets.token_urlsafe(16)
    _NONCE.set(value)
    return value


def nonce() -> str:
    """This request's nonce. Registered as the `csp_nonce` template global."""
    return _NONCE.get()


def policy(value: str = "") -> str:
    """The header value, carrying `value` (default: this request's nonce)."""
    n = value or nonce()
    return "; ".join(f"{k} {v.format(nonce=n)}" for k, v in DIRECTIVES)
