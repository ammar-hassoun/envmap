"""Refuse requests a browser made on some other page's behalf.

WHY THIS EXISTS
    The session cookie is SameSite=Lax, and that stops a request from another
    SITE carrying it. But a site is a registrable domain, not an origin: a page
    on any sibling subdomain -- anything.example.com beside
    envmap.example.com -- is same-site, so the browser attaches the cookie to
    whatever that page sends here. Nothing else checked where a request came
    from. There was no token, no Origin check and no Sec-Fetch-Site check, so a
    page on a sibling could post any form in the product as whoever was signed
    in.

    The sharpest edge was the websockets. A WebSocket handshake is exempt from
    CORS altogether -- no preflight, and the response is never withheld -- so a
    sibling page could open /pam/ssh.ws with the person's cookie and drive a
    live shell on a production host through the credential Privileged Access
    brokers for them, with the recording filed under their name. The Origin
    header is the only thing that tells a socket opened by the portal's own
    page from one opened by somebody else's.

HOW IT DECIDES -- the algorithm of Go's net/http CrossOriginProtection
    Safe methods pass, EXCEPT a WebSocket: its handshake is a GET, and that GET
    is the whole attack. For everything else:

      * Sec-Fetch-Site says same-origin or none -> pass. The browser computes
        it from the real URL, so a proxy that rewrites Host can fool it in
        neither direction.
      * Sec-Fetch-Site says anything else -> REFUSE, whatever the Origin says.
        The browser has already judged it, and it can see the scheme. Falling
        through to the Origin comparison -- which cannot -- let a page at
        http://<portal> post to https://<portal>: cross-site to the browser,
        the portal itself to the Host check.
      * otherwise an Origin header (a browser too old to send Sec-Fetch-Site)
        -> pass only if it names this portal: the Host the
        request arrived with, the host a proxy says it was reached at
        (X-Forwarded-Host), or PORTAL_BASE_URL. The scheme is not compared,
        on purpose: behind a proxy that does not forward the protocol the
        portal believes it is on http while the browser is on https, and a
        guard that refuses the portal's own pages there is a guard somebody
        switches off.
      * neither header -> pass. Every browser that can carry the cookie sends
        at least one of them on a cross-origin request, so their absence means
        a script, curl, or an MCP client -- none of which ride anybody's
        cookie.

    A REQUEST THAT CARRIES ITS OWN CREDENTIAL PASSES, before any of that. The
    attack is a page riding the cookie the browser attaches by itself; an
    `Authorization` header is attached by nobody but the caller, and a page
    cannot put one on another origin's request without that origin's CORS
    consent, which this portal never gives. A browser-based MCP client sends
    an Origin beside its bearer token and must not be refused for it. A socket
    cannot carry the header at all, so this never applies to one.

    A browser cannot forge any of the three headers this reads: Origin and
    Sec-Fetch-* are forbidden request headers, and X-Forwarded-Host is not one
    a page may set on a form post or a socket.
"""
from __future__ import annotations

import logging
import urllib.parse

from . import env

log = logging.getLogger("uvicorn.error")

SAFE = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
PASSING_SITES = frozenset({"same-origin", "none"})
_DEFAULT_PORTS = {"80", "443"}


def _hostport(netloc: str) -> str:
    """`host[:port]`, lower-cased, with a default port dropped -- so
    `Portal.example.com:443` and `portal.example.com` are the same place."""
    netloc = (netloc or "").strip().lower()
    if not netloc:
        return ""
    try:
        u = urllib.parse.urlsplit("//" + netloc)
        port = u.port
    except ValueError:
        return ""
    host = u.hostname or ""
    if ":" in host:                                   # IPv6, re-bracketed
        host = f"[{host}]"
    return host if port is None or str(port) in _DEFAULT_PORTS \
        else f"{host}:{port}"


def _headers(scope: dict) -> dict:
    return {k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers") or []}


def trusted(headers: dict) -> set:
    """Every host this portal may legitimately be reached at, for this
    request: the Host it arrived with, a forwarding proxy's view of it, and
    the configured public address."""
    out = {_hostport(headers.get("host", ""))}
    fwd = headers.get("x-forwarded-host", "")
    if fwd:
        out.add(_hostport(fwd.split(",")[0]))
    if env.BASE_URL:
        try:
            out.add(_hostport(urllib.parse.urlsplit(env.BASE_URL).netloc))
        except ValueError:
            pass
    out.discard("")
    return out


def refusal(scope: dict) -> str:
    """Why this request must be refused, or "" to let it through."""
    kind = scope.get("type")
    if kind not in ("http", "websocket"):
        return ""
    if kind == "http" and scope.get("method", "GET").upper() in SAFE:
        return ""
    h = _headers(scope)
    # A bearer token is a client that is not a browser (MCP, scripts): it
    # cannot be made to send one cross-site. Basic or Negotiate CAN be — a
    # browser behind a signing-in proxy attaches them to every request on its
    # own — so they pass no further than any other request.
    if kind == "http" and h.get("authorization", "").strip().lower().startswith("bearer "):
        return ""
    site = h.get("sec-fetch-site", "").strip().lower()
    if site in PASSING_SITES:
        return ""
    if site:
        return f"sent from another {site} page"
    origin = h.get("origin", "").strip()
    if not origin:
        return ""
    if origin.lower() == "null":
        return "sent from an opaque origin"
    try:
        u = urllib.parse.urlsplit(origin)
    except ValueError:
        # `https://[bad` makes urlsplit raise. A header nobody's browser
        # would send is refused -- and it must not become a 500 on the way.
        return "the Origin header is not an origin"
    if not u.scheme or not u.netloc:
        return "the Origin header is not an origin"
    if _hostport(u.netloc) in trusted(h):
        return ""
    return f"sent from {u.scheme}://{u.netloc}"


class CrossOriginGuard:
    """Pure ASGI, so it sees websockets as well as requests -- an
    `@app.middleware("http")` function never runs for a socket, which is how
    every socket in the product came to have no check at all."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        why = refusal(scope)
        if not why:
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        log.warning("cross-origin %s refused: %s %s",
                    "socket" if scope["type"] == "websocket" else "request",
                    path, why)
        if scope["type"] == "websocket":
            # Answer the handshake with a close BEFORE accepting it, which the
            # server turns into an HTTP 403 -- the socket never opens, so no
            # handler runs and nothing on the far side is touched.
            msg = await receive()
            if msg.get("type") == "websocket.connect":
                await send({"type": "websocket.close", "code": 1008,
                            "reason": "cross-origin socket refused"})
            return None
        body = (b"This request came from another page, so it was refused. "
                b"Open the portal itself and try again.\n")
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
        return None
