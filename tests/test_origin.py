"""Cross-origin requests and sockets are refused; the portal's own are not.

See app/origin.py for why: SameSite=Lax lets a SIBLING subdomain's page carry
the session cookie, and a WebSocket handshake is exempt from CORS, so without
this a page on anything.example.com could drive a live PAM shell as whoever
was signed in. Every rule is pinned here against the real app, through the
real middleware stack, because a rule that is right in isolation and bypassed
by the order the middleware is added in protects nothing.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("origin-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from app import env, main, origin  # noqa: E402

bad = 0


def check(name, ok, detail=""):
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + name
          + (f"  [{detail}]" if detail and not ok else ""))


def scope(method="POST", kind="http", **hdrs):
    return {"type": kind, "method": method,
            "headers": [(k.replace("_", "-").encode(), v.encode())
                        for k, v in hdrs.items()]}


def rules() -> None:
    print("the decision, rule by rule")
    r = origin.refusal
    check("a GET passes whatever it says",
          r(scope("GET", host="portal.example.com",
                  origin="https://evil.example")) == "")
    check("a POST from the portal's own page passes",
          r(scope(host="portal.example.com",
                  origin="https://portal.example.com")) == "")
    check("a POST from another origin is refused",
          r(scope(host="portal.example.com", origin="https://evil.example")) != "")
    check("a POST from a SIBLING subdomain is refused (same-site is not same-origin)",
          r(scope(host="envmap.example.com",
                  origin="https://other.example.com",
                  sec_fetch_site="same-site")) != "")
    check("Sec-Fetch-Site: same-origin passes on the browser's word",
          r(scope(host="internal-svc:8471", origin="https://portal.example.com",
                  sec_fetch_site="same-origin")) == "")
    check("Sec-Fetch-Site: none passes (typed into the address bar)",
          r(scope(host="portal.example.com", sec_fetch_site="none")) == "")
    check("cross-site with no Origin is refused",
          r(scope(host="portal.example.com", sec_fetch_site="cross-site")) != "")
    # The Host comparison cannot see a scheme; the browser can. http://portal
    # posting to https://portal is cross-site to it, and its word is final.
    check("the browser's cross-site verdict wins over a matching Origin",
          r(scope(host="portal.example.com", origin="http://portal.example.com",
                  sec_fetch_site="cross-site")) != "")
    check("and so does same-site, from the portal's own host name",
          r(scope(host="portal.example.com", origin="https://portal.example.com",
                  sec_fetch_site="same-site")) != "")
    # A caller's own credential is not a ridden cookie: a page cannot add an
    # Authorization header cross-origin without CORS consent, never given.
    check("a request carrying its own bearer token passes (MCP from a browser)",
          r(scope(host="portal.example.com", origin="https://evil.example",
                  authorization="Bearer x", sec_fetch_site="cross-site")) == "")
    check("but a socket is never excused by one",
          r(scope("GET", "websocket", host="portal.example.com",
                  origin="https://evil.example", authorization="Bearer x")) != "")
    check("no browser headers at all passes (curl, a script, an MCP client)",
          r(scope(host="portal.example.com")) == "")
    check("an opaque origin is refused",
          r(scope(host="portal.example.com", origin="null")) != "")
    check("a default port on either side is the same place",
          r(scope(host="portal.example.com:443",
                  origin="https://portal.example.com")) == ""
          and r(scope(host="portal.example.com",
                      origin="http://portal.example.com:80")) == "")
    check("a different port is a different origin",
          r(scope(host="portal.example.com",
                  origin="https://portal.example.com:8443")) != "")
    check("host names compare case-insensitively",
          r(scope(host="Portal.Example.COM",
                  origin="https://portal.example.com")) == "")
    check("IPv6 hosts compare as hosts",
          r(scope(host="[::1]:8471", origin="http://[::1]:8471")) == "")
    check("a proxy's X-Forwarded-Host is believed",
          r(scope(host="svc.ns.svc:8471", x_forwarded_host="portal.example.com",
                  origin="https://portal.example.com")) == "")
    saved = env.BASE_URL
    try:
        env.BASE_URL = "https://portal.example.com/"
        check("PORTAL_BASE_URL is believed",
              r(scope(host="10.0.0.5:8471",
                      origin="https://portal.example.com")) == "")
    finally:
        env.BASE_URL = saved
    check("a WebSocket is never a safe method (the handshake is a GET)",
          r(scope("GET", "websocket", host="portal.example.com",
                  origin="https://evil.example")) != "")
    check("the portal's own socket passes",
          r(scope("GET", "websocket", host="portal.example.com",
                  origin="https://portal.example.com")) == "")
    check("a garbage Origin is refused, not crashed on",
          r(scope(host="portal.example.com", origin="https://[bad")) != "")
    check("and a garbage Host cannot widen the trusted set",
          r(scope(host="[bad", origin="https://evil.example")) != "")


def through_the_app() -> None:
    print("through the real middleware stack")
    c = TestClient(main.app)
    r = c.post("/login", data={"email": "x@y.z", "password": "p"},
               headers={"origin": "https://evil.example"},
               follow_redirects=False)
    check(f"a cross-origin form post is answered 403 ({r.status_code})",
          r.status_code == 403 and "another page" in r.text)
    r = c.post("/login", data={"email": "x@y.z", "password": "p"},
               headers={"origin": "http://testserver"}, follow_redirects=False)
    check(f"the portal's own post reaches the route ({r.status_code})",
          r.status_code != 403)
    r = c.post("/login", data={"email": "x@y.z", "password": "p"},
               follow_redirects=False)
    check(f"a post with no browser headers reaches the route ({r.status_code})",
          r.status_code != 403)
    r = c.get("/healthz", headers={"origin": "https://evil.example"})
    check("a cross-origin GET is not refused", r.status_code == 200)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
               headers={"origin": "https://evil.example",
                        "authorization": "Bearer not-a-real-token"})
    check(f"a bearer-token call reaches the MCP door, not the guard "
          f"({r.status_code})", "another page" not in r.text)

    for path in ("/pam/ssh.ws?tid=x", "/pam/guac.ws?tid=x",
                 "/pam/session/ps-000000000000/shadow.ws",
                 "/clusters/pty.ws", "/ansible/host.ws",
                 "/provision/vm/console.ws"):
        code = None
        try:
            with c.websocket_connect(path, headers={
                    "origin": "https://evil.example"}) as ws:
                ws.receive_text()
        except WebSocketDisconnect as e:
            code = e.code
        except Exception as e:                                   # noqa: BLE001
            code = getattr(e, "code", type(e).__name__)
        check(f"{path.split('?')[0]} refuses another origin before it opens "
              f"({code})", code == 1008)
    said = ""
    try:
        with c.websocket_connect("/pam/ssh.ws?tid=x", headers={
                "origin": "http://testserver"}) as ws:
            said = ws.receive_text()
    except WebSocketDisconnect as e:
        said = f"closed {e.code}"
    # Signed out, so the handler's OWN gate answers -- which proves the socket
    # was let through the origin check and reached it.
    check(f"the portal's own origin reaches the socket's own gate ({said!r})",
          "Privileged Access" in said)


def order() -> None:
    print("it is the OUTERMOST layer")
    # Added last means it wraps everything else, so nothing -- the session
    # parse, the login redirect, a route -- runs for a refused request.
    stack = [m.cls.__name__ for m in main.app.user_middleware]
    check(f"CrossOriginGuard wraps the session middleware ({stack[:3]})",
          stack and stack[0] == "CrossOriginGuard")


if __name__ == "__main__":
    rules()
    through_the_app()
    order()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
