#!/usr/bin/env python3
"""The Content-Security-Policy, and the discipline that lets it be strict.

WHY THIS EXISTS
    Recorded as SEC-8 while fixing SEC-7, and it is why that finding mattered:
    a stored `javascript:` URL, an operator's name in a `title`, a connection
    name in an `aria-label` — each was a way to get markup onto a page, and
    each became CODE EXECUTION in an admin's session because nothing stopped
    the browser running it. This product holds kubeconfigs, git tokens and
    brokered SSH credentials, so script in a reader's session reaches all of
    them.

    The policy is worth nothing if it carries `unsafe-inline`, because that
    keyword permits an inline <script> AND an on* attribute and no directive
    separates the two. So the whole mechanism rests on two properties that a
    single careless edit restores:

      1. **No template contains an inline on* handler.** 112 were converted to
         data attributes driven by one delegated listener. The next person to
         write `onclick=` will not have read this file, so the check is a
         SWEEP of every template rather than a list — a list cannot find the
         copy nobody added to it, which is the lesson test_placesync_js.py
         already learned the expensive way.
      2. **Every <script> carries the request's nonce.** One that does not is
         a script the browser silently refuses to run, and silent is the
         problem: the page renders, and only the behaviour is missing.

    ./.venv/bin/python tests/test_csp.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("csp-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = sorted((ROOT / "templates").glob("*.html"))
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def strip_comments(text: str) -> str:
    """Jinja comments only. Prose explaining the rule is not a breach of it."""
    return re.sub(r"\{#.*?#\}", "", text, flags=re.S)


def main() -> int:
    from fastapi.testclient import TestClient

    from app import auth, csp, db, main

    print("the policy itself")
    pol = csp.policy("NONCEVALUE")
    parts = dict(p.strip().split(" ", 1) for p in pol.split(";"))
    check("script-src carries the nonce", "'nonce-NONCEVALUE'" in parts["script-src"])
    # The one that makes the rest worth having.
    check("script-src has no 'unsafe-inline'", "unsafe-inline" not in parts["script-src"])
    check("script-src has no 'unsafe-eval'", "unsafe-eval" not in parts["script-src"])
    check("nothing may be framed", parts["frame-ancestors"] == "'none'")
    check("<base> cannot be retargeted", parts["base-uri"] == "'self'")
    check("a form cannot post off-origin", parts["form-action"] == "'self'")
    # Script that runs and cannot phone home is the fallback for the day the
    # gate above fails, and the two fail independently.
    check("nothing may be sent off-origin", parts["connect-src"] == "'self'")
    check("style-src is knowingly still open",
          "unsafe-inline" in parts["style-src"])

    print("every template obeys the two rules the policy rests on")
    handler = re.compile(r"\bon(click|change|input|submit|keydown|keyup|focus|"
                         r"blur|load|error|mouse\w+|touch\w+)\s*=\s*[\"']")
    offenders, unnonced = [], []
    for f in TEMPLATES:
        text = strip_comments(f.read_text())
        if handler.search(text):
            offenders.append(f.name)
        for m in re.finditer(r"<script(\s[^>]*)?>", text):
            if "nonce=" not in (m.group(1) or ""):
                unnonced.append(f"{f.name}: {m.group(0)[:50]}")
    check(f"no inline on* handler in any of {len(TEMPLATES)} templates "
          f"({', '.join(offenders[:4])})", not offenders)
    check(f"every <script> carries a nonce ({'; '.join(unnonced[:3])})", not unnonced)

    print("and the SVG the diagram builds in Python, which no template sweep sees")
    src = (ROOT / "app" / "diagram.py").read_text()
    check("the topology's own script is nonced", 'nonce="{csp.nonce()}"' in src)

    print("served: the header is on a page, and the nonce is the page's own")
    email, pw = "csp@test.local", "Policy-Holds-Here-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    try:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        page = c.get("/")
        sent = page.headers.get("content-security-policy", "")
        check("the header is sent", "script-src" in sent)
        check("nosniff rides along",
              page.headers.get("x-content-type-options") == "nosniff")

        served = re.search(r"script-src [^;]*'nonce-([^']+)'", sent)
        check("the served policy carries a nonce", served is not None)
        if served:
            n = served.group(1)
            tags = re.findall(r'<script[^>]*nonce="([^"]*)"', page.text)
            check(f"the page has nonced scripts ({len(tags)})", bool(tags))
            # The whole mechanism: a tag whose nonce is not the header's is a
            # script the browser refuses, and nothing on the page says so.
            check("every script's nonce is the one the header authorised",
                  all(t == n for t in tags))

        # A nonce reused across requests is a nonce an attacker can read off
        # one page and paste into an injection on the next.
        second = c.get("/")
        other = re.search(r"'nonce-([^']+)'",
                          second.headers.get("content-security-policy", ""))
        check("a second request gets a different nonce",
              served and other and other.group(1) != served.group(1))

        # A year-long immutable cache and a per-request nonce cannot both be
        # right about the same bytes.
        st = c.get("/static/app.css?v=test")
        check("static files carry no policy",
              "content-security-policy" not in {k.lower() for k in st.headers})
    finally:
        c.__exit__(None, None, None)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
