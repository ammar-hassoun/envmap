#!/usr/bin/env python3
"""Everything the app imports is something the IMAGE will have.

WHY THIS EXISTS
    0.6.0 was built, signed, published and announced to every managed customer,
    and it could not start. `app/provision.py` imports `httpx` at module level;
    `httpx` was in requirements-DEV.txt, whose comment said in as many words
    "the portal itself does not [need an HTTP client]". That stopped being true
    the day the Proxmox client was written and nothing noticed.

    Nothing noticed because every way we look at the code has httpx present.
    The suite runs in a venv with the dev requirements installed. The linters
    import fine. The release workflow asks the image what version it is — which
    imported other modules, never `app.main`, so the one module that would have
    blown up was never touched. The failure surfaced on a cluster, as
    CrashLoopBackOff, after the announcement had gone out.

    So: read every third-party module `app/` imports and require it to be
    accounted for. A dependency is accounted for when requirements.txt declares
    it, or when it is on the short list below of things that arrive WITH a
    declared package and are therefore always in the image.

    THE POINT IS THE UNKNOWN CASE. A new import that is neither declared nor
    listed fails here, at the commit that adds it, instead of on somebody's
    cluster. Adding a line to `BUNDLED` is a deliberate claim that the module
    ships with something already declared — make it only when that is true.

    ./.venv/bin/python tests/test_deps.py
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Module name → the declared package it arrives with. Every one of these is a
# hard dependency of something in requirements.txt, so it is in the image
# whether or not we name it; declaring them separately would be pinning
# somebody else's transitive tree.
BUNDLED = {
    "anyio": "starlette",          # starlette requires it outright
    "markupsafe": "jinja2",        # jinja2 requires it outright
    "websockets": "uvicorn",       # uvicorn[standard]'s WebSocket implementation
}

# Import name → distribution name, where they differ. Only needed for the ones
# that are not simply the same word.
DIST = {
    "yaml": "pyyaml",
    "ruamel": "ruamel.yaml",
    "pymysql": "pymysql",
    "multipart": "python-multipart",
}

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def declared() -> set:
    """The distribution names requirements.txt asks for, lowercased.

    Extras and version pins are stripped: `psycopg[binary]==3.2.*` is a
    declaration of `psycopg`, and a test that missed it because of the extra
    would send somebody hunting for a dependency that is right there.
    """
    out = set()
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        name = re.split(r"[<>=!~\[]", line)[0].strip().lower()
        if name:
            out.add(name)
    return out


def imports_of(folder: str) -> dict:
    """Third-party top-level modules imported under `folder`, → the files."""
    std = set(sys.stdlib_module_names)
    found: dict = {}
    for f in sorted((ROOT / folder).glob("*.py")):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:                     # relative: our own code
                    continue
                mods = [node.module or ""]
            else:
                continue
            for m in mods:
                top = m.split(".")[0]
                if top and top not in std and top != "app":
                    found.setdefault(top, set()).add(f.name)
    return found


def image_trusts_its_ingress() -> None:
    """The app must be able to tell that it is reached over https.

    It could not. uvicorn parses X-Forwarded-Proto only from a peer on its
    trust list, and that list defaults to 127.0.0.1 — sensible behind a local
    nginx, wrong for a container behind an ingress. So Traefik's headers were
    discarded and the portal concluded it was on http at its own hostname
    while the browser was on https.

    Silent until something derives a URL from the request, and then badly
    wrong: passkeys refused outright (WebAuthn is secure-context only), the
    SSO redirect URI came out with the wrong scheme, and invitation links
    would have been http. Checked here because it is a property of the IMAGE,
    and because nothing running outside a container reproduces it — the same
    reason the ansible tool-path check lives beside it.
    """
    print("the image trusts the ingress in front of it")
    dockerfile = (ROOT / "Dockerfile").read_text()
    # The ENV DIRECTIVE, not any mention of the name: the first version of this
    # check was satisfied by the explanatory comment beside it, so deleting the
    # assignment passed. A test that its own documentation can satisfy is not a
    # test.
    env_block = ""
    for stanza in dockerfile.split("\nENV ")[1:]:
        # a backslash-continued ENV runs until the first line that does not
        # continue it
        lines, out = stanza.splitlines(), []
        for ln in lines:
            out.append(ln)
            if not ln.rstrip().endswith("\\"):
                break
        env_block += "\n".join(out) + "\n"
    # A PROXY THAT EATS PING/PONG KILLS A HEALTHY SOCKET. uvicorn's default is
    # ping every 20s and close after 20s without a pong, which is about forty
    # seconds — exactly the window a browser seat needs to be scheduled and
    # started, and a window in which the socket carries nothing upstream.
    # Reported from an install behind a cloud load balancer as
    # `keepalive ping timeout` on a blank pane.
    entry = "".join(ln for ln in dockerfile.split("\n")
                    if "uvicorn" in ln or "--ws-ping" in ln)
    check("the websocket keepalive timeout is relaxed for slow starts",
          "--ws-ping-timeout" in entry and "--ws-ping-interval" in entry)

    check(f"FORWARDED_ALLOW_IPS is ASSIGNED in an ENV directive, or uvicorn "
          f"discards the proxy headers",
          "FORWARDED_ALLOW_IPS=" in env_block)
    # Naming the reason next to it: the value is a security decision, not a
    # magic string, and the next person should find the argument rather than
    # the conclusion.
    check("and the reason is written down beside it",
          "secure-context" in dockerfile or "X-Forwarded-Proto" in dockerfile)
    # proxy_headers itself defaults to True in the uvicorn that is pinned, so
    # the trust list is the whole fix. If a future uvicorn flips that default,
    # this is the check that should start failing.
    from uvicorn.config import Config
    import inspect
    default = inspect.signature(Config.__init__).parameters["proxy_headers"].default
    check(f"uvicorn still parses the headers by default ({default})",
          default is True)


def main() -> int:
    have = declared()
    print(f"requirements.txt declares {len(have)} packages")

    print("every third-party import in app/ is in the image")
    used = imports_of("app")
    unaccounted = []
    for mod, files in sorted(used.items()):
        if mod in BUNDLED:
            # The claim has to be true: the thing it ships with must itself be
            # declared, or this is two undeclared dependencies rather than one.
            check(f"{mod} rides on {BUNDLED[mod]}, which is declared",
                  BUNDLED[mod].lower() in have)
            continue
        if DIST.get(mod, mod).lower() in have:
            continue
        unaccounted.append(f"{mod} (imported by {', '.join(sorted(files))})")
    check(f"nothing is imported that the image will not have: {unaccounted}",
          not unaccounted)

    print("the one that got through, specifically")
    # Named rather than left to the general rule: this is the import that was
    # published broken, and a regression here is the same outage again.
    check("httpx is a runtime dependency, not a dev one",
          "httpx" in have)
    check("and requirements-dev.txt no longer claims the portal has no HTTP "
          "client",
          "the portal itself does not" not in
          (ROOT / "requirements-dev.txt").read_text().lower())
    check("provision.py is still the reason (if it stops importing httpx, this "
          "test's story is out of date)",
          "import httpx" in (ROOT / "app" / "provision.py").read_text())

    print("the check covers the module the release gate does not")
    # The workflow asks the image its version. The
    # module that crashed was app.main. If app/ ever shrinks to nothing this
    # test would pass vacuously, so the corpus is asserted too.
    check(f"app/ has modules to check ({len(used)} third-party imports found)",
          len(used) >= 8)
    check("including the entrypoint the container actually runs",
          (ROOT / "app" / "main.py").exists())

    image_trusts_its_ingress()

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
