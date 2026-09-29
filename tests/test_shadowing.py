#!/usr/bin/env python3
"""base.html must not quietly take a name a page is using.

WHY THIS EXISTS
    base.html is the parent of nearly every page, and anything it binds at its
    own top level — a macro, or a `{% set %}` — is visible inside the child's
    blocks. When the child was passed a context value under the same name, the
    parent's wins, and the page reads something it never asked for.

    Nothing about the failure points at the cause:

      * a macro called `link` rendered a console URL as "<Macro 'link'>", which
        came back from Alibaba as "The specified InstanceId does not exist"
      * a loop variable in the top bar called `ns` shadowed the Kubernetes
        namespace the cluster page passes under that name. The page handed a
        Jinja Namespace object to |tojson and answered 500 — from a line in a
        different template, on a page whose own code had not changed
      * `lic` had been shadowed since the licence banner was written. That one
        never showed, because the banner's value happened to be a superset of
        the route's, so the settings page read the right fields by luck

    A THIRD SHADOW, found by a 500 on the service page: a dict field whose
    name is also a dict METHOD. Jinja resolves `row.keys` by trying getattr
    first, so it answers with the bound `dict.keys` method and never looks for
    the item — `row.keys|length` is then "object of type
    builtin_function_or_method has no len()", raised from a template line that
    looks correct. Where it does not raise it is worse: `{{ c.items }}` printed
    "<built-in method items of dict object at 0x…>" on the Monitoring page, and
    `{% if c.items %}` was true whatever the count was, because a method is
    truthy. That had been shipping.

    It is the same failure as the two above — a name collision where one of the
    two names is invisible — so it is checked here rather than somewhere new.

    Three halves, because each alone would have missed one of those:

      1. the STATIC half — every name base.html binds is compared against what
         ctx() is actually called with, so a collision is a failing test rather
         than a page nobody opens for a month
      2. the LIVE half — a real request through a real child template, checking
         that a context value survives into the block. This is the one that
         would have caught `ns`: the guard in ctx() only fires for names it
         knows, and this proves the mechanism it is guarding against
      3. the DICT-METHOD half — every Jinja expression in every template, for a
         field read as `x.keys`, `x.items`, `x.get` and the rest. Restricted to
         Jinja expressions on purpose: the same spellings are ordinary
         JavaScript, and `_combo_js.html` is full of `api.items` that is none of
         Jinja's business

    ./.venv/bin/python tests/test_shadowing.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("shadow-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi import Request                                    # noqa: E402
from fastapi.responses import HTMLResponse                     # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, store                          # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main_test() -> int:
    print("the guard knows every name base.html binds")
    base = (ROOT / "templates" / "base.html").read_text()
    macros = set(re.findall(r"{%-?\s*macro\s+([A-Za-z_][A-Za-z0-9_]*)", base))
    sets = set(re.findall(r"{%-?\s*set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", base))
    for name in sorted(macros | sets):
        check(f"{name} is in SHADOWED", name in main.SHADOWED)
    check("and macros are still covered", macros <= main.SHADOWED)
    # `set` was the half that was missing, and the half that cost a 500.
    check("and so are top-level sets", bool(sets) and sets <= main.SHADOWED)

    print("no route passes a name base.html has taken")
    src = (ROOT / "app" / "main.py").read_text()
    # Every ctx(...) call's keyword arguments, read from the source rather than
    # by importing: a route that only runs on a live cluster still counts.
    passed = set()
    for call in re.findall(r"ctx\(request[^)]*\)", src, re.S):
        passed |= set(re.findall(r"[,(]\s*([a-z_][a-z0-9_]*)\s*=", call))
    clash = passed & main.SHADOWED
    check(f"nothing collides, got {sorted(clash)}", not clash)

    print("and nothing base.html CALLS can be taken by a route either")
    # The same fault from the other direction, and it cost a second 500. The
    # top bar used Jinja's `namespace()` to group the picker; the pod-log page
    # passes its own `namespace` — the Kubernetes one — which replaced the
    # global with a string, and base.html died on "'str' object is not
    # callable". Anything base.html invokes has to be a name no page passes.
    called = set(re.findall(r"[{%]{1,2}[^{}]*?\b([a-z_][a-z0-9_]*)\s*\(", base))
    taken = sorted(called & passed)
    check(f"nothing base.html calls is passed by a route, got {taken}", not taken)

    print("no template reads a dict field whose name is a dict method")
    # The rule: inside a Jinja expression, `x.<dict method>` that is not being
    # CALLED is always wrong. Either it is a field of that name — which Jinja
    # cannot reach, because the method wins — or it is the method itself used as
    # a value, which renders as "<built-in method …>". Calling it, `x.items()`,
    # is fine and common, so the check turns on the absence of the parenthesis.
    DICT_METHODS = ("keys", "items", "values", "get", "copy", "pop", "update",
                    "clear", "setdefault", "popitem", "fromkeys")
    jinja = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
    shadowed = re.compile(r"\b([a-z_]\w*)\.(" + "|".join(DICT_METHODS)
                          + r")\b(?!\s*\()")
    found = []
    for f in sorted((ROOT / "templates").glob("*.html")):
        for region in jinja.finditer(f.read_text()):
            for m in shadowed.finditer(region.group(0)):
                found.append(f"{f.name}: {m.group(0)} in {region.group(0).strip()[:44]!r}")
    check(f"nothing reads a dict method as a value ({len(found)}):"
          + "".join("\n      " + x for x in found[:8]), not found)

    print("a context value survives into the child's block")
    # The live half. `ns` is the real case: the cluster page passes the selected
    # Kubernetes namespace under that name, and the top bar's shortcuts are what
    # binds names at base.html's top level.
    probe = ROOT / "templates" / "_probe_shadow.html"
    probe.write_text('{% extends "base.html" %}'
                     '{% block content %}NS=[{{ ns }}] LIC=[{{ lic }}]{% endblock %}')

    @main.app.get("/_probe_shadow", response_class=HTMLResponse)
    def _probe(request: Request):
        return main.templates.TemplateResponse(
            request, "_probe_shadow.html",
            main.ctx(request, ns="kube-system", lic="from-the-route"))

    try:
        email, pw = "shadow@test.invalid", "Passw0rd!xY"
        uid = auth.create_user(email, "S", pw, role="admin")
        db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
               ("TESTSECRET", uid))
        pid = store.add_project("Shadow")
        cid = store.add_cluster(pid, "c1", "apiVersion: v1\n", "ctx1")
        # The shortcuts only draw when there is somewhere to point them, and it
        # is the drawing that binds the names.
        store.update_cluster(pid, cid, manage="1")
        client = TestClient(main.app, raise_server_exceptions=False)
        with client:
            client.post("/login", data={"email": email, "password": pw},
                        follow_redirects=False)
            u = auth.by_email(email)
            client.post("/mfa", data={"code": auth._totp_at(
                u["totp_secret"], int(time.time() // auth.TOTP_STEP))},
                follow_redirects=False)
            page = client.get("/_probe_shadow", follow_redirects=True).text
            check("the top bar's shortcuts drew, so base.html did bind names",
                  'data-quick="shell"' in page)
            check(f"ns is the route's value, not base.html's "
                  f"({page[page.find('NS=['):page.find('NS=[') + 40]})",
                  "NS=[kube-system]" in page)
            check("and so is lic", "LIC=[from-the-route]" in page)
    finally:
        probe.unlink(missing_ok=True)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
