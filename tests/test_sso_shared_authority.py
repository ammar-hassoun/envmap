#!/usr/bin/env python3
"""Microsoft's shared endpoints are not a tenant -- app/sso.py.

WHY THIS EXISTS
    A tenant could be saved as `common`, `organizations` or `consumers`. Those
    are Microsoft's endpoints for EVERY directory, so a sign-in sent there is
    pinned to nothing; the save went through because "the endpoint still pins
    it", and the directory comparison was skipped because no GUID could be
    looked up for them. With a multi-tenant app registration, anybody could
    make a free Entra tenant, give an account the email of an EnvMap
    administrator, and sign in as that administrator ("nOAuth", 2023).

    Proved here, through the real routes, with Microsoft's endpoints faked:
      * the form refuses each shared endpoint, in any spelling, and stores
        nothing
      * a row ALREADY stored that way (an older install) is refused at sign-in
        before the code is ever exchanged
      * a tenant typed as a domain whose directory was never confirmed is
        looked up at sign-in, and an account from another directory is
        refused; when the lookup fails, the sign-in is refused, not trusted
      * the ordinary case, a GUID tenant, still signs in

    ./.venv/bin/python tests/test_sso_shared_authority.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ssoshared-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, sso, store                     # noqa: E402
import test_sso_tenants as h                                   # noqa: E402

bad = 0
OUR = "aaaaaaaa-1111-2222-3333-444444444444"
EVIL = "eeeeeeee-1111-2222-3333-444444444444"
APP = "11111111-aaaa-bbbb-cccc-dddddddddddd"
SHARED_NAMES = {"common", "organizations", "consumers"}


def is_shared(tenant: str) -> bool:
    # The test's own copy, so it runs (and fails) against code without the fix.
    return (tenant or "").strip().strip("/").lower() in SHARED_NAMES


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
    print(("  ok   " if cond else "  FAIL ") + what)


def store_row(tenant: str, tid: str = "") -> None:
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('sso', ?)",
           (json.dumps({"enabled": True, "client_id": APP,
                        "client_secret": "s", "tenants": [
                            {"id": "t-1", "tenant": tenant, "tid": tid}]}),))
    store.invalidate()


def sign_in_as(claims: dict, discovery: dict | None = None):
    """Like test_sso_tenants.sign_in, but the fake also answers the discovery
    document, and records every URL asked -- so a refusal BEFORE the code
    exchange can be told apart from one after it."""
    c = TestClient(main.app)
    r = c.get("/login/microsoft", follow_redirects=False)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(
        r.headers.get("location", "")).query)
    state, nonce = q.get("state", [""])[0], q.get("nonce", [""])[0]
    asked = []

    def fake(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        asked.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            if discovery is None:
                raise OSError("no route to login.microsoftonline.com")
            return h._Reply(json.dumps(discovery).encode())
        return h._Reply(json.dumps({"id_token": h._id_token({
            "exp": time.time() + 600, "nonce": nonce, "aud": APP,
            "name": "X", "oid": "o", **claims})}).encode())

    real = sso.urlguard.urlopen
    sso.urlguard.urlopen = fake
    try:
        r = c.get(f"/auth/microsoft/callback?code=x&state={state}",
                  follow_redirects=False)
    finally:
        sso.urlguard.urlopen = real
    return r, asked


def exchanged(asked: list) -> bool:
    return any(u.endswith("/oauth2/v2.0/token") for u in asked)


def main_test() -> int:
    c = h.admin_client()
    auth.create_sso_user("boss@northwind.example", "Boss")

    print("the form refuses Microsoft's shared endpoints")
    for spelling in ("common", "organizations", "Consumers", " ORGANIZATIONS ",
                     "organizations/"):
        r = c.post("/admin/sso", data={
            "enabled": "1", "client_id": APP, "client_secret": "s",
            "t_id": [""], "t_label": ["Us"], "t_tenant": [spelling],
            "t_domains": ["northwind.example"], "t_client_id": [""],
            "t_client_secret": [""]}, follow_redirects=False)
        check(f"{spelling!r} is refused in place ({r.status_code})",
              r.status_code == 200 and "endpoint for every directory" in r.text)
        check("  and nothing was stored",
              not any(is_shared(t["tenant"])
                      for t in sso.config()["tenants"]))
    check("the Test button says the same",
          not sso.test("organizations")[0]
          and "every directory" in sso.test("organizations")[1])

    print("a row already stored that way is refused at sign-in")
    store_row("organizations")
    r, asked = sign_in_as({"tid": EVIL, "email": "boss@northwind.example"})
    check("the administrator's address from another tenant does not get in",
          h.refused_with(r, "shared endpoint"))
    check("and the code was never exchanged", not exchanged(asked))

    print("a domain tenant whose directory was never confirmed")
    store_row("northwind.example")
    disco = {"issuer": f"https://login.microsoftonline.com/{OUR}/v2.0"}
    r, _ = sign_in_as({"tid": EVIL, "email": "boss@northwind.example"}, disco)
    check("is looked up, and an account from another directory is refused",
          h.refused_with(r, "different tenant"))
    r, _ = sign_in_as({"tid": OUR, "email": "boss@northwind.example"}, disco)
    check("while its own directory signs in", h.landed_home(r))
    r, asked = sign_in_as({"tid": OUR, "email": "boss@northwind.example"}, None)
    check("and when the lookup fails the sign-in is refused, not trusted",
          h.refused_with(r, "could not be confirmed") and not exchanged(asked))

    print("the ordinary case is unchanged")
    store_row(OUR)
    r, _ = sign_in_as({"tid": OUR, "email": "boss@northwind.example"})
    check("a GUID tenant signs in", h.landed_home(r))
    r, _ = sign_in_as({"tid": EVIL, "email": "boss@northwind.example"})
    check("and another directory is still refused",
          h.refused_with(r, "different tenant"))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
