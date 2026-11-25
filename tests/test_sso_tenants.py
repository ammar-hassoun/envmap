#!/usr/bin/env python3
"""Microsoft sign-in from more than one tenant — app/sso.py.

WHY THIS EXISTS
    One tenant was the whole model: a single tenant id, a single button, and a
    sign-in pinned to that directory. Asked for: several organisations, each
    signing in from its own Entra tenant. What a second tenant changes is not
    the button, it is who can claim whom:

      * a portal account is found by EMAIL, and the email claim is whatever the
        account's own directory says. Any trusted tenant's admin can give an
        account somebody else's address, so each tenant answers only for its
        own email domains, and listing them is required once there are two
      * the answer must come from the tenant the sign-in was SENT to — checked
        by its directory id, and with the tenant carried in the session, never
        read back off the URL Microsoft returns to
      * one shared application, or a tenant's own; a stored secret survives a
        save that does not retype it, matched by the row's id and never by its
        position in the list
      * a refused save comes back as the form with the submission in it

    Everything runs through the real routes. Microsoft's token endpoint is
    replaced by a stand-in that records where it was asked and answers with
    the claims a test chooses.

    ./.venv/bin/python tests/test_sso_tenants.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ssotenants-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, sso, store                     # noqa: E402

bad = 0
A_TID = "aaaaaaaa-1111-2222-3333-444444444444"
B_TID = "bbbbbbbb-1111-2222-3333-444444444444"
SHARED = "11111111-aaaa-bbbb-cccc-dddddddddddd"
B_APP = "22222222-aaaa-bbbb-cccc-dddddddddddd"
PW = "Sso-Tenants-Admin-42"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def admin_client() -> TestClient:
    uid = auth.create_user("tenants-admin@test.local", "CI", PW, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "tenants-admin@test.local", "password": PW},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


class _Reply:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


def _id_token(claims: dict) -> str:
    def part(d):
        return base64.urlsafe_b64encode(
            json.dumps(d).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


def two_tenants(c: TestClient, **over) -> object:
    """Save Northwind (shared app) and Fabrikam East (its own app) through the
    real form, as the dialog posts it."""
    data = {"enabled": "1", "client_id": SHARED, "client_secret": "shared-s",
            "t_id": ["", ""], "t_label": ["Northwind", "Fabrikam East"],
            "t_tenant": [A_TID, B_TID],
            "t_domains": ["northwind.example", "fabrikam.co.example, @fabrikam.example"],
            "t_client_id": ["", B_APP], "t_client_secret": ["", "b-own-s"]}
    data.update(over)
    return c.post("/admin/sso", data=data, follow_redirects=False)


def sign_in(start: str, claims: dict, callback_extra: str = ""):
    """Press a sign-in button and come back with `claims`. -> (the callback's
    response, the token endpoint that was asked, what was posted to it)."""
    c = TestClient(main.app)
    r = c.get(start, follow_redirects=False)
    loc = r.headers.get("location", "")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
    state, nonce = q.get("state", [""])[0], q.get("nonce", [""])[0]
    seen = []

    def fake(req, timeout=None):
        seen.append((req.full_url, urllib.parse.parse_qs(
            (req.data or b"").decode())))
        return _Reply(json.dumps({"id_token": _id_token({
            "exp": time.time() + 600, "nonce": nonce, "name": "P",
            "oid": "o", **claims})}).encode())

    real = sso.urlguard.urlopen
    sso.urlguard.urlopen = fake
    try:
        r = c.get(f"/auth/microsoft/callback?code=x&state={state}"
                  + callback_extra, follow_redirects=False)
    finally:
        sso.urlguard.urlopen = real
    url, posted = seen[-1] if seen else ("", {})
    return r, loc, url, posted


def landed_home(r) -> bool:
    return r.status_code == 303 and r.headers.get("location") == "/"


def refused_with(r, words: str) -> bool:
    loc = urllib.parse.unquote(r.headers.get("location", ""))
    return r.status_code == 303 and loc.startswith("/login?err=") \
        and words in loc


def main_test() -> int:
    c = admin_client()
    auth.create_sso_user("dana@northwind.example", "Dana")
    auth.create_sso_user("kai@fabrikam.co.example", "Kai")

    print("an install upgrading from one tenant changes nothing")
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('sso', ?)",
           (json.dumps({"enabled": True, "tenant": A_TID,
                        "client_id": SHARED, "client_secret": "shared-s"}),))
    store.invalidate()
    cfg = sso.config()
    check("the old row reads as one tenant",
          [t["tenant"] for t in cfg["tenants"]] == [A_TID] and sso.ready())
    page = TestClient(main.app).get("/login").text
    check("and the sign-in page keeps its one plain button",
          page.count('class="sso" href="/login/microsoft') == 1
          and "Sign in with Microsoft ·" not in page
          and "/login/microsoft?next=" in page)
    r, _loc, _u, _p = sign_in("/login/microsoft", {
        "aud": SHARED, "tid": A_TID, "email": "dana@northwind.example"})
    check("and signs in exactly as before", landed_home(r))

    print("two tenants, saved through the form")
    r = two_tenants(c)
    check(f"the save goes through, got {r.status_code} "
          f"{urllib.parse.unquote(r.headers.get('location', ''))}",
          r.status_code == 303 and "sso_err" not in r.headers.get("location", ""))
    cfg = sso.config()
    ts = {t["label"]: t for t in cfg["tenants"]}
    check("both are stored, each with its domains",
          set(ts) == {"Northwind", "Fabrikam East"}
          and ts["Fabrikam East"]["domains"] == ["fabrikam.co.example", "fabrikam.example"])
    check("the second keeps its own application",
          sso.creds(cfg, ts["Fabrikam East"]) == (B_APP, "b-own-s")
          and sso.creds(cfg, ts["Northwind"]) == (SHARED, "shared-s"))
    raw = db.one("SELECT value FROM settings WHERE key='sso'")
    raw = raw["value"] if isinstance(raw, dict) else (raw or [""])[0]
    check("and the row is still sealed, the tenant's own secret included",
          str(raw).startswith("enc.v1.") and "b-own-s" not in str(raw))

    page = TestClient(main.app).get("/login").text
    check("the sign-in page shows a button per tenant",
          "Sign in with Microsoft · Northwind" in page
          and "Sign in with Microsoft · Fabrikam East" in page)
    a_id, b_id = ts["Northwind"]["id"], ts["Fabrikam East"]["id"]

    print("each button goes to its own tenant, with its own application")
    r, loc, url, posted = sign_in(f"/login/microsoft?t={b_id}", {
        "aud": B_APP, "tid": B_TID, "email": "kai@fabrikam.co.example"})
    check("Fabrikam East is sent to its own directory with its own app",
          loc.startswith(f"https://login.microsoftonline.com/{B_TID}/")
          and f"client_id={B_APP}" in loc)
    check("its code is exchanged at its own token endpoint, with its secret",
          url.startswith(f"https://login.microsoftonline.com/{B_TID}/")
          and posted.get("client_secret") == ["b-own-s"])
    check("and its person is signed in", landed_home(r))
    row = db.one("SELECT detail FROM audit WHERE action='login_microsoft' "
                 "ORDER BY rowid DESC LIMIT 1")
    detail = row["detail"] if isinstance(row, dict) else (row or [""])[0]
    check(f"the audit names the tenant, got {detail!r}",
          "Fabrikam East" in str(detail))

    r, loc, _u, posted = sign_in(f"/login/microsoft?t={a_id}", {
        "aud": SHARED, "tid": A_TID, "email": "dana@northwind.example"})
    check("Northwind uses the shared application",
          f"client_id={SHARED}" in loc
          and posted.get("client_secret") == ["shared-s"] and landed_home(r))

    print("several tenants and no choice made is not guessed")
    r = TestClient(main.app).get("/login/microsoft", follow_redirects=False)
    check("the bare button refuses rather than picking one",
          refused_with(r, "choose which organisation"))

    print("one organisation cannot sign in as the other's people")
    r, *_ = sign_in(f"/login/microsoft?t={b_id}", {
        "aud": B_APP, "tid": B_TID, "email": "dana@northwind.example"})
    check("a Fabrikam East account claiming a Northwind address is refused",
          refused_with(r, "is not an address Fabrikam East signs in with"))
    r, *_ = sign_in(f"/login/microsoft?t={a_id}", {
        "aud": SHARED, "tid": B_TID, "email": "dana@northwind.example"})
    check("an answer from another directory than the one asked is refused",
          refused_with(r, "belongs to a different tenant"))
    r, _l, url, _p = sign_in(f"/login/microsoft?t={a_id}", {
        "aud": SHARED, "tid": B_TID, "email": "kai@fabrikam.co.example"},
        callback_extra=f"&t={b_id}")
    check("the callback ignores a tenant named in its own URL",
          url.startswith(f"https://login.microsoftonline.com/{A_TID}/")
          and refused_with(r, "different tenant"))

    print("a stored secret is kept by the row's id, not its position")
    r = c.post("/admin/sso", data={
        "enabled": "1", "client_id": SHARED, "client_secret": "",
        "t_id": [b_id], "t_label": ["Fabrikam East"], "t_tenant": [B_TID],
        "t_domains": ["fabrikam.co.example"], "t_client_id": [B_APP],
        "t_client_secret": [""]}, follow_redirects=False)
    cfg = sso.config()
    check("removing the first tenant leaves the second's secret with it",
          r.status_code == 303 and [t["label"] for t in cfg["tenants"]]
          == ["Fabrikam East"] and cfg["tenants"][0]["client_secret"] == "b-own-s"
          and cfg["client_secret"] == "shared-s")
    r = c.post("/admin/sso", data={
        "enabled": "1", "client_id": SHARED, "client_secret": "",
        "t_id": ["", b_id], "t_label": ["Northwind", "Fabrikam East"],
        "t_tenant": [A_TID, B_TID],
        "t_domains": ["northwind.example", "fabrikam.co.example"],
        "t_client_id": [B_APP, ""], "t_client_secret": ["", ""]},
        follow_redirects=False)
    check("a NEW row naming another tenant's application does not inherit "
          "its secret", r.status_code == 200
          and "needs its client secret" in r.text)

    print("a refused save is the form again, with what was typed")
    before = sso.config()
    r = two_tenants(c, t_domains=["northwind.example", ""],
                    t_label=["Northwind", "Typed But Refused"])
    check(f"a second tenant without domains is refused in place "
          f"({r.status_code})", r.status_code == 200
          and "list the email domains" in r.text)
    check("the dialog comes back open with the submission in it",
          'id="ssoDialog" class="pdialog" data-open="1"' in r.text
          and 'value="Typed But Refused"' in r.text
          and f'value="{B_TID}"' in r.text)
    check("and the secret typed is not sent back",
          "b-own-s" not in r.text and "shared-s" not in r.text)
    check("nothing was stored", sso.config() == before)
    r = two_tenants(c, t_domains=["northwind.example", "fabrikam..example"])
    check("a word that is not a domain is named and kept in the field",
          r.status_code == 200 and "not an email domain: fabrikam..example" in r.text
          and 'value="fabrikam..example"' in r.text)
    r = two_tenants(c, t_domains=["northwind.example", "northwind.example"])
    check("one domain under two tenants is refused",
          r.status_code == 200 and "listed under both" in r.text)

    print("a tenant typed as a domain is looked up to its directory")
    real = sso.urlguard.urlopen
    sso.urlguard.urlopen = lambda req, timeout=None: _Reply(json.dumps({
        "issuer": f"https://login.microsoftonline.com/{B_TID}/v2.0"}).encode())
    try:
        r = two_tenants(c, t_tenant=[A_TID, "fabrikam.co.example"])
    finally:
        sso.urlguard.urlopen = real
    t = [t for t in sso.config()["tenants"] if t["label"] == "Fabrikam East"][0]
    check(f"its directory id is stored, got {t['tid']!r}", t["tid"] == B_TID)
    r, *_ = sign_in(f"/login/microsoft?t={t['id']}", {
        "aud": B_APP, "tid": A_TID, "email": "kai@fabrikam.co.example"})
    check("so another directory's answer is refused for it too",
          refused_with(r, "different tenant"))

    print("the settings card lists every tenant")
    page = c.get("/admin/users").text
    check("both are on the card", "Enabled for 2 tenants" in page
          and "Northwind" in page and "Fabrikam East" in page)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
