#!/usr/bin/env python3
"""Signing in with a fingerprint, driven by a software authenticator.

WHY THIS EXISTS
    This replaces a password AND a TOTP code with one gesture, so the whole
    feature rests on a signature check being right. Mocking that away would
    leave a test that proves the buttons are wired and nothing about whether
    anybody can get in — or whether the wrong person can.

    So the test builds a REAL authenticator: a P-256 key, a CBOR attestation
    object, authenticator data with the flags set, and an ECDSA signature over
    exactly what the specification says a browser signs. Everything below goes
    through `webauthn.verify_*`, the same code the routes call.

    The five things that would be silent and dangerous:

      1. **A forged assertion accepted.** Signed by the wrong key, or over the
         wrong challenge. Either one means anybody can be anybody.
      2. **A replayed challenge accepted.** The challenge is single-use and
         typed — a registration challenge must not be spendable as a login.
      3. **User verification not enforced.** The entire justification for
         skipping the second factor is that the device verified a person. A
         credential that only proves presence (a tap) must be refused, or this
         is one factor wearing the badge of two.
      4. **A passkey signing in the wrong account.** The credential id decides
         whose session starts; getting that lookup wrong is a total compromise.
      5. **Password and TOTP quietly stopping working.** They are the recovery
         path. If a passkey becomes the ONLY way in, a lost laptop locks
         somebody out of their own control plane.

    ./.venv/bin/python tests/test_passkeys.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import struct
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("passkeys-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import cbor2                                                   # noqa: E402
from cryptography.hazmat.primitives import hashes              # noqa: E402
from cryptography.hazmat.primitives.asymmetric import (ec,     # noqa: E402
                                                       padding, rsa)
from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, passkeys                       # noqa: E402

bad = 0

# HTTPS, because that is what a real install has and what the product requires.
# TestClient does not perform TLS — it just reports this scheme — so asking for
# https here costs nothing and keeps the fixture honest about the one condition
# the feature cannot work without. (The FIRST version of this file used
# http://testserver and was refused by readiness(), which is the guard doing
# its job; localhost would also have been accepted, but no customer is on it.)
ORIGIN = "https://testserver"
RP_ID = "testserver"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


class Authenticator:
    """A software security key. Produces what a browser would POST.

    Deliberately able to misbehave — `uv=False` makes a credential that only
    proves somebody was present, which is the case the product must refuse.
    """

    def __init__(self, cred_id: bytes = b"\x01" * 32, uv: bool = True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = cred_id
        self.uv = uv
        self.sign_count = 0

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,                       # kty: EC2
            3: -7,                      # alg: ES256
            -1: 1,                      # crv: P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        })

    def _auth_data(self, rp_id: str, attested: bool) -> bytes:
        flags = 0x01                                   # user present
        if self.uv:
            flags |= 0x04                              # user verified
        if attested:
            flags |= 0x40                              # attested credential data
        out = hashlib.sha256(rp_id.encode()).digest()
        out += bytes([flags]) + struct.pack(">I", self.sign_count)
        if attested:
            out += b"\x00" * 16                        # AAGUID
            out += struct.pack(">H", len(self.cred_id)) + self.cred_id
            out += self._cose()
        return out

    def _sign(self, payload: bytes) -> bytes:
        return self.key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def _client_data(self, kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge,
                           "origin": origin, "crossOrigin": False}).encode()

    def register(self, options: dict, origin: str = ORIGIN,
                 rp_id: str = RP_ID) -> dict:
        cdj = self._client_data("webauthn.create", options["challenge"], origin)
        att = cbor2.dumps({"fmt": "none", "attStmt": {},
                           "authData": self._auth_data(rp_id, True)})
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64(cdj),
                             "attestationObject": b64(att)}}

    def assert_(self, options: dict, origin: str = ORIGIN, rp_id: str = RP_ID,
                sign_with=None, over_challenge: str | None = None) -> dict:
        """A signed assertion. `sign_with` and `over_challenge` exist so the
        test can forge one and watch it be refused."""
        self.sign_count += 1
        challenge = over_challenge or options["challenge"]
        cdj = self._client_data("webauthn.get", challenge, origin)
        ad = self._auth_data(rp_id, False)
        payload = ad + hashlib.sha256(cdj).digest()
        # Through a hook so a subclass can sign with a different scheme; an
        # explicit `sign_with` is the forgery case and stays ECDSA.
        sig = (sign_with.sign(payload, ec.ECDSA(hashes.SHA256()))
               if sign_with else self._sign(payload))
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64(cdj),
                             "authenticatorData": b64(ad),
                             "signature": b64(sig), "userHandle": None}}


class RsaAuthenticator(Authenticator):
    """A Windows Hello-shaped authenticator: an RSA key signing RS256.

    Every other authenticator in this file is P-256/ES256, which is what Apple,
    Android and YubiKeys use — so without this the RS256 branch of the offered
    algorithm list was never exercised end to end, and Windows Hello backed by
    a TPM is exactly the case that uses it. A different key type, a different
    COSE encoding and a different signature scheme: if any of the three were
    wrong, ES256 tests would still all pass.
    """

    def __init__(self, cred_id: bytes = b"\x0e" * 32, uv: bool = True):
        super().__init__(cred_id=cred_id, uv=uv)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({
            1: 3,                                       # kty: RSA
            3: -257,                                    # alg: RS256
            -1: n.n.to_bytes((n.n.bit_length() + 7) // 8, "big"),
            -2: n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"),
        })

    def _sign(self, payload: bytes) -> bytes:
        return self.key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app, base_url=ORIGIN)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def enrol(client: TestClient, dev: Authenticator, ua: str = "") -> dict:
    """No name is sent: the server reads it off the browser. That is the point
    of the change — a text box for a string the User-Agent already carries."""
    opts = client.post("/me/passkey/options").json()
    return client.post("/me/passkey/verify",
                       json={"credential": dev.register(opts)},
                       headers={"user-agent": ua} if ua else None).json()


def main_test() -> int:
    uid = auth.create_user("a@t.local", "A", "Passkey-Test-Pw-42", role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    uid2 = auth.create_user("b@t.local", "B", "Passkey-Test-Pw-42", role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid2))

    print("where the site says it is")
    check("localhost is allowed without TLS — the browser exempts it too",
          passkeys.readiness("http://localhost:8471")["ok"])
    plain = passkeys.readiness("http://envmap.example.com")
    check("plain HTTP anywhere else is refused, in words",
          not plain["ok"] and "HTTPS" in plain["why"])
    check("and HTTPS is fine",
          passkeys.readiness("https://envmap.example.com")["ok"])
    check("the RP ID is the bare host — a port in it makes browsers refuse",
          passkeys.readiness("https://envmap.example.com:8443")["rp_id"]
          == "envmap.example.com")

    print("enrolling a passkey")
    c = signed_in("a@t.local", "Passkey-Test-Pw-42")
    dev = Authenticator()
    got = enrol(c, dev, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")
    check(f"it registers ({got})", got.get("ok"))
    mine = passkeys.for_user(uid)
    check("and is stored against the account", len(mine) == 1)
    check(f"named from the browser that made it ({mine[0]['name']})",
          mine[0]["name"] == "Mac · Safari")
    # The private key is the whole point: only the public half may be here.
    stored = json.dumps(mine[0])
    priv = dev.key.private_numbers().private_value.to_bytes(32, "big")
    check("the PRIVATE key is nowhere in the database",
          b64(priv) not in stored and priv.hex() not in stored)
    raw = pathlib.Path(os.environ["PORTAL_DATA_DIR"], "portal.db").read_bytes()
    check("nor anywhere in the database file", priv not in raw)

    print("signing in with it — no password, no code")
    fresh = TestClient(main.app, base_url=ORIGIN)
    fresh.__enter__()
    opts = fresh.post("/login/passkey/options", data={"email": ""}).json()
    check("a challenge is offered with no email typed at all",
          bool(opts.get("challenge")))
    out = fresh.post("/login/passkey/verify",
                     json=dev.assert_(opts)).json()
    check(f"the assertion is accepted ({out})", out.get("ok"))
    # The real proof: a page that needs a full session renders.
    r = fresh.get("/me")
    # The marker is the sign-in table rather than a sentence: a heading is
    # rewritten every time the page is redesigned, and this assertion is about
    # the SESSION being whole, not about the wording.
    check(f"and the session is COMPLETE, not half — /me renders ({r.status_code})",
          r.status_code == 200 and 'class="jenkins acc-t"' in r.text)

    print("a forged assertion is refused")
    other_key = ec.generate_private_key(ec.SECP256R1())
    f2 = TestClient(main.app, base_url=ORIGIN)
    f2.__enter__()
    o = f2.post("/login/passkey/options", data={"email": ""}).json()
    r = f2.post("/login/passkey/verify",
                json=dev.assert_(o, sign_with=other_key))
    check(f"signed by the wrong key -> refused ({r.status_code})",
          r.status_code == 400 and not r.json().get("ok"))
    check("and that session is still anonymous",
          f2.get("/me", follow_redirects=False).status_code in (302, 303))

    o = f2.post("/login/passkey/options", data={"email": ""}).json()
    r = f2.post("/login/passkey/verify",
                json=dev.assert_(o, over_challenge=b64(b"z" * 32)))
    check(f"signed over a different challenge -> refused ({r.status_code})",
          r.status_code == 400)

    print("a challenge is single use, and typed")
    f3 = TestClient(main.app, base_url=ORIGIN)
    f3.__enter__()
    o = f3.post("/login/passkey/options", data={"email": ""}).json()
    first = f3.post("/login/passkey/verify", json=dev.assert_(o))
    check("the first use works", first.json().get("ok"))
    replay = f3.post("/login/passkey/verify", json=dev.assert_(o))
    check(f"the same challenge a second time -> refused ({replay.status_code})",
          replay.status_code == 400)
    # A registration challenge must not be spendable as a login one.
    c2 = signed_in("a@t.local", "Passkey-Test-Pw-42")
    c2.post("/me/passkey/options")            # mints a REGISTER challenge
    r = c2.post("/login/passkey/verify", json=dev.assert_({"challenge": b64(b"x" * 32)}))
    check("a registration challenge cannot be spent as a login one",
          r.status_code == 400)

    print("user verification is required, or this is not two factors")
    c3 = signed_in("b@t.local", "Passkey-Test-Pw-42")
    tap_only = Authenticator(cred_id=b"\x02" * 32, uv=False)
    opts = c3.post("/me/passkey/options").json()
    r = c3.post("/me/passkey/verify",
                json={"name": "tap key", "credential": tap_only.register(opts)})
    check(f"a presence-only authenticator is refused at enrolment ({r.status_code})",
          r.status_code == 400)
    check("and nothing was stored for it", len(passkeys.for_user(uid2)) == 0)

    print("a passkey signs in ITS OWN account and no other")
    c4 = signed_in("b@t.local", "Passkey-Test-Pw-42")
    dev_b = Authenticator(cred_id=b"\x03" * 32)
    enrol(c4, dev_b)
    f5 = TestClient(main.app, base_url=ORIGIN)
    f5.__enter__()
    o = f5.post("/login/passkey/options", data={"email": ""}).json()
    f5.post("/login/passkey/verify", json=dev_b.assert_(o))
    who = f5.get("/me").text
    check("B's passkey signs in B, not A",
          "b@t.local" in who and "a@t.local" not in who)

    print("an unknown email does not say so")
    f6 = TestClient(main.app, base_url=ORIGIN)
    f6.__enter__()
    known = f6.post("/login/passkey/options", data={"email": "a@t.local"})
    f6b = TestClient(main.app, base_url=ORIGIN)
    f6b.__enter__()
    unknown = f6b.post("/login/passkey/options", data={"email": "nope@t.local"})
    check("both answer 200 — this endpoint is not an account oracle",
          known.status_code == 200 and unknown.status_code == 200)
    check("and both hand back a challenge",
          bool(known.json().get("challenge"))
          and bool(unknown.json().get("challenge")))

    print("the recovery path is untouched — this is ADDITIVE")
    rec = TestClient(main.app, base_url=ORIGIN)
    rec.__enter__()
    r = rec.post("/login", data={"email": "a@t.local",
                                 "password": "Passkey-Test-Pw-42"},
                 follow_redirects=False)
    check("password sign-in still starts the flow", r.status_code == 303)
    r = rec.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    check("and the TOTP code still completes it", r.status_code == 303)
    check("so somebody with a passkey can still get in without their device",
          rec.get("/me").status_code == 200)
    page = rec.get("/login").text
    check("the login page keeps the password form beside the passkey button",
          'name="password"' in page and 'id="pk-go"' in page)

    print("removing one — the only management there is")
    c5 = signed_in("a@t.local", "Passkey-Test-Pw-42")
    mine = passkeys.for_user(uid)
    # Somebody else's passkey is not yours to touch, even holding its id.
    other = passkeys.for_user(uid2)[0]
    c5.post(f"/me/passkey/{other['id']}/delete", follow_redirects=False)
    check("another account's passkey is not deletable with its id",
          len(passkeys.for_user(uid2)) == 1)
    c5.post(f"/me/passkey/{mine[0]['id']}/delete", follow_redirects=False)
    check("your own is", len(passkeys.for_user(uid)) == 0)
    # Taking a lost device away is the one thing that must exist; naming it was
    # a text box for a string the browser supplies, and it is gone.
    page = c5.get("/me").text
    check("there is no name box and no rename form",
          'id="pk-name"' not in page and "/rename" not in page)

    print("what the audit log kept")
    rows = [r[0] for r in db.q("SELECT action FROM audit")]
    for want in ("passkey_added", "passkey_removed", "passkey_failed"):
        check(f"{want} is recorded", want in rows)
    detail = db.q("SELECT target, detail FROM audit WHERE action='login' "
                  "AND target='passkey'")
    check(f"a passkey sign-in is audited as a login ({len(detail)})", detail)

    print("THERE IS NOTHING TO CONFIGURE — that is the feature")
    a = signed_in("a@t.local", "Passkey-Test-Pw-42")
    adm = a.get("/admin/users").text
    # A settings card lived here and was removed on request: the appeal of
    # signing in with a fingerprint is that there is nothing to set up, and a
    # feature that opens with a form contradicts its own headline.
    check("no admin settings card", "/admin/passkeys" not in adm
          and 'name="rp_id"' not in adm)
    # 404, not 405: the path does not exist at all, which is a stronger
    # answer than "that verb is not allowed here".
    check("and the route is gone, not merely unlinked from the page",
          a.post("/admin/passkeys", data={"rp_id": "x"}).status_code == 404)
    # The escape hatch for a proxy that hides the real host is an environment
    # variable, so nobody sees it and nobody has to know it is there.
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "app" / "passkeys.py").read_text()
    check("the override is an env var, not a stored setting",
          "env.PASSKEY_RPID" in src and "_setting" not in src)
    check("and an RP ID given as a URL is reduced to its host, not trusted",
          passkeys._host_of("https://x.example.com:8443") == "x.example.com")

    print("the fingerprint offers ITSELF — no button, no typing")
    # The point of the whole feature as asked for: land on the sign-in page
    # with a passkey already registered and Touch ID appears on its own.
    # That is conditional mediation, and it needs three things together —
    # miss any one and the automatic path is silently dead while the button
    # still works, which is the worst way for this to break.
    page = TestClient(main.app, base_url=ORIGIN).get("/login").text
    check("the email field advertises that a passkey can fill it",
          'autocomplete="username webauthn"' in page)
    check("the browser is asked whether it supports conditional mediation",
          "isConditionalMediationAvailable" in page)
    check("and the request is made with mediation: conditional",
          "'conditional'" in page and "req.mediation" in page)
    # A conditional request that nobody answers is normal — it is what happens
    # every time somebody types their password instead — so it must not shout.
    # Asserted as BEHAVIOUR, not wording: the first version matched a comment
    # and broke the moment the comment was reworded, which tests nothing.
    _watch = page.split("async function watch()")[1].split("\n  }")[0]
    check("an abandoned conditional request says nothing — its catch is silent",
          "catch" in _watch and "say(" not in _watch)
    check("and it never sends allowCredentials, or there is nothing to discover",
          "mediation ? '' :" in page)
    # REPORTED FROM THE BROWSER: pressing the button gave "A request is already
    # pending". The conditional call starts on page load and stays outstanding
    # while somebody reads the page, and a browser permits exactly one
    # credential request at a time — so the button's was refused by the browser
    # for doing precisely what it was asked to do. It has to cancel the silent
    # one first.
    check("the silent request is held on an AbortController",
          "AbortController" in page and "req.signal = signal" in page)
    check("and the button cancels it before starting its own",
          "stopPending();" in page
          and page.index("stopPending();") < page.index("await finish(await go(null))"))
    check("the silent one comes back if the button's attempt fails, so the "
          "autofill route is not lost for the rest of the page's life",
          "watch();" in page.split("btn.addEventListener")[1].split("});")[0]
          or "      watch();" in page)

    print("the account page is a table, and short until it is asked")
    a2 = signed_in("a@t.local", "Passkey-Test-Pw-42")
    me = a2.get("/me").text
    # It was eight cards, all open, all shouting: the details you change once a
    # year had the same weight as the audit trail you read when something has
    # gone wrong. One table for how you sign in, everything else behind a
    # summary.
    check(f"one card, not eight ({me.count('class=\"card\"')})",
          me.count('class="card"') == 1)
    check("sign-in is ONE table with real headers",
          'class="jenkins acc-t"' in me
          and ">Method</th>" in me and ">Status</th>" in me)
    # A flat sort would scramble a form away from the row it belongs to — the
    # same reason a grouped table opts out.
    check("whose headers opt out of sorting, because it has detail rows",
          me.count("no-sort") >= 3 and 'class="acc-form"' in me)
    check("its actions are house buttons on one line",
          me.count('class="actrow oneline"') >= 4)
    check("nothing arrives open", '<details class="acc-sec" open' not in me)
    # Every form the four old cards carried still posts to the same place.
    for act in ("/me/password", "/me/mfa", "/me/name"):
        check(f"{act} survived the rebuild", act in me)

    print("a deleted account takes its passkeys with it")
    gone = auth.create_user("c@t.local", "C", "Passkey-Test-Pw-42", role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", gone))
    cc = signed_in("c@t.local", "Passkey-Test-Pw-42")
    dev_c = Authenticator(cred_id=b"\x04" * 32)
    enrol(cc, dev_c)
    check("C has one", len(passkeys.for_user(gone)) == 1)
    adm = signed_in("a@t.local", "Passkey-Test-Pw-42")
    adm.post(f"/admin/users/{gone}/delete", data={"confirm": "Delete"},
             follow_redirects=False)
    check("the account is gone", auth.by_id(gone) is None)
    check("and so are its passkeys — no credential outlives its owner",
          len(passkeys.for_user(gone)) == 0)
    # Belt and braces: even if a row survived, the login route must refuse it.
    f7 = TestClient(main.app, base_url=ORIGIN)
    f7.__enter__()
    o = f7.post("/login/passkey/options", data={"email": ""}).json()
    r = f7.post("/login/passkey/verify", json=dev_c.assert_(o))
    check(f"a passkey for a deleted account cannot sign in ({r.status_code})",
          r.status_code in (400, 403))

    print("WORKS ON ANY OS AND ANY DEVICE — what the browser is offered")
    # Asked for directly: be sure this works everywhere. Compatibility here is
    # decided almost entirely by four fields in the registration options, and
    # getting any of them wrong excludes a whole platform silently — the
    # affected people simply cannot enrol, and nobody else notices.
    import json as _json
    opts = _json.loads(passkeys.register_options(
        {"id": "u-x", "email": "x@y.z", "name": "X"},
        "https://portal.example.com", {}))
    algs = [pkp["alg"] for pkp in opts["pubKeyCredParams"]]
    # -7 ES256: Apple, Android, YubiKey. -257 RS256: Windows Hello on a TPM.
    # -8 EdDSA: newer keys. Dropping RS256 is how Windows stops working.
    check(f"ES256, RS256 and EdDSA are all offered ({algs})",
          -7 in algs and -257 in algs and -8 in algs)
    sel = opts.get("authenticatorSelection") or {}
    # THE ONE THAT WOULD HURT MOST. Pinning attachment to `platform` would
    # limit this to a built-in sensor: no security keys, and no signing in on a
    # laptop by scanning a QR code with a phone. Its ABSENCE is the feature.
    check(f"attachment is NOT pinned, so a security key and a phone over QR "
          f"both work ({sel})", "authenticatorAttachment" not in sel)
    check("attestation is 'none' — asking for it prompts people and buys "
          "nothing without an enterprise policy to check it against",
          opts.get("attestation") == "none")
    check("resident key is preferred, not required, so an older key with no "
          "room for one still enrols",
          sel.get("residentKey") == "preferred")

    print("a Windows Hello-shaped RSA key, end to end")
    # The RS256 branch, exercised for real: a different key type, COSE encoding
    # and signature scheme from every other test here.
    uidw = auth.create_user("w@t.local", "W", "Passkey-Test-Pw-42", role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uidw))
    cw = signed_in("w@t.local", "Passkey-Test-Pw-42")
    hello = RsaAuthenticator()
    check(f"an RSA credential registers ({enrol(cw, hello)})",
          len(passkeys.for_user(uidw)) == 1)
    fw = TestClient(main.app, base_url=ORIGIN)
    fw.__enter__()
    ow = fw.post("/login/passkey/options", data={"email": ""}).json()
    rw = fw.post("/login/passkey/verify", json=hello.assert_(ow))
    check(f"and signs in ({rw.status_code})", rw.json().get("ok"))
    check("its session is complete like any other",
          fw.get("/me").status_code == 200)

    print("EVERY ADDRESS a portal is reached at")
    # The RP ID is derived from the request, so the shape of the host decides
    # whether this works at all — and three of these were wrong.
    for url, ok, rp in (
            ("https://envmap.example.com", True, "envmap.example.com"),
            ("https://portal.example.co.uk", True, "portal.example.co.uk"),
            # the port belongs in the origin and must NOT be in the RP ID: a
            # browser refuses one that carries it, silently
            ("https://envmap.example.com:8443", True, "envmap.example.com"),
            ("http://localhost:8471", True, "localhost"),
            ("https://127.0.0.1:8471", True, "127.0.0.1"),
            # A host is case-insensitive; the browser lowercases before
            # comparing, so a mixed-case Host header must not produce a
            # different RP ID than the same name typed lower.
            ("https://EnvMap.Example.COM", True, "envmap.example.com"),
            # AN IP IS NOT A DOMAIN. The spec is explicit and the browser
            # answers with a SecurityError, so an internal portal on an address
            # has to be told rather than left clicking a dead button.
            ("https://10.0.0.5", False, None),
            ("https://192.168.1.20", False, None),
            ("https://[2001:db8::1]", False, None),
            # Browsers compute both the RP ID and the origin from the PUNYCODE
            # form, so a non-ASCII host must be encoded or nothing matches.
            ("https://müller.example.com", True, "xn--mller-kva.example.com"),
    ):
        got = passkeys.readiness(url)
        check(f"{url} -> ok={got['ok']} (wanted {ok})", got["ok"] is ok)
        if ok and rp:
            check(f"  and its RP ID is {rp} (got {got['rp_id']})",
                  got["rp_id"] == rp)
        if not ok:
            check(f"  and it says why ({got['why'][:40]}…)", bool(got["why"]))
    # The IDN origin has to be encoded too, or the RP ID matches and the origin
    # check fails instead — the same bug one field along.
    check("an IDN origin is encoded as well as its RP ID",
          passkeys.where("https://müller.example.com")[1]
          == "https://xn--mller-kva.example.com")
    check("and a port survives that encoding",
          passkeys.where("https://müller.example.com:8443")[1]
          == "https://xn--mller-kva.example.com:8443")

    print("SIGNATURE COUNTERS — both behaviours that exist in the world")
    # This is the one that breaks on the SECOND sign-in, which is the worst
    # kind: enrolment works, the demo works, and it fails the next morning.
    for label, cid, keep_zero in (("Apple and every synced passkey (always 0)",
                                   b"\x21" * 32, True),
                                  ("a security key that increments",
                                   b"\x22" * 32, False)):
        uidc = auth.create_user(f"c{cid[0]}@t.local", "C",
                                "Passkey-Test-Pw-42", role="user")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uidc))
        dc = Authenticator(cred_id=cid)
        enrol(signed_in(f"c{cid[0]}@t.local", "Passkey-Test-Pw-42"), dc)
        oks = []
        for _ in range(3):
            if keep_zero:
                dc.sign_count = -1      # assert_ adds 1, so the wire sees 0
            fc = TestClient(main.app, base_url=ORIGIN)
            fc.__enter__()
            oc = fc.post("/login/passkey/options", data={"email": ""}).json()
            oks.append(bool(fc.post("/login/passkey/verify",
                                    json=dc.assert_(oc)).json().get("ok")))
        check(f"{label}: three sign-ins in a row ({oks})", all(oks))

    print("ONE INSTALL REACHED AT TWO HOSTNAMES")
    # The last shape that exists in the field: a portal on an internal name and
    # an external one, or moving from `envmap.corp` to `envmap.example.com`. An
    # RP ID is baked into the credential, so by default a passkey enrolled at
    # one name is useless at the other and the person is simply locked out of
    # the fast path with no explanation. WebAuthn's answer is to set the RP ID
    # to the shared parent, which a browser accepts for any subdomain of it —
    # so PORTAL_PASSKEY_RPID is not a nicety, it is the multi-hostname story,
    # and it is asserted here because nothing else exercises that branch.
    was = passkeys.env.PASSKEY_RPID
    try:
        passkeys.env.PASSKEY_RPID = "example.com"
        A, B = "https://envmap.example.com", "https://portal.example.com"
        ra, rb = passkeys.readiness(A), passkeys.readiness(B)
        check(f"both hostnames resolve to the shared RP ID "
              f"({ra['rp_id']}, {rb['rp_id']})",
              ra["rp_id"] == rb["rp_id"] == "example.com")
        check(f"while each keeps its OWN origin, which is compared verbatim "
              f"({ra['origin']}, {rb['origin']})",
              ra["origin"] == A and rb["origin"] == B)

        uidm = auth.create_user("m@t.local", "M", "Passkey-Test-Pw-42",
                                role="user")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uidm))
        roam = Authenticator(cred_id=b"\x31" * 32)
        ca = TestClient(main.app, base_url=A)
        ca.__enter__()
        ca.post("/login", data={"email": "m@t.local",
                                "password": "Passkey-Test-Pw-42"},
                follow_redirects=False)
        ca.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        oa = ca.post("/me/passkey/options").json()
        ga = ca.post("/me/passkey/verify", json={"credential": roam.register(
            oa, origin=A, rp_id="example.com")}).json()
        check(f"a passkey enrols at the first hostname ({ga.get('ok')})",
              ga.get("ok"))
        # The actual claim: the SAME credential, at the OTHER address.
        cb = TestClient(main.app, base_url=B)
        cb.__enter__()
        ob = cb.post("/login/passkey/options", data={"email": ""}).json()
        gb = cb.post("/login/passkey/verify",
                     json=roam.assert_(ob, origin=B, rp_id="example.com"))
        check(f"and signs in at the second, unchanged "
              f"({gb.status_code} {gb.json().get('error', '')[:40]})",
              gb.json().get("ok"))
        check("with a real session behind it",
              cb.get("/me").status_code == 200)
        # And the guard still holds inside the parent: a DIFFERENT origin under
        # the same RP ID is still a different origin, so a credential cannot be
        # replayed from a host the operator never served.
        oc = cb.post("/login/passkey/options", data={"email": ""}).json()
        gc = cb.post("/login/passkey/verify", json=roam.assert_(
            oc, origin="https://evil.example.com", rp_id="example.com"))
        check(f"but an origin the portal is not served at is still refused "
              f"({gc.status_code})", not gc.json().get("ok"))
    finally:
        passkeys.env.PASSKEY_RPID = was
    check("and the override is back off by default, so none of this is "
          "configuration anybody has to know about",
          not passkeys.env.PASSKEY_RPID)

    print("the dependency is declared, because 0.6.0 taught us that")
    reqs = (pathlib.Path(__file__).resolve().parent.parent
            / "requirements.txt").read_text().lower()
    check("webauthn is in requirements.txt, not dev-only", "webauthn" in reqs)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
