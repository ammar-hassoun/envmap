#!/usr/bin/env python3
"""Issuing a certificate, against a CA that checks the protocol.

WHY A STUB THAT VERIFIES RATHER THAN ONE THAT AGREES
    Every interesting mistake in an ACME client produces the same symptom from
    the real CA — "JWS verification error" or "urn:ietf:params:acme:error:
    malformed" — and none of them can be told apart from the outside. So the
    stub here is strict on purpose: it verifies the signature against the JWK it
    was first shown, refuses a nonce it did not issue, refuses one twice, and
    checks that the `url` in the protected header is the URL the request went to.
    A client that passes this is one the real CA will accept, and a stub that
    merely said 200 would pass with the signature bytes reversed.

    The other half is the dns-01 digest. It is not checked by the stub — the real
    CA computes it from its own view of the account key — so it is checked
    against the published RFC 7638 example instead, in test_thumbprint below.

WHAT IS BEING PROVED BEYOND "IT WORKS"
    * closing the page cannot lose an order: every step is taken again from the
      row alone, with every module-level cache dropped first
    * a wildcard and its base name produce ONE record name with TWO values, and
      both have to be present
    * a private key is never in the database in the clear
    * "keep the same key" keeps the same key — compared by public numbers, not
      by trusting the label on the form

    ./.venv/bin/python tests/test_certs.py
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import pathlib
import re
import socket
import struct
import sys
import threading
import time
import types

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("certs-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509                                   # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec         # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym  # noqa: E402
from cryptography.x509.oid import ExtensionOID, NameOID          # noqa: E402

from app import certs, db, secretbox                            # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


# ── the stub CA ────────────────────────────────────────────────
class CA:
    """A small, strict RFC 8555 server. Holds the state one account and its
    orders need, and nothing else."""

    def __init__(self) -> None:
        self.base = ""
        self.nonces: set[str] = set()
        self.spent: set[str] = set()
        self.accounts: dict[str, dict] = {}        # kid -> {jwk}
        self.orders: dict[str, dict] = {}
        self.dns: dict[str, set[str]] = {}         # what "the internet" serves
        self.calls: list[str] = []
        self.fail_validation = False
        self.slow_finalize = 0                     # times to answer "processing"
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_cert = self._self_signed()

    # ---- certificate minting ----
    def _self_signed(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Stub CA E1")])
        now = time.time()
        return (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(self.ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_dt(now - 86400))
                .not_valid_after(_dt(now + 3650 * 86400))
                .add_extension(x509.BasicConstraints(True, None), critical=True)
                .sign(self.ca_key, hashes.SHA256()))

    def issue(self, csr_der: bytes) -> str:
        csr = x509.load_der_x509_csr(csr_der)
        names = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        now = time.time()
        leaf = (x509.CertificateBuilder()
                .subject_name(csr.subject or x509.Name([]))
                .issuer_name(self.ca_cert.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_dt(now - 60))
                .not_valid_after(_dt(now + 90 * 86400))
                .add_extension(names, critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        pem = leaf.public_bytes(serialization.Encoding.PEM)
        return (pem + self.ca_cert.public_bytes(serialization.Encoding.PEM)
                ).decode()

    # ---- protocol ----
    def nonce(self) -> str:
        n = _b64(os.urandom(16))
        self.nonces.add(n)
        return n

    def verify(self, path: str, body: bytes) -> tuple[dict, dict | None, str]:
        """Return (payload, account, kid) or raise AssertionError, which the
        handler turns into the CA's own 400."""
        doc = json.loads(body)
        protected = json.loads(_unb64(doc["protected"]))
        signing_input = f"{doc['protected']}.{doc['payload']}".encode()

        assert protected.get("url") == self.base + path, \
            f"url in the header is {protected.get('url')}, request went to {path}"
        n = protected.get("nonce", "")
        assert n in self.nonces, "unknown nonce"
        assert n not in self.spent, "nonce replayed"
        self.spent.add(n)
        self.nonces.discard(n)

        kid = protected.get("kid", "")
        jwk = protected.get("jwk") or (self.accounts.get(kid) or {}).get("jwk")
        assert jwk, "neither a jwk nor a known kid"
        assert protected.get("alg") == "ES256", f"alg {protected.get('alg')}"
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_unb64(jwk["x"]), "big"),
            int.from_bytes(_unb64(jwk["y"]), "big"),
            ec.SECP256R1()).public_key()
        sig = _unb64(doc["signature"])
        assert len(sig) == 64, f"ES256 signature is {len(sig)} bytes, not 64"
        der = asym.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                        int.from_bytes(sig[32:], "big"))
        pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        payload = (json.loads(_unb64(doc["payload"]))
                   if doc["payload"] else None)
        return payload, jwk, kid

    def thumb(self, jwk: dict) -> str:
        canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"],
                            "x": jwk["x"], "y": jwk["y"]},
                           sort_keys=True, separators=(",", ":")).encode()
        return _b64(hashlib.sha256(canon).digest())


def _dt(epoch: float):
    import datetime
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)


class Handler(http.server.BaseHTTPRequestHandler):
    ca: CA = None                                              # set below

    def log_message(self, *a):                                 # noqa: D102
        pass

    def _send(self, code: int, body: bytes = b"", ctype="application/json",
              extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Replay-Nonce", self.ca.nonce())
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):                                         # noqa: N802
        self.ca.calls.append(f"HEAD {self.path}")
        self._send(200)

    def do_GET(self):                                          # noqa: N802
        ca = self.ca
        ca.calls.append(f"GET {self.path}")
        if self.path == "/directory":
            return self._send(200, json.dumps({
                "newNonce": ca.base + "/nonce",
                "newAccount": ca.base + "/account",
                "newOrder": ca.base + "/order",
                "meta": {"termsOfService": ca.base + "/terms.pdf"},
            }).encode())
        return self._send(404, b"{}")

    def do_POST(self):                                         # noqa: N802
        ca = self.ca
        ca.calls.append(f"POST {self.path}")
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.headers.get("Content-Type") != "application/jose+json":
            return self._send(400, json.dumps({
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "not jose+json"}).encode())
        try:
            payload, jwk, kid = ca.verify(self.path, raw)
        except AssertionError as e:
            return self._send(400, json.dumps({
                "type": "urn:ietf:params:acme:error:badNonce"
                        if "nonce" in str(e) else
                        "urn:ietf:params:acme:error:malformed",
                "detail": str(e)}).encode())
        except Exception as e:                                 # noqa: BLE001
            return self._send(400, json.dumps({
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": f"signature did not verify: {e}"}).encode())

        if self.path == "/account":
            # Keyed by the account key, and a key already registered gets its
            # existing id back with a 200 — which is what RFC 8555 §7.3 says and
            # what caught a stub that minted /acct/1 every time: the second
            # registration overwrote the first one's key, and every later request
            # signed by the first account then failed to verify.
            thumb = ca.thumb(jwk)
            for k, v in ca.accounts.items():
                if ca.thumb(v["jwk"]) == thumb:
                    return self._send(200, json.dumps(
                        {"status": "valid"}).encode(), extra={"Location": k})
            k = f"{ca.base}/acct/{len(ca.accounts) + 1}"
            ca.accounts[k] = {"jwk": jwk}
            return self._send(201, json.dumps({"status": "valid"}).encode(),
                              extra={"Location": k})

        if self.path == "/order":
            oid = str(len(ca.orders) + 1)
            authz = []
            for i, ident in enumerate(payload["identifiers"]):
                value = ident["value"]
                authz.append({
                    "url": f"{ca.base}/authz/{oid}-{i}",
                    "identifier": {"type": "dns",
                                   "value": value.removeprefix("*.")},
                    "wildcard": value.startswith("*."),
                    "status": "pending",
                    "token": _b64(os.urandom(16)),
                })
            ca.orders[oid] = {"status": "pending", "authz": authz,
                              "cert": "", "kid": kid, "finalized": 0}
            return self._send(201, json.dumps({
                "status": "pending",
                "authorizations": [a["url"] for a in authz],
                "finalize": f"{ca.base}/finalize/{oid}",
            }).encode(), extra={"Location": f"{ca.base}/order/{oid}"})

        m = re.match(r"^/authz/(\d+)-(\d+)$", self.path)
        if m:
            a = ca.orders[m.group(1)]["authz"][int(m.group(2))]
            return self._send(200, json.dumps({
                "status": a["status"],
                "identifier": a["identifier"],
                "wildcard": a["wildcard"],
                "challenges": [{"type": "dns-01", "token": a["token"],
                                "url": a["url"].replace("/authz/", "/chall/"),
                                **({"error": {"detail": a["why"]}}
                                   if a.get("why") else {})}],
            }).encode())

        m = re.match(r"^/chall/(\d+)-(\d+)$", self.path)
        if m:
            order = ca.orders[m.group(1)]
            a = order["authz"][int(m.group(2))]
            want = _b64(hashlib.sha256(
                f"{a['token']}.{ca.thumb(ca.accounts[order['kid']]['jwk'])}"
                .encode()).digest())
            name = "_acme-challenge." + a["identifier"]["value"]
            served = ca.dns.get(name, set())
            if ca.fail_validation or want not in served:
                a["status"] = "invalid"
                a["why"] = (f"no TXT record found at {name}"
                            if not served else
                            f"incorrect TXT record at {name}")
            else:
                a["status"] = "valid"
            return self._send(200, json.dumps({"status": "processing"}).encode())

        m = re.match(r"^/finalize/(\d+)$", self.path)
        if m:
            order = ca.orders[m.group(1)]
            if any(a["status"] != "valid" for a in order["authz"]):
                return self._send(403, json.dumps({
                    "type": "urn:ietf:params:acme:error:orderNotReady",
                    "detail": "not every authorization is valid"}).encode())
            order["cert"] = ca.issue(_unb64(payload["csr"]))
            order["finalized"] = 1
            order["status"] = ("processing" if ca.slow_finalize else "valid")
            return self._send(200, json.dumps({"status": order["status"]}).encode())

        m = re.match(r"^/order/(\d+)$", self.path)
        if m:
            order = ca.orders[m.group(1)]
            if order["status"] == "processing":
                ca.slow_finalize -= 1
                if ca.slow_finalize <= 0:
                    order["status"] = "valid"
            body = {"status": order["status"],
                    "authorizations": [a["url"] for a in order["authz"]],
                    "finalize": f"{ca.base}/finalize/{m.group(1)}"}
            if order["status"] == "valid":
                body["certificate"] = f"{ca.base}/cert/{m.group(1)}"
            return self._send(200, json.dumps(body).encode())

        m = re.match(r"^/cert/(\d+)$", self.path)
        if m:
            return self._send(200, ca.orders[m.group(1)]["cert"].encode(),
                              ctype="application/pem-certificate-chain")
        return self._send(404, b"{}")


def start_ca() -> CA:
    ca = CA()
    Handler.ca = ca
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ca.base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return ca


# ── the DNS the portal sees ────────────────────────────────────
class FakeDNS:
    """Stands in for txt_at. Separate from the CA's own view on purpose: the
    interesting states are "the portal can see it and the CA cannot yet" and
    "the portal cannot ask at all", and one shared dict could not express them."""

    def __init__(self, ca: CA) -> None:
        self.ca = ca
        self.reachable = True
        self.lag = False              # portal cannot see what the CA can

    def __call__(self, name: str) -> dict:
        if not self.reachable:
            return {"txt": [], "asked": "nothing answered",
                    "reachable": False, "error": "no route to port 53",
                    "cname": ""}
        served = set() if self.lag else set(self.ca.dns.get(name, set()))
        return {"txt": sorted(served), "asked": "the stub",
                "reachable": True, "error": "", "cname": ""}


def publish(ca: CA, order: dict) -> None:
    """Do what the operator does: paste every printed record into the DNS."""
    for group in order["records"]:
        ca.dns.setdefault(group["record"], set()).update(group["txt"])


def drive(oid: str, rounds: int = 8) -> dict:
    """Advance until it stops moving, the way the worker would."""
    for _ in range(rounds):
        before = certs.one(oid)["status"]
        certs.advance(oid)
        after = certs.one(oid)
        if after["status"] == before and after["status"] in ("ready", "failed",
                                                            "cancelled"):
            break
        if after["status"] in ("ready", "failed"):
            break
    return certs.one(oid)


def forget_everything() -> None:
    """Every module-level cache dropped, as a restart would drop them. If any
    step needs something that is only in memory, the next advance() fails."""
    certs._nonces.clear()
    certs._dir_cache.clear()
    certs._zone_cache.clear()
    certs._live = (0.0, [])


# ── the DNS wire parser, on packets rather than the network ────
def synthetic_txt_answer() -> bytes:
    """A response with a compression pointer and a TXT split into two strings —
    both of which a hand-rolled parser gets wrong first."""
    name = b"\x0f_acme-challenge\x07example\x03com\x00"
    head = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    q = name + struct.pack(">HH", 16, 1)
    part1, part2 = b"first-half", b"second-half"
    rdata = bytes([len(part1)]) + part1 + bytes([len(part2)]) + part2
    # 0xC00C points back at the question's name rather than repeating it
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(rdata)) + rdata)
    return head + q + answer


def test_wire() -> None:
    print("the DNS parser, on a packet with a pointer and a split string")
    got = certs._answers(synthetic_txt_answer())
    check(f"one TXT record came out, got {got}", len(got) == 1)
    check(f"and its strings are joined, got {got[0][1]!r}",
          got[0] == (certs.DNS_TXT, "first-halfsecond-half"))
    name, end = certs._read_name(synthetic_txt_answer(), 12)
    check(f"the name reads back, got {name}",
          name == "_acme-challenge.example.com")
    check("and the caller is told where the name ended", end == 12 + 29)


def test_thumbprint() -> None:
    print("the account thumbprint matches the published example")
    # RFC 7638 §3.1. The dns-01 value is sha256(token + "." + thumbprint), so a
    # thumbprint that is off by one byte of JSON whitespace produces a record
    # that looks right, is pasted correctly, and never validates.
    key = certs.new_key("ec256")
    check("a P-256 key produces an ES256 alg", certs._alg(key) == "ES256")
    jwk = {"e": "AQAB", "kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmb"
           "XEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"
           "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5"
           "v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5ha"
           "jrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHa"
           "Q-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
    canon = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
    got = _b64(hashlib.sha256(canon).digest())
    check(f"got {got}", got == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")


def test_domains() -> None:
    print("what the form is allowed to ask for")
    check("a URL is reduced to its host",
          certs.clean_domains("https://api.example.com/x")== ["api.example.com"])
    check("case and trailing dots are normalised",
          certs.clean_domains("Example.COM.") == ["example.com"])
    check("duplicates collapse",
          certs.clean_domains("a.example.com, a.example.com")
          == ["a.example.com"])
    for raw in ("under_score.com", "*.*.example.com", "10.0.0.1", "localhost",
                "münchen.de", ""):
        try:
            certs.clean_domains(raw)
            check(f"{raw!r} should have been refused", False)
        except certs.CertError:
            pass
    print("and where the record goes for each of them")
    # The wildcard case is the one that gets pasted wrongly: the record name has
    # no star in it, and it is the same name the base domain uses.
    check("a wildcard validates at its base",
          certs.challenge_name("*.example.com")
          == certs.challenge_name("example.com")
          == "_acme-challenge.example.com")
    check("a subdomain validates under itself",
          certs.challenge_name("api.example.com")
          == "_acme-challenge.api.example.com")


def main() -> int:
    test_wire()
    test_thumbprint()
    test_domains()

    ca = start_ca()
    dns = FakeDNS(ca)
    certs.txt_at = dns                     # the only patch: the network itself

    print("a certificate, from the form to a downloadable file")
    oid = certs.create("user-1", "example.com, www.example.com",
                       ca="custom", ca_url=ca.base + "/directory",
                       email="ops@example.com", key_source="new",
                       key_type="ec256", agreed=True)
    order = certs.one(oid)
    check(f"it starts waiting for the operator, got {order['status']}",
          order["status"] == "awaiting_dns")
    check(f"both names are on it, got {order['domains']}",
          order["domains"] == ["example.com", "www.example.com"])
    check(f"two records to paste, got {len(order['records'])}",
          len(order["records"]) == 2)
    check("each with exactly one value",
          all(len(g["txt"]) == 1 for g in order["records"]))
    check("and the names are the _acme-challenge ones",
          sorted(g["record"] for g in order["records"])
          == ["_acme-challenge.example.com", "_acme-challenge.www.example.com"])
    check("nothing has been asked of the CA's challenge endpoint yet",
          not any(c.startswith("POST /chall/") for c in ca.calls))

    print("pressing 'carry on' before the records exist waits, and says so")
    certs.proceed(oid)
    order = drive(oid, rounds=2)
    check(f"still looking, got {order['status']}",
          order["status"] == "checking_dns")
    check(f"and it says what is missing, got {order['dns_note']!r}",
          "not visible yet" in order["dns_note"])
    check("the CA was still not asked to validate",
          not any(c.startswith("POST /chall/") for c in ca.calls))

    print("the operator pastes the records and closes the page")
    publish(ca, order)
    forget_everything()                    # as a restart would
    order = drive(oid)
    check(f"it finished on its own, got {order['status']} "
          f"({order.get('error')})", order["status"] == "ready")
    check("the certificate is downloadable",
          sorted(order["downloads"]) == ["cert", "chain", "csr", "fullchain",
                                         "privkey"])
    facts = order["facts"]
    check(f"the CA's own dates were read back, got {facts.get('not_after')}",
          facts["not_after"] > time.time() + 80 * 86400)
    check(f"days_left is about 90, got {order['days_left']}",
          88 <= order["days_left"] <= 90)
    check(f"both names are in the certificate, got {facts['domains']}",
          sorted(facts["domains"]) == ["example.com", "www.example.com"])
    check(f"the issuer is named, got {facts['issuer']!r}",
          facts["issuer"] == "Stub CA E1")
    check(f"the key type is the one asked for, got {facts['key']}",
          "256" in facts["key"] and "ECDSA" in facts["key"])
    check(f"the chain has the intermediate on it, got {facts['chain_len']}",
          facts["chain_len"] == 2)

    print("the files are the files a server needs")
    got = certs.files(oid)
    full = got["fullchain"][1]
    check("fullchain holds both certificates",
          full.count("BEGIN CERTIFICATE") == 2)
    check("cert holds only the leaf",
          got["cert"][1].count("BEGIN CERTIFICATE") == 1)
    check("chain holds only what is above it",
          got["chain"][1].count("BEGIN CERTIFICATE") == 1)
    check("and the leaf is first in the fullchain",
          full.startswith(got["cert"][1]))
    check("the private key is a private key",
          "PRIVATE KEY" in got["privkey"][1])
    check("the filenames say which is which",
          got["fullchain"][0] == "example.com.fullchain.pem")

    print("no private key is in the database in the clear")
    # The whole blob is sealed, so this reads the raw column rather than trusting
    # that the field it was put in is on somebody's list.
    raw = db.one("SELECT data FROM certorders WHERE id = ?", (oid,))["data"]
    check("the row is sealed", secretbox.sealed(raw))
    check("the key's PEM is not in it", "PRIVATE KEY" not in raw)
    acct = db.one("SELECT data FROM certaccounts LIMIT 1")["data"]
    check("and neither is the ACME account key", secretbox.sealed(acct)
          and "PRIVATE KEY" not in acct)

    print("a restart mid-order resumes instead of starting again")
    orders_before = len(ca.orders)
    oid2 = certs.create("user-1", "resume.example.com", ca="custom",
                        ca_url=ca.base + "/directory", email="ops@example.com",
                        key_source="new", key_type="rsa2048", agreed=True)
    before = certs.one(oid2)
    publish(ca, before)
    certs.proceed(oid2)
    certs.advance(oid2)                    # gets as far as validating
    mid = certs.one(oid2)
    check(f"it is mid-flight, got {mid['status']}",
          mid["status"] in ("validating", "finalizing", "ready"))
    forget_everything()
    after = drive(oid2)
    check(f"and it completed after the restart, got {after['status']} "
          f"({after.get('error')})", after["status"] == "ready")
    check("without opening a second order at the CA",
          len(ca.orders) == orders_before + 1)
    # An account per contact address, registered once. A CA counts new accounts,
    # so an order that registered its own would spend that allowance on nothing.
    check(f"the account was reused rather than registered again, "
          f"got {len(ca.accounts)}", len(ca.accounts) == 1)
    check("and the portal stored exactly one account row",
          len(db.q("SELECT id FROM certaccounts")) == 1)

    print("a wildcard and its base share one record name with two values")
    oid3 = certs.create("user-1", "*.wild.example.com, wild.example.com",
                        ca="custom", ca_url=ca.base + "/directory",
                        key_source="new", key_type="ec256", agreed=True)
    w = certs.one(oid3)
    check(f"one record name, got {[g['record'] for g in w['records']]}",
          len(w["records"]) == 1)
    group = w["records"][0]
    check(f"named for the base, got {group['record']}",
          group["record"] == "_acme-challenge.wild.example.com")
    check(f"with two DIFFERENT values, got {group['txt']}",
          len(group["txt"]) == 2 and len(set(group["txt"])) == 2)
    check("and both domains listed against it",
          sorted(group["domains"]) == ["*.wild.example.com",
                                       "wild.example.com"])
    # half the pair is the failure this shape exists to prevent
    ca.dns[group["record"]] = {group["txt"][0]}
    certs.proceed(oid3)
    half = drive(oid3, rounds=2)
    check(f"one value alone is not enough, got {half['status']}",
          half["status"] == "checking_dns")
    check("and it says one of two is missing",
          "1 of 2 values missing" in half["dns_note"])
    publish(ca, half)
    check(f"both values and it issues, got {drive(oid3)['status']}",
          certs.one(oid3)["status"] == "ready")

    print("renewing with the same key keeps the same key")
    oid4 = certs.renew(oid, "user-1", same_key=True)
    publish(ca, certs.one(oid4))
    certs.proceed(oid4)
    new = drive(oid4)
    check(f"the renewal issued, got {new['status']} ({new.get('error')})",
          new["status"] == "ready")
    old_key = certs._row(oid)["d"]["key_pem"]
    new_key = certs._row(oid4)["d"]["key_pem"]
    check("the stored key is byte-for-byte the same", old_key == new_key)
    # and the certificate the CA signed really carries that key, which is the
    # part that matters to whatever is already deployed
    def pubnums(pem_or_cert, is_cert=False):
        if is_cert:
            obj = x509.load_pem_x509_certificate(pem_or_cert.encode())
            return obj.public_key().public_numbers()
        return serialization.load_pem_private_key(
            pem_or_cert.encode(), password=None).public_key().public_numbers()
    check("and the new certificate is for that same public key",
          pubnums(certs.files(oid4)["cert"][1], True) == pubnums(new_key))
    check("while the certificate itself is a new one",
          certs.one(oid4)["facts"]["serial"] != certs.one(oid)["facts"]["serial"])

    print("renewing with a new key changes the key")
    oid5 = certs.renew(oid, "user-1", same_key=False)
    publish(ca, certs.one(oid5))
    certs.proceed(oid5)
    drive(oid5)
    check("it issued", certs.one(oid5)["status"] == "ready")
    check("with a different private key",
          certs._row(oid5)["d"]["key_pem"] != old_key)

    print("a pasted CSR is signed without the portal ever holding the key")
    outside_key = certs.new_key("rsa2048")
    csr = certs.make_csr(outside_key, ["csr.example.com", "alt.example.com"])
    oid6 = certs.create("user-1", "", ca="custom",
                        ca_url=ca.base + "/directory", key_source="csr",
                        csr_in=csr, agreed=True)
    c = certs.one(oid6)
    check(f"the domains came out of the CSR, got {c['domains']}",
          c["domains"] == ["csr.example.com", "alt.example.com"])
    check("and the portal says it holds no key", not c["has_key"])
    publish(ca, c)
    certs.proceed(oid6)
    done = drive(oid6)
    check(f"it issued, got {done['status']} ({done.get('error')})",
          done["status"] == "ready")
    check("there is no private key to download",
          "privkey" not in certs.files(oid6))
    check("the certificate is for the outside key",
          pubnums(certs.files(oid6)["cert"][1], True)
          == outside_key.public_key().public_numbers())
    check("and that order cannot be picked for 'keep the same key'",
          oid6 not in [o["id"] for o in certs.reusable()])

    print("when the CA rejects the records, the reason is the CA's own words")
    ca.fail_validation = True
    oid7 = certs.create("user-1", "bad.example.com", ca="custom",
                        ca_url=ca.base + "/directory", key_source="new",
                        agreed=True)
    publish(ca, certs.one(oid7))
    certs.proceed(oid7)
    failed = drive(oid7)
    check(f"it failed, got {failed['status']}", failed["status"] == "failed")
    check(f"quoting the CA, got {failed['error']!r}",
          "incorrect TXT record" in failed["error"]
          or "no TXT record" in failed["error"])
    check("and it says a new order is needed rather than a retry",
          "new order" in failed["error"])
    ca.fail_validation = False

    print("a CA that signs slowly is waited for, not given up on")
    ca.slow_finalize = 2
    oid8 = certs.create("user-1", "slow.example.com", ca="custom",
                        ca_url=ca.base + "/directory", key_source="new",
                        agreed=True)
    publish(ca, certs.one(oid8))
    certs.proceed(oid8)
    check(f"it still finished, got {drive(oid8)['status']}",
          certs.one(oid8)["status"] == "ready")

    print("a portal that cannot query DNS waits — it does NOT spend the order")
    # This asserted the opposite until *.preprod.acme.ke was burnt by it. The
    # old reasoning was that a blind container should ask the CA regardless,
    # since the CA does its own lookup and would have succeeded. True whenever
    # the record happens to be published — and the old test only ever tried it
    # that way, which is why it passed. Publish nothing and the same code fails
    # an authorization that ACME does not allow to be retried, ending the order
    # about a minute after it was opened.
    dns.reachable = False
    oid9 = certs.create("user-1", "blind.example.com", ca="custom",
                        ca_url=ca.base + "/directory", key_source="new",
                        agreed=True)
    before = len([c for c in ca.calls if "/chall/" in c])
    certs.proceed(oid9)                     # NOTE: nothing published yet
    for _ in range(certs.BLIND_ROUNDS + 2):
        certs.advance(oid9)
    waiting = certs.one(oid9)
    check(f"it says it cannot ask, got {waiting['dns_note']!r}",
          "cannot query the DNS" in waiting["dns_note"])
    check(f"and is still waiting rather than failed, got {waiting['status']}",
          waiting["status"] == "checking_dns")
    check("and the CA was never asked, so the order is not spent",
          len([c for c in ca.calls if "/chall/" in c]) == before)
    check(f"and the page can offer the override, blind={waiting['blind']}",
          waiting["blind"] >= 1)

    print("...and asks only when the operator accepts the cost")
    publish(ca, certs.one(oid9))
    certs.check_anyway(oid9)
    got = drive(oid9)
    check(f"then it asks and issues, got {got['status']} "
          f"({got.get('error')})", got["status"] == "ready")
    check("and the CA was asked exactly then",
          len([c for c in ca.calls if "/chall/" in c]) > before)
    dns.reachable = True

    print("the CA is the one that rejected it, so the strictness was real")
    check("every request was signature-checked and nonce-checked",
          len(ca.spent) > 20)
    check("and POST-as-GET was used to read, never a bare GET",
          not any(c.startswith("GET /order") or c.startswith("GET /authz")
                  for c in ca.calls))

    print("the list, and what it says about each order")
    every = certs.orders()
    check(f"every order is listed, got {len(every)}", len(every) == 9)
    check("newest first", every[0]["created_at"] >= every[-1]["created_at"])
    ready = [o for o in every if o["status"] == "ready"]
    check("the ready ones carry a days_left",
          all(o["days_left"] is not None for o in ready))
    check("and none of them is flagged as expiring",
          not any(o["expiring"] for o in ready))
    check("'keep the key' offers only orders whose key is here",
          all(o["has_key"] for o in certs.reusable()))
    check("the in-flight flag is off once everything settled",
          not any(o["in_flight"] for o in every))

    print("an order can be abandoned, and a finished one cannot")
    spare = certs.create("user-1", "spare.example.com", ca="custom",
                         ca_url=ca.base + "/directory", key_source="new",
                         agreed=True)
    certs.cancel(spare)
    check(f"the abandoned one is cancelled, got {certs.one(spare)['status']}",
          certs.one(spare)["status"] == "cancelled")
    check("and the worker leaves it alone", spare not in certs.due())
    certs.cancel(oid)
    check("an issued certificate is not cancellable",
          certs.one(oid)["status"] == "ready")
    certs.remove(spare)
    check("and removing it removes it", certs.one(spare) is None)

    print("nobody has to be watching: the worker finishes it alone")
    # The whole point of the page. Every other test here calls advance() by hand,
    # which proves the state machine and not the thing the operator was promised:
    # paste the records, close the browser, come back to a certificate. So this
    # one starts the real worker and then does nothing at all.
    certs.TICK = 1
    certs.start_worker()
    alone = certs.create("user-1", "unattended.example.com", ca="custom",
                         ca_url=ca.base + "/directory", key_source="new",
                         key_type="ec256", agreed=True)
    publish(ca, certs.one(alone))
    certs.proceed(alone)                   # the button, and then nothing
    deadline = time.time() + 30
    while time.time() < deadline and certs.one(alone)["status"] in certs.IN_FLIGHT:
        time.sleep(0.5)
    got = certs.one(alone)
    check(f"it issued with no further request, got {got['status']} "
          f"({got.get('error')})", got["status"] == "ready")
    check("and the certificate is there to download",
          "fullchain" in certs.files(alone))
    check("its timeline says what happened while nobody was looking",
          any("issued by" in e["text"] for e in got["events"]))

    print("the routes are wired to the engine they think they are")
    # The engine is exercised directly everywhere above, which proves the engine
    # and not the wiring. These call the route functions with a form, because the
    # failure this catches is a mis-wired field — a passphrase arriving as a CSR
    # — and it produces a valid-looking order that simply cannot work.
    import asyncio
    from app import main as M

    class Form(dict):
        pass

    def request(form=None):
        return types.SimpleNamespace(
            url=types.SimpleNamespace(path="/certs"), session={}, scope={},
            client=types.SimpleNamespace(host="10.0.0.9"),
            headers={},
            query_params=types.SimpleNamespace(getlist=lambda k: [],
                                               get=lambda k, d=None: d),
            state=types.SimpleNamespace(user={"id": "user-1",
                                              "email": "ops@example.com",
                                              "role": "admin"}),
            form=lambda: _form(form or {}))

    async def _form(d):
        return Form(d)

    outside = certs.new_key("rsa2048")
    resp = asyncio.run(M.certs_new(request({
        "domains": "route.example.com", "ca": "custom",
        "ca_url": ca.base + "/directory", "email": "ops@example.com",
        "key_source": "paste", "key_pem": certs.key_pem(outside),
        "agreed": "1"})))
    check(f"the form redirects to the new order, got {resp.headers['location']}",
          resp.headers["location"].startswith("/certs?id=ct-"))
    rid = resp.headers["location"].split("id=")[1]
    routed = certs.one(rid)
    check(f"with the domain from the form, got {routed['domains']}",
          routed["domains"] == ["route.example.com"])
    # the field that would betray a mis-wiring: the pasted key was used, not
    # generated, so the stored key is byte-for-byte the one the form carried
    check("and the pasted key is the key it will use",
          certs._row(rid)["d"]["key_pem"] == certs.key_pem(outside))

    publish(ca, routed)
    asyncio.run(M.certs_proceed(request(), rid))
    check(f"the proceed route moved it on, got {certs.one(rid)['status']}",
          certs.one(rid)["status"] in certs.IN_FLIGHT + ("ready",))
    for _ in range(8):
        asyncio.run(M.certs_check(request(), rid))
        if certs.one(rid)["status"] == "ready":
            break
    check(f"and the check route carried it to ready, got "
          f"{certs.one(rid)['status']}", certs.one(rid)["status"] == "ready")

    got = asyncio.run(M.certs_download(request(), rid, "fullchain"))
    check("the download route returns the chain",
          b"BEGIN CERTIFICATE" in got.body)
    check("named for the domain",
          "route.example.com.fullchain.pem" in got.headers["content-disposition"])
    asyncio.run(M.certs_download(request(), rid, "privkey"))
    # Downloading a private key is the one act here worth being able to prove
    # happened, so it is recorded rather than merely permitted.
    trail = db.q("SELECT action, target FROM audit WHERE action = ?",
                 ("cert_key_download",))
    check(f"and the key download is in the audit log, got {len(trail)} entries",
          len(trail) == 1
          and "route.example.com" in (trail[0]["target"] or ""))
    check("as is the request itself",
          any(r["action"] == "cert_requested"
              for r in db.q("SELECT action FROM audit")))
    try:
        asyncio.run(M.certs_download(request(), rid, "nonsense"))
        check("an unknown file kind should 404", False)
    except Exception as e:                                     # noqa: BLE001
        check(f"an unknown file kind 404s, got {type(e).__name__}",
              getattr(e, "status_code", None) == 404)

    print("no field name is invisible from a template")
    # `{{ group.values }}` resolved to the dict's own .values METHOD, so the
    # records card raised "object of type builtin_function_or_method has no
    # len()" — and only for an order that had records to show, which is every
    # order somebody actually needs. Jinja tries the attribute before the item,
    # so any field named after one of dict's methods cannot be read from a
    # template. Walked over everything a template is handed rather than the one
    # field that was noticed: this is the third time in this codebase.
    def shadowed(obj, where, depth=0):
        if depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and hasattr({}, k):
                    check(f"{where}.{k} shadows dict.{k}", False)
                shadowed(v, f"{where}.{k}", depth + 1)
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:3]):
                shadowed(v, f"{where}[{i}]", depth + 1)

    for o in certs.orders():
        shadowed(o, f"order[{o['status']}]")
    shadowed(certs.txt_at("_acme-challenge.example.com"), "txt_at")
    shadowed({"cas": certs.CAS, "key_types": certs.KEY_TYPES,
              "key_sources": certs.KEY_SOURCES}, "form")

    print("agreeing to the terms is not optional")
    try:
        certs.create("user-1", "nope.example.com", ca="custom",
                     ca_url=ca.base + "/directory", key_source="new")
        check("an order without agreement should have been refused", False)
    except certs.CertError as e:
        check(f"and it says why, got {e}", "agreement" in str(e))

    print("the list does not parse a private key to describe one")
    # WHY THIS IS COUNTED AND NOT TIMED. The fault was 143ms per order inside
    # `load_pem_private_key`, so a wall-clock assertion would pass on a fast
    # machine with the bug still there, and fail on a slow one without it. The
    # parse either happens or it does not.
    import app.certs as _c
    parses = []
    real_load = _c.load_key

    def counting_load(pem, passphrase=""):
        parses.append(1)
        return real_load(pem, passphrase)

    _c.load_key = counting_load
    try:
        every = _c.orders()
        parses.clear()                 # the backfill may legitimately run once
        every = _c.orders()
        after_list = len(parses)
    finally:
        _c.load_key = real_load

    check(f"a second listing parses no keys at all, got {after_list}",
          after_list == 0)

    # COUNT THE CALL, NOT THE PARSE. The first version of this asserted that
    # reusable() parsed no keys — which is true however it is written, now that
    # the description is stored, so it passed with the re-read still in place.
    # What the fix actually removes is a second whole listing: the query, the
    # unseal and the decorate for every order.
    listings = []
    real_orders = _c.orders

    def counting_orders():
        listings.append(1)
        return real_orders()

    _c.orders = counting_orders
    try:
        reuse = _c.reusable(every)
    finally:
        _c.orders = real_orders
    check(f"and reusable() re-reads nothing when handed the list, got "
          f"{len(listings)} listing(s)", not listings)
    check("while still describing the keys it holds",
          any(o["key_desc"].startswith(("RSA", "ECDSA")) for o in every))
    check(f"and still finding the reusable ones, got {len(reuse)}",
          len(reuse) >= 1)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
