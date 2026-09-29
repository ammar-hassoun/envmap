#!/usr/bin/env python3
"""A certificate somebody else signs: generate the CSR, keep the key, take the
.crt back, and bundle a p12.

THE FAILURE THIS EXISTS TO PREVENT is not a software bug. A key is generated
with `openssl req` on a laptop, the CSR is emailed to a provider, and three
weeks later the signed certificate arrives and the key is in a Downloads
folder on a machine that has been reimaged. So the key is generated here,
sealed here, and still here when the certificate comes back.

The signing is done by a REAL throwaway CA built in this file rather than by a
fixture, because the one check worth having -- that the certificate and the
held key are actually a pair -- can only be proven by signing a CSR properly
and then trying to attach a certificate signed from a different key.

    ./.venv/bin/python tests/test_extcert.py
"""
from __future__ import annotations

import datetime
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("extcert-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cryptography import x509                                  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa      # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402
from cryptography.x509.oid import NameOID                      # noqa: E402

from app import certs                                          # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    print(("  ok  " if cond else "  FAIL ") + what)
    if not cond:
        bad += 1


# ── a throwaway provider ───────────────────────────────────────
def make_ca(name="Test Issuing CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def sign(ca_key, ca_cert, csr_pem, days=365, names=None):
    """Sign a CSR the way a provider would, optionally adjusting the names."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(n) for n in (names or certs.csr_domains(csr_pem))]
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pem_of(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def main() -> int:
    ca_key, ca_cert = make_ca()

    print("the CSR carries the subject a commercial CA demands")
    # An ACME CA reads the SAN list and throws the subject away. A provider
    # signing an OV certificate REFUSES an order without O, C and ST -- days
    # later, by email, from a person.
    oid = certs.create_external(
        "u1", ["api.example.com", "www.example.com"], name="api",
        key_type="rsa2048",
        subject={"org": "Acme Ltd", "country": "ae", "state": "Dubai",
                 "locality": "Dubai", "unit": "Platform"})
    row = certs.one(oid)
    check("the order is waiting for the provider",
          row["status"] == "awaiting_signing")
    check("...and says so in words", row["state_label"] == "With the provider")
    csr_pem = certs.files(oid)["csr"][1]
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    dn = csr.subject.rfc4514_string()
    check("the subject carries O", "O=Acme Ltd" in dn)
    check("...and a two-letter country, upper-cased", "C=AE" in dn)
    check("...and the state spelled out", "ST=Dubai" in dn)
    check("every domain is in the SAN list",
          set(certs.csr_domains(csr_pem)) == {"api.example.com",
                                              "www.example.com"})

    print("the private key is held, sealed, and never in the CSR")
    check("the CSR is downloadable", "csr" in certs.files(oid))
    check("the key is downloadable", "privkey" in certs.files(oid))
    check("...and the CSR does not contain it",
          "PRIVATE KEY" not in csr_pem)
    # Sealed at rest: the raw column must not contain the key.
    from app import db
    raw = dict(db.one("SELECT data FROM certorders WHERE id = ?", (oid,)))["data"]
    check("the stored blob is sealed, not plaintext",
          "BEGIN PRIVATE KEY" not in raw and "BEGIN RSA PRIVATE KEY" not in raw)

    print("the signed certificate comes back and is matched to the key")
    crt = sign(ca_key, ca_cert, csr_pem)
    got = certs.attach_cert(oid, crt + pem_of(ca_cert))
    check("it is accepted", got["matched_key"] is True)
    row = certs.one(oid)
    check("the order is ready", row["status"] == "ready")
    check("the expiry is recorded, so the radar can see it",
          row["expires_at"] > 0 and row["days_left"] > 300)
    check("the names are read back off the certificate",
          set(row["facts"].get("domains") or []) == {"api.example.com",
                                                     "www.example.com"})

    print("...and a certificate from a DIFFERENT key is refused")
    # The failure this prevents: a p12 that builds, deploys, and fails the
    # handshake, at which point somebody is reading TLS logs at 02:00.
    other = certs.create_external("u1", ["api.example.com"], name="other")
    other_crt = sign(ca_key, ca_cert, certs.files(other)["csr"][1])
    try:
        certs.attach_cert(oid, other_crt)
        check("a mismatched certificate is refused", False)
    except certs.CertError as e:
        check("a mismatched certificate is refused",
              "does not match" in str(e))
    check("...and the good certificate is still in place",
          certs.one(oid)["status"] == "ready")

    print("a chain in the wrong order is straightened, not rejected")
    oid2 = certs.create_external("u1", ["svc.example.com"], name="svc")
    leaf2 = sign(ca_key, ca_cert, certs.files(oid2)["csr"][1])
    # A provider's bundle commonly arrives root-first. Caught rather than left
    # to propagate: without the straightening the key-match check fires on the
    # CA certificate and raises "public key does not match", which is true of
    # what it examined and a completely misleading description of the fault.
    try:
        certs.attach_cert(oid2, pem_of(ca_cert) + leaf2)
        straightened = True
    except certs.CertError:
        straightened = False
    check("a root-first bundle is accepted, not mistaken for a mismatch",
          straightened)
    f = certs.files(oid2) if straightened else {}
    first = x509.load_pem_x509_certificate(
        f["cert"][1].encode()) if "cert" in f else None
    check("the stored chain has a leaf at all", first is not None)
    if first is None:
        print("OK" if not bad else f"{bad} FAILED")
        return 1 if bad else 0
    check("the leaf is first in the stored chain",
          first.subject != first.issuer)
    check("...and the chain file holds the CA", "chain" in f)

    print("...and a bundle with no end-entity certificate says so")
    oid3 = certs.create_external("u1", ["x.example.com"], name="x")
    try:
        certs.attach_cert(oid3, pem_of(ca_cert))
        check("a CA-only file is refused", False)
    except certs.CertError as e:
        check("a CA-only file is refused", "no end-entity" in str(e))

    print("names the provider changed are REPORTED, not refused")
    # Providers legitimately adjust a request. Refusing would leave somebody
    # holding a certificate they paid for and cannot store.
    oid4 = certs.create_external("u1", ["a.example.com", "b.example.com"],
                                 name="adj")
    adj = sign(ca_key, ca_cert, certs.files(oid4)["csr"][1],
               names=["a.example.com", "extra.example.com"])
    got4 = certs.attach_cert(oid4, adj)
    check("it is still accepted", certs.one(oid4)["status"] == "ready")
    check("the dropped name is reported", got4["missing"] == ["b.example.com"])
    check("the added name is reported", got4["extra"] == ["extra.example.com"])

    print("the p12 is real, and openable by what will consume it")
    name, blob = certs.pkcs12_bundle(oid, "s3cret")
    check("it is named for the order", name.endswith(".p12"))
    key, cert, cas = pkcs12.load_key_and_certificates(blob, b"s3cret")
    check("the key is in it", key is not None)
    check("the leaf is in it",
          cert is not None and "api.example.com" in
          [g.value for g in cert.extensions.get_extension_for_class(
              x509.SubjectAlternativeName).value])
    check("the chain is in it, which openssl pkcs12 most often drops",
          bool(cas))
    try:
        pkcs12.load_key_and_certificates(blob, b"wrong")
        check("the passphrase actually protects it", False)
    except Exception:                                          # noqa: BLE001
        check("the passphrase actually protects it", True)

    print("...and the legacy mode is a DIFFERENT file, for Java 8")
    # Java 8 cannot read an AES-256 PKCS#12 and fails with an unhelpful parse
    # error, so this is not a cosmetic option.
    _n, legacy = certs.pkcs12_bundle(oid, "s3cret", mode="legacy")
    # NOT `legacy != blob`: a PKCS#12 carries a random salt, so two
    # serialisations of identical input differ anyway and that assertion is
    # true however the mode is implemented. It passed with the legacy branch
    # deleted. Check the ALGORITHM instead, by its OID in the DER.
    #   1.2.840.113549.1.12.1.3  pbeWithSHAAnd3-KeyTripleDES-CBC  (legacy)
    #   1.2.840.113549.1.5.13    PBES2                            (modern)
    TRIPLE_DES = bytes.fromhex("2a864886f70d010c0103")
    PBES2 = bytes.fromhex("2a864886f70d01050d")
    check("the legacy bundle really is 3DES", TRIPLE_DES in legacy)
    check("...and the modern one really is PBES2/AES", PBES2 in blob)
    check("...so they are genuinely different formats",
          (TRIPLE_DES in legacy) != (TRIPLE_DES in blob))
    k2, c2, _ = pkcs12.load_key_and_certificates(legacy, b"s3cret")
    check("...and the legacy one still opens", k2 is not None and c2 is not None)

    print("the refusals that keep a broken bundle from being built")
    try:
        certs.pkcs12_bundle(oid3, "x")
        check("no certificate yet -> refused", False)
    except certs.CertError as e:
        check("no certificate yet -> refused", "no certificate" in str(e))

    print("through the HTTP stack, which is where the wiring actually is")
    import time as _t
    from fastapi.testclient import TestClient
    from app import auth, db, main
    email, pw = "cert@test.local", "Provider-Signed-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    with c:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(_t.time() // auth.TOTP_STEP))},
            follow_redirects=False)

        page = c.get("/certs?new=1").text
        check("the form offers a provider", 'value="external"' in page)
        check("...and the subject fields it needs", 'name="subj_org"' in page)
        check("...hidden until it is chosen",
              'id="subj_fields" class="hidden"' in page)

        r = c.post("/certs/new", data={
            "ca": "external", "domains": "pay.example.com",
            "name": "pay", "key_type": "ec256",
            "subj_org": "Acme Ltd", "subj_country": "AE",
            "subj_state": "Dubai", "note": "ticket OPS-4210"},
            follow_redirects=False)
        check("it creates an order", r.status_code == 303)
        new_oid = r.headers["location"].split("id=")[-1]
        page = c.get(f"/certs?id={new_oid}").text
        check("the page shows the CSR to send",
              "Send this to the provider" in page
              and "BEGIN CERTIFICATE REQUEST" in page)
        check("...and the note, for three weeks from now",
              "ticket OPS-4210" in page)
        check("...and an upload box for the .crt", "/attach" in page)
        # A form that posts a certificate must not be snapshotted into browser
        # storage by the portal-wide retry mechanism.
        check("the paste box is marked data-nosave",
              'name="cert_pem" rows="8" data-nosave' in page)

        signed = sign(ca_key, ca_cert, certs.files(new_oid)["csr"][1])
        r = c.post(f"/certs/{new_oid}/attach", data={"cert_pem": signed},
                   follow_redirects=False)
        check("the upload is accepted", r.status_code == 303
              and "err=" not in r.headers["location"])
        page = c.get(f"/certs?id={new_oid}").text
        check("the order is now ready", "PKCS#12" in page)
        check("...and offers both p12 formats",
              "Modern (AES-256)" in page and "Compatible" in page)

        r = c.post(f"/certs/{new_oid}/p12",
                   data={"passphrase": "hunter2", "mode": "modern"})
        check("the p12 downloads", r.status_code == 200
              and r.headers["content-type"] == "application/x-pkcs12")
        k, cert, _cas = pkcs12.load_key_and_certificates(r.content, b"hunter2")
        check("...and opens with the passphrase", k is not None)

        # A p12 CONTAINS the private key, so it must be audited exactly as a
        # key download is.
        rows = db.q("SELECT action FROM audit ORDER BY id DESC LIMIT 12")
        acts = [dict(x)["action"] for x in rows]
        check("the p12 download is audited", "cert_p12_download" in acts)
        check("...and so is the upload", "cert_attached" in acts)

        r = c.post(f"/certs/{new_oid}/attach", data={"cert_pem": "not a cert"},
                   follow_redirects=False)
        check("rubbish is refused, in words",
              "err=" in r.headers["location"])

    print("the expiry radar sees it — which is the tracking half of the ask")
    from app import expiry, rbac
    me = {"id": uid, "email": email, "role": "admin"}
    check("the user can read the radar", rbac.may_area(me, "expiry"))
    rows, _notes = expiry._certificates(me, False)
    # the row is named for the ORDER, which is "pay" -- not for the domain.
    mine = [r for r in rows if r and r.get("name") == "pay"]
    check("the provider certificate is on the radar", bool(mine))
    if mine:
        check("...with a real countdown", mine[0]["days"] > 300)
        check("...and marked as needing a person, since nothing renews it",
              mine[0]["renewal"] == expiry.MANUAL)
        # The row must not claim the portal issued it: nothing here can
        # reissue a provider certificate, and sending somebody to the wrong
        # place is the whole cost of getting this sentence wrong.
        check("...and says a provider signed it, not this portal",
              "provider" in mine[0]["detail"])

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
