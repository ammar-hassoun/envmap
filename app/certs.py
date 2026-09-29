"""Let's Encrypt certificates, issued from a page instead of from a terminal.

WHAT THIS REPLACES
    `certbot --manual --preferred-challenges dns`, run on somebody's laptop,
    with a TXT record copied into the DNS by hand and the terminal held open
    until validation finished. Three things about that are worth fixing rather
    than writing down: the private key ends up wherever the command happened to
    run, the person who pasted the record has to stay for the DNS to propagate,
    and the next renewal is a command somebody has to remember.

THE SHAPE OF THE ANSWER
    An order is a row, and every step it has taken lives in that row. Nothing is
    held in a request and nothing is held in a browser tab: the records are
    printed, the tab can be closed, and a worker in the background carries the
    order from "the records are in the DNS" to "here is your certificate".
    Coming back an hour later is the normal path, not a recovery path — which is
    also why a pod restart mid-order resumes instead of starting again.

WHY THE PROTOCOL IS SPOKEN DIRECTLY
    certbot in the image would be a second thing to install and keep current,
    and its manual hook wants a terminal to talk to. ACME itself is small — a
    signed POST, a nonce, and four URLs out of the directory — and speaking it
    here means the portal owns the key, the state and the retry, which is the
    whole point of the page.

WHY THE DNS RECORD IS STILL MANUAL
    The portal can already reach Cloudflare and NS1 from the Edge page, so
    writing the record itself is a short step from here. It is deliberately not
    taken yet: the zone that needs the record is frequently not the zone the
    portal holds a token for, and a certificate that *cannot* be issued without
    an API token in the portal is a worse product than one that prints a record
    to paste. The visibility check below exists so that manual step is not also
    a blind one.

WHAT IS SEALED
    Both private keys — the ACME account key and the certificate's own key — and
    everything else in an order's blob. A certificate is public, but it sits in
    the same JSON as the key that answers it, and sealing the blob has no
    failure mode where somebody adds a field and forgets. See secretbox.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym
from cryptography.x509.oid import ExtensionOID, NameOID

from . import db, env, secretbox, urlguard

# ── what the form offers ───────────────────────────────────────
# key: (label, directory URL, note)
CAS = {
    "le": ("Let's Encrypt",
           "https://acme-v02.api.letsencrypt.org/directory",
           "certificates every browser trusts · 90 days · rate limited per "
           "registered domain"),
    "le-staging": ("Let's Encrypt staging",
                   "https://acme-staging-v02.api.letsencrypt.org/directory",
                   "for rehearsing: the certificate is NOT trusted, but the "
                   "limits are generous — use this to prove a DNS record works"),
    "custom": ("Another ACME provider", "",
               "any RFC 8555 directory URL. External account binding is not "
               "supported, so providers that require it will refuse"),
}

# key: (label, note). RSA 2048 is first on purpose: an ECDSA certificate is the
# better choice everywhere it is accepted, and payment endpoints and older
# middleboxes are exactly where it is not. Somebody generating a certificate for
# a bank's callback URL should not have to discover that here.
KEY_TYPES = {
    "rsa2048": ("RSA 2048", "the safe default — accepted by everything"),
    "rsa3072": ("RSA 3072", "stronger, still RSA"),
    "rsa4096": ("RSA 4096", "slowest handshake of the four; ask before using it "
                            "on a high-traffic endpoint"),
    "ec256": ("ECDSA P-256", "smaller and faster than any RSA key here, and "
                             "what certbot now picks by default"),
    "ec384": ("ECDSA P-384", "ECDSA, one size up"),
}

# Where the private key comes from. The middle two exist because renewing without
# changing the key is a real requirement — a pinned key, a key inside an HSM's
# escrow, a key already deployed to fifty devices — and the terminal answer to it
# is `certbot --csr`, which is what "paste a CSR" is.
KEY_SOURCES = {
    "new": ("Generate a new private key",
            "the usual choice — a fresh key and a fresh certificate"),
    "reuse": ("Keep the key from a certificate here",
              "same private key, new certificate: nothing deployed has to "
              "change except the certificate file"),
    "paste": ("Paste an existing private key",
              "for a key this portal has not seen; it is sealed at rest like "
              "every other secret here"),
    "csr": ("Paste a CSR",
            "the portal never sees the key at all — it signs what you give it. "
            "This is `certbot --csr` and it is the safest of the four"),
}

STATES = {
    "awaiting_dns": ("Waiting for you", "▲",
                     "the records below are ready to paste into the DNS"),
    "checking_dns": ("Looking for the records", "◴",
                     "asking the DNS until the records appear — you can close "
                     "this page"),
    "validating": ("Being validated", "◴",
                   "the CA has been asked to check the records"),
    "finalizing": ("Being signed", "◴", "the CSR is with the CA"),
    "awaiting_signing": ("With the provider", "✉",
                        "the CSR is ready to send; upload the .crt when it "
                        "comes back"),
    "ready": ("Ready", "✓", "the certificate is issued and downloadable"),
    "failed": ("Failed", "✕", "nothing was issued — the reason is on the order"),
    "cancelled": ("Cancelled", "—", "abandoned before it finished"),
}
IN_FLIGHT = ("checking_dns", "validating", "finalizing")

# How long to keep asking the DNS for a record nobody has pasted yet. Six hours
# because a delegated zone with a slow secondary is measured in hours, and the
# alternative — failing at ten minutes — throws away an order that would have
# worked. The CA's own order expiry (a week) is the real ceiling.
DNS_WAIT = 6 * 3600
# Rounds where the *lookup itself* failed, as opposed to answering "no record",
# after which the CA is asked anyway. A pod with no egress on port 53 can still
# have perfectly good public DNS; refusing to proceed because this container
# cannot see it would make the page useless in exactly the networks it is
# most likely to run in.
BLIND_ROUNDS = 3
TICK = 20                     # seconds between worker passes
HTTP_TIMEOUT = 30
UA = f"envmap/{env.VERSION} (ACME client)"

DNS_TXT, DNS_NS, DNS_A, DNS_CNAME = 16, 2, 1, 5


class CertError(Exception):
    """Something the person on the page needs to read."""


# ── storage ────────────────────────────────────────────────────
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS certorders (
        id TEXT PRIMARY KEY,
        name TEXT,
        ca TEXT,
        status TEXT,
        created_at INTEGER,
        updated_at INTEGER,
        expires_at INTEGER DEFAULT 0,
        user_id TEXT,
        data TEXT)""",
    """CREATE TABLE IF NOT EXISTS certaccounts (
        id TEXT PRIMARY KEY,
        ca TEXT,
        email TEXT,
        kid TEXT,
        created_at INTEGER,
        data TEXT)""",
    "CREATE INDEX IF NOT EXISTS certorders_status ON certorders (status)",
]


def _migrate(c) -> None:
    for stmt in SCHEMA:
        c.execute(stmt)
    _backfill_key_desc(c)


def _backfill_key_desc(c) -> None:
    """Write `key_desc` into orders stored before it was recorded at creation.

    Once, at startup, rather than on the page: this parses a private key per
    order and that is the 143ms the read path exists to stop paying. Orders
    created from here on carry it already, so this finds nothing and costs one
    query.

    Deliberately forgiving. An order whose blob will not unseal (a rotated
    sealing key) or whose key will not parse is SKIPPED, not fixed and not
    fatal — `_key_desc` still answers for it, and a portal that will not start
    because one certificate is unreadable is a far worse outcome than a page
    that is slow for that row.
    """
    try:
        rows = c.execute("SELECT id, data FROM certorders").fetchall()
    except Exception:                                             # noqa: BLE001
        return
    for r in rows:
        try:
            d = _unpack(r["data"])
            if not d or d.get("key_desc") or not d.get("key_pem"):
                continue
            if d.get("key_source") == "csr":
                continue
            d["key_desc"] = key_kind(load_key(d["key_pem"]))
            c.execute("UPDATE certorders SET data = ? WHERE id = ?",
                      (_pack(d), r["id"]))
        except Exception:                                         # noqa: BLE001
            continue


db.register(_migrate)


def _pack(extra: dict) -> str:
    return secretbox.seal(json.dumps(extra))


def _unpack(raw) -> dict:
    try:
        return json.loads(secretbox.unseal(raw or "") or "{}")
    except Exception:                                          # noqa: BLE001
        # An unreadable blob means the sealing key changed. One order losing its
        # state must not take down the list that shows every other order.
        return {}


def _rid(prefix: str) -> str:
    return f"{prefix}-{os.urandom(5).hex()}"


def _row(oid: str) -> dict | None:
    r = db.one("SELECT * FROM certorders WHERE id = ?", (oid,))
    if not r:
        return None
    out = dict(r)
    out["d"] = _unpack(out.pop("data"))
    return out


def _save(oid: str, status: str | None = None, expires_at: int | None = None,
          **fields) -> None:
    """Merge into one order's blob, and touch it. Every state change goes
    through here so nothing can advance in memory only — the worker has to be
    able to pick up where a restart left off."""
    with db.tx() as c:
        row = c.execute("SELECT data FROM certorders WHERE id = ?",
                        (oid,)).fetchone()
        if row is None:
            return
        blob = _unpack(row["data"])
        blob.update(fields)
        sets = ["data = ?", "updated_at = ?"]
        vals: list = [_pack(blob), int(time.time())]
        if status is not None:
            sets.append("status = ?")
            vals.append(status)
        if expires_at is not None:
            sets.append("expires_at = ?")
            vals.append(int(expires_at))
        c.execute(f"UPDATE certorders SET {', '.join(sets)} WHERE id = ?",
                  vals + [oid])


def _note(oid: str, text: str) -> None:
    """One line on the order's own timeline.

    The page is frequently opened hours after the interesting thing happened, so
    "what did it do while I was away" has to be answerable from the row. Capped,
    because a polling loop would otherwise write for ever.
    """
    row = _row(oid)
    if not row:
        return
    events = (row["d"].get("events") or [])[-49:]
    events.append({"at": int(time.time()), "text": text[:300]})
    _save(oid, events=events)


# ── keys, CSRs and certificates ────────────────────────────────
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def new_key(kind: str):
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    bits = {"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}.get(kind, 2048)
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()


def load_key(pem: str, passphrase: str = ""):
    """A pasted key. The passphrase is used to READ it and is not kept: the key
    is sealed by the portal's own sealing key from then on, so a second secret
    to lose would protect nothing."""
    try:
        key = serialization.load_pem_private_key(
            (pem or "").strip().encode(),
            password=(passphrase.encode() if passphrase else None))
    except TypeError as e:
        raise CertError("that key is encrypted — give its passphrase, or "
                        "decrypt it first") from e
    except ValueError as e:
        detail = str(e).lower()
        if "decrypt" in detail or "password" in detail:
            raise CertError("that passphrase does not open the key") from e
        raise CertError("that does not read as a PEM private key") from e
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CertError("only RSA and ECDSA keys can be used for a "
                        "certificate here")
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise CertError(f"that key is {key.key_size} bits — a public CA will "
                        f"refuse anything under 2048")
    return key


def key_kind(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECDSA {key.curve.name}"
    return f"RSA {key.key_size}"


# The subject fields a commercial CA asks for. An ACME CA ignores every one of
# them and reads only the SAN list -- but an OV or EV order placed with a
# commercial provider is REFUSED without them, and the refusal arrives days
# later as an email from a person. Ordered as X.509 conventionally prints them.
SUBJECT_FIELDS = (
    ("org", NameOID.ORGANIZATION_NAME, "Organisation", "O",
     "the legal entity name, exactly as the provider will verify it"),
    ("unit", NameOID.ORGANIZATIONAL_UNIT_NAME, "Department", "OU",
     "optional, and some providers refuse an order that carries it"),
    ("country", NameOID.COUNTRY_NAME, "Country", "C", "two letters, e.g. AE"),
    ("state", NameOID.STATE_OR_PROVINCE_NAME, "State or province", "ST",
     "spelled out, not abbreviated"),
    ("locality", NameOID.LOCALITY_NAME, "City", "L", ""),
    ("email", NameOID.EMAIL_ADDRESS, "Contact email", "emailAddress",
     "optional; this goes in the subject, not the SAN list"),
)


def make_csr(key, domains: list[str], subject: dict | None = None) -> str:
    """A CSR over every name, with the first also as the common name.

    The common name is redundant -- a public CA reads the SAN list and nothing
    else -- but it is set anyway because plenty of software that consumes the
    finished certificate still prints it, and an empty subject reads as broken.
    A name over 64 characters cannot go there at all, so it is left out rather
    than truncated into a lie.

    `subject` CARRIES THE REST OF THE DISTINGUISHED NAME, and exists for the
    other kind of CA entirely. An ACME provider reads the SAN list and throws
    the subject away; a commercial provider signing an OV certificate refuses
    an order without O, C and ST, and that refusal arrives days later as an
    email from a person. It is optional, so the ACME path is unchanged.
    """
    parts = []
    first = domains[0]
    if len(first) <= 64:
        parts.append(x509.NameAttribute(NameOID.COMMON_NAME, first))
    for field, oid, _label, _short, _note in SUBJECT_FIELDS:
        val = str((subject or {}).get(field) or "").strip()
        if not val:
            continue
        if oid is NameOID.COUNTRY_NAME:
            # TWO LETTERS IS THE ENCODING, not a convention: `cryptography`
            # raises on anything else, and that raise would land at signing
            # time rather than on the form where it can be corrected.
            val = val.upper()[:2]
        parts.append(x509.NameAttribute(oid, val))
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(parts))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
        critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def csr_domains(pem: str) -> list[str]:
    """Every name in a pasted CSR, so the order asks for exactly what the CSR
    will be signed for. Reading them out of the CSR rather than asking twice
    removes the failure where the two disagree and the CA rejects the pair."""
    try:
        csr = x509.load_pem_x509_csr((pem or "").strip().encode())
    except ValueError as e:
        raise CertError("that does not read as a PEM certificate request") from e
    if not csr.is_signature_valid:
        raise CertError("that CSR's signature does not verify — it is corrupt "
                        "or was truncated in the paste")
    names: list[str] = []
    try:
        ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names += list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if attr.value not in names:
            names.append(str(attr.value))
    if not names:
        raise CertError("that CSR names no domains — it has neither a subject "
                        "alternative name nor a common name")
    return names


def read_cert(pem: str) -> dict:
    """What a certificate says about itself, for anything that needs to know.

    `cert_facts` is the ACME flow's own reader and is strict: it walks the
    extensions to find the SAN list, and a certificate whose extensions this
    library refuses to parse yields nothing at all. Measured against a real
    cluster, three certificates in sixty-six were like that — sealed-secrets
    controller keys, whose KeyUsage sets encipher_only without key_agreement,
    which RFC 5280 forbids and `cryptography` enforces.

    Refusing to report an expiry because an unrelated extension is malformed
    would hide precisely the certificates nobody is watching, so this degrades
    instead: full facts when they can be read, the date alone when they cannot,
    and an explicit error when even that fails. `partial` says which happened.
    """
    # `not_before` is declared here, not only merged from `cert_facts`, so the
    # PARTIAL path carries it too. It is what makes a certificate its own
    # second witness: lifetime = not_after - not_before, and a certificate
    # that claims an automatic renewer while sitting below its own renewal
    # window is proof from its own bytes that nothing is renewing it.
    out = {"not_after": None, "not_before": None, "domains": [], "issuer": "",
           "serial": "", "partial": False, "error": ""}
    text = (pem or "").strip()
    if not text:
        out["error"] = "no certificate"
        return out
    try:
        facts = cert_facts(text)
    except Exception:                                          # noqa: BLE001
        facts = {}
    if facts.get("not_after"):
        return {**out, **facts, "partial": False, "error": ""}
    # the strict read failed; the date alone is still worth having
    try:
        leaf = _split_chain(text)
        one = x509.load_pem_x509_certificate((leaf[0] if leaf else text).encode())
        out["not_after"] = int(one.not_valid_after_utc.timestamp())
        out["not_before"] = int(one.not_valid_before_utc.timestamp())
        out["partial"] = True
        out["error"] = "only the dates could be read from this certificate"
    except Exception as e:                                     # noqa: BLE001
        out["error"] = f"unreadable certificate ({type(e).__name__})"
    return out


def _split_chain(pem: str) -> list[str]:
    parts = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem or "", re.S)
    return [p.strip() + "\n" for p in parts]


def cert_facts(pem: str) -> dict:
    """What the page prints about an issued certificate. Read back out of the
    PEM rather than remembered from the request: the CA decides the dates, and
    the only honest source for them is the certificate itself."""
    chain = _split_chain(pem)
    if not chain:
        return {}
    leaf = x509.load_pem_x509_certificate(chain[0].encode())
    try:
        names = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    issuer = ""
    for attr in leaf.issuer:
        if attr.oid == NameOID.COMMON_NAME:
            issuer = str(attr.value)
    return {
        "domains": list(names),
        "not_before": int(leaf.not_valid_before_utc.timestamp()),
        "not_after": int(leaf.not_valid_after_utc.timestamp()),
        "issuer": issuer or "unknown",
        "serial": f"{leaf.serial_number:x}",
        "key": key_kind_public(leaf.public_key()),
        "chain_len": len(chain),
    }


def key_kind_public(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}"
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    return type(pub).__name__


# ── JOSE: the signed envelope every ACME request travels in ────
def _jwk(key) -> dict:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        nums = key.public_key().public_numbers()
        size = (key.curve.key_size + 7) // 8
        crv = {256: "P-256", 384: "P-384", 521: "P-521"}[key.curve.key_size]
        return {"crv": crv, "kty": "EC",
                "x": _b64(nums.x.to_bytes(size, "big")),
                "y": _b64(nums.y.to_bytes(size, "big"))}
    nums = key.public_key().public_numbers()
    return {"e": _b64(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
            "kty": "RSA",
            "n": _b64(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"))}


def _alg(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {256: "ES256", 384: "ES384", 521: "ES512"}[key.curve.key_size]
    return "RS256"


def _sign(key, data: bytes) -> bytes:
    """ECDSA signatures come out of `cryptography` as DER and go into a JWS as
    raw r||s. Getting this wrong produces a signature the CA rejects with
    "JWS verification error", which says nothing about the cause.

    The hash follows the curve, not the default: ES384 means SHA-384, and signing
    a P-384 key's JWS with SHA-256 would be a valid signature under the wrong
    algorithm name. Only P-256 account keys are generated here, so this is the
    branch that would rot quietly if it were wrong.
    """
    if isinstance(key, ec.EllipticCurvePrivateKey):
        algo = {256: hashes.SHA256(), 384: hashes.SHA384(),
                521: hashes.SHA512()}[key.curve.key_size]
        r, s = asym.decode_dss_signature(key.sign(data, ec.ECDSA(algo)))
        size = (key.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def thumbprint(key) -> str:
    """RFC 7638: SHA-256 of the JWK with sorted keys and no whitespace. The
    canonical form is the whole point — a space anywhere and every DNS record
    computed from it is wrong in a way that only the CA notices."""
    canon = json.dumps(_jwk(key), sort_keys=True,
                       separators=(",", ":")).encode()
    return _b64(hashlib.sha256(canon).digest())


# ── talking to the CA ──────────────────────────────────────────
_nonces: dict[str, str] = {}
_dir_cache: dict[str, tuple[float, dict]] = {}


def _http(url: str, body: bytes | None = None, ctype: str = "",
          accept: str = "") -> tuple[int, bytes, dict]:
    headers = {"User-Agent": UA}
    if ctype:
        headers["Content-Type"] = ctype
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(urlguard.check(url), data=body,
                                 headers=headers,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        # An ACME error is a body worth reading, not an exception worth hiding:
        # "detail" is the only field that ever tells you what to fix.
        return e.code, e.read(), dict(e.headers or {})
    except urllib.error.URLError as e:
        raise CertError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: "
                        f"{e.reason}") from e
    except OSError as e:
        raise CertError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: "
                        f"{e}") from e


def _problem(status: int, body: bytes) -> str:
    """The CA's complaint, in the words it used."""
    try:
        doc = json.loads(body or b"{}")
    except ValueError:
        return f"HTTP {status} from the CA"
    bits = [str(doc.get("detail") or doc.get("type") or f"HTTP {status}")]
    for sub in doc.get("subproblems") or []:
        who = (sub.get("identifier") or {}).get("value", "")
        bits.append(f"{who}: {sub.get('detail', '')}".strip(": "))
    return " · ".join(b for b in bits if b)[:600]


def directory(url: str) -> dict:
    """The CA's four URLs. Cached for an hour: it changes about never, and every
    order would otherwise start with a round trip that teaches nothing."""
    hit = _dir_cache.get(url)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    status, body, _ = _http(url)
    if status != 200:
        raise CertError(f"that does not look like an ACME directory "
                        f"({_problem(status, body)})")
    try:
        doc = json.loads(body)
    except ValueError as e:
        raise CertError("the directory did not answer with JSON — check the "
                        "URL ends in /directory") from e
    if not doc.get("newOrder") or not doc.get("newAccount"):
        raise CertError("that JSON is not an ACME directory: it has no "
                        "newOrder or newAccount")
    _dir_cache[url] = (time.time(), doc)
    return doc


def _nonce(dirdoc: dict) -> str:
    url = dirdoc.get("newNonce") or ""
    got = _nonces.pop(url, "")
    if got:
        return got
    _, _, headers = _http(url)
    n = headers.get("Replay-Nonce", "")
    if not n:
        raise CertError("the CA issued no nonce, so nothing can be signed")
    return n


def _post(dirdoc: dict, url: str, payload, key, kid: str = "",
          accept: str = "") -> tuple[int, bytes, dict]:
    """One signed request. `payload` of None means POST-as-GET, which is how
    everything is read in ACME — a plain GET is not authenticated and the CA
    will not answer an order with one."""
    for attempt in (1, 2):
        protected = {"alg": _alg(key), "nonce": _nonce(dirdoc), "url": url}
        if kid:
            protected["kid"] = kid
        else:
            protected["jwk"] = _jwk(key)
        p64 = _b64(json.dumps(protected, separators=(",", ":")).encode())
        body64 = ("" if payload is None
                  else _b64(json.dumps(payload, separators=(",", ":")).encode()))
        sig = _sign(key, f"{p64}.{body64}".encode())
        env_body = json.dumps({"protected": p64, "payload": body64,
                               "signature": _b64(sig)}).encode()
        status, raw, headers = _http(url, env_body, "application/jose+json",
                                     accept)
        if headers.get("Replay-Nonce"):
            _nonces[dirdoc.get("newNonce", "")] = headers["Replay-Nonce"]
        if status == 400 and attempt == 1 and b"badNonce" in raw:
            # The spec requires a retry with a fresh nonce, and a replayed one
            # is normal whenever two orders move at the same moment.
            _nonces.pop(dirdoc.get("newNonce", ""), None)
            continue
        return status, raw, headers
    return status, raw, headers                        # pragma: no cover


def account(ca_url: str, email: str) -> tuple[object, str]:
    """The ACME account for this CA and address, registered once and reused.

    Reused rather than created per order because a CA counts new accounts: Let's
    Encrypt allows ten per address block per three hours, and an order that
    registers its own account would spend that allowance on nothing. The key
    never leaves this row.
    """
    email = (email or "").strip().lower()
    row = db.one("SELECT * FROM certaccounts WHERE ca = ? AND email = ?",
                 (ca_url, email))
    if row:
        blob = _unpack(row["data"])
        pem = blob.get("key_pem") or ""
        if pem and row["kid"]:
            return serialization.load_pem_private_key(pem.encode(),
                                                      password=None), row["kid"]
    dirdoc = directory(ca_url)
    key = ec.generate_private_key(ec.SECP256R1())
    payload = {"termsOfServiceAgreed": True}
    if email:
        payload["contact"] = [f"mailto:{email}"]
    status, body, headers = _post(dirdoc, dirdoc["newAccount"], payload, key)
    if status not in (200, 201):
        raise CertError(f"the CA would not register an account: "
                        f"{_problem(status, body)}")
    kid = headers.get("Location", "")
    if not kid:
        raise CertError("the CA registered an account but returned no id")
    aid = _rid("ac")
    db.run("INSERT INTO certaccounts (id, ca, email, kid, created_at, data) "
           "VALUES (?,?,?,?,?,?)",
           (aid, ca_url, email, kid, int(time.time()),
            _pack({"key_pem": key_pem(key)})))
    return key, kid


def terms(ca_url: str) -> str:
    """The subscriber agreement the account has to accept. Shown on the form,
    because agreeing on somebody's behalf without showing them what they agreed
    to is not a thing this page is going to do."""
    try:
        return str((directory(ca_url).get("meta") or {}).get(
            "termsOfService", ""))
    except CertError:
        return ""


# ── DNS: can the internet see the record yet? ──────────────────
_zone_cache: dict[str, tuple[float, list[str]]] = {}


def _candidate_resolvers() -> list[str]:
    """Whom to ask when the zone's own servers cannot be found.

    The system resolver comes first because inside a cluster it is the only one
    that can see a split-horizon zone. The public ones follow because a pod's
    resolver is frequently a CoreDNS with no route off the cluster, and a
    challenge record has to be visible from the internet anyway.
    """
    out = [x.strip() for x in (env.DNS_RESOLVERS or "").split(",") if x.strip()]
    if out:
        return out
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    bits = line.split()
                    if len(bits) > 1:
                        out.append(bits[1])
    except OSError:
        pass
    return out + ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


_live: tuple[float, list[str]] = (0.0, [])
_live_lock = threading.Lock()


def _resolvers() -> list[str]:
    """The candidates that actually answer, probed once and remembered.

    Measured, not guessed: /etc/resolv.conf on the first machine this ran on
    listed two IPv6 addresses it could not route, and paying their timeouts on
    every question turned a two-second visibility check into twenty-four
    seconds. Probed in parallel so learning that costs one timeout, not five,
    and re-probed every few minutes because a resolver coming back is normal.
    """
    global _live
    with _live_lock:
        if time.time() - _live[0] < 300 and _live[1]:
            return list(_live[1])
    cands = _candidate_resolvers()
    ok: dict[str, bool] = {}

    def probe(ip: str) -> None:
        try:
            # The root's NS records: every recursive resolver answers it from
            # its own hints, so this asks "are you a resolver and can I reach
            # you" without depending on anything downstream being up.
            ok[ip] = bool(_ask(ip, "", DNS_NS, timeout=1.5))
        except Exception:                                      # noqa: BLE001
            ok[ip] = False

    threads = [threading.Thread(target=probe, args=(ip,), daemon=True)
               for ip in cands]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)
    live = [ip for ip in cands if ok.get(ip)]
    with _live_lock:
        _live = (time.time(), live)
    # None answered: hand back the candidates anyway so the caller reports
    # "could not query the DNS" rather than "the record is missing".
    return live or cands


def _pack_query(name: str, qtype: int) -> tuple[int, bytes]:
    qid = int.from_bytes(os.urandom(2), "big")
    head = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    body = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue                      # the root, which is the null label
        raw = label.encode("ascii", "strict")
        if len(raw) > 63:
            raise CertError(f"{name} is not a name this can look up")
        body += bytes([len(raw)]) + raw
    return qid, head + body + b"\x00" + struct.pack(">HH", qtype, 1)


def _read_name(buf: bytes, pos: int) -> tuple[str, int]:
    """A DNS name, following compression pointers. `pos` after the name as it
    appeared — a pointer is two bytes however far it jumps."""
    parts: list[str] = []
    end, jumped, hops = pos, False, 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated name")
        n = buf[pos]
        if n & 0xC0 == 0xC0:
            if hops > 16:
                raise ValueError("compression loop")
            hops += 1
            ptr = struct.unpack(">H", buf[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            pos, jumped = ptr, True
            continue
        pos += 1
        if n == 0:
            if not jumped:
                end = pos
            break
        parts.append(buf[pos:pos + n].decode("ascii", "replace"))
        pos += n
    return ".".join(parts), end


def _ask(server: str, name: str, qtype: int, timeout: float = 2.5) -> list[tuple]:
    """One question to one server, over UDP and then TCP if the answer did not
    fit. Returns [(type, value)] for the answer section."""
    qid, query = _pack_query(name, qtype)
    fam = (socket.AF_INET6 if ":" in server else socket.AF_INET)
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, (server, 53))
        while True:
            buf, _ = s.recvfrom(4096)
            if len(buf) >= 2 and struct.unpack(">H", buf[:2])[0] == qid:
                break
    if len(buf) < 12:
        raise OSError("short DNS answer")
    flags = struct.unpack(">H", buf[2:4])[0]
    if flags & 0x0200:                                    # truncated
        buf = _ask_tcp(server, query, fam, timeout)
    return _answers(buf)


def _ask_tcp(server: str, query: bytes, fam: int, timeout: float) -> bytes:
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(query)) + query)
        head = s.recv(2)
        if len(head) < 2:
            raise OSError("short DNS answer over TCP")
        want = struct.unpack(">H", head)[0]
        out = b""
        while len(out) < want:
            chunk = s.recv(want - len(out))
            if not chunk:
                break
            out += chunk
    return out


def _answers(buf: bytes) -> list[tuple]:
    qd, an = struct.unpack(">HH", buf[4:8])
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(buf, pos)
        pos += 4
    out: list[tuple] = []
    for _ in range(an):
        _, pos = _read_name(buf, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        rdata = buf[pos:pos + rdlen]
        if rtype == DNS_TXT:
            text, at = "", 0
            while at < len(rdata):
                ln = rdata[at]
                text += rdata[at + 1:at + 1 + ln].decode("utf-8", "replace")
                at += 1 + ln
            out.append((DNS_TXT, text))
        elif rtype in (DNS_NS, DNS_CNAME):
            got, _ = _read_name(buf, pos)
            out.append((rtype, got.rstrip(".").lower()))
        elif rtype == DNS_A and rdlen == 4:
            out.append((DNS_A, socket.inet_ntoa(rdata)))
        pos += rdlen
    return out


def _authoritative(name: str) -> tuple[list[str], str]:
    """The addresses of the servers that own this name, walking up the labels.

    Asked directly, rather than through a recursive resolver, because of one
    failure that wastes everybody's afternoon: a resolver that was asked for the
    record before it existed caches the *absence* for the zone's negative TTL,
    and will keep saying "no such record" long after the record is live. The
    server that owns the zone has nothing to cache.
    """
    labels = name.rstrip(".").lower().split(".")
    start = 1 if labels and labels[0].startswith("_") else 0
    for cut in range(start, max(len(labels) - 1, start + 1)):
        zone = ".".join(labels[cut:])
        if zone.count(".") < 1:
            break
        hit = _zone_cache.get(zone)
        if hit and time.time() - hit[0] < 300:
            if hit[1]:
                return hit[1], zone
            continue
        names: list[str] = []
        for server in _resolvers()[:3]:
            try:
                names = [v for t, v in _ask(server, zone, DNS_NS) if t == DNS_NS]
            except (OSError, ValueError, CertError):
                continue
            if names:
                break
        ips: list[str] = []
        for ns in names[:4]:
            for server in _resolvers()[:2]:
                try:
                    ips += [v for t, v in _ask(server, ns, DNS_A) if t == DNS_A]
                    break
                except (OSError, ValueError, CertError):
                    continue
        _zone_cache[zone] = (time.time(), ips)
        if ips:
            return ips, zone
    return [], ""


def txt_at(name: str) -> dict:
    """What the DNS is serving at this name right now.

    `reachable` is the field that matters as much as the values: "the record is
    not there" and "this container cannot ask" are different situations, and
    treating the second as the first would strand every install whose egress on
    port 53 is closed.
    """
    servers, zone = _authoritative(name)
    how = f"{zone}'s own nameservers" if servers else "public resolvers"
    if not servers:
        servers = _resolvers()[:3]
    seen: set[str] = set()
    cname = ""
    reached, errors = 0, []

    def _sweep(ips):
        nonlocal reached, cname
        for ip in ips:
            try:
                got = _ask(ip, name, DNS_TXT)
            except (OSError, ValueError) as e:
                errors.append(f"{ip}: {e}")
                continue
            except CertError as e:
                errors.append(str(e))
                continue
            reached += 1
            for rtype, value in got:
                if rtype == DNS_TXT:
                    seen.add(value)
                elif rtype == DNS_CNAME:
                    cname = value

    _sweep(servers[:4])
    if not reached and zone:
        # The zone's own nameservers are preferred because a recursive resolver
        # can serve a cached NXDOMAIN long after the record is published. But
        # preferring them is not the same as needing them: where egress to the
        # public internet on port 53 is closed and only the cluster resolver
        # answers — which is the common shape inside a cluster — insisting on
        # authoritative means reporting blindness while a perfectly good answer
        # sits one query away. Take the weaker answer and say it is weaker.
        _sweep(_resolvers()[:3])
        if reached:
            how = ("a recursive resolver, not the zone's nameservers — a stale "
                   "negative is possible, so trust a positive more than a blank")
    if cname and not seen:
        # Delegating _acme-challenge with a CNAME into a zone you can write is a
        # normal way to run this, and the target's nameservers are not the ones
        # asked above — so follow it once.
        for ip in _resolvers()[:3]:
            try:
                for rtype, value in _ask(ip, cname, DNS_TXT):
                    if rtype == DNS_TXT:
                        seen.add(value)
            except (OSError, ValueError, CertError):
                continue
        how += f" · followed the CNAME to {cname}"
    return {"txt": sorted(seen), "asked": how, "reachable": bool(reached),
            "error": "; ".join(errors[:2]) if not reached else "",
            "cname": cname}


# ── an order, from the form to a certificate ───────────────────
_DOMAIN = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def clean_domains(raw) -> list[str]:
    """What the form typed, as names a CA will accept.

    Rejecting here rather than letting the CA reject is not politeness: a
    malformed name in an order means the whole order fails, after the account
    round trip and against the failed-order limit.
    """
    if isinstance(raw, str):
        parts = re.split(r"[\s,;]+", raw)
    else:
        parts = list(raw or [])
    out: list[str] = []
    for p in parts:
        d = (p or "").strip().rstrip(".").lower()
        if d.startswith("http://") or d.startswith("https://"):
            d = urllib.parse.urlsplit(d).netloc or d
        if not d:
            continue
        if d in out:
            continue
        try:
            d.encode("ascii")
        except UnicodeEncodeError:
            raise CertError(
                f"{d} is not ASCII — enter the punycode form (xn--…) instead"
            ) from None
        if not _DOMAIN.match(d):
            raise CertError(f"{d} is not a domain name a public CA will issue "
                            f"for")
        if d.count("*") and not d.startswith("*."):
            raise CertError(f"{d}: a wildcard can only be the leftmost label")
        out.append(d)
    if not out:
        raise CertError("no domains were given")
    if len(out) > 100:
        raise CertError("a certificate can carry 100 names at most")
    return out


def challenge_name(domain: str) -> str:
    """Where the TXT record goes. A wildcard validates at its base — the star is
    not part of the record name, which is the single most common way a pasted
    record ends up in the wrong place."""
    return "_acme-challenge." + domain.removeprefix("*.")


def create(user_id: str, domains, ca: str = "le", ca_url: str = "",
           email: str = "", key_source: str = "new", key_type: str = "rsa2048",
           reuse_from: str = "", key_pem_in: str = "", passphrase: str = "",
           csr_in: str = "", agreed: bool = False) -> str:
    """Ask the CA for an order and write down what it wants proved.

    Everything expensive happens here — the account, the order, the challenge
    digests — so that by the time the page renders, the records are final and
    can be pasted without anything else needing to be running.
    """
    if not agreed:
        raise CertError("the CA's subscriber agreement has to be accepted "
                        "before an account can be registered")
    url = (ca_url or "").strip() if ca == "custom" else CAS.get(ca, ("", ""))[1]
    if not url:
        raise CertError("no ACME directory URL — pick a provider or paste one")
    if ca == "custom":
        urlguard.check(url)

    key_obj, csr_pem, stored_key = None, "", ""
    if key_source == "csr":
        csr_pem = (csr_in or "").strip()
        names = clean_domains(csr_domains(csr_pem))
    else:
        names = clean_domains(domains)
        if key_source == "reuse":
            src = _row(reuse_from)
            if not src or not (src["d"].get("key_pem") or ""):
                raise CertError("that certificate has no private key here to "
                                "keep — it was issued from a pasted CSR")
            key_obj = load_key(src["d"]["key_pem"])
        elif key_source == "paste":
            key_obj = load_key(key_pem_in, passphrase)
        else:
            if key_type not in KEY_TYPES:
                raise CertError("unknown key type")
            key_obj = new_key(key_type)
        stored_key = key_pem(key_obj)
        csr_pem = make_csr(key_obj, names)

    dirdoc = directory(url)
    acct_key, kid = account(url, email)
    status, body, headers = _post(
        dirdoc, dirdoc["newOrder"],
        {"identifiers": [{"type": "dns", "value": d} for d in names]},
        acct_key, kid)
    if status not in (200, 201):
        raise CertError(f"the CA refused the order: {_problem(status, body)}")
    order = json.loads(body)
    order_url = headers.get("Location", "")
    if not order_url:
        raise CertError("the CA created an order but returned no URL for it")

    thumb = thumbprint(acct_key)
    authz = []
    for au in order.get("authorizations") or []:
        st, ab, _ = _post(dirdoc, au, None, acct_key, kid)
        if st != 200:
            raise CertError(f"the CA would not describe what to prove: "
                            f"{_problem(st, ab)}")
        doc = json.loads(ab)
        ident = (doc.get("identifier") or {}).get("value", "")
        wild = bool(doc.get("wildcard"))
        chall = next((c for c in doc.get("challenges") or []
                      if c.get("type") == "dns-01"), None)
        if not chall:
            raise CertError(f"the CA offers no DNS challenge for {ident} — "
                            f"only DNS validation can be done from here")
        token = chall.get("token", "")
        keyauth = f"{token}.{thumb}"
        authz.append({
            "domain": ("*." + ident) if wild else ident,
            "record": challenge_name(ident),
            "value": _b64(hashlib.sha256(keyauth.encode()).digest()),
            "url": au, "chall_url": chall.get("url", ""),
            "status": doc.get("status", "pending"), "detail": "",
        })

    oid = _rid("ct")
    now = int(time.time())
    db.run("INSERT INTO certorders (id, name, ca, status, created_at, "
           "updated_at, expires_at, user_id, data) VALUES (?,?,?,?,?,?,?,?,?)",
           (oid, names[0], url, "awaiting_dns", now, now, 0, user_id or "",
            _pack({
                "domains": names, "email": email, "ca_key": ca,
                "key_source": key_source, "key_type": key_type,
                "reuse_from": reuse_from, "key_pem": stored_key,
                "key_desc": key_kind(key_obj) if key_obj else "",
                "csr_pem": csr_pem, "order_url": order_url,
                "finalize_url": order.get("finalize", ""),
                "authz": authz, "events": [], "blind": 0, "waited_from": 0,
            })))
    _note(oid, f"order opened with {CAS.get(ca, ('the CA',))[0]} for "
               f"{', '.join(names)}")
    return oid


def records(row: dict) -> list[dict]:
    """The records to paste, grouped by name.

    A wildcard and its base domain both validate at `_acme-challenge.<base>`
    with a DIFFERENT value each, and both values must exist at the same time.
    Grouped into one entry with two values because the other shape — the same
    name twice — reads as a duplicate and gets helpfully "corrected" into one,
    which fails validation for the half that was deleted.
    """
    out: dict[str, dict] = {}
    for a in row["d"].get("authz") or []:
        got = out.setdefault(a["record"], {"record": a["record"], "txt": [],
                                           "domains": [], "done": True})
        if a["value"] not in got["txt"]:
            got["txt"].append(a["value"])
        got["domains"].append(a["domain"])
        if a.get("status") != "valid":
            got["done"] = False
    return list(out.values())


# ── the state machine, run by the worker and by "check now" ────
_busy: set[str] = set()
_busy_lock = threading.Lock()


def advance(oid: str) -> str:
    """Move one order as far as it can go without waiting on anybody.

    Every branch reads its state from the row and writes it back, so this is
    safe to call from the worker, from a button, or from a fresh process after a
    restart — and calling it twice does no more than calling it once.
    """
    with _busy_lock:
        if oid in _busy:
            return "busy"
        _busy.add(oid)
    try:
        return _advance(oid)
    except CertError as e:
        _fail(oid, str(e))
        return "failed"
    except Exception as e:                                    # noqa: BLE001
        # A bug in here must not take the worker down with it, and must not look
        # like a CA failure either.
        _fail(oid, f"the portal hit an internal error: {type(e).__name__}: {e}")
        return "failed"
    finally:
        with _busy_lock:
            _busy.discard(oid)


def _fail(oid: str, why: str) -> None:
    _save(oid, status="failed", error=why[:600])
    _note(oid, f"failed: {why[:200]}")


def _advance(oid: str) -> str:
    row = _row(oid)
    if not row or row["status"] not in IN_FLIGHT:
        return row["status"] if row else "gone"
    d = row["d"]
    dirdoc = directory(row["ca"])
    acct_key, kid = account(row["ca"], d.get("email", ""))

    if row["status"] == "checking_dns":
        return _step_dns(row, dirdoc, acct_key, kid)
    if row["status"] == "validating":
        return _step_validate(row, dirdoc, acct_key, kid)
    return _step_finalize(row, dirdoc, acct_key, kid)


def _step_dns(row: dict, dirdoc: dict, acct_key, kid: str) -> str:
    """Wait for the records, then tell the CA to look."""
    oid, d = row["id"], row["d"]
    started = d.get("waited_from") or int(time.time())
    missing, unreachable = [], 0
    for group in records(row):
        got = txt_at(group["record"])
        if not got["reachable"]:
            unreachable += 1
            continue
        absent = [v for v in group["txt"] if v not in got["txt"]]
        if absent:
            missing.append(f"{group['record']} ({len(absent)} of "
                           f"{len(group['txt'])} values missing)")
    blind = int(d.get("blind") or 0)
    if unreachable and not missing:
        blind += 1
        # BLIND IS NOT A REASON TO ASK THE CA. It used to be: after a few
        # unanswered rounds this called validation anyway, on the reasoning that
        # the CA does its own lookup and therefore knows better. The reasoning
        # is true and the conclusion was still wrong, because the two outcomes
        # do not cost the same. If the record is there, the CA says so and
        # nothing was gained over waiting. If it is not, the authorization fails
        # and **cannot be retried** — the whole order is spent, and the operator
        # has to start again. That is what happened to *.preprod.acme.ke: the
        # container had no route to the zone's nameservers, three blind rounds
        # elapsed inside a minute, and the order was burnt before anyone had
        # finished pasting the record into the DNS.
        #
        # So blindness now waits, exactly like a record that has not appeared
        # yet, and only an operator who is told the consequence can spend the
        # order on a guess. force_check is that decision.
        _save(oid, blind=blind, waited_from=started,
              dns_note="cannot query the DNS from here — waiting. Add the "
                       "record, then use Check anyway if it still says this.")
        if not d.get("force_check"):
            if time.time() - started > DNS_WAIT:
                raise CertError(
                    "could not query the DNS from this installation for "
                    f"{int(DNS_WAIT / 3600)} hours, so the records were never "
                    "confirmed. Nothing was sent to the CA, so no order was "
                    "spent: open port 53 outbound, or use Check anyway once "
                    "the record is published.")
            return "checking_dns"
        _note(oid, "cannot see the DNS from here — told to ask the CA anyway")
    elif missing:
        _save(oid, blind=0, waited_from=started,
              dns_note="not visible yet: " + "; ".join(missing[:3]))
        if time.time() - started > DNS_WAIT:
            raise CertError(
                "the records never appeared. Checked for "
                f"{int(DNS_WAIT / 3600)} hours: {'; '.join(missing[:3])}")
        return "checking_dns"
    else:
        _save(oid, blind=0, dns_note="")
        _note(oid, "the records are visible in the DNS")

    for a in d.get("authz") or []:
        if a.get("status") == "valid":
            continue
        st, body, _ = _post(dirdoc, a["chall_url"], {}, acct_key, kid)
        if st not in (200, 202):
            raise CertError(f"the CA would not start validation for "
                            f"{a['domain']}: {_problem(st, body)}")
    _save(oid, status="validating")
    _note(oid, "the CA has been asked to check the records")
    return "validating"


def _step_validate(row: dict, dirdoc: dict, acct_key, kid: str) -> str:
    """Poll the authorizations. A short inner loop, because validation usually
    takes a few seconds and a person who just pressed the button should see the
    answer rather than the next tick."""
    oid, d = row["id"], row["d"]
    authz = list(d.get("authz") or [])
    for _ in range(5):
        pending = False
        for a in authz:
            if a.get("status") in ("valid", "invalid"):
                continue
            st, body, _ = _post(dirdoc, a["url"], None, acct_key, kid)
            if st != 200:
                raise CertError(f"cannot read the authorization for "
                                f"{a['domain']}: {_problem(st, body)}")
            doc = json.loads(body)
            a["status"] = doc.get("status", "pending")
            for ch in doc.get("challenges") or []:
                if ch.get("type") == "dns-01" and ch.get("error"):
                    err = ch["error"]
                    a["detail"] = str(err.get("detail") or err.get("type"))[:300]
            if a["status"] not in ("valid", "invalid"):
                pending = True
        _save(oid, authz=authz)
        if not pending:
            break
        time.sleep(2)

    bad = [a for a in authz if a.get("status") == "invalid"]
    if bad:
        why = "; ".join(f"{a['domain']}: {a.get('detail') or 'rejected'}"
                        for a in bad)
        raise CertError(f"the CA could not verify the records — {why}. Fix the "
                        f"record and start a new order: an authorization the "
                        f"CA has failed cannot be retried.")
    if any(a.get("status") != "valid" for a in authz):
        return "validating"

    _note(oid, "every domain is validated")
    csr = x509.load_pem_x509_csr(d["csr_pem"].encode())
    st, body, _ = _post(
        dirdoc, d["finalize_url"],
        {"csr": _b64(csr.public_bytes(serialization.Encoding.DER))},
        acct_key, kid)
    if st not in (200, 201, 202):
        raise CertError(f"the CA refused the certificate request: "
                        f"{_problem(st, body)}")
    _save(oid, status="finalizing")
    _note(oid, "the CSR is with the CA")
    return _step_finalize(_row(oid), dirdoc, acct_key, kid)


def _step_finalize(row: dict, dirdoc: dict, acct_key, kid: str) -> str:
    """Poll the order until there is a certificate to fetch, then fetch it."""
    oid, d = row["id"], row["d"]
    for _ in range(6):
        st, body, _ = _post(dirdoc, d["order_url"], None, acct_key, kid)
        if st != 200:
            raise CertError(f"cannot read the order: {_problem(st, body)}")
        order = json.loads(body)
        state = order.get("status", "")
        if state == "valid" and order.get("certificate"):
            st, pem, _ = _post(dirdoc, order["certificate"], None, acct_key,
                               kid, accept="application/pem-certificate-chain")
            if st != 200:
                raise CertError(f"cannot download the certificate: "
                                f"{_problem(st, pem)}")
            body_pem = pem.decode()
            facts = cert_facts(body_pem)
            if not facts:
                raise CertError("the CA returned something that is not a "
                                "certificate chain")
            _save(oid, status="ready", expires_at=facts["not_after"],
                  cert_pem=body_pem, facts=facts, error="")
            _note(oid, f"issued by {facts['issuer']}, valid until "
                       f"{time.strftime('%d %B %Y', time.gmtime(facts['not_after']))}")
            return "ready"
        if state == "invalid":
            why = str((order.get("error") or {}).get("detail", ""))
            raise CertError("the CA marked the order invalid: "
                            + (why or "no reason given"))
        if state == "ready":
            # finalize was accepted but the CA has not started signing yet
            time.sleep(2)
            continue
        time.sleep(2)
    return "finalizing"


# ── what the routes call ───────────────────────────────────────
def proceed(oid: str) -> None:
    """The records are in the DNS — carry on without me.

    Records the intent and returns. It deliberately does not start the work: the
    worker owns that, and an order whose progress depended on the request that
    asked for it would be an order that stops when the browser does — which is
    the one thing this page exists not to do. A route wanting a head start calls
    kick() as well.
    """
    row = _row(oid)
    if not row or row["status"] not in ("awaiting_dns", "failed"):
        return
    _save(oid, status="checking_dns", waited_from=int(time.time()),
          blind=0, error="", dns_note="")
    _note(oid, "told to carry on: waiting for the records to appear")


def check_anyway(oid: str) -> None:
    """Spend the order on the operator's word that the record is published.

    Only reachable from a button that says what it costs. The portal cannot see
    the DNS from here, so this is the operator asserting what the portal cannot
    confirm — and if the assertion is wrong the authorization fails and the
    order is gone. That is why it is a separate action and not a shorter
    timeout: a timeout makes the same gamble without anybody choosing it.
    """
    row = _row(oid)
    if not row or row["status"] not in ("awaiting_dns", "checking_dns"):
        return
    _save(oid, status="checking_dns", force_check=1, error="",
          waited_from=row["d"].get("waited_from") or int(time.time()))
    _note(oid, "told to ask the CA without seeing the records here")


def kick(oid: str) -> None:
    """Advance one order in a thread, so a button does not hold a request open
    for the length of a validation."""
    threading.Thread(target=advance, args=(oid,), name=f"acme-{oid}",
                     daemon=True).start()


def cancel(oid: str) -> None:
    row = _row(oid)
    if row and row["status"] not in ("ready",):
        _save(oid, status="cancelled")
        _note(oid, "cancelled")


def remove(oid: str) -> None:
    db.run("DELETE FROM certorders WHERE id = ?", (oid,))


def renew(oid: str, user_id: str, same_key: bool = True) -> str:
    """A new order for the same names. Renewal is issuance here — there is no
    shortcut in ACME for "the same thing again", and DNS-01 needs fresh records
    every time, so pretending otherwise would only hide the work."""
    row = _row(oid)
    if not row:
        raise CertError("that certificate is gone")
    d = row["d"]
    has_key = bool(d.get("key_pem"))
    return create(
        user_id, d.get("domains") or [], ca=d.get("ca_key") or "le",
        ca_url=row["ca"], email=d.get("email", ""),
        key_source=("reuse" if (same_key and has_key) else "new"),
        key_type=d.get("key_type") or "rsa2048", reuse_from=oid,
        agreed=True)


def files(oid: str) -> dict:
    row = _row(oid)
    return _files_for(row) if row else {}


def _files_for(row: dict) -> dict:
    """Everything downloadable for one order, as {kind: (filename, text)}.

    Named for what a person is about to do with them, because "cert.pem" and
    "fullchain.pem" have burned enough afternoons: a server wants the chain, and
    the leaf on its own produces a browser error that names the wrong cause.

    Takes the row rather than an id because the page asks this of every order it
    lists, and going back to the database for each one meant a second read and a
    second unseal per row — and, worse, meant the list could disagree with the
    order it was listing.
    """
    d = row["d"]
    stem = (row["name"] or "certificate").replace("*.", "wildcard.")
    out: dict[str, tuple[str, str]] = {}
    chain = _split_chain(d.get("cert_pem") or "")
    if chain:
        out["fullchain"] = (f"{stem}.fullchain.pem", "".join(chain))
        out["cert"] = (f"{stem}.cert.pem", chain[0])
        if len(chain) > 1:
            out["chain"] = (f"{stem}.chain.pem", "".join(chain[1:]))
    if d.get("key_pem"):
        out["privkey"] = (f"{stem}.privkey.pem", d["key_pem"])
    if d.get("csr_pem"):
        out["csr"] = (f"{stem}.csr", d["csr_pem"])
    return out


def one(oid: str) -> dict | None:
    """One order, decorated for the page."""
    row = _row(oid)
    return _decorate(row) if row else None


def orders() -> list[dict]:
    rows = db.q("SELECT * FROM certorders ORDER BY created_at DESC")
    out = []
    for r in rows:
        row = dict(r)
        row["d"] = _unpack(row.pop("data"))
        out.append(_decorate(row))
    return out


def reusable(every: list[dict] | None = None) -> list[dict]:
    """Orders whose private key this portal holds, for the "keep the key"
    choice. A pasted-CSR order is excluded: there is nothing to keep.

    TAKES THE LIST. Every caller renders `orders()` on the same page, and this
    re-ran the whole of it — the database read, the unseal and (before the line
    above) a private-key parse per order — to throw all but a filter away. The
    default is kept so a caller with nothing in hand still works.
    """
    return [o for o in (orders() if every is None else every)
            if o["d"].get("key_pem") and o["status"] in ("ready", "failed")]


# ── certificates somebody else signs ───────────────────────────
# A provider takes a CSR, verifies the organisation by hand or by phone, and
# emails a .crt back days later. Nothing about that is automatable, and this
# code does not try: what it does is stop the private key from being the thing
# that goes missing in between. Generated here, sealed here, and still here
# when the certificate arrives.
EXTERNAL = "external"
EXTERNAL_LABEL = "Signed by a provider"


def create_external(user_id: str, domains, name: str = "",
                    key_type: str = "rsa2048", subject: dict | None = None,
                    note: str = "") -> str:
    """Generate a key and a CSR and hold both, waiting for the signed certificate.

    THE KEY NEVER LEAVES unless somebody downloads it. The failure this exists
    to prevent is the ordinary one: a key generated with `openssl req` on a
    laptop, the CSR emailed to the provider, and three weeks later the signed
    certificate arrives and the key is in a Downloads folder on a machine that
    has been reimaged.
    """
    names = clean_domains(domains)
    if not names:
        raise CertError("name at least one domain")
    if key_type not in KEY_TYPES:
        raise CertError(f"{key_type!r} is not a key type this portal makes")
    key = new_key(key_type)
    csr = make_csr(key, names, subject or {})
    oid = _rid("co")
    now = int(time.time())
    db.run("INSERT INTO certorders (id, name, ca, status, created_at, "
           "updated_at, expires_at, user_id, data) VALUES (?,?,?,?,?,?,?,?,?)",
           (oid, name.strip() or names[0], EXTERNAL, "awaiting_signing",
            now, now, 0, user_id,
            _pack({"domains": names, "key_pem": key_pem(key),
                   "key_desc": key_kind(key),
                   "csr_pem": csr, "key_type": key_type,
                   "subject": {k: str((subject or {}).get(k) or "").strip()
                               for k, *_ in SUBJECT_FIELDS},
                   "note": (note or "").strip()[:500],
                   "events": [{"at": now, "text": "CSR generated and held; "
                                                  "send it to the provider"}]})))
    return oid


def attach_cert(oid: str, pem: str) -> dict:
    """Store the certificate the provider signed, against the key we kept.

    Returns a dict of what was checked, because the checks ARE the feature --
    anyone can save a file. Raises `CertError` only on the two faults that
    make the pair useless.
    """
    row = _row(oid)
    if not row:
        raise CertError("that order is gone")
    if row["ca"] != EXTERNAL:
        raise CertError("this order was issued by an ACME provider; a "
                        "certificate cannot be pasted into it")
    chain = _split_chain(pem or "")
    if not chain:
        raise CertError("that is not a PEM certificate — it should begin "
                        "-----BEGIN CERTIFICATE-----")

    d = row["d"]
    # ORDER THE CHAIN LEAF-FIRST. A provider's bundle arrives in any order, and
    # some send the leaf in one file and the intermediates in another; a server
    # handed a chain in the wrong order serves an incomplete one and the
    # browser blames the certificate.
    leaf_at = None
    for i, one in enumerate(chain):
        try:
            c = x509.load_pem_x509_certificate(one.encode())
        except Exception:                                      # noqa: BLE001
            raise CertError(f"block {i + 1} of that file is not a certificate")
        if c.subject != c.issuer:                  # not self-signed = not a root
            try:
                c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                is_ca = c.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS).value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            if not is_ca and leaf_at is None:
                leaf_at = i
    if leaf_at is None:
        raise CertError("that file has no end-entity certificate in it — every "
                        "block is a CA. Paste the certificate the provider "
                        "issued, not only the chain")
    if leaf_at:
        chain = [chain[leaf_at]] + [c for i, c in enumerate(chain) if i != leaf_at]

    leaf = x509.load_pem_x509_certificate(chain[0].encode())

    # THE CHECK THAT MATTERS. A certificate and a private key that do not go
    # together produce a p12 that builds, deploys, and fails the handshake --
    # at which point somebody is reading TLS logs at 02:00. Compare the public
    # keys, which is the only thing that actually proves the pair.
    checks = {"matched_key": False, "covers": [], "missing": [], "extra": []}
    if d.get("key_pem"):
        try:
            priv = load_key(d["key_pem"])
        except Exception:                                      # noqa: BLE001
            priv = None
        if priv is not None:
            mine = priv.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            theirs = leaf.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            if mine != theirs:
                raise CertError(
                    "that certificate was not signed from this order's CSR — "
                    "its public key does not match the private key held here. "
                    "Check you have the right file, or that the provider did "
                    "not re-key the request.")
            checks["matched_key"] = True

    # `read_cert`, not `cert_facts`: the strict reader yields NOTHING when a
    # certificate carries an extension `cryptography` refuses, and a provider's
    # certificate is exactly the one we did not build and cannot re-issue.
    # Degrading to the dates alone keeps the expiry -- the whole point of
    # storing it -- when the SAN list cannot be parsed.
    facts = read_cert("".join(chain)) or {}
    asked = set(d.get("domains") or [])
    got = set(facts.get("domains") or [])
    checks["covers"] = sorted(got)
    # A NAME MISMATCH IS A WARNING, NOT A REFUSAL. Providers legitimately
    # adjust a request -- dropping a name they will not validate, or adding
    # the bare domain beside the www -- and refusing the upload would leave
    # somebody holding a certificate they paid for and cannot store.
    checks["missing"] = sorted(asked - got)
    checks["extra"] = sorted(got - asked)

    now = int(time.time())
    events = list(d.get("events") or [])
    events.append({"at": now, "text": "certificate uploaded"
                   + (" and matched to the stored key"
                      if checks["matched_key"] else "")})
    # `_save` MERGES KEYWORDS into the blob -- passing the whole dict as one
    # keyword stored it under a key literally called "extra" and nothing
    # landed, which the end-to-end test caught immediately and reading the
    # signature would not have.
    _save(oid, status="ready", expires_at=int(facts.get("not_after") or 0),
          cert_pem="".join(chain), facts=facts, checks=checks, events=events)
    return checks


# PKCS#12 is what a JVM, a .NET service and most SDKs actually want, and
# building one by hand is the step that goes wrong -- `openssl pkcs12` with
# the wrong -certfile produces a bundle missing its chain, which fails only
# against clients that do not already trust the intermediate.
P12_MODES = {
    "modern": ("Modern (AES-256)",
               "what current OpenSSL, Go, .NET and Java 11+ read"),
    "legacy": ("Compatible (3DES/SHA-1)",
               "for Java 8 and older keystores, which cannot read AES-256 "
               "PKCS#12 and fail with an unhelpful parse error"),
}


def pkcs12_bundle(oid: str, passphrase: str, mode: str = "modern") -> tuple:
    """(filename, bytes) for a .p12 holding the key, the leaf and the chain."""
    from cryptography.hazmat.primitives.serialization import (   # noqa: PLC0415
        BestAvailableEncryption, NoEncryption, PrivateFormat, pkcs12)

    row = _row(oid)
    if not row:
        raise CertError("that order is gone")
    d = row["d"]
    if not d.get("key_pem"):
        raise CertError("this order has no private key here, so there is "
                        "nothing to bundle")
    if not d.get("cert_pem"):
        raise CertError("no certificate has been uploaded to this order yet")
    chain = _split_chain(d["cert_pem"])
    key = load_key(d["key_pem"])
    leaf = x509.load_pem_x509_certificate(chain[0].encode())
    cas = [x509.load_pem_x509_certificate(c.encode()) for c in chain[1:]]

    if not passphrase:
        # An unprotected p12 is legal and almost always a mistake: it holds a
        # private key and it is about to be attached to an email or copied to
        # a build agent.
        enc = NoEncryption()
    elif mode == "legacy":
        enc = (PrivateFormat.PKCS12.encryption_builder()
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
               .hmac_hash(hashes.SHA1())        # an INSTANCE, not the class
               .build(passphrase.encode()))
    else:
        enc = BestAvailableEncryption(passphrase.encode())

    stem = (row["name"] or "certificate").replace("*.", "wildcard.")
    blob = pkcs12.serialize_key_and_certificates(
        name=stem.encode(), key=key, cert=leaf, cas=cas or None,
        encryption_algorithm=enc)
    return f"{stem}.p12", blob


def _stamp(epoch, with_time: bool = False) -> str:
    """A date as somebody reads it: "21 April 2026".

    Assembled rather than handed to strftime because the format that drops the
    leading zero is "%-d" on glibc and BSD and something else elsewhere, and a
    date is not worth a portability question.
    """
    if not epoch:
        return ""
    t = time.localtime(epoch)
    out = f"{t.tm_mday} {time.strftime('%B %Y', t)}"
    return f"{out}, {time.strftime('%H:%M', t)}" if with_time else out


def _decorate(row: dict) -> dict:
    d = row["d"]
    label, icon, note = STATES.get(row["status"], (row["status"], "·", ""))
    facts = d.get("facts") or {}
    left = None
    if row["expires_at"]:
        left = int((row["expires_at"] - time.time()) // 86400)
    return {
        **row,
        "domains": d.get("domains") or facts.get("domains") or [row["name"]],
        "state_label": label, "state_icon": icon, "state_note": note,
        "in_flight": row["status"] in IN_FLIGHT,
        "records": records(row),
        "facts": facts,
        "days_left": left,
        "expires_on": _stamp(row["expires_at"]),
        "created_on": _stamp(row["created_at"]),
        "opened_on": _stamp(row["created_at"], with_time=True),
        "expiring": left is not None and left <= 30,
        "error": d.get("error") or "",
        "dns_note": d.get("dns_note") or "",
        # drives the "Check anyway" button: offered only to an install that
        # cannot query the DNS, because for anyone else waiting is strictly
        # better than guessing
        "blind": int(d.get("blind") or 0),
        "events": [{**e, "when": _stamp(e.get("at"), with_time=True)}
                   for e in reversed(d.get("events") or [])],
        "ca_label": (EXTERNAL_LABEL if row["ca"] == EXTERNAL else
                     next((v[0] for v in CAS.values() if v[1] == row["ca"]),
                          row["ca"])),
        "external": row["ca"] == EXTERNAL,
        # NAMED FIELDS, not the blob. `d` is in the row and therefore reachable
        # from a template, and it holds `key_pem` -- so anything the page needs
        # is lifted out by name rather than by reaching in.
        "note": d.get("note") or "",
        "csr_pem": d.get("csr_pem") or "",
        "checks": d.get("checks") or {},
        "subject": d.get("subject") or {},
        "key_desc": _key_desc(d),
        "has_key": bool(d.get("key_pem")),
        "downloads": sorted(_files_for(row)) if row["status"] == "ready" else [],
    }


def _key_desc(d: dict) -> str:
    """"RSA 2048" or "ECDSA secp384r1", for the list and the reuse chooser.

    READ, NOT DERIVED. This used to load the private key to ask its size, on
    every order, every time the page rendered — and `load_pem_private_key`
    validates the key material, which is deliberately expensive: 143ms each,
    measured, so sixteen orders cost 2.3s of a page that reads nothing else
    slow. The answer cannot change once the key exists, so it is written when
    the key is generated and read back here.

    The parse survives as the fallback for an order stored before that, and
    `_backfill_key_desc` empties that set once at startup — without it a legacy
    row would pay the 143ms on every render for ever.
    """
    if d.get("key_source") == "csr":
        return "from a pasted CSR — the portal holds no key"
    if d.get("key_desc"):
        return str(d["key_desc"])
    pem = d.get("key_pem") or ""
    if not pem:
        return "no key"
    try:
        return key_kind(load_key(pem))
    except CertError:
        return "unreadable"


# ── the worker ─────────────────────────────────────────────────
def due() -> list[str]:
    return [r["id"] for r in db.q(
        "SELECT id FROM certorders WHERE status IN (?,?,?)", IN_FLIGHT)]


def start_worker() -> None:
    """Carry every order in flight, for ever, from a thread that cannot block a
    request. This is the whole reason the page can be closed: the browser is a
    view of the row, and this is what changes the row."""
    def loop():
        while True:
            try:
                for oid in due():
                    advance(oid)
            except Exception:                                  # noqa: BLE001
                pass          # a bad order is the page's problem, not the loop's
            time.sleep(TICK)

    threading.Thread(target=loop, name="acme-worker", daemon=True).start()
