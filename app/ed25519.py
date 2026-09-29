"""Ed25519 signing and verification, in the standard library alone.

The rest of the portal has no cryptographic dependency — the AWS signer, the
Alibaba signer and the session tokens all come out of hashlib and hmac — and a
signature check is not a good reason to add one: every extra wheel is another thing
that has to be present in an air-gapped customer's image.

This is the RFC 8032 reference construction. Verification runs in the portal;
signing runs only in the issuing tool on a machine you control, so the absence of
constant-time arithmetic costs nothing here — there is no secret to leak on the
verifying side, and nothing untrusted on the signing side.
"""
from __future__ import annotations

import hashlib
import os

# curve25519 / edwards25519 parameters, RFC 8032 §5.1
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)              # noqa: E741 — the RFC's name for it
BY = (4 * pow(5, P - 2, P)) % P
BX = 0                                   # recovered below


def _recover_x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x


BX = _recover_x(BY, 0)
B = (BX, BY, 1, (BX * BY) % P)           # extended coordinates


def _add(pt1: tuple, pt2: tuple) -> tuple:
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    d = (2 * z1 * z2) % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(pt: tuple, n: int) -> tuple:
    out = (0, 1, 1, 0)                   # neutral element
    while n > 0:
        if n & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        n >>= 1
    return out


def _equal(pt1: tuple, pt2: tuple) -> bool:
    x1, y1, z1, _ = pt1
    x2, y2, z2, _ = pt2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _compress(pt: tuple) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(raw: bytes) -> tuple | None:
    if len(raw) != 32:
        return None
    n = int.from_bytes(raw, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _secret_expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("an Ed25519 private key is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte private seed."""
    a, _ = _secret_expand(seed)
    return _compress(_mul(B, a))


def generate() -> tuple[bytes, bytes]:
    """(private seed, public key) from the OS entropy source."""
    seed = os.urandom(32)
    return seed, public_key(seed)


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _secret_expand(seed)
    pub = _compress(_mul(B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    big_r = _compress(_mul(B, r))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % L
    return big_r + int.to_bytes((r + k * a) % L, 32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """True when sig is a valid signature of msg under pub. Never raises: a
    malformed key or signature is simply an invalid one."""
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        point = _decompress(pub)
        big_r = _decompress(sig[:32])
        if point is None or big_r is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= L:
            return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                           "little") % L
        return _equal(_mul(B, s), _add(big_r, _mul(point, k)))
    except Exception:                                          # noqa: BLE001
        return False
