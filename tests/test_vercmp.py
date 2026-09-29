#!/usr/bin/env python3
"""Version comparison, against the package managers' OWN test vectors.

Every finding this scanner will ever produce reduces to one question: is the
installed version older than the version the distro says fixes the CVE. A
comparator that is subtly wrong produces false positives AND false negatives,
in silence, on pages that look completely normal -- so it is written and
proven before anything imports it.

THE VECTORS ARE UPSTREAM, not invented here. rpm's tests/rpmvercmp.at and
dpkg's own test suite are the definition of correct; a hand-written table
would only test that the implementation agrees with whatever the author
believed while writing it, which is the failure this file exists to prevent.

    ./.venv/bin/python tests/test_vercmp.py
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("vercmp-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import vercmp                                         # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def run(label, fn, vectors):
    """Each vector is (a, b, expected) with expected in -1, 0, 1."""
    wrong = []
    for a, b, want in vectors:
        got = fn(a, b)
        if got != want:
            wrong.append(f"{a!r} vs {b!r}: got {got}, want {want}")
        # ANTISYMMETRY, checked on every vector for free. A comparator that
        # says a < b and also b < a sorts differently depending on argument
        # order, and nothing downstream would ever notice.
        back = fn(b, a)
        if back != -want:
            wrong.append(f"{b!r} vs {a!r}: got {back}, want {-want} (antisymmetry)")
    check(f"{label}: {len(vectors)} vectors", not wrong)
    for w in wrong[:14]:
        print(f"       {w}")
    if len(wrong) > 14:
        print(f"       ...and {len(wrong) - 14} more")


# ── rpm: lifted from rpm's tests/rpmvercmp.at ──────────────────
RPM = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0), ("2.0", "2.0.1", -1), ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0), ("5.5p1", "5.5p2", -1), ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0), ("xyz10", "xyz10.1", -1), ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("xyz.4", "2", -1), ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1), ("5.6p1", "5.5p2", 1),
    ("5.6p1", "6.5p1", -1), ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0), ("10.0001", "10.1", 0), ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1), ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1), ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0), ("20101121", "20101122", -1),
    ("20101122", "20101121", 1),
    ("2_0", "2_0", 0), ("2.0", "2_0", 0), ("2_0", "2.0", 0),
    # the released-versus-snapshot pair the whole tilde rule exists for
    ("a", "a", 0), ("a+", "a+", 0), ("a+", "a_", 0), ("a_", "a+", 0),
    ("+a", "+a", 0), ("+a", "_a", 0), ("_a", "+a", 0),
    ("+_", "+_", 0), ("_+", "+_", 0), ("_+", "_+", 0), ("+", "_", 0),
    ("_", "+", 0),
    # tilde: older than anything, including the empty string
    ("1.0~rc1", "1.0~rc1", 0), ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0),
    ("1.0~rc1~git123", "1.0~rc1", -1), ("1.0~rc1", "1.0~rc1~git123", 1),
    # A TILDE MEETING A REAL SEGMENT, which every vector above misses: in all
    # of those one side runs out and the end-of-string branch decides it, so
    # flipping the in-loop tilde rule left the suite green. Found by reverting
    # the rule and watching nothing fail.
    ("1.0~rc1", "1.0.1", -1), ("1.0.1", "1.0~rc1", 1),
    ("1.0~1", "1.0a", -1), ("1.0a", "1.0~1", 1),
    ("1.0~rc1", "1.0a", -1), ("1.0a", "1.0~rc1", 1),
    # caret: newer than the bare version, OLDER than the next one along
    ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0), ("1.0^git1", "1.0", 1), ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1), ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0),
    ("1.0^20160101", "1.0.1", -1), ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1),
    ("1.0^20160101^git1", "1.0^20160102", -1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0),
    ("1.0~rc1^git1", "1.0~rc1", 1), ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0),
    ("1.0^git1", "1.0^git1~pre", 1), ("1.0^git1~pre", "1.0^git1", -1),
]

# ── dpkg: from dpkg's own version test suite ───────────────────
DPKG = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("1.0-1", "1.0-1", 0), ("1.0-1", "1.0-2", -1), ("1.0-2", "1.0-1", 1),
    ("1:1.0", "1.0", 1), ("1.0", "1:1.0", -1),
    ("1:1.0", "2:0.9", -1), ("2:0.9", "1:1.0", 1),
    # the separator is an ORDINARY character here, unlike rpm
    ("1.0", "1..0", -1), ("1..0", "1.0", 1),
    # tilde before everything, including end of string
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~~", "1.0~", -1), ("1.0~", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    # letters sort BELOW other punctuation, which ASCII would get backwards
    ("1.0a", "1.0+", -1), ("1.0+", "1.0a", 1),
    ("1.0a", "1.0", 1), ("1.0", "1.0a", -1),
    # leading zeros carry no value
    ("1.007", "1.7", 0), ("1.07", "1.8", -1),
    # the LAST hyphen splits the revision; upstream may contain hyphens
    ("1.0-a-1", "1.0-a-2", -1), ("1.0-a-2", "1.0-a-1", 1),
    # real Debian security versions
    ("2.4.57-2", "2.4.57-2+deb12u1", -1),
    ("2.4.57-2+deb12u1", "2.4.57-2+deb12u2", -1),
    ("1:9.16.44-1", "1:9.16.48-1", -1),
    ("0.9.8-1ubuntu1", "0.9.8-1ubuntu2", -1),
]

# ── apk (Alpine) ───────────────────────────────────────────────
APK = [
    ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.1", "1.0", 1),
    ("1.0-r0", "1.0-r1", -1), ("1.0-r1", "1.0-r0", 1),
    ("1.0-r0", "1.0-r0", 0),
    ("1.0a", "1.0", 1), ("1.0", "1.0a", -1),
    ("1.0_alpha1", "1.0", -1), ("1.0", "1.0_alpha1", 1),
    ("1.0_alpha1", "1.0_alpha2", -1),
    ("1.0_alpha1", "1.0_beta1", -1),
    ("1.0_rc1", "1.0", -1),
    ("1.0_p1", "1.0", 1), ("1.0", "1.0_p1", -1),
    ("1.2.3", "1.2.3.1", -1), ("1.2.3.1", "1.2.3", 1),
    ("3.1.4-r2", "3.1.10-r0", -1),
]


def main() -> int:
    print("the package managers' own vectors")
    run("rpm (rpmvercmp.at)", vercmp.rpm_vercmp, RPM)
    run("dpkg", vercmp.dpkg_compare, DPKG)
    run("apk", vercmp.apk_compare, APK)

    print("epoch is a number, and an absent one is ZERO not missing")
    # `rpm -qa` prints `(none)`; comparing that as a string sorts it against
    # digits and gets every epoch bump backwards -- and an epoch was bumped
    # precisely BECAUSE the version went backwards.
    check("'(none)' reads as epoch 0",
          vercmp.rpm_evr("(none)", "1.0", "1") == (0, "1.0", "1"))
    check("'' reads as epoch 0", vercmp.rpm_evr("", "1.0", "1")[0] == 0)
    check("None reads as epoch 0", vercmp.rpm_evr(None, "1.0", "1")[0] == 0)
    check("an epoch outranks the version entirely",
          vercmp.rpm_compare((1, "1.0", "1"), (0, "99.0", "1")) == 1)
    check("...and a string epoch is parsed, not compared as text",
          vercmp.rpm_compare(vercmp.rpm_evr("10", "1.0", "1"),
                             vercmp.rpm_evr("9", "1.0", "1")) == 1)

    print("a blank release compares equal, deliberately")
    # A distro advisory often names a fix by version alone. Treating "" as
    # older would report every such package vulnerable for ever.
    check("rpm: blank release is not older",
          vercmp.rpm_compare((0, "1.0", ""), (0, "1.0", "5")) == 0)
    check("dpkg: blank revision is not older",
          vercmp.dpkg_compare("1.0", "1.0-5") == 0)

    print("the one call the scanner actually makes")
    check("older() is True when installed < fixed",
          vercmp.older("rpm", "1:3.0.7-24.el9", "1:3.0.7-25.el9"))
    check("...False when installed == fixed",
          not vercmp.older("rpm", "1:3.0.7-25.el9", "1:3.0.7-25.el9"))
    check("...False when installed > fixed",
          not vercmp.older("rpm", "1:3.0.8-1.el9", "1:3.0.7-25.el9"))
    check("...and it parses a full EVR string",
          vercmp.older("deb", "2.4.57-2", "2.4.57-2+deb12u1"))

    print("an unknown package type RAISES, it does not guess")
    # A silently wrong comparator is the single failure this module exists to
    # prevent, so there is no default branch.
    try:
        vercmp.compare("msi", "1.0", "2.0")
        check("unknown type raises", False)
    except ValueError:
        check("unknown type raises", True)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
