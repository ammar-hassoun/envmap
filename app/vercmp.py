"""Version comparison, per package manager. The floor the whole scanner stands on.

A vulnerability finding is, in the end, one comparison: is the version installed
on this host older than the version the distro says fixes the CVE. Get that
wrong and the product produces BOTH false positives and false negatives, in
silence, and neither is visible on any page -- which is why this module is
written and tested before anything imports it.

THREE ALGORITHMS, NOT ONE. It is tempting to write a single "sensible" version
comparator and use it everywhere. It is wrong, and the disagreements are not
edge cases:

    rpm  says  1.0 == 1..0 == 1_0     (every run of non-alphanumerics is a
                                       separator, and repeats collapse)
    dpkg says  1.0 <  1..0            (the separator is an ordinary character
                                       and `.` sorts by its own rule)

    rpm  says  1.a < 1.1              (a numeric segment always beats an
                                       alphabetic one, whatever it contains)
    dpkg says  1.a < 1.1              (same answer, different reason -- digits
                                       order 0, letters order by ASCII)

    rpm  says  1.0^1 > 1.0            (`^` is "later than the release", for a
                                       post-release snapshot; rpm 4.15+)
    dpkg has   no `^` at all          (it is an ordinary character, so
                                       1.0^1 < 1.0a)

So the comparator is selected BY PACKAGE TYPE, never by distro family: an rpm
built on SUSE is still rpm, and a .deb on a derivative is still dpkg.

WHAT `~` MEANS, because it is the one both share and the one most often wrong:
a tilde sorts BEFORE everything, including the empty string. `1.0~rc1 < 1.0`.
It exists so a pre-release can be packaged without inventing a lower version.
rpm gained it in 4.10; dpkg has always had it. A comparator that treats `~` as
an ordinary separator calls `1.0~rc1` NEWER than `1.0` and then reports a
release candidate as patched.

No dependencies. Stdlib only, by design -- this is the one module that must be
verifiable by reading it.
"""
from __future__ import annotations

# ── rpm ────────────────────────────────────────────────────────
# Ported from rpmvercmp() in rpm's lib/rpmvercmp.c. The comments name the
# behaviour rather than the C, because the C is terse and the behaviour is
# what has to stay true.


def _rpm_segments(s: str) -> list:
    """(kind, text) runs, where kind is 'n' numeric, 'a' alphabetic, '~', '^'.

    Everything else is a SEPARATOR and is dropped entirely -- which is why rpm
    considers `1.0`, `1..0` and `1_0` the same version. Dropping rather than
    collapsing is deliberate: a trailing separator must not create an empty
    segment that then compares as older.
    """
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "~":
            out.append(("~", "~")); i += 1
        elif c == "^":
            out.append(("^", "^")); i += 1
        elif c.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            out.append(("n", s[i:j])); i = j
        elif c.isalpha():
            j = i
            while j < n and s[j].isalpha():
                j += 1
            out.append(("a", s[i:j])); i = j
        else:
            i += 1                      # separator: contributes nothing
    return out


def rpm_vercmp(a: str, b: str) -> int:
    """Compare two rpm version or release strings. -1, 0 or 1."""
    if a == b:
        return 0
    sa, sb = _rpm_segments(a or ""), _rpm_segments(b or "")
    for x, y in zip(sa, sb):
        kx, vx = x
        ky, vy = y
        if kx != ky:
            # A TILDE IS OLDER THAN ANYTHING, and a caret is newer than
            # anything -- checked before the numeric/alpha rule, because both
            # are about position relative to the whole rest of the string.
            if kx == "~":
                return -1
            if ky == "~":
                return 1
            # A CARET LOSES TO A REAL SEGMENT and beats only the end of the
            # string. `1.0^git1 > 1.0` because the other side ran out, but
            # `1.0^20160101 < 1.0.1` because `.1` is a segment and a caret
            # means "after 1.0, before whatever 1.0 is followed by". Getting
            # this backwards passes every hand-written example and fails
            # rpm's own vectors, which is what caught it.
            if kx == "^":
                return -1
            if ky == "^":
                return 1
            # Numeric beats alphabetic outright: rpm reads `1.10` as newer
            # than `1.9a` without looking at the letters.
            return 1 if kx == "n" else -1
        if kx == "n":
            # Leading zeros carry no value, so compare by length first and
            # only then lexically -- `10` beats `9`, and `007` equals `7`.
            lx, ly = vx.lstrip("0"), vy.lstrip("0")
            if len(lx) != len(ly):
                return 1 if len(lx) > len(ly) else -1
            if lx != ly:
                return 1 if lx > ly else -1
        elif kx == "a":
            if vx != vy:
                return 1 if vx > vy else -1
        # '~' vs '~' and '^' vs '^' are equal; fall through.
    if len(sa) == len(sb):
        return 0
    # ONE RAN OUT. The longer is newer -- unless what it continues with is a
    # tilde, which is the whole point of a tilde: `1.0~rc1` is older than the
    # `1.0` it precedes, even though it is longer.
    longer, sign = (sa, 1) if len(sa) > len(sb) else (sb, -1)
    nxt = longer[len(sb) if sign == 1 else len(sa)][0]
    if nxt == "~":
        return -sign
    return sign


def rpm_evr(epoch, version: str, release: str) -> tuple:
    """(epoch, version, release) normalised for comparison.

    AN ABSENT EPOCH IS ZERO, not missing. `rpm -qa` prints `(none)` for it,
    and treating that as a string sorts it against digits and gets the wrong
    answer on every package that has ever had an epoch bump -- which is
    exactly the set somebody bumped BECAUSE the version went backwards.
    """
    try:
        e = int(str(epoch).strip() or 0)
    except (TypeError, ValueError):
        e = 0                            # '(none)', '', None
    return e, version or "", release or ""


def rpm_compare(a: tuple, b: tuple) -> int:
    """Compare two (epoch, version, release) triples."""
    ea, va, ra = a
    eb, vb, rb = b
    if ea != eb:
        return 1 if ea > eb else -1
    got = rpm_vercmp(va, vb)
    if got:
        return got
    # A BLANK RELEASE COMPARES EQUAL, deliberately. A distro advisory often
    # names a fix as a version alone; treating "" as older would report every
    # such package vulnerable for ever.
    if not ra or not rb:
        return 0
    return rpm_vercmp(ra, rb)


# ── dpkg ───────────────────────────────────────────────────────
# Ported from dpkg's lib/dpkg/version.c.

def _dpkg_order(c: str) -> int:
    """dpkg's character ordering, which is not ASCII.

    A tilde is before everything (including end-of-string, which is 0); a
    letter keeps its own value; every other character is pushed ABOVE the
    letters by adding 256. So `1.0~rc1 < 1.0 < 1.0a < 1.0+b`.
    """
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_frag(a: str, b: str) -> int:
    """Compare one upstream-version or revision fragment."""
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit run, character by character under dpkg's ordering
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return 1 if ac > bc else -1
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
            first += 1
            if first > len(a) + len(b) + 2:
                break                    # cannot happen; guards a bad edit
        # digit run, numerically, leading zeros ignored
        si, sj = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        na = int(a[si:i] or 0)
        nb = int(b[sj:j] or 0)
        if na != nb:
            return 1 if na > nb else -1
    return 0


def dpkg_split(v: str) -> tuple:
    """'1:2.3-4' -> (1, '2.3', '4'). Epoch defaults to 0, revision to ''."""
    v = (v or "").strip()
    epoch = 0
    if ":" in v:
        head, _, rest = v.partition(":")
        try:
            epoch = int(head)
            v = rest
        except ValueError:
            pass                         # not an epoch; a colon in the version
    # THE LAST hyphen separates the revision, not the first: an upstream
    # version is allowed to contain hyphens and frequently does.
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """Compare two full Debian version strings."""
    ea, ua, ra = dpkg_split(a)
    eb, ub, rb = dpkg_split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    got = _dpkg_frag(ua, ub)
    if got:
        return got
    if not ra or not rb:
        return 0                         # same reason as rpm's blank release
    return _dpkg_frag(ra, rb)


# ── apk (Alpine) ───────────────────────────────────────────────
# Alpine versions are `1.2.3a_alpha1-r4`: dotted numbers, an optional single
# letter, zero or more suffixes, and a package revision.

# Ordered: anything below the unsuffixed release is a pre-release.
_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
               "": 0,
               "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_parse(v: str) -> tuple:
    """(numbers, letter, [(suffix_rank, n)], revision)."""
    v = (v or "").strip()
    rev = 0
    if "-r" in v:
        v, _, r = v.rpartition("-r")
        try:
            rev = int(r)
        except ValueError:
            rev = 0
    suffixes = []
    while "_" in v:
        v, _, suf = v.rpartition("_")
        name = "".join(c for c in suf if c.isalpha())
        num = "".join(c for c in suf if c.isdigit())
        suffixes.insert(0, (_APK_SUFFIX.get(name, 0), int(num or 0)))
    letter = ""
    if v and v[-1].isalpha():
        letter, v = v[-1], v[:-1]
    nums = []
    for part in v.split("."):
        digits = "".join(c for c in part if c.isdigit())
        nums.append(int(digits or 0))
    return nums, letter, suffixes, rev


def apk_compare(a: str, b: str) -> int:
    na, la, sa, ra = _apk_parse(a)
    nb, lb, sb, rb = _apk_parse(b)
    for x, y in zip(na, nb):
        if x != y:
            return 1 if x > y else -1
    if len(na) != len(nb):
        return 1 if len(na) > len(nb) else -1
    if la != lb:
        return 1 if la > lb else -1
    # A SUFFIX CAN LOWER A VERSION. `1.0_alpha1` is older than `1.0`, so an
    # absent suffix is compared as rank 0 rather than as "nothing to compare".
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (0, 0)
        y = sb[i] if i < len(sb) else (0, 0)
        if x != y:
            return 1 if x > y else -1
    if ra != rb:
        return 1 if ra > rb else -1
    return 0


# ── the one entry point ────────────────────────────────────────
TYPES = ("rpm", "deb", "apk")


def compare(pkg_type: str, a, b) -> int:
    """-1, 0 or 1, by PACKAGE TYPE -- never by distro family.

    `a` and `b` are full version strings, or for rpm an (epoch, version,
    release) triple. An unknown type raises rather than guessing: a silently
    wrong comparator is the one failure mode this module exists to prevent.
    """
    t = (pkg_type or "").lower()
    if t == "rpm":
        ta = a if isinstance(a, tuple) else rpm_evr(*_split_evr(a))
        tb = b if isinstance(b, tuple) else rpm_evr(*_split_evr(b))
        return rpm_compare(ta, tb)
    if t in ("deb", "dpkg"):
        return dpkg_compare(a, b)
    if t == "apk":
        return apk_compare(a, b)
    raise ValueError(f"no comparator for package type {pkg_type!r}")


def _split_evr(s: str) -> tuple:
    """'1:3.0.7-24.el9' -> ('1', '3.0.7', '24.el9')."""
    s = (s or "").strip()
    epoch = "0"
    if ":" in s:
        head, _, rest = s.partition(":")
        if head.strip().isdigit():
            epoch, s = head, rest
    if "-" in s:
        version, _, release = s.rpartition("-")
    else:
        version, release = s, ""
    return epoch, version, release


def older(pkg_type: str, installed, fixed) -> bool:
    """True when `installed` is strictly older than `fixed` -- i.e. vulnerable.

    The whole scanner reduces to this call, so it is named for what it decides
    rather than for what it computes.
    """
    return compare(pkg_type, installed, fixed) < 0
