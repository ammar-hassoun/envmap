"""Giving freed memory back to the system, which glibc does not do by itself.

WHY THIS EXISTS
    The portal was OOMKilled thirty times in thirty-six days on a 4GiB limit,
    with no errors and a quiet log. It was not a leak in anything Python holds.
    Measured on 10 November 2026: the pod, 14 minutes after a restart, had 67
    glibc malloc ARENAS holding 388MB of its 476MB of anonymous memory, and
    it climbed about 80MB per warmer pass. Reproduced on the same glibc
    against twelve fake clusters, `tracemalloc` counted 15MB of live Python
    objects while the process held 1.3GB.

    The shape that causes it is this product's: every warmer pass starts fresh
    threads (`fleet._pmap`, `cluster._refresh_behind`, the gatherers), and each
    one decodes a `kubectl -o json` answer that runs to tens of megabytes on a
    real cluster. glibc gives a new thread an arena of its own (up to eight per
    CPU, and a pod sees the NODE's CPUs), the decode is freed when the thread
    ends, and the arena keeps the pages. They are reused only by whichever
    thread lands on that arena next, and only for allocations that happen to
    fit the holes, so the total climbs until the kernel kills the pod. That
    drops every live SSH, RDP and web session in Privileged Access.

TWO MEASURES, BECAUSE EACH COVERS THE OTHER'S GAP
    **Fewer arenas** (`M_ARENA_MAX`). Bounds how many separate heaps the
    fragmentation is multiplied across. Set before the app's threads start;
    an arena that already exists is not taken away.

    **A trim after each warmer pass** (`malloc_trim(0)`). Since glibc 2.8 this
    walks every arena and returns whole free pages inside it to the kernel,
    not just the top of the main heap. It costs milliseconds and the warmer
    runs it every 200 seconds, after the work that made the garbage.

WHAT IT DOES NOT DO
    It does not touch musl, macOS or anything that is not glibc: the calls
    are looked up, and a missing symbol means there is nothing to do.
    `MALLOC_ARENA_MAX` in the environment still wins, so an install that has
    tuned it keeps its own number.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os

# glibc's mallopt parameter number for the arena cap (malloc.h: M_ARENA_MAX -8).
M_ARENA_MAX = -8

# Two, not one: one arena makes every thread contend on a single lock, and the
# warmer's fan-out is exactly the many-threads case. Two is the common setting
# for this problem and measured flat here (see tests/test_memtrim.py).
ARENAS = 2

_libc = None


def _glibc():
    """The C library if it is glibc, else None. Looked up once."""
    global _libc
    if _libc is None:
        try:
            lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
            _libc = lib if hasattr(lib, "malloc_trim") and hasattr(
                lib, "mallopt") else False
        except OSError:
            _libc = False
    return _libc or None


def limit_arenas(n: int = ARENAS) -> bool:
    """Cap the number of malloc arenas. True when the cap was set here."""
    if os.environ.get("MALLOC_ARENA_MAX"):
        return False                    # the operator's own setting stands
    lib = _glibc()
    if not lib:
        return False
    return bool(lib.mallopt(M_ARENA_MAX, int(n)))


def trim() -> bool:
    """Return free pages in every arena to the kernel. True if any were."""
    lib = _glibc()
    if not lib:
        return False
    return bool(lib.malloc_trim(0))
