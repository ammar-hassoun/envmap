#!/usr/bin/env python3
"""The portal gives back the memory its warmer frees — app/memtrim.py.

WHY THIS EXISTS
    The pod was OOMKilled thirty times in thirty-six days at a 4GiB limit, and
    nothing Python held was growing: at 15MB of live objects the process held
    1.3GB. glibc kept freed kubectl answers in per-thread arenas, one arena per
    short-lived warmer thread, for ever. Two measures fix it, and this checks
    that BOTH are in force in the process uvicorn actually runs:

      * importing `app.main` caps the arena count — counted by glibc itself
        (`malloc_info`), not inferred from addresses
      * every warmer pass ends with the freed pages back with the kernel —
        proved by trimming once more straight after a pass and measuring what
        that second trim still finds in RssAnon. The passes are shaped like
        production: fresh `_pmap` threads, overlapped by a second fan-out,
        each decoding a JSON answer of a different size

    The work runs in a CHILD process, because the arena cap is decided at
    import time and this test must not depend on what imported first.

    It needs glibc, so on macOS it checks only that the calls are harmless
    no-ops and says so. CI (`.github/workflows/check.yml`, ubuntu) runs it for
    real; so does `python:3.13-slim` in Docker.

    ./.venv/bin/python tests/test_memtrim.py
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import _sandbox                                                # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import memtrim                                         # noqa: E402

bad = 0


def check(what: str, cond: bool, detail: str = "") -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}" + (f" — {detail}" if detail else ""))


# The child: the real app import, the real warmer pass, production-shaped work.
CHILD = r'''
import ctypes, json, os, random, sys, tempfile
sys.path.insert(0, sys.argv[1])
import app.main                                   # the module uvicorn runs
from app import fleet, warmer

random.seed(7)
def blob(n):                                       # a `kubectl get pods -A -o json`
    pod = {"metadata": {"name": "p", "namespace": "ns", "labels": {"a": "x" * 40}},
           "spec": {"containers": [{"name": "c", "env": [{"name": "E", "value": "v" * 60}] * 20}]},
           "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}}
    return json.dumps({"items": [pod] * n}, indent=4).encode()
# answers of different sizes, as a real estate's are from one pass to the next
BLOBS = [blob(n) for n in (2500, 4000, 5500, 7000, 8500)]

def read_cluster(i):                              # one thread per read, as _pmap does
    doc = json.loads(BLOBS[random.randrange(len(BLOBS))].decode())
    return len(doc["items"])

def churn():
    # The pass's own fan-out, overlapped by a reader's stale-serve refresh —
    # in production those two run at once, and overlap is what multiplies
    # arenas: glibc hands a thread a new one when the others are busy.
    import threading
    behind = threading.Thread(
        target=lambda: fleet._pmap(read_cluster, list(range(12)), workers=12))
    behind.start()
    fleet._pmap(read_cluster, list(range(36)), workers=24)
    behind.join()

for name in ("_warm_summary", "_warm_clusters", "_warm_user_pages",
             "_trim_recordings"):
    setattr(warmer, name, lambda: None)
warmer._warm_fleet = churn

def rss():
    for line in open("/proc/self/status"):
        if line.startswith("RssAnon:"):
            return int(line.split()[1]) // 1024

def arenas():
    libc = ctypes.CDLL("libc.so.6")
    libc.fopen.restype = ctypes.c_void_p
    path = tempfile.mktemp()
    fp = libc.fopen(path.encode(), b"w")
    libc.malloc_info(0, ctypes.c_void_p(fp))
    libc.fclose(ctypes.c_void_p(fp))
    xml = open(path).read()
    os.unlink(path)
    return xml.count("<heap nr=")

# After each pass, trim once MORE ourselves: if the pass already handed its
# freed pages back, this finds almost nothing; if it did not, it finds them.
libc = ctypes.CDLL("libc.so.6")
seen, left = [], []
for _ in range(int(sys.argv[2])):
    warmer.pass_once("slow")
    before = rss()
    libc.malloc_trim(0)
    seen.append(before)
    left.append(before - rss())
print(json.dumps({"rss": seen, "left": left, "arenas": arenas(),
                  "blob_mb": max(map(len, BLOBS)) >> 20}))
'''

PASSES = 30
# Measured on glibc 2.41 (python:3.13-slim-trixie), 10 November 2026. With the
# fix: 2 arenas, and a trim after a pass found 0MB in every one of 30. With the
# trim deleted: 19-49MB per pass. With the cap deleted: 10-11 arenas. RssAnon is
# printed but not asserted: this workload is small enough to run in seconds,
# so its peak (267MB fixed, 453-505MB reverted) is too close to call with a
# bound that would never flake — the two checks below are exact instead.
TRIM_LEFT_MB = 10


def main() -> int:
    glibc = memtrim._glibc() is not None
    if not glibc:
        # Off glibc both calls must be quiet no-ops, never an exception at import.
        check("limit_arenas is a no-op off glibc", memtrim.limit_arenas() is False)
        check("trim is a no-op off glibc", memtrim.trim() is False)
        print("OK (glibc not present: the memory checks run on Linux — CI does)"
              if not bad else f"{bad} FAILED")
        return bad

    env = {**os.environ,
           "PORTAL_DATA_DIR": _sandbox.data_dir("memtrim-test-"),
           "PORTAL_SCHEDULER": "0"}
    # An operator's own MALLOC_ARENA_MAX would make the cap's check meaningless.
    env.pop("MALLOC_ARENA_MAX", None)
    r = subprocess.run([sys.executable, "-c", CHILD, str(ROOT), str(PASSES)],
                       capture_output=True, text=True, env=env, timeout=600)
    if r.returncode != 0:
        check("the child ran", False, r.stderr.strip()[-600:])
        print(f"{bad} FAILED")
        return bad
    got = json.loads(r.stdout.strip().splitlines()[-1])
    rss, n, left = got["rss"], got["arenas"], got["left"]
    print(f"  {PASSES} passes: RssAnon {rss[0]}MB -> {max(rss)}MB peak, "
          f"{rss[-1]}MB last, {n} arenas; a further trim after a pass "
          f"found {max(left)}MB at most")

    check("importing app.main caps the malloc arenas",
          n <= memtrim.ARENAS, f"glibc reports {n} arenas")
    # The trim must END every pass. A second trim straight after one finds what
    # the pass left behind: nothing with the fix, tens of MB without it.
    check("every warmer pass ends with freed memory given back",
          max(left) < TRIM_LEFT_MB,
          f"a trim after a pass still freed {max(left)}MB "
          f"(per pass: {left})")

    # An operator's own setting wins over ours.
    os.environ["MALLOC_ARENA_MAX"] = "4"
    check("MALLOC_ARENA_MAX in the environment is left to stand",
          memtrim.limit_arenas() is False)
    del os.environ["MALLOC_ARENA_MAX"]

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
