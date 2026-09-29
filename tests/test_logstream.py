#!/usr/bin/env python3
"""What the log stream does when kubectl succeeds, ends, and refuses.

WHY THIS EXISTS
    A browser's EventSource reconnects on its own. That is the right default for
    a dropped link and the wrong one for a refusal, and the difference is not
    visible from watching a healthy pod:

      * a finished Job whose container has been reaped answers "unable to
        retrieve container logs for containerd://…" and exits non-zero. With
        stderr folded into stdout that arrived as though the POD had logged it,
        the stream ended, the browser reconnected, and the same line appeared
        again every few seconds — one kubectl run per retry, for as long as the
        window stayed open, against somebody's API server
      * poll() answers None for a process that is merely finishing, which read
        as a clean end and sent the browser back round the same loop

    So the generator says which of the three happened, and the batching that
    makes a busy pod survivable is checked here too — it is a property of the
    frames, invisible from the page.

    None of this needs a cluster: kubectl is replaced with a fake whose exit
    code and output are the whole point.

    ./.venv/bin/python tests/test_logstream.py
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("logstream-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import logs                                           # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


class Fake:
    """kubectl, as far as this module can tell."""

    def __init__(self, out=(), err=(), rc=0, delay=0.0):
        self._out, self._err, self.returncode, self._delay = out, err, rc, delay
        self.stdout = self._drip(out)
        self.stderr = iter(list(err))

    def _drip(self, lines):
        for line in lines:
            if self._delay:
                time.sleep(self._delay)
            yield line

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        pass

    def kill(self):
        pass


def frames_of(**kw) -> list:
    real = subprocess.Popen
    subprocess.Popen = lambda *a, **k: Fake(**kw)                # noqa: E731
    try:
        return [f for f in logs.stream({"x": 1}, "ns", "pod")
                if not f.startswith(":")]
    finally:
        subprocess.Popen = real


def kinds(frames) -> list:
    return [f.split("\n", 1)[0].removeprefix("event: ") for f in frames]


def main() -> int:
    logs.base_args = lambda c: ["kubectl"]

    print("a pod whose logs cannot be fetched refuses once, and says so")
    reaped = ("unable to retrieve container logs for "
              "containerd://d3f0af1b51c9c32c3889ca8125dcd08cc5b7a9bc0c36a80")
    got = frames_of(out=(), err=[reaped + "\n"], rc=1)
    check(f"one frame, not a stream of them ({kinds(got)})", len(got) == 1)
    check("and it is fatal, which is what stops the browser retrying",
          kinds(got) == ["fatal"])
    # The whole bug: this text arriving as content instead of as a refusal.
    check("kubectl's complaint is never dressed up as a log line",
          not any(k == "log" for k in kinds(got)))
    check("and the reason is carried, not swallowed", reaped in got[0])

    print("a stream that simply ends says that instead")
    got = frames_of(out=["2026-08-09T03:00:00Z hello\n"], rc=0)
    check(f"log then end ({kinds(got)})", kinds(got) == ["log", "end"])
    # `end` and `fatal` are different on purpose: one is a pod that stopped
    # writing, the other is a pod that can never be read. Only one is worth
    # offering to retry with --previous.
    check("an ending is not reported as a failure", "fatal" not in kinds(got))

    print("a burst is batched rather than sent line by line")
    got = frames_of(out=[f"line {i}\n" for i in range(2000)], rc=0)
    logframes = [f for f in got if f.startswith("event: log")]
    delivered = sum(f.count('", "') + 1 for f in logframes)
    check(f"2000 lines in far fewer frames ({len(logframes)})",
          len(logframes) < 40)
    check(f"and all of them arrive ({delivered})", delivered >= 2000)

    print("nothing kubectl writes to stderr reaches the log view")
    got = frames_of(out=["real line\n"],
                    err=["W0809 deprecated flag\n"], rc=0)
    body = "".join(f for f in got if f.startswith("event: log"))
    check("a warning on stderr is not shown as pod output",
          "deprecated flag" not in body)
    check("while the pod's own line still is", "real line" in body)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
