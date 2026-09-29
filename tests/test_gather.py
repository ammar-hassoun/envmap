#!/usr/bin/env python3
"""The collection policy three pages share — timing, joining, and not raising.

WHY THIS EXISTS
    `gather.Gatherer` is the whole reason the timeline, the expiry radar and
    the cluster page are usable on an estate whose clusters take fifteen
    seconds to answer, and it had NO test — the two callers' tests exercise
    their own merging over a warm cache, which is the one state where the
    policy does nothing.

    Every check here is about the cold and half-cold states, because that is
    where a caching policy is either right or invisible:

      * sources run TOGETHER, so a page costs its slowest source and not the
        sum (three 300ms jobs must not cost 900ms)
      * a reader gets a partial answer at the deadline and the NAMES of what
        has not arrived — a page that renders nothing until everything lands
        is the fifteen-second click this module exists to remove
      * a second reader JOINS the collection instead of starting another,
        because the alternative is doubling the load on somebody's cluster
        every time a page is opened twice
      * the deadline belongs to the COLLECTION: a joiner waits the remainder
        of it, never a fresh one. With the VPN down the fan-outs take 8-18s,
        so a collection outlives many clicks and a per-reader clock made every
        visit cost the full first_paint rather than only the first
      * a job that raises becomes an error STRING, never an exception — one
        broken integration must not empty a page that has six other sources
      * `ttl`/`hard`/`refresh` mean what the docstring says they mean, including
        the zero-ttl configuration the cluster page deliberately uses

    Timing assertions are the awkward part: this is the one module whose
    behaviour IS time, so they cannot be avoided. They are written as wide
    one-sided bounds against deliberately slow fixtures (a 0.4s deadline
    against a 4s job) so machine load cannot make a correct answer fail —
    test_certs' flake is what a tight bound buys.

    The "instant" bounds were 0.1s and one of them flaked anyway, under the
    load of the whole suite running at once. They are 0.4s now: what they
    distinguish is a cache hit (~10ms) from paying the 1.5s first-paint
    deadline, so four hundred milliseconds keeps the distinction decisive while
    leaving forty times the headroom the real answer needs. A bound that fails
    on a busy laptop is a bound that teaches people to re-run the suite until
    it passes, which is worse than not asserting.

    ./.venv/bin/python tests/test_gather.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import threading
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("gather-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import gather                                          # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# A job returns its value VERBATIM and signals failure by RAISING — the
# gatherer stores whatever came back and never inspects it (timeline's sources
# hand back a whole (rows, errors) tuple as one opaque part). Fixtures that
# returned (value, "") passed the tuple through as the value, which is how the
# first version of this file "failed" against correct code.
def slow(seconds: float, value):
    """A source that takes its time."""
    def fn():
        time.sleep(seconds)
        return value
    return fn


def quick(value):
    return lambda: value


def boom(message: str):
    def fn():
        raise RuntimeError(message)
    return fn


def timed(fn, *a, **k):
    t = time.perf_counter()
    out = fn(*a, **k)
    return out, time.perf_counter() - t


# ── together, not one after another ────────────────────────────
def test_sources_run_concurrently():
    g = gather.Gatherer("t", first_paint=9.0)
    jobs = [(f"s{i}", f"Source {i}", slow(0.3, i)) for i in range(3)]
    got, took = timed(g.gather, "k", jobs)
    check("all three sources arrive", set(got["parts"]) == {"s0", "s1", "s2"})
    # Sum would be 0.9s. Concurrent is ~0.3s. Bound at 0.7 leaves room for a
    # loaded machine while still failing a sequential implementation.
    check(f"concurrent, not sequential ({took:.2f}s)", took < 0.7)
    check("nothing pending once it all landed", got["pending"] == [])


# ── the deadline, and what a partial answer says ────────────────
def test_deadline_returns_partial_and_names_the_rest():
    g = gather.Gatherer("t", first_paint=0.4)
    jobs = [("fast", "Fast one", quick("here")),
            ("slow", "Slow fan-out", slow(4.0, "eventually"))]
    got, took = timed(g.gather, "k", jobs)
    check(f"returned at the deadline, not at the slow source ({took:.2f}s)",
          took < 2.0)
    check("the fast source is in the answer", got["parts"].get("fast") == "here")
    check("the slow one is absent, not None", "slow" not in got["parts"])
    check("and it is NAMED as pending", got["pending"] == ["Slow fan-out"])
    check("a partial answer is not called stale", got["stale"] == 0)


def test_the_collection_finishes_behind_the_reader():
    g = gather.Gatherer("t", first_paint=0.3, ttl=30.0)
    jobs = [("fast", "Fast", quick(1)), ("slow", "Slow", slow(1.0, 2))]
    g.gather("k", jobs)                       # returns partial at 0.3s
    time.sleep(1.4)                           # the collection completes
    got, took = timed(g.gather, "k", jobs)
    check("the next look has the whole answer",
          got["parts"] == {"fast": 1, "slow": 2})
    check(f"and it is instant ({took*1000:.0f}ms)", took < 0.4)
    check("nothing pending", got["pending"] == [])


# ── the fix under test: whose clock is the deadline? ────────────
def test_a_joiner_waits_the_remainder_not_a_fresh_deadline():
    """The point of the change. A joiner must not restart first_paint.

    Reader one starts a collection whose slow source takes 4s and pays the
    0.4s deadline. Reader two arrives at ~0.5s — already past it — and must be
    served the sink as it stands, not made to wait another 0.4s.
    """
    g = gather.Gatherer("t", first_paint=0.4)
    jobs = [("fast", "Fast", quick("here")),
            ("slow", "Slow fan-out", slow(4.0, "eventually"))]

    first: dict = {}

    def reader_one():
        first["got"], first["took"] = timed(g.gather, "k", jobs)

    t = threading.Thread(target=reader_one)
    t.start()
    time.sleep(0.55)                          # past the collection's deadline
    got, took = timed(g.gather, "k", jobs)
    t.join()

    check(f"the joiner does not wait again ({took*1000:.0f}ms)", took < 0.25)
    check("the joiner still gets what has landed",
          got["parts"].get("fast") == "here")
    check("and is still told what has not", got["pending"] == ["Slow fan-out"])
    check(f"the reader who STARTED it still pays the deadline "
          f"({first['took']:.2f}s)", 0.3 <= first["took"] < 2.0)
    check("one collection, not two", len(g._inflight) <= 1)


def test_a_joiner_still_waits_for_a_collection_that_is_about_to_finish():
    """The remainder is a REMAINDER, not zero. A joiner arriving inside the
    deadline on a fast estate must still be handed the complete answer rather
    than a partial one — that is the no-regression half of the same change."""
    g = gather.Gatherer("t", first_paint=1.0)
    jobs = [("a", "A", slow(0.5, 1)), ("b", "B", slow(0.5, 2))]

    def reader_one():
        g.gather("k", jobs)

    t = threading.Thread(target=reader_one)
    t.start()
    time.sleep(0.1)                           # well inside the deadline
    got, took = timed(g.gather, "k", jobs)
    t.join()
    check("a joiner inside the deadline gets the FULL answer",
          got["parts"] == {"a": 1, "b": 2})
    check(f"having waited for it ({took:.2f}s)", took >= 0.25)


def test_a_second_reader_does_not_start_a_second_collection():
    """The load half: two readers, one set of calls to somebody's cluster."""
    g = gather.Gatherer("t", first_paint=2.0)
    calls = []
    lock = threading.Lock()

    def counted():
        with lock:
            calls.append(1)
        time.sleep(0.6)
        return "v"

    jobs = [("s", "Source", counted)]
    out: list = []
    threads = [threading.Thread(target=lambda: out.append(g.gather("k", jobs)))
               for _ in range(4)]
    for th in threads:
        th.start()
        time.sleep(0.05)
    for th in threads:
        th.join()
    check(f"one collection for four readers ({len(calls)} calls)",
          len(calls) == 1)
    check("and all four got the answer",
          all(o["parts"].get("s") == "v" for o in out))


# ── a broken source is an error, never an exception ─────────────
def test_a_raising_source_does_not_empty_the_page():
    g = gather.Gatherer("t", first_paint=9.0)
    jobs = [("ok", "Working one", quick("value")),
            ("bust", "Broken integration", boom("connection refused"))]
    got = g.gather("k", jobs)
    check("the working source survives", got["parts"].get("ok") == "value")
    check("the broken one is not in parts", "bust" not in got["parts"])
    check("its label and message are reported",
          len(got["errors"]) == 1
          and "Broken integration" in got["errors"][0]
          and "connection refused" in got["errors"][0])
    check("a broken source is not reported as pending", got["pending"] == [])


def test_no_jobs_is_an_empty_answer_not_a_crash():
    g = gather.Gatherer("t")
    got = g.gather("k", [])
    check("empty in, empty out",
          got == {"parts": {}, "errors": [], "pending": [], "stale": 0})


# ── ttl, hard, refresh ─────────────────────────────────────────
def test_within_ttl_is_served_without_recollecting():
    g = gather.Gatherer("t", ttl=30.0, first_paint=9.0)
    calls = []
    jobs = [("s", "S", lambda: (calls.append(1), "v")[1])]
    g.gather("k", jobs)
    got, took = timed(g.gather, "k", jobs)
    check("one collection", len(calls) == 1)
    check(f"the second look is instant ({took*1000:.0f}ms)", took < 0.4)
    check("and complete", got["parts"] == {"s": "v"})
    check("fresh is not stale", got["stale"] == 0)


def test_past_ttl_serves_the_old_answer_and_refreshes_behind():
    g = gather.Gatherer("t", ttl=0.2, hard=900.0, first_paint=9.0)
    seq = iter(["first", "second", "third"])
    calls = []

    def fn():
        calls.append(1)
        return next(seq)

    jobs = [("s", "S", fn)]
    g.gather("k", jobs)
    time.sleep(0.3)                           # past ttl, inside hard
    got, took = timed(g.gather, "k", jobs)
    check("the STALE answer is served, immediately",
          got["parts"] == {"s": "first"} and took < 0.4)
    check("and it says how old it is", got["stale"] >= 0)
    time.sleep(0.4)                           # the background refresh lands
    check("a refresh ran behind the reader", len(calls) == 2)
    check("and the next look has it",
          g.gather("k", jobs)["parts"] == {"s": "second"})


def test_past_hard_is_too_old_to_show():
    g = gather.Gatherer("t", ttl=0.1, hard=0.2, first_paint=9.0)
    seq = iter(["first", "second"])
    jobs = [("s", "S", lambda: next(seq))]
    g.gather("k", jobs)
    time.sleep(0.3)                           # past hard
    got = g.gather("k", jobs)
    check("past hard the answer is recollected, not served",
          got["parts"] == {"s": "second"})


def test_refresh_waits_for_everything():
    """An explicit Refresh is somebody asking to wait. It must ignore both the
    cache and the deadline, or the button does not mean anything."""
    g = gather.Gatherer("t", ttl=900.0, first_paint=0.2)
    seq = iter(["first", "second"])
    jobs = [("s", "S", lambda: (time.sleep(0.6), next(seq))[1])]
    g.gather("k", jobs)
    got, took = timed(g.gather, "k", jobs, True)
    check("refresh ignores the cache", got["parts"] == {"s": "second"})
    check(f"and the deadline ({took:.2f}s)", took >= 0.5)
    check("so nothing is pending", got["pending"] == [])


def test_zero_ttl_is_deadline_only():
    """The cluster page's configuration: no cache of its own, just the
    deadline and the joining. Its cache dict must not be READ, and its key set
    must stay bounded (one entry per cluster) rather than growing per look."""
    g = gather.Gatherer("t", ttl=0.0, hard=0.0, first_paint=9.0)
    calls = []
    jobs = [("s", "S", lambda: (calls.append(1), "v")[1])]
    for _ in range(3):
        g.gather("same-cluster", jobs)
    check("every look recollects (no second cache over the part cache)",
          len(calls) == 3)
    check("and the key set stays bounded", list(g._cache) == ["same-cluster"])


def test_invalidate_drops_the_cache():
    g = gather.Gatherer("t", ttl=900.0, first_paint=9.0)
    seq = iter(["first", "second"])
    jobs = [("s", "S", lambda: next(seq))]
    g.gather("k", jobs)
    g.invalidate()
    check("after invalidate the next look recollects",
          g.gather("k", jobs)["parts"] == {"s": "second"})


# ── the two real callers are wired to it ───────────────────────
def test_the_pages_that_depend_on_this_use_it():
    """A page that stopped going through the Gatherer would lose the deadline
    silently — it would simply get slow. Read the callers rather than trust it."""
    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    for name in ("timeline", "expiry", "cluster"):
        src = (root / f"{name}.py").read_text()
        check(f"{name} builds a Gatherer", "Gatherer(" in src)
        check(f"{name} gathers through it", ".gather(" in src)


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
