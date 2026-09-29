"""Reading from several slow places at once without making anybody wait.

WHY THIS IS SHARED
    The timeline and the expiry radar collect the same shape of thing: a
    handful of sources, most local and instant, one or two of them a fan-out
    across every cluster that can take fifteen seconds and may never answer.
    Both need the same three behaviours, and the second copy had already
    drifted from the first — different lifetimes, and a `_running` set one of
    them kept but never read. Two copies of a caching policy is two policies.

THE THREE BEHAVIOURS, IN THE ORDER THEY MATTER
    **Together, not one after another.** Sources run concurrently, so a page
    costs its slowest source rather than the sum of all of them.

    **A deadline, not a spinner.** Even run together, the slowest source sets
    the floor — measured on a real estate that floor was fifteen seconds, and a
    click that costs fifteen seconds is a broken page however well it
    parallelises. So the caller gets whatever has arrived by `first_paint` and
    the names of what has not; the collection carries on and the next look has
    it.

    **Serve what is already known.** Inside `ttl` the answer is reused, and
    between `ttl` and `hard` it is served immediately while a fresh one is
    collected behind the reader. Past `hard` it is too old to show.

    A second reader arriving mid-collection joins the one already running.
    Without that, opening a page twice doubles the load on every cluster it
    reads — and these are exactly the pages people open twice.

    **And the deadline belongs to the COLLECTION, not to each reader.** A
    joiner waits only the remainder of it, so a second look during a slow
    collection is nearly free instead of costing another full `first_paint`.
    Measured with the VPN down, where the fan-outs take 8-18s: the timeline's
    sources are 1095/8153/18024/8994/13027ms cold, so a collection outlives
    many clicks, and restarting the clock per reader made EVERY visit cost
    1.5s rather than only the one that started it. The joiner also cannot lose
    by not waiting — the sink only accumulates, so what has landed by their
    arrival is already at least what the previous reader was shown.

WHAT IT DOES NOT DO
    It does not merge. Each caller knows what its sources return and how to
    combine them; this hands back a dict keyed by source and stays out of it.
"""
from __future__ import annotations

import threading
import time

from . import fleet


class Gatherer:
    """One cache and one collection policy, for one page."""

    def __init__(self, name: str, ttl: float = 45.0, hard: float = 900.0,
                 first_paint: float = 1.5, workers: int = 9):
        self.name = name
        self.ttl = ttl
        self.hard = hard
        self.first_paint = first_paint
        self.workers = workers
        self._cache: dict = {}
        self._inflight: dict = {}
        self._guard = threading.Lock()

    def invalidate(self) -> None:
        self._cache.clear()

    # ── the one call a page makes ──────────────────────────────
    def gather(self, key, jobs, refresh: bool = False) -> dict:
        """`jobs` is [(source key, label, callable)]. Never raises.

        -> {"parts": {source: value}, "errors": [str], "pending": [label],
            "stale": seconds or 0}
        """
        if not jobs:
            return {"parts": {}, "errors": [], "pending": [], "stale": 0}
        if refresh:
            parts, errors = self._run(jobs, None)
            self._cache[key] = {"at": time.monotonic(), "parts": parts,
                                "errors": errors}
            return {"parts": parts, "errors": errors, "pending": [], "stale": 0}

        hit = self._cache.get(key)
        if hit:
            age = time.monotonic() - hit["at"]
            if age < self.ttl:
                return {**_served(hit), "stale": 0}
            if age < self.hard:
                self._behind(key, jobs)
                return {**_served(hit), "stale": round(age)}
        return self._partial(key, jobs)

    # ── the three paths ────────────────────────────────────────
    def _run(self, jobs, sink) -> tuple[dict, list]:
        """Every job at once. A job that raises becomes an error string, never
        an exception: one broken integration must not empty the page."""
        def one(job):
            source, label, fn = job
            try:
                out, err = fn(), ""
            except Exception as e:                             # noqa: BLE001
                out, err = None, f"{label}: {e}"
            if sink is not None:
                sink[source] = (out, err)
            return source, out, err

        parts, errors = {}, []
        for got in fleet._pmap(one, list(jobs),
                               workers=min(len(jobs), self.workers)):
            if not got:
                continue
            source, out, err = got
            if err:
                errors.append(err)
            else:
                parts[source] = out
        return parts, errors

    def _partial(self, key, jobs) -> dict:
        """Start — or join — the collection, and give it `first_paint`."""
        labels = {source: label for source, label, _fn in jobs}
        with self._guard:
            job = self._inflight.get(key)
            if job is None:
                job = {"sink": {}, "done": threading.Event(), "data": None,
                       "started": time.monotonic()}
                self._inflight[key] = job

                def run():
                    try:
                        parts, errors = self._run(jobs, job["sink"])
                        job["data"] = {"parts": parts, "errors": errors}
                        self._cache[key] = {"at": time.monotonic(),
                                            "parts": parts, "errors": errors}
                    except Exception:                          # noqa: BLE001
                        pass
                    finally:
                        job["done"].set()
                        with self._guard:
                            self._inflight.pop(key, None)

                threading.Thread(target=run, name=f"{self.name}-collect",
                                 daemon=True).start()

        # The remainder of the COLLECTION's deadline, not a fresh one. Whoever
        # started it waits the full first_paint (elapsed is ~0); a joiner waits
        # what is left of it and takes the sink as it stands.
        job["done"].wait(max(0.0, self.first_paint
                             - (time.monotonic() - job["started"])))
        if job["data"] is not None:
            return {**job["data"], "pending": [], "stale": 0}

        parts, errors = {}, []
        for source, (out, err) in list(job["sink"].items()):
            if err:
                errors.append(err)
            else:
                parts[source] = out
        return {"parts": parts, "errors": errors,
                "pending": [labels[s] for s, _l, _f in jobs
                            if s not in job["sink"]],
                "stale": 0}

    def _behind(self, key, jobs) -> None:
        """Collect a fresh answer behind whoever is reading the stale one."""
        with self._guard:
            if key in self._inflight:
                return
            self._inflight[key] = {"sink": {}, "done": threading.Event(),
                                   "data": None}

        def run():
            try:
                parts, errors = self._run(jobs, None)
                self._cache[key] = {"at": time.monotonic(), "parts": parts,
                                    "errors": errors}
            except Exception:                                  # noqa: BLE001
                pass
            finally:
                with self._guard:
                    self._inflight.pop(key, None)

        threading.Thread(target=run, name=f"{self.name}-refresh",
                         daemon=True).start()


def _served(hit: dict) -> dict:
    return {"parts": hit["parts"], "errors": list(hit["errors"]),
            "pending": []}


# ── reading the same thing from every connection ───────────────
# WHY THIS IS HERE AND NOT WRITTEN OUT PER PAGE
#     Three pages had the identical block: build a reader per connection,
#     `_pmap` them, keep the ones that came back. Which meant three pages had
#     the identical BUG — the map joins every thread, so the page cost the
#     slowest connection there is. Measured on real data, /gitops took 19.6
#     seconds and /bmc 16.1, both against a warm figure of under 10ms; the cost
#     was entirely the first read of an unreachable box, waited out in full.
#
#     The deadline belongs with the other deadlines rather than being invented
#     three times, so it lives here. What each connection MEANS is still the
#     page's business: `read` is called untouched and whatever it returns is
#     what the page gets.
_ACROSS = Gatherer("across", ttl=0.0, hard=0.0, first_paint=0.4, workers=6)


def across(what: str, conns: list, read, refresh: bool = False) -> tuple:
    """Read `read(conn)` from every connection, without waiting for all of them.

    `conns` is the connection records, each with "id" and "name". Ordering is
    preserved so a page's rows do not reshuffle between loads.

    -> (values that arrived, names of the connections still being read)

    A `read` that raises is reported as a pending connection rather than
    emptying the page — but a page that wants to SHOW the failure (most do,
    "this one could not be reached" being the point of the page) should catch
    inside `read` and return a row saying so, exactly as before.

    `refresh` is somebody pressing Refresh, which is a request to wait: the
    deadline is skipped and every connection is read to completion.
    """
    conns = list(conns or [])
    if not conns:
        return [], []
    if refresh:
        return [v for v in fleet._pmap(read, conns,
                                       workers=min(6, len(conns)))
                if v is not None], []
    got = _ACROSS.gather(what, [
        (c.get("id") or str(i), c.get("name") or c.get("id") or "?",
         (lambda c=c: read(c)))
        for i, c in enumerate(conns)])
    order = {(c.get("id") or str(i)): i for i, c in enumerate(conns)}
    rows = sorted(((k, v) for k, v in got["parts"].items() if v is not None),
                  key=lambda kv: order.get(kv[0], 0))
    return [v for _k, v in rows], list(got["pending"])
