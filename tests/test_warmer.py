#!/usr/bin/env python3
"""What the warmer warms, and — more importantly — what it leaves alone.

WHY THIS EXISTS
    A background loop that reads other people's clusters is load somebody else
    pays for, on a timer, whether or not anyone is looking. The policy is
    therefore the whole design, and none of it is visible from watching the
    portal work:

      * the fleet snapshot is warmed ALWAYS, because it is the page every
        person lands on after signing in — the pause after typing the MFA code
        was that snapshot being built while the browser waited
      * a cluster is warmed only if somebody has opened it, so an estate of
        twenty clusters is not twenty permanent readers for pages nobody views
      * what stops being looked at stops being warmed — and a connection page,
        which is a live poll of somebody else's Prometheus rather than a cheap
        cached read, is forgotten sooner than a cluster is
      * each cadence has to beat the cache it exists to fill. Warming slower
        than the entry expires is the whole cost with none of the benefit: the
        page is cold on most visits anyway
      * two passes must never run at once, or a slow estate stacks collections
        behind itself until nothing finishes

    And one thing that is not policy but fails just as quietly: PAGES names a
    collector per page, so renaming one leaves that page never warm again with
    nothing broken, nothing logged and nothing to notice. Every entry is
    resolved here rather than trusted.

    None of this needs a cluster: the collectors are replaced with counters, so
    what is under test is the policy rather than kubectl.

    ./.venv/bin/python tests/test_warmer.py
"""
from __future__ import annotations

import importlib
import os
import pathlib
import re
import sys
import threading
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("warmer-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import (cluster as clusterview, fleet, rbac, store,    # noqa: E402
                 summary, warmer)

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    calls: dict = {"fleet": 0, "parts": []}
    real_fleet, real_part = fleet.overview, clusterview.part
    # summary's roll-ups spawn threads at real CI and scanner connections; the
    # policy under test here is which targets are warmed, not what they return
    summary.pipelines = summary.security_roll = lambda: None
    fleet.overview = lambda force=False: calls.__setitem__("fleet", calls["fleet"] + 1)
    clusterview.part = lambda c, name, refresh=False: calls["parts"].append(
        (c.get("id"), name))
    # a project with two clusters, of which only one will ever be looked at
    pid = store.add_project("Warm", "🔥")
    seen = store.add_cluster(pid, "seen", "apiVersion: v1\n", "seen")
    store.add_cluster(pid, "unseen", "apiVersion: v1\n", "unseen")
    # reachable() would try to talk to /dev/null; the question here is which
    # clusters are ASKED about, not whether they answer
    real_reach = warmer_reachable_patch()

    print("the fleet snapshot is warmed whether or not anything was viewed")
    warmer._seen.clear()
    warmer.pass_once()
    check(f"the snapshot was built ({calls['fleet']})", calls["fleet"] == 1)
    check("and no cluster was read, because none was opened",
          calls["parts"] == [])

    print("only a cluster somebody opened")
    warmer.note_view("cluster", seen)
    warmer.pass_once()
    warmed = {cid for cid, _n in calls["parts"]}
    check(f"the one that was opened is warmed ({warmed})", warmed == {seen})
    check("and the parts warmed are the ones a page reads",
          {n for _c, n in calls["parts"]} >= {"nodes", "pods", "namespaces"})
    # The cost of getting this wrong is a permanent reader on somebody's API
    # server for a page nobody has ever opened.
    check("the one nobody opened is left alone", len(warmed) == 1)

    print("what stops being looked at stops being warmed")
    calls["parts"].clear()
    warmer._seen[("cluster", seen)] = time.time() - warmer.REMEMBER - 1
    warmer.pass_once()
    check("a cluster last seen beyond REMEMBER is dropped",
          calls["parts"] == [])
    check("and forgotten rather than kept for ever",
          ("cluster", seen) not in warmer._seen)

    print("every page's collector still exists")
    # The failure this catches is silent in a way no page shows: rename
    # `virt.read` and nothing breaks, nothing logs, and the Hypervisors page is
    # simply never warm again. So the table is resolved rather than trusted.
    for area, (kind, mod, fn) in warmer.PAGES.items():
        try:
            module = importlib.import_module(f"app.{mod}")
        except ImportError:
            check(f"{area}: app/{mod}.py exists", False)
            continue
        check(f"{area}: {mod}.{fn} exists", callable(getattr(module, fn, None)))
        check(f"{area}: '{kind}' is a connection kind store knows",
              kind in _store_kinds())
        check(f"{area} is a real area", area in rbac.AREAS)
    # logstore and cloud warm themselves from app startup already. Listing
    # either here as well would poll one customer's server twice for one page,
    # and nothing about the page would look wrong while it happened.
    for own in ("logs", "clouds"):
        check(f"{own} is left to its own warmer", own not in warmer.PAGES)

    print("a connection page is warmed only once somebody opens it")
    warmer._seen.clear()
    warmed: list = []
    from app import monitoring
    real_mon = monitoring.overview
    monitoring.overview = lambda c, refresh=False: warmed.append(c.get("id"))
    store.add_mon(pid, {"name": "prom", "base_url": "https://example.invalid"})
    warmer.pass_once("pages")
    check("nobody opened Monitoring, so nothing was polled", warmed == [])
    warmer.note_view("page", "monitoring")
    warmer.pass_once("pages")
    check(f"opening it warms its connections ({warmed})", len(warmed) == 1)
    # Half an hour, not the four hours a cheap cached target gets: this one is
    # a live poll of somebody else's Prometheus every 35s.
    warmer._seen[("page", "monitoring")] = (
        time.time() - warmer.REMEMBER_PAGE - 1)
    warmed.clear()
    warmer.pass_once("pages")
    check("and it stops when nobody has been back for REMEMBER_PAGE",
          warmed == [])
    check("a page forgets sooner than a cluster does",
          warmer.REMEMBER_PAGE < warmer.REMEMBER)
    monitoring.overview = real_mon

    print("the git working copies are fetched, never forced")
    # The safety property of the whole feature. clone_or_pull refuses a dirty
    # working copy, and the automatic sync must never be the caller that
    # overrides that: somebody's uncommitted edit cannot be reset by a timer
    # they did not start and cannot see.
    import inspect
    src = inspect.getsource(warmer._sync_repos)
    check("the automatic sync never forces",
          "force=False" in src and "force=True" not in src)
    check(f"and runs every five minutes ({warmer.REPO_EVERY}s)",
          warmer.REPO_EVERY == 300.0)

    from app import gitrepo
    pulls = []
    real_pull = gitrepo.clone_or_pull
    pid2 = store.add_project("Synced")
    rgid2 = store.add_region(pid2, "region")
    # the model-true fixture: an ENVIRONMENT declares the repository — the
    # warmer syncs each distinct binding, there is no region repo to warm
    store.set_env_source(pid2, rgid2, "dev",
                         {"url": "https://example.invalid/r.git",
                          "branch": "", "path": "envs/dev",
                          "protocol": "https"})

    def fake(p, r, repo, force=False, **kw):
        pulls.append((p, r, force))
        return "updated"

    gitrepo.clone_or_pull = fake
    try:
        warmer._seen.clear()
        warmer.pass_once("repos")
        check("a region nobody opened is not fetched", pulls == [])
        warmer.note_view("region", f"{pid2}/{rgid2}")
        warmer.pass_once("repos")
        check(f"opening one starts it ({pulls})",
              pulls == [(pid2, rgid2, False)])
        check("and what it did is on the record",
              warmer.repo_state(rgid2).get("outcome") == "updated")

        # A dirty region is the normal state of one being worked on, so it is
        # reported as held rather than as a failure — otherwise every region
        # anybody is editing cries wolf on the page.
        def dirty(p, r, repo, force=False, **kw):
            raise gitrepo.GitError("there are uncommitted changes in this region")

        gitrepo.clone_or_pull = dirty
        warmer.pass_once("repos")
        state = warmer.repo_state(rgid2)
        check(f"a dirty working copy is held, not failed ({state.get('outcome')})",
              state.get("outcome") == "skipped")

        def broken(p, r, repo, force=False, **kw):
            raise gitrepo.GitError("could not reach the remote")

        gitrepo.clone_or_pull = broken
        warmer.pass_once("repos")
        check("but a real failure still says failed",
              warmer.repo_state(rgid2).get("outcome") == "failed")
    finally:
        gitrepo.clone_or_pull = real_pull

    print("a region found stale is fetched at the next tick, not the next cadence")
    # The gap this closes: _due() fires once at startup, before anybody has
    # opened a page, so the next repo pass is five minutes away. Landing on a
    # region the remote has moved past therefore showed "out of date · Sync now"
    # for up to five minutes while a sync was in fact coming — which reads as
    # "the automatic sync does not work".
    pulls.clear()
    gitrepo.clone_or_pull = fake
    try:
        warmer._seen.clear()
        warmer._repo_wanted.clear()
        warmer._last.pop("repos", None)
        warmer._last.pop("repos-soon", None)
        # a prompt pass with nothing asked for does nothing
        warmer.pass_once("repos-soon")
        check("nothing asked for, nothing fetched", pulls == [])
        # asking for one both records the view and marks it
        warmer.sync_soon(pid2, rgid2)
        check("asking marks the region",
              rgid2 in warmer._repo_wanted
              and ("region", f"{pid2}/{rgid2}") in warmer._seen)
        warmer.pass_once("repos-soon")
        check(f"and the prompt pass fetches it ({pulls})",
              pulls == [(pid2, rgid2, False)])
        check("still never forcing", all(force is False for _p, _r, force in pulls))
        # and it is a ONE-SHOT: a stale region that cannot be fixed must not turn
        # every page view into another fetch of somebody's git host.
        pulls.clear()
        warmer.pass_once("repos-soon")
        check("the mark is spent, so it does not fetch again", pulls == [])
        # a second region asked for does not drag the first along with it
        pid3 = store.add_project("Third")
        rgid3 = store.add_region(pid3, "region")
        store.set_env_source(pid3, rgid3, "dev",
                             {"url": "https://example.invalid/t.git",
                              "branch": "", "path": "envs/dev",
                              "protocol": "https"})
        warmer.sync_soon(pid3, rgid3)
        warmer.pass_once("repos-soon")
        check(f"only the region asked for is fetched ({pulls})",
              pulls == [(pid3, rgid3, False)])
        # the floor is what stops the prompt path becoming a poll
        check(f"and there is a floor on how often it may run "
              f"({warmer.REPO_FLOOR}s)",
              0 < warmer.REPO_FLOOR < warmer.REPO_EVERY)
    finally:
        gitrepo.clone_or_pull = real_pull

    print("each cadence beats the cache it is there to fill")
    # Warming slower than a cache expires is the whole cost and none of the
    # benefit — the page is cold on most visits anyway. These pages block once
    # their entry ages out, so the pass has to be quicker than the shortest TTL.
    #
    # Derived from PAGES rather than from a list of three modules named here.
    # The table had nine entries and this named gitops, monitoring and
    # workflows; a tenth page with a tighter TTL than those would have been
    # warmed too slowly to matter, and nothing would have said so.
    ttls = {}
    for area, (_kind, mod, _fn) in warmer.PAGES.items():
        ttl = getattr(importlib.import_module(f"app.{mod}"), "CACHE_TTL", None)
        if isinstance(ttl, (int, float)):
            ttls[area] = ttl
    check(f"a TTL was found for most pages ({len(ttls)}/{len(warmer.PAGES)})",
          len(ttls) >= len(warmer.PAGES) - 2)
    for area, ttl in sorted(ttls.items(), key=lambda kv: kv[1]):
        check(f"PAGE_EVERY ({warmer.PAGE_EVERY}) is under {area}'s TTL ({ttl})",
              warmer.PAGE_EVERY < ttl)
    # The serve-stale targets are the opposite case: they never block, so the
    # only requirement is never to fall out of the stale window.
    check(f"SLOW_EVERY ({warmer.SLOW_EVERY}) stays inside cluster.STALE_MAX "
          f"({clusterview.STALE_MAX})", warmer.SLOW_EVERY < clusterview.STALE_MAX)
    check("and the loop wakes often enough to honour the shorter one",
          warmer.TICK < warmer.PAGE_EVERY)

    print("two passes never run at once")
    # A pass that outlives its interval must not have a second one start
    # underneath it: that is how a slow estate ends up with every pass in
    # flight at once and none of them finishing.
    started, release = threading.Event(), threading.Event()

    def slow(force=False):
        started.set()
        release.wait(5)
    fleet.overview = slow
    first = threading.Thread(target=warmer.pass_once, daemon=True)
    first.start()
    check("the first pass is under way", started.wait(2))
    ran_again = []
    fleet.overview = lambda force=False: ran_again.append(1)
    warmer.pass_once()
    check("a second pass while one is running does nothing", not ran_again)
    release.set()
    first.join(5)

    fleet.overview, clusterview.part = real_fleet, real_part
    real_reach()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


def _store_kinds() -> set:
    """The connection kinds store actually files things under, read from its
    own add_* helpers rather than listed here a second time."""
    src = pathlib.Path(__file__).resolve().parent.parent / "app" / "store.py"
    return set(re.findall(r'add_conn\("([a-z]+)"', src.read_text()))


def warmer_reachable_patch():
    """Make every cluster answer, and hand back the undo."""
    from app import kube
    real = kube.reachable
    kube.reachable = lambda c: (True, "")
    return lambda: setattr(kube, "reachable", real)


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
