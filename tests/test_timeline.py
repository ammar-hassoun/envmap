#!/usr/bin/env python3
"""The timeline is only worth having if the order is true.

WHY THIS EXISTS
    Five systems, five timestamp formats, and two of them are naive strings
    that look identical and mean different things: the audit log writes local
    time with no offset, and Argo CD writes UTC with the Z stripped off. Read
    both as "local" and a deploy made at 14:03 local sits four hours after the
    alert it caused in the Gulf; read both as "UTC" and every human action
    jumps forward instead. Either way the page still renders, still looks
    plausible, and inverts cause and effect — which is the only thing it is
    for.

    So the ordering is the assertion, not the parsing: the checks below build
    the same instant in each source's own dialect and require them to land on
    one point, and require a known cause-then-effect sequence to come back in
    that order.

    ./.venv/bin/python tests/test_timeline.py
"""
from __future__ import annotations

import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("timeline-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import rbac, timeline                                 # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


_CLIENT = None


def render(path: str, seed: bool = False) -> str:
    """One page as a browser is sent it, signed in as an administrator."""
    global _CLIENT
    import time as _time

    from fastapi.testclient import TestClient
    from app import auth, db, main

    if _CLIENT is None:
        email, pw = "timeline@test.local", "What-Changed-At-Two-AM-42"
        uid = auth.create_user(email, "CI", pw, role="admin")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uid))
        _CLIENT = TestClient(main.app)
        _CLIENT.__enter__()
        _CLIENT.post("/login", data={"email": email, "password": pw},
                     follow_redirects=False)
        _CLIENT.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(_time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
    if seed:
        auth.audit({"email": "ammar@test.local"}, "config-push", "bff-mobile",
                   "raise minio timeout")
    r = _CLIENT.get(path)
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    return r.text


def local_of(utc_naive: str) -> datetime:
    """What a UTC wall-clock string should become once converted, computed the
    long way round so the test does not simply repeat the implementation."""
    dt = datetime.strptime(utc_naive, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None)


def main() -> int:
    print("one instant, five dialects")
    # 10:03:11 UTC, as each source actually writes it
    want = local_of("2026-08-06 10:03:11")
    epoch_ms = int(datetime(2026, 8, 6, 10, 3, 11,
                            tzinfo=timezone.utc).timestamp() * 1000)
    same = {
        "argo (UTC, Z stripped)": timeline.at("2026-08-06 10:03:11"),
        "prometheus (Z)": timeline.at("2026-08-06T10:03:11Z"),
        "prometheus (fractional)": timeline.at("2026-08-06T10:03:11.482913Z"),
        "argo (7-digit fraction)": timeline.at("2026-08-06T10:03:11.4829137Z"),
        "ci (epoch ms)": timeline.at(epoch_ms),
        "ci (epoch ms as text)": timeline.at(str(epoch_ms)),
        "explicit +00:00": timeline.at("2026-08-06T10:03:11+00:00"),
    }
    for label, got in same.items():
        check(f"{label} lands on the same instant (got {got}, want {want})",
              got == want)

    # A committer in the Gulf writes the same instant with an offset on it.
    check("git's own offset is honoured, not assumed",
          timeline.at("2026-08-06T14:03:11+04:00") == want)
    check("and a negative offset too",
          timeline.at("2026-08-06T06:03:11-04:00") == want)

    print("the two naive shapes that mean different things")
    # THE bug this file exists for: identical strings, different clocks.
    as_utc = timeline.at("2026-08-06T10:03:11")
    as_local = timeline.at("2026-08-06T10:03:11", clock="local")
    # the offset in force at that instant, not today's — the difference is DST,
    # and a test that ignores it fails twice a year on half the planet
    offset = (datetime(2026, 8, 6, 10, 3, 11, tzinfo=timezone.utc)
              .astimezone().utcoffset() or timedelta(0))
    check("a naive value defaults to UTC", as_utc == want)
    check("the audit log's naive value is taken as local",
          as_local == datetime(2026, 8, 6, 10, 3, 11))
    check(f"so the same string read the two ways differs by the local offset "
          f"({offset}) — the whole reason this file exists",
          (as_utc - as_local) == offset)
    check("an offset on the value still wins over clock=local",
          timeline.at("2026-08-06T10:03:11Z", clock="local") == want)

    print("what is not a timestamp")
    for junk in (None, "", "never", "not a date", "2026-02-31T00:00:00Z", 0, -5):
        check(f"{junk!r} yields nothing rather than now", timeline.at(junk) is None)

    print("ordering: cause below effect, newest on top")
    # A deploy, then the alert it caused two minutes later, expressed the way
    # each system would express it. Ordered wrongly, the alert sinks below the
    # commit that preceded the deploy by an hour — the exact failure that makes
    # the page lie about causality.
    events = [
        timeline._ev(timeline.at("2026-08-06T09:00:00Z"), "commit", "raise timeout"),
        timeline._ev(timeline.at("2026-08-06 10:03:11"), "deploy", "bff-mobile"),
        timeline._ev(timeline.at("2026-08-06T10:05:11Z"), "alert", "PodCrashLooping"),
    ]
    check("every event was placed", all(events))
    events.sort(key=lambda e: (e["at"], timeline._CAUSALITY.get(e["kind"], 9)),
                reverse=True)
    check(f"newest first: {[e['what'] for e in events]}",
          [e["kind"] for e in events] == ["alert", "deploy", "commit"])

    # Same second, different kinds: the effect belongs above the cause. An
    # alert caused by a deploy caused by a commit, all stamped the same second,
    # must not be shuffled into a story that runs backwards.
    tied = [timeline._ev(want, k, k)
            for k in ("alert", "commit", "deploy", "build", "event")]
    tied.sort(key=lambda e: (e["at"], timeline._CAUSALITY.get(e["kind"], 9)),
              reverse=True)
    check(f"a tie is broken by causality, not by chance: "
          f"{[e['kind'] for e in tied]}",
          [e["kind"] for e in tied] == ["alert", "event", "deploy", "build",
                                        "commit"])

    print("an event with no usable time is dropped, not guessed at")
    check("no timestamp, no row", timeline._ev(None, "sync", "x") is None)

    print("the window")
    since, until = timeline.window(hours=6)
    check("six hours back", 5.9 < (until - since).total_seconds() / 3600 < 6.1)
    check("clamped at the top", (timeline.window(hours=99999)[1]
                                 - timeline.window(hours=99999)[0])
          .total_seconds() / 3600 <= timeline.MAX_HOURS)
    check("and at the bottom", (timeline.window(hours=0)[1]
                                - timeline.window(hours=0)[0])
          .total_seconds() > 0)
    centre = datetime(2026, 8, 6, 14, 0, 0)
    lo, hi = timeline.window(centre=centre, span=30)
    check("centring is symmetrical",
          lo == centre - timedelta(minutes=30) and hi == centre + timedelta(minutes=30))

    print("grouping")
    rows = [timeline._ev(datetime(2026, 8, 6, 14, 0), "sync", "a"),
            timeline._ev(datetime(2026, 8, 6, 9, 0), "sync", "b"),
            timeline._ev(datetime(2026, 8, 5, 23, 0), "sync", "c")]
    days = timeline.group_by_day(rows)
    check(f"two days, in the order given: {[d for d, _ in days]}",
          [d for d, _ in days] == ["2026-08-06", "2026-08-05"])
    check("and every row is kept", sum(len(r) for _d, r in days) == 3)
    check("nothing in, nothing out", timeline.group_by_day([]) == [])

    print("every source is governed by a real area")
    # A source gated by an area that does not exist would be gated by nothing:
    # may_area() would answer False for everyone and the source would silently
    # vanish, or a typo'd key would never match and it would show to all.
    for key, (label, _icon, areas) in timeline.SOURCES.items():
        check(f"{key} names at least one area", bool(areas))
        for area in areas:
            check(f"{key} -> area {area!r} exists", area in rbac.AREAS)
        check(f"{key} has a label", bool(label))
        check(f"{key} has a fetcher", key in timeline._FETCH)
    check("the page itself is governed", "timeline" in rbac.AREAS)
    check("and its prefix routes to it",
          rbac.area_for_path("/timeline") == "timeline")
    check("every kind has a causality rank",
          set(timeline.SOURCES) == set(timeline._CAUSALITY))

    print("permissions: a role with the page but no sources sees nothing")
    # collect() must not fall back to "show it anyway" when a role grants the
    # timeline and none of the systems it merges.
    nobody = {"id": "u-none", "role": "viewer"}
    got = timeline.collect(nobody, hours=1)
    check("no events", got["events"] == [])
    check(f"and every source is named as hidden: {got['hidden']}",
          len(got["hidden"]) == len(timeline.SOURCES))

    print("counts a human can read")
    # Kubernetes counts a chronic failure every time it retries, so these reach
    # seven figures. Printed in full they bury the two-digit ones beside them.
    for raw, want_txt in ((1, "1"), (999, "999"), (1000, "1k"), (23640, "23.6k"),
                          (11775, "11.8k"), (2097456, "2.1M")):
        check(f"{raw} reads as {want_txt} (got {timeline._compact(raw)})",
              timeline._compact(raw) == want_txt)

    print("routine control-plane chatter is not a change")
    # LeaderElection renews constantly on a healthy cluster and was most of the
    # page when it was allowed through.
    check("LeaderElection is not treated as noteworthy",
          "LeaderElection" not in timeline._EVENTS_WORTH)
    check("but a node going away still is",
          "NodeNotReady" in timeline._EVENTS_WORTH)

    print("the quiet between bursts")
    # Four changes in two minutes, then nothing for three hours, then one more.
    # The gap belongs on the row ABOVE the older one, reading newest-first.
    burst = [timeline._ev(datetime(2026, 8, 6, 14, 2), "event", "d"),
             timeline._ev(datetime(2026, 8, 6, 14, 1), "event", "c"),
             timeline._ev(datetime(2026, 8, 6, 14, 0), "event", "b"),
             timeline._ev(datetime(2026, 8, 6, 11, 0), "event", "a")]
    gaps = [timeline.gap_before(burst, i) for i in range(len(burst))]
    check(f"only the real gap is drawn: {gaps}",
          gaps[0] == "" and gaps[1] == "" and gaps[2] == "3.0 hours")
    check("and the oldest row has nothing below it to measure against",
          gaps[3] == "")
    check("a gap under the threshold is not drawn",
          timeline.gap_before([timeline._ev(datetime(2026, 8, 6, 14, 20), "event", "x"),
                               timeline._ev(datetime(2026, 8, 6, 14, 0), "event", "y")],
                              0) == "")

    print("the density strip")
    lo, hi = datetime(2026, 8, 6, 12, 0), datetime(2026, 8, 6, 13, 0)
    bs = timeline.buckets(
        [timeline._ev(datetime(2026, 8, 6, 12, 1), "event", "x", tone="bad"),
         timeline._ev(datetime(2026, 8, 6, 12, 1), "event", "y"),
         timeline._ev(datetime(2026, 8, 6, 12, 59), "event", "z")], lo, hi)
    check(f"one bucket per slot: {len(bs)}", len(bs) == timeline.BUCKETS)
    check("everything is counted", sum(b["n"] for b in bs) == 3)
    check("the busiest bucket is the full-height one",
          max(b["pct"] for b in bs) == 100)
    check("a bad event colours its bucket",
          any(b["tone"] == "bad" for b in bs))
    check("an event exactly at the end lands inside the strip, not past it",
          sum(b["n"] for b in timeline.buckets(
              [timeline._ev(hi, "event", "edge")], lo, hi)) == 1)
    check("an empty window does not divide by zero",
          len(timeline.buckets([], lo, lo)) == timeline.BUCKETS)

    print("as rendered, through the real app")
    # A module that returns correct rows and a template that raises on one of
    # them are the same broken page to a reader, so the page is fetched rather
    # than reasoned about. The sandbox has no connections, so the audit log is
    # the source under test here — which is also the only one that works on a
    # fresh install, and therefore the one a first-run page must not fall over
    # on.
    page = render("/timeline", seed=True)
    check("the page renders", "Timeline</h1>" in page)
    check("the seeded change is on it", "raise minio timeout" in page)
    check("with its target", "bff-mobile" in page)
    check("and the source filters are offered",
          all(lbl in page for lbl, _i, _a in timeline.SOURCES.values()))
    check("sources this role cannot see are not claimed as covered",
          "do not include" not in page)          # the seeded user is an admin

    empty = render("/timeline?hours=1&kind=commit")
    check("an empty window says so rather than showing a bare page",
          "Nothing changed in this window" in empty)
    check("and does not show the seeded action, which was not asked for",
          "raise minio timeout" not in empty)
    # The sandbox has no CI, no Argo, no clusters. Those sources must read as
    # "not connected", never as "looked and found nothing" — the distinction
    # this page got wrong first time round. It is on the tab itself now: greyed
    # out, with a dash where a count would be.
    check("unconnected sources are marked so on their tab",
          "Nothing of this kind is connected yet" in empty)
    check("and are not presented as clickable",
          'class="on off"' in empty or ' off"' in empty)

    print("a cold page renders before the slow sources answer")
    # Measured on a real estate, one source at a time, everything cold: cluster
    # events 15.0s, deployments 10.7s, security scans 5.5s. Running them
    # together still costs fifteen seconds, and a click that costs fifteen
    # seconds is a broken page however well it parallelises. So the render has
    # a deadline and the stragglers are named rather than waited for.
    import threading
    import time as _time
    slow = threading.Event()

    def crawl(user, since, refresh=False):
        slow.wait(20)                    # never answers within the deadline
        return [], []

    # Only the sources with something behind them are ever asked for, and this
    # sandbox has no clusters or CI — so the one to slow down is a source that
    # is always configured, and the one to leave alone is the other.
    real = dict(timeline._FETCH)
    try:
        timeline._FETCH = {**real, "cert": crawl}
        timeline.invalidate()
        started = _time.monotonic()
        got = timeline.collect({"id": "u-cold", "role": "admin"}, hours=24)
        took = _time.monotonic() - started
        check(f"it does not wait for them (took {took:.1f}s, deadline "
              f"{timeline.FIRST_PAINT}s)", took < timeline.FIRST_PAINT + 1.5)
        check(f"and names what is still coming: {got['pending']}",
              "Certificates" in got["pending"])
        check("while what did arrive is not named as pending",
              "Portal actions" not in got["pending"])
    finally:
        slow.set()
        timeline._FETCH = real
        timeline.invalidate()

    print("tabs, one per source, built from the source table")
    page = render("/timeline")
    for label, _icon, _areas in timeline.SOURCES.values():
        check(f"there is a tab for {label}", f">{label}</span>" in page)
    check("plus an All tab", ">All</span>" in page)
    check("All is the default", 'class="on"' in page)
    one = render("/timeline?tab=build")
    check("a tab can be selected", 'tab=build' in one or 'class="on"' in one)
    check("and the checkbox filters are gone",
          'type="checkbox"' not in one)

    print("the density strip is clickable")
    check("each bar links somewhere", "click to open this window" in page)
    check("and centres on a moment", "at=2026-" in page or "at=202" in page)

    centred = render("/timeline?at=2026-08-06T14:00:00&span=30")
    check("centring renders", "within 30 minutes" in centred
          or "2026-08-06 14:00:00" in centred)

    junk = render("/timeline?at=not-a-time")
    check("an unreadable moment is reported, not silently ignored",
          "could not be read" in junk)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
