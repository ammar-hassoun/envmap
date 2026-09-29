#!/usr/bin/env python3
"""What runs out, and whether the page can be trusted about it.

WHY THIS EXISTS
    A countdown page is only worth having if every number on it is exact. Two
    kinds of mistake matter here and neither shows up by looking:

      1. **A tile that does not agree with the filter it links to.** "Needs a
         person: 8" that opens a list of six is worse than no number, because
         the two disagree silently and the reader believes the bigger one.
      2. **A silence that reads as safety.** An unreachable cluster, an
         unparseable certificate or a source a role cannot see must all be
         reported. A radar that shows nothing because it could not look is
         indistinguishable from one that shows nothing because nothing is
         wrong — and the cluster nobody can reach is exactly where the expired
         certificate lives.

    The measured case behind the whole feature: on one real cluster, eight
    serving certificates, six not managed by cert-manager, one expired
    ninety-seven days ago and still installed. Nothing in the portal could see
    it, because only cert-manager's own objects were ever read.

    ./.venv/bin/python tests/test_expiry.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time
from datetime import date, datetime, timedelta, timezone

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("expiry-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import certs, expiry, rbac                            # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _utc() -> datetime:
    """Naive UTC — what the certificate builder expects, and what makes the
    epoch it produces comparable to a UTC clock rather than this machine's."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def row(days: int, renewal: str = expiry.MANUAL, kind: str = "certificate",
        name: str = "thing"):
    return expiry._row(date.today() + timedelta(days=days), name, kind,
                       renewal=renewal)


_CLIENT = None


def render(path: str) -> str:
    global _CLIENT
    from fastapi.testclient import TestClient
    from app import auth, db, main
    if _CLIENT is None:
        email, pw = "expiry@test.local", "What-Runs-Out-And-When-42"
        uid = auth.create_user(email, "CI", pw, role="admin")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uid))
        _CLIENT = TestClient(main.app)
        _CLIENT.__enter__()
        _CLIENT.post("/login", data={"email": email, "password": pw},
                     follow_redirects=False)
        _CLIENT.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
    r = _CLIENT.get(path)
    return r.text if r.status_code == 200 else f"HTTP {r.status_code}"


def main() -> int:
    print("the date, whatever shape the source produced it in")
    want = date(2026, 8, 21)
    for raw in ("2026-08-21", "2026-08-21T10:33:00Z", "2026-08-21 10:33:00",
                datetime(2026, 8, 21, 10, 33), date(2026, 8, 21)):
        check(f"{raw!r} reads as {want}", expiry._date(raw) == want)
    stamp = datetime(2026, 8, 21, 10, 33).timestamp()
    check("an epoch second reads as the local date",
          expiry._date(stamp) == want)
    for junk in (None, "", "never", "not a date", 0, -5, "0000-00-00"):
        check(f"{junk!r} yields nothing rather than today",
              expiry._date(junk) is None)
    check("and a row with no date is dropped entirely",
          expiry._row(None, "x", "certificate") is None)

    print("the bands")
    for days, want_band in ((-400, "expired"), (-1, "expired"), (0, "critical"),
                            (7, "critical"), (8, "soon"), (30, "soon"),
                            (31, "watch"), (90, "watch"), (91, "later")):
        check(f"{days:>5}d is {want_band} (got {expiry.band(days)})",
              expiry.band(days) == want_band)
    check("no date at all sorts as later", expiry.band(None) == "later")

    print("the tile agrees with the filter it links to")
    # The bug this prevents: the tile counted "anything not automatic" and
    # linked to renewal=manual, so a page with one `unknown` row promised a
    # number one larger than the list it opened.
    rows = [row(-5, expiry.MANUAL), row(10, expiry.MANUAL),
            row(40, expiry.AUTOMATIC), row(60, expiry.UNKNOWN),
            row(800, expiry.MANUAL)]
    s = expiry.summary(rows)
    same = [r for r in rows if r["days"] <= 90 and r["renewal"] == expiry.MANUAL]
    check(f"“needs a person” counts exactly what renewal=manual within 90d "
          f"returns ({s['act']} vs {len(same)})", s["act"] == len(same))
    check("an unknown renewal is not counted as needing a person",
          s["act"] == 2)
    check("expired is its own count", s["expired"] == 1)
    check("and what renews itself is counted apart", s["auto"] == 1)

    print("grouping and the forward view")
    groups = expiry.group_by_band(rows)
    check(f"bands come back in urgency order: {[k for k, _l, _r in groups]}",
          [k for k, _l, _r in groups] == [k for k in expiry.BAND_ORDER
                                          if any(r["band"] == k for r in rows)])
    check("every row is kept", sum(len(r) for _k, _l, r in groups) == len(rows))
    check("nothing in, nothing out", expiry.group_by_band([]) == [])

    plan = expiry.by_month(rows, months=12)
    check(f"twelve months are laid out ({len(plan['buckets'])})",
          len(plan["buckets"]) == 12)
    # An overdue item folded into this month would make the first bar lie.
    check("what already expired is held apart from the months",
          len(plan["overdue"]) == 1)
    check("and does not appear in any month",
          not any(r["days"] < 0 for b in plan["buckets"] for r in b["rows"]))
    check("what falls beyond the horizon is held apart too",
          len(plan["beyond"]) == 1)
    check("every row is accounted for exactly once",
          sum(len(b["rows"]) for b in plan["buckets"])
          + len(plan["overdue"]) + len(plan["beyond"]) == len(rows))
    check("the tallest month is the full-height bar",
          max((b["pct"] for b in plan["buckets"]), default=0) == 100)

    print("where the work is")
    at = [expiry._row(date.today() + timedelta(days=d), n, "certificate",
                      where=w)
          for d, n, w in ((3, "a", "ke-preprod · traefik"),
                          (4, "b", "ke-preprod · default"),
                          (5, "c", "za-preprod · traefik"),
                          (6, "d", ""))]
    ranked = expiry.places(at)
    check(f"the busiest place leads: {[p['name'] for p in ranked]}",
          [p["name"] for p in ranked] == ["ke-preprod", "za-preprod"])
    check("counted by the head of `where`, not the whole string",
          ranked[0]["n"] == 2)
    check("and a row with no place does not become one", len(ranked) == 2)

    print("the ring, drawn from the mix")
    import math as _math
    import re as _re

    from app import charts
    svg = str(charts.ring([("renews itself", 3, "var(--ok)"),
                           ("needs a person", 1, "var(--warn)"),
                           ("unknown", 0, "var(--line2)")], centre="4"))
    # A zero part with a round cap still paints a dot, which at this radius
    # reads as a real slice of something that does not exist.
    check("an empty part is not drawn at all", "unknown" not in svg)
    # only the arcs carry a dash pattern; the grey track behind them is a plain
    # circle, so every match here is a part of the mix
    dashes = [float(d.split()[0]) for d in
              _re.findall(r'stroke-dasharray="([^"]+)"', svg)]
    offs = [float(o) for o in _re.findall(r'stroke-dashoffset="(-?[\d.]+)"', svg)]
    circ = 2 * _math.pi * ((122 - 14) / 2)
    check(f"one arc per part that has a value ({len(dashes)})", len(dashes) == 2)
    check("the first part starts at the top", offs and offs[0] == 0)
    check(f"the second starts where the first ended "
          f"({-offs[1]:.1f} vs {circ * 0.75:.1f})",
          abs(-offs[1] - circ * 0.75) < 1.0)
    check("no part overruns the circle", all(d <= circ + 0.01 for d in dashes))
    solo = str(charts.ring([("all of it", 5, "var(--ok)")]))
    check("a single part closes the circle rather than leaving a seam",
          abs(float(_re.findall(r'stroke-dasharray="([\d.]+)', solo)[0]) - circ)
          < 0.01)
    check("and nothing at all says so",
          "nothing to show" in str(charts.ring([])))

    print("the words a person reads")
    for days, want_text in ((0, "today"), (1, "tomorrow"), (-1, "yesterday"),
                            (-9, "9 days ago"), (12, "in 12 days")):
        check(f"{days} reads as {want_text!r}",
              expiry.days_word(days) == want_text)

    print("a certificate that this library will not fully parse")
    # cryptography refuses certificates whose KeyUsage sets encipher_only
    # without key_agreement — three of sixty-six on a real cluster, all of them
    # sealed-secrets controller keys. Refusing to report a date because an
    # unrelated extension is malformed would hide exactly the certificates
    # nobody is watching, so read_cert degrades instead of failing.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    key = certs.new_key("ec-p256")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example")])
    good = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_utc() - timedelta(days=1))
            .not_valid_after(_utc() + timedelta(days=42))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("t.example")]), critical=False)
            .sign(key, hashes.SHA256()))
    pem = good.public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["x"]).Encoding.PEM).decode()
    got = certs.read_cert(pem)
    check("a normal certificate reads fully", got["not_after"] is not None)
    check("with its names", "t.example" in got["domains"])
    check("and is not marked partial", not got["partial"])
    want_at = (datetime.now(timezone.utc) + timedelta(days=42)).timestamp()
    check(f"the expiry is the one it was built with "
          f"(off by {abs(got['not_after'] - want_at):.0f}s)",
          abs(got["not_after"] - want_at) < 120)
    for junk in ("", "not a certificate", "-----BEGIN CERTIFICATE-----\nxx\n"
                 "-----END CERTIFICATE-----"):
        out = certs.read_cert(junk)
        check(f"{junk[:18]!r} yields no date and says why",
              out["not_after"] is None and bool(out["error"]))

    print("permissions: the area only opens the door")
    nobody = {"id": "u-none", "role": "viewer"}
    got = expiry.collect(nobody)
    check("a role with the radar and nothing else sees no rows",
          got["rows"] == [])
    check(f"and every gated source is named as hidden: {got['hidden']}",
          len(got["hidden"]) == len([k for k, (_l, _i, a)
                                     in expiry.SOURCES.items() if a]))
    check("the licence is not gated by an area it does not have",
          "Portal licence" not in got["hidden"])
    for key, (_label, _icon, areas) in expiry.SOURCES.items():
        for area in areas:
            check(f"{key} -> area {area!r} exists", area in rbac.AREAS)
        check(f"{key} has a fetcher", key in expiry._FETCH)
    check("the page itself is governed", "expiry" in rbac.AREAS)
    check("and its prefix routes to it",
          rbac.area_for_path("/expiry") == "expiry")
    # by prefix, so a sub-path added later is governed without anyone
    # remembering to add it here
    check("including anything under it",
          rbac.area_for_path("/expiry/anything") == "expiry")

    print("every source runs with a connection of its own kind present")
    # The bug this catches: _certificates() collects edge certificates through
    # fleet._pmap, and `fleet` was never imported — so the radar raised
    # NameError for anybody holding the edge area with at least one edge
    # connection configured. Two conditions at once, which is why no page test
    # saw it: with no edge connection the parallel call is never reached, and
    # with no edge area the whole block is skipped.
    #
    # So every source is exercised with something of its kind to collect, rather
    # than against an empty estate where most of the code never runs.
    from app import store as _store
    admin = {"id": "u-all", "role": "admin"}
    pid = _store.add_project("Radar")
    planted = []
    # `conn`, not `row` — there is a row() helper above, and shadowing it is
    # exactly the fault this section was written to catch.
    for label, add, conn in (
            ("edge", _store.add_edge,
             {"name": "cf", "provider": "cloudflare", "token": "tok"}),
            ("storage", _store.add_stor,
             {"name": "nas", "provider": "synology", "base_url": "https://x.invalid"}),
            ("cloud", _store.add_cloud,
             {"name": "acct", "provider": "aws", "access_key": "k",
              "secret_key": "s"}),
    ):
        try:
            add(pid, conn)
            planted.append(label)
        except Exception:                                     # noqa: BLE001
            pass       # a kind this build does not have is not this test's job
    check(f"there was something to collect ({', '.join(planted)})",
          "edge" in planted)
    for key, fetch in expiry._FETCH.items():
        try:
            rows, notes = fetch(admin, False)
            ok = True
        except NameError as e:
            # A NameError is never a connection failing — it is code that has
            # never run. Kept separate from the broad case below for that
            # reason: an unreachable Cloudflare must not look like this.
            ok = False
            check(f"{key} has no undefined name ({e})", False)
        except Exception as e:                                # noqa: BLE001
            ok = True     # unreachable connections are the page's normal life
            rows, notes = [], [str(e)]
        if ok:
            check(f"{key} collected without crashing "
                  f"({len(rows)} rows, {len(notes)} notes)", True)
    # and the whole radar, with those connections present
    try:
        got = expiry.collect(admin)
        check(f"the radar assembles over a populated estate "
              f"({len(got['rows'])} rows)", isinstance(got.get("rows"), list))
    except Exception as e:                                    # noqa: BLE001
        check(f"the radar assembles over a populated estate ({e})", False)

    print("a tab is a scope, not a smaller collection")
    # The bug this catches, reported from the page itself: `kinds` narrowed what
    # was COLLECTED, and the tab bar is built from what came back — so choosing
    # one tab left every other tab with no count, and _source_tabs renders no
    # tab at all for a source it has no count for. Clicking any tab made every
    # other tab vanish, leaving only All and the one just clicked.
    real = expiry._FETCH
    try:
        expiry._FETCH = {k: (lambda u, r=False, kk=k: (
            [row(5, expiry.MANUAL, kk, f"{kk}-a"),
             row(40, expiry.AUTOMATIC, kk, f"{kk}-b")], []))
            for k in expiry.SOURCES}
        expiry.invalidate()
        one = expiry.collect(admin, kinds=["certificate"])
        every = expiry.collect(admin)
    finally:
        expiry._FETCH = real
        expiry.invalidate()
    check(f"the list holds the chosen kind only "
          f"({sorted({r['kind'] for r in one['rows']})})",
          {r["kind"] for r in one["rows"]} == {"certificate"})
    check(f"every source still carries a count: {sorted(one['counts'])}",
          sorted(one["counts"]) == sorted(expiry.SOURCES))
    check(f"and each count is the real number, not zero "
          f"({sorted(one['counts'].values())})",
          all(n == 2 for n in one["counts"].values()))
    check("the tiles describe the tab that is open",
          one["summary"]["total"] == 2)
    check("the All tab still counts the whole estate",
          len(one["all_rows"]) == 2 * len(expiry.SOURCES) == len(every["rows"]))
    check("and the tab narrows nothing when none is chosen",
          len(every["scope"]) == len(every["rows"]))

    print("the month behind each column of the chart")
    plan = expiry.by_month(every["scope"])
    check("twelve months by default", plan["months"] == 12)
    check("the busiest month is the full-height bar",
          max(b["pct"] for b in plan["buckets"]) == 100)
    check("an empty month divides by nothing",
          all(b["mpct"] == 0 for b in plan["buckets"] if not b["n"]))
    check("each month splits into what does and does not renew itself",
          all(b["auto"] + b["manual"] == b["n"] for b in plan["buckets"]))
    busy = [b for b in plan["buckets"] if b["n"]]
    if busy:
        try:
            expiry._FETCH = {k: (lambda u, r=False, kk=k: (
                [row(5, expiry.MANUAL, kk, f"{kk}-a"),
                 row(40, expiry.AUTOMATIC, kk, f"{kk}-b")], []))
                for k in expiry.SOURCES}
            expiry.invalidate()
            picked = expiry.collect(admin, month=busy[0]["month"])
        finally:
            expiry._FETCH = real
            expiry.invalidate()
        check(f"clicking {busy[0]['month']} shows exactly that month's rows "
              f"({len(picked['rows'])} vs {busy[0]['n']})",
              len(picked["rows"]) == busy[0]["n"]
              and all(r["month"] == busy[0]["month"] for r in picked["rows"]))
    check("the month is said out loud",
          expiry.month_label("2026-11") == "November 2026")
    check("and a broken one is not guessed at",
          expiry.month_label("later") == "later")

    print("as rendered, through the real app")
    page = render("/expiry")
    check("the radar renders", "Expiry radar</h1>" in page)
    check("with the tile that matters", "Needs a person" in page)
    check("which links to the filter it counts",
          "renewal=manual" in page and "horizon=90" in page)
    import html as _html
    missing = [lbl for lbl, _i, _a in expiry.SOURCES.values()
               if _html.escape(lbl) not in page]
    check(f"a tab per source, missing {missing}", not missing)

    # The sandbox has nothing with a date, so the list, its bands and the
    # footer only appear once there is something to show. Injected rather than
    # mocked away: this is the only check that the rows themselves render.
    real = expiry._FETCH
    try:
        expiry._FETCH = {k: (lambda u, r=False, kk=k: (
            [row(-3, expiry.MANUAL, kk, f"{kk}-overdue"),
             row(20, expiry.AUTOMATIC, kk, f"{kk}-later")], []))
            for k in expiry.SOURCES}
        expiry.invalidate()
        full = render("/expiry")
        picked = render("/expiry?tab=certificate")
        narrow = render("/expiry?band=expired&renewal=manual")
    finally:
        expiry._FETCH = real
        expiry.invalidate()
    check("the rows render", "certificate-overdue" in full)
    check("grouped into bands", "EXPIRED" in full.upper())
    check("each carrying how it renews",
          "needs a person" in full and "renews itself" in full)
    check("and it says where certificates come from",
          "not only from cert-manager" in full)
    check("and that keys are never fetched", "Private keys are never" in full)

    print("the charts that replaced the calendar page")
    check("the months are drawn on the radar itself", 'class="ex-cal"' in full)
    check("each column is a link that filters the list by month",
          "month=" in full)
    check("the automatic/manual split is named under the chart",
          "renews itself" in full and "needs a person" in full)
    check("the mix is drawn as a ring", 'class="chart-donut"' in full)
    check("past due keeps a column of its own", ">past<" in full)
    check("and the separate calendar page is gone",
          render("/expiry/calendar").startswith("HTTP 4"))

    print("choosing a tab keeps the other tabs")
    missing = [lbl for lbl, _i, _a in expiry.SOURCES.values()
               if _html.escape(lbl) not in picked]
    check(f"every source is still on the tab bar, missing {missing}", not missing)
    check("and the list narrowed to the one that was chosen",
          "certificate-overdue" in picked and "warranty-overdue" not in picked)

    print("what is filtering the list says so, and can be undone")
    check("the filters in force are named", "showing only:" in narrow)
    check("expired is one of them", "Expired" in narrow)
    check("so is the renewal", "needs a person" in narrow)
    # Each × must lift its own filter and keep the rest, or the only way out of
    # two filters is to clear both and start again.
    check("lifting the band keeps the renewal",
          'href="/expiry?renewal=manual" title="remove this filter"' in narrow)
    check("lifting the renewal keeps the band",
          'href="/expiry?band=expired" title="remove this filter"' in narrow)
    filtered = render("/expiry?renewal=manual&horizon=90")
    check("the filter is accepted", "Expiry radar</h1>" in filtered)

    print("things that do not need renewing stop being counted")
    # A headline number that counts certificates nobody intends to renew is a
    # number people learn to discount -- and a discounted number hides the one
    # certificate that did matter among a dozen that never did. So they can be
    # set aside, install-wide, with a reason.
    from app import cluster as clusterview                    # noqa: PLC0415
    from app import db as _db                                 # noqa: PLC0415
    admin = {"id": "u-all", "role": "admin"}
    _db.run("DELETE FROM expiry_ignored")
    expiry.invalidate()
    r1 = expiry._row(date.today() + timedelta(days=10), "keep.example",
                     "certificate", where="c1 · ns", source="cluster")
    r2 = expiry._row(date.today() + timedelta(days=20), "internal-ca",
                     "certificate", where="c1 · ns", source="cluster")
    # THE NAME MUST SURVIVE A RENEWAL. The point of setting one aside is that
    # nobody intends to act on it, so anything that changes when the
    # certificate changes cannot be part of its identity -- not the date, and
    # not the serial.
    k2 = expiry.ignore_key(r2)
    later = dict(r2, on="2030-01-01", days=9999,
                 when=date.today() + timedelta(days=9999))
    check("the key ignores the date, so a reissue stays set aside",
          expiry.ignore_key(later) == k2)
    check("...and is different for a different name in the same place",
          expiry.ignore_key(r1) != k2)
    other_place = dict(r2, where="c2 · ns")
    check("...and for the same name in a different place",
          expiry.ignore_key(other_place) != k2)

    expiry.set_aside(r2, "internal CA, never renewed", "me@test.local")
    got = expiry.ignored_map()
    check("it is recorded with the reason and who said so",
          k2 in got and got[k2]["reason"] == "internal CA, never renewed"
          and got[k2]["who"] == "me@test.local")

    # THROUGH collect(), which is what the page and the overview both read.
    def two(part, refresh=False):
        if part != "tls":
            return []
        return [{"pid": "", "cid": "", "cluster": "c1", "present": True,
                 "certs": [
                     {"name": "keep", "namespace": "ns",
                      "domains": ["keep.example"],
                      "not_after": _utc() + timedelta(days=10), "auto": False},
                     {"name": "ca", "namespace": "ns",
                      "domains": ["internal-ca"],
                      "not_after": _utc() + timedelta(days=20), "auto": False}]}]
    real_ew = clusterview.everywhere
    clusterview.everywhere = two
    expiry.invalidate()
    try:
        out = expiry.collect(admin, kinds=["certificate"])
        names = [r["name"] for r in out["rows"]]
        check(f"the set-aside one is not in the rows ({names})",
              names == ["keep.example"])
        check("...nor in the summary the tiles and the overview read",
              out["summary"]["total"] == 1 and out["summary"]["manual"] == 1)
        # NOT DELETED, THOUGH: something invisible cannot be corrected, and an
        # assertion nobody can review is worse than a wrong count.
        check(f"...but it is counted as set aside ({out['aside_count']})",
              out["aside_count"] == 1)
        shown = expiry.collect(admin, kinds=["certificate"], aside=True)
        check("asking for them shows exactly the ones held back",
              [r["name"] for r in shown["rows"]] == ["internal-ca"])
        # THE HOUSE RULE: a tile's number is the rows its link opens.
        check("...so the tile's count is the list it links to",
              out["aside_count"] == len(shown["rows"]))
        check("...and each row carries why and who, for the next person",
              shown["rows"][0]["aside_why"] == "internal CA, never renewed"
              and shown["rows"][0]["aside_who"] == "me@test.local")
        # PUT BACK, and the number moves again.
        check("putting it back reports that it did", expiry.count_again(k2))
        check("...and again reports that there was nothing to put back",
              not expiry.count_again(k2))
        expiry.invalidate()
        back = expiry.collect(admin, kinds=["certificate"])
        check(f"...and it is counted again ({back['summary']['total']})",
              back["summary"]["total"] == 2 and back["aside_count"] == 0)
    finally:
        clusterview.everywhere = real_ew
        _db.run("DELETE FROM expiry_ignored")
        expiry.invalidate()

    print("...and setting one aside demands a reason, because the number moves")
    # This is somebody asserting that a certificate the portal can see expiring
    # does not matter, and it changes what everybody else reads. Six months on,
    # "why is this not counted?" is the question, and a reason recorded at the
    # time is the only thing that answers it.
    body = render("/expiry")
    check("the page offers the action on a row", "data-aside" in body)
    check("...and a tile only once something is set aside",
          'aside=1' not in body or 'Not counted' in body)
    cl = _CLIENT
    r = cl.post("/expiry/aside", data={"kind": "certificate", "source": "cluster",
                "name": "x.example", "where": "c1 · ns", "reason": "no"},
                follow_redirects=False)
    check(f"a reason of two characters is refused ({r.status_code})",
          r.status_code == 303 and "err=" in r.headers.get("location", ""))
    check("...and nothing was set aside", not expiry.ignored_map())
    r = cl.post("/expiry/aside", data={"kind": "certificate", "source": "cluster",
                "name": "x.example", "where": "c1 · ns",
                "reason": "decommissioned next month"}, follow_redirects=False)
    check(f"a real reason is accepted ({r.status_code})",
          r.status_code == 303 and len(expiry.ignored_map()) == 1)
    # A row with no name cannot be identified, and guessing is worse than
    # refusing.
    r = cl.post("/expiry/aside", data={"kind": "certificate", "reason": "why not"},
                follow_redirects=False)
    check("a row that cannot be identified is refused",
          r.status_code == 303 and len(expiry.ignored_map()) == 1)
    trail = _db.q("SELECT action, target, detail FROM audit "
                  "WHERE action = 'expiry_set_aside' ORDER BY rowid DESC LIMIT 1")
    check("...and the assertion is on the audit trail, with its reason",
          bool(trail) and "x.example" in trail[0]["target"]
          and "decommissioned" in trail[0]["detail"])
    k = next(iter(expiry.ignored_map()))
    r = cl.post("/expiry/count-again", data={"k": k, "name": "x.example"},
                follow_redirects=False)
    check(f"putting it back works from the page too ({r.status_code})",
          r.status_code == 303 and not expiry.ignored_map())
    _db.run("DELETE FROM expiry_ignored")
    expiry.invalidate()

    print("narrowed by WHERE it lives — project, cluster, region")
    # The page is dominated by cluster certificates, and the only way to see
    # one cluster's was a substring search over the `where` sentence — which
    # matched a namespace sharing a word, and could not express "this project"
    # at all. Three exact axes now, and they are genuinely three: a project
    # spans clusters, a cluster serves several regions, and a region is served
    # by more than one cluster, so none is derivable from the others.
    from app import auth, store
    from app import cluster as clusterview

    pid_a = store.add_project("Alpha", "🧪")
    pid_b = store.add_project("Beta", "🧪")
    c_multi = store.add_cluster(pid_a, "alpha-dev", "", "ctx-alpha-dev")
    c_solo = store.add_cluster(pid_a, "alpha-prod", "", "ctx-alpha-prod")
    c_beta = store.add_cluster(pid_b, "beta-dev", "", "ctx-beta-dev")
    # alpha-dev serves TWO regions and alpha-prod serves one of them, so
    # "region KE" and "cluster alpha-dev" are different questions with
    # overlapping answers — which is the case a single combined filter cannot
    # express and the reason there are three.
    rg_ke = store.add_region(pid_a, "KE")
    rg_tz = store.add_region(pid_a, "TZ")
    rg_uae = store.add_region(pid_b, "UAE")
    store.map_env_cluster(pid_a, rg_ke, "dev", c_multi)
    store.map_env_cluster(pid_a, rg_tz, "dev", c_multi)
    store.map_env_cluster(pid_a, rg_ke, "prod", c_solo)
    store.map_env_cluster(pid_b, rg_uae, "dev", c_beta)

    def fake(part, refresh=False):
        if part != "tls":
            return []
        def cluster(pid, cid, name, n):
            return {"pid": pid, "cid": cid, "cluster": name, "present": True,
                    "certs": [{"name": f"{name}-cert-{i}", "namespace": "app",
                               "domains": [f"{i}.{name}.example"],
                               "not_after": _utc() + timedelta(days=30 + i),
                               "auto": False} for i in range(n)]}
        return [cluster(pid_a, c_multi, "alpha-dev", 5),
                cluster(pid_a, c_solo, "alpha-prod", 3),
                cluster(pid_b, c_beta, "beta-dev", 2)]

    real_everywhere = clusterview.everywhere
    clusterview.everywhere = fake
    expiry.invalidate()
    try:
        me = auth.by_id(auth.by_email("expiry@test.local")["id"])
        got = expiry.collect(me, kinds=["certificate"])
        f = got["facets"]
        by = {a: {o["label"]: o for o in f[a]}
              for a in ("projects", "clusters", "regions")}
        check(f"every cluster's certificates are collected ({len(got['scope'])})",
              len(got["scope"]) == 10)
        # .get throughout: an axis that stopped being offered at all is a
        # FAILING CHECK, not a KeyError — a traceback reads as a broken test
        # rather than as the thing it caught.
        def n_of(axis, label):
            return (by[axis].get(label) or {}).get("n")
        check(f"projects are offered with counts ({by['projects']})",
              n_of("projects", "Alpha") == 8 and n_of("projects", "Beta") == 2)
        check(f"and clusters ({sorted(by['clusters'])})",
              n_of("clusters", "alpha-dev") == 5
              and n_of("clusters", "beta-dev") == 2)
        # A cluster serving two regions counts in BOTH, and a region served by
        # two clusters sums them — a row belongs to every region it is in, and
        # counting it once would make the numbers not add up in either
        # direction.
        check(f"and regions, a row counting in every one it serves "
              f"({sorted((k, v['n']) for k, v in by['regions'].items())})",
              n_of("regions", "KE") == 8       # alpha-dev 5 + alpha-prod 3
              and n_of("regions", "TZ") == 5   # alpha-dev only
              and n_of("regions", "UAE") == 2)

        # THE RULE THIS PAGE LIVES BY: a number opens a list of its own size.
        mismatched = []
        for axis, key in (("projects", "project"), ("clusters", "cluster"),
                          ("regions", "region")):
            for o in f[axis]:
                n = len(expiry.collect(me, kinds=["certificate"],
                                       **{key: o["value"]})["rows"])
                if n != o["n"]:
                    mismatched.append(f"{axis}/{o['label']} said {o['n']} opened {n}")
        check(f"every option opens exactly what it counted ({mismatched})",
              not mismatched)

        # The axes compose, and they are not the same axis wearing three hats.
        both = expiry.collect(me, kinds=["certificate"],
                              cluster=c_multi, region="TZ")["rows"]
        check(f"cluster and region narrow together ({len(both)})", len(both) == 5)
        neither = expiry.collect(me, kinds=["certificate"],
                                 cluster=c_solo, region="TZ")["rows"]
        check("and a combination nothing satisfies is empty, not everything",
              neither == [])
        check("a project filter does not leak another project's rows",
              all(r["pid"] == pid_b for r in
                  expiry.collect(me, kinds=["certificate"],
                                 project=pid_b)["rows"]))
        # A row that names no cluster must not be swept in by a place filter.
        check("a filter offers nothing that opens an empty page",
              all(o["n"] > 0 for a in f for o in f[a]))

        # The ranked bars link to the exact cluster rather than a text search
        # over the `where` sentence, which matched a namespace sharing a word.
        places = expiry.places(got["scope"], top=5)
        check(f"each bar carries the cluster id it counted ({places[0]})",
              places and all(p["cid"] for p in places))
        check("and the bar's id opens the bar's own number",
              len(expiry.collect(me, kinds=["certificate"],
                                 cluster=places[0]["cid"])["rows"])
              == places[0]["n"])

        # As rendered: the selects appear, and a chip says what is in force by
        # NAME — "showing only: c-34f8b73f" is a filter nobody can recognise.
        page = render(f"/expiry?tab=certificate&cluster={c_multi}")
        check("the page renders the three place selects",
              'name="project"' in page and 'name="cluster"' in page
              and 'name="region"' in page)
        check("and names the filter in force rather than showing its id",
              "alpha-dev" in page and c_multi not in
              page.split("showing only:")[-1][:400])
    finally:
        clusterview.everywhere = real_everywhere
        expiry.invalidate()

    print("a row that could never exist is not storable, and the list has a lid")
    # The route takes the row's identity from the FORM, so nothing tied a
    # stored key to a thing the portal can see. An unrecognised kind would be
    # a permanent entry in a table every single read of the radar walks
    # (`ignored_map` stamps `aside` onto every row), describing nothing, that
    # no page could offer a "count again" button for.
    real = {"kind": "certificate", "source": "clusters",
            "where": "ns/thing", "name": "tls-probe"}
    try:
        expiry.set_aside(dict(real, kind="not-a-kind"), "because", "t@t")
        check("an unknown kind is refused", False)
    except ValueError:
        check("an unknown kind is refused", True)
    check("...and nothing was stored for it",
          not any(v.get("kind") == "not-a-kind"
                  for v in expiry.ignored_map().values()))
    k = expiry.set_aside(real, "self-signed, never renewed", "t@t")
    check("a real kind still stores", k in expiry.ignored_map())

    # The lid. Re-stating a reason on something ALREADY held back has to keep
    # working when the list is full, or the cap would block the one edit that
    # does not grow anything.
    keep = expiry.MAX_ASIDE
    try:
        expiry.MAX_ASIDE = 1
        try:
            expiry.set_aside(dict(real, name="another"), "reason", "t@t")
            check("the cap refuses a new row when full", False)
        except expiry.TooMany:
            check("the cap refuses a new row when full", True)
        # Caught rather than left to propagate: a regression here is the cap
        # blocking the one write that does not grow the table, and that
        # should read as a FAIL line, not as a traceback that hides every
        # check after it.
        try:
            again = expiry.set_aside(real, "a clearer reason", "t@t")
        except expiry.TooMany:
            again = None
        check("...but re-stating a reason on an existing one still works",
              again == k)
        check("...and it really did update",
              (expiry.ignored_map().get(k) or {}).get("reason")
              == "a clearer reason")
    finally:
        expiry.MAX_ASIDE = keep
    expiry.count_again(k)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
