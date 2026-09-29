#!/usr/bin/env python3
"""The subscription register and its money.

The arithmetic is the point. A quarterly bill and a yearly one cannot be added
together, a one-off counted as a run rate overstates it forever, and adding two
currencies without a rate produces a confident wrong number — so each of those
is a case here rather than a comment.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_spend.py
"""
from __future__ import annotations

import datetime as dt
import os
import pathlib
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("spend-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import spend                                          # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def in_days(n: int) -> str:
    return (dt.date.today() + dt.timedelta(days=n)).isoformat()


def _raises(fn) -> bool:
    try:
        fn()
    except ValueError:
        return True
    return False


def add(**over):
    row = {"name": "thing", "vendor": "Acme", "category": "saas",
           "kind": "subscription", "cost": "100", "currency": "USD",
           "cycle": "yearly", "status": "active"}
    row.update(over)
    return spend.create(row, "tester")


def main() -> int:
    print("the run rate is derived, not typed")
    check("a yearly bill spreads over twelve months",
          spend.run_rate(1200, "yearly") == (100.0, 1200.0))
    check("a monthly bill annualises",
          spend.run_rate(250, "monthly") == (250.0, 3000.0))
    check("a quarterly bill is not simply added",
          spend.run_rate(300, "quarterly") == (100.0, 1200.0))
    check("a two-year term spreads over 24 months",
          spend.run_rate(2400, "biennial") == (100.0, 1200.0))
    # a one-off in the monthly total would overstate the run rate forever
    check("a one-off contributes nothing to the run rate",
          spend.run_rate(5000, "one-off") == (0.0, 0.0))
    check("a metered row contributes nothing either",
          spend.run_rate(5000, "metered") == (0.0, 0.0))

    print("renewal windows")
    check("a past date reads as lapsed",
          spend.renewal_state(in_days(-3))["state"] == "expired")
    check("and says how long ago",
          "3 days ago" in spend.renewal_state(in_days(-3))["label"])
    # a one-off has no renewal to be late for: an invoice paid in December is
    # a thing that happened, not a lapse, and it must stay out of the count of
    # things needing attention
    past = spend.renewal_state(in_days(-3), "active", "one-off")
    check(f"a paid one-off is charged, not expired, got {past['state']}",
          past["state"] == "charged")
    check(f"and says when it was charged, got {past['label']}",
          past["label"] == f"charged {in_days(-3)}")
    check("a one-off still ahead of us falls due rather than renews",
          spend.renewal_state(in_days(90), "active", "one-off")["label"]
          .startswith("due "))
    check("while a subscription still renews",
          spend.renewal_state(in_days(90), "active", "yearly")["label"]
          .startswith("renews "))
    check("tomorrow is soon", spend.renewal_state(in_days(1))["state"] == "soon")
    check("a day is singular",
          spend.renewal_state(in_days(1))["label"] == "renews in 1 day")
    check("the edge of the window is still soon",
          spend.renewal_state(in_days(spend.SOON_DAYS))["state"] == "soon")
    check("beyond it is not",
          spend.renewal_state(in_days(spend.SOON_DAYS + 1))["state"] == "ok")
    check("no date is its own state, not an expiry",
          spend.renewal_state("")["state"] == "none")
    check("an unparseable date does not raise",
          spend.renewal_state("whenever")["state"] == "none")
    check("a cancelled row is not chased for renewal",
          spend.renewal_state(in_days(-9), "cancelled")["state"] == "inactive")

    print("what people actually type into a date field")
    for typed, want in (("2027-03-01", "2027-03-01"), ("01/03/2027", "2027-03-01"),
                        ("1 March 2027", "2027-03-01"), ("2027/03/01", "2027-03-01"),
                        ("", ""), ("soon", "")):
        got = spend._iso_date(typed)
        check(f"{typed!r} -> {want!r} (got {got!r})", got == want)

    print("totals")
    spend.set_base_currency("USD")
    add(name="M365", vendor="Microsoft", cost="3000", cycle="yearly",
        seats="25", renews=in_days(200))
    add(name="Hostinger", vendor="Hostinger", cost="12", cycle="monthly",
        category="hosting", renews=in_days(10))
    add(name="Elementor", vendor="Elementor", cost="99", cycle="yearly",
        category="plugin", renews=in_days(-5))
    add(name="a laptop", cost="2000", cycle="one-off", category="other")
    t = spend.totals()
    check(f"four active rows, got {t['count']}", t["count"] == 4)
    check(f"seats counted, got {t['seats']}", t["seats"] == 25)
    # 3000/12 + 12 + 99/12 = 250 + 12 + 8.25, and the laptop adds nothing
    check(f"monthly run rate excludes the one-off, got {t['monthly']}",
          t["monthly"] == 270.25)
    check(f"yearly is twelve times it, got {t['yearly']}", t["yearly"] == 3243.0)
    check("the lapsed row is listed", len(t["expired"]) == 1)
    check("the one due in ten days is listed", len(t["soon"]) == 1)
    check("the undated one-off is separated", len(t["undated"]) == 1)
    check("the breakdown is biggest-first",
          [v for _, v in t["by_vendor"]] == sorted(
              [v for _, v in t["by_vendor"]], reverse=True))
    check("Microsoft leads it", t["by_vendor"][0][0] == "Microsoft")

    print("any currency in, any currency out")
    # pegs are published constants, so they need no typing and cannot go stale
    check("the dirham peg is built in", spend.rates()["AED"]["rate"] == 3.6725)
    check("and the riyal", spend.rates()["SAR"]["rate"] == 3.75)
    check("a peg is marked as one", spend.rates()["AED"]["src"] == "peg")
    check("a peg carries no age to go stale on",
          [r for r in spend.rate_rows() if r["code"] == "AED"][0]["stale"]
          is False)
    # conversion goes through the pivot, so a pair cannot contradict itself
    aed_to_sar, ok = spend.convert(3.6725, "AED", "SAR")
    check(f"1 USD of dirhams is 3.75 riyals (got {aed_to_sar})",
          ok and abs(aed_to_sar - 3.75) < 1e-9)
    back, _ = spend.convert(aed_to_sar, "SAR", "AED")
    check(f"and it round-trips (got {back})", abs(back - 3.6725) < 1e-9)
    check("the same currency is a no-op",
          spend.convert(10, "AED", "AED") == (10.0, True))
    check("an unknown source is refused, not guessed",
          spend.convert(10, "ZZZ", "USD")[1] is False)
    check("an unknown target too",
          spend.convert(10, "USD", "ZZZ")[1] is False)
    check("a typed rate overrides a peg",
          (spend.set_rate("AED", 4.0), spend.rates()["AED"]["rate"])[1] == 4.0)
    check("and is marked as entered", spend.rates()["AED"]["src"] == "manual")
    check("removing it restores the peg",
          (spend.set_rate("AED", 0), spend.rates()["AED"]["rate"])[1] == 3.6725)
    check("a rate needs a real code", spend.set_rate("E", "3") is False)
    check("and a real number", spend.set_rate("KES", "soon") is False)
    check("the pivot cannot be re-rated", spend.set_rate("USD", "2") is False)
    check("a thousands separator in a rate is accepted",
          (spend.set_rate("IDR", "16,200"), spend.rates()["IDR"]["rate"])[1]
          == 16200.0)
    # a typed rate for a floating currency goes stale; the page must say so
    spend.set_rate("KES", 129.5, when=(dt.date.today()
                                       - dt.timedelta(days=200)).isoformat())
    kes = [r for r in spend.rate_rows() if r["code"] == "KES"][0]
    check(f"an old rate is flagged stale (age {kes['age']})", kes["stale"])
    spend.set_rate("KES", 129.5)
    kes = [r for r in spend.rate_rows() if r["code"] == "KES"][0]
    check("re-entering it clears the flag", not kes["stale"])
    check("and stamps today", kes["at"] == dt.date.today().isoformat())

    print("switching the display currency moves every figure")
    spend.set_display_currency("USD")
    usd = spend.totals()["yearly"]
    spend.set_display_currency("AED")
    aed = spend.totals()
    check("the totals are now in dirhams", aed["base"] == "AED")
    check(f"and scaled by the peg (got {aed['yearly']} from {usd})",
          abs(aed["yearly"] - usd * 3.6725) < 0.01)
    check("a row reports what it shows as",
          all(r["shown_in"] == "AED" for r in spend.search()))
    spend.set_display_currency("USD")
    check("switching back returns the original figure",
          abs(spend.totals()["yearly"] - usd) < 0.01)
    for junk in ("", "E", "12", None):
        spend.set_display_currency(junk)
        check(f"junk display currency {junk!r} is ignored",
              spend.base_currency() == "USD")

    print("a currency with no peg and no rate is reported, not summed")
    spend.set_display_currency("USD")
    before = spend.totals()["yearly"]
    # the Tanzanian shilling floats, so nothing can be assumed about it
    add(name="TZ hosting", vendor="Local ISP", cost="2600000", cycle="yearly",
        currency="TZS", renews=in_days(90))
    t = spend.totals()
    check(f"it is named as unconverted, got {t['unconverted']}",
          t["unconverted"] == ["TZS"])
    check("and the row itself is named, not only the code",
          [r["name"] for r in t["stranded"]] == ["TZ hosting"])
    check("the total has not moved", abs(t["yearly"] - before) < 0.01)
    spend.set_rate("TZS", 2600)
    t = spend.totals()
    check("once a rate exists there is nothing unconverted",
          t["unconverted"] == [] and t["stranded"] == [])
    check(f"and it joins the total, got {t['yearly']}",
          abs(t["yearly"] - (before + 2600000 / 2600)) < 0.01)
    check("a rate of zero strands it again",
          (spend.set_rate("TZS", 0),
           spend.totals()["unconverted"])[1] == ["TZS"])
    check("changing the display currency does not lose the row",
          (spend.set_display_currency("SAR"), spend.totals()["count"])[1] == 5)
    spend.set_display_currency("USD")

    print("input is cleaned, not trusted")
    rid = add(name="  spaces  ", cost="1,250.50", currency="usd",
              cycle="nonsense", category="nonsense", kind="nonsense",
              status="nonsense", seats="-4")
    row = spend.get(rid)
    check("the name is trimmed", row["name"] == "spaces")
    check("a thousands separator is accepted", row["cost"] == 1250.50)
    check("the currency is upper-cased", row["currency"] == "USD")
    check("an unknown cycle falls back to yearly", row["cycle"] == "yearly")
    check("an unknown category becomes other", row["category"] == "other")
    check("an unknown kind becomes subscription",
          row["kind"] == "subscription")
    check("an unknown status becomes active", row["status"] == "active")
    check("negative seats become zero", row["seats"] == 0)
    try:
        add(name="   ")
        check("a nameless row must be refused", False)
    except ValueError:
        pass
    spend.delete(rid)

    print("through the HTTP stack")
    from fastapi.testclient import TestClient
    from app import auth, db, main
    email, pw = "spend@test.local", "Subs-Add-Up-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    with c:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

        page = c.get("/spend").text
        check("the page renders", "IT spend" in page)
        # the page leads with the year, not a run rate: thirteen boxes, one
        # per month plus the whole year, each carrying its own total
        check("it shows a box per month and one for the year",
              page.count('class="ybox') == 13)
        check("the year can be changed", 'id="yr"' in page and 'name="year"' in page)
        check("the thirteenth box is the whole year", "Whole year" in page)
        check("a box opens the lines behind it", "&m=all#detail" in page)
        # The register moved off this page; what is left is the calendar.
        check("the register lists a row", "Hostinger" in c.get("/spend/manage").text)
        check("the nav offers it", "/spend" in c.get("/").text)

        # a row added through the form appears, and the totals move with it
        before = spend.totals()["monthly"]
        r = c.post("/spend/save", data={
            "name": "Zoom", "vendor": "Zoom", "category": "saas",
            "cost": "60", "currency": "USD", "cycle": "monthly",
            "renews": in_days(45)}, follow_redirects=False)
        check(f"saving redirects, got {r.status_code}", r.status_code == 303)
        check("the total moved by exactly the new row",
              abs(spend.totals()["monthly"] - (before + 60)) < 0.01)
        check("and it is on the page", "Zoom" in c.get("/spend/manage").text)

        zoom = next(r for r in spend.search() if r["name"] == "Zoom")
        # deletion needs the word, like every other removal in the portal
        for typed in ("", "yes", zoom["id"]):
            c.post("/spend/delete", data={"id": zoom["id"], "confirm": typed},
                   follow_redirects=False)
            check(f"delete refused {typed!r}", spend.get(zoom["id"]) is not None)
        c.post("/spend/delete", data={"id": zoom["id"], "confirm": "Delete"},
               follow_redirects=False)
        check("Delete removes it", spend.get(zoom["id"]) is None)

        # filters must not move the totals: a run rate that changes when you
        # search is worse than no run rate
        whole = spend.totals()["monthly"]
        filtered = c.get("/spend/manage?category=hosting").text
        # scoped to the register table: the totals and the cash-out chart cover
        # every active row on purpose, so names the filter excluded still appear
        # in the chart's table view further up the page
        register = filtered[filtered.find('id="register"'):]
        check("filtering shows fewer rows in the register",
              "M365" not in register)
        check("the register is where that was checked", 'id="register"' in filtered)
        # The global run rate is not printed on this page at all — the first
        # version of this check looked for its figure anyway, and passed for
        # YEARS because the number happened to appear inside the inline
        # stylesheet ("270" in a pixel value). Moving the CSS to a file was
        # what exposed it. What the page actually promises is that the charts
        # ABOVE the register ignore the filter, so the excluded name is still
        # in them.
        # The page's own words beside the filter: "the figures and charts
        # above cover every active row". Asserted by comparing the year grid
        # byte-for-byte against the unfiltered page rather than hunting for a
        # figure in it — the first version of this check looked for the run
        # rate's NUMBER, which this page never prints, and passed for its whole
        # life because "270" happened to appear in the inline stylesheet.
        # Extracting the CSS to a file is what finally made it fail.
        def year_grid(page: str) -> str:
            return page[page.find('id="year"'):page.find('id="detail"')]
        unfiltered = c.get("/spend/manage").text
        check("while the year grid above ignores the filter entirely",
              year_grid(filtered) == year_grid(unfiltered)
              and len(year_grid(filtered)) > 200)

        csv = c.get("/spend/export.csv")
        check("the CSV downloads",
              csv.status_code == 200 and "text/csv" in csv.headers["content-type"])
        check("with a header naming the base currency",
              "per year (USD)" in csv.text)
        check("and a row in it", "Hostinger" in csv.text)
        check("it says which rows were converted", "converted" in csv.text)

        r = c.post("/spend/currency",
                   data={"display": "AED", "code": "KES", "rate": "129.5"},
                   follow_redirects=False)
        check("currency saves", r.status_code == 303)
        check("the display currency changed", spend.base_currency() == "AED")
        check("and the rate is kept", spend.rates()["KES"]["rate"] == 129.5)
        spend.set_base_currency("USD")

    # Kept last: it clears the register to work on known data, so it must not
    # run before the sections that expect rows to exist.
    print("the forecast says when money leaves, not the average")
    spend.set_display_currency("USD")
    check("31 January plus a month clamps to February",
          spend._add_months(dt.date(2027, 1, 31), 1) == dt.date(2027, 2, 28))
    check("and in a leap year to the 29th",
          spend._add_months(dt.date(2028, 1, 31), 1) == dt.date(2028, 2, 29))
    check("December plus one rolls the year",
          spend._add_months(dt.date(2026, 12, 15), 1) == dt.date(2027, 1, 15))

    for r in spend.search(status=""):
        spend.delete(r["id"])
    today = dt.date.today()
    this_month = dt.date(today.year, today.month, 1).isoformat()

    # a yearly licence is not a twelfth of itself every month
    spend.create({"name": "yearly thing", "cost": "1200", "cycle": "yearly",
                  "currency": "USD", "renews": in_days(40)}, "t")
    f = spend.forecast(12)
    hit = [b for b in f["months"] if b["amount"]]
    check(f"a yearly bill lands in exactly one month, got {len(hit)}",
          len(hit) == 1)
    check("for its whole amount", bool(hit) and hit[0]["amount"] == 1200.0)
    check("and the row is named for the tooltip",
          bool(hit) and hit[0]["rows"][0]["name"] == "yearly thing")
    check("twelve buckets regardless", len(f["months"]) == 12)
    check("the first bucket is this month",
          f["months"][0]["ym"] == today.strftime("%Y-%m"))
    running = 1200.0

    # dated to the 1st of this month, so every bucket in the window contains it
    spend.create({"name": "monthly thing", "cost": "100", "cycle": "monthly",
                  "currency": "USD", "renews": this_month}, "t")
    f = spend.forecast(12)
    got = len([b for b in f["months"] if b["amount"] >= 100])
    check(f"a monthly bill lands in all twelve, got {got}", got == 12)
    running += 1200.0
    check(f"the window totals {running}, got {f['total']}",
          abs(f["total"] - running) < 0.01)

    # a lapsed recurring row still has a next date — it must not vanish
    spend.create({"name": "lapsed yearly", "cost": "600", "cycle": "yearly",
                  "currency": "USD", "renews": in_days(-20)}, "t")
    f = spend.forecast(12)
    check("a lapsed recurring row is rolled forward, not dropped",
          any(any(x["name"] == "lapsed yearly" for x in b["rows"])
              for b in f["months"]))
    check("exactly once", sum(1 for b in f["months"] for x in b["rows"]
                              if x["name"] == "lapsed yearly") == 1)
    running += 600.0

    # a one-off already paid must not reappear as a future charge
    spend.create({"name": "old laptop", "cost": "2000", "cycle": "one-off",
                  "currency": "USD", "renews": in_days(-60)}, "t")
    f = spend.forecast(12)
    check("a past one-off is not projected",
          not any(any(x["name"] == "old laptop" for x in b["rows"])
                  for b in f["months"]))
    check(f"so the total is unchanged at {running}, got {f['total']}",
          abs(f["total"] - running) < 0.01)

    spend.create({"name": "new laptop", "cost": "2000", "cycle": "one-off",
                  "currency": "USD", "renews": in_days(45)}, "t")
    f = spend.forecast(12)
    check("a future one-off lands exactly once",
          sum(1 for b in f["months"]
              for x in b["rows"] if x["name"] == "new laptop") == 1)
    running += 2000.0

    # a metered row has no amount to project, and is named rather than dropped
    spend.create({"name": "metered egress", "cost": "500", "cycle": "metered",
                  "currency": "USD", "renews": in_days(15)}, "t")
    f = spend.forecast(12)
    check("a metered row is reported apart",
          [r["name"] for r in f["unknown"]] == ["metered egress"])
    check(f"and adds nothing, still {running}, got {f['total']}",
          abs(f["total"] - running) < 0.01)

    spend.create({"name": "undated", "cost": "9", "cycle": "yearly",
                  "currency": "USD"}, "t")
    check("a row with no date cannot be projected",
          abs(spend.forecast(12)["total"] - running) < 0.01)
    f = spend.forecast(12)
    check("the peak month is identified", f["peak"]["amount"] == f["max"])

    spend.set_display_currency("AED")
    check(f"the forecast follows the display currency, got "
          f"{spend.forecast(12)['total']}",
          abs(spend.forecast(12)["total"] - running * 3.6725) < 0.01)
    spend.set_display_currency("USD")
    check("a one-month window is allowed", len(spend.forecast(1)["months"]) == 1)
    check("and a nonsense window still yields one",
          len(spend.forecast(0)["months"]) == 1)

    print("cloud accounts read themselves in")
    from app import cloud, store
    spend.set_display_currency("USD")
    for r in spend.search(status=""):
        spend.delete(r["id"])

    # cloud connections hang off a project; "" is the global scope
    store.add_cloud("", {"type": "alibaba", "name": "Alibaba production",
                         "key_id": "k1", "secret": "s1",
                         "region": "me-central-1"})
    conn = [c for c in store.all_cloud() if c["name"] == "Alibaba production"][0]

    served = {"months": [{"cycle": "2026-05", "total": 500.0, "rows": []},
                         {"cycle": "2026-06", "total": 600.0, "rows": []},
                         {"cycle": "2026-07", "total": 683.20, "rows": []}],
              "currency": "USD", "notes": []}
    real_bills = cloud.bills
    cloud.bills = lambda c, months=12, refresh=False: served

    rep = spend.sync_clouds()
    linked = [r for r in spend.search(status="") if r.get("source")]
    check(f"one row is created, got {len(linked)}", len(linked) == 1)
    row = linked[0] if linked else {}
    check(f"at the last full month's figure, got {row.get('cost')}",
          row.get("cost") == 683.20)
    check("as a monthly consumption row",
          row.get("cycle") == "monthly" and row.get("kind") == "consumption")
    check("in the provider's currency", row.get("currency") == "USD")
    check("filed under cloud accounts", row.get("category") == "cloud")
    check("marked with where it came from",
          row.get("source") == f"cloud:{conn['id']}")
    check(f"and which bill, got {row.get('source_note')!r}",
          "2026-07" in (row.get("source_note") or ""))
    check("with the month-on-month move",
          "up" in (row.get("source_note") or ""))
    check("it counts as one account", rep["accounts"] == 1)
    # people name accounts after the provider, so prefixing it again gave
    # "Alibaba Cloud — Alibaba production"
    check(f"the name is not doubled, got {row.get('name')!r}",
          row.get("name") == "Alibaba production")
    check("but an account named without its provider gets one",
          (store.add_cloud("", {"type": "aws", "name": "shared services",
                                "key_id": "k9", "secret": "s9"}),
           spend.sync_clouds(),
           any(r["name"] == "AWS — shared services"
               for r in spend.search(status="")))[2])
    for extra in [r for r in spend.search(status="")
                  if r["name"] == "AWS — shared services"]:
        spend.delete(extra["id"])
    for c9 in [c for c in store.all_cloud() if c["name"] == "shared services"]:
        store.delete_cloud(c9.get("pid", ""), c9["id"])

    print("the month in progress is never the run rate")
    # A provider bills as it goes, so the current cycle holds however many
    # hours of the month have happened. Reading it made a USD 700 account
    # report USD 15 on the first of August, while the Clouds pages — which
    # show every month — were right the whole time.
    now = dt.date.today()
    this_cycle = f"{now.year:04d}-{now.month:02d}"
    last = (dt.date(now.year, now.month, 1) - dt.timedelta(days=1))
    last_cycle = f"{last.year:04d}-{last.month:02d}"
    before = (dt.date(last.year, last.month, 1) - dt.timedelta(days=1))
    before_cycle = f"{before.year:04d}-{before.month:02d}"

    served = {"months": [{"cycle": before_cycle, "total": 672.59, "rows": []},
                         {"cycle": last_cycle, "total": 707.28, "rows": []},
                         {"cycle": this_cycle, "total": 16.36, "rows": []}],
              "currency": "USD", "notes": []}
    spend.sync_clouds()
    row = [r for r in spend.search(status="") if r.get("source")][0]
    check(f"the finished month is used, got {row.get('cost')}",
          row.get("cost") == 707.28)
    note = row.get("source_note") or ""
    check(f"and it says so, got {note!r}", "last full month" in note)
    check("month-to-date is still shown, as context",
          f"{this_cycle} so far" in note and "16.36" in note)

    # a brand new account has no finished month at all — use what there is and
    # label it, rather than reporting the account as unreadable
    served = {"months": [{"cycle": this_cycle, "total": 16.36, "rows": []}],
              "currency": "USD", "notes": []}
    spend.sync_clouds()
    row = [r for r in spend.search(status="") if r.get("source")][0]
    check(f"a new account still gets a row, got {row.get('cost')}",
          row.get("cost") == 16.36)
    check(f"marked as incomplete, got {row.get('source_note')!r}",
          "no completed month yet" in (row.get("source_note") or ""))

    print("an account that costs nothing says so rather than vanishing")
    served = {"months": [{"cycle": before_cycle, "total": 0.0, "rows": []},
                         {"cycle": last_cycle, "total": 0.0, "rows": []}],
              "currency": "USD", "notes": []}
    rep = spend.sync_clouds()
    linked = [r for r in spend.search(status="") if r.get("source")]
    check(f"the row is still there, got {len(linked)}", len(linked) == 1)
    check(f"at zero, got {linked and linked[0].get('cost')}",
          linked and linked[0].get("cost") == 0.0)
    check("and not counted as a failure", not rep["failed"])
    check(f"saying why, got {linked[0].get('source_note')!r}",
          "no spend" in (linked[0].get("source_note") or ""))

    # but a bill that could not be read leaves the last figure alone
    served = {"months": [], "currency": "", "notes": ["the key cannot see billing"]}
    rep = spend.sync_clouds()
    linked = [r for r in spend.search(status="") if r.get("source")]
    check("an unreadable bill is a failure", len(rep["failed"]) == 1)
    check("and the last known figure is kept",
          linked and linked[0].get("cost") == 0.0)

    served = {"months": [{"cycle": before_cycle, "total": 600.0, "rows": []},
                         {"cycle": last_cycle, "total": 683.20, "rows": []}],
              "currency": "USD", "notes": []}
    spend.sync_clouds()

    # running it again must update, never duplicate
    spend.sync_clouds()
    check("a second run does not duplicate",
          len([r for r in spend.search(status="") if r.get("source")]) == 1)
    check("and reports it unchanged",
          len(spend.sync_clouds()["unchanged"]) == 1)

    # when the bill for the last full month changes, so does the cost. Written
    # against the months relative to today rather than fixed ones: this used to
    # append "2026-08", which was a finished month when it was written and the
    # month in progress by the time anybody ran it in August.
    served = {**served, "months": [{"cycle": before_cycle, "total": 683.20,
                                    "rows": []},
                                   {"cycle": last_cycle, "total": 910.0,
                                    "rows": []}]}
    rep = spend.sync_clouds()
    row = [r for r in spend.search(status="") if r.get("source")][0]
    check(f"a new figure moves the cost, got {row['cost']}", row["cost"] == 910.0)
    check("and it is reported as updated", len(rep["updated"]) == 1)
    check("with what it was before", rep["updated"][0]["was"] == 683.20)

    # what a person set on the row must survive the refresh
    spend.update(row["id"], {**row, "owner": "DevOps", "project": "acme",
                             "notes": "charged to the platform budget",
                             "status": "active"}, "human")
    spend.sync_clouds()
    row = [r for r in spend.search(status="") if r.get("source")][0]
    check("the owner survives a refresh", row["owner"] == "DevOps")
    check("so does the project", row["project"] == "acme")
    check("and the note", "platform budget" in (row["notes"] or ""))

    # editing through the form, which carries no source fields at all: a plain
    # save must not sever the link, or the next sync adds a second row alongside
    form_post = {"name": row["name"], "vendor": row["vendor"],
                 "category": "cloud", "kind": "consumption",
                 "cost": str(row["cost"]), "currency": row["currency"],
                 "cycle": "monthly", "renews": row["renews"],
                 "owner": "Platform", "status": "active"}
    rid = row["id"]
    spend.update(rid, form_post, "human")
    saved = spend.get(rid) or {}
    check("a form save keeps the link",
          (saved.get("source") or "").startswith("cloud:"))
    check("and keeps which bill it came from", bool(saved.get("source_note")))
    spend.sync_clouds()
    linked_now = [r for r in spend.search(status="") if r.get("source")]
    check(f"so the next read still finds one row, not two, got {len(linked_now)}",
          len(linked_now) == 1)
    check(f"and the whole register has no duplicate, got "
          f"{len(spend.search(status=''))}", len(spend.search(status="")) == 1)
    row = linked_now[0] if linked_now else saved

    # a cancelled account stays cancelled: the sync owns money, not intent
    spend.update(row["id"], {**row, "status": "cancelled"}, "human")
    spend.sync_clouds()
    row = [r for r in spend.search(status="") if r.get("source")][0]
    check("a cancelled linked row is not resurrected", row["status"] == "cancelled")
    spend.update(row["id"], {**row, "status": "active"}, "human")

    # the important one: a failed read must never look like a month of zero
    before = [r for r in spend.search(status="") if r.get("source")][0]["cost"]
    def boom(c, months=12, refresh=False):
        raise RuntimeError("connection refused")
    cloud.bills = boom
    rep = spend.sync_clouds()
    after = [r for r in spend.search(status="") if r.get("source")][0]["cost"]
    check(f"a raising provider leaves the figure alone, {before} -> {after}",
          after == before)
    check("and is reported as failed", len(rep["failed"]) == 1)
    check("saying the old figure was kept", rep["failed"][0]["kept"] is True)
    check("and why", "refused" in rep["failed"][0]["why"])

    cloud.bills = lambda c, months=12, refresh=False: {
        "months": [], "currency": "USD", "notes": ["no permission to read bills"]}
    rep = spend.sync_clouds()
    after = [r for r in spend.search(status="") if r.get("source")][0]["cost"]
    check("an empty bill also leaves it alone", after == before)
    check("and passes the provider's reason on",
          "permission" in rep["failed"][0]["why"])

    # A bill that answers with zero is an answer, not a failure — and this used
    # to say the opposite. Treating all-zero as unreadable meant a connected
    # account with nothing charged to it was reported as broken and never got a
    # row at all, so it was missing from the register entirely. Both providers
    # report an unreadable bill as no months plus a reason (checked above), so
    # the two cases are distinguishable and zero can be taken at face value.
    cloud.bills = lambda c, months=12, refresh=False: {
        "months": [{"cycle": before_cycle, "total": 0.0, "rows": []},
                   {"cycle": last_cycle, "total": 0.0, "rows": []}],
        "currency": "USD", "notes": []}
    rep = spend.sync_clouds()
    zeroed = [r for r in spend.search(status="") if r.get("source")][0]
    check("a bill of nothing is recorded as zero, not as a failure",
          not rep["failed"] and zeroed["cost"] == 0.0)
    check(f"and says why, got {zeroed['source_note']!r}",
          "no spend" in (zeroed["source_note"] or ""))

    print("what was actually spent, month by month")
    # The forecast is a flat line for a register of monthly commitments — that
    # is what committed means — so the variation has to come from the bills.
    hist = [{"cycle": before_cycle, "total": 600.0, "rows": []},
            {"cycle": last_cycle, "total": 707.28, "rows": []},
            {"cycle": this_cycle, "total": 16.36, "rows": []}]
    cloud.bills = lambda c, months=12, refresh=False: {
        "months": hist, "currency": "USD", "notes": []}
    real_peek = cloud.bills_peek
    cloud.bills_peek = lambda c, months=12: {"months": hist, "currency": "USD",
                                             "notes": []}
    spend.set_display_currency("USD")
    a = spend.actuals(12)
    got = {m["ym"]: round(m["amount"], 2) for m in a["months"] if m["amount"]}
    check(f"each month carries its own figure, got {got}",
          got.get(last_cycle) == 707.28 and got.get(before_cycle) == 600.0)
    check("the month in progress is marked as such",
          a["running"] and a["running"]["ym"] == this_cycle)
    check(f"and left out of the average, got {round(a['average'], 2)}",
          abs(a["average"] - 653.64) < 0.01)
    check(f"the last full month is the last full one, got {a['last']['ym']}",
          a["last"]["ym"] == last_cycle)
    check("with the move on the month before",
          round(a["move"]) == 18)
    check("the peak is named", a["peak"] and a["peak"]["ym"] == last_cycle)
    check("and the split by account is there",
          a["months"][-1]["rows"] and "name" in a["months"][-1]["rows"][0])

    # a month before the account existed must not drag the typical month down
    hist2 = [{"cycle": before_cycle, "total": 0.0, "rows": []},
             {"cycle": last_cycle, "total": 800.0, "rows": []}]
    cloud.bills_peek = lambda c, months=12: {"months": hist2, "currency": "USD",
                                             "notes": []}
    a = spend.actuals(12)
    check(f"months with nothing in them are not averaged in, got "
          f"{round(a['average'], 2)}", a["average"] == 800.0)
    check("and only the months with spend are counted", a["counted"] == 1)

    # a provider whose bills have not been read yet says so
    cloud.bills_peek = lambda c, months=12: None
    a = spend.actuals(12)
    check("an unread account is reported as pending, not as zero",
          a["pending"] == a["accounts"] and a["accounts"] > 0)
    check("and nothing is invented", a["max"] == 0)
    cloud.bills_peek = real_peek

    print("a month on the chart filters the register")
    cloud.bills = lambda c, months=12, refresh=False: {
        "months": [{"cycle": before_cycle, "total": 600.0, "rows": []},
                   {"cycle": last_cycle, "total": 683.20, "rows": []}],
        "currency": "USD", "notes": []}
    spend.sync_clouds()
    fcast = spend.forecast(12)
    with_money = next((m for m in fcast["months"] if m["amount"]), None)
    check("the forecast has a month with something in it", with_money)

    from fastapi.testclient import TestClient as _TC
    from app import auth as _auth, db as _db, main as _main
    _mail, _pw = "spendmonth@test.local", "Subs-Add-Up-42"
    _uid = (_auth.by_email(_mail) or {}).get("id") or \
        _auth.create_user(_mail, "CI", _pw, role="admin")
    _db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
            ("TESTSECRET", _uid))
    client = _TC(_main.app)
    client.post("/login", data={"email": _mail, "password": _pw},
                follow_redirects=False)
    client.post("/mfa", data={"code": _auth._totp_at(
        "TESTSECRET", int(time.time() // _auth.TOTP_STEP))},
        follow_redirects=False)

    # The register and its filters live at /spend/manage; /spend itself is the
    # calendar and nothing else. Checked separately below, because "the page
    # people open" and "the page rows are edited on" are now two questions.
    r = client.get(f"/spend/manage?month={with_money['ym']}")
    check(f"the month filter renders, got {r.status_code}", r.status_code == 200)
    check("and says what it is narrowed to",
          "falling due in" in r.text and with_money["label"] in r.text)
    check("with a way to clear it", ">clear</a>" in r.text)
    empty = client.get("/spend/manage?month=1999-01")
    check("a month with nothing in it narrows to nothing, rather than to all",
          "data-rid=" not in empty.text)
    check("and the table says the filter is why it is empty",
          "matches the filter" in empty.text)
    check("the register comes up as a table per billing cycle",
          all(f'data-tab="{k}"' in r.text
              for k in ("all", "one-off", "monthly", "yearly")))
    # A row is read, not filled in: the grid of inputs squeezed the name — the
    # column people actually read — down to nothing, and every row carried its
    # own Save. Clicking a row opens the same dialog it was added in, so one
    # place knows what a valid expense looks like.
    check("a row opens the editor rather than being an input grid",
          "editSub(" in r.text and 'class="cel ' not in r.text)
    check("and there is exactly one form that writes an expense",
          r.text.count('action="/spend/save"') == 1)
    check("and the detail table has the same tabs as the register",
          all(f'>{lab}' in r.text or lab in r.text
              for _k, lab in spend.BUCKETS if _k != "metered"))

    # ── the calendar, which is all /spend is now ──────────────────────────
    cal = client.get("/spend")
    check(f"the calendar renders, got {cal.status_code}", cal.status_code == 200)
    # A month box opens that month's own page. It used to open a table further
    # down the same page, which is why this page carried seven things.
    check("every month box that has happened links to its own month page",
          cal.text.count("/spend/month?ym=") >= 7)
    check("and the register is not on it — it moved",
          "data-rid=" not in cal.text and "regtable" not in cal.text)
    # …but the editor is, because adding an expense from the calendar must not
    # mean a trip to a page you did not ask for and then a trip back.
    check("while the editor itself is on it", 'id="addSub"' in cal.text)
    check("but there is a way to reach it", "/spend/manage" in cal.text)

    # A month that money actually LEFT in, which is not the same as a month the
    # forecast names: the forecast is when the next payment falls due, and a
    # future month has no lines to break down.
    # A row of our own, charged in a month that has been and gone, so the page
    # under test has something to break down. The cloud stub above feeds the
    # forecast rather than month_detail, which reads the providers' cached
    # bills — a fixture detail that is not what this check is about.
    spend.create({"name": "Breakdown probe", "vendor": "Probe Ltd",
                  "category": "hosting", "cost": "120", "currency": "USD",
                  "cycle": "monthly", "renews": f"{last_cycle}-15"})
    spent = spend.month_detail(last_cycle)
    check(f"the month has lines to break down ({len(spent['lines'])})",
          bool(spent["lines"]))
    # ── one level out: every year, and the lot together ──────────────────
    allv = client.get("/spend?year=all")
    check(f"the all-years view renders, got {allv.status_code}",
          allv.status_code == 200)
    yv = spend.years_view()
    check(f"every year with anything in it gets a box ({yv['years']})",
          all(str(y) in allv.text for y in yv["years"]))
    # The grand total has to BE the years added up. Holding it separately is
    # how a summary comes to disagree with the thing it summarises.
    check(f"and the total is the years added up ({yv['total']:.2f})",
          abs(yv["total"] - sum(b["total"] for b in yv["boxes"])) < 0.01)
    check("a year box opens that year's months",
          f'/spend?year={yv["years"][0]}' in allv.text)

    one = client.get(f"/spend/month?ym={last_cycle}")
    check(f"a month page renders, got {one.status_code}", one.status_code == 200)
    check("with the month named on it", spent["label"] in one.text)
    # The breakdowns are what the page was rebuilt for; a month page that is
    # only a table is the table that was already there.
    check("and a split by category", "Where it went" in one.text)
    check("and a split by kind", "split by kind" in one.text)
    check("and a comparison with the month before it", "vs " in one.text)

    cloud.bills = real_bills
    check("the sync stamps when it ran", bool(spend.cloud_synced_at()))
    check("and the age reads as fresh",
          (spend.cloud_sync_age() or 99) < 1)
    print("the register, split by how often the money leaves")
    # The tabs exist so two different kinds of number are never added: a
    # subscription has a run rate, a thing bought once has an amount that was
    # charged and will not be charged again.
    for r in spend.search(status=""):
        spend.delete(r["id"])
    add(name="a monthly thing", cost="100", cycle="monthly", renews=in_days(5))
    add(name="a yearly thing", cost="1200", cycle="yearly", renews=in_days(200))
    add(name="a laptop", cost="2000", cycle="one-off", renews=in_days(-40))
    add(name="a desk", cost="500", cycle="one-off", renews=in_days(-10))
    add(name="something quarterly", cost="300", cycle="quarterly",
        renews=in_days(20))
    add(name="billed in guilders", cost="99", currency="ZZZ", cycle="monthly",
        renews=in_days(9))
    g = {x["key"]: x for x in spend.cycle_groups(spend.search(status=""))}
    check(f"the one-off table totals what was charged, got {g['one-off']['charged']}",
          g["one-off"]["charged"] == 2500.0)
    check("and reports no run rate, because a purchase has none",
          g["one-off"]["monthly"] == 0.0 and g["one-off"]["n_recurring"] == 0)
    check(f"the monthly table is a per-month figure, got {g['monthly']['monthly']}",
          g["monthly"]["monthly"] == 100.0)
    check(f"annualised on the same row, got {g['monthly']['yearly']}",
          g["monthly"]["yearly"] == 1200.0)
    check(f"the yearly table reads per year, got {g['yearly']['yearly']}",
          g["yearly"]["yearly"] == 1200.0)
    check(f"and per month beside it, got {g['yearly']['monthly']}",
          g["yearly"]["monthly"] == 100.0)
    check("quarterly and the rest land in their own table, not in the main three",
          [r["name"] for r in g["other"]["rows"]] == ["something quarterly"])
    # the whole point: Everything carries both totals and merges neither
    check(f"Everything keeps the run rate apart, got {g['all']['monthly']}",
          g["all"]["monthly"] == 300.0)      # 100 monthly + 1200/12 + 300/3
    check(f"and the money spent once apart, got {g['all']['charged']}",
          g["all"]["charged"] == 2500.0)
    check("a currency with no rate is in neither total",
          g["all"]["unconverted"] == ["ZZZ"])
    check("the chip on the one-off tab is what was charged",
          (g["one-off"]["headline"], g["one-off"]["unit"]) == (2500.0, "charged"))
    check("and the yearly chip is a yearly figure",
          (g["yearly"]["headline"], g["yearly"]["unit"]) == (1200.0, "a year"))
    check("the rare cycles tab stays hidden until it has something in it",
          g["other"]["always"] is False and g["all"]["always"] is True)
    print("  a run rate and a one-off purchase are never added together")

    print("editing one cell does not blank the others")
    # The table posts only the cells somebody touched. Routed through update(),
    # which writes every column it is handed, that would wipe the notes and the
    # project each time a price was corrected.
    rid = add(name="M365", vendor="Microsoft", cost="100", cycle="monthly",
              owner="ammar", project="LMS", notes="renewal quote attached",
              seats="11", renews=in_days(30))
    spend.update_fields(rid, {"cost": "125.50"}, "tester")
    got = spend.get(rid)
    check(f"the price is written, got {got['cost']}", got["cost"] == 125.50)
    check("the owner survives", got["owner"] == "ammar")
    check("the project survives", got["project"] == "LMS")
    check("the notes survive", got["notes"] == "renewal quote attached")
    check("the seats survive", got["seats"] == 11)
    # auto_renew is stored 1/0 and read back as a checkbox: str(0) is "0",
    # a non-empty string, so a careless round trip switches it on for every row
    off = add(name="no auto", cost="10", cycle="monthly", renews=in_days(30))
    spend.update_fields(off, {"cost": "11"}, "tester")
    check("auto-renew stays off rather than being switched on by a round trip",
          not spend.get(off)["auto_renew"])
    on = add(name="has auto", cost="10", cycle="monthly", auto_renew="on",
             renews=in_days(30))
    spend.update_fields(on, {"cost": "11"}, "tester")
    check("and stays on when it was on", bool(spend.get(on)["auto_renew"]))
    check("an edit to a row that is gone is refused, not silently ignored",
          _raises(lambda: spend.update_fields("sub-nope", {"cost": "1"})))
    print("  a cell edit writes the cell and nothing else")

    print("one month, in detail")
    # The page that answers "what did we spend last month". Three things have
    # to hold: a cloud account is one line for the month rather than forty
    # product lines burying the invoices beside it; a credit note comes off the
    # total instead of being clamped to zero; and a line in a currency with no
    # rate is named rather than dropped, which made the month read low with
    # nothing on the page to say why.
    for r in spend.search(status=""):
        spend.delete(r["id"])
    cloud.bills_peek = lambda c, months=12: {
        "currency": "USD", "notes": [], "months": [
            {"cycle": last_cycle, "total": 707.28, "rows": [
                {"product": "ApsaraDB RDS", "amount": 400.0},
                {"product": "Elastic Compute Service", "amount": 307.28}]}]}
    ly, lm = (int(x) for x in last_cycle.split("-"))
    mid = f"{ly:04d}-{lm:02d}-15"
    add(name="M365 invoice", cost="1000", cycle="one-off", renews=mid)
    add(name="M365 credit note", cost="-250", cycle="one-off", renews=mid)
    add(name="Hostinger", cost="106.12", currency="AUD", cycle="one-off",
        renews=mid)
    d = spend.month_detail(last_cycle)
    names = [r["what"] for r in d["lines"]]
    metered = [r for r in d["lines"] if r["kind"] == "metered"]
    check(f"the cloud account is one line, not one per product, got {names}",
          len(metered) == 1)
    check(f"carrying the account's whole month, got {metered and metered[0]['amount']}",
          metered and round(metered[0]["amount"], 2) == 707.28)
    check("and saying how many charges are behind it",
          metered and "2 charges" in metered[0]["note"])
    check(f"a credit note comes off the total, got {round(d['total'], 2)}",
          round(d["total"], 2) == 1457.28)          # 707.28 + 1000 − 250
    check(f"a line with no rate is named, got {d['unconverted']}",
          [r["currency"] for r in d["stranded"]] == ["AUD"])
    check("rather than silently left out of the month",
          not any("Hostinger" in n for n in names))
    print("  a month reads as one line per thing charged, and says what it "
          "could not add")

    cloud.bills_peek = real_peek
    for r in spend.search(status=""):
        spend.delete(r["id"])
    store.delete_cloud(conn.get("pid", ""), conn["id"])

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
