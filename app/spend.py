"""Subscriptions, licence keys we pay for, and what they cost.

WHAT THIS IS FOR
    Server Assets answers "what hardware do we own". This answers the question
    that arrives at budget time: what are we paying for, to whom, how often, and
    what lapses next month. Microsoft 365, a cloud account, hosting, a domain, a
    single WordPress plugin — anything with a renewal date and a price.

WHY THE MONEY IS NORMALISED
    A quarterly bill and a yearly one cannot be added together, and a monthly
    total assembled by hand is wrong within a month. Every row is reduced to a
    cost per month and a cost per year from its own cycle, so the totals are
    derived rather than maintained.

WHY CONVERSION IS EXPLICIT AND HONEST
    Rows arrive in whatever currency the vendor bills in. Adding AED to USD
    needs a rate, and a rate nobody set is a wrong number wearing a confident
    face. Rates are entered by hand and stored; anything with no rate is
    reported separately as unconverted rather than quietly folded in at 1.0.

WHY A ONE-OFF IS NOT A LAPSED SUBSCRIPTION
    The register holds two kinds of thing: commitments that recur, and charges
    that happened once. They share a date column, so the cycle decides how the
    date reads. A subscription renews and can lapse. An invoice falls due, is
    charged, and is then simply history — counting it as lapsed put nine paid
    invoices in the column of things needing attention.

WHAT IT DELIBERATELY DOES NOT HOLD
    No card numbers, no vendor passwords, no API tokens. The account field is
    for "which tenant is this under", not for how to log in. Connected cloud
    accounts report their real bills here as one line per account per month;
    what that bill was spent on stays on the provider's own page.
"""
from __future__ import annotations

import datetime as dt
import json
import secrets
import sqlite3

from . import db

# ── the shape of a row ─────────────────────────────────────────────────────
COLUMNS = [
    ("name", "TEXT NOT NULL"),      # "Microsoft 365 Business Standard"
    ("vendor", "TEXT"),             # "Microsoft"
    ("category", "TEXT"),           # one of CATEGORIES
    ("kind", "TEXT"),               # subscription | perpetual | consumption
    ("seats", "INTEGER"),           # how many licences this row covers
    ("cost", "REAL"),               # per cycle, in currency
    ("currency", "TEXT"),
    ("cycle", "TEXT"),              # one of CYCLES
    ("started", "TEXT"),
    ("renews", "TEXT"),             # next renewal, or the expiry of a perpetual
    ("auto_renew", "INTEGER"),
    ("owner", "TEXT"),              # who inside the company owns it
    ("account", "TEXT"),            # which tenant/account it sits under
    ("project", "TEXT"),            # optional: which project it serves
    ("url", "TEXT"),                # the vendor console, for going to source
    ("notes", "TEXT"),
    ("status", "TEXT"),             # active | cancelled | ended
    # "" for a row somebody typed; "cloud:<connection id>" for one read from a
    # provider's own bill. The sync owns the money on those rows and nothing
    # else, so an owner or a note added by hand survives every refresh.
    ("source", "TEXT"),
    ("source_at", "TEXT"),          # when it was last read
    ("source_note", "TEXT"),        # which bill it came from, in words
]

CATEGORIES = {
    "saas": "SaaS and software",
    "cloud": "Cloud accounts",
    "hosting": "Hosting and servers",
    "domain": "Domains",
    "certificate": "Certificates",
    "plugin": "Plugins and themes",
    "security": "Security and compliance",
    "support": "Support contracts",
    "other": "Other",
}

KINDS = {
    "subscription": "Subscription — recurring until cancelled",
    "perpetual": "Perpetual licence — owned, may still expire for support",
    "consumption": "Pay as you go — the amount here is an estimate",
}

# months per cycle. None means it does not recur, so it is excluded from the
# run-rate: a one-off purchase in the monthly total would overstate it forever.
CYCLES = {
    "monthly": ("Monthly", 1),
    "quarterly": ("Quarterly", 3),
    "yearly": ("Yearly", 12),
    "biennial": ("Every two years", 24),
    "one-off": ("One-off", None),
    "metered": ("Metered / variable", None),
}

STATUSES = ("active", "cancelled", "ended")
SOON_DAYS = 30

# How much cloud history to ask a provider for. One number, because bills_peek
# caches per (account, months): asking for 24 here and 12 there is not two
# views of one answer, it is two separate collections and two caches — and the
# one that has not been filled yet returns nothing at all, which is how the
# year grid came to report every month's metered spend as zero.
BILL_MONTHS = 24


def _migrate(c: sqlite3.Connection) -> None:
    """Create the table, then add any column this version knows about.

    Additive only, like the assets table: an older database opened by a newer
    portal gains columns and never loses rows.
    """
    cols = ", ".join(f"{n} {t}" for n, t in COLUMNS)
    c.execute(f"""CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY, {cols},
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    have = {r["name"] for r in c.execute("PRAGMA table_info(subscriptions)")}
    for name, decl in COLUMNS:
        if name not in have:
            c.execute(f"ALTER TABLE subscriptions ADD COLUMN {name} "
                      f"{decl.replace(' NOT NULL', '')}")
    for col in ("vendor", "category", "renews", "status"):
        c.execute(f"CREATE INDEX IF NOT EXISTS idx_sub_{col} "
                  f"ON subscriptions({col})")
    # base currency and the hand-entered rates live here
    c.execute("""CREATE TABLE IF NOT EXISTS spend_meta (
        k TEXT PRIMARY KEY, v TEXT NOT NULL)""")


db.register(_migrate)


# ── settings: the base currency and the rates ──────────────────────────────
def _meta(key: str, default: str = "") -> str:
    row = db.one("SELECT v FROM spend_meta WHERE k = ?", (key,))
    return row["v"] if row else default


def _set_meta(key: str, value: str) -> None:
    db.run("""INSERT INTO spend_meta (k, v) VALUES (?, ?)
              ON CONFLICT(k) DO UPDATE SET v = excluded.v""", (key, value))


# Every rate is held as "units of this currency per 1 USD", because that is how
# the pegs below are officially quoted and a single pivot means one number per
# currency rather than a matrix that can disagree with itself.
PIVOT = "USD"

# Currencies formally pegged to the dollar by their central bank. These are
# published constants, not market guesses — the dirham has been 3.6725 since
# 1997 — so shipping them is stating a fact rather than inventing a rate. A
# manual rate always overrides one, in case a peg is ever moved.
PEGS = {
    "AED": 3.6725,      # United Arab Emirates
    "SAR": 3.7500,      # Saudi Arabia
    "QAR": 3.6400,      # Qatar
    "OMR": 0.384497,    # Oman
    "BHD": 0.376000,    # Bahrain
    "JOD": 0.709000,    # Jordan
}

# A hand-entered rate for a floating currency goes stale. After this many days
# the page says so rather than presenting an old number as current.
STALE_DAYS = 90


def display_currency() -> str:
    """The currency the page shows totals in. Any code, not just the pivot."""
    return (_meta("display", PIVOT) or PIVOT).upper()[:3]


def set_display_currency(code: str) -> None:
    code = _code(code)
    if code:
        _set_meta("display", code)


# kept as an alias: plenty of callers ask for "the currency the totals are in"
base_currency = display_currency
set_base_currency = set_display_currency


def _code(value) -> str:
    code = "".join(ch for ch in str(value or "").upper() if ch.isalpha())
    return code[:3] if len(code) >= 3 else ""


def _manual() -> dict:
    try:
        got = json.loads(_meta("fx") or "{}")
        return {k: v for k, v in got.items() if isinstance(v, dict)}
    except (json.JSONDecodeError, AttributeError):
        return {}


def rates() -> dict:
    """{code: {"rate": per 1 USD, "at": when set, "src": peg|manual}}.

    Pegs first, then anything entered by hand on top — so a manual rate wins if
    a peg is ever revalued, and nobody has to type the ones that are constants.
    """
    out = {PIVOT: {"rate": 1.0, "at": "", "src": "pivot"}}
    for code, rate in PEGS.items():
        out[code] = {"rate": rate, "at": "", "src": "peg"}
    for code, spec in _manual().items():
        try:
            rate = float(spec.get("rate"))
        except (TypeError, ValueError):
            continue
        if rate > 0:
            out[_code(code) or code] = {"rate": rate,
                                        "at": str(spec.get("at") or ""),
                                        "src": "manual"}
    return out


def set_rate(code: str, per_usd, when: str = "") -> bool:
    """Store "1 USD = <per_usd> <code>". A rate of zero forgets it."""
    code = _code(code)
    if not code or code == PIVOT:
        return False
    try:
        rate = float(str(per_usd).replace(",", "").strip())
    except (TypeError, ValueError):
        return False
    have = _manual()
    if rate <= 0:
        have.pop(code, None)
    else:
        have[code] = {"rate": rate,
                      "at": _iso_date(when) or dt.date.today().isoformat()}
    _set_meta("fx", json.dumps(have, sort_keys=True))
    return True


def convert(amount, frm: str, to: str = "") -> tuple[float, bool]:
    """Any currency to any other. (value, whether both rates were known).

    Goes through the pivot rather than storing pairs: with one number per
    currency, AED→SAR cannot contradict SAR→AED.
    """
    try:
        amount = float(amount or 0)
    except (TypeError, ValueError):
        return 0.0, False
    frm = _code(frm) or display_currency()
    to = _code(to) or display_currency()
    if frm == to:
        return amount, True
    known = rates()
    a, b = known.get(frm), known.get(to)
    if not a or not b:
        # Returned unchanged and flagged, so a caller reports it apart instead of
        # adding a number it made up.
        return amount, False
    return amount / a["rate"] * b["rate"], True


def rate_rows() -> list:
    """Every rate the install knows, for the page: source and how old it is."""
    today = dt.date.today()
    out = []
    for code, spec in sorted(rates().items()):
        if code == PIVOT:
            continue
        age = None
        if spec["at"]:
            try:
                age = (today - dt.date.fromisoformat(spec["at"])).days
            except ValueError:
                age = None
        out.append({
            "code": code, "rate": spec["rate"], "src": spec["src"],
            "at": spec["at"], "age": age,
            # a peg cannot go stale; a typed number for a floating currency can
            "stale": spec["src"] == "manual" and age is not None
                     and age > STALE_DAYS,
            "inverse": round(1 / spec["rate"], 6) if spec["rate"] else 0,
        })
    return out


def currencies_in_use() -> list:
    """Codes that actually appear on rows, so the picker offers real choices."""
    seen = {display_currency(), PIVOT}
    seen |= {r["currency"] for r in db.q(
        "SELECT DISTINCT currency AS currency FROM subscriptions "
        "WHERE currency IS NOT NULL AND currency != ''") if r["currency"]}
    seen |= set(PEGS)
    seen |= set(_manual())
    return sorted(c for c in seen if c)


# ── rows ───────────────────────────────────────────────────────────────────
def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _iso_date(v) -> str:
    """Accept what people actually type; store one format or nothing."""
    s = str(v or "").strip()
    if not s:
        return ""
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y", "%d %B %Y",
                "%d %b %Y", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def _clean(form: dict) -> dict:
    out = {}
    for name, _decl in COLUMNS:
        raw = form.get(name)
        if name in ("started", "renews"):
            out[name] = _iso_date(raw)
        elif name == "seats":
            try:
                out[name] = max(0, int(str(raw or "0").strip() or 0))
            except ValueError:
                out[name] = 0
        elif name == "cost":
            # Negative is allowed, and has to be: a credit note is a real line
            # on a real invoice, and clamping it to zero made a refunded month
            # add up to more than was actually paid. A typo is visible in the
            # register; a silently discarded credit is not.
            try:
                out[name] = float(str(raw or "0").replace(",", "").strip() or 0)
            except ValueError:
                out[name] = 0.0
        elif name == "auto_renew":
            out[name] = 1 if str(raw or "").strip() else 0
        elif name == "currency":
            code = "".join(ch for ch in str(raw or "").upper() if ch.isalpha())
            out[name] = code[:3] or base_currency()
        elif name == "cycle":
            out[name] = raw if raw in CYCLES else "yearly"
        elif name == "category":
            out[name] = raw if raw in CATEGORIES else "other"
        elif name == "kind":
            out[name] = raw if raw in KINDS else "subscription"
        elif name == "status":
            out[name] = raw if raw in STATUSES else "active"
        else:
            out[name] = str(raw or "").strip()
    return out


def create(form: dict, actor: str = "") -> str:
    row = _clean(form)
    if not row["name"]:
        raise ValueError("a subscription needs a name")
    rid = f"sub-{secrets.token_hex(4)}"
    names = ", ".join(n for n, _ in COLUMNS)
    marks = ", ".join("?" for _ in COLUMNS)
    db.run(f"""INSERT INTO subscriptions (id, {names}, created, updated,
                                          created_by, updated_by)
               VALUES (?, {marks}, ?, ?, ?, ?)""",
           (rid, *[row[n] for n, _ in COLUMNS], _now(), _now(), actor, actor))
    return rid


def update(rid: str, form: dict, actor: str = "") -> None:
    row = _clean(form)
    if not row["name"]:
        raise ValueError("a subscription needs a name")
    # The edit form carries no source fields, so a plain save would blank them
    # and unlink the row from its cloud account — and the next sync, finding no
    # linked row, would add a second one alongside it. Provenance is only ever
    # written by the sync, so it is preserved here unless a caller passes it.
    if "source" not in form:
        was = db.one("SELECT source, source_at, source_note FROM subscriptions "
                     "WHERE id = ?", (rid,))
        if was:
            row["source"] = was["source"] or ""
            row["source_at"] = was["source_at"] or ""
            row["source_note"] = was["source_note"] or ""
    sets = ", ".join(f"{n} = ?" for n, _ in COLUMNS)
    db.run(f"UPDATE subscriptions SET {sets}, updated = ?, updated_by = ? "
           f"WHERE id = ?",
           (*[row[n] for n, _ in COLUMNS], _now(), actor, rid))


def update_fields(rid: str, form: dict, actor: str = "") -> None:
    """Write only the columns the form carries, and leave the rest alone.

    The table edits in place and posts the handful of cells somebody touched.
    Sending that through update(), which writes every column from the form it
    is handed, would blank the owner, the project and the notes each time a
    price was corrected — so the stored row is read first and the posted
    fields laid over it.
    """
    was = db.one("SELECT * FROM subscriptions WHERE id = ?", (rid,))
    if not was:
        raise ValueError("that record no longer exists")
    base = {n: was[n] for n, _ in COLUMNS}
    # provenance is the sync's to write, never an edit's
    editable = {n for n, _ in COLUMNS} - {"source", "source_at", "source_note"}
    for key, value in form.items():
        if key in editable:
            base[key] = value
    # auto_renew is stored as 1/0 and read back as a checkbox: str(0) is "0",
    # which is a non-empty string, so passing the stored zero through _clean
    # would switch auto-renew on for every row that had it off.
    base["auto_renew"] = "on" if base.get("auto_renew") else ""
    update(rid, base, actor)


def delete(rid: str) -> None:
    db.run("DELETE FROM subscriptions WHERE id = ?", (rid,))


def get(rid: str) -> dict | None:
    row = db.one("SELECT * FROM subscriptions WHERE id = ?", (rid,))
    return _row(row) if row else None


def _row(r) -> dict:
    d = dict(r)
    d["seats"] = d.get("seats") or 0
    d["cost"] = float(d.get("cost") or 0)
    d["currency"] = d.get("currency") or base_currency()
    d["cycle"] = d.get("cycle") if d.get("cycle") in CYCLES else "yearly"
    d["monthly"], d["yearly"] = run_rate(d["cost"], d["cycle"])
    shown = display_currency()
    d["base_monthly"], d["converted"] = convert(d["monthly"], d["currency"], shown)
    d["base_yearly"], _ = convert(d["yearly"], d["currency"], shown)
    d["shown_cost"], _ = convert(d["cost"], d["currency"], shown)
    d["shown_in"] = shown
    # a row already in the display currency needs no "(converted from …)" note
    d["native"] = d["currency"] == shown
    d["renewal"] = renewal_state(d.get("renews"), d.get("status"),
                                 d.get("cycle"))
    d["category_label"] = CATEGORIES.get(d.get("category"), "Other")
    d["cycle_label"] = CYCLES[d["cycle"]][0]
    return d


def run_rate(cost: float, cycle: str) -> tuple[float, float]:
    """(per month, per year). A non-recurring cycle contributes nothing."""
    months = CYCLES.get(cycle, ("", 12))[1]
    if not months:
        return 0.0, 0.0
    return cost / months, cost * (12 / months)


def renewal_state(when, status: str = "active", cycle: str = "") -> dict:
    """How close a renewal is, in words the page can colour by.

    A non-recurring row has no renewal to be late for. An invoice paid in
    December is not "expired 233 days ago" and does not belong in the lapsed
    count — it is a thing that happened, and the date is when it happened. So
    the cycle decides the vocabulary: a subscription renews, a one-off falls
    due and then is simply charged.

    The cycle is optional, and left out the wording is the recurring one — the
    default keeps every caller that only ever holds subscriptions correct.
    """
    if (status or "active") != "active":
        return {"state": "inactive", "days": None, "label": status or "inactive"}
    if not when:
        return {"state": "none", "days": None, "label": "no date set"}
    try:
        day = dt.date.fromisoformat(str(when))
    except ValueError:
        return {"state": "none", "days": None, "label": "no date set"}
    recurs = CYCLES.get(cycle, ("", 12))[1] is not None if cycle else True
    days = (day - dt.date.today()).days
    if days < 0:
        if not recurs:
            return {"state": "charged", "days": days,
                    "label": f"charged {day.isoformat()}"}
        return {"state": "expired", "days": days,
                "label": f"expired {abs(days)} day"
                         f"{'' if abs(days) == 1 else 's'} ago"}
    verb = "renews" if recurs else "due"
    if days <= SOON_DAYS:
        return {"state": "soon", "days": days,
                "label": f"{verb} in {days} day{'' if days == 1 else 's'}"}
    return {"state": "ok", "days": days, "label": f"{verb} {day.isoformat()}"}


# ── reading ────────────────────────────────────────────────────────────────
def search(q: str = "", category: str = "", vendor: str = "",
           status: str = "active", sort: str = "renews") -> list:
    where, args = [], []
    if status and status != "all":
        where.append("status = ?")
        args.append(status)
    if category:
        where.append("category = ?")
        args.append(category)
    if vendor:
        where.append("vendor = ?")
        args.append(vendor)
    if q:
        like = f"%{q.strip()}%"
        where.append("(name LIKE ? OR vendor LIKE ? OR account LIKE ? "
                     "OR owner LIKE ? OR notes LIKE ?)")
        args += [like] * 5
    sql = "SELECT * FROM subscriptions"
    if where:
        sql += " WHERE " + " AND ".join(where)
    rows = [_row(r) for r in db.q(sql, tuple(args))]

    if sort == "cost":
        rows.sort(key=lambda r: r["base_yearly"], reverse=True)
    elif sort == "name":
        rows.sort(key=lambda r: r["name"].casefold())
    elif sort == "vendor":
        rows.sort(key=lambda r: ((r["vendor"] or "~").casefold(),
                                 r["name"].casefold()))
    else:
        # by renewal: soonest first, and rows with no date last rather than
        # first — an empty string sorts before every real date
        rows.sort(key=lambda r: (r["renews"] or "9999-99-99", r["name"]))
    return rows


def distinct(column: str) -> list:
    if column not in {n for n, _ in COLUMNS}:
        return []
    return [r[column] for r in db.q(
        f"SELECT DISTINCT {column} AS {column} FROM subscriptions "
        f"WHERE {column} IS NOT NULL AND {column} != '' ORDER BY {column}")]


def totals(rows: list | None = None) -> dict:
    """The numbers the summary tiles and the Overview panel both need."""
    rows = search(status="active") if rows is None else rows
    base = display_currency()
    monthly = yearly = 0.0
    unconverted = set()
    stranded = []
    for r in rows:
        if r["converted"]:
            monthly += r["base_monthly"]
            yearly += r["base_yearly"]
        elif r["monthly"] or r["yearly"]:
            # naming the rows, not only the code: "AED is missing" sends you
            # hunting, "Etisalat business line is missing" does not
            unconverted.add(r["currency"])
            stranded.append(r)

    expired = [r for r in rows if r["renewal"]["state"] == "expired"]
    soon = [r for r in rows if r["renewal"]["state"] == "soon"]
    undated = [r for r in rows if r["renewal"]["state"] == "none"]

    by_vendor = {}
    by_category = {}
    for r in rows:
        if not r["converted"]:
            continue
        by_vendor[r["vendor"] or "unattributed"] = (
            by_vendor.get(r["vendor"] or "unattributed", 0.0) + r["base_yearly"])
        by_category[r["category_label"]] = (
            by_category.get(r["category_label"], 0.0) + r["base_yearly"])

    return {
        "base": base,
        "count": len(rows),
        "seats": sum(r["seats"] for r in rows),
        "monthly": round(monthly, 2),
        "yearly": round(yearly, 2),
        "unconverted": sorted(unconverted),
        "stranded": stranded,
        "stale": [r for r in rate_rows() if r["stale"]],
        "expired": expired,
        "soon": soon,
        "undated": undated,
        # biggest first: the useful order for a breakdown nobody scrolls
        "by_vendor": sorted(by_vendor.items(), key=lambda kv: -kv[1]),
        "by_category": sorted(by_category.items(), key=lambda kv: -kv[1]),
        "metered": [r for r in rows if r["cycle"] == "metered"],
    }


def stats() -> dict:
    """The Overview panel's view: counts and the two numbers that matter."""
    t = totals()
    return {
        "total": t["count"], "seats": t["seats"], "base": t["base"],
        "monthly": t["monthly"], "yearly": t["yearly"],
        "expired": len(t["expired"]), "soon": len(t["soon"]),
        "undated": len(t["undated"]), "unconverted": t["unconverted"],
        "top": t["by_vendor"][:3],
        # the single most urgent row, so the panel can name it rather than
        # only counting
        "next": (sorted([r for r in (t["expired"] + t["soon"])],
                        key=lambda r: r["renews"] or "9999")[:1] or [None])[0],
    }


# How many months apart two charges of each cycle are. A one-off happens once;
# a metered row has no known amount, so it is reported apart rather than guessed.
STEP_MONTHS = {"monthly": 1, "quarterly": 3, "yearly": 12, "biennial": 24}

MONTH_NAMES = ("January", "February", "March", "April", "May", "June", "July",
               "August", "September", "October", "November", "December")


def _add_months(d: dt.date, n: int) -> dt.date:
    """Same day n months on, clamped — 31 January plus one month is 28/29 Feb."""
    total = d.month - 1 + n
    year = d.year + total // 12
    month = total % 12 + 1
    last = [31, 29 if (year % 4 == 0 and (year % 100 or year % 400 == 0)) else 28,
            31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return dt.date(year, month, min(d.day, last))


def _scale(top: float) -> tuple[float, list]:
    """A rounded ceiling and clean tick values — axis labels people can read.

    An axis topped at the data's own maximum gives ticks like 41,383, which is
    noise. Rounding up to 1/2/5 × a power of ten gives 0 / 25,000 / 50,000.
    """
    if top <= 0:
        return 0.0, [0.0]
    import math
    power = 10 ** math.floor(math.log10(top))
    for mult in (1, 2, 2.5, 5, 10):
        if top <= power * mult:
            ceiling = power * mult
            break
    else:                                                # pragma: no cover
        ceiling = power * 10
    steps = 4
    return ceiling, [ceiling * i / steps for i in range(steps + 1)]


def forecast(months: int = 12, rows=None) -> dict:
    """What actually falls due in each of the next N calendar months.

    The run rate answers "what does this cost per month on average"; this answers
    "when does the money leave", which is the question a register of renewals is
    really for. A yearly licence is not a twelfth of itself every month — it is
    the whole amount, in one month, and that is the month you need to have it.
    """
    rows = search(status="active") if rows is None else rows
    today = dt.date.today()
    shown = display_currency()
    first = dt.date(today.year, today.month, 1)
    buckets = []
    for i in range(max(1, months)):
        at = _add_months(first, i)
        buckets.append({"ym": at.strftime("%Y-%m"), "at": at,
                        "label": f"{MONTH_NAMES[at.month - 1]} {at.year}",
                        "short": MONTH_NAMES[at.month - 1][:3],
                        "year": at.year, "amount": 0.0, "rows": []})
    index = {b["ym"]: b for b in buckets}
    horizon = _add_months(first, max(1, months))
    unknown = []

    for r in rows:
        if not r["renews"]:
            continue
        try:
            due = dt.date.fromisoformat(r["renews"])
        except (TypeError, ValueError):
            continue
        amount, ok = convert(r["cost"], r["currency"], shown)
        if not ok:
            unknown.append(r)
            continue
        step = STEP_MONTHS.get(r["cycle"])
        if step is None:
            # a one-off already in the past is paid for; a future one lands once
            if r["cycle"] == "one-off" and due >= today:
                b = index.get(due.strftime("%Y-%m"))
                if b:
                    b["amount"] += amount
                    b["rows"].append({"name": r["name"], "amount": amount})
            elif r["cycle"] == "metered":
                unknown.append(r)
            continue
        # a lapsed recurring row still has a next date: roll forward to it
        guard = 0
        while due < first and guard < 400:
            due = _add_months(due, step)
            guard += 1
        while due < horizon and guard < 400:
            b = index.get(due.strftime("%Y-%m"))
            if b:
                b["amount"] += amount
                b["rows"].append({"name": r["name"], "amount": amount})
            due = _add_months(due, step)
            guard += 1

    for b in buckets:
        b["rows"].sort(key=lambda x: -x["amount"])
        b.pop("at", None)
    peak = max(buckets, key=lambda b: b["amount"]) if buckets else None
    top = max((b["amount"] for b in buckets), default=0.0)
    ceiling, ticks = _scale(top)
    for b in buckets:
        # the share of the plot each column fills, so the view does no arithmetic
        b["frac"] = (b["amount"] / ceiling) if ceiling else 0.0
    return {
        "months": buckets,
        "ceiling": ceiling,
        "ticks": ticks,
        "max": top,
        "total": sum(b["amount"] for b in buckets),
        "peak": peak,
        "currency": shown,
        # named, not silently dropped: a metered row has no amount to project
        "unknown": unknown,
    }


def actuals(months: int = 12) -> dict:
    """What was actually spent, month by month, from the providers' own bills.

    WHY THIS EXISTS NEXT TO THE FORECAST
        The forecast answers "when does money leave" and, for a register made
        mostly of monthly subscriptions, it is a flat line by construction — a
        monthly commitment falls due at the same figure every month, so twelve
        identical columns are arithmetically right and tell you nothing.

        The variation is in the metered spend, and it is history, not
        commitment: this estate ran 621, 589, 584, 673, 707. That is the shape
        somebody opening a spend page is looking for, and until now the only
        place to see it was each cloud account's own page, one account at a
        time.

    IT SHOWS ONLY WHAT IT CAN READ
        Typed rows have no history — a subscription entered by hand has a
        current price and nothing else — so this covers the connected accounts
        only, and says so rather than implying it is the whole picture. Bills
        are asked for without blocking; on a cold cache the answer is "still
        collecting" and the chart appears on the next view.
    """
    from . import cloud, store

    shown = display_currency()
    today = dt.date.today()
    this_ym = f"{today.year:04d}-{today.month:02d}"
    seen: dict[str, dict] = {}
    accounts = pending = 0
    unconverted: list[str] = []
    for conn in store.all_cloud():
        accounts += 1
        name = conn.get("name") or conn.get("id") or "cloud account"
        try:
            got = cloud.bills_peek(conn, BILL_MONTHS)
        except Exception:                                       # noqa: BLE001
            got = None
        if got is None:
            pending += 1
            continue
        cur = (got.get("currency") or "USD").upper()[:3]
        for m in got.get("months") or []:
            total = m.get("total")
            if not isinstance(total, (int, float)):
                continue
            amount, ok = convert(total, cur, shown)
            if not ok:
                if name not in unconverted:
                    unconverted.append(name)
                continue
            b = seen.setdefault(m["cycle"], {"amount": 0.0, "rows": []})
            b["amount"] += amount
            b["rows"].append({"name": name, "amount": amount})

    # a continuous run of months ending with the one in progress, so a gap in
    # one provider's bill is a gap in the chart rather than a shifted column
    buckets = []
    at = _add_months(dt.date(today.year, today.month, 1), -(max(1, months) - 1))
    for _ in range(max(1, months)):
        ym = at.strftime("%Y-%m")
        got = seen.get(ym) or {"amount": 0.0, "rows": []}
        got["rows"].sort(key=lambda x: -x["amount"])
        buckets.append({"ym": ym, "label": f"{MONTH_NAMES[at.month - 1]} {at.year}",
                        "short": MONTH_NAMES[at.month - 1][:3], "year": at.year,
                        "amount": got["amount"], "rows": got["rows"],
                        "partial": ym == this_ym, "missing": ym not in seen})
        at = _add_months(at, 1)

    top = max((b["amount"] for b in buckets), default=0.0)
    ceiling, ticks = _scale(top)
    for b in buckets:
        b["frac"] = (b["amount"] / ceiling) if ceiling else 0.0
    # The month in progress is not a month, so it is left out. So are months
    # with nothing in them: an account opened in December has zeros before it,
    # and averaging those in reports a typical month far below any real one.
    full = [b for b in buckets if not b["partial"] and not b["missing"]]
    spent = [b for b in full if b["amount"] > 0]
    peak = max(full, key=lambda b: b["amount"]) if full else None
    prev = spent[-2]["amount"] if len(spent) > 1 else 0.0
    last = spent[-1] if spent else None
    return {
        "months": buckets, "ceiling": ceiling, "ticks": ticks, "max": top,
        "currency": shown, "accounts": accounts, "pending": pending,
        "unconverted": unconverted,
        "total": sum(b["amount"] for b in full),
        "average": (sum(b["amount"] for b in spent) / len(spent)) if spent else 0.0,
        "counted": len(spent),
        "peak": peak, "last": last,
        "move": ((last["amount"] - prev) / prev * 100) if last and prev else 0.0,
        "running": next((b for b in buckets if b["partial"]), None),
    }


# The register split by how often the money leaves. Each tab is a table with
# its own total, because the totals are not the same kind of number: a monthly
# subscription has a run rate, a one-off purchase has an amount that was
# charged once, and adding those two together is the single easiest way to
# produce a confident wrong figure. Keeping them in separate tables means the
# page never has to.
CYCLE_TABS = (
    ("all", "Everything", (), True),
    ("one-off", "Bought once", ("one-off",), True),
    ("monthly", "Monthly", ("monthly",), True),
    ("yearly", "Yearly", ("yearly",), True),
    # quarterly, biennial and metered are real but rare. The tab appears only
    # when something is in it, rather than sitting there empty forever.
    ("other", "Other cycles", ("quarterly", "biennial", "metered"), False),
)


def cycle_groups(rows: list) -> list[dict]:
    """One entry per tab: the rows in it and what they add up to.

    A group reports up to two totals and never merges them. ``charged`` is
    money that left once and is not coming back — the sum of the one-off rows.
    ``monthly``/``yearly`` are the run rate of the recurring rows. The
    Everything tab carries both, side by side and labelled, so the page can
    say "USD 707 a month, plus USD 3,205 bought once" instead of inventing a
    single number that means neither.

    Anything in a currency with no rate is counted in neither and named in
    ``unconverted``, the same bargain the rest of the module keeps.
    """
    shown = display_currency()
    out = []
    for key, label, cycles, always in CYCLE_TABS:
        mine = (list(rows) if key == "all"
                else [r for r in rows if r.get("cycle") in cycles])
        charged = monthly = yearly = 0.0
        n_charged = n_recurring = 0
        unconverted: set[str] = set()
        for r in mine:
            recurs = CYCLES.get(r.get("cycle"), ("", 12))[1] is not None
            if not r.get("converted"):
                unconverted.add(r.get("currency") or "")
                continue
            if recurs:
                n_recurring += 1
                monthly += r.get("base_monthly") or 0.0
                yearly += r.get("base_yearly") or 0.0
            else:
                n_charged += 1
                charged += r.get("shown_cost") or 0.0
        out.append({
            "key": key, "label": label, "cycles": cycles, "always": always,
            "rows": mine, "count": len(mine), "currency": shown,
            "charged": round(charged, 2), "n_charged": n_charged,
            "monthly": round(monthly, 2), "yearly": round(yearly, 2),
            "n_recurring": n_recurring,
            "unconverted": sorted(c for c in unconverted if c),
            # what the tab chip shows: the one number that describes this
            # table, and the unit it is in
            "headline": round(charged, 2) if key == "one-off" else
                        round(yearly, 2) if key == "yearly" else
                        round(monthly, 2),
            "unit": "charged" if key == "one-off" else
                    "a year" if key == "yearly" else "a month",
        })
    return out


# ── one month, and twelve of them ──────────────────────────────────────────
# The year grid and the month table are the same arithmetic asked twice, so
# they share it. Two implementations would drift, and the day they did, a box
# saying USD 186 would open onto a table adding up to something else — which
# is the kind of wrong that destroys confidence in every other number here.
def _cloud_months(shown: str) -> tuple[list, int]:
    """Every connected account's bills, keyed by month. Read once, not per month."""
    from . import cloud, store
    out, pending = [], 0
    for conn in store.all_cloud():
        name = conn.get("name") or conn.get("id") or "cloud account"
        try:
            got = cloud.bills_peek(conn, BILL_MONTHS)
        except Exception:                                       # noqa: BLE001
            got = None
        if got is None:
            pending += 1
            continue
        cur = (got.get("currency") or "USD").upper()[:3]
        months = {}
        for month in got.get("months") or []:
            rows = month.get("rows") or []
            months[month.get("cycle")] = (sum(r.get("amount") or 0 for r in rows),
                                          len(rows))
        out.append({"name": name, "currency": cur, "months": months})
    return out, pending


def _due_in(row: dict, first, nxt) -> bool:
    """Whether this row falls due in [first, nxt).

    Walks forward only, which is the honest limit of what the register knows:
    it holds the next renewal, not a payment history. A monthly subscription
    added today therefore does not invent charges for last March.
    """
    try:
        due = dt.date.fromisoformat(row["renews"])
    except (TypeError, ValueError):
        return False
    step = STEP_MONTHS.get(row.get("cycle"))
    if step:
        guard = 0
        while due < first and guard < 400:
            due = _add_months(due, step)
            guard += 1
    return first <= due < nxt


def _month_lines(y: int, m: int, rows: list, clouds: list, shown: str):
    """(lines, stranded) for one month — the single definition of what a
    month contains."""
    lines: list[dict] = []
    stranded: list[dict] = []
    ym = f"{y:04d}-{m:02d}"

    for acct in clouds:
        raw, n = acct["months"].get(ym, (0.0, 0))
        if not n:
            continue
        amount, ok = convert(raw, acct["currency"], shown)
        if not ok:
            stranded.append({"what": acct["name"], "currency": acct["currency"],
                             "amount": raw})
            continue
        if not amount:
            continue
        lines.append({"what": acct["name"], "who": "cloud usage",
                      "kind": "metered", "amount": amount, "category": "cloud",
                      "note": f"metered · {n} charge{'s' if n != 1 else ''}"})

    first = dt.date(y, m, 1)
    nxt = _add_months(first, 1)
    for row in rows:
        if row.get("source") or not row.get("renews"):
            continue          # a cloud account is already above, from its bill
        if not _due_in(row, first, nxt):
            continue
        amount, ok = convert(row["cost"], row["currency"], shown)
        if not ok:
            stranded.append({"what": row["name"], "currency": row["currency"],
                             "amount": row["cost"]})
            continue
        # the category travels as a key, not only as a label: the month page
        # groups by it, and a label is a thing to print rather than to group on
        # The row itself travels with the line so a month page can open the
        # editor on it. A cloud account gets none: its figure is read from the
        # provider's bill every six hours, and an edit here would be silently
        # overwritten — which is worse than not offering it.
        lines.append({"what": row["name"], "who": row.get("vendor") or "",
                      "kind": row.get("cycle") or "one-off", "amount": amount,
                      "category": row.get("category") or "other",
                      "row": row,
                      "note": CATEGORIES.get(row.get("category"), "")})
    return lines, stranded


# Which tab a line belongs to. Metered is its own: a cloud bill is neither a
# commitment nor a purchase, it is whatever was used.
def _bucket(kind: str) -> str:
    if kind == "metered":
        return "metered"
    if kind in ("monthly", "quarterly"):
        return "monthly"
    if kind in ("yearly", "biennial"):
        return "yearly"
    return "once"


BUCKETS = (("once", "Bought once"), ("monthly", "Monthly"),
           ("yearly", "Yearly"), ("metered", "Cloud usage"))


def years_view() -> dict:
    """Every year there is anything for, as one box each, and the lot together.

    THE QUESTION THIS ANSWERS
        "What have we spent altogether?" — which the year grid could not, being
        one year at a time with no way up. It is the same shape one level out:
        a box per year instead of a box per month, split the same way, so
        reading it needs nothing new learned.
    """
    shown = display_currency()
    years = sorted(years_known())
    boxes, total = [], 0.0
    by_all = {k: 0.0 for k, _ in BUCKETS}
    pending, gap = 0, False
    for y in years:
        yv = year_view(y)
        pending = max(pending, yv.get("pending", 0))
        gap = gap or bool(yv.get("cloud_gap"))
        total += yv["total"]
        for k, _ in BUCKETS:
            by_all[k] += yv["by"].get(k, 0.0)
        boxes.append({"year": y, "total": yv["total"], "by": yv["by"],
                      "counted": yv.get("counted", 0)})
    top = max((b["total"] for b in boxes), default=0.0) or 1.0
    for b in boxes:
        b["frac"] = b["total"] / top
    counted = [b for b in boxes if b["total"]]
    return {"years": years, "boxes": list(reversed(boxes)), "total": total,
            "by": by_all, "currency": shown, "buckets": BUCKETS,
            "pending": pending, "cloud_gap": gap,
            "average": (total / len(counted)) if counted else 0.0,
            "counted": len(counted),
            "peak": max(counted, key=lambda b: b["total"], default=None)}


def years_known() -> list[int]:
    """Years there is anything to show, newest first, always including this one."""
    from . import cloud, store
    got = {dt.date.today().year}
    for row in search(status=""):
        for field in ("renews", "started"):
            v = (row.get(field) or "")[:4]
            if v.isdigit():
                got.add(int(v))
    for conn in store.all_cloud():
        try:
            bills = cloud.bills_peek(conn, BILL_MONTHS)
        except Exception:                                       # noqa: BLE001
            bills = None
        for month in (bills or {}).get("months") or []:
            v = str(month.get("cycle") or "")[:4]
            if v.isdigit():
                got.add(int(v))
    return sorted(got, reverse=True)


def year_view(year: int = 0) -> dict:
    """Twelve months of one year, each split the way the tabs split them.

    THE QUESTION THIS ANSWERS
        "What did this year cost, month by month, and what kind of spending
        was it?" — answerable before clicking anything, which the old page
        could not do: it led with a run rate, and the only way to see a month
        was to pick it out of a chart.
    """
    shown = display_currency()
    today = dt.date.today()
    year = int(year or today.year)
    rows = search(status="")
    clouds, pending = _cloud_months(shown)

    # How far back the providers' own bills reach. A year before that is not a
    # year with no cloud spend, and a grid of zeroes saying so would be the
    # page quietly lying — so it is stated instead.
    seen_months = sorted(ym for acct in clouds for ym in acct["months"])
    earliest = seen_months[0] if seen_months else ""

    months, stranded = [], []
    for m in range(1, 13):
        lines, mine = _month_lines(year, m, rows, clouds, shown)
        stranded += mine
        by = {k: 0.0 for k, _ in BUCKETS}
        for line in lines:
            by[_bucket(line["kind"])] += line["amount"]
        running = (year == today.year and m == today.month)
        months.append({
            "ym": f"{year:04d}-{m:02d}", "n": m, "label": MONTH_NAMES[m - 1],
            "short": MONTH_NAMES[m - 1][:3], "total": round(sum(by.values()), 2),
            "by": {k: round(v, 2) for k, v in by.items()},
            "count": len(lines),
            "running": running,
            # a month that has not happened yet is not "zero spend", and
            # colouring it the same as one that genuinely cost nothing is how
            # a page starts lying quietly
            "future": (year > today.year
                       or (year == today.year and m > today.month)),
        })

    total = round(sum(x["total"] for x in months), 2)
    by_year = {k: round(sum(x["by"][k] for x in months), 2) for k, _ in BUCKETS}
    spent = [x for x in months if x["total"] and not x["future"]]
    peak = max(spent, key=lambda x: x["total"]) if spent else None
    top = max((x["total"] for x in months), default=0.0)
    for x in months:
        x["frac"] = (x["total"] / top) if top > 0 and x["total"] > 0 else 0.0
    return {
        "year": year, "months": months, "total": total, "by": by_year,
        "currency": shown, "pending": pending,
        "counted": len(spent),
        "average": round(total / len(spent), 2) if spent else 0.0,
        "peak": peak, "buckets": BUCKETS,
        # set when this year is wholly before the oldest bill we hold
        "cloud_from": earliest,
        "cloud_gap": bool(clouds and earliest
                          and f"{year:04d}-12" < earliest),
        "stranded": stranded,
        "unconverted": sorted({r["currency"] for r in stranded}),
        "years": years_known(),
    }


def year_lines(year: int) -> dict:
    """Every line charged in a whole year — what the thirteenth box opens onto.

    Built from the same per-month helper rather than by widening the month
    query, so the year table is exactly the twelve month tables concatenated
    and cannot total to something the boxes above it disagree with.
    """
    shown = display_currency()
    year = int(year or dt.date.today().year)
    rows = search(status="")
    clouds, pending = _cloud_months(shown)
    lines, stranded = [], []
    for m in range(1, 13):
        got, mine = _month_lines(year, m, rows, clouds, shown)
        stranded += mine
        for line in got:
            line["bucket"] = _bucket(line["kind"])
            line["month"] = MONTH_NAMES[m - 1]
            line["ym"] = f"{year:04d}-{m:02d}"
        lines += got
    lines.sort(key=lambda r: (-r["amount"]))
    total = round(sum(r["amount"] for r in lines), 2)
    charged = sum(r["amount"] for r in lines if r["amount"] > 0)
    for r in lines:
        r["share"] = ((r["amount"] / charged * 100)
                      if charged and r["amount"] > 0 else 0.0)
        r["credit"] = r["amount"] < 0
    return {"ym": str(year), "label": str(year), "lines": lines, "total": total,
            "currency": shown, "pending": pending, "stranded": stranded,
            "unconverted": sorted({r["currency"] for r in stranded}),
            "whole_year": True,
            "note": "" if lines else "nothing was charged in that year"}


def month_total(ym: str) -> float | None:
    """What one month came to, or None if it is not a month. Deliberately not
    month_detail: the comparison on a month page must not recurse into another
    month's charts, and a total is all it needs."""
    try:
        y, m = (int(x) for x in ym.split("-", 1))
    except (ValueError, AttributeError):
        return None
    shown = display_currency()
    clouds, _pending = _cloud_months(shown)
    lines, _stranded = _month_lines(y, m, search(status=""), clouds, shown)
    return sum(r["amount"] for r in lines)


def month_detail(ym: str = "") -> dict:
    """Every line charged in one month, and what they add up to.

    THE QUESTION THIS ANSWERS
        "What did we spend last month?" — and then, immediately, "on what?".
        The register could answer the first with a run rate and the second not
        at all: a cloud account was one row saying USD 707, and the products
        inside it lived on a different page in a different shape.

        This is one list, at one level: a line per thing charged. A cloud
        account is one line for what that account cost that month — the split
        by product is the provider's console's business, and putting it here
        buried the invoices under forty EC2 rows. A subscription or an invoice
        that fell due that month is one entry for what it cost. Everything is
        converted to the display currency and totalled.
    """
    shown = display_currency()
    today = dt.date.today()
    if not ym:
        last = dt.date(today.year, today.month, 1) - dt.timedelta(days=1)
        ym = f"{last.year:04d}-{last.month:02d}"
    try:
        y, m = (int(x) for x in ym.split("-", 1))
        label = f"{MONTH_NAMES[m - 1]} {y}"
    except (ValueError, IndexError):
        return {"ym": ym, "label": ym, "lines": [], "total": 0.0,
                "currency": shown, "pending": 0, "stranded": [],
                "unconverted": [], "note": "that is not a month"}

    # the same arithmetic the year grid uses, so a box and the table it opens
    # can never disagree about what a month contains
    clouds, pending = _cloud_months(shown)
    lines, stranded = _month_lines(y, m, search(status=""), clouds, shown)
    first = dt.date(y, m, 1)
    for line in lines:
        line["bucket"] = _bucket(line["kind"])

    lines.sort(key=lambda r: -r["amount"])
    total = sum(r["amount"] for r in lines)
    # Share is of what was *charged*, not of the net total. A month holding a
    # credit note has a small net and would otherwise report a 1,200 line as
    # 2,279% of it — arithmetically true, and useless. A credit gets no share:
    # it is not a portion of the spend, it is the opposite of one.
    charged = sum(r["amount"] for r in lines if r["amount"] > 0)
    for r in lines:
        r["share"] = ((r["amount"] / charged * 100)
                      if charged and r["amount"] > 0 else 0.0)
        r["credit"] = r["amount"] < 0
    prev = _add_months(first, -1)
    nxt_m = _add_months(first, 1)
    this_ym = f"{today.year:04d}-{today.month:02d}"

    # What the month was made of, two ways. Both are built here rather than in
    # the template: a share that disagrees with the table under it is the kind
    # of thing nobody notices and everybody quotes.
    #
    # Credits are excluded from both. A negative slice of a pie is not a
    # smaller slice, it is a different statement, and mixing them makes the
    # percentages add up to something other than the month.
    charged_lines = [r for r in lines if r["amount"] > 0]
    by_cat: dict = {}
    for r in charged_lines:
        key = r.get("category") or "other"
        by_cat[key] = by_cat.get(key, 0.0) + r["amount"]
    categories = sorted(
        ({"key": k, "label": CATEGORIES.get(k, k.title()), "amount": v,
          "share": (v / charged * 100) if charged else 0.0}
         for k, v in by_cat.items()), key=lambda c: -c["amount"])

    by_bucket: dict = {}
    for r in charged_lines:
        by_bucket[r["bucket"]] = by_bucket.get(r["bucket"], 0.0) + r["amount"]
    buckets = [{"key": k, "label": lab, "amount": by_bucket.get(k, 0.0),
                "share": (by_bucket.get(k, 0.0) / charged * 100) if charged else 0.0}
               for k, lab in BUCKETS if by_bucket.get(k)]

    # The same month last time, so the headline number has something to be
    # bigger or smaller THAN. Without it a total is a number with no verdict.
    before = month_total(prev.strftime("%Y-%m"))

    return {"ym": ym, "label": label, "lines": lines, "total": total,
            "charged": charged, "categories": categories, "buckets": buckets,
            "prev_total": before,
            "delta": (total - before) if before is not None else None,
            "delta_pct": (((total - before) / before * 100)
                          if before else None),
            "prev": prev.strftime("%Y-%m"),
            "prev_label": f"{MONTH_NAMES[prev.month - 1]} {prev.year}",
            # never offers the month in progress: a part-month total invites
            # being read as a month's spend
            "next": nxt_m.strftime("%Y-%m") if nxt_m.strftime("%Y-%m") < this_ym else "",
            "next_label": f"{MONTH_NAMES[nxt_m.month - 1]} {nxt_m.year}",
            "currency": shown, "pending": pending,
            "stranded": stranded,
            "unconverted": sorted({r["currency"] for r in stranded}),
            "note": "" if lines or stranded else
                    ("still reading the bills" if pending else
                     "nothing was charged in that month")}


# ── cloud accounts, read rather than typed ─────────────────────────────────
def _linked(source: str) -> dict | None:
    row = db.one("SELECT * FROM subscriptions WHERE source = ?", (source,))
    return _row(row) if row else None


def sync_clouds(refresh: bool = False, actor: str = "") -> dict:
    """Read each connected cloud account's own bill into the register.

    WHY THIS IS NOT A MANUAL ROW
        Cloud spend is the one line nobody can maintain by hand: it changes
        every month, and a figure typed in March is wrong by April. The portal
        already reads these bills for the Clouds pages, so the register asks the
        same reader rather than the person.

    WHAT THE SYNC OWNS
        The money only — cost, currency, the month it came from, and the next
        bill date. Owner, project, notes and status stay whoever set them, so
        marking an account cancelled or assigning it to a team is not undone on
        the next refresh.

    WHICH MONTH THE FIGURE COMES FROM
        The last month that has finished, never the one in progress. A provider
        bills as it goes, so on the first of the month the current cycle holds
        a few hours of spend and reading it makes a USD 700 account look like a
        USD 15 one. Month-to-date is still read and shown in the note, because
        it is worth seeing — it just is not a monthly cost.

    WHAT IT WILL NOT DO
        Guess at a figure it could not read. A provider that cannot be reached
        leaves the last known cost alone and is reported as failed — a network
        blip must never look like a month where spending stopped.

        A bill that is genuinely zero is a different thing and is recorded as
        zero: an account that costs nothing should say so on the register
        rather than disappear from it.
    """
    from . import cloud, store

    today = dt.date.today()
    report = {"updated": [], "unchanged": [], "failed": [], "at": _now(),
              "accounts": 0}
    for conn in store.all_cloud():
        report["accounts"] += 1
        cid = conn.get("id") or ""
        label = (cloud.PROVIDERS.get(conn.get("type"), {}) or {}).get(
            "label", conn.get("type") or "cloud")
        # People name their accounts "AWS — shared services", so prefixing the
        # provider produced "AWS — AWS — shared services". Only prefix when the
        # name does not already say who it is with.
        given = (conn.get("name") or "").strip()
        first = label.split()[0].casefold()
        title = given if (given and first in given.casefold()) else \
            f"{label} — {given or cid}"
        source = f"cloud:{cid}"
        existing = _linked(source)
        try:
            got = cloud.bills(conn, months=6, refresh=refresh)
        except Exception as exc:                                # noqa: BLE001
            report["failed"].append({"name": title, "why": str(exc)[:160],
                                     "kept": bool(existing)})
            continue

        months = [m for m in (got.get("months") or [])
                  if isinstance(m.get("total"), (int, float))]
        if not months:
            why = "; ".join(got.get("notes") or []) or "the bill had no months in it"
            report["failed"].append({"name": title, "why": why[:160],
                                     "kept": bool(existing)})
            continue

        # THE MONTH THIS TAKES ITS FIGURE FROM
        #     Never the current one. A provider bills as it goes, so on the
        #     first of the month the current cycle holds a few hours of spend:
        #     an account running at USD 707 a month reported USD 15, and the
        #     register said that was the run rate. The Clouds pages were right
        #     the whole time because they show every month and a partial one is
        #     obviously partial next to the others.
        #
        #     So: the last month that has finished. The current month is still
        #     read, and shown in the note as "so far", because month-to-date is
        #     worth seeing — it just is not a monthly cost.
        this_cycle = f"{today.year:04d}-{today.month:02d}"
        finished = [m for m in months if m["cycle"] < this_cycle]
        running = next((m for m in months if m["cycle"] == this_cycle), None)
        priced = [m for m in finished if m["total"] > 0]

        partial = False
        if priced:
            latest = priced[-1]
            prior = priced[-2] if len(priced) > 1 else None
        elif finished:
            # every finished month is zero — a real answer, not a failure, and
            # an account that costs nothing should say so rather than vanish
            latest, prior = finished[-1], None
        elif running:
            # nothing has finished yet: a new account. Use what there is and
            # label it, rather than reporting the account as unreadable.
            latest, prior, partial = running, None, True
        else:
            why = "; ".join(got.get("notes") or []) or "the bill had no months in it"
            report["failed"].append({"name": title, "why": why[:160],
                                     "kept": bool(existing)})
            continue

        cur = (got.get("currency") or "USD").upper()[:3]
        # the next bill lands at the start of next month
        nxt = _add_months(dt.date(today.year, today.month, 1), 1)
        if partial:
            note = (f"{latest['cycle']} so far — this account has no completed "
                    f"month yet")
        else:
            note = f"read from the {latest['cycle']} bill, the last full month"
            if prior and prior["total"]:
                move = (latest["total"] - prior["total"]) / prior["total"] * 100
                note += (f", {abs(move):.0f}% {'up' if move >= 0 else 'down'} "
                         f"on {prior['cycle']}")
            if running is not None:
                note += f"; {running['cycle']} so far {cur} {running['total']:,.2f}"
            if not latest["total"]:
                note = (f"the bill reports no spend for {latest['cycle']} — "
                        f"nothing is being charged to this account")

        fields = {
            "name": title, "vendor": label, "category": "cloud",
            "kind": "consumption", "cost": latest["total"], "currency": cur,
            "cycle": "monthly", "renews": nxt.isoformat(), "auto_renew": 1,
            "url": conn.get("base_url") or "",
            "source": source, "source_at": _now(), "source_note": note,
        }
        if existing:
            same = (abs((existing["cost"] or 0) - latest["total"]) < 0.005
                    and existing["currency"] == cur)
            db.run(f"UPDATE subscriptions SET "
                   f"{', '.join(k + ' = ?' for k in fields)}, "
                   f"updated = ?, updated_by = ? WHERE id = ?",
                   (*fields.values(), _now(), actor or "cloud sync",
                    existing["id"]))
            (report["unchanged"] if same else report["updated"]).append(
                {"name": title, "cost": latest["total"], "currency": cur,
                 "month": latest["cycle"],
                 "was": existing["cost"] if not same else None})
        else:
            create({**fields, "status": "active",
                    "account": conn.get("name") or "",
                    "notes": "Added automatically from the connected cloud "
                             "account. The cost refreshes from the provider's "
                             "own bill; anything you type here is kept."},
                   actor or "cloud sync")
            report["updated"].append({"name": title, "cost": latest["total"],
                                      "currency": cur,
                                      "month": latest["cycle"], "was": None})
    _set_meta("cloud_synced_at", report["at"])
    return report


def cloud_synced_at() -> str:
    return _meta("cloud_synced_at", "")


def cloud_sync_age() -> float | None:
    """Hours since the last sync, or None if it has never run."""
    stamp = cloud_synced_at()
    if not stamp:
        return None
    try:
        then = dt.datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return (dt.datetime.now() - then).total_seconds() / 3600


def money(amount, code: str = "") -> str:
    """Currency code always written out — a bare number is ambiguous here."""
    try:
        amount = float(amount or 0)
    except (TypeError, ValueError):
        amount = 0.0
    return f"{(code or display_currency())} {amount:,.2f}"
