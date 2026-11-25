"""Server and hardware inventory, stored in SQLite.

WHY THIS ONE USES A DATABASE
    Everything else the portal stores is configuration: a few projects, a
    handful of connections, kilobytes of JSON read whole and written whole. An
    inventory is not that. It is an open-ended list that people add to through
    the UI, filter, sort and edit concurrently, and it grows without bound.
    Read-modify-write on a JSON file loses an edit the moment two people save at
    once, and filtering means loading everything into memory.

    SQLite answers exactly that and nothing more: real transactions, indexes,
    concurrent readers alongside a writer (WAL), and no server to run, no
    driver to install, no backup story beyond "copy the file". It is stdlib, so
    the portal still installs with pip and nothing else.

    The tables live in the portal's single database (db.py) alongside accounts
    and the audit trail — one file to back up, one connection per thread, and
    an inventory change and its audit entry can share a transaction.

NOTHING IS ENUMERATED
    Placement, provider, model, status and environment are free text. The forms
    suggest values, but every suggestion is drawn from what this deployment has
    already entered — the vocabulary grows out of the data rather than being
    decided here. `attributes` holds whatever else a team tracks, as JSON, so a
    field nobody anticipated does not require a schema change.
"""
import json
import re
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone

from . import db
from .paths import DATA

LEGACY_DB = DATA / "assets.db"   # pre-consolidation location, imported once

# When a warranty starts being called out. Two thresholds so "act now" and
# "start the paperwork" look different; the list tile uses the first.
WARRANTY_HORIZON_DAYS = 30
WARRANTY_WATCH_DAYS = 90

# The columns worth having a real column for: the ones searched, filtered,
# sorted or summed. Anything else a team tracks lives in `attributes`.
COLUMNS = [
    ("hostname", "TEXT NOT NULL"),   # what people call it
    ("pid", "TEXT"),                 # owning project, blank = unassigned
    ("region", "TEXT"),
    ("env", "TEXT"),
    ("placement", "TEXT"),           # on-prem, cloud, colocation, edge…
    ("provider", "TEXT"),            # AWS, Azure, VMware, Proxmox, bare metal…
    ("model", "TEXT"),
    ("serial", "TEXT"),              # service tag / serial number
    ("kind", "TEXT"),                # physical, VM, appliance, container host…
    ("status", "TEXT"),              # active, spare, decommissioned…
    ("ip", "TEXT"),
    ("mgmt_ip", "TEXT"),             # iDRAC / iLO / IPMI
    ("os", "TEXT"),
    ("cpu", "INTEGER"),
    ("ram_gb", "REAL"),
    ("disk_gb", "REAL"),
    ("location", "TEXT"),            # datacentre, rack, availability zone
    ("owner", "TEXT"),
    ("purchased", "TEXT"),           # ISO date
    ("warranty_until", "TEXT"),      # ISO date — drives the expiry warnings
    ("tags", "TEXT"),
    ("notes", "TEXT"),
    ("attributes", "TEXT"),          # JSON: anything this team tracks
]

# Free-text fields worth offering suggestions for. The suggestions themselves
# come from the data; these are only the fields that get a picker.
SUGGESTED = ("placement", "provider", "model", "kind", "status", "os",
             "location", "owner", "region", "env")

# Shown only when a deployment has nothing of its own yet, and never enforced —
# a starting point, not a vocabulary.
EXAMPLES = {
    "placement": ["on-prem", "cloud", "colocation", "edge"],
    "kind": ["physical", "virtual machine", "appliance", "container host"],
    "status": ["active", "spare", "staging", "decommissioned"],
}

# What the page offers as filters and breakdowns. Ownership and whereabouts
# first — project, region, environment, site — because that is how a fleet is
# usually divided up before anyone asks about hardware.
FACETS = ("pid", "region", "env", "location", "placement", "provider", "status")
BREAKDOWN = ("region", "env", "location", "placement", "provider", "status", "pid")

SORTABLE = {"hostname", "pid", "region", "env", "placement", "provider", "model",
            "serial", "status", "owner", "location", "warranty_until", "updated",
            "cpu", "ram_gb", "disk_gb", "ip", "mgmt_ip"}

# Addresses sort by octet, not as text — otherwise .9 lands after .29, which
# looks like a bug to anyone reading down a column of a /24.
ADDRESS_COLS = ("ip", "mgmt_ip")

# `kind` stays free text, but "is this a machine or a guest" is a question every
# team asks, so the two are told apart by the words the industry already uses
# rather than by a fixed list of allowed kinds. Anything with a kind that is not
# one of these counts as physical; a blank kind counts as neither, because
# guessing would put unclassified rows into a total someone relies on.
VIRTUAL_WORDS = ("virtual", "vm", "kvm", "guest", "instance", "droplet")
CLASSES = ("physical", "virtual")

# A CSV export is one HTTP response, so it is bounded. Far above any real
# inventory, and it says so in the response rather than truncating quietly.
EXPORT_MAX = 20000


def _conn() -> sqlite3.Connection:
    """The portal's shared connection for this thread."""
    return db.connect()


def _migrate(c: sqlite3.Connection) -> None:
    """Create the table, then add any column this version knows about.

    Additive only: an older database opened by a newer portal gains columns; it
    never loses data. That keeps upgrades boring.
    """
    cols = ", ".join(f"{n} {t}" for n, t in COLUMNS)
    c.execute(f"""CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY, {cols},
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    have = {r["name"] for r in c.execute("PRAGMA table_info(assets)")}
    for name, decl in COLUMNS:
        if name not in have:
            # NOT NULL cannot be added to an existing table without a default
            c.execute(f"ALTER TABLE assets ADD COLUMN {name} "
                      f"{decl.replace(' NOT NULL', '')}")
    for col in ("hostname", "pid", "env", "placement", "status", "warranty_until"):
        c.execute(f"CREATE INDEX IF NOT EXISTS idx_assets_{col} ON assets({col})")
    _import_legacy(c)


def _import_legacy(c: sqlite3.Connection) -> None:
    """Move an inventory written before the databases were consolidated.

    Copies rows across if the old file exists and the shared table is still
    empty, then renames it. Column names are read from the old file, so a file
    written by an older version with fewer columns still imports.
    """
    if not LEGACY_DB.exists():
        return
    if c.execute("SELECT 1 FROM assets LIMIT 1").fetchone():
        return
    try:
        old = sqlite3.connect(LEGACY_DB, timeout=10)
        old.row_factory = sqlite3.Row
        rows = old.execute("SELECT * FROM assets").fetchall()
        old.close()
        here = {r["name"] for r in c.execute("PRAGMA table_info(assets)")}
        for r in rows:
            cols = [k for k in r.keys() if k in here]
            c.execute(f"INSERT OR IGNORE INTO assets ({', '.join(cols)}) "
                      f"VALUES ({', '.join('?' * len(cols))})",
                      [r[k] for k in cols])
        LEGACY_DB.rename(LEGACY_DB.with_suffix(".db.migrated"))
    except sqlite3.Error:
        # leave the old file alone; the inventory is simply empty until it is
        # dealt with by hand, which is better than a portal that will not start
        pass


db.register(_migrate)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(form: dict) -> dict:
    """Form values to column values, keeping unknown keys as attributes."""
    known = {n for n, _t in COLUMNS}
    out, extra = {}, {}
    for k, v in form.items():
        v = v.strip() if isinstance(v, str) else v
        if k in known and k != "attributes":
            out[k] = v
        elif k.startswith("attr_") and k[5:].strip():
            extra[k[5:].strip()] = v
    for num in ("cpu",):
        if out.get(num) not in (None, ""):
            try:
                out[num] = int(float(out[num]))
            except (TypeError, ValueError):
                out[num] = None
    for num in ("ram_gb", "disk_gb"):
        if out.get(num) not in (None, ""):
            try:
                out[num] = float(out[num])
            except (TypeError, ValueError):
                out[num] = None
    for d in ("purchased", "warranty_until"):
        if out.get(d):
            out[d] = _iso_date(out[d])
    if extra:
        out["attributes"] = json.dumps(extra)
    return {k: (v if v != "" else None) for k, v in out.items()}


def _iso_date(v: str) -> str:
    """Accept what people actually type; store one format."""
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%d %b %Y",
                "%d %B %Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    return s


# ── writes ─────────────────────────────────────────────────────
def create(form: dict, actor: str = "") -> str:
    data = _clean(form)
    if not data.get("hostname"):
        raise ValueError("hostname is required")
    aid = "a-" + uuid.uuid4().hex[:10]
    data.update(id=aid, created=_now(), updated=_now(),
                created_by=actor, updated_by=actor)
    cols = ", ".join(data)
    marks = ", ".join("?" for _ in data)
    _conn().execute(f"INSERT INTO assets ({cols}) VALUES ({marks})",
                    list(data.values()))
    return aid


def update(aid: str, form: dict, actor: str = "") -> None:
    data = _clean(form)
    if "hostname" in data and not data["hostname"]:
        raise ValueError("hostname is required")
    data.update(updated=_now(), updated_by=actor)
    sets = ", ".join(f"{k}=?" for k in data)
    _conn().execute(f"UPDATE assets SET {sets} WHERE id=?",
                    list(data.values()) + [aid])


def delete(aid: str) -> None:
    _conn().execute("DELETE FROM assets WHERE id=?", (aid,))


def delete_many(ids: list) -> list:
    """Remove several assets at once, returning the hostnames actually removed.

    One transaction, so a bulk removal either happens or does not — and the
    hostnames come back so the audit entry can say what went, not just how many.
    """
    ids = [i for i in ids if i]
    if not ids:
        return []
    marks = ", ".join("?" * len(ids))
    with db.tx() as c:
        gone = [r["hostname"] for r in c.execute(
            f"SELECT hostname FROM assets WHERE id IN ({marks})", ids)]
        c.execute(f"DELETE FROM assets WHERE id IN ({marks})", ids)
    return gone


def get(aid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return _row(r) if r else None


# ── reads ──────────────────────────────────────────────────────
def many(ids) -> dict:
    """{id: asset} for several ids in ONE query.

    `get()` per id is fine for a handful and N round trips for a real
    inventory — the Ansible catalogue resolves every host's asset on each
    Privileged Access page load, which is where that arithmetic starts to
    show.
    """
    ids = sorted({str(i) for i in ids if i})
    if not ids:
        return {}
    marks = ", ".join("?" for _ in ids)
    return {r["id"]: _row(r) for r in _conn().execute(
        f"SELECT * FROM assets WHERE id IN ({marks})", tuple(ids))}


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["attributes"] = json.loads(d.get("attributes") or "{}")
    except (TypeError, ValueError):
        d["attributes"] = {}
    d["warranty"] = warranty_state(d.get("warranty_until"))
    return d


def warranty_state(until) -> dict:
    """Days left on the warranty, so the list can flag what is lapsing."""
    if not until:
        return {"days": None, "label": "", "state": ""}
    try:
        d = (date.fromisoformat(str(until)) - date.today()).days
    except ValueError:
        return {"days": None, "label": str(until), "state": ""}
    if d < 0:
        return {"days": d, "label": f"expired {-d}d ago", "state": "expired"}
    if d <= WARRANTY_HORIZON_DAYS:
        return {"days": d, "label": f"{d}d left", "state": "soon"}
    if d <= WARRANTY_WATCH_DAYS:
        return {"days": d, "label": f"{d}d left", "state": "watch"}
    return {"days": d, "label": f"{d}d left", "state": "ok"}


def _where(q: str = "", filters: dict | None = None,
           ids: list | None = None) -> tuple[str, list]:
    """The WHERE clause behind the list, the totals and the export.

    One place, so what you see, what the tiles count and what a CSV contains
    can never disagree — the surprise of exporting the whole inventory while
    looking at a filtered page comes from having two of these.
    """
    where, params = [], []
    if q:
        # every text column, so one box finds a serial, an IP or a hostname
        text_cols = [n for n, t in COLUMNS if t.startswith("TEXT")]
        where.append("(" + " OR ".join(f"COALESCE({c},'') LIKE ?" for c in text_cols) + ")")
        params += [f"%{q}%"] * len(text_cols)
    for col, val in (filters or {}).items():
        if col == "class":
            clause, extra = _class_clause(val)
            if clause:
                where.append(clause)
                params += extra
        elif val and col in {n for n, _t in COLUMNS}:
            where.append(f"COALESCE({col},'')=?")
            params.append(val)
    if ids:
        where.append(f"id IN ({', '.join('?' * len(ids))})")
        params += list(ids)
    return (" WHERE " + " AND ".join(where)) if where else "", params


def _class_clause(value: str) -> tuple[str, list]:
    """SQL for physical-or-virtual, from the words in `kind`."""
    likes = " OR ".join(["LOWER(COALESCE(kind,'')) LIKE ?"] * len(VIRTUAL_WORDS))
    params = [f"%{w}%" for w in VIRTUAL_WORDS]
    if value == "virtual":
        return f"({likes})", params
    if value == "physical":
        # a kind must be recorded to count as physical: "not virtual" and
        # "not filled in" are different things
        return f"(COALESCE(kind,'') <> '' AND NOT ({likes}))", params
    return "", []


def kind_class(kind: str) -> str:
    """Which of the two a kind belongs to, or "" when nothing was recorded."""
    k = (kind or "").lower()
    if not k:
        return ""
    return "virtual" if any(w in k for w in VIRTUAL_WORDS) else "physical"


def search(q: str = "", filters: dict | None = None, sort: str = "hostname",
           desc: bool = False, limit: int = 500, offset: int = 0,
           ids: list | None = None) -> dict:
    """Filtered, sorted page of assets plus the total that matched."""
    sql_where, params = _where(q, filters, ids)
    col = sort if sort in SORTABLE else "hostname"
    c = _conn()
    total = c.execute(f"SELECT COUNT(*) FROM assets{sql_where}", params).fetchone()[0]

    if col in ADDRESS_COLS:
        # ordering by address needs the octets compared as numbers, which no
        # engine does for a text column. An inventory is small enough to sort
        # the matching set here rather than store a second, derived column.
        rows = c.execute(f"SELECT * FROM assets{sql_where}", params).fetchall()
        addressed = [r for r in rows if _addr_key(r[col])[0] == 0]
        rest = [r for r in rows if _addr_key(r[col])[0] != 0]
        addressed.sort(key=lambda r: (_addr_key(r[col]),
                                      (r["hostname"] or "").lower()), reverse=desc)
        rest.sort(key=lambda r: (r["hostname"] or "").lower())
        # rows with no address stay at the end whichever way the column is
        # sorted: they are missing data, not the smallest or largest value
        page = (addressed + rest)[offset:offset + limit]
    else:
        order = f" ORDER BY {col} {'DESC' if desc else 'ASC'}, hostname ASC"
        page = c.execute(f"SELECT * FROM assets{sql_where}{order} LIMIT ? OFFSET ?",
                         params + [limit, offset]).fetchall()
    return {"rows": [_row(r) for r in page], "total": total,
            "limit": limit, "offset": offset}


def _addr_key(value) -> tuple:
    """Sort key for an address. Anything that is not four numbers — a DNS name,
    a blank — sorts after the addresses rather than being dropped."""
    parts = str(value or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), "")
    return (1, (), str(value or "").lower())


def distinct(column: str) -> list:
    """Values this deployment already uses — the source of every suggestion."""
    if column not in {n for n, _t in COLUMNS}:
        return []
    rows = _conn().execute(
        f"SELECT DISTINCT {column} AS v FROM assets "
        f"WHERE COALESCE({column},'') <> '' ORDER BY v COLLATE NOCASE").fetchall()
    return [r["v"] for r in rows]


def suggestions() -> dict:
    """Per-field pickers: what is already in use, plus neutral examples only
    while a field is still empty."""
    out = {}
    for col in SUGGESTED:
        vals = distinct(col)
        out[col] = vals or EXAMPLES.get(col, [])
    return out


def attribute_keys() -> list:
    """Custom attribute names already in use, so they can be offered again."""
    keys = set()
    for r in _conn().execute("SELECT attributes FROM assets "
                             "WHERE COALESCE(attributes,'') <> ''"):
        try:
            keys.update(json.loads(r["attributes"]).keys())
        except (TypeError, ValueError):
            continue
    return sorted(keys)


def stats(q: str = "", filters: dict | None = None) -> dict:
    """Headline counts for the page, computed by the database.

    Follows the same filter as the list, so the tiles describe what is on
    screen. The breakdown deliberately does not: it is how you get from one
    filter to another, and a breakdown of the current filter would only ever
    show the value you already picked.
    """
    c = _conn()
    sql_where, params = _where(q, filters)
    total = c.execute(f"SELECT COUNT(*) FROM assets{sql_where}", params).fetchone()[0]
    by = {}
    for col in BREAKDOWN:
        by[col] = [{"v": r["v"] or "unset", "n": r["n"]} for r in c.execute(
            f"SELECT COALESCE({col},'') AS v, COUNT(*) AS n FROM assets "
            f"GROUP BY v ORDER BY n DESC LIMIT 8")]
    caps = c.execute(f"SELECT SUM(cpu) AS cpu, SUM(ram_gb) AS ram, "
                     f"SUM(disk_gb) AS disk FROM assets{sql_where}",
                     params).fetchone()
    # the cut-off dates are computed here rather than in SQL: date arithmetic is
    # the one thing every engine spells differently, and this keeps the query
    # standard (see db.py on staying portable)
    today = date.today()
    horizon = (today + timedelta(days=WARRANTY_HORIZON_DAYS)).isoformat()
    today = today.isoformat()
    more = " AND " if sql_where else " WHERE "
    soon = c.execute(
        f"SELECT COUNT(*) FROM assets{sql_where}{more}"
        "COALESCE(warranty_until,'') <> '' "
        "AND warranty_until <= ? AND warranty_until >= ?",
        params + [horizon, today]).fetchone()[0]
    expired = c.execute(
        f"SELECT COUNT(*) FROM assets{sql_where}{more}"
        "COALESCE(warranty_until,'') <> '' AND warranty_until < ?",
        params + [today]).fetchone()[0]
    # physical and virtual counted inside whatever filter is in force, using the
    # same clause the tiles link to, so the number and the link always agree
    classes = {}
    for name in CLASSES:
        clause, extra = _class_clause(name)
        classes[name] = c.execute(
            f"SELECT COUNT(*) FROM assets{sql_where}{more}{clause}",
            params + extra).fetchone()[0]
    return {"total": total, "by": by, "classes": classes,
            "cpu": caps["cpu"] or 0, "ram": caps["ram"] or 0,
            "disk": caps["disk"] or 0,
            "warranty_soon": soon, "warranty_expired": expired}


# ── bulk ───────────────────────────────────────────────────────
def export_rows(q: str = "", filters: dict | None = None,
                ids: list | None = None, sort: str = "hostname",
                desc: bool = False) -> tuple[list, list]:
    """Flattened rows for CSV export — the same set the page is showing.

    Defaults to everything, but a filtered view or a selection exports exactly
    that: a CSV that quietly contains more than the screen did is worse than no
    export at all, because it looks like it worked.
    """
    names = [n for n, _t in COLUMNS if n != "attributes"]
    extra = attribute_keys()
    header = names + [f"attr_{k}" for k in extra]
    rows = search(q=q, filters=filters, ids=ids, sort=sort, desc=desc,
                  limit=EXPORT_MAX)["rows"]
    out = []
    for d in rows:
        out.append([d.get(n) if d.get(n) is not None else "" for n in names]
                   + [d["attributes"].get(k, "") for k in extra])
    return header, out


def import_rows(rows: list, actor: str = "") -> dict:
    """Create or update from parsed CSV rows.

    Matching is by serial first and hostname second: a machine keeps its serial
    when it is renamed, so that is the more stable identity.
    """
    created = updated = skipped = 0
    errors = []
    c = _conn()
    c.execute("BEGIN")
    try:
        for i, row in enumerate(rows, start=2):
            form = {k: v for k, v in row.items() if v not in (None, "")}
            host = (form.get("hostname") or "").strip()
            serial = (form.get("serial") or "").strip()
            if not host and not serial:
                skipped += 1
                continue
            found = None
            if serial:
                found = c.execute("SELECT id FROM assets WHERE serial=?",
                                  (serial,)).fetchone()
            if not found and host:
                found = c.execute("SELECT id FROM assets WHERE hostname=?",
                                  (host,)).fetchone()
            try:
                if found:
                    update(found["id"], form, actor)
                    updated += 1
                else:
                    create(form, actor)
                    created += 1
            except Exception as e:                            # noqa: BLE001
                errors.append(f"row {i}: {e}")
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return {"created": created, "updated": updated, "skipped": skipped,
            "errors": errors[:10]}


def count() -> int:
    return _conn().execute("SELECT COUNT(*) FROM assets").fetchone()[0]
