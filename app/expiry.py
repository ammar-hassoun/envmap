"""Everything that runs out, on one clock, with the renewal story attached.

WHY THIS EXISTS
    Four parts of this portal already count down to something, and each one
    invented its own vocabulary to do it: hardware warranty says
    expired/soon/watch, subscriptions say expired/soon/charged/inactive,
    certificates carry three separate "within 30 days" flags in three modules,
    and spend has its own. None of them can see each other, so nobody can
    answer "what needs renewing this month" without opening four pages and
    holding the dates in their head.

THE GAP THAT MADE IT WORTH BUILDING
    Only cert-manager's *Certificate objects* were ever read — what cert-manager
    has been asked to manage. Nothing opened the TLS secrets, so any certificate
    installed by hand, or issued by something no longer running, was invisible.
    Measured against one real cluster the first time this ran: eight serving
    certificates, six of them not managed by cert-manager, and one of those
    expired ninety-seven days ago and still installed. That is the entire case
    for this page — the certificates that renew themselves were never the
    problem.

RENEWAL IS THE COLUMN THAT MATTERS
    A date alone does not tell you whether to act. A cert-manager certificate
    thirty days out needs nothing; a hand-installed one thirty days out needs a
    person and a change window. So every row carries how it renews —
    automatic, manual, or unknown — and the page leads with what will not renew
    itself. "Expiring soon" sorted by date alone puts sixty self-renewing
    certificates in front of the one that matters.

BANDS, NOT A SINGLE THRESHOLD
    Thirty days is the wrong horizon for a support contract and the right one
    for a certificate. The bands here are shared so the colours mean the same
    thing everywhere, and each source keeps its own opinion of when to worry by
    choosing what it reports, not by redefining "soon".

PERMISSIONS
    Same model as the timeline: the area opens the page, and every source is
    gated again by the area that governs its own page. A role with the radar
    and nothing else sees an empty page that says so. A subscription
    is the exception — it has no area, it is already on the sidebar for anyone
    who can see it, and an install that is about to lock should say so to
    whoever is looking.
"""
from __future__ import annotations

from datetime import date, datetime
from urllib.parse import quote

from . import db, gather, rbac

# key -> (label, icon, the areas that can contribute)
# The middle field names a line icon in app/logodata.py, not an emoji.
SOURCES = {
    "certificate": ("Certificates", "shield-check", ("clusters", "certs", "edge")),
    "warranty": ("Hardware warranty", "server", ("assets",)),
    "subscription": ("Subscriptions & licences", "receipt", ("spend",)),
    "invite": ("Invites & resets", "mail", ("users",)),
}

# One vocabulary for the whole page. Shared so a colour means the same thing
# whatever it is describing, which is the point of putting them together.
BANDS = (
    ("expired", "Expired", -10 ** 6, -1),
    ("critical", "Next 7 days", 0, 7),
    ("soon", "Next 30 days", 8, 30),
    ("watch", "Next 90 days", 31, 90),
    ("later", "Later", 91, 10 ** 6),
)
BAND_ORDER = [b[0] for b in BANDS]

# How a thing gets renewed. The difference between a quiet week and an outage.
AUTOMATIC, MANUAL, UNKNOWN = "automatic", "manual", "unknown"


# ── set aside ──────────────────────────────────────────────────
# THINGS THAT DO NOT NEED RENEWING, SAID ONCE. A page whose headline number
# counts certificates nobody intends to renew is a page people learn to
# discount, and a number that is discounted is worse than no number: it hides
# the one certificate that did matter among a dozen that never did.
#
# INSTALL-WIDE, NOT PER-PERSON. "this certificate does not need renewing" is a
# fact about the certificate, not somebody's preference -- and the overview it
# is meant to correct is read by everybody, so a per-user setting would leave
# the shared number as wrong as it was. Who and when and why are recorded,
# because a fact somebody asserted is one somebody may need to ask about.
_SCHEMA = """CREATE TABLE IF NOT EXISTS expiry_ignored (
        k TEXT PRIMARY KEY,
        kind TEXT DEFAULT '', name TEXT DEFAULT '',
        where_ TEXT DEFAULT '', reason TEXT DEFAULT '',
        who TEXT DEFAULT '', at TEXT DEFAULT '')"""


def _migrate(c) -> None:
    c.execute(_SCHEMA)


db.register(_migrate)


def ignore_key(row: dict) -> str:
    """The stable name for one thing across refreshes and renewals.

    NOT the date and NOT the serial. A certificate that is set aside must STAY
    set aside when it is reissued -- the point of setting it aside is that
    nobody intends to act on it -- so anything that changes when the
    certificate changes cannot be part of its name. What identifies it is the
    kind of thing, where it lives and what it is called, which is also exactly
    what somebody reads off the row before deciding.
    """
    import hashlib                                           # noqa: PLC0415
    raw = "\x1f".join((str(row.get("kind") or ""),
                       str(row.get("source") or ""),
                       str(row.get("where") or ""),
                       str(row.get("name") or "")))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def ignored_map() -> dict:
    """key -> the row that was set aside, for the page and for `collect`."""
    out = {}
    for r in db.q("SELECT k, kind, name, where_, reason, who, at "
                  "FROM expiry_ignored"):
        d = dict(r)
        d["where"] = d.pop("where_", "")
        out[d["k"]] = d
    return out


# The most rows anybody can hold back. Every read of the radar loads this
# whole table (`ignored_map`) to stamp `aside` onto each row, so it is on the
# path of the overview tile, the page and every filter -- and the route that
# writes it takes the row's identity FROM THE FORM, so nothing tied a stored
# key to a thing that exists. Unbounded growth on a table every read consults
# is the shape worth capping even when nobody is being hostile: a script that
# posts the form in a loop is indistinguishable from one that renews a lot.
MAX_ASIDE = 2000


class TooMany(Exception):
    """The set-aside list is full."""


def set_aside(row: dict, reason: str, who: str) -> str:
    """Stop counting one thing. Returns its key.

    The KIND is checked against the sources this module actually collects.
    It arrives from the form, and an unrecognised one could never match a
    real row -- so it would be a permanent entry in a table every read walks,
    describing nothing, that no page could offer a "count again" button for.
    """
    from datetime import timezone                            # noqa: PLC0415
    kind = str(row.get("kind") or "")
    if kind not in _FETCH:
        raise ValueError(f"there is nothing of kind {kind!r} to set aside")
    k = ignore_key(row)
    # Re-stating a reason on something already held back is an UPDATE, not a
    # new row, so it must not be refused when the list is full.
    if not db.q("SELECT 1 FROM expiry_ignored WHERE k = ?", (k,)):
        held = (db.q("SELECT COUNT(*) AS n FROM expiry_ignored") or [{}])[0]
        if int(dict(held).get("n") or 0) >= MAX_ASIDE:
            raise TooMany(
                f"{MAX_ASIDE} things are already held back — put some back on "
                "the clock before adding more")
    db.run("INSERT OR REPLACE INTO expiry_ignored "
           "(k, kind, name, where_, reason, who, at) VALUES (?,?,?,?,?,?,?)",
           (k, str(row.get("kind") or ""), str(row.get("name") or ""),
            str(row.get("where") or ""), (reason or "").strip()[:300],
            (who or "")[:120],
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")))
    invalidate()
    return k


def count_again(k: str) -> bool:
    """Put one thing back on the clock. True when there was one to put back.

    Asked before deleting, because `db.run` reports nothing about what it
    touched -- and "restored" printed over a key that was never set aside is
    the kind of message that teaches people not to read messages.
    """
    k = (k or "").strip()
    if not k or not db.q("SELECT 1 FROM expiry_ignored WHERE k = ?", (k,)):
        return False
    db.run("DELETE FROM expiry_ignored WHERE k = ?", (k,))
    invalidate()
    return True


def band(days: int | None) -> str:
    if days is None:
        return "later"
    for key, _label, lo, hi in BANDS:
        if lo <= days <= hi:
            return key
    return "later"


def _row(when, name: str, kind: str, where: str = "", detail: str = "",
         renewal: str = UNKNOWN, url: str = "", note: str = "",
         source: str = "", pid: str = "", cid: str = "",
         names: list | None = None, owner: str = "", renewer: str = "",
         life: int | None = None, age: int | None = None) -> dict | None:
    """One thing that runs out. None when there is no usable date — a countdown
    with nothing to count to is not information, and guessing today would put
    it at the top of the page.

    `pid`/`cid` are the PROJECT and CLUSTER this belongs to, when the source
    knows them. `where` is prose for a person to read ("cluster · namespace")
    and was the only place they appeared, which meant the only way to narrow
    the page to one cluster was a substring search over that sentence — it
    matched a namespace that happened to share a word, and it could not express
    "this project" at all. The ids travel beside the prose so a filter can be
    exact; `project`, `cluster` and `regions` are filled in by `collect` from
    the estate, because which regions a cluster serves changes without any
    certificate changing.
    """
    if when is None:
        return None
    if isinstance(when, datetime):
        when = when.date()
    if not isinstance(when, date):
        return None
    days = (when - date.today()).days
    return {"when": when, "days": days, "band": band(days), "kind": kind,
            # EVERY name on the certificate, not just the one in `name`. The
            # blast-radius walk compares the whole SAN list against the hosts
            # an ingress answers for, and they are free here -- the cluster
            # read that produced this row already had them. Empty for every
            # other kind, which is what keeps the row shape uniform.
            "names": list(names or []),
            # THE EVIDENCE, kept apart from the verdict. `renewal` is a claim
            # the portal makes; these are facts the API server and the
            # certificate stated, and a reader who can see them can disagree
            # with the claim. This is the half the radar never had: 279 rows
            # asserting "needs a person" with nothing on the row to check it
            # against.
            "owner": owner, "renewer": renewer,
            "life": life, "age": age,
            "name": name, "where": where, "detail": detail,
            "renewal": renewal, "url": url, "note": note,
            "source": source or kind,
            "pid": pid or "", "cid": cid or "",
            "project": "", "cluster": "", "regions": (),
            "on": when.strftime("%Y-%m-%d"),
            "month": when.strftime("%Y-%m")}


def _date(value) -> date | None:
    """Any of the shapes these sources produce, as a local date."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value).date()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


# ── certificates ───────────────────────────────────────────────
def _certificates(user, refresh: bool) -> tuple[list, list]:
    """Every certificate this portal can see, from all three places they live.

    The cluster read is the one that matters and the one that did not exist:
    the TLS secrets themselves, which is what is actually served, rather than
    cert-manager's opinion of what it manages.
    """
    from . import certs as certlib
    from . import cluster as clusterview
    # fleet for _pmap: the edge certificates below are collected in parallel,
    # and this import was missing — so the Expiry radar raised NameError for
    # anybody holding the edge area with at least one edge connection
    # configured. Not caught by any page test because both conditions have to
    # hold at once, and pyflakes says it plainly.
    from . import edge, fleet, store
    out, notes = [], []

    if rbac.may_area(user, "clusters"):
        allowed = rbac.visible_clusters(user, "clusters")
        for r in clusterview.everywhere("tls", refresh=refresh):
            if allowed is not None and r.get("cid") not in allowed:
                continue
            if r.get("error"):
                notes.append(f"{r.get('cluster', '?')}: certificates could not "
                             f"be read ({r['error']})")
                continue
            if not r.get("present"):
                continue
            if r.get("unreadable"):
                notes.append(f"{r.get('cluster', '?')}: {r['unreadable']} "
                             f"certificate(s) could not be parsed")
            for c in r.get("certs") or []:
                first = (c.get("domains") or [None])[0] or c["name"]
                more = len(c.get("domains") or [])
                out.append(_row(
                    _date(c.get("not_after")), first, "certificate",
                    where=f"{r.get('cluster', '')} · {c['namespace']}",
                    detail=(f"{c['name']}"
                            + (f" · +{more - 1} more name"
                               f"{'s' if more > 2 else ''}" if more > 1 else "")
                            + (f" · issued by {c['issuer']}" if c.get("issuer") else "")),
                    # auto = cert-manager OR an operator (e.g. CloudNativePG)
                    # that rotates its own TLS — those are not "needs a person".
                    #
                    # AN OVERDUE ONE READS AS MANUAL, deliberately, and that
                    # is the whole safety margin of trusting a renewer at all.
                    # `overdue` means something claims to renew this and the
                    # certificate's own dates say it has not — so it does need
                    # a person, it belongs in the count that matters, and the
                    # note below says which renewer let it happen. A fourth
                    # renewal state would have meant retuning every tile and
                    # the donut; this needs neither and fails in the safe
                    # direction.
                    renewal=(MANUAL if (not c.get("auto") or c.get("overdue"))
                             else AUTOMATIC),
                    # the clusters page keys off query params, not a path segment
                    # (/clusters/<cid> is no route → the "open" link 404'd)
                    url=(f"/clusters?project={quote(str(r.get('pid', '')))}"
                         f"&cluster={quote(str(r.get('cid', '')))}&tab=network"),
                    note=(f"{c.get('renewer') or 'something'} owns this and "
                          f"has not renewed it — it should have renewed by now"
                          if c.get("overdue") else
                          "only the dates could be read from this certificate"
                          if c.get("partial") else ""),
                    source="cluster",
                    names=c.get("domains") or [],
                    owner=c.get("owner", ""), renewer=c.get("renewer", ""),
                    life=c.get("lifetime_days"), age=c.get("age_days"),
                    pid=str(r.get("pid", "")), cid=str(r.get("cid", ""))))

        # cert-manager objects that are NOT ready are a renewal that has already
        # failed. The secret beside them still shows the old certificate, which
        # is the date that matters — this says why it will not move.
        for r in clusterview.everywhere("certs", refresh=refresh):
            if allowed is not None and r.get("cid") not in allowed:
                continue
            for c in r.get("certs") or []:
                if c.get("ready"):
                    continue
                notes.append(
                    f"{r.get('cluster', '')} · {c['namespace']}/{c['name']}: "
                    f"cert-manager is not renewing this "
                    f"({c.get('reason') or 'not ready'})")

    if rbac.may_area(user, "certs"):
        try:
            for o in certlib.orders():
                if o.get("status") != "ready" or not o.get("expires_at"):
                    continue
                # "issued by this portal" IS NOT TRUE OF ALL OF THEM. A
                # provider-signed order was issued by somebody else entirely;
                # the portal only generated the CSR and kept the key. Saying
                # otherwise sends whoever reads this row to the wrong place
                # when they go looking for who can reissue it.
                out.append(_row(
                    _date(o["expires_at"]), o.get("name") or "certificate",
                    "certificate",
                    where=(o.get("ca_label") if o.get("external")
                           else o.get("ca") or "ACME"),
                    detail=("signed by a provider; the key is held here"
                            if o.get("external") else "issued by this portal"),
                    # the portal issues these but does not renew them on its
                    # own — the button is manual, and saying otherwise here
                    # would be the most dangerous lie on the page
                    # the order view is /certs?id=<oid> (a query param), not a
                    # path segment — /certs/<id> is no route and 404'd
                    renewal=MANUAL, url=f"/certs?id={quote(str(o.get('id', '')))}",
                    source="acme"))
        except Exception as e:                                 # noqa: BLE001
            notes.append(f"certificate orders could not be read ({e})")

    if rbac.may_area(user, "edge"):
        def one(conn):
            try:
                return conn, edge.inventory(conn, refresh=refresh), ""
            except Exception as e:                             # noqa: BLE001
                return conn, None, str(e)

        conns = store.all_edge()
        for got in (fleet._pmap(one, conns, workers=min(4, len(conns)))
                    if conns else []):
            if not got:
                continue
            conn, inv, err = got
            if inv is None:
                notes.append(f"{conn.get('name', '?')}: edge certificates "
                             f"unavailable ({err})")
                continue
            for group in inv.get("groups") or []:
                if group.get("key") != "certs":
                    continue
                for row in group.get("rows") or []:
                    out.append(_row(
                        _date(row.get("extra")), row.get("name") or "certificate",
                        "certificate",
                        where=f"{conn.get('name', '')} · {row.get('zone', '')}",
                        detail=row.get("kind", ""),
                        # a CDN pack renews itself while the zone is active
                        renewal=AUTOMATIC, url="/edge", source="edge"))
    return [r for r in out if r], notes


# ── the rest ───────────────────────────────────────────────────
def _warranty(user, refresh: bool) -> tuple[list, list]:
    del refresh
    if not rbac.may_area(user, "assets"):
        return [], []
    from . import assets
    out = []
    # search() returns a page, not a list: {"rows": [...], "total": n}
    for a in assets.search(sort="warranty_until", limit=2000).get("rows", []):
        when = _date(a.get("warranty_until"))
        if when is None:
            continue
        # `env`, NOT `environment`. The column is `env` (assets.py:49) and
        # this read `a.get("environment")`, which is never present -- so every
        # warranty row on the radar has shown only its location for as long as
        # the feature has existed, and a machine with no location typed showed
        # a blank `where`. Nothing failed; the sentence was just half missing.
        where = " · ".join(x for x in (a.get("location"), a.get("env")) if x)
        out.append(_row(when, a.get("hostname") or a.get("serial") or "machine",
                        "warranty", where=where,
                        detail=" · ".join(x for x in (a.get("model"),
                                                      a.get("serial")) if x),
                        renewal=MANUAL, url=f"/assets/{a.get('id', '')}",
                        # `assets.search` already returns the project, and
                        # `_place_index` needs it to narrow the row by place --
                        # without it a warranty row could never be filtered to
                        # a project even though the answer was in hand.
                        pid=a.get("pid") or "",
                        source="assets"))
    return [r for r in out if r], []


def _subscriptions(user, refresh: bool) -> tuple[list, list]:
    del refresh
    if not rbac.may_area(user, "spend"):
        return [], []
    from . import spend
    out = []
    for s in spend.search(status="all", sort="renews"):
        when = _date(s.get("renews"))
        if when is None:
            continue
        state = spend.renewal_state(s.get("renews"), s.get("status", ""),
                                    s.get("cycle", ""))
        # a cancelled row has nothing to renew, and a one-off that has already
        # been charged is a thing that happened, not a thing that lapsed
        if state.get("state") in ("inactive", "charged"):
            continue
        out.append(_row(
            when, s.get("name") or "subscription", "subscription",
            where=s.get("vendor") or "",
            detail=" · ".join(x for x in (
                s.get("category_label"),
                f"{s.get('currency', '')} {s.get('cost', '')}".strip(),
                s.get("cycle_label")) if x),
            renewal=AUTOMATIC if s.get("auto_renew") else MANUAL,
            url="/spend", source="spend"))
    return [r for r in out if r], []


def _invites(user, refresh: bool) -> tuple[list, list]:
    del refresh
    if not rbac.may_area(user, "users"):
        return [], []
    from . import auth, invite
    out = []
    for uid, u in (auth.users() or {}).items():
        for kind in ("invite", "reset"):
            try:
                got = invite.outstanding(uid, kind)
            except Exception:                                  # noqa: BLE001
                continue
            if not got or not got.get("expires"):
                continue
            out.append(_row(
                _date(got["expires"]),
                f"{kind} for {u.get('email', uid)}", "invite",
                where=u.get("name") or "", detail=f"issued {got.get('created', '')[:10]}",
                renewal=MANUAL, url="/admin/users", source="invite"))
    return [r for r in out if r], []


_FETCH = {"certificate": _certificates, "warranty": _warranty,
          "subscription": _subscriptions, "invite": _invites}


# ── collection ─────────────────────────────────────────────────
# The cluster fan-out is the only expensive source here; the rest are local
# reads costing under a millisecond. Same bargain as the timeline: run them
# together, serve what is already collected, refresh behind the reader.
# And the page never waits for the slow one: reading the TLS secrets of every
# cluster costs seconds, and an unreachable cluster costs its whole timeout.
# Whatever has answered by FIRST_PAINT is rendered, the rest is named on the
# page and keeps collecting. Same bargain as the timeline, for the same reason.
CACHE_TTL = 60.0
CACHE_HARD = 15 * 60.0
FIRST_PAINT = 1.5

_GATHER = gather.Gatherer("expiry", ttl=CACHE_TTL, hard=CACHE_HARD,
                          first_paint=FIRST_PAINT, workers=5)


def invalidate() -> None:
    _GATHER.invalidate()


def _key(user, kinds) -> tuple:
    return ((user or {}).get("id", "?"), frozenset(rbac.areas_of(user)),
            tuple(sorted(kinds)))


def _collect_sources(user, kinds, refresh: bool) -> dict:
    jobs = [(k, SOURCES[k][0], (lambda kk=k: _FETCH[kk](user, refresh)))
            for k in kinds]
    got = _GATHER.gather(_key(user, kinds), jobs, refresh)
    rows, notes = [], list(got["errors"])
    for got_rows, said in got["parts"].values():
        rows += got_rows
        notes += said
    return {"rows": rows, "notes": notes, "pending": got["pending"],
            "stale": got["stale"]}


def _place_index() -> dict:
    """cid → {project, pid, regions} for every registered cluster.

    Read from the estate at request time rather than baked into the rows,
    because which regions a cluster serves is edited on the clusters page and
    changes without any certificate changing — a cached row would keep
    answering with yesterday's mapping. It is a couple of dict walks over data
    already in memory.

    `regions` is a SET: one cluster commonly serves several (the dev cluster
    here runs UAE, CR and KE), so "in region X" is a membership test, not an
    equality.
    """
    from . import store
    idx: dict = {}
    view = store.projects()
    for pid, p in view.items():
        for cid, c in (p.get("clusters") or {}).items():
            idx[cid] = {"pid": pid, "project": p.get("name", "") or pid,
                        "cluster": c.get("name", "") or cid, "regions": set()}
    for cid, rows in store.serves(view).items():
        if cid in idx:
            idx[cid]["regions"].update(r["region"] for r in rows)
    return idx


# ── blast radius ───────────────────────────────────────────────
EXACT, WILDCARD = "exact", "wildcard"


def covers(san: str, host: str) -> str:
    """How this certificate name covers this host name — "" when it does not.

    A WILDCARD MATCHES EXACTLY ONE LABEL (RFC 6125): `*.example.com` covers
    `api.example.com` and does NOT cover `api.eu.example.com`. Matching by
    suffix alone is the obvious shortcut and it OVERSTATES the blast radius,
    which is the one direction this answer must never be wrong in — somebody
    reads it to decide whether a renewal is urgent, and a list padded with
    hosts the certificate does not actually serve makes every future list
    untrustworthy.

    Both sides are lowered and a trailing root dot is dropped, because a DNS
    name is case-insensitive and `example.com.` and `example.com` are the same
    name written two ways.
    """
    san = (san or "").strip().lower().rstrip(".")
    host = (host or "").strip().lower().rstrip(".")
    if not san or not host:
        return ""
    if san == host:
        return EXACT
    if san.startswith("*."):
        suffix = san[1:]                                  # ".example.com"
        stem = host[: -len(suffix)] if host.endswith(suffix) else ""
        if stem and "." not in stem:
            return WILDCARD
    return ""


def service_names(namespace: str, name: str) -> list:
    """Every in-cluster name a Service is reached by, longest first.

    Only `<name>.<ns>.svc.cluster.local` is a name the cluster's DNS actually
    SERVES. The shorter forms — `<name>`, `<name>.<ns>`, `<name>.<ns>.svc` —
    resolve only through a pod's own `search` list, which is why they appear on
    certificates: the client connecting is a pod. All four are matched because
    all four are what operators put in a SAN.

    The cluster domain is assumed to be `cluster.local`. It is configurable,
    and reading it would mean another cluster call for a name that is the
    default essentially everywhere — so the shorter forms carry the match on
    an estate that changed it, and the answer degrades rather than breaking.
    """
    if not namespace or not name:
        return []
    return [f"{name}.{namespace}.svc.cluster.local",
            f"{name}.{namespace}.svc",
            f"{name}.{namespace}",
            name]


def blast_radius(pid: str, cid: str, domains: list,
                 refresh: bool = False) -> dict:
    """What stops working if this certificate is not renewed.

    WHY THIS IS ON DEMAND rather than collected with the radar. The names on a
    certificate are already in hand when the row is built (`everywhere("tls")`
    carries `domains`), but the hosts an ingress ROUTES are not — that is the
    `network` part, and asking for it across the estate would put a
    twenty-four-cluster fan-out behind a page that already has one. Measured
    on this estate, a bare fan-out is 7.5s. So the walk runs for ONE
    certificate on ONE cluster, when somebody asks the question, through the
    same cached part the cluster's own Network tab reads — usually already
    warm, and never more than one cluster cold.

    THE MATCH IS A NAME MATCH, and the result says so per host. A certificate
    does not record what serves it; the portal is comparing the names on it
    against the names an ingress answers for. That is the honest link and it
    is right almost always, but it is inference and not a fact the cluster
    stated, so every hit carries HOW it matched and the reader can disagree.

    A SAN THAT MATCHES NOTHING IS PART OF THE ANSWER, not a gap in it. A
    wildcard commonly covers names nothing routes yet, and a name that no
    longer routes anywhere is the interesting case: it may mean the
    certificate is broader than it needs to be, or that something moved.
    """
    from . import cluster as clusterview                      # noqa: PLC0415
    from . import store                                       # noqa: PLC0415

    doms = [d for d in (domains or []) if (d or "").strip()]
    out = {"cluster": "", "domains": doms, "hosts": [], "unmatched": [],
           "services": [], "namespaces": [], "environments": [],
           "services_in": [], "ambiguous": [], "internal": False,
           "routes_seen": 0, "services_seen": 0, "error": ""}
    c = store.get_cluster(pid, cid) if pid and cid else None
    if not c:
        out["error"] = "that cluster is no longer registered"
        return out
    out["cluster"] = c.get("name") or cid
    # The environments this CLUSTER serves. Cluster granularity, deliberately
    # not claimed as per-service: which values file declares the workload
    # behind a route is the checkout's answer, and this must not imply a
    # precision it did not pay for. The page labels it as the cluster's.
    out["environments"] = store.serves(store.projects(), pid).get(cid, [])
    if not doms:
        out["error"] = "this certificate carries no host names to trace"
        return out

    net = clusterview.part(c, "network", refresh=refresh)
    if net.get("error"):
        # UNREACHABLE IS NOT "NOTHING USES IT". An empty answer here would
        # read as a certificate nobody needs, which is the worst possible
        # wrong answer for a renewal decision.
        out["error"] = net["error"]
        return out

    routes = net.get("routes") or []
    out["routes_seen"] = len(routes)
    out["services_seen"] = len(net.get("services") or [])
    hit: dict = {}
    for r in routes:
        # `tls_hosts` overlaps `hosts` on a TLS ingress, so they are merged and
        # de-duplicated rather than counted twice.
        for host in dict.fromkeys(list(r.get("hosts") or [])
                                  + list(r.get("tls_hosts") or [])):
            # THE BEST MATCH OVER THE WHOLE SAN LIST, not the first one. A
            # certificate often carries both `*.example.com` and
            # `api.example.com`; the exact name is the better explanation of
            # why this host is served, so it wins the label. The first version
            # broke out of this loop on the first hit, which made the
            # exact-wins branch unreachable -- and because the wildcard is
            # usually listed first, the answer was "wildcard" for a host the
            # certificate names outright. Caught by a test, not by reading.
            best = ""
            best_san = ""
            for san in doms:
                how = covers(san, host)
                if not how:
                    continue
                if how == EXACT:
                    best, best_san = EXACT, san
                    break                       # nothing beats an exact name
                if not best:
                    best, best_san = how, san
            if not best:
                continue
            key = (host or "").strip().lower().rstrip(".")
            row = hit.setdefault(key, {"host": key, "how": best,
                                       "san": best_san,
                                       "routes": [], "services": []})
            if best == EXACT and row["how"] != EXACT:
                row["how"], row["san"] = EXACT, best_san
            where = f"{r.get('namespace', '')}/{r.get('name', '')}"
            if where not in [x["where"] for x in row["routes"]]:
                row["routes"].append({"where": where, "kind": r.get("kind", ""),
                                      "namespace": r.get("namespace", ""),
                                      "name": r.get("name", ""),
                                      "class": r.get("class", "")})
            for svc in r.get("services") or []:
                if svc not in row["services"]:
                    row["services"].append(svc)

    out["hosts"] = sorted(hit.values(), key=lambda h: h["host"])

    # ── THE INTERNAL PASS ────────────────────────────────────────────────
    # Most certificates in a real estate are never ingress-served: a
    # CloudNativePG server cert, an operator's webhook cert, anything doing
    # in-cluster mTLS. Matching only ingress hosts answered "nothing matched"
    # for the majority of rows, which reads as a broken button rather than as
    # the honest "these are in-cluster names". `net["services"]` was already
    # fetched by the same call and simply ignored.
    #
    # SAME READ, no extra cluster call.
    svc_hit: dict = {}
    ambiguous: dict = {}
    # EVERY SAN THAT MATCHED SOMETHING, not just the one form kept on each
    # service row. A CNPG certificate carries the whole ladder -- bare,
    # `.ns`, `.ns.svc`, `.ns.svc.cluster.local` -- all four naming ONE
    # service; only the longest is kept as that row's evidence, so scoring
    # `unmatched` from the kept form reported the other three as "routed
    # nowhere". Four names, one service, and three of them read as alarming.
    matched_sans: set = set()
    for svc in net.get("services") or []:
        ns, nm = svc.get("namespace", ""), svc.get("name", "")
        for form in service_names(ns, nm):
            for san in doms:
                if covers(san, form) != EXACT:
                    # A wildcard SAN against a service name would match half
                    # the cluster; only an exact in-cluster name is evidence.
                    continue
                key = f"{ns}/{nm}"
                # A BARE `<name>` SAN IS AMBIGUOUS across namespaces, and
                # guessing which one is exactly the overstatement this whole
                # function refuses. It is recorded and shown as ambiguous, and
                # deliberately contributes to no tally.
                if form == nm:
                    ambiguous.setdefault(san, set()).add(key)
                    continue
                matched_sans.add(san)
                row = svc_hit.setdefault(key, {
                    "service": nm, "namespace": ns, "san": san,
                    "form": form, "type": svc.get("type", ""),
                    "published": bool(svc.get("published")),
                    "ports": list(svc.get("ports") or [])})
                # the longest form that matched is the most specific evidence
                if len(form) > len(row["form"]):
                    row["form"], row["san"] = form, san
    # A BARE NAME WITH ONE CANDIDATE IS NOT AMBIGUOUS -- it is resolved.
    # Ambiguity is two namespaces offering the same service name, which is the
    # only case where picking one would be a guess. Reporting the single-
    # candidate case as ambiguous put a warning next to every ordinary CNPG
    # certificate, since the bare form is always on them.
    for san, where in list(ambiguous.items()):
        if len(where) != 1:
            continue
        key = next(iter(where))
        ns, nm = key.split("/", 1)
        matched_sans.add(san)
        row = svc_hit.get(key)
        if row is None:
            svc = next((v for v in (net.get("services") or [])
                        if v.get("namespace") == ns and v.get("name") == nm), {})
            svc_hit[key] = {"service": nm, "namespace": ns, "san": san,
                            "form": nm, "type": svc.get("type", ""),
                            "published": bool(svc.get("published")),
                            "ports": list(svc.get("ports") or [])}
        del ambiguous[san]
    out["services_in"] = sorted(svc_hit.values(),
                                key=lambda r: (r["namespace"], r["service"]))
    # `sorted` needs a KEY here: these are dicts, and two of them are not
    # orderable against each other -- it raised only once a second ambiguous
    # name appeared, which a one-item fixture would never have shown.
    out["ambiguous"] = sorted(
        ({"san": san, "could_be": sorted(where)}
         for san, where in ambiguous.items()
         if not any(h["san"] == san for h in out["hosts"])
         and not any(r["san"] == san for r in out["services_in"])),
        key=lambda a: a["san"])
    out["internal"] = bool(out["services_in"] or out["ambiguous"])
    # Every SAN that covered nothing anywhere -- ingress OR in-cluster -- in
    # the order the certificate lists them. A name matched internally is NOT
    # unmatched, which the first version got wrong by only consulting hosts.
    named = ({h["san"] for h in out["hosts"]}
             | matched_sans
             | {a["san"] for a in out["ambiguous"]})
    out["unmatched"] = [
        d for d in doms
        if d not in named and not any(covers(d, h["host"]) for h in out["hosts"])
    ]
    out["services"] = sorted({s for h in out["hosts"] for s in h["services"]})
    out["namespaces"] = sorted({r["namespace"] for h in out["hosts"]
                                for r in h["routes"] if r["namespace"]})
    return out


def facets(rows: list) -> dict:
    """The project / cluster / region values PRESENT in these rows, with counts.

    Built from the rows rather than from the estate, so the dropdowns never
    offer a choice that leads to an empty page — an estate has twenty-four
    clusters and only some of them have anything expiring. Each carries its
    count for the same reason the tiles do: the number tells you whether it is
    worth opening before you open it.
    """
    def tally(get):
        out: dict = {}
        for r in rows:
            for v in get(r):
                if v:
                    out[v] = out.get(v, 0) + 1
        return [{"value": k, "label": lbl, "n": n}
                for (k, lbl), n in sorted(out.items(),
                                          key=lambda kv: (-kv[1], kv[0][1].lower()))]
    return {
        "projects": tally(lambda r: [(r["pid"], r["project"])] if r.get("pid") else []),
        "clusters": tally(lambda r: [(r["cid"], r["cluster"])] if r.get("cid") else []),
        "regions": tally(lambda r: [(x, x) for x in (r.get("regions") or ())]),
    }


def collect(user, kinds=None, horizon: int = 0, q: str = "",
            renewal: str = "", refresh: bool = False, band_only: str = "",
            month: str = "", project: str = "", cluster: str = "",
            region: str = "", aside: bool = False) -> dict:
    """Everything that runs out, soonest first.

    `horizon` in days narrows to what falls due inside it; 0 means everything,
    including what has already expired — which is the first thing anyone wants
    to see and the last thing a "next 30 days" filter would show them.

    `kinds` narrows the ROWS, not the collection: every source this person may
    see is always read. It used to narrow the collection, and the tab bar is
    built from what was collected — so choosing "Certificates" left the other
    tabs with no count, and a tab with no count is not rendered at all. Picking
    any tab made every other tab disappear. Reading everything also costs less
    than it looks: one cached collection serves the whole page instead of a
    different one per tab.
    """
    want = set(kinds) if kinds else set(SOURCES)
    hidden, ask = [], []
    for key, (label, _icon, areas) in SOURCES.items():
        if areas and not any(rbac.may_area(user, a) for a in areas):
            hidden.append(label)
            continue
        ask.append(key)

    got = _collect_sources(user, ask, refresh)
    # The estate's own words for where a row lives, stamped on after the cache:
    # the collection is expensive and shared, the mapping is cheap and moves.
    idx = _place_index()
    for r in got["rows"]:
        at = idx.get(r.get("cid") or "")
        if at:
            r["project"] = at["project"]
            r["cluster"] = at["cluster"]
            r["regions"] = tuple(sorted(at["regions"]))
            if not r.get("pid"):
                r["pid"] = at["pid"]
    everything = sorted(got["rows"],
                        key=lambda r: (r["days"], r["name"].lower()))
    # The tab is a scope, not a filter: the tiles and the chart describe it
    # whole, so clicking either one opens a list of exactly the size it
    # promised. The tab counts describe every source, because that is how you
    # get out of the tab you are in.
    # SET ASIDE, AND OUT OF EVERY NUMBER ON THE PAGE. Each row carries its own
    # key and whether it was set aside, so a template can offer the action
    # without recomputing an identity; the scope the tiles and the chart
    # describe then excludes them, which is the whole point -- a headline
    # number that counts certificates nobody intends to renew is a number
    # people learn to discount.
    #
    # NOT DELETED, though: `aside=True` shows exactly the ones held back, so
    # they can be read and put back. Something invisible cannot be corrected,
    # and an assertion nobody can review is worse than a wrong count.
    put_aside = ignored_map()
    for r in everything:
        r["key"] = ignore_key(r)
        r["aside"] = r["key"] in put_aside
        r["aside_why"] = (put_aside.get(r["key"]) or {}).get("reason", "")
        r["aside_who"] = (put_aside.get(r["key"]) or {}).get("who", "")
    kept = [r for r in everything if r["kind"] in want]
    scope = [r for r in kept if r["aside"]] if aside else \
            [r for r in kept if not r["aside"]]

    rows = list(scope)
    # WHERE it lives, narrowed exactly. A row that names no cluster — a
    # subscription — simply does not match a cluster or a
    # project, which is the honest answer rather than a reason to keep it.
    if project:
        rows = [r for r in rows if r.get("pid") == project]
    if cluster:
        rows = [r for r in rows if r.get("cid") == cluster]
    if region:
        rows = [r for r in rows if region in (r.get("regions") or ())]
    # The tiles are the filter: clicking "Expired" must show the expired ones
    # and nothing else, which a "next N days" horizon cannot express.
    if band_only in BAND_ORDER:
        rows = [r for r in rows if r["band"] == band_only]
    if month:
        rows = [r for r in rows if r["month"] == month]
    if horizon:
        rows = [r for r in rows if r["days"] <= horizon]
    if renewal in (AUTOMATIC, MANUAL, UNKNOWN):
        rows = [r for r in rows if r["renewal"] == renewal]
    if q:
        needle = q.lower()
        rows = [r for r in rows
                if needle in f"{r['name']} {r['where']} {r['detail']}".lower()]
    return {"rows": rows, "notes": got["notes"], "hidden": hidden,
            "asked": ask, "stale": got["stale"], "all_rows": everything,
            "scope": scope, "pending": got.get("pending", []),
            "counts": {k: sum(1 for r in everything if r["kind"] == k)
                       for k in ask},
            "facets": facets(scope),
            # The tile that says how many are set aside links to aside=1, and
            # the count is of exactly the rows that link opens -- counted over
            # the same `kept` scope the tab is showing, not over everything.
            "aside_count": sum(1 for r in kept if r["aside"]),
            "aside": aside,
            "summary": summary(scope)}


def summary(rows: list) -> dict:
    """The numbers the page leads with.

    `act` is the one that matters: what expires inside ninety days and will not
    renew itself. Everything else on this page is context for that number.
    """
    bands = {key: 0 for key, *_ in BANDS}
    for r in rows:
        bands[r["band"]] += 1
    # MANUAL exactly, not "anything but automatic": the tile is a link to
    # renewal=manual, and a count that included `unknown` would send you to a
    # shorter list than the number promised.
    act = [r for r in rows if r["days"] <= 90 and r["renewal"] == MANUAL]
    # `next_act` is the one the page names in a sentence: the soonest thing that
    # will not renew itself and has not already lapsed. rows[0] is the most
    # overdue item, which is the opposite of "next" and had been read as it.
    ahead = [r for r in act if r["days"] >= 0]
    return {"total": len(rows), "bands": bands,
            "expired": bands["expired"],
            "act": len(act), "act_rows": act[:6],
            "auto": sum(1 for r in rows if r["renewal"] == AUTOMATIC),
            "manual": sum(1 for r in rows if r["renewal"] == MANUAL),
            "unknown": sum(1 for r in rows if r["renewal"] == UNKNOWN),
            "next_act": ahead[0] if ahead else None,
            "soonest": rows[0] if rows else None}


def places(rows: list, top: int = 6) -> list:
    """Where the work is: the cluster, the vendor or the site, ranked.

    The first segment of `where` — every source writes it as "the thing that
    owns this · the detail", so the head of it is the estate's own word for a
    place. Worth ranking because renewals cluster: one expired wildcard usually
    means four certificates in the same namespace, and the count says so before
    anybody scrolls.
    """
    tally: dict = {}
    ids: dict = {}
    for r in rows:
        name = (r.get("where") or "").split(" · ")[0].strip()
        if not name:
            continue
        tally[name] = tally.get(name, 0) + 1
        # A bar over a cluster carries its id, so the link can be the exact
        # cluster filter rather than a substring search over the `where`
        # sentence — which also matched a namespace that shared a word, making
        # the list longer than the number on the bar. A vendor or a site has no
        # id and keeps the search.
        if r.get("cid"):
            ids.setdefault(name, r["cid"])
    ranked = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [{"name": n, "n": c, "cid": ids.get(n, "")} for n, c in ranked[:top]]


def group_by_band(rows: list) -> list:
    """[(key, label, rows)] in urgency order, empty bands dropped."""
    out = []
    for key, label, _lo, _hi in BANDS:
        got = [r for r in rows if r["band"] == key]
        if got:
            out.append((key, label, got))
    return out


def by_month(rows: list, months: int = 12) -> dict:
    """The forward view: what falls due in each of the next N months.

    Anything already expired, and anything beyond the horizon, is reported
    separately rather than folded into the first and last buckets — a bar that
    silently includes forty overdue items is a bar that lies about this month.
    """
    today = date.today()
    buckets: list = []
    cursor = date(today.year, today.month, 1)
    for _ in range(max(1, months)):
        buckets.append({"month": cursor.strftime("%Y-%m"),
                        "label": cursor.strftime("%b"),
                        "long": cursor.strftime("%B %Y"),
                        "year": cursor.strftime("%Y"),
                        "rows": [], "manual": 0})
        cursor = date(cursor.year + (cursor.month == 12),
                      1 if cursor.month == 12 else cursor.month + 1, 1)
    index = {b["month"]: b for b in buckets}
    overdue, beyond = [], []
    for r in rows:
        if r["days"] < 0:
            overdue.append(r)
        elif r["month"] in index:
            index[r["month"]]["rows"].append(r)
            if r["renewal"] != AUTOMATIC:
                index[r["month"]]["manual"] += 1
        else:
            beyond.append(r)
    top = max([len(b["rows"]) for b in buckets] or [0]) or 1
    for b in buckets:
        b["n"] = len(b["rows"])
        b["auto"] = b["n"] - b["manual"]
        b["pct"] = round(b["n"] / top * 100)
        # the manual share of this month's bar, so the template does no
        # arithmetic and an empty month cannot divide by zero
        b["mpct"] = round(b["manual"] / b["n"] * 100) if b["n"] else 0
    return {"buckets": buckets, "overdue": overdue, "beyond": beyond,
            "top": top, "months": len(buckets),
            "due": sum(b["n"] for b in buckets),
            "manual": sum(b["manual"] for b in buckets)}


def horizons() -> list:
    """The windows the page offers, and what each is for."""
    return [(0, "everything"), (7, "next 7 days"), (30, "next 30 days"),
            (90, "next 90 days"), (365, "next year")]


def month_label(month: str) -> str:
    """"2026-11" as "November 2026" — the month filter, said out loud."""
    try:
        return datetime.strptime(str(month)[:7], "%Y-%m").strftime("%B %Y")
    except ValueError:
        return str(month)


def days_word(days: int) -> str:
    """"in 12 days", "today", "41 days ago" — the phrase, not the number."""
    if days < -1:
        return f"{abs(days)} days ago"
    if days == -1:
        return "yesterday"
    if days == 0:
        return "today"
    if days == 1:
        return "tomorrow"
    if days < 60:
        return f"in {days} days"
    if days < 730:
        return f"in {round(days / 30.44)} months"
    return f"in {round(days / 365.25)} years"
