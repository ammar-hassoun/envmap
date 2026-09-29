"""What changed, from every system at once, on one clock.

WHY THIS EXISTS
    The portal already knows when Argo synced, when a build ran, when somebody
    edited a value and pushed it, when a pod started crash-looping and when an
    alert began firing. It has never put any two of those on the same axis, so
    the first question of every incident — "what changed just before this
    broke?" — costs nine pages and a mental join of as many timestamp formats.
    Nothing here fetches anything the other pages do not already fetch; the
    whole of it is the join.

WHERE A SOURCE COMES FROM MATTERS MORE THAN WHETHER IT IS CONFIGURED
    The first version read only *registered connections*, and on an estate that
    runs Argo CD without handing this portal its credentials that meant the page
    showed builds and nothing else — it looked like a CI feed. Deployments and
    cluster events are therefore read off the clusters themselves when no
    controller is registered, which is the same route the cluster pages already
    take and needs no new credential.

    A source with nothing behind it is also not the same as a source that looked
    and found nothing. `_configured()` separates them, so the page can say "not
    connected" instead of a zero that reads as "all quiet".

THE CLOCK IS THE WHOLE PROBLEM
    Every source speaks a different one, and none of them say so:

        audit log       local time, naive          "2026-08-06T14:03:11"
        Argo CD         UTC, with the Z stripped   "2026-08-06 10:03:11"
        Prometheus      UTC, offset attached       "2026-08-06T10:03:11Z"
        CI              UTC, offset attached       (from epoch milliseconds)
        git             the committer's own offset "2026-08-06T14:03:11+04:00"

    Two of those are naive strings that look identical and mean times four hours
    apart in the Gulf. Sorting them as text, or parsing them as one format, puts
    an alert *before* the deploy that caused it and quietly inverts the only
    thing this page is for. So a source declares which clock a naive value from
    it speaks (`clock=`), an offset on the value always wins over that
    declaration, and everything is converted to local time — the clock the audit
    log already speaks and the one the reader's own wall says.

WHAT IT DOES NOT KNOW, AND SAYS SO
    Each source keeps its own history and none of it is retained here, so the
    reach of this page is the reach of whatever it asks:

    * **Builds are the latest run of each pipeline**, not every run. The full
      feed is one API call per repository per page load, which is what makes
      the Pipelines page slow enough to need a cache; a timeline that paid that
      on every filter change would be worse than no timeline.
    * **Alerts are the ones still firing.** Prometheus does not keep resolved
      ones, so an alert that fired and cleared last night is gone from the
      source, not dropped here.
    * **Argo keeps roughly ten revisions per application**, and only the most
      recent sync of each is read (the deeper history is one call per app).
    * **Kubernetes keeps about an hour of events** and emits thousands of them,
      so they are capped per cluster and filtered to warnings plus the handful
      of routine reasons that mean something moved. Everything dropped is
      dropped by a rule stated on the page, not silently.
    * A source that is unreachable is **named in `notes`**, never silently
      omitted — an empty timeline must not be able to mean "nothing happened"
      when it actually means "the controller was down".

PERMISSIONS ARE PER SOURCE, NOT PER PAGE
    A merged view is a way to see round the areas a role does not grant, so each
    source is gated by the area that governs its own page — builds by
    `pipelines`, cluster events by `clusters`, and so on — and commits are
    additionally confined to the projects the role can see. A source that can be
    read two ways is gated twice, separately: a role with `clusters` but not
    `gitops` sees the deployments its clusters report and none from a registered
    controller. What a role excludes is reported in `hidden` so the page can say
    "two sources are not shown to you" rather than implying it covered
    everything.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from . import (auth, certs, ci, cluster as clusterview, fleet, gather,
               git_ops, gitops, monitoring, rbac, security, store,
               workflows)

# The furthest back the page will look. Not a performance limit — every source
# caps itself long before this — but a promise: past a fortnight the answer is
# mostly "the sources no longer remember", and a control offering a year would
# imply otherwise.
MAX_HOURS = 24 * 14
DEFAULT_HOURS = 24

# Per source, so one chatty system cannot crowd the others out of the page.
PER_SOURCE = 300

# Kubernetes is the exception: a busy cluster emits thousands of events an hour
# and would be the only thing on the page. Capped per cluster, warnings first.
PER_CLUSTER_EVENTS = 60

# When centring on a moment, how far either side by default.
DEFAULT_SPAN = 30

# key -> (label, icon, the areas that can contribute to it)
#
# A source may draw on more than one area: a deployment is read from a
# registered Argo CD when there is one, and otherwise straight off the cluster,
# which is a cluster read and governed as one. Both feed the same row type, so
# they are one line here and gated separately inside the fetcher.
# The middle field names a line icon in app/logodata.py, not an emoji — see
# the note on cluster.TABS for why.
SOURCES = {
    "commit": ("Commits", "git-branch", ("config",)),
    "action": ("Portal actions", "clipboard-list", ("audit",)),
    "build": ("Builds", "zap", ("pipelines",)),
    "deploy": ("Deployments", "rocket", ("gitops", "clusters")),
    "event": ("Cluster events", "hexagon", ("clusters",)),
    "alert": ("Alerts", "triangle-alert", ("monitoring",)),
    "flow": ("Workflow runs", "workflow", ("workflows",)),
    "scan": ("Security scans", "shield", ("security",)),
    "cert": ("Certificates", "shield-check", ("certs",)),
}

# Ties are broken so that within one second the effect sits above the cause,
# which is the order the eye expects when the newest row is on top. It also
# makes the output deterministic, which the tests depend on.
_CAUSALITY = {"commit": 0, "action": 1, "scan": 2, "cert": 3, "build": 4,
              "flow": 5, "deploy": 6, "event": 7, "alert": 8}

# Deliberately not datetime.fromisoformat: before 3.11 it rejects a trailing
# "Z" and accepts only 3 or 6 fractional digits, and these sources produce
# both 7-digit fractions (Argo) and none at all. One regex reads every shape
# any of them has ever sent.
_TS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?"
    r"(?:\.(\d+))?\s*(Z|z|[+-]\d{2}:?\d{2})?")


def _local(dt: datetime) -> datetime:
    """An aware datetime as local naive — the clock everything is compared on."""
    return dt.astimezone().replace(tzinfo=None)


def _tz(off: str) -> timezone:
    if off in ("Z", "z"):
        return timezone.utc
    body = off[1:].replace(":", "")
    delta = timedelta(hours=int(body[:2] or 0), minutes=int(body[2:4] or 0))
    return timezone(delta if off[0] == "+" else -delta)


def at(raw, clock: str = "utc") -> datetime | None:
    """One timestamp, whatever shape its system produces, as local naive time.

    `clock` says what a value carrying NO offset means for this source. An
    offset on the value itself always wins, so declaring the wrong one can only
    affect the sources that are genuinely ambiguous.
    """
    if raw is None or raw == "":
        return None
    text = str(raw).strip()
    if isinstance(raw, (int, float)) or text.isdigit():
        seconds = float(raw)
        if seconds > 1e11:                     # milliseconds, as CI reports
            seconds /= 1000.0
        if seconds <= 0:
            return None
        try:
            return _local(datetime.fromtimestamp(seconds, timezone.utc))
        except (OverflowError, OSError, ValueError):
            return None
    m = _TS.search(text)
    if not m:
        return None
    y, mo, d, hh, mm, ss, _frac, off = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss or 0))
    except ValueError:                         # 31 February and friends
        return None
    if off:
        return _local(dt.replace(tzinfo=_tz(off)))
    if clock == "local":
        return dt
    return _local(dt.replace(tzinfo=timezone.utc))


def _ev(when, kind: str, what: str, where: str = "", who: str = "",
        detail: str = "", url: str = "", tone: str = "",
        status: str = "") -> dict | None:
    """One row. None when the source gave no usable time — a change that cannot
    be placed on the axis does not belong on a timeline, and guessing "now"
    would put it at the top of every incident.

    `status` is a word or two that fits in a pill — "failed", "Succeeded",
    "critical". `detail` is prose and gets a line of its own. They were one
    field to begin with, which put "issued for 90 days" inside a pill.
    """
    if when is None:
        return None
    return {"at": when, "kind": kind, "what": what, "where": where, "who": who,
            "detail": detail, "url": url, "tone": tone, "status": status,
            "day": when.strftime("%Y-%m-%d"), "time": when.strftime("%H:%M:%S")}


# ── the sources ────────────────────────────────────────────────
# Each returns (events, notes). A note is a source that could not be read, and
# it is as much of the answer as the rows are.

def _commits(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del refresh                      # a working copy is read from disk anyway
    out, notes = [], []
    allowed = rbac.visible_projects(user, "config")
    stamp = since.strftime("%Y-%m-%dT%H:%M:%S")
    for pid, p in store.projects().items():
        if allowed is not None and pid not in allowed:
            continue
        for rgid, rg in (p.get("regions") or {}).items():
            # one read per DISTINCT checkout — a region's environments may
            # split across repositories and branches, and two environments on
            # one monorepo must not report every commit twice
            from . import repo as repomod
            seen: set = set()
            for env in sorted(store.env_sources(pid, rgid)):
                key = str(repomod.checkout(pid, rgid, env))
                if key in seen or not repomod.binding(pid, rgid, env)["url"]:
                    continue
                seen.add(key)
                try:
                    rows = git_ops.commits(pid, rgid, since=stamp,
                                           limit=PER_SOURCE, env=env)
                except Exception as e:                         # noqa: BLE001
                    notes.append(f"{p.get('name', pid)} / "
                                 f"{rg.get('name', rgid)}: could not read the "
                                 f"working copy ({e})")
                    continue
                for c in rows:
                    out.append(_ev(at(c["at"]), "commit", c["subject"],
                                   where=f"{p.get('name', pid)} / "
                                         f"{rg.get('name', rgid)}",
                                   who=c["who"], detail=c["sha"]))
    return out, notes


# Actions that changed the world, as opposed to the ones that merely record
# somebody looking at it. A timeline of sign-ins is a different page.
_QUIET = ("login", "logout", "signin", "sign-in", "session", "mfa",
          "password-check", "view")
_LOUD = ("denied", "refused", "fail", "error", "revoke", "delete", "drain")


def _actions(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del user, refresh                # the audit log is local and never cached
    out = []
    for r in auth.read_audit(PER_SOURCE * 4):
        # the audit log is the one source written by this portal, on this
        # portal's own clock, with no offset recorded
        when = at(r.get("at"), clock="local")
        if when is None or when < since:
            continue
        action = (r.get("action") or "").lower()
        if any(q in action for q in _QUIET):
            continue
        out.append(_ev(when, "action", r.get("action") or "?",
                       where=r.get("target") or "", who=r.get("user") or "",
                       detail=r.get("detail") or "",
                       tone="bad" if any(l in action for l in _LOUD) else ""))
    return out, []


def _builds(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del user, since
    conns = store.all_ci()
    if not conns:
        return [], []

    def one(c):
        try:
            return c, ci.fetch(c, refresh=refresh), ""
        except Exception as e:                                 # noqa: BLE001
            return c, None, str(e)

    out, notes = [], []
    for got in fleet._pmap(one, conns, workers=min(5, len(conns))):
        if not got:
            continue
        c, payload, err = got
        if payload is None:
            notes.append(f"{c.get('name', '?')}: builds unavailable ({err})")
            continue
        for j in payload.get("jobs") or []:
            status = (j.get("status") or "").lower()
            tone = ("bad" if status in ("failed", "failure")
                    else "ok" if status == "success" else "")
            out.append(_ev(at(j.get("started_at") or j.get("started")),
                           "build",
                           f"{j.get('name', '?')}"
                           + (f" #{j['number']}" if j.get("number") else ""),
                           where=c.get("name", ""), who=j.get("branch") or "",
                           status=status, url=j.get("url") or "", tone=tone))
    return out, notes


def _phase_tone(phase: str) -> str:
    phase = (phase or "").lower()
    if phase in ("failed", "error", "degraded"):
        return "bad"
    return "ok" if phase in ("succeeded", "success", "synced") else ""


def _deploys(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    """Argo CD syncs, from a registered controller or straight off the cluster.

    Most estates running Argo never register it here — the credentials are one
    more thing to hold, and the cluster pages already read its Applications
    without any. Reading only registered controllers therefore reported "no
    deployments" to exactly the people who deploy the most, which is how this
    page came to look like a list of builds.
    """
    del since
    out, notes = [], []

    if rbac.may_area(user, "gitops"):
        conns = store.all_gitops()
        allowed = rbac.visible_clusters(user, "gitops")

        def one(c):
            try:
                return c, gitops.apps(c, refresh=refresh), ""
            except Exception as e:                             # noqa: BLE001
                return c, None, str(e)

        for got in fleet._pmap(one, conns, workers=min(5, len(conns))) if conns else []:
            if not got:
                continue
            c, rows, err = got
            if rows is None:
                notes.append(f"{c.get('name', '?')}: applications unavailable ({err})")
                continue
            if allowed is not None and c.get("cluster") and c["cluster"] not in allowed:
                continue
            for a in rows:
                # Argo prints an offset-less UTC time; see the module header
                out.append(_ev(at(a.get("when")), "deploy", a.get("name", "?"),
                               where=a.get("dest") or c.get("name", ""),
                               who=a.get("revision") or "",
                               status=a.get("op_phase") or "",
                               detail=(a.get("op_message") or "")[:160],
                               url=a.get("url") or "",
                               tone=_phase_tone(a.get("op_phase"))))

    if rbac.may_area(user, "clusters"):
        seen = {(e["what"], e["at"]) for e in out if e}
        allowed = rbac.visible_clusters(user, "clusters")
        for r in clusterview.everywhere("argocd", refresh=refresh):
            if allowed is not None and r.get("cid") not in allowed:
                continue
            if not r.get("present"):
                continue
            for a in r.get("apps") or []:
                when = at(a.get("when"))
                # the same application read through both routes is one
                # deployment, not two
                if when is None or (a.get("name"), when) in seen:
                    continue
                out.append(_ev(when, "deploy", a.get("name", "?"),
                               where=f"{r.get('cluster', '')}"
                                     f"{' · ' + a['dest'] if a.get('dest') else ''}",
                               who=a.get("revision") or "",
                               status=a.get("phase") or a.get("sync") or "",
                               detail=f"{a.get('sync', '')} · {a.get('health', '')}"
                                      .strip(" ·"),
                               tone=_phase_tone(a.get("phase"))))
    return out, notes


# Warnings are always worth a line. Routine events are mostly noise — a busy
# cluster emits thousands an hour — except for the handful that mean something
# moved, which is what this page is about.
#
# LeaderElection is deliberately NOT here despite meaning "the control plane
# changed hands": on a healthy cluster the kube-controller-manager and
# scheduler leases renew constantly, and against a real estate it was most of
# the page. SuccessfulAttachVolume is the same kind of routine.
_EVENTS_WORTH = {"ScalingReplicaSet", "SuccessfulRescale", "Rollback",
                 "NodeReady", "NodeNotReady", "NodeHasDiskPressure",
                 "NodeHasMemoryPressure", "Preempted", "Drain", "Evicted"}
_EVENTS_BAD = ("oom", "fail", "crash", "backoff", "unhealthy", "evict",
               "error", "killing")


def _compact(n: int) -> str:
    """23640 -> "23.6k". Kubernetes counts a chronic failure every time it
    retries, so these reach seven figures; printed in full they are a wall of
    digits that hides the two-digit ones next to them."""
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k".replace(".0k", "k")
    return f"{n / 1_000_000:.1f}M".replace(".0M", "M")


def _events(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del since
    if not rbac.may_area(user, "clusters"):
        return [], []
    allowed = rbac.visible_clusters(user, "clusters")
    out, notes = [], []
    for r in clusterview.everywhere("events", refresh=refresh):
        if allowed is not None and r.get("cid") not in allowed:
            continue
        if r.get("error"):
            notes.append(f"{r.get('cluster', '?')}: events unavailable "
                         f"({r['error']})")
            continue
        rows = [e for e in r.get("events") or []
                if e.get("type") == "Warning" or e.get("reason") in _EVENTS_WORTH]
        # One reason firing across six volumes in the same second is one
        # problem, not six rows — the cluster page groups warnings for exactly
        # this reason, and a timeline that did not would be all Kubernetes.
        # Grouped to the minute, so a reason that recurs an hour later is still
        # its own entry.
        groups: dict = {}
        for e in rows:
            when = at(e.get("when"))
            if when is None:
                continue
            key = (e.get("namespace", ""), e.get("reason", ""),
                   when.replace(second=0, microsecond=0))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {"at": when, "objects": [], "count": 0,
                                   "message": (e.get("message") or "")[:180],
                                   "warning": e.get("type") == "Warning"}
            g["at"] = max(g["at"], when)
            g["count"] += int(e.get("count") or 1)
            if e.get("object") and e["object"] not in g["objects"]:
                g["objects"].append(e["object"])
        best = sorted(groups.items(), key=lambda kv: kv[1]["at"],
                      reverse=True)[:PER_CLUSTER_EVENTS]
        for (namespace, reason, _minute), g in best:
            objects = g["objects"]
            out.append(_ev(g["at"], "event", reason or "?",
                           where=f"{r.get('cluster', '')}"
                                 f"{' · ' + namespace if namespace else ''}",
                           who=(objects[0] if len(objects) == 1
                                else f"{len(objects)} objects" if objects else ""),
                           status=f"×{_compact(g['count'])}" if g["count"] > 1 else "",
                           detail=g["message"],
                           tone=("bad" if g["warning"] and any(
                               b in (reason or "").lower() for b in _EVENTS_BAD)
                               else "warn" if g["warning"] else "")))
    return out, notes


def _flows(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del user, since
    conns = store.all_wf()
    if not conns:
        return [], []

    def one(c):
        try:
            return c, workflows.overview(c, refresh=refresh), ""
        except Exception as e:                                 # noqa: BLE001
            return c, None, str(e)

    out, notes = [], []
    for got in fleet._pmap(one, conns, workers=min(4, len(conns))):
        if not got:
            continue
        c, ov, err = got
        if ov is None:
            notes.append(f"{c.get('name', '?')}: workflow runs unavailable ({err})")
            continue
        for g in ov.get("groups") or []:
            for row in g.get("rows") or []:
                state = (row.get("state") or "").lower()
                out.append(_ev(at(row.get("at")), "flow", row.get("name", "?"),
                               where=f"{c.get('name', '')} · {g.get('name', '')}"
                                     .strip(" ·"),
                               who=row.get("kind") or "",
                               status=row.get("state") or "",
                               url=row.get("href") or row.get("url") or "",
                               tone=("bad" if state in ("failed", "terminated",
                                                        "timedout")
                                     else "ok" if state in ("completed",
                                                            "success") else "")))
    return out, notes


def _scans(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del user, since
    conns = store.all_sec()
    if not conns:
        return [], []

    def one(c):
        try:
            return c, security.scans(c, refresh=refresh), ""
        except Exception as e:                                 # noqa: BLE001
            return c, None, str(e)

    out, notes = [], []
    for got in fleet._pmap(one, conns, workers=min(4, len(conns))):
        if not got:
            continue
        c, rows, err = got
        if rows is None:
            notes.append(f"{c.get('name', '?')}: scans unavailable ({err})")
            continue
        for s in rows:
            out.append(_ev(at(s.get("iso")), "scan", s.get("name", "scan"),
                           where=f"{c.get('name', '')}"
                                 f"{' · ' + s['product'] if s.get('product') else ''}",
                           who=s.get("engagement") or "",
                           url=s.get("url") or ""))
    return out, notes


def _certs(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    """The portal's own certificate orders, by when they last moved."""
    del user, since, refresh
    out = []
    try:
        rows = certs.orders()
    except Exception as e:                                     # noqa: BLE001
        return [], [f"certificate orders unavailable ({e})"]
    for o in rows:
        status = (o.get("status") or "").lower()
        out.append(_ev(at(o.get("updated_at") or o.get("created_at")),
                       "cert", o.get("name") or "certificate",
                       where=o.get("ca") or "", status=status,
                       detail=o.get("note") or "",
                       url=f"/certs/{o.get('id', '')}",
                       tone=("bad" if status in ("failed", "cancelled")
                             else "ok" if status == "ready" else "")))
    return out, []


def _alerts(user, since: datetime, refresh: bool = False) -> tuple[list, list]:
    del user, since
    conns = store.all_mon()
    if not conns:
        return [], []

    def one(c):
        try:
            return c, monitoring.alerts(c, refresh=refresh), ""
        except Exception as e:                                 # noqa: BLE001
            return c, None, str(e)

    out, notes = [], []
    for got in fleet._pmap(one, conns, workers=min(5, len(conns))):
        if not got:
            continue
        c, rows, err = got
        if rows is None:
            notes.append(f"{c.get('name', '?')}: alerts unavailable ({err})")
            continue
        for a in rows:
            sev = (a.get("severity") or "").lower()
            out.append(_ev(at(a.get("at")), "alert", a.get("name", "?"),
                           where=a.get("source") or c.get("name", ""),
                           status=sev, detail=a.get("summary") or "",
                           url=a.get("url") or "",
                           tone="bad" if sev in ("critical", "high") else "warn"))
    return out, notes


_FETCH = {"commit": _commits, "action": _actions, "build": _builds,
          "deploy": _deploys, "event": _events, "alert": _alerts,
          "flow": _flows, "scan": _scans, "cert": _certs}


# ── putting it together ────────────────────────────────────────
def window(hours: int = DEFAULT_HOURS, centre: datetime | None = None,
           span: int = DEFAULT_SPAN) -> tuple[datetime, datetime]:
    """The span the page is asking about, as (since, until).

    Centred on a moment when one is given — the "what happened around this
    alert" question — and otherwise the last N hours up to now.
    """
    if centre is not None:
        span = max(1, min(int(span or DEFAULT_SPAN), 24 * 60))
        return centre - timedelta(minutes=span), centre + timedelta(minutes=span)
    hours = max(1, min(int(hours or DEFAULT_HOURS), MAX_HOURS))
    now = datetime.now()
    return now - timedelta(hours=hours), now


# ── speed ──────────────────────────────────────────────────────
# Measured on a five-cluster estate, every cache cold: cluster events 8.2s,
# security scans 5.7s, deployments 4.1s, workflow runs 2.6s, the rest under a
# second. Run one after another that is 22 seconds, which is what "the timeline
# page is slow" was — nine sources queueing behind each other for no reason.
#
# Two fixes, in this order of effect:
#   * run the sources CONCURRENTLY — the page then costs the slowest source
#     rather than the sum, ~8s instead of ~22s;
#   * serve what is already collected and refresh behind the reader, the same
#     bargain summary.py strikes for the Overview. A page that is 45 seconds
#     out of date and instant beats one that is exact and takes eight seconds,
#     because every source it reads is itself a cache of something older.
#
# Selecting one tab reads one source, so a specific tab is fast even cold.
#   * and never make the page WAIT for the slow ones. Measured cold, one
#     source at a time: cluster events 15.0s, deployments 10.7s, security
#     scans 5.5s. Running them together brings the page down to the slowest
#     one, and the slowest one is still fifteen seconds — a click that costs
#     fifteen seconds is a broken page however well it parallelises. So the
#     render has a deadline: whatever has answered by then is shown, whatever
#     has not keeps collecting in the background and is named on the page. The
#     next load has it. This is the bargain summary.py already strikes for the
#     Overview, which is why that page is fast and this one was not.
CACHE_TTL = 45.0                  # fresh: serve it, ask nobody
CACHE_HARD = 15 * 60.0            # too old to show; collect behind the reader
# Measured: the local sources land inside 0.3s and builds inside ~1.1s, so this
# sits just past them — the first paint carries most of the page, and only the
# genuinely slow cluster reads arrive on the second.
FIRST_PAINT = 1.5

_GATHER = gather.Gatherer("timeline", ttl=CACHE_TTL, hard=CACHE_HARD,
                          first_paint=FIRST_PAINT, workers=9)


def invalidate() -> None:
    _GATHER.invalidate()


def _cache_key(user, since: datetime, kinds) -> tuple:
    # The areas a role grants change what the sources return, so two people
    # must never share an entry. Cheap to compute and correct when a role is
    # edited mid-session, which keying on the user id alone would not be.
    return ((user or {}).get("id", "?"),
            frozenset(rbac.areas_of(user)),
            since.strftime("%Y-%m-%dT%H:%M"),
            tuple(sorted(kinds)))


def _gather(user, since: datetime, kinds, refresh: bool) -> dict:
    """Every wanted source, collected without blocking the page. See
    app/gather.py for the policy; this only says what a source is and how to
    put the pieces back together."""
    jobs = [(k, SOURCES[k][0],
             (lambda kk=k: _FETCH[kk](user, since, refresh))) for k in kinds]
    got = _GATHER.gather(_cache_key(user, since, kinds), jobs, refresh)
    events, notes = [], list(got["errors"])
    for rows, said in got["parts"].values():
        events += [e for e in rows if e]
        notes += said
    return {"events": events, "notes": notes,
            "pending": got["pending"], "stale": got["stale"]}


def collect(user, hours: int = DEFAULT_HOURS, kinds=None,
            centre: datetime | None = None, span: int = DEFAULT_SPAN,
            q: str = "", refresh: bool = False) -> dict:
    """Every change in the window, newest first.

    `kinds` narrows which sources are read at all, so unticking Builds makes the
    page faster as well as shorter — filtering after fetching would keep paying
    for what it then threw away.
    """
    since, until = window(hours, centre, span)
    want = set(kinds) if kinds else set(SOURCES)
    hidden, idle, ask = [], [], []
    for key, (label, _icon, areas) in SOURCES.items():
        if not any(rbac.may_area(user, a) for a in areas):
            hidden.append(label)
            continue
        if not _configured(key):
            idle.append(label)
            continue
        if key in want:
            ask.append(key)
    got = _gather(user, since, ask, refresh)
    events, notes = list(got["events"]), list(got["notes"])
    events = [e for e in events if since <= e["at"] <= until]
    if q:
        needle = q.lower()
        events = [e for e in events
                  if needle in f"{e['what']} {e['where']} {e['who']} "
                               f"{e['detail']}".lower()]
    events.sort(key=lambda e: (e["at"], _CAUSALITY.get(e["kind"], 9)),
                reverse=True)
    now = datetime.now()
    for i, e in enumerate(events):
        e["gap"] = gap_before(events, i)
        e["ago"] = ago(e["at"], now)
    return {"events": events, "since": since, "until": until,
            "notes": notes, "hidden": hidden, "idle": idle,
            "buckets": buckets(events, since, until),
            # which sources this answer actually rests on, so a tab showing no
            # count is distinguishable from one showing zero
            "asked": ask, "stale": got.get("stale", 0),
            # sources still being collected as this was rendered. Named, not
            # hidden: a page that quietly omits cluster events looks like a
            # quiet estate.
            "pending": got.get("pending", []),
            "counts": {k: sum(1 for e in events if e["kind"] == k)
                       for k in ask}}


def _configured(key: str) -> bool:
    """Whether anything of this kind is set up at all.

    A source with nothing behind it is not the same as a source that found
    nothing, and conflating them is what made this page claim to have looked at
    five systems when two of them were never connected. Cheap: every check is a
    row count already in memory.
    """
    try:
        if key == "build":
            return bool(store.all_ci())
        if key == "alert":
            return bool(store.all_mon())
        if key == "flow":
            return bool(store.all_wf())
        if key == "scan":
            return bool(store.all_sec())
        if key == "deploy":
            return bool(store.all_gitops()) or _any_cluster()
        if key == "event":
            return _any_cluster()
        if key == "commit":
            return any((p.get("regions") or {})
                       for p in store.projects().values())
    except Exception:                                          # noqa: BLE001
        return True          # never hide a source because the check itself broke
    return True              # actions and certificates are always local


def _any_cluster() -> bool:
    return any((p.get("clusters") or {}) for p in store.projects().values())


# ── shaping it for a page ──────────────────────────────────────
def ago(when: datetime, now: datetime | None = None) -> str:
    """"14m", "3h", "2d" — the absolute time answers "when", this answers "how
    long ago", and during an incident the second one is what is being asked."""
    secs = ((now or datetime.now()) - when).total_seconds()
    if secs < 0:
        return "just now"
    if secs < 90:
        return f"{int(secs)}s"
    if secs < 5400:
        return f"{int(secs // 60)}m"
    if secs < 172800:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


BUCKETS = 48


def buckets(events: list, since: datetime, until: datetime) -> list:
    """A coarse histogram of the window, for the density strip.

    The gaps are the information: a timeline that reads as a flat list hides
    that nothing happened for six hours and then everything happened at once.
    """
    span_s = max(1.0, (until - since).total_seconds())
    step = span_s / BUCKETS
    counts = [0] * BUCKETS
    worst = [""] * BUCKETS
    for e in events:
        i = int((e["at"] - since).total_seconds() / step)
        i = max(0, min(BUCKETS - 1, i))
        counts[i] += 1
        if e["tone"] == "bad" or (e["tone"] == "warn" and worst[i] != "bad"):
            worst[i] = e["tone"]
    top = max(counts) or 1
    # Each bar carries the moment at its middle and how wide it is, so clicking
    # one can re-ask the same question centred there. Without that the strip is
    # decoration: it shows you where the interesting minute is and then makes
    # you find it by hand.
    half = max(1, int(step / 60 / 2))
    out = []
    for i, n in enumerate(counts):
        start = since + timedelta(seconds=step * i)
        middle = start + timedelta(seconds=step / 2)
        out.append({"n": n, "pct": round(n / top * 100), "tone": worst[i],
                    "at": start.strftime("%H:%M"),
                    "centre": middle.strftime("%Y-%m-%dT%H:%M:%S"),
                    "span": half,
                    "label": f"{start.strftime('%a %H:%M')} · {n} "
                             f"change{'s' if n != 1 else ''}"})
    return out


# A gap worth drawing. Below this the rows are simply consecutive; above it,
# the quiet is part of the story and gets a line of its own.
QUIET_AFTER = timedelta(minutes=25)


def gap_before(events: list, i: int) -> str:
    """How long nothing happened before events[i], or "" when it was busy.

    Read from the newest-first list, so the gap sits above the older row — the
    direction the eye travels when working backwards from a symptom.
    """
    if i + 1 >= len(events):
        return ""
    delta = events[i]["at"] - events[i + 1]["at"]
    if delta < QUIET_AFTER:
        return ""
    mins = int(delta.total_seconds() // 60)
    if mins < 120:
        return f"{mins} minutes"
    hours = mins / 60
    if hours < 48:
        return f"{hours:.0f} hours" if hours >= 10 else f"{hours:.1f} hours"
    return f"{hours / 24:.0f} days"


def group_by_day(events: list) -> list:
    """[(day, [events…])] in the order given — the template should not have to
    track when the date last changed."""
    out: list = []
    for e in events:
        if not out or out[-1][0] != e["day"]:
            out.append((e["day"], []))
        out[-1][1].append(e)
    return out
