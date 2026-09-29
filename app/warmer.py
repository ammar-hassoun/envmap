"""Filling the caches before anybody asks, so no page is ever the cold one.

WHY THIS EXISTS
    Every slow page in this portal is slow for the same reason: it is reading
    somebody else's system over a VPN or the internet, where one call costs
    about a second. Caching already fixed the second visit — a cluster page
    measured 8.6s cold and 9ms warm — but nothing fixed the FIRST one, and
    "first" turns out to be most visits:

      * the first page after a deploy or a pod restart, every time
      * anything nobody has opened for a few minutes, which past its cache's
        window is a cold read again — open a page before lunch, come back
        after, cold
      * signing in. `/mfa` redirects to the Overview, whose fleet snapshot
        costs about three seconds to build, so the last thing a person sees of
        signing in is a pause with no explanation

    So this walks the same paths a page would, on a timer, and leaves the
    caches full. It adds no cache of its own and no endpoint: it calls exactly
    what a request calls, and the existing policy in each module decides
    whether that turns out to be free or expensive.

WHY THERE ARE TWO CADENCES
    Because the caches are not all the same shape, and warming on the wrong
    beat is worse than not warming at all — it is the whole cost with none of
    the benefit.

      * The fleet snapshot, the cluster parts, the timeline and the expiry
        radar all SERVE STALE: past their freshness window they hand back what
        they have and refresh behind the reader. Nothing there ever blocks, so
        the only job is to stay inside the stale window — 600s for a cluster,
        900s for the timeline — and SLOW_EVERY sits well inside the shortest.
      * The connection pages — Argo CD, Prometheus, Jenkins, DefectDojo and the
        rest — do not. Their caches BLOCK once the entry ages past 45–120s.
        Warming those every few minutes would leave them cold on three visits
        in four, so they are warmed just under their own TTL instead.

    PAGE_EVERY is therefore a live poll of somebody else's system, which is a
    thing to spend carefully rather than by default. It is spent only on pages
    somebody has actually opened, and REMEMBER_PAGE is half an hour rather than
    the four hours the cheap targets get: while a person is working on the
    Monitoring page it stays hot, and half an hour after they wander off it
    stops costing that Prometheus anything.

WHAT IT DELIBERATELY DOES NOT DO
    **It does not warm everything.** Reading every cluster and every connection
    for a page nobody opens is a permanent load on somebody's API server for no
    reader. Only what has actually been looked at recently is kept warm, which
    is why note_view exists and why the loop shrinks to nothing but the fleet
    snapshot on an idle portal.

    **It does not make the terminal faster**, or anything else that is a live
    round trip by definition. A cache in front of `kubectl exec` would be a lie
    rather than a speed-up.

    **It does not warm the database console.** Those pages hold no stored
    credential — whoever opens one types their own account and it lives in that
    session only — so there is nothing here to read with.
"""
from __future__ import annotations

import importlib
import threading
import time

# How often the loop wakes. Only a granularity: what actually runs is decided
# per target by the intervals below.
TICK = 20.0

# The serve-stale targets. Well inside the shortest stale window in the app
# (cluster.STALE_MAX, 600s), so nothing ever falls off the end of it, and about
# a tenth of the traffic that chasing the 20s TTL would cost.
SLOW_EVERY = 200.0

# The connection pages, which block once their own cache ages out. Under the
# shortest of those TTLs (monitoring, gitops, workflows and vpn are all 45s) so
# a warmed page is genuinely warm rather than warm for the last ten seconds of
# every pass.
PAGE_EVERY = 35.0

# How long something stays "worth warming" after it was last looked at. Past
# this the loop forgets it, and an idle portal settles down to warming only the
# fleet snapshot.
REMEMBER = 4 * 3600.0
REMEMBER_PAGE = 30 * 60.0          # see "why there are two cadences" above

# A THIRD CADENCE: the GitOps working copies.
#
# Not a cache — a `git fetch` and a fast-forward of a real checkout on disk, so
# the page stops showing a file somebody else changed an hour ago. Five minutes
# because that is roughly how long a colleague's merge should stay invisible,
# and because it is far enough apart that a large estate is not hammering a
# git host on the portal's behalf.
#
# It NEVER forces. gitrepo.clone_or_pull refuses outright when the working copy
# is dirty, and that refusal is the whole safety property here: somebody's
# uncommitted edit must not be reset by a timer they cannot see. A dirty region
# is recorded as skipped, not as an error — it is the normal state of a region
# being worked on.
REPO_EVERY = 300.0

# ...and the floor for one asked for sooner. The cadence alone left a real gap:
# _due() fires once at startup, before anybody has opened a page, so the next
# pass is five minutes away — and somebody landing on a region the remote has
# moved past reads "out of date · Sync now" for up to five minutes with nothing
# telling them a sync is coming. Opening a stale region therefore asks for one,
# and this is how often that asking is allowed to turn into a git fetch.
REPO_FLOOR = 45.0
_repo_state: dict = {}             # rgid -> {"at", "outcome", "detail"}
_repo_wanted: set = set()          # regions asked for ahead of the cadence


def sync_soon(pid: str, rgid: str) -> None:
    """Ask for this region to be fetched at the next tick, not the next cadence.

    Called when a page renders a region the remote has moved past. It does not
    fetch anything itself — a page render must not wait on somebody's git host —
    and REPO_FLOOR keeps a stale region that cannot be fixed from turning every
    page view into another fetch.
    """
    if not (pid and rgid):
        return
    note_view("region", f"{pid}/{rgid}")
    with _guard:
        _repo_wanted.add(rgid)

# Which collector stands behind each page, as (store kind, module, function).
# The call is the same one the route makes — the point of this module is that
# it warms what a request warms, so a page that changes where it reads from
# must change here too. tests/test_warmer.py resolves every entry, because the
# failure of getting one wrong is silent: a page that is simply never warm.
#
# Pipelines are here rather than in a startup hook of their own. main.py had
# one, so a cold boot ran two full passes over every CI connection at the same
# moment — twice the calls, and on a throttled Bitbucket the second pass is what
# turns a slow start into a refused one.
#
# Logs and Cloud accounts are deliberately absent: logstore and cloud each
# already run their own warmer from app startup, on the same reasoning and the
# same beat (logstore.WARM_EVERY is 45s under a 60s TTL). Adding them here
# would poll those servers twice for one page.
PAGES = {
    "monitoring": ("mon", "monitoring", "overview"),
    "gitops": ("gitops", "gitops", "apps"),
    "workflows": ("wf", "workflows", "overview"),
    "security": ("sec", "security", "overview"),
    "virt": ("virt", "virt", "read"),
    "vpn": ("vpn", "vpn", "read"),
    "edge": ("edge", "edge", "inventory"),
    "bmc": ("bmc", "bmc", "read"),
    "pipelines": ("ci", "ci", "fetch"),
}

# One pass must not run into the next: a slow estate would otherwise stack
# collections up behind itself for ever.
_running = threading.Lock()
_seen: dict = {}          # ("cluster"|"user"|"page", key) -> last looked at
_last: dict = {}          # target -> monotonic clock of its last run
_guard = threading.Lock()
_started = False


def note_view(kind: str, key) -> None:
    """Record that somebody looked at this. Called from the request path, so it
    does nothing but write one dict entry."""
    if not key:
        return
    with _guard:
        _seen[(kind, str(key))] = time.time()


def _recent(kind: str) -> list:
    remember = REMEMBER_PAGE if kind == "page" else REMEMBER
    cutoff = time.time() - remember
    with _guard:
        for k, when in list(_seen.items()):
            if k[0] == kind and when < cutoff:
                _seen.pop(k, None)
        return [key for (t, key) in _seen if t == kind]


def _due(target: str, every: float) -> bool:
    """Whether this target's interval has elapsed, marking it run if so."""
    now = time.monotonic()
    with _guard:
        if now - _last.get(target, float("-inf")) < every:
            return False
        _last[target] = now
    return True


def _warm_fleet() -> None:
    """The snapshot the Overview is made of, and the first thing anybody sees
    after signing in. Warmed unconditionally: it is the one page every user
    lands on whether or not they have looked at anything yet."""
    from . import fleet
    fleet.overview()


def _warm_summary() -> None:
    """The Overview's two expensive neighbours — the pipeline and scan
    roll-ups. These never block a reader; they answer `pending` and collect
    behind. So the thing being fixed here is not a pause but a hole: without
    this the Overview's first load after a restart says "still reading" in two
    of its panels, which is the same restart every customer's upgrade causes."""
    from . import summary
    for call in (summary.pipelines, summary.security_roll):
        try:
            call()
        except Exception:                                      # noqa: BLE001
            pass


def _warm_clusters() -> None:
    """The parts a cluster page reads, for clusters somebody has opened."""
    from . import cluster as clusterview, kmanage, kube, store
    wanted = set(_recent("cluster"))
    if not wanted:
        return
    for pid, proj in store.projects().items():
        for cid, sel in (proj.get("clusters") or {}).items():
            if cid not in wanted:
                continue
            full = {**sel, "id": cid}
            # The negative verdict is cached too, so a cluster behind a dropped
            # VPN costs one short probe per pass rather than a timeout per part.
            if not kube.reachable(full)[0]:
                continue
            parts = ["nodes", "pods", "namespaces"]
            if kmanage.writable(full):
                parts.append("netshoots")
            for name in parts:
                try:
                    clusterview.part(full, name)
                except Exception:                              # noqa: BLE001
                    pass                # one bad part must not end the pass


def _warm_user_pages() -> None:
    """The timeline and the expiry radar, which cache per user because what
    each one may see depends on their roles. So they are warmed per user, for
    the people actually using the portal — warming them for an account nobody
    signs into would be collection with no reader."""
    from . import auth, expiry, timeline
    for uid in _recent("user"):
        user = auth.by_id(uid)
        if not user or user.get("disabled"):
            continue
        for call in (lambda: timeline.collect(user),
                     lambda: expiry.collect(user)):
            try:
                call()
            except Exception:                                  # noqa: BLE001
                pass


def _warm_conn_pages() -> None:
    """Every connection behind a page somebody has opened lately."""
    from . import store
    for area in _recent("page"):
        entry = PAGES.get(area)
        if not entry:
            continue
        kind, mod, fn = entry
        try:
            call = getattr(importlib.import_module(f".{mod}", __package__), fn)
        except (ImportError, AttributeError):                  # noqa: BLE001
            continue
        for conn in store.all_conns(kind):
            try:
                call(conn)
            except Exception:                                  # noqa: BLE001
                pass         # one unreachable server must not end the pass


def _sync_repos(wanted_only: bool = False) -> None:
    """Fast-forward every region somebody has been looking at.

    `wanted_only` is the prompt pass: just the regions a page found stale, so
    the between-cadence run is not a full sweep of the estate every 45 seconds.
    """
    from . import gitrepo, store
    # note_view() stringifies its key, so a region travels as "pid/rgid" — the
    # pair is needed to reach the repo config and neither half identifies it.
    for key in _recent("region"):
        pid, _, rgid = str(key).partition("/")
        if not (pid and rgid):
            continue
        if wanted_only and rgid not in _repo_wanted:
            continue
        with _guard:
            _repo_wanted.discard(rgid)
        rg = store.get_region(pid, rgid) or {}
        try:
            # one pull per distinct checkout among this region's environments —
            # the region itself has no repository to pull any more
            from . import repo as repomod
            did, seen = [], set()
            for env in sorted(store.env_sources(pid, rgid)):
                b = repomod.binding(pid, rgid, env)
                key = str(repomod.checkout(pid, rgid, env))
                if not b["url"] or key in seen:
                    continue
                seen.add(key)
                did.append(gitrepo.sync_env(pid, rgid, env, force=False))
            if not did:
                continue
            _repo_state[rgid] = {"at": time.time(),
                                 "outcome": "; ".join(did), "detail": ""}
        except Exception as e:                                # noqa: BLE001
            why = str(e)
            # Being mid-edit is not a failure. Saying so plainly keeps the page
            # from crying wolf on every region anybody is actually using.
            skipped = "uncommitted changes" in why
            _repo_state[rgid] = {"at": time.time(),
                                 "outcome": "skipped" if skipped else "failed",
                                 "detail": why[:200]}


def repo_state(rgid: str) -> dict:
    """What the last automatic sync of this region did, for the page to show."""
    return dict(_repo_state.get(rgid) or {})


def pass_once(what: str = "all") -> None:
    """One pass. Public so a test can run it without the thread, and so the
    loop can run the two cadences separately."""
    if not _running.acquire(blocking=False):
        return                          # the previous pass is still going
    try:
        steps = []
        if what in ("all", "slow"):
            steps += [_warm_fleet, _warm_summary, _warm_clusters,
                      _warm_user_pages]
        if what in ("all", "pages"):
            steps += [_warm_conn_pages]
        if what in ("all", "repos"):
            steps += [_sync_repos]
        if what in ("all", "slow"):
            steps += [_trim_recordings]
        if what == "repos-soon":
            steps += [lambda: _sync_repos(wanted_only=True)]
        for step in steps:
            try:
                step()
            except Exception:                                  # noqa: BLE001
                pass
    finally:
        _running.release()


def _trim_recordings() -> None:
    """Apply the PAM retention policy, if one is set.

    Here rather than in its own thread because it is the same shape as the
    other periodic work and costs nothing when no policy is configured — the
    function returns immediately when both limits are zero, which is the
    default. A retention policy nobody set must not delete anything.
    """
    from . import pam
    if not pam.enabled():
        return
    cfg = pam.config()
    if not cfg["keep_days"] and not cfg["keep_mb"] and not cfg["web_spares"]:
        return
    # Top the warm-seat pool up on the same cadence. Cheap when off: it
    # returns before touching a cluster if the pool size is zero.
    from . import webseat
    with __import__("contextlib").suppress(Exception):
        # Orphans FIRST: a finished or abandoned seat holds its memory request
        # until its deadline, and `ensure_spares` never looked at anything but
        # pods labelled as spares — so `taken` and unlabelled seats
        # accumulated. `pam.active_sessions` is the portal's own view of what
        # is genuinely open.
        live = {a.get("id") for a in (pam.active_sessions() or [])
                if a.get("id")}
        webseat.reap_orphans(cfg, live)
        webseat.ensure_spares(cfg)
    got = pam.trim_recordings()
    if got["by_age"] or got["by_size"]:
        from . import auth
        auth.audit(None, "pam_recordings_trimmed",
                   f"{got['by_age'] + got['by_size']} recording(s)",
                   f"{got['by_age']} past {cfg['keep_days']} days, "
                   f"{got['by_size']} over the {cfg['keep_mb']}MB cap, "
                   f"{got['freed'] // 1024}KB freed", "")


def start() -> None:
    """Begin warming. Called once, from the app's startup."""
    global _started
    with _guard:
        if _started:
            return
        _started = True

    def loop():
        # A short wait first: the app has just started, and the first request
        # is more likely than not already on its way in.
        time.sleep(5)
        while True:
            if _due("slow", SLOW_EVERY):
                pass_once("slow")
            if _due("pages", PAGE_EVERY):
                pass_once("pages")
            if _due("repos", REPO_EVERY):
                pass_once("repos")
            elif _repo_wanted and _due("repos-soon", REPO_FLOOR):
                pass_once("repos-soon")
            time.sleep(TICK)

    threading.Thread(target=loop, name="warmer", daemon=True).start()
