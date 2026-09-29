"""Overview roll-ups for things that live outside the clusters — CI pipelines
and security scan platforms.

These are the expensive neighbours: a Jenkins with a few hundred jobs costs
~1.5s and a DefectDojo portfolio ~1.8s. The fleet dashboard was deliberately
brought down to ~1.6s, so neither is allowed to block it. Each roll-up is
cached, refreshed on a background thread, and reports `pending` on the very
first look so the page can render immediately and fill in.

Everything here is read-only and derives from ci.fetch / security.overview,
which keep their own short caches — so a warm Overview costs nothing.
"""
import threading
import time

from . import ci, security, store

TTL = 90.0

_cache: dict = {}          # kind -> {"at": float, "data": dict}
_guard = threading.Lock()
_running: set = set()


def _get(kind: str, produce) -> dict:
    """Serve the cached roll-up; refresh behind the scenes when it ages out."""
    now = time.monotonic()
    hit = _cache.get(kind)
    if hit and now - hit["at"] < TTL:
        return hit["data"]
    _spawn(kind, produce)
    if hit:
        return {**hit["data"], "stale": True}
    return {"pending": True, "stale": True}


def _spawn(kind: str, produce) -> None:
    with _guard:
        if kind in _running:
            return
        _running.add(kind)

    def run():
        try:
            _cache[kind] = {"at": time.monotonic(), "data": produce()}
        except Exception:                                     # noqa: BLE001
            _cache[kind] = {"at": time.monotonic(),
                            "data": {"error": "could not be collected"}}
        finally:
            _running.discard(kind)

    threading.Thread(target=run, daemon=True).start()


def invalidate() -> None:
    _cache.clear()


# ── pipelines ──────────────────────────────────────────────────
def _pipelines() -> dict:
    conns = store.all_ci()
    counts = {"success": 0, "failed": 0, "running": 0, "cancelled": 0,
              "pending": 0, "unknown": 0}
    providers, failing, broken = {}, [], 0
    for c in conns:
        try:
            jobs = ci.fetch(c)["jobs"]
        except Exception:                                     # noqa: BLE001
            broken += 1
            continue
        pv = ci.PROVIDERS.get(c.get("type"), {})
        slot = providers.setdefault(c.get("type"), {
            "label": pv.get("label", c.get("type")), "icon": pv.get("icon", "⚡"),
            "key": c.get("type"), "jobs": 0, "failed": 0, "running": 0})
        slot["jobs"] += len(jobs)
        for j in jobs:
            counts[j["status"]] = counts.get(j["status"], 0) + 1
            if j["status"] == "failed":
                slot["failed"] += 1
                failing.append({"name": j["name"], "conn": c["name"],
                                "provider": c.get("type"), "cid": c["id"],
                                "branch": j.get("branch", ""),
                                "when": (j.get("last_failure") or {}).get("when", ""),
                                "url": j.get("url", "")})
            elif j["status"] == "running":
                slot["running"] += 1
    total = sum(counts.values())
    graded = counts["success"] + counts["failed"]
    return {
        "pending": False, "stale": False, "conns": len(conns), "total": total,
        "counts": counts, "broken": broken,
        "providers": sorted(providers.values(), key=lambda p: -p["jobs"]),
        "failing": sorted(failing, key=lambda f: f["name"].lower())[:6],
        # green share of jobs that actually have a verdict — pending and
        # never-built jobs would otherwise drag the figure down for no reason
        "green": round(counts["success"] / graded * 100, 1) if graded else 0.0,
        "graded": graded,
    }


def pipelines() -> dict:
    conns = store.all_ci()
    if not conns:
        return {"pending": False, "stale": False, "conns": 0, "total": 0}
    # the connection count is known without asking anyone, so carry it even in
    # the pending shape — otherwise the card has nothing to render on the first
    # load and vanishes instead of showing that it is still collecting
    return {"conns": len(conns), **_get("ci", _pipelines)}


# ── security ───────────────────────────────────────────────────
def _security() -> dict:
    conns = store.all_sec()
    totals = {s: 0 for s in security.SEVERITIES}
    platforms, products, broken = {}, 0, 0
    incomplete: list = []          # severities a platform could not answer for
    for c in conns:
        try:
            got = security.overview(c)
        except Exception:                                     # noqa: BLE001
            broken += 1
            continue
        for sev in (got.get("incomplete") or []):
            if sev not in incomplete:
                incomplete.append(sev)
        pv = security.PROVIDERS.get(c.get("type"), {})
        slot = platforms.setdefault(c.get("type"), {
            "label": pv.get("label", c.get("type")), "icon": pv.get("icon", "🛡"),
            "key": c.get("type"), "products": 0, "open": 0, "critical": 0})
        slot["products"] += got.get("products", 0)
        slot["open"] += got.get("open", 0)
        slot["critical"] += (got.get("totals") or {}).get("critical", 0)
        products += got.get("products", 0)
        for s in security.SEVERITIES:
            totals[s] += (got.get("totals") or {}).get(s, 0)
    return {
        "pending": False, "stale": False, "conns": len(conns),
        "totals": totals, "open": sum(totals.values()), "products": products,
        "broken": broken, "incomplete": incomplete,
        "platforms": sorted(platforms.values(), key=lambda p: -p["open"]),
    }


def security_roll() -> dict:
    conns = store.all_sec()
    if not conns:
        return {"pending": False, "stale": False, "conns": 0, "open": 0}
    return {"conns": len(conns), **_get("sec", _security)}
