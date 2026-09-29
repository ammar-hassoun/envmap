"""Who sees what on the Overview page, and in which order.

WHY THIS IS DATA AND NOT MARKUP
    The Overview started as a fixed page, which meant every "can we also show…"
    was a code change. A panel is now an entry in the catalogue below plus a
    template of the same name; the order and widths are a per-person layout
    stored in the database and rearranged by dragging. Adding a panel is one
    template and one line; changing your own view is no code at all.

PER PERSON, NOT PER DEPLOYMENT
    Layouts are stored per user. Two people watching different things is normal —
    the person on call wants alerts first, the person doing a migration wants
    repositories — and one shared layout would mean they fight over it. A user
    with no saved layout gets DEFAULT, so a fresh install still looks composed.

COST FOLLOWS THE LAYOUT
    Each panel declares what data it needs. The route builds only what the
    visible panels ask for, so removing a panel actually makes the page cheaper
    rather than just hiding work that still happens.
"""
import json

from . import db

# width is in twelfths: quarter, third, half, two thirds, three quarters, full
WIDTHS = (3, 4, 6, 8, 9, 12)
# height is in board rows of ~96px; 0 means "as tall as the content", which is
# what every panel starts as. A fixed height scrolls inside itself.
HEIGHTS = (0, 2, 3, 4, 5, 6, 8)
# seconds between a panel's own refreshes. 0 means "follow the page", which is
# what every panel does until somebody says otherwise: a costly panel can be
# told to idle while an alerts panel is told to hurry, on the same board.
REFRESH = (0, 15, 30, 60, 300, 900)


CATALOGUE = {
    "tiles": {
        "title": "Fleet tiles", "icon": "🔢", "w": 12, "needs": ("fleet",),
        "note": "clusters reachable, nodes ready, pods healthy and unhealthy",
    },
    "health": {
        "title": "Fleet health", "icon": "🩺", "w": 12, "needs": ("fleet", "trend", "agg"),
        "note": "pooled cpu and memory, the healthy-pod ratio, and their trend",
    },
    "projects": {
        "title": "Projects", "icon": "🗂", "w": 12, "needs": ("fleet",),
        "note": "a card per project with its regions, environments and clusters",
    },
    "clusters": {
        "title": "Cluster cards", "icon": "☸", "w": 12, "needs": ("fleet", "trend"),
        "note": "one card per cluster with nodes, pods, usage and problems",
    },
    "pipelines": {
        "title": "Pipelines", "icon": "⚡", "w": 6, "needs": ("pipes",),
        "note": "build outcomes across every connected CI provider",
    },
    "security": {
        "title": "Security", "icon": "🛡", "w": 6, "needs": ("sec",),
        "note": "findings by severity from the connected scan platforms",
    },
    "alerts": {
        "title": "Firing alerts", "icon": "📣", "w": 6, "needs": ("alerts",),
        "note": "what is firing right now across the monitoring systems",
    },
    "assets": {
        "title": "Server assets", "icon": "🖥", "w": 6, "needs": ("assets",),
        "note": "inventory totals, warranty warnings and the physical/virtual split",
    },
    "spend": {
        "title": "IT spend", "icon": "🧾", "w": 6, "needs": ("spend",),
        "note": "what IT costs a month and a year, what has lapsed, and what "
                "renews in the next 30 days",
    },
    "repos": {
        "title": "Repositories", "icon": "⑂", "w": 6, "needs": ("repos",),
        "note": "clone state per region: branch, uncommitted files, staleness",
    },
    "activity": {
        "title": "Recent activity", "icon": "🕑", "w": 6, "needs": ("activity",),
        "note": "the latest entries from the audit log",
    },
    "logs": {
        "title": "Log stores", "icon": "📚", "w": 6, "needs": ("logs",),
        "note": "error-level volume in the last hour per connected log store",
    },
    "wf": {
        "title": "Workflows", "icon": "⏱", "w": 6, "needs": ("wf",),
        "note": "what is running and what failed recently, per Temporal "
                "namespace or Airflow DAG",
    },
    "gitops": {
        "title": "GitOps", "icon": "🔁", "w": 6, "needs": ("gitops",),
        "note": "Argo CD applications that have drifted from git or gone "
                "unhealthy — the two are counted apart",
    },
    "virt": {
        "title": "Hypervisors", "icon": "🖧", "w": 6, "needs": ("virt",),
        "note": "hosts, and how many virtual machines are actually powered on",
    },
    "dbs": {
        "title": "Database servers", "icon": "🗃", "w": 6, "needs": ("dbs",),
        "note": "registered servers per engine and what their last test "
                "recorded — this one makes no connection of its own",
    },
}

# What a new user sees: the shape the page had before it was arrangeable.
DEFAULT = [
    {"id": "tiles", "w": 12},
    {"id": "health", "w": 12},
    {"id": "pipelines", "w": 6},
    {"id": "security", "w": 6},
    {"id": "clusters", "w": 12},
    {"id": "projects", "w": 12},
]

SCHEMA = ["""CREATE TABLE IF NOT EXISTS layouts (
    user_id TEXT NOT NULL,
    page TEXT NOT NULL,
    panels TEXT,
    PRIMARY KEY (user_id, page))"""]


def _migrate(c) -> None:
    for stmt in SCHEMA:
        c.execute(stmt)


db.register(_migrate)


def _snap(value, allowed, fallback):
    """The nearest allowed step — a resize handle sends whatever the pointer
    said, and the grid only has the steps."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return fallback
    return min(allowed, key=lambda a: abs(a - v))


def clean(panels) -> list:
    """Only known panels, only allowed sizes, no duplicates.

    A layout arrives from a browser, so it is treated as a suggestion: anything
    unrecognised is dropped rather than trusted, and an empty result falls back
    to the default so nobody can save themselves a blank page. Off-step sizes
    snap to the nearest allowed value instead of being discarded, because they
    are what a drag handle naturally produces.
    """
    out, seen = [], set()
    for item in panels or []:
        pid = str((item or {}).get("id", ""))
        if pid not in CATALOGUE or pid in seen:
            continue
        w = _snap((item or {}).get("w"), WIDTHS, CATALOGUE[pid]["w"])
        h = _snap((item or {}).get("h") or 0, HEIGHTS, 0)
        entry = {"id": pid, "w": w}
        if h:
            entry["h"] = h
        if (item or {}).get("c"):
            entry["c"] = 1
        # Membership, not nearest: an interval is a choice from a menu, and
        # snapping 7 to 15 would silently give somebody a rate they did not pick.
        r = (item or {}).get("r")
        try:
            r = int(r or 0)
        except (TypeError, ValueError):
            r = 0
        if r in REFRESH and r:
            entry["r"] = r
        out.append(entry)
        seen.add(pid)
    return out


def get(user_id: str, page: str = "overview") -> list:
    row = db.one("SELECT panels FROM layouts WHERE user_id = ? AND page = ?",
                 (user_id or "", page))
    if not row:
        return [dict(p) for p in DEFAULT]
    try:
        saved = clean(json.loads(row["panels"] or "[]"))
    except json.JSONDecodeError:
        saved = []
    return saved or [dict(p) for p in DEFAULT]


def save(user_id: str, panels, page: str = "overview") -> list:
    kept = clean(panels)
    # An empty arrangement would be a blank landing page with no way back to the
    # panels, so it falls back to the default rather than being stored.
    if not kept:
        kept = [dict(p) for p in DEFAULT]
    db.run("INSERT OR REPLACE INTO layouts (user_id, page, panels) "
           "VALUES (?, ?, ?)", (user_id or "", page, json.dumps(kept)))
    return kept


def reset(user_id: str, page: str = "overview") -> list:
    db.run("DELETE FROM layouts WHERE user_id = ? AND page = ?",
           (user_id or "", page))
    return [dict(p) for p in DEFAULT]


def needs(panels) -> set:
    """The data keys the visible panels between them require."""
    out: set = set()
    for p in panels:
        out |= set(CATALOGUE[p["id"]]["needs"])
    return out


def available(panels) -> list:
    """Panels not currently on the page, for the "add" tray."""
    used = {p["id"] for p in panels}
    return [{"id": k, **v} for k, v in CATALOGUE.items() if k not in used]
