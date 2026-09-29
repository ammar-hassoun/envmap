"""A short rolling history of fleet samples, so the dashboard can show trend
rather than only a point-in-time snapshot.

Deliberately small and boring: one JSON file, a fixed-length ring, appended
whenever the fleet is collected. This is decoration for a dashboard, not a
metrics store — if you want real retention, point Grafana at Prometheus. Losing
this file costs nothing but the sparklines.
"""
import json
import os
import threading
import time

from .store import DATA

FILE = DATA / "fleet-history.json"
CAP = 360                     # ~6h at one sample a minute
MIN_GAP = 20.0                # don't record more often than this

_lock = threading.Lock()


def _read() -> list:
    try:
        got = json.loads(FILE.read_text())
        return got if isinstance(got, list) else []
    except Exception:
        return []


def record(clusters: list, totals: dict) -> None:
    """Append one sample. Cheap enough to call on every collect."""
    now = time.time()
    with _lock:
        rows = _read()
        if rows and now - (rows[-1].get("t") or 0) < MIN_GAP:
            return
        rows.append({
            "t": round(now),
            "pods": totals.get("pods", 0),
            "bad": totals.get("pods_bad", 0),
            "nodes_ready": totals.get("nodes_ready", 0),
            "nodes": totals.get("nodes", 0),
            "c": {c["cid"]: {"cpu": (c.get("cpu") or {}).get("pct", 0),
                             "mem": (c.get("mem") or {}).get("pct", 0),
                             "pods": (c.get("pods") or {}).get("total", 0),
                             "bad": (c.get("pods") or {}).get("bad", 0),
                             "up": 1 if c.get("reachable") else 0}
                  for c in clusters},
        })
        rows = rows[-CAP:]
        try:
            tmp = FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(rows))
            os.chmod(tmp, 0o600)
            tmp.replace(FILE)
        except Exception:
            pass


def series(cid: str = "", key: str = "cpu", limit: int = 60) -> list:
    """Recent values for one cluster metric, oldest first. `cid=""` reads the
    fleet-level keys instead."""
    rows = _read()[-limit:]
    out = []
    for r in rows:
        if cid:
            out.append((r.get("c") or {}).get(cid, {}).get(key, 0) or 0)
        else:
            out.append(r.get(key, 0) or 0)
    return out


def span() -> str:
    """Human label for how much history we hold."""
    rows = _read()
    if len(rows) < 2:
        return ""
    mins = round((rows[-1]["t"] - rows[0]["t"]) / 60)
    if mins < 1:
        return "under a minute"
    if mins < 90:
        return f"{mins} min"
    return f"{round(mins / 60, 1)} h"


def samples() -> int:
    return len(_read())
