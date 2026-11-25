"""The city: every cluster a person may open, as one place to walk through.

WHY THIS EXISTS
    The 3D view (`scene.py`) is one cluster from the inside. This is the level
    above it: each cluster is a building on a street, and its door leads into
    that cluster's own view. What a building looks like from the street is
    what the fleet snapshot already knows about it, and nothing else.

WHAT IT MUST NEVER GET WRONG
    A picture is believed, and this one is looked at from a distance, so the
    three states that would draw the same quiet building have to stay apart:

      1. **Not read yet is not healthy.** The fleet snapshot is built behind
         the reader (`fleet.overview`, bounded by `FIRST_PAINT`), so the first
         answer after a restart holds no cluster at all. Every cluster the
         person may open is still listed here, from the database, and marked
         `reading`: a building with no lights on yet, not a calm one.
      2. **Did not answer is not empty.** An unreachable cluster carries no
         counts at all (`pods` is None, never zeros) and says why.
      3. **A cluster outside the role is not in the city.** The list is cut by
         `rbac.visible_clusters`, the same scope the hub and the 3D view
         apply, before the snapshot is consulted: a building that could not be
         entered would also be a name the role was never shown.

    Nothing here asks a cluster anything. It reads the database and the
    snapshot the Overview already keeps, so the page costs what the hub costs
    and polls for free.
"""
from __future__ import annotations

from . import config, fleet, rbac, repo, store

PROBLEMS = 6          # the pods a building's crowd speaks for, at most
WHY_CHARS = 160


def _serves(row: dict) -> list:
    """The environments a cluster serves, as the labels the hub shows."""
    out = []
    for u in row.get("used_by") or []:
        label = u.get("label") if isinstance(u, dict) else str(u)
        if label:
            out.append(str(label))
    return out[:6]


def building(pid: str, project: dict, cid: str, cluster: dict,
             row: dict | None, prod: bool) -> dict:
    """One cluster as the street sees it. `row` is its line in the fleet
    snapshot, or None when the snapshot has not read it yet."""
    out = {"pid": pid, "cid": cid, "name": cluster.get("name", cid),
           "project": project.get("name", pid), "prod": bool(prod),
           "state": "reading", "why": "", "nodes": None, "pods": None,
           "cpu": None, "mem": None, "cpu_src": "", "problems": [], "serves": []}
    if row is None:
        return out
    out["serves"] = _serves(row)
    if not row.get("reachable"):
        out["state"] = "down"
        out["why"] = (row.get("error") or "it did not answer")[:WHY_CHARS]
        return out
    nodes, pods = row.get("nodes") or {}, row.get("pods") or {}
    out["nodes"] = {"total": int(nodes.get("total") or 0),
                    "ready": int(nodes.get("ready") or 0)}
    out["pods"] = {"total": int(pods.get("total") or 0),
                   "bad": int(pods.get("bad") or 0),
                   "pending": int(pods.get("pending") or 0)}
    out["cpu"] = (row.get("cpu") or {}).get("pct")
    out["mem"] = (row.get("mem") or {}).get("pct")
    # "live" is measured use; anything else is what the pods ASKED for, which
    # is all a cluster without a metrics server can say, and the meter says so
    out["cpu_src"] = str((row.get("cpu") or {}).get("source") or "")
    out["problems"] = [{"name": str(p.get("name", "")), "ns": str(p.get("namespace", "")),
                        "status": str(p.get("status", "")),
                        "restarts": int(p.get("restarts") or 0)}
                       for p in (row.get("problems") or [])[:PROBLEMS]]
    sick = out["pods"]["bad"] or out["nodes"]["ready"] < out["nodes"]["total"]
    out["state"] = "bad" if sick else "ok"
    return out


def collect(user: dict | None) -> dict:
    """The city this person may walk: its districts (projects) and buildings
    (clusters), with whatever the snapshot knows of each."""
    seen = rbac.visible_clusters(user, "clusters")          # None: every one
    snap = fleet.overview()
    read = {c["cid"]: c for c in snap.get("clusters") or []}
    districts, buildings = [], []
    for pid, p in sorted(store.projects().items(),
                         key=lambda kv: (kv[1].get("name", ""), kv[0])):
        mine = sorted(((cid, c) for cid, c in (p.get("clusters") or {}).items()
                       if seen is None or cid in seen),
                      key=lambda kv: (kv[1].get("name", ""), kv[0]))
        if not mine:
            continue
        # which of this project's clusters serve production, once per project
        aliases = repo.naming(pid)["aliases"]
        prod = {mapped for rg in (p.get("regions") or {}).values()
                for env, mapped in (rg.get("env_clusters") or {}).items()
                if mapped and config.is_prod_env(env, aliases)}
        districts.append({"pid": pid, "name": p.get("name", pid),
                          "clusters": len(mine)})
        for cid, c in mine:
            buildings.append(building(pid, p, cid, c, read.get(cid), cid in prod))
    known = [b for b in buildings if b["pods"] is not None]
    return {
        "districts": districts, "buildings": buildings,
        "totals": {
            "clusters": len(buildings),
            "reading": sum(1 for b in buildings if b["state"] == "reading"),
            "down": sum(1 for b in buildings if b["state"] == "down"),
            "bad": sum(1 for b in buildings if b["state"] == "bad"),
            "ok": sum(1 for b in buildings if b["state"] == "ok"),
            # counted over the clusters that answered, and said to be
            "pods": sum(b["pods"]["total"] for b in known),
            "pods_bad": sum(b["pods"]["bad"] for b in known),
            "nodes": sum(b["nodes"]["total"] for b in known),
        },
        "at": snap.get("at", ""), "stale": bool(snap.get("stale")),
    }
