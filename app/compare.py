"""Configuration comparison.

Two modes:
  matrix  — one service across every environment of a region (the common case:
            "where does this differ between dev / preprod / prod?")
  pair    — any two services side by side, across projects if needed
"""
from . import config, repo, store

SEP = "|"


def encode(pid: str, rgid: str, env: str, fname: str) -> str:
    return SEP.join((pid, rgid, env, fname))


def decode(token: str):
    parts = (token or "").split(SEP)
    return tuple(parts) if len(parts) == 4 else None


def tree() -> list[dict]:
    """Nested catalogue for cascading pickers:
    projects → regions → envs → services, plus a service→envs index."""
    out = []
    for pid, p in store.projects().items():
        regions = []
        for rgid, rg in p.get("regions", {}).items():
            envs = []
            by_service: dict[str, list[str]] = {}
            for env, files in repo.list_envs(pid, rgid, include_hidden=True).items():
                services = []
                for f in files:
                    disp = repo.display(pid, f)
                    services.append({"file": f, "name": disp})
                    by_service.setdefault(disp, []).append(env)
                envs.append({"env": env, "label": env,
                             "services": sorted(services, key=lambda s: s["name"])})
            if envs:
                regions.append({"id": rgid, "name": rg.get("name", "?"),
                                "flag": rg.get("flag", ""), "envs": envs,
                                "service_envs": {k: sorted(v)
                                                 for k, v in by_service.items()}})
        if regions:
            out.append({"id": pid, "name": p.get("name", "?"),
                        "icon": p.get("icon", "📦"), "regions": regions})
    return out


def _load(token: str):
    d = decode(token)
    if not d:
        return None
    try:
        return repo.load_service(*d)
    except Exception:
        return None


def _flat(entry) -> tuple[dict, set]:
    cfg = {**entry["service_config"], **entry["platform_config"]}
    return cfg, set(entry["platform_config"])


def matrix(pid: str, rgid: str, service: str, envs: list[str],
           files: dict[str, str]) -> dict | None:
    """Compare one service across several environments of one region."""
    cols, loaded = [], {}
    for env in envs:
        e = _load(encode(pid, rgid, env, files[env]))
        if e is None:
            continue
        loaded[env] = e
        cols.append(env)
    if len(cols) < 2:
        return None

    plat_all: set = set()
    flat = {}
    for env in cols:
        cfg, plat = _flat(loaded[env])
        flat[env] = cfg
        plat_all |= plat

    rows = []
    all_keys = sorted(set().union(*(set(f) for f in flat.values())))
    for k in all_keys:
        vals = {e: (str(flat[e][k]) if k in flat[e] else None) for e in cols}
        present = [v for v in vals.values() if v is not None]
        distinct = len(set(present))
        missing = any(v is None for v in vals.values())
        rows.append({
            "key": k, "vals": vals, "platform": k in plat_all,
            "state": "same" if distinct <= 1 and not missing else "diff",
            "distinct": distinct, "missing": missing,
        })

    meta_rows = []
    for field, nice in (("image_tag", "image tag"), ("image_repo", "image repository"),
                        ("namespace", "namespace"), ("replicaCount", "replicas")):
        vals = {e: (str(loaded[e]["meta"].get(field))
                    if loaded[e]["meta"].get(field) is not None else None)
                for e in cols}
        present = [v for v in vals.values() if v is not None]
        meta_rows.append({"key": nice, "vals": vals, "platform": False,
                          "state": "same" if len(set(present)) <= 1
                                   and not any(v is None for v in vals.values())
                                   else "diff"})

    secret_rows = []
    all_secrets = sorted(set().union(*(set(loaded[e]["secret_keys"]) for e in cols)))
    for k in all_secrets:
        vals = {e: ("present" if k in loaded[e]["secret_keys"] else None) for e in cols}
        secret_rows.append({
            "key": k, "vals": vals, "platform": False,
            "state": "same" if all(v == "present" for v in vals.values()) else "diff"})

    diff_by_env = {e: sum(1 for r in rows if r["vals"][e] is None) for e in cols}
    # column headings and per-column links, the same two keys the pair view
    # provides — the template reads both for either mode
    aliases = (store.get_project(pid) or {}).get("env_aliases") or {}
    return {
        "mode": "matrix", "cols": cols, "rows": meta_rows + rows,
        "headers": {e: config.resolve_env(e, aliases) for e in cols},
        "links": {e: f"/p/{pid}/{rgid}/{e}/s/{files[e]}" for e in cols},
        "secrets": secret_rows, "service": service,
        "project": (store.get_project(pid) or {}).get("name", ""),
        "region": (store.get_region(pid, rgid) or {}).get("name", ""),
        "pid": pid, "rgid": rgid, "files": files,
        "counts": {
            "diff": sum(1 for r in rows if r["state"] == "diff"),
            "same": sum(1 for r in rows if r["state"] == "same"),
            "secret_diff": sum(1 for r in secret_rows if r["state"] == "diff"),
            "missing_by_env": diff_by_env,
        },
    }


def _two(a, b) -> dict:
    """Two loaded services, compared. The whole of one pair's answer.

    Lifted out of pair() so a sweep over forty services uses exactly the same
    comparison as one service compared on its own. Two implementations of "what
    differs" would eventually disagree, and the one nobody is looking at would be
    the wrong one.
    """
    ca, plat_a = _flat(a)
    cb, plat_b = _flat(b)
    rows = []
    for k in sorted(set(ca) | set(cb)):
        va = str(ca[k]) if k in ca else None
        vb = str(cb[k]) if k in cb else None
        rows.append({"key": k, "vals": {"A": va, "B": vb},
                     "platform": k in plat_a or k in plat_b,
                     "state": "same" if va == vb and va is not None else "diff"})
    meta_rows = []
    for field, nice in (("image_tag", "image tag"), ("image_repo", "image repository"),
                        ("namespace", "namespace"), ("replicaCount", "replicas")):
        va, vb = a["meta"].get(field), b["meta"].get(field)
        meta_rows.append({"key": nice, "platform": False,
                          "vals": {"A": None if va is None else str(va),
                                   "B": None if vb is None else str(vb)},
                          "state": "same" if str(va) == str(vb) else "diff"})
    sa, sb = set(a["secret_keys"]), set(b["secret_keys"])
    secret_rows = [{"key": k, "platform": False,
                    "vals": {"A": "present" if k in sa else None,
                             "B": "present" if k in sb else None},
                    "state": "same" if k in sa and k in sb else "diff"}
                   for k in sorted(sa | sb)]
    # only-in-one is counted apart from differs-in-value: "this key is missing
    # there" and "this key is set to something else" are different findings and
    # lead to different fixes.
    only_a = [r["key"] for r in rows if r["vals"]["B"] is None]
    only_b = [r["key"] for r in rows if r["vals"]["A"] is None]
    return {
        "rows": meta_rows + rows, "secrets": secret_rows,
        "counts": {
            "diff": sum(1 for r in rows if r["state"] == "diff"),
            "same": sum(1 for r in rows if r["state"] == "same"),
            "secret_diff": sum(1 for r in secret_rows if r["state"] == "diff"),
            "only_a": len(only_a), "only_b": len(only_b),
            "meta_diff": sum(1 for r in meta_rows if r["state"] == "diff"),
            "missing_by_env": {},
        },
    }


# There was a pair(token_a, token_b) here: two tokens, one service, its own
# result shape and its own half of the page. It is gone because a sweep with one
# service ticked answers exactly that question, through the same _two(), and two
# ways to ask it meant two shapes for a template to render and two paths for an
# answer to drift down.


# ── many services at once ──────────────────────────────────────
def services_in(pid: str, rgid: str, env: str) -> dict:
    """Display name → file, for one side. Matching is by the name a person sees,
    because the file behind it differs between regions often enough that matching
    on filename would report every service as missing from the other side."""
    out = {}
    for f in repo.list_envs(pid, rgid, include_hidden=True).get(env, []):
        out[repo.display(pid, f)] = f
    return out


def sweep(pid: str, rgid_a: str, env_a: str, rgid_b: str, env_b: str,
          services: list[str] | None = None) -> dict:
    """Every service on both sides, compared in one pass.

    WHY THIS EXISTS
        The pair view answers one question at a time, and the question is almost
        never about one service: "preprod works and prod does not" is asked about
        a deployment, and answering it meant choosing a service, comparing,
        going back, choosing the next. Forty services was forty round trips.

        So the sides pick a region and an environment, and every service they
        have in common is compared at once. What comes back is ordered by how
        different each service is, because that ordering is the answer — the
        service at the top is where to look.

    A SERVICE ON ONLY ONE SIDE IS A FINDING, NOT AN ERROR
        It is frequently THE finding: the reason prod behaves differently is
        that something was never deployed there. Those are listed with the
        rest rather than skipped, and they sort to the top.
    """
    ina = services_in(pid, rgid_a, env_a)
    inb = services_in(pid, rgid_b, env_b)
    names = sorted(set(ina) | set(inb))
    if services:
        want = {s for s in services}
        names = [n for n in names if n in want]
    rows = []
    for name in names:
        fa, fb = ina.get(name), inb.get(name)
        if not fa or not fb:
            rows.append({
                "service": name, "only": "A" if fa else "B",
                "counts": None, "rows": [], "secrets": [], "error": "",
                "links": {"A": (f"/p/{pid}/{rgid_a}/{env_a}/s/{fa}" if fa else ""),
                          "B": (f"/p/{pid}/{rgid_b}/{env_b}/s/{fb}" if fb else "")},
            })
            continue
        a = _load(encode(pid, rgid_a, env_a, fa))
        b = _load(encode(pid, rgid_b, env_b, fb))
        if a is None or b is None:
            # One unreadable file must not lose the other thirty-nine services.
            rows.append({"service": name, "only": "", "counts": None,
                         "rows": [], "secrets": [],
                         "error": "one side could not be read",
                         "links": {"A": f"/p/{pid}/{rgid_a}/{env_a}/s/{fa}",
                                   "B": f"/p/{pid}/{rgid_b}/{env_b}/s/{fb}"}})
            continue
        got = _two(a, b)
        rows.append({
            "service": name, "only": "", "error": "",
            "counts": got["counts"], "rows": got["rows"],
            "secrets": got["secrets"],
            "links": {"A": f"/p/{pid}/{rgid_a}/{env_a}/s/{fa}",
                      "B": f"/p/{pid}/{rgid_b}/{env_b}/s/{fb}"},
        })

    def weight(r):
        # missing first, then unreadable, then by how much differs. Sorting by
        # name would bury the one row worth reading.
        if r["only"]:
            return (0, 0, r["service"])
        if r["error"]:
            return (1, 0, r["service"])
        c = r["counts"]
        return (2, -(c["diff"] + c["secret_diff"] + c["meta_diff"]), r["service"])
    rows.sort(key=weight)
    differing = [r for r in rows
                 if r["only"] or r["error"] or r["counts"]["diff"]
                 or r["counts"]["secret_diff"] or r["counts"]["meta_diff"]]
    rg_a = store.get_region(pid, rgid_a) or {}
    rg_b = store.get_region(pid, rgid_b) or {}
    return {
        "mode": "sweep", "cols": ["A", "B"], "rows": [], "secrets": [],
        "services": rows,
        "headers": {"A": f"{rg_a.get('name', rgid_a)} · {env_a}",
                    "B": f"{rg_b.get('name', rgid_b)} · {env_b}"},
        "totals": {
            "services": len(rows),
            "differing": len(differing),
            "identical": len(rows) - len(differing),
            "only_a": sum(1 for r in rows if r["only"] == "A"),
            "only_b": sum(1 for r in rows if r["only"] == "B"),
            # Named key_diffs, not keys: `{{ totals.keys }}` in a template
            # resolves to the dict's own .keys METHOD, and the page printed
            # "<built-in method keys of dict object at 0x…>" where a number
            # belonged — and coloured the tile amber for ever, because a bound
            # method is truthy. Same trap as a row keyed "items".
            "key_diffs": sum((r["counts"]["diff"] if r["counts"] else 0)
                             for r in rows),
            "secret_diffs": sum((r["counts"]["secret_diff"] if r["counts"] else 0)
                                for r in rows),
            "unreadable": sum(1 for r in rows if r["error"]),
        },
        "counts": {"diff": 0, "same": 0, "secret_diff": 0, "missing_by_env": {}},
    }
