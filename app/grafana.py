"""A Grafana dashboard, read the way Grafana's own browser code reads it.

WHY THIS EXISTS. The dashboards tab first linked out to Grafana, then drew each
panel as a card of text, and both were rejected for the same reason: somebody
who opens a dashboard here expects to see what Grafana shows. Grafana has no
image renderer on the estates this was built against, so a picture cannot be
borrowed; the panels have to be drawn here, from the data.

MOST OF WHAT GRAFANA SHOWS IS DECIDED IN THE BROWSER, NOT BY THE SERVER. That
is the fact this module is built around, and each piece of it was confirmed by
asking a real Grafana rather than reading the schema:

  * template variables are resolved by the frontend, by running each one's own
    lookup (`label_values(cbnode_healthy{cluster="$cluster"}, node)`), in order,
    because later ones depend on earlier ones. `/api/ds/query` interpolates
    nothing: a query carrying `$node` is sent verbatim and matches nothing.
  * series are NAMED by the frontend. Each arrives as its own frame, named after
    the metric, with its labels attached and no display name. The legend reads
    `10.0.10.5:8091` because Grafana drops every label all the series share and
    shows what is left — a panel's overrides match on that computed name.
  * "table" format is a frontend pivot. The backend returns one single-row frame
    per series; the browser turns them into rows with a `Value #A` column per
    query, and the dashboard's own overrides are keyed on those names.

Rendering lives in `grafview`. This module only turns a dashboard, a time range
and a set of variable choices into panels and data.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import time
import urllib.parse
from datetime import datetime, timezone

from .monitoring import MonError, _auth, _cached, _req

# ── time ────────────────────────────────────────────────────────
_UNIT_S = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
           "M": 2592000, "y": 31536000}

QUICK_RANGES = (
    ("now-5m", "Last 5 minutes"), ("now-15m", "Last 15 minutes"),
    ("now-30m", "Last 30 minutes"), ("now-1h", "Last 1 hour"),
    ("now-3h", "Last 3 hours"), ("now-6h", "Last 6 hours"),
    ("now-12h", "Last 12 hours"), ("now-24h", "Last 24 hours"),
    ("now-2d", "Last 2 days"), ("now-7d", "Last 7 days"),
    ("now-30d", "Last 30 days"),
)


def parse_time(expr: str, now: float | None = None, is_to: bool = False) -> int:
    """Grafana's own words for a moment, as epoch milliseconds.

    `now`, `now-5m`, `now-1d/d` and `now/d` (rounded to the start of the unit,
    or its end for the right-hand side), bare epoch milliseconds as Grafana puts
    them in a URL, and ISO timestamps. Anything unreadable falls back to a sane
    window rather than refusing to draw: a wrong-but-plausible range shows data,
    a refusal shows nothing.
    """
    now = time.time() if now is None else now
    e = str(expr or "").strip()
    if not e or e == "now":
        return int(now * 1000)
    if e.isdigit():
        return int(e)
    m = re.fullmatch(r"now(?:([+-])(\d+)([smhdwMy]))?(?:/([smhdwMy]))?", e)
    if m:
        t = now
        if m.group(1):
            delta = int(m.group(2)) * _UNIT_S[m.group(3)]
            t = t - delta if m.group(1) == "-" else t + delta
        if m.group(4):
            step = _UNIT_S[m.group(4)]
            t = (math.floor(t / step) * step) + (step - 0.001 if is_to else 0)
        return int(t * 1000)
    try:
        return int(datetime.fromisoformat(e.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return int((now - (0 if is_to else 3600)) * 1000)


def time_range(frm: str, to: str) -> dict:
    a, b = parse_time(frm or "now-6h"), parse_time(to or "now", is_to=True)
    if b <= a:
        a = b - 3600_000
    label = next((lbl for key, lbl in QUICK_RANGES if key == frm and to in ("", "now")),
                 f"{frm} → {to}")
    return {"from": frm or "now-6h", "to": to or "now", "from_ms": a, "to_ms": b,
            "span_ms": b - a, "label": label}


# Grafana's own interval rounding, so `$__interval` means what the dashboard's
# author saw when they wrote the query.
_NICE_MS = (10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10_000, 15_000,
            20_000, 30_000, 60_000, 120_000, 300_000, 600_000, 900_000,
            1_200_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000,
            21_600_000, 43_200_000, 86_400_000, 604_800_000)


def _ms_to_prom(ms: int) -> str:
    s = max(1, int(round(ms / 1000)))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s % size == 0:
            return f"{s // size}{unit}"
    return f"{s}s"


def _prom_to_ms(text: str) -> int:
    m = re.fullmatch(r"(\d+)(ms|s|m|h|d|w|y)", str(text or "").strip())
    if not m:
        return 0
    n, u = int(m.group(1)), m.group(2)
    return n if u == "ms" else n * _UNIT_S[u] * 1000


def interval_ms(trange: dict, max_points: int, min_interval: str = "") -> int:
    raw = max(1, trange["span_ms"] // max(1, max_points))
    nice = next((n for n in _NICE_MS if n >= raw), _NICE_MS[-1])
    return max(nice, _prom_to_ms(min_interval) or 0)


def builtins(trange: dict, step_ms: int, dash: dict, scrape_ms: int = 15_000) -> dict:
    """The `$__` variables Grafana's frontend fills in before a query is sent."""
    rate = max(step_ms + scrape_ms, 4 * scrape_ms)
    span_s = max(1, trange["span_ms"] // 1000)
    return {
        "__interval": _ms_to_prom(step_ms), "__interval_ms": str(step_ms),
        "__rate_interval": _ms_to_prom(rate), "__rate_interval_ms": str(rate),
        "__range": f"{span_s}s", "__range_s": str(span_s),
        "__range_ms": str(trange["span_ms"]),
        "__from": str(trange["from_ms"]), "__to": str(trange["to_ms"]),
        "__dashboard": dash.get("title") or "",
    }


# ── playlists ───────────────────────────────────────────────────
# A wall screen in a NOC cycles through dashboards on its own. Grafana calls it
# a playlist and stores one; here a playlist is a FILTER over the dashboards the
# portal already lists -- every one, a folder, a tag, or a search -- so it needs
# no storage, cannot go stale when a dashboard is added, and is a URL somebody
# can bookmark on the TV.
PLAY_EVERY = (30, 60, 120, 300, 600)


def playlist(items: list, spec: str) -> list:
    """The dashboards a playlist spec selects, in the order they are listed."""
    kind, _, arg = (spec or "all").partition(":")
    arg_l = arg.lower()
    out = []
    for d in items:
        if not d.get("uid") or d.get("platform") != "grafana":
            continue
        if kind == "folder" and d.get("folder") != arg:
            continue
        if kind == "tag" and arg not in (d.get("tags") or []):
            continue
        if kind == "q" and arg_l not in " ".join(
                [d.get("title") or "", d.get("folder") or "", *(d.get("tags") or [])]).lower():
            continue
        out.append(d)
    return out


def playlist_label(spec: str) -> str:
    kind, _, arg = (spec or "all").partition(":")
    return {"folder": f"Folder: {arg}", "tag": f"Tag: {arg}",
            "q": f"Matching “{arg}”"}.get(kind, "All dashboards")


# ── the definition ──────────────────────────────────────────────
def _flatten(panels: list, row: dict | None = None) -> list:
    """Every panel with its enclosing row recorded.

    A COLLAPSED row keeps its children inside itself; an open one has them as
    ordinary siblings after it. Both are normalised to one list so the layout
    code can place them the same way, and collapsed children are marked so they
    are not queried until somebody opens the row — which is what Grafana does,
    and on a 122-panel exporter dashboard it is most of the cost.
    """
    out = []
    current = row
    for p in panels or []:
        if p.get("type") == "row":
            current = {"id": p.get("id"), "title": p.get("title") or "",
                       "collapsed": bool(p.get("collapsed")),
                       "y": (p.get("gridPos") or {}).get("y", 0)}
            out.append({**p, "_row": current})
            for child in p.get("panels") or []:
                out.append({**child, "_in_row": current,
                            "_hidden": current["collapsed"]})
        else:
            out.append({**p, "_in_row": current, "_hidden": False})
    return out


_LEGACY_CALC = {"current": "lastNotNull", "avg": "mean", "total": "sum", "min": "min",
                "max": "max", "first": "firstNotNull", "delta": "delta", "diff": "diff",
                "range": "range", "count": "count", "last": "lastNotNull"}


def _rgba_to_color(c):
    return str(c or "").replace(" ", "") or None


def _modernize(p: dict) -> dict:
    """Legacy panels, converted the way Grafana converts them on load.

    `singlestat` and `graph` were replaced in Grafana 7/8, but a dashboard
    imported from grafana.com years ago still carries them, and they keep what
    they look like in fields the new panels do not read: the unit in `format`
    or `yaxes`, thresholds as a string ("80,90") with a parallel `colors` list,
    colour modes as booleans, per-series colours in `aliasColors`. Read the
    modern way, every one of those values was simply ignored: an uptime showed
    as 1874274, a RAM figure as 806789120, and every line was grey.
    """
    kind = p.get("type")
    fc = copy.deepcopy(p.get("fieldConfig") or {"defaults": {}, "overrides": []})
    fc.setdefault("defaults", {})
    fc.setdefault("overrides", [])
    d = fc["defaults"]
    opt = copy.deepcopy(p.get("options") or {})
    if kind == "singlestat":
        d.setdefault("unit", p.get("format") or "none")
        if p.get("decimals") is not None:
            d.setdefault("decimals", p.get("decimals"))
        th = [x.strip() for x in str(p.get("thresholds") or "").split(",") if x.strip()]
        colors = p.get("colors") or []
        if th or colors:
            steps = [{"color": _rgba_to_color(colors[0]) if colors else "green", "value": None}]
            for i, t in enumerate(th):
                try:
                    steps.append({"color": _rgba_to_color(colors[i + 1]) if i + 1 < len(colors) else "red",
                                  "value": float(t)})
                except ValueError:
                    continue
            d.setdefault("thresholds", {"mode": "absolute", "steps": steps})
        d.setdefault("color", {"mode": "thresholds"})
        # Which list applies is decided by `mappingType` -- 1 value maps (the
        # default), 2 range maps -- never both. And a range from "null" to
        # "null" is not an open range: it is how the old panel said "when the
        # value is null". Read as a range it matched EVERY value, and every
        # legacy tile on a dashboard would have read "N/A".
        maps = []
        if int(p.get("mappingType") or 1) == 2:
            for rm in p.get("rangeMaps") or []:
                lo, hi = str(rm.get("from")), str(rm.get("to"))
                if lo == "null" and hi == "null":
                    maps.append({"type": "special", "options": {"match": "null",
                                 "result": {"text": rm.get("text")}}})
                else:
                    maps.append({"type": "range", "options": {
                        "from": None if lo in ("null", "None", "") else rm.get("from"),
                        "to": None if hi in ("null", "None", "") else rm.get("to"),
                        "result": {"text": rm.get("text")}}})
        else:
            for vm in p.get("valueMaps") or []:
                val = vm.get("value")
                if str(val) == "null":
                    maps.append({"type": "special", "options": {"match": "null",
                                 "result": {"text": vm.get("text")}}})
                else:
                    maps.append({"type": "value", "options": {str(val): {"text": vm.get("text")}}})
        if maps and not d.get("mappings"):
            d["mappings"] = maps
        opt.setdefault("colorMode", "background" if p.get("colorBackground") else
                       "value" if p.get("colorValue") else "none")
        opt.setdefault("graphMode", "area" if (p.get("sparkline") or {}).get("show") else "none")
        opt.setdefault("reduceOptions", {"calcs": [_LEGACY_CALC.get(p.get("valueName") or "current", "lastNotNull")]})
        opt.setdefault("textMode", "value")
        if (p.get("gauge") or {}).get("show"):
            gg = p["gauge"]
            d.setdefault("min", gg.get("minValue", 0))
            d.setdefault("max", gg.get("maxValue", 100))
            kind = "gauge"
            opt.setdefault("showThresholdMarkers", gg.get("thresholdMarkers", True))
        pre, post = p.get("prefix") or "", p.get("postfix") or ""
        if pre or post:
            opt["_affix"] = (pre, post)
    elif kind == "graph":
        ya = (p.get("yaxes") or [{}])[0] or {}
        d.setdefault("unit", ya.get("format") or "short")
        for k in ("min", "max"):
            if ya.get(k) not in (None, ""):
                try:
                    d.setdefault(k, float(ya[k]))
                except (TypeError, ValueError):
                    pass
        if p.get("decimals") is not None:
            d.setdefault("decimals", p.get("decimals"))
        d.setdefault("color", {"mode": "palette-classic"})
        cu = d.setdefault("custom", {})
        cu.setdefault("drawStyle", "bars" if p.get("bars") and not p.get("lines", True) else "line")
        cu.setdefault("lineWidth", p.get("linewidth", 1))
        cu.setdefault("fillOpacity", int(p.get("fill", 1) or 0) * 10)
        cu.setdefault("showPoints", "always" if p.get("points") else "never")
        cu.setdefault("pointSize", int(p.get("pointradius", 2) or 2) * 2)
        if p.get("stack"):
            cu.setdefault("stacking", {"mode": "percent" if p.get("percentage") else "normal"})
        for name, color in (p.get("aliasColors") or {}).items():
            fc["overrides"].append({"matcher": {"id": "byName", "options": name},
                                    "properties": [{"id": "color", "value": {"mode": "fixed",
                                                    "fixedColor": color}}]})
        for so in p.get("seriesOverrides") or []:
            alias = str(so.get("alias") or "")
            props = []
            if so.get("color"):
                props.append({"id": "color", "value": {"mode": "fixed", "fixedColor": so["color"]}})
            if "fill" in so:
                props.append({"id": "custom.fillOpacity", "value": int(so["fill"] or 0) * 10})
            if "linewidth" in so:
                props.append({"id": "custom.lineWidth", "value": so["linewidth"]})
            if props and alias:
                rx = alias[1:-1] if alias.startswith("/") and alias.endswith("/") else None
                fc["overrides"].append({"matcher": {"id": "byRegexp" if rx else "byName",
                                                    "options": rx or alias}, "properties": props})
        lg = p.get("legend") or {}
        if "legend" not in opt:
            calcs = [k for k, v in (("mean", lg.get("avg")), ("max", lg.get("max")),
                                    ("min", lg.get("min")), ("lastNotNull", lg.get("current")),
                                    ("sum", lg.get("total"))) if v]
            opt["legend"] = {"showLegend": lg.get("show", True) is not False,
                             "displayMode": "table" if lg.get("alignAsTable") else "list",
                             "placement": "right" if lg.get("rightSide") else "bottom",
                             "calcs": calcs}
        kind = "timeseries"
    elif kind == "grafana-piechart-panel":
        kind = "piechart"
        opt.setdefault("pieType", p.get("pieType") or "pie")
        d.setdefault("unit", p.get("format") or "short")
    return {**p, "type": kind, "fieldConfig": fc, "options": opt}


def dashboard(conn: dict, uid: str, refresh: bool = False) -> dict:
    if conn.get("type") != "grafana":
        raise MonError("only Grafana dashboards can be opened in the portal")
    base = conn["base_url"].rstrip("/")
    got = _cached(conn, f"dash:{uid}", refresh, lambda: _req(
        f"{base}/api/dashboards/uid/{urllib.parse.quote(uid)}",
        _auth(conn), not conn.get("skip_tls")))
    doc = (got or {}).get("dashboard") or {}
    meta = (got or {}).get("meta") or {}
    panels = []
    for p in _flatten(doc.get("panels") or []):
        p = _modernize(p)
        g = p.get("gridPos") or {}
        panels.append({
            "id": p.get("id"), "type": p.get("type") or "",
            "title": p.get("title") or "", "description": p.get("description") or "",
            "grid": {"x": int(g.get("x") or 0), "y": int(g.get("y") or 0),
                     "w": int(g.get("w") or 12), "h": int(g.get("h") or 8)},
            "is_row": p.get("type") == "row", "row": p.get("_row"),
            "in_row": p.get("_in_row"), "hidden": bool(p.get("_hidden")),
            "datasource": p.get("datasource"), "targets": p.get("targets") or [],
            "field_config": p.get("fieldConfig") or {"defaults": {}, "overrides": []},
            "options": p.get("options") or {},
            "transformations": p.get("transformations") or [],
            "interval": p.get("interval") or "", "max_points": p.get("maxDataPoints"),
            "time_from": p.get("timeFrom") or "", "links": p.get("links") or [],
            "repeat": p.get("repeat") or "",
            # legacy text panels keep their body at the top level
            "content": ((p.get("options") or {}).get("content")
                        or p.get("content") or ""),
            "mode": ((p.get("options") or {}).get("mode") or p.get("mode")
                     or "markdown"),
        })
    return {
        "uid": uid, "title": doc.get("title") or uid,
        "description": doc.get("description") or "",
        "tags": doc.get("tags") or [], "refresh": doc.get("refresh") or "",
        "folder": meta.get("folderTitle") or "General",
        "url": conn["base_url"].rstrip("/") + (meta.get("url") or ""),
        "time": doc.get("time") or {"from": "now-6h", "to": "now"},
        "timezone": doc.get("timezone") or "browser",
        "templating": (doc.get("templating") or {}).get("list") or [],
        "panels": panels,
    }


def datasources(conn: dict) -> list:
    try:
        got = _cached(conn, "datasources", False, lambda: _req(
            f"{conn['base_url'].rstrip('/')}/api/datasources",
            _auth(conn), not conn.get("skip_tls")))
        return got if isinstance(got, list) else []
    except MonError:
        return []


def resolve_ds(conn: dict, ds, scope: dict | None = None, want: str = "") -> dict:
    """A datasource reference as a real {type, uid}, however it was stored.

    Grafana has written this three ways and one estate holds all of them: the
    modern {type, uid}; a DATASOURCE VARIABLE (`${ds_prometheus}`), which the
    API never interpolates and answers with 404; and a bare string that is a
    uid on some dashboards and a NAME on others. An unresolvable variable falls
    back to the first datasource of the requested type — never across types,
    because drawing the right kind of thing from the wrong instance is a worse
    answer than none.
    """
    known = datasources(conn)
    by_uid = {d.get("uid"): d for d in known if d.get("uid")}
    by_name = {(d.get("name") or "").lower(): d for d in known}
    if ds is None or ds == "" or (isinstance(ds, dict) and ds.get("uid") in ("-- Dashboard --", "-- Mixed --")):
        pick = next((d for d in known if d.get("isDefault")), known[0] if known else {})
        return {"type": pick.get("type", ""), "uid": pick.get("uid", "")}
    if isinstance(ds, str):
        text = interpolate(ds, scope or {}, {}, "raw") if "$" in ds else ds
        hit = by_uid.get(text) or by_name.get(text.lower())
        if hit:
            return {"type": hit.get("type", ""), "uid": hit.get("uid", "")}
        ds = {"type": want, "uid": text}
    ds = dict(ds)
    uid = str(ds.get("uid") or "")
    if "$" in uid:
        uid = interpolate(uid, scope or {}, {}, "raw")
    if not uid and (hit := by_uid.get(str(ds.get("type") or ""))):
        return {"type": hit.get("type", ""), "uid": hit.get("uid", "")}
    if uid in by_uid:
        return {"type": by_uid[uid].get("type", ""), "uid": uid}
    hit = by_name.get(uid.lower())
    if hit:
        return {"type": hit.get("type", ""), "uid": hit.get("uid", "")}
    kind = ds.get("type") or want
    if kind:
        # ONLY WHEN THERE IS NO CHOICE TO MAKE. A uid this Grafana does not have
        # usually means the dashboard was imported from another one; with a
        # single datasource of that type the answer is obvious, with several it
        # is a guess, and a guess here draws the wrong instance's numbers
        # under the right title.
        same = [d for d in known if d.get("type") == kind]
        if len(same) == 1:
            return {"type": kind, "uid": same[0].get("uid", "")}
    return {"type": kind or "", "uid": uid if uid and "$" not in uid else ""}


def scrape_ms(conn: dict, ds: dict) -> int:
    """The datasource's own minimum interval ("scrape interval"), in ms.

    Grafana reads it from the datasource's jsonData.timeInterval and defaults a
    Prometheus to 15s when it is unset.
    """
    hit = next((d for d in datasources(conn) if d.get("uid") == (ds or {}).get("uid")), None)
    iv = str(((hit or {}).get("jsonData") or {}).get("timeInterval") or "")
    ms = _prom_to_ms(iv)
    if ms:
        return ms
    return 15_000 if _dialect(ds) == "prometheus" else 0


# ── variables ───────────────────────────────────────────────────
ALL = "$__all"


def _var_def(v: dict) -> str:
    q = v.get("query")
    if isinstance(q, dict):
        q = q.get("query") or q.get("qryType") and "" or ""
    return str(v.get("definition") or q or "")


def _prom_resource(conn: dict, ds_uid: str, path: str, params: dict) -> dict:
    base = conn["base_url"].rstrip("/")
    url = (f"{base}/api/datasources/uid/{urllib.parse.quote(ds_uid)}/resources/api/v1/"
           f"{path}?{urllib.parse.urlencode(params, doseq=True)}")
    return _req(url, _auth(conn), not conn.get("skip_tls")) or {}


def _prom_lookup(conn: dict, ds: dict, text: str, trange: dict) -> list[str]:
    """Run one Prometheus variable definition, as the Grafana frontend would."""
    window = {"start": trange["from_ms"] // 1000, "end": trange["to_ms"] // 1000}
    text = text.strip()
    m = re.fullmatch(r"label_values\(\s*(?:(.+?)\s*,\s*)?([A-Za-z_][\w]*)\s*\)", text, re.S)
    if m:
        match, label = m.group(1), m.group(2)
        params = dict(window)
        if match:
            params["match[]"] = match
        got = _prom_resource(conn, ds["uid"], f"label/{label}/values", params)
        return [str(x) for x in (got.get("data") or [])]
    m = re.fullmatch(r"label_names\(\s*(.*?)\s*\)", text, re.S)
    if m:
        params = dict(window)
        if m.group(1):
            params["match[]"] = m.group(1)
        got = _prom_resource(conn, ds["uid"], "labels", params)
        return [str(x) for x in (got.get("data") or []) if x != "__name__"]
    m = re.fullmatch(r"metrics\(\s*(.*?)\s*\)", text, re.S)
    if m:
        got = _prom_resource(conn, ds["uid"], "label/__name__/values", window)
        rx = m.group(1) or ".*"
        return [str(x) for x in (got.get("data") or []) if re.search(rx, str(x))]
    m = re.fullmatch(r"query_result\(\s*(.+)\s*\)", text, re.S)
    body = m.group(1) if m else text
    frames = _query(conn, [{"refId": "V", "datasource": ds, "expr": body,
                            "instant": True, "range": False}], trange)
    out = []
    for fr in (frames.get("V") or {}).get("frames") or []:
        for f in _fields(fr):
            if f["type"] == "number":
                lab = f.get("labels") or {}
                name = lab.get("__name__", "")
                inner = ",".join(f'{k}="{v}"' for k, v in lab.items() if k != "__name__")
                val = f["values"][-1] if f["values"] else ""
                out.append(f"{name}{{{inner}}} {val} {int(time.time() * 1000)}")
    return out


def _sql_lookup(conn: dict, ds: dict, text: str, trange: dict) -> list[str]:
    frames = _query(conn, [{"refId": "V", "datasource": ds, "rawSql": text,
                            "format": "table"}], trange)
    out = []
    for fr in (frames.get("V") or {}).get("frames") or []:
        fields = _fields(fr)
        pick = next((f for f in fields if f["name"] == "__value"), None) or \
            (fields[0] if fields else None)
        if pick:
            out.extend(str(v) for v in pick["values"] if v is not None)
    return out


def _options_from(values: list[str], regex: str, sort: int) -> list[dict]:
    """Grafana's regex filter and sort, applied to a variable's raw values."""
    rx = None
    if regex:
        body = regex[1:regex.rindex("/")] if regex.startswith("/") and regex.count("/") >= 2 else regex
        try:
            rx = re.compile(body)
        except re.error:
            rx = None
    opts, seen = [], set()
    for raw in values:
        text = value = raw
        if rx is not None:
            m = rx.search(raw)
            if not m:
                continue
            gd = m.groupdict()
            if gd.get("value") or gd.get("text"):
                value = gd.get("value") or gd.get("text")
                text = gd.get("text") or value
            elif m.groups():
                text = value = next((g for g in m.groups() if g is not None), raw)
        if value in seen:
            continue
        seen.add(value)
        opts.append({"text": text, "value": value})
    if sort in (1, 2):
        opts.sort(key=lambda o: o["text"], reverse=sort == 2)
    elif sort in (3, 4):
        def num(o):
            m = re.search(r"-?\d+(?:\.\d+)?", o["text"])
            return float(m.group()) if m else float("inf")
        opts.sort(key=num, reverse=sort == 4)
    elif sort in (5, 6):
        opts.sort(key=lambda o: o["text"].lower(), reverse=sort == 6)
    return opts


def variables(conn: dict, dash: dict, chosen: dict, trange: dict,
              refresh: bool = False) -> list[dict]:
    """Every template variable resolved, IN ORDER, the way Grafana does it.

    `chosen` is what the URL asked for (`var-node=…`, repeatable). A choice the
    options do not contain is dropped, the stored current value is used if it
    is still valid, and otherwise the first option — or All, when the variable
    was saved on All. That last rule matters: a dashboard nobody has opened
    since its exporter was renamed stores a value that no longer exists, and
    keeping it is how every panel ends up empty.
    """
    out, scope = {}, {}
    for v in _dependency_order(dash.get("templating") or []):
        name, kind = v.get("name") or "", v.get("type") or "query"
        if not name:
            continue
        rec = {"name": name, "label": v.get("label") or name, "type": kind,
               "hide": int(v.get("hide") or 0), "multi": bool(v.get("multi")),
               "include_all": bool(v.get("includeAll")),
               "all_value": v.get("allValue") or None,
               "options": [], "current": [], "error": ""}
        try:
            if kind == "custom":
                parts = [p.strip() for p in re.split(r"(?<!\\),", _var_def(v)) if p.strip()]
                rec["options"] = []
                for p in parts:
                    t, _, val = p.partition(" : ")
                    rec["options"].append({"text": t.strip(), "value": (val or t).strip()})
            elif kind == "constant":
                rec["options"] = [{"text": _var_def(v), "value": _var_def(v)}]
                rec["hide"] = 2
            elif kind == "textbox":
                txt = (chosen.get(name) or [None])[0]
                if txt is None:
                    txt = (v.get("current") or {}).get("value") or _var_def(v)
                rec["options"] = [{"text": str(txt), "value": str(txt)}]
            elif kind == "interval":
                parts = [p.strip() for p in _var_def(v).split(",") if p.strip()]
                rec["options"] = [{"text": p, "value": p} for p in parts]
            elif kind == "datasource":
                want = str(v.get("query") or "")
                rx = v.get("regex") or ""
                rec["options"] = [{"text": d.get("name"), "value": d.get("uid")}
                                  for d in datasources(conn) if d.get("type") == want
                                  and (not rx or re.search(rx.strip("/"), d.get("name") or ""))]
            elif kind == "query":
                ds = resolve_ds(conn, v.get("datasource"), scope)
                text = interpolate(_var_def(v), scope, builtins(trange, 60_000, dash),
                                   _dialect(ds))
                key = hashlib.sha1(f"{ds.get('uid')}|{text}|{trange['from']}|{trange['to']}"
                                   .encode(), usedforsecurity=False).hexdigest()[:16]

                def look():
                    if _dialect(ds) == "prometheus":
                        return _prom_lookup(conn, ds, text, trange)
                    if _dialect(ds) == "sql":
                        return _sql_lookup(conn, ds, text, trange)
                    return []
                raw = _cached(conn, f"var:{key}", refresh, look)
                rec["options"] = _options_from(raw, v.get("regex") or "",
                                               int(v.get("sort") or 0))
            else:
                rec["hide"] = max(rec["hide"], 2) if kind == "adhoc" else rec["hide"]
        except MonError as e:
            rec["error"] = str(e)[:160]

        values = [o["value"] for o in rec["options"]]
        want = [x for x in chosen.get(name, []) if x == ALL or x in values
                or kind in ("textbox",)]
        if not want:
            stored = (v.get("current") or {}).get("value")
            stored = stored if isinstance(stored, list) else ([stored] if stored not in (None, "") else [])
            stored = [str(s) for s in stored]
            if stored and all(s == ALL or s in values for s in stored):
                want = stored
            elif stored and ALL in stored and rec["include_all"]:
                want = [ALL]
            elif values:
                want = [values[0]]
        if want and not rec["multi"] and want != [ALL]:
            want = want[:1]
        if want == [ALL] and not rec["include_all"]:
            want = values[:1]
        rec["current"] = want
        rec["is_all"] = want == [ALL]
        rec["values"] = values if rec["is_all"] else want
        out[name] = rec
        scope[name] = rec
    # resolved in dependency order, SHOWN in the dashboard's own order -- the
    # variable bar is laid out the way the author arranged it
    return [out[v["name"]] for v in dash.get("templating") or []
            if v.get("name") in out]


def _refs(text: str, name: str) -> bool:
    return bool(re.search(r"\$\{" + re.escape(name) + r"(?:[:}])|\$" + re.escape(name)
                          + r"(?!\w)|\[\[" + re.escape(name) + r"(?::\w+)?\]\]", text or ""))


def _dependency_order(templating: list) -> list:
    """Variables ordered so each one comes after every variable it mentions.

    Grafana resolves in DEPENDENCY order, not list order, and dashboards rely on
    it: one on this estate declares `host` -- `label_values(...{job="$job"},
    instance)` -- BEFORE `job`. Resolved in list order, `$job` does not exist
    yet, the lookup matches nothing, `host` has no options, and every panel
    queries `instance=~""`. A cycle keeps the author's order rather than
    looping.
    """
    named = [v for v in templating if v.get("name")]
    text = {v["name"]: json.dumps([_var_def(v), v.get("datasource"),
                                   v.get("regex") or ""]) for v in named}
    deps = {v["name"]: {o["name"] for o in named
                        if o["name"] != v["name"] and _refs(text[v["name"]], o["name"])}
            for v in named}
    done, order = set(), []
    pending = list(named)
    while pending:
        ready = [v for v in pending if deps[v["name"]] <= done]
        if not ready:                       # a cycle: fall back to list order
            ready = pending[:1]
        for v in ready:
            order.append(v)
            done.add(v["name"])
            pending.remove(v)
    return order + [v for v in templating if not v.get("name")]


def scope_of(vars_: list) -> dict:
    return {v["name"]: v for v in vars_}


# ── interpolation ───────────────────────────────────────────────
_VAR_RX = re.compile(r"\$\{([\w.]+)(?::(\w+))?\}|\[\[(\w+)(?::(\w+))?\]\]|\$([A-Za-z_]\w*)")
_PROM_SPECIAL = re.compile(r"[$^*{}\[\]'+?.()|]")


def _dialect(ds: dict) -> str:
    t = (ds or {}).get("type") or ""
    if "prometheus" in t or t in ("loki",):
        return "prometheus"
    if any(k in t for k in ("mysql", "postgres", "mssql", "sql")):
        return "sql"
    return "raw"


def _fmt(values: list[str], fmt: str, var: dict | None, dialect: str) -> str:
    if fmt == "regex":
        esc = [re.escape(x) for x in values]
        return esc[0] if len(esc) == 1 else "(" + "|".join(esc) + ")"
    if fmt == "pipe":
        return "|".join(values)
    if fmt == "csv":
        return ",".join(values)
    if fmt in ("raw", "text"):
        return ",".join(values)
    if fmt == "json":
        return json.dumps(values if len(values) != 1 else values[0])
    if fmt == "singlequote":
        return ",".join("'" + x.replace("'", "\\'") + "'" for x in values)
    if fmt == "doublequote":
        return ",".join('"' + x.replace('"', '\\"') + '"' for x in values)
    if fmt == "sqlstring":
        return ",".join("'" + x.replace("'", "''") + "'" for x in values)
    if fmt == "glob":
        return values[0] if len(values) == 1 else "{" + ",".join(values) + "}"
    if fmt in ("queryparam", "percentencode"):
        return "&".join(urllib.parse.quote(x) for x in values)
    # the datasource's own default, as Grafana's datasource plugins apply it
    multiish = bool(var and (var.get("multi") or var.get("include_all")))
    if dialect == "prometheus":
        if not multiish:
            return (values[0] if values else "").replace("\\", "\\\\").replace("'", "\\'")
        esc = [_PROM_SPECIAL.sub(lambda m: "\\\\" + m.group(), x) for x in values]
        return esc[0] if len(esc) == 1 else "(" + "|".join(esc) + ")"
    if dialect == "sql":
        if not multiish and len(values) == 1:
            return values[0]
        return ",".join("'" + x.replace("'", "''") + "'" for x in values)
    return values[0] if len(values) == 1 else "{" + ",".join(values) + "}"


def interpolate(text: str, scope: dict, extra: dict, dialect: str = "prometheus") -> str:
    """Substitute `$var`, `${var}`, `${var:format}` and `[[var]]` into text."""
    if not text or "$" not in text and "[[" not in text:
        return text or ""

    def one(m):
        name = m.group(1) or m.group(3) or m.group(5)
        fmt = m.group(2) or m.group(4) or ""
        if name in extra:
            return str(extra[name])
        var = scope.get(name)
        if var is None:
            return m.group(0)
        if var.get("is_all") and var.get("all_value") is not None:
            return str(var["all_value"])
        values = [str(x) for x in (var.get("values") or [])]
        if not values:
            return ""
        return _fmt(values, fmt, var, dialect)
    return _VAR_RX.sub(one, text)


# ── queries ─────────────────────────────────────────────────────
_QUERY_KEYS = ("expr", "query", "rawSql", "target", "queryText", "expression")


def _query(conn: dict, queries: list, trange: dict) -> dict:
    body = {"queries": queries, "from": str(trange["from_ms"]),
            "to": str(trange["to_ms"])}
    got = _req(f"{conn['base_url'].rstrip('/')}/api/ds/query", _auth(conn),
               not conn.get("skip_tls"), body)
    return (got or {}).get("results") or {}


def _fields(frame: dict) -> list:
    schema = frame.get("schema") or {}
    values = (frame.get("data") or {}).get("values") or []
    out = []
    for i, f in enumerate(schema.get("fields") or []):
        out.append({"name": f.get("name") or "", "type": f.get("type") or "",
                    "labels": f.get("labels") or {},
                    "config": f.get("config") or {},
                    "values": values[i] if i < len(values) else []})
    return out


def run_panel(conn: dict, dash: dict, panel: dict, scope: dict, trange: dict,
              width_px: int = 800, refresh: bool = False) -> dict:
    """Every visible query on a panel, run together, as frames."""
    targets = [t for t in panel["targets"] if not t.get("hide")]
    if not targets:
        return {"frames": [], "errors": [], "queries": []}
    points = int(panel.get("max_points") or max(40, min(1200, width_px // 2)))
    panel_ds = resolve_ds(conn, panel.get("datasource"), scope)
    # THE STEP NEVER GOES BELOW THE SCRAPE INTERVAL, which is Grafana's own
    # rule. Derived from the panel's pixel width alone, a five-minute window on
    # a 700px panel asked for a 1s step: 301 points for an exporter scraped
    # every 15s, each sample repeated fifteen times, drawn as flat runs with
    # vertical cliffs where Grafana draws 21 points joined by diagonals.
    scrape = scrape_ms(conn, panel_ds)
    step = interval_ms(trange, points, panel.get("interval") or "")
    step = max(step, scrape) if _dialect(panel_ds) == "prometheus" else step
    extra = builtins(trange, step, dash, scrape_ms=scrape or 15_000)
    payload, shown = [], []
    for i, t in enumerate(targets):
        # A target naming no datasource, or one that cannot be resolved -- an
        # IMPORT PLACEHOLDER like ${DS_PROMETHEUS} left behind when an exported
        # dashboard's inputs were never mapped -- uses the panel's, which is
        # what Grafana's own frontend does. Sending it through unresolved is a
        # 400 "does not contain a valid data source identifier".
        ds = resolve_ds(conn, t.get("datasource"), scope, panel_ds.get("type", "")) \
            if t.get("datasource") else panel_ds
        if not ds.get("uid"):
            ds = panel_ds
        dialect = _dialect(ds)
        q = {k: v for k, v in t.items() if k not in ("datasource",)}
        q["refId"] = t.get("refId") or chr(65 + i)
        q["datasource"] = ds
        q["intervalMs"], q["maxDataPoints"] = step, points
        for key in _QUERY_KEYS:
            if isinstance(q.get(key), str):
                q[key] = interpolate(q[key], scope, extra, dialect)
        if dialect == "prometheus":
            inst = bool(t.get("instant")) and not t.get("range")
            q["instant"], q["range"] = inst, not inst
            if q.get("expr"):
                shown.append(q["expr"])
        elif q.get("rawSql"):
            shown.append(q["rawSql"])
        payload.append(q)

    # the cache key is the query AS SENT, so two users choosing different
    # variables never share an answer, and the window is rounded to the step so
    # a relative range still hits the cache within its lifetime
    fp = hashlib.sha1(json.dumps({"q": payload, "f": trange["from"], "t": trange["to"],
                                  "b": trange["from_ms"] // max(step, 15_000)},
                                 sort_keys=True, default=str).encode(),
                      usedforsecurity=False).hexdigest()[:20]

    def go():
        try:
            res = _query(conn, payload, trange)
        except MonError as e:
            return {"frames": [], "errors": [str(e)[:200]], "queries": shown}
        frames, errors = [], []
        for q in payload:
            r = res.get(q["refId"]) or {}
            if r.get("error"):
                errors.append(f"{q['refId']}: {str(r['error'])[:200]}")
            for fr in r.get("frames") or []:
                frames.append({"refId": q["refId"], "name": (fr.get("schema") or {}).get("name") or "",
                               "fields": _fields(fr)})
        return {"frames": frames, "errors": errors, "queries": shown}
    return _cached(conn, f"pq:{dash['uid']}:{panel['id']}:{fp}", refresh, go)


# ── frames → series and tables ─────────────────────────────────
def _legend(fmt: str, labels: dict) -> str:
    return re.sub(r"\{\{\s*([\w.]+)\s*\}\}", lambda m: str(labels.get(m.group(1), "")), fmt)


def _label_text(labels: dict) -> str:
    name = labels.get("__name__", "")
    rest = ", ".join(f'{k}="{v}"' for k, v in labels.items() if k != "__name__")
    return f"{name}{{{rest}}}" if rest else name


def series(frames: list, panel: dict) -> list:
    """Numeric fields as series, named the way Grafana's legend names them."""
    legends = {t.get("refId"): t.get("legendFormat") or "" for t in panel["targets"]}
    out = []
    for fr in frames:
        fields = fr["fields"]
        tfield = next((f for f in fields if f["type"] == "time"), None)
        for f in fields:
            if f["type"] != "number":
                continue
            out.append({"refId": fr["refId"], "field": f["name"], "labels": f["labels"],
                        "times": tfield["values"] if tfield else [],
                        "values": f["values"], "frame": fr["name"],
                        "ds_name": (f["config"] or {}).get("displayNameFromDS") or "",
                        "legend": legends.get(fr["refId"], "")})
    # Grafana's naming: labels shared by EVERY series say nothing about which
    # one this is, so they are dropped and what is left is the name.
    common = {}
    if len(out) > 1:
        first = out[0]["labels"]
        common = {k: v for k, v in first.items()
                  if all(s["labels"].get(k) == v for s in out)}
    for s in out:
        if s["ds_name"]:
            s["name"] = s["ds_name"]
            continue
        lf = s["legend"]
        if lf and lf != "__auto" and "{{" in lf:
            s["name"] = _legend(lf, s["labels"])
            continue
        if lf and lf != "__auto":
            s["name"] = lf
            continue
        uniq = {k: v for k, v in s["labels"].items() if k not in common}
        if len(uniq) == 1:
            s["name"] = str(next(iter(uniq.values())))
        elif len(uniq) > 1:
            s["name"] = _label_text(uniq)
        elif s["labels"]:
            s["name"] = _label_text(s["labels"])
        else:
            s["name"] = s["frame"] or s["field"] or "Value"
    return out


def tables(frames: list, panel: dict) -> list:
    """Frames as tables — pivoting Prometheus "table" format the way Grafana does."""
    table_refs = {t.get("refId") for t in panel["targets"] if t.get("format") == "table"}
    multi = len([t for t in panel["targets"] if not t.get("hide")]) > 1
    out, pivot = [], {}
    for fr in frames:
        fields = fr["fields"]
        numeric = [f for f in fields if f["type"] == "number"]
        if fr["refId"] in table_refs and numeric and numeric[0]["labels"] is not None \
                and len(fields) <= 2:
            # one row per series: its labels, its time, and its value under the
            # name Grafana gives it — `Value #A` when the panel has several queries
            tf = next((f for f in fields if f["type"] == "time"), None)
            col = f"Value #{fr['refId']}" if multi else "Value"
            t = pivot.setdefault(fr["refId"], {"columns": ["Time"], "rows": [], "types": {"Time": "time"}})
            for f in numeric:
                lab = {k: v for k, v in f["labels"].items() if k != "__name__"}
                for k in lab:
                    if k not in t["columns"]:
                        t["columns"].append(k)
                        t["types"][k] = "string"
                vals = [v for v in f["values"] if v is not None]
                row = {"Time": (tf["values"][-1] if tf and tf["values"] else None), **lab,
                       col: vals[-1] if vals else None}
                t["rows"].append(row)
            if col not in t["columns"]:
                t["columns"].append(col)
                t["types"][col] = "number"
        else:
            cols = [f["name"] or f"Field {i + 1}" for i, f in enumerate(fields)]
            n = max((len(f["values"]) for f in fields), default=0)
            rows = [{cols[i]: (f["values"][r] if r < len(f["values"]) else None)
                     for i, f in enumerate(fields)} for r in range(n)]
            out.append({"columns": cols, "rows": rows,
                        "types": {cols[i]: f["type"] for i, f in enumerate(fields)},
                        "refId": fr["refId"]})
    for ref, t in pivot.items():
        out.append({**t, "refId": ref})
    return out


def _merge(tabs: list) -> list:
    """Grafana's `merge`: rows agreeing on every shared non-numeric field join."""
    if len(tabs) < 2:
        return tabs
    columns, types = [], {}
    for t in tabs:
        for c in t["columns"]:
            if c not in columns:
                columns.append(c)
                types[c] = t["types"].get(c, "string")
    merged: dict = {}
    for t in tabs:
        keys = [c for c in t["columns"] if types.get(c) not in ("number", "time")]
        for r in t["rows"]:
            k = tuple((c, r.get(c)) for c in sorted(keys))
            merged.setdefault(k, {}).update({c: v for c, v in r.items() if v is not None
                                             or c not in merged.get(k, {})})
    return [{"columns": columns, "rows": list(merged.values()), "types": types,
             "refId": ""}]


def transform(tabs: list, transformations: list) -> tuple[list, list]:
    """The transformations tables commonly use. Anything else is NAMED, not faked."""
    skipped = []
    for tr in transformations or []:
        if tr.get("disabled"):
            continue
        tid, opt = tr.get("id"), tr.get("options") or {}
        if tid == "merge":
            tabs = _merge(tabs)
        elif tid == "filterFieldsByName":
            inc = (opt.get("include") or {})
            exc = (opt.get("exclude") or {})
            for t in tabs:
                keep = list(t["columns"])
                if inc.get("names"):
                    keep = [c for c in keep if c in inc["names"]]
                if inc.get("pattern"):
                    keep = [c for c in keep if re.search(inc["pattern"], c)]
                if exc.get("names"):
                    keep = [c for c in keep if c not in exc["names"]]
                if exc.get("pattern"):
                    keep = [c for c in keep if not re.search(exc["pattern"], c)]
                t["columns"] = keep
        elif tid == "organize":
            ex = opt.get("excludeByName") or {}
            idx = opt.get("indexByName") or {}
            ren = opt.get("renameByName") or {}
            for t in tabs:
                cols = [c for c in t["columns"] if not ex.get(c)]
                if idx:
                    cols.sort(key=lambda c: idx.get(c, 10_000 + cols.index(c)))
                t["columns"] = cols
                t["rename"] = {**t.get("rename", {}), **{k: v for k, v in ren.items() if v}}
        elif tid == "sortBy":
            for spec in reversed(opt.get("sort") or []):
                f, desc = spec.get("field"), bool(spec.get("desc"))
                for t in tabs:
                    t["rows"].sort(key=lambda r: (r.get(f) is None, r.get(f) if not isinstance(r.get(f), str) else r.get(f).lower()), reverse=desc)
        elif tid == "limit":
            for t in tabs:
                t["rows"] = t["rows"][: int(opt.get("limitField") or 10)]
        elif tid == "renameByRegex":
            try:
                rx = re.compile(str(opt.get("regex") or ""))
            except re.error:
                skipped.append(tid)
                continue
            pat = re.sub(r"\$(\d+)", r"\\\1", str(opt.get("renamePattern") or ""))
            for t in tabs:
                t["rename"] = {**t.get("rename", {}),
                               **{c: rx.sub(pat, c) for c in t["columns"] if rx.search(c)}}
        elif tid in ("labelsToFields",):
            continue
        else:
            skipped.append(tid)
    return tabs, skipped


# ── field config ────────────────────────────────────────────────
def _set_path(d: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = value


def field_config(panel: dict, display: str, field: str = "", ref: str = "",
                 ftype: str = "number") -> dict:
    fc = panel.get("field_config") or {}
    out = copy.deepcopy(fc.get("defaults") or {})
    for ov in fc.get("overrides") or []:
        m = ov.get("matcher") or {}
        mid, opt = m.get("id"), m.get("options")
        hit = False
        if mid == "byName":
            hit = opt in (display, field)
        elif mid == "byRegexp":
            try:
                hit = bool(re.search(str(opt), display) or re.search(str(opt), field))
            except re.error:
                hit = False
        elif mid == "byFrameRefID":
            hit = opt == ref
        elif mid == "byType":
            hit = opt == ftype
        elif mid == "byNames":
            hit = display in ((opt or {}).get("names") or [])
        if hit:
            for prop in ov.get("properties") or []:
                if prop.get("id"):
                    _set_path(out, prop["id"], prop.get("value"))
    return out


# ── reducers ────────────────────────────────────────────────────
def reduce(values: list, calc: str = "lastNotNull"):
    nums = [v for v in values if isinstance(v, (int, float)) and not
            (isinstance(v, float) and math.isnan(v))]
    if calc == "last":
        v = values[-1] if values else None
        return v if isinstance(v, (int, float)) else None
    if calc == "first":
        v = values[0] if values else None
        return v if isinstance(v, (int, float)) else None
    if not nums:
        return None
    return {
        "lastNotNull": lambda: nums[-1], "firstNotNull": lambda: nums[0],
        "mean": lambda: sum(nums) / len(nums), "max": lambda: max(nums),
        "min": lambda: min(nums), "sum": lambda: sum(nums),
        "count": lambda: len(nums), "range": lambda: max(nums) - min(nums),
        "delta": lambda: max(0, nums[-1] - nums[0]), "diff": lambda: nums[-1] - nums[0],
        "median": lambda: sorted(nums)[len(nums) // 2],
    }.get(calc, lambda: nums[-1])()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
