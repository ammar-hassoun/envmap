"""Draw Grafana panels the way Grafana draws them.

`grafana` turns a dashboard into panels and data; this turns those into HTML
and SVG that look like the panel somebody sees in Grafana: stat tiles on their
threshold colour, gauges with their threshold ring, bar gauges, tables with
units, and time series (the time series are drawn in the browser, by
static/grafdash.js, because they need real pixel sizes and a hover).

EVERY STRING IS ESCAPED, AND IT HAS TO BE. Titles, series names, label values,
table cells and mapping texts are written by whoever built the dashboard, or
come back from somebody's exporter. This module builds markup by hand and hands
it to Jinja as Markup, which is a promise that it is already safe -- the exact
shape of SEC-7, the logos lettermark and charts.hbars. `tests/test_grafana.py`
feeds every renderer a name carrying a quote, a tag and an event handler.

Text panels are the one place a dashboard author writes HTML on purpose, so
they go through `sanitize()`, an allowlist, rather than being escaped whole --
and the CSP stands behind it either way.
"""
from __future__ import annotations

import html
import json
import math
import re
from datetime import datetime, timezone
from html.parser import HTMLParser

from markupsafe import Markup

from . import grafana as g

esc = html.escape

# ── colour ──────────────────────────────────────────────────────
# Grafana's named visualisation colours (dark theme), so a threshold saved as
# "green" or "semi-dark-orange" is the colour the author picked.
NAMED = {
    "green": "#73BF69", "semi-dark-green": "#56A64B", "dark-green": "#37872D",
    "light-green": "#96D98D", "super-light-green": "#C8F2C2",
    "yellow": "#FADE2A", "semi-dark-yellow": "#F2CC0C", "dark-yellow": "#E0B400",
    "light-yellow": "#FFEE52", "super-light-yellow": "#FFF899",
    "red": "#F2495C", "semi-dark-red": "#E02F44", "dark-red": "#C4162A",
    "light-red": "#FF7383", "super-light-red": "#FFA6B0",
    "blue": "#5794F2", "semi-dark-blue": "#3274D9", "dark-blue": "#1F60C4",
    "light-blue": "#8AB8FF", "super-light-blue": "#C0D8FF",
    "orange": "#FF9830", "semi-dark-orange": "#FF780A", "dark-orange": "#FA6400",
    "light-orange": "#FFB357", "super-light-orange": "#FFCB7D",
    "purple": "#B877D9", "semi-dark-purple": "#A352CC", "dark-purple": "#8F3BB8",
    "light-purple": "#CA95E5", "super-light-purple": "#DEB6F2",
    "white": "#FFFFFF", "black": "#000000", "gray": "#808080", "grey": "#808080",
    "transparent": "transparent", "text": "var(--text)",
}
# Grafana's classic palette, in its own order -- the green, yellow and blue a
# three-series chart is drawn in.
PALETTE = ("#73BF69", "#F2CC0C", "#8AB8FF", "#FF780A", "#F2495C", "#5794F2",
           "#B877D9", "#705DA0", "#37872D", "#FADE2A", "#447EBC", "#C15C17",
           "#890F02", "#0A437C", "#6D1F62", "#584477", "#B7DBAB", "#F4D598",
           "#70DBED", "#F9BA8F", "#F29191", "#82B5D8", "#E5A8E2", "#AEA2E0",
           "#629E51", "#E5AC0E", "#64B0C8", "#E0752D", "#BF1B00", "#0A50A1",
           "#962D82", "#614D93", "#9AC48A", "#F2C96D", "#65C5DB", "#F9934E")
_HEX = re.compile(r"^#[0-9a-fA-F]{3,8}$|^rgba?\([\d\s.,%]+\)$|^hsla?\([\d\s.,%deg]+\)$")


def css_color(name) -> str:
    """A colour Grafana stored, as CSS -- and nothing else gets through."""
    n = str(name or "").strip()
    if n in NAMED:
        return NAMED[n]
    if _HEX.match(n):
        return n
    return NAMED["green"] if not n else "var(--muted)"


def threshold_color(value, thresholds: dict | None, lo=None, hi=None) -> str:
    th = thresholds or {}
    steps = th.get("steps") or [{"color": "green", "value": None}]
    v = value
    if th.get("mode") == "percentage" and lo is not None and hi is not None:
        v = 0 if hi == lo else (value - lo) / (hi - lo) * 100
    color = steps[0].get("color")
    for st in steps:
        sv = st.get("value")
        if sv is None or (isinstance(v, (int, float)) and v >= sv):
            color = st.get("color")
    return css_color(color)


def _legacy_mappings(mappings: list) -> list:
    out = []
    for m in mappings or []:
        if m.get("type") in (1, "1") and "value" in m:
            out.append({"type": "value", "options": {str(m.get("value")): {
                "text": m.get("text"), "color": m.get("color")}}})
        elif m.get("type") in (2, "2"):
            out.append({"type": "range", "options": {"from": m.get("from"), "to": m.get("to"),
                        "result": {"text": m.get("text"), "color": m.get("color")}}})
        else:
            out.append(m)
    return out


def _num_eq(a, b) -> bool:
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return str(a) == str(b)


_BAD = object()


def _bound(x):
    if x is None or (isinstance(x, str) and x.strip().lower() in ("", "null", "none")):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return _BAD


def map_value(value, mappings: list) -> dict | None:
    """Grafana value mappings: `1` → "Up" on green, a range, a regex, or null."""
    for m in _legacy_mappings(mappings):
        t, opt = m.get("type"), m.get("options") or {}
        if t == "value":
            for key, res in opt.items():
                if value is not None and _num_eq(value, key):
                    return res
        elif t == "range":
            # Legacy singlestat range maps store an open end as the STRING
            # "null", so a bound is read defensively: one malformed mapping
            # must not take the panel down with it.
            lo, hi = _bound(opt.get("from")), _bound(opt.get("to"))
            if lo is _BAD or hi is _BAD:
                continue
            if isinstance(value, (int, float)) and (lo is None or value >= lo) \
                    and (hi is None or value <= hi):
                return opt.get("result") or {}
        elif t == "regex":
            try:
                if value is not None and re.search(str(opt.get("pattern") or ""), str(value)):
                    return opt.get("result") or {}
            except re.error:
                continue
        elif t == "special":
            match = opt.get("match")
            isnan = isinstance(value, float) and math.isnan(value)
            if (match in ("null", "null+nan") and value is None) or \
                    (match in ("nan", "null+nan") and isnan) or \
                    (match == "true" and value is True) or (match == "false" and value is False) or \
                    (match == "empty" and value == ""):
                return opt.get("result") or {}
    return None


def field_color(cfg: dict, value, index: int, lo=None, hi=None) -> str:
    mode = (cfg.get("color") or {}).get("mode") or "thresholds"
    fixed = (cfg.get("color") or {}).get("fixedColor")
    if mode in ("fixed", "shades", "single"):
        return css_color(fixed or "green")
    if mode.startswith("palette"):
        return PALETTE[index % len(PALETTE)]
    if mode.startswith("continuous") and isinstance(value, (int, float)) and \
            lo is not None and hi is not None and hi > lo:
        return _continuous(mode, (value - lo) / (hi - lo))
    if value is None:
        return "var(--muted)"
    return threshold_color(value, cfg.get("thresholds"), lo, hi)


_SCHEMES = {
    "continuous-GrYlRd": ("#73BF69", "#FADE2A", "#F2495C"),
    "continuous-RdYlGr": ("#F2495C", "#FADE2A", "#73BF69"),
    "continuous-BlYlRd": ("#5794F2", "#FADE2A", "#F2495C"),
    "continuous-YlRd": ("#FADE2A", "#F2495C"),
    "continuous-BlPu": ("#5794F2", "#B877D9"),
    "continuous-YlBl": ("#FADE2A", "#5794F2"),
    "continuous-blues": ("#C0D8FF", "#1F60C4"),
    "continuous-reds": ("#FFA6B0", "#C4162A"),
    "continuous-greens": ("#C8F2C2", "#37872D"),
    "continuous-purples": ("#DEB6F2", "#8F3BB8"),
}


def _continuous(mode: str, frac: float) -> str:
    stops = _SCHEMES.get(mode, _SCHEMES["continuous-GrYlRd"])
    frac = max(0.0, min(1.0, frac))
    seg = frac * (len(stops) - 1)
    i = min(int(seg), len(stops) - 2)
    t = seg - i
    a, b = stops[i], stops[i + 1]
    mix = [round(int(a[k:k + 2], 16) * (1 - t) + int(b[k:k + 2], 16) * t) for k in (1, 3, 5)]
    return "#" + "".join(f"{c:02X}" for c in mix)


# ── units ───────────────────────────────────────────────────────
def _auto(v: float, decimals=None) -> str:
    if decimals is not None:
        try:
            return f"{v:.{max(0, int(decimals))}f}"
        except (TypeError, ValueError):
            pass
    if v == 0:
        return "0"
    if float(v).is_integer() and abs(v) < 1e15:
        return str(int(v))
    a = abs(v)
    d = 0 if a >= 100 else 1 if a >= 10 else 2 if a >= 1 else min(6, 2 - math.floor(math.log10(a)))
    return f"{v:.{d}f}"


def _scaled(v: float, base: int, suffixes: tuple, decimals=None, start: int = 0) -> str:
    i = start
    while abs(v) >= base and i < len(suffixes) - 1:
        v /= base
        i += 1
    return f"{_auto(v, decimals)}{suffixes[i]}"


_SI_BYTES = (" B", " kB", " MB", " GB", " TB", " PB", " EB")
_IEC_BYTES = (" B", " KiB", " MiB", " GiB", " TiB", " PiB", " EiB")
_SI_BITS = (" b", " kb", " Mb", " Gb", " Tb", " Pb")
_IEC_BITS = (" b", " Kib", " Mib", " Gib", " Tib", " Pib")
_SHORT = ("", " K", " Mil", " Bil", " Tri", " Quadr", " Quint")
_RATE = {"ops": " ops", "reqps": " req/s", "rps": " rd/s", "wps": " wr/s",
         "iops": " io/s", "opm": " ops/min", "rpm": " rd/min", "wpm": " wr/min",
         "cps": " c/s", "pps": " p/s", "mps": " m/s"}
_SUFFIX = {"celsius": "°C", "fahrenheit": "°F", "kelvin": " K", "humidity": "%H",
           "volt": " V", "amp": " A", "watt": " W", "kwatt": " kW", "hertz": " Hz",
           "lengthm": " m", "lengthkm": " km", "velocityms": " m/s", "areaM2": " m²"}
_CURRENCY = {"currencyUSD": "$", "currencyEUR": "€", "currencyGBP": "£",
             "currencyJPY": "¥", "currencyINR": "₹", "currencyAED": "AED ",
             "currencyKES": "KES "}
_DUR = (("year", 31_536_000), ("month", 2_592_000), ("week", 604_800),
        ("day", 86_400), ("hour", 3600), ("minute", 60), ("second", 1))


def _seconds(v: float, decimals=None) -> str:
    """Grafana's `s` unit: the largest unit that keeps the number small."""
    a = abs(v)
    if a < 1e-6:
        return f"{_auto(v * 1e9, decimals)} ns"
    if a < 1e-3:
        return f"{_auto(v * 1e6, decimals)} µs"
    if a < 1:
        return f"{_auto(v * 1e3, decimals)} ms"
    for name, size, top in (("s", 1, 60), ("min", 60, 3600), ("hour", 3600, 86400),
                            ("day", 86400, 604800), ("week", 604800, 31536000)):
        if a < top:
            return f"{_auto(v / size, decimals)} {name}"
    return f"{_auto(v / 31536000, decimals)} year"


def _humanize(seconds: float, parts: int = 1) -> str:
    """Grafana's `dtdurations`: "3 weeks", "2 days, 4 hours"."""
    s = abs(seconds)
    out = []
    for name, size in _DUR:
        if s >= size or (not out and name == "second"):
            n = int(s // size)
            s -= n * size
            out.append(f"{n} {name}{'' if n == 1 else 's'}")
            if len(out) >= parts:
                break
    return ", ".join(out) or "0 seconds"


def fmt(value, unit: str = "", decimals=None) -> str:
    """One number the way Grafana writes it in that unit."""
    if value is None:
        return "No data"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    if math.isnan(v):
        return "NaN"
    u = unit or "none"
    if u in ("none", "short") and u == "none":
        return _auto(v, decimals)
    if u == "short":
        return _scaled(v, 1000, _SHORT, decimals)
    if u == "percent":
        return f"{_auto(v, decimals)}%"
    if u == "percentunit":
        return f"{_auto(v * 100, decimals)}%"
    if u in ("decbytes", "bytes_si"):
        return _scaled(v, 1000, _SI_BYTES, decimals)
    if u == "bytes":
        return _scaled(v, 1024, _IEC_BYTES, decimals)
    if u == "deckbytes":
        return _scaled(v, 1000, _SI_BYTES, decimals, 1)
    if u == "kbytes":
        return _scaled(v, 1024, _IEC_BYTES, decimals, 1)
    if u == "decmbytes":
        return _scaled(v, 1000, _SI_BYTES, decimals, 2)
    if u == "mbytes":
        return _scaled(v, 1024, _IEC_BYTES, decimals, 2)
    if u == "decgbytes":
        return _scaled(v, 1000, _SI_BYTES, decimals, 3)
    if u == "gbytes":
        return _scaled(v, 1024, _IEC_BYTES, decimals, 3)
    if u == "decbits":
        return _scaled(v, 1000, _SI_BITS, decimals)
    if u == "bits":
        return _scaled(v, 1024, _IEC_BITS, decimals)
    if u == "bps":
        return _scaled(v, 1000, tuple(s + "/s" for s in _SI_BITS), decimals)
    if u == "Bps":
        return _scaled(v, 1000, tuple(s + "/s" for s in _SI_BYTES), decimals)
    if u == "binbps":
        return _scaled(v, 1024, tuple(s + "/s" for s in _IEC_BITS), decimals)
    if u == "binBps":
        return _scaled(v, 1024, tuple(s + "/s" for s in _IEC_BYTES), decimals)
    if u in ("KBs", "KiBs"):
        return _scaled(v * 1000, 1000, tuple(s + "/s" for s in _SI_BYTES), decimals)
    if u in ("MBs", "MiBs"):
        return _scaled(v * 1e6, 1000, tuple(s + "/s" for s in _SI_BYTES), decimals)
    if u == "s":
        return _seconds(v, decimals)
    if u == "ms":
        return _seconds(v / 1000, decimals)
    if u in ("µs", "us"):
        return _seconds(v / 1e6, decimals)
    if u == "ns":
        return _seconds(v / 1e9, decimals)
    if u == "m":
        return _seconds(v * 60, decimals)
    if u == "h":
        return _seconds(v * 3600, decimals)
    if u == "d":
        return _seconds(v * 86400, decimals)
    if u == "dtdurations":
        return _humanize(v, int(decimals) if decimals else 1)
    if u == "dtdurationms":
        return _humanize(v / 1000, int(decimals) if decimals else 1)
    if u in ("dthms", "dtdhms"):
        s = int(abs(v))
        d, s = divmod(s, 86400)
        h, s = divmod(s, 3600)
        mi, s = divmod(s, 60)
        body = f"{h:02d}:{mi:02d}:{s:02d}"
        return f"{d} d {body}" if (u == "dtdhms" and d) else (f"{d * 24 + h:02d}:{mi:02d}:{s:02d}" if d else body)
    if u in ("dateTimeAsIso", "dateTimeAsUS", "dateTimeAsSystem", "dateTimeAsLocal"):
        ts = v / 1000 if v > 1e11 else v
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if u == "dateTimeFromNow":
        ts = v / 1000 if v > 1e11 else v
        ago = datetime.now(timezone.utc).timestamp() - ts
        return f"{_humanize(ago)} ago" if ago >= 0 else f"in {_humanize(-ago)}"
    if u in _RATE:
        return _scaled(v, 1000, tuple(s.rstrip() for s in _SHORT), decimals) + _RATE[u]
    if u in _SUFFIX:
        return f"{_auto(v, decimals)}{_SUFFIX[u]}"
    if u in _CURRENCY:
        return _CURRENCY[u] + _scaled(v, 1000, ("", "K", "M", "B", "T"), decimals)
    if u.startswith("suffix:"):
        return f"{_auto(v, decimals)}{u[7:]}"
    if u.startswith("prefix:"):
        return f"{u[7:]}{_auto(v, decimals)}"
    if u.startswith("si:"):
        return _scaled(v, 1000, tuple(p + u[3:] for p in ("", "k", "M", "G", "T", "P")), decimals)
    if u in ("string",):
        return str(value)
    if u in ("bool", "bool_yes_no", "bool_on_off"):
        pair = {"bool": ("true", "false"), "bool_yes_no": ("Yes", "No"),
                "bool_on_off": ("On", "Off")}[u]
        return pair[0] if v else pair[1]
    return f"{_auto(v, decimals)} {u}"


def display(value, cfg: dict, index: int = 0, lo=None, hi=None) -> dict:
    """A value's text and colour: mappings first, then the unit and thresholds."""
    mapped = map_value(value, cfg.get("mappings") or [])
    text = None
    color = None
    if mapped:
        text = mapped.get("text")
        if mapped.get("color"):
            color = css_color(mapped["color"])
    if text is None or text == "":
        text = fmt(value, cfg.get("unit") or "", cfg.get("decimals"))
    if color is None:
        color = field_color(cfg, value, index, lo, hi)
    return {"text": text, "color": color}


# ── helpers ─────────────────────────────────────────────────────
def _calc(panel: dict) -> str:
    ro = (panel["options"] or {}).get("reduceOptions") or {}
    calcs = ro.get("calcs") or []
    # singlestat, the pre-7 panel, kept its reducer as `valueName`
    return (calcs[0] if calcs else panel["options"].get("valueName") or "lastNotNull") \
        .replace("current", "lastNotNull").replace("avg", "mean").replace("total", "sum")


def _named(panel: dict, ss: list) -> list:
    """Each series with its resolved field config and display name applied."""
    out = []
    for i, s in enumerate(ss):
        cfg = g.field_config(panel, s["name"], s["field"], s["refId"])
        name = cfg.get("displayName") or s["name"]
        name = re.sub(r"\$\{__field\.labels\.([\w.]+)\}",
                      lambda m: str(s["labels"].get(m.group(1), "")), str(name))
        name = name.replace("${__series.name}", s["name"]).replace("${__field.name}", s["field"])
        out.append({**s, "cfg": cfg, "display": name, "index": i})
    return out


def _bounds(cfg: dict, values: list, default=(0, 100)) -> tuple:
    lo, hi = cfg.get("min"), cfg.get("max")
    unit = cfg.get("unit") or ""
    nums = [v for v in values if isinstance(v, (int, float))]
    if lo is None:
        lo = 0 if unit in ("percent", "percentunit") or not nums or min(nums) >= 0 else min(nums)
    if hi is None:
        hi = 100 if unit == "percent" else 1 if unit == "percentunit" else \
            (max(nums) if nums else default[1])
    if hi <= lo:
        hi = lo + 1
    return float(lo), float(hi)


def _orient(panel: dict, n: int) -> str:
    """Grafana's repeater: "vertical" lays items side by side, "horizontal"
    stacks them, and "auto" picks by the panel's shape -- wide panels side by
    side, tall ones stacked. The names are Grafana's and read backwards."""
    o = (panel["options"] or {}).get("orientation") or "auto"
    if o == "horizontal":
        return "stack"
    if o == "vertical":
        return "side"
    w, h = panel["grid"]["w"] * 66, panel["grid"]["h"] * 38
    return "side" if w >= h or n <= 1 else "stack"


def _empty(msg: str = "No data") -> Markup:
    return Markup(f'<div class="gp-empty">{esc(msg)}</div>')


# ── stat ────────────────────────────────────────────────────────
def stat(panel: dict, ss: list) -> Markup:
    o = panel["options"] or {}
    ss = _named(panel, ss)
    if not ss:
        return _empty()
    calc = _calc(panel)
    mode = o.get("colorMode") or "value"
    text_mode = o.get("textMode") or "auto"
    graph = o.get("graphMode") or "none"
    items = []
    for s in ss[:48]:
        v = g.reduce(s["values"], calc)
        lo, hi = _bounds(s["cfg"], s["values"])
        d = display(v, s["cfg"], s["index"], lo, hi)
        pre, post = o.get("_affix") or ("", "")
        items.append({"s": s, "text": f"{pre}{d['text']}{post}", "color": d["color"]})
    many = len(items) > 1
    show_name = text_mode in ("value_and_name", "name") or (text_mode == "auto" and many)
    show_value = text_mode not in ("name", "none")
    layout = _orient(panel, len(items))
    cls = {"background": "bg", "background_solid": "bgs", "value": "val"}.get(mode, "plain")
    parts = [f'<div class="gstat {layout}">']
    for it in items:
        spark = ""
        if graph == "area" and len([x for x in it["s"]["values"] if isinstance(x, (int, float))]) > 1:
            spark = _spark(it["s"]["values"])
        name = f'<div class="gs-name">{esc(it["s"]["display"])}</div>' if show_name else ""
        val = f'<div class="gs-val">{esc(it["text"])}</div>' if show_value else ""
        # Grafana sizes the value to FILL the tile, so "Up" is enormous and a
        # long number is not. The text's own length is carried to the CSS,
        # which divides the tile's width by it.
        vlen = max(2, len(str(it["text"])))
        nlen = max(4, len(str(it["s"]["display"])))
        parts.append(f'<div class="gs-item {cls}" style="--c:{esc(it["color"])};--vl:{vlen};--nl:{nlen}" '
                     f'title="{esc(it["s"]["display"])}: {esc(it["text"])}">'
                     f'{spark}<div class="gs-text">{name}{val}</div></div>')
    parts.append("</div>")
    return Markup("".join(parts))


def _spark(values: list) -> str:
    nums = [v if isinstance(v, (int, float)) else None for v in values]
    real = [v for v in nums if v is not None]
    lo, hi = min(real), max(real)
    span = (hi - lo) or 1
    n = len(nums)
    pts = [f"{i / max(1, n - 1) * 100:.2f},{100 - (v - lo) / span * 80 - 10:.2f}"
           for i, v in enumerate(nums) if v is not None]
    return (f'<svg class="gs-spark" viewBox="0 0 100 100" preserveAspectRatio="none" '
            f'aria-hidden="true"><polygon points="0,100 {" ".join(pts)} 100,100"/>'
            f'<polyline points="{" ".join(pts)}"/></svg>')


# ── gauge ───────────────────────────────────────────────────────
_SWEEP, _START = 240.0, 210.0


def _pt(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy - r * math.sin(a)


def _arc(cx, cy, r, f0, f1) -> str:
    a0, a1 = _START - _SWEEP * f0, _START - _SWEEP * f1
    x0, y0 = _pt(cx, cy, r, a0)
    x1, y1 = _pt(cx, cy, r, a1)
    large = 1 if (a0 - a1) > 180 else 0
    return f"M{x0:.2f},{y0:.2f} A{r},{r} 0 {large} 1 {x1:.2f},{y1:.2f}"


def gauge(panel: dict, ss: list) -> Markup:
    o = panel["options"] or {}
    ss = _named(panel, ss)
    if not ss:
        return _empty()
    calc = _calc(panel)
    markers = o.get("showThresholdMarkers", True)
    many = len(ss) > 1
    layout = _orient(panel, len(ss))
    parts = [f'<div class="ggauge {layout}">']
    for s in ss[:24]:
        v = g.reduce(s["values"], calc)
        lo, hi = _bounds(s["cfg"], s["values"])
        d = display(v, s["cfg"], s["index"], lo, hi)
        frac = 0.0 if not isinstance(v, (int, float)) else max(0.0, min(1.0, (v - lo) / (hi - lo)))
        svg = ['<svg viewBox="0 0 200 150" preserveAspectRatio="xMidYMid meet" aria-hidden="true">']
        if markers:
            steps = ((s["cfg"].get("thresholds") or {}).get("steps") or
                     [{"color": "green", "value": None}])
            pct = (s["cfg"].get("thresholds") or {}).get("mode") == "percentage"
            bounds = []
            for i, st in enumerate(steps):
                start = st.get("value")
                start = lo if start is None else (lo + (hi - lo) * start / 100 if pct else start)
                nxt = steps[i + 1].get("value") if i + 1 < len(steps) else None
                end = hi if nxt is None else (lo + (hi - lo) * nxt / 100 if pct else nxt)
                a = max(0.0, min(1.0, (start - lo) / (hi - lo)))
                b = max(0.0, min(1.0, (end - lo) / (hi - lo)))
                if b > a:
                    bounds.append((a, b, css_color(st.get("color"))))
            for a, b, c in bounds:
                svg.append(f'<path d="{_arc(100, 92, 84, a, b)}" stroke="{esc(c)}" '
                           f'stroke-width="5" fill="none"/>')
        svg.append(f'<path class="gg-track" d="{_arc(100, 92, 70, 0, 1)}" '
                   f'stroke-width="18" fill="none"/>')
        if frac > 0.001:
            svg.append(f'<path d="{_arc(100, 92, 70, 0, frac)}" stroke="{esc(d["color"])}" '
                       f'stroke-width="18" fill="none"/>')
        size = max(12, min(38, 210 / max(4, len(d["text"]))))
        svg.append(f'<text x="100" y="{101 + size * 0.1:.1f}" text-anchor="middle" '
                   f'font-size="{size:.1f}" fill="{esc(d["color"])}" class="gg-val">'
                   f'{esc(d["text"])}</text></svg>')
        name = f'<div class="gg-name">{esc(s["display"])}</div>' if many else ""
        parts.append(f'<div class="gg-item" title="{esc(s["display"])}: {esc(d["text"])}">'
                     f'{"".join(svg)}{name}</div>')
    parts.append("</div>")
    return Markup("".join(parts))


# ── bar gauge ───────────────────────────────────────────────────
def bargauge(panel: dict, ss: list) -> Markup:
    o = panel["options"] or {}
    ss = _named(panel, ss)
    if not ss:
        return _empty()
    calc = _calc(panel)
    mode = o.get("displayMode") or "gradient"
    vals = [g.reduce(s["values"], calc) for s in ss]
    nums = [v for v in vals if isinstance(v, (int, float))]
    orient = o.get("orientation") or "auto"
    vertical = orient == "vertical" or (orient == "auto" and
                                        panel["grid"]["w"] * 66 > panel["grid"]["h"] * 38 * 1.6
                                        and len(ss) > 2)
    unfilled = o.get("showUnfilled", True)
    parts = [f'<div class="gbar {"v" if vertical else "h"} {esc(mode)}{" track" if unfilled else ""}">']
    for s, v in list(zip(ss, vals))[:40]:
        lo, hi = _bounds(s["cfg"], nums or [0])
        d = display(v, s["cfg"], s["index"], lo, hi)
        pct = 0 if not isinstance(v, (int, float)) else max(0, min(100, (v - lo) / (hi - lo) * 100))
        parts.append(
            f'<div class="gb-item" style="--c:{esc(d["color"])};--p:{pct:.2f}%" '
            f'title="{esc(s["display"])}: {esc(d["text"])}">'
            f'<div class="gb-name">{esc(s["display"])}</div>'
            f'<div class="gb-row"><div class="gb-bar"><i></i></div>'
            f'<div class="gb-val">{esc(d["text"])}</div></div></div>')
    parts.append("</div>")
    return Markup("".join(parts))


# ── time series ─────────────────────────────────────────────────
def _nice(span: float, n: int) -> float:
    raw = span / max(1, n)
    mag = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            return m * mag
    return 10 * mag


def _ticks(lo: float, hi: float, n: int, unit: str, decimals) -> list:
    if hi <= lo:
        hi = lo + 1
    step = _nice(hi - lo, n)
    start = math.floor(lo / step) * step
    vals, v = [], start
    # the LAST tick must reach the maximum, not stop short of it -- otherwise
    # the axis ends at 10% while the data peaks at 10.4% and the line is drawn
    # straight through the panel's title
    while len(vals) < 24:
        vals.append(round(v, 10))
        if v >= hi - step * 1e-6:
            break
        v += step
    labels = None
    for d in range(0, 5):
        cand = [fmt(x, unit, d if decimals is None else decimals) for x in vals]
        if len(set(cand)) == len(cand):
            labels = cand
            break
    labels = labels or [fmt(x, unit, decimals) for x in vals]
    return [{"v": x, "l": lbl} for x, lbl in zip(vals, labels)]


def timeseries(panel: dict, ss: list, trange: dict) -> Markup:
    ss = _named(panel, ss)
    if not ss:
        return _empty()
    defaults = (panel["field_config"].get("defaults") or {})
    custom = defaults.get("custom") or {}
    stack = ((custom.get("stacking") or {}).get("mode") or "none") != "none"
    legend = (panel["options"] or {}).get("legend") or {}
    series_out, all_vals = [], []
    for s in ss[:60]:
        vals = [v if isinstance(v, (int, float)) and not
                (isinstance(v, float) and math.isnan(v)) else None for v in s["values"]]
        cfg = s["cfg"]
        # A time series with no colour mode is drawn from the classic palette,
        # which is Grafana's default for the panel. Treating "unset" as
        # thresholds painted every line the base threshold colour -- or grey.
        if not (cfg.get("color") or {}).get("mode"):
            cfg = {**cfg, "color": {**(cfg.get("color") or {}), "mode": "palette-classic"}}
        color = field_color(cfg, None, s["index"])
        if (cfg.get("color") or {}).get("mode") == "thresholds":
            real = [v for v in vals if v is not None]
            color = threshold_color(real[-1] if real else 0, cfg.get("thresholds"))
        series_out.append({"n": s["display"], "c": color, "t": s["times"], "v": vals,
                           "f": [fmt(v, cfg.get("unit") or defaults.get("unit") or "",
                                     cfg.get("decimals")) if v is not None else "" for v in vals],
                           "w": (cfg.get("custom") or {}).get("lineWidth", custom.get("lineWidth", 1)),
                           "fo": (cfg.get("custom") or {}).get("fillOpacity", custom.get("fillOpacity", 0)),
                           "hide": bool(((cfg.get("custom") or {}).get("hideFrom") or {}).get("viz"))})
        all_vals.extend(v for v in vals if v is not None)
    if stack and series_out:
        n = max(len(x["v"]) for x in series_out)
        sums = [sum((x["v"][i] or 0) for x in series_out if i < len(x["v"])) for i in range(n)]
        all_vals = sums + [0]
    unit = defaults.get("unit") or (ss[0]["cfg"].get("unit") if ss else "") or ""
    lo = defaults.get("min")
    hi = defaults.get("max")
    if all_vals:
        lo = min(all_vals) if lo is None else lo
        hi = max(all_vals) if hi is None else hi
        if lo == hi:
            lo, hi = lo - 1, hi + 1
        # Grafana fits the axis to the data rather than anchoring it at zero:
        # a CPU line between 6% and 10% on a 0-12% axis is a flat line along
        # the top. `softMin`/`softMax` are the author's way of widening it.
        soft_lo, soft_hi = custom.get("axisSoftMin"), custom.get("axisSoftMax")
        if soft_lo is not None and defaults.get("min") is None:
            lo = min(lo, soft_lo)
        if soft_hi is not None and defaults.get("max") is None:
            hi = max(hi, soft_hi)
    else:
        lo, hi = 0, 1
    height = panel["grid"]["h"] * 38 - 32
    ticks = _ticks(float(lo), float(hi), max(2, int(height / 55)), unit, defaults.get("decimals"))
    spec = {"s": series_out, "yt": ticks, "ymin": ticks[0]["v"] if ticks else lo,
            "ymax": ticks[-1]["v"] if ticks else hi, "from": trange["from_ms"],
            "to": trange["to_ms"], "stack": stack,
            "draw": custom.get("drawStyle") or "line",
            "pts": custom.get("showPoints") or "auto", "ps": custom.get("pointSize") or 5,
            "interp": custom.get("lineInterpolation") or "linear"}
    show_legend = legend.get("showLegend", legend.get("show", True)) is not False
    place = legend.get("placement") or "bottom"
    body = [f'<div class="gts-wrap {"lr" if place == "right" else "lb"}">',
            f'<div class="gts" data-spec="{esc(json.dumps(spec, separators=(",", ":")), quote=True)}"></div>']
    if show_legend:
        calcs = legend.get("calcs") or []
        if (legend.get("displayMode") == "table") and calcs:
            body.append('<div class="gl-table"><table><thead><tr><th></th>' +
                        "".join(f"<th>{esc(c)}</th>" for c in calcs) + "</tr></thead><tbody>")
            for s, so in zip(ss, series_out):
                cells = "".join(f"<td>{esc(fmt(g.reduce(s['values'], c), unit, defaults.get('decimals')))}</td>"
                                for c in calcs)
                body.append(f'<tr><td><i style="background:{esc(so["c"])}"></i>{esc(so["n"])}</td>{cells}</tr>')
            body.append("</tbody></table></div>")
        else:
            body.append('<div class="gl-list">' + "".join(
                f'<span class="gl-i"><i style="background:{esc(so["c"])}"></i>{esc(so["n"])}</span>'
                for so in series_out if not so["hide"]) + "</div>")
    body.append("</div>")
    return Markup("".join(body))


# ── table ───────────────────────────────────────────────────────
def table(panel: dict, frames: list) -> Markup:
    tabs = g.tables(frames, panel)
    tabs, skipped = g.transform(tabs, panel["transformations"])
    if not tabs or not tabs[0]["rows"]:
        return _empty()
    t = tabs[0]
    rename = t.get("rename") or {}
    cols = []
    for c in t["columns"]:
        cfg = g.field_config(panel, rename.get(c, c), c, t.get("refId", ""),
                             t["types"].get(c, "string"))
        if (cfg.get("custom") or {}).get("hidden"):
            continue
        if c == "Time" and t["types"].get(c) == "time" and not cfg.get("displayName") \
                and "Time" not in rename and any(x.get("format") == "table" for x in panel["targets"]):
            # an instant table's time column is the same instant on every row
            continue
        cols.append((c, cfg))
    nums = {c: [r.get(c) for r in t["rows"] if isinstance(r.get(c), (int, float))] for c, _ in cols}
    out = ['<div class="gtab"><table class="jenkins gtable"><thead><tr>']
    for c, cfg in cols:
        name = cfg.get("displayName") or rename.get(c, c)
        right = t["types"].get(c) == "number"
        out.append(f'<th{" class=r" if right else ""}>{esc(str(name))}</th>')
    out.append("</tr></thead><tbody>")
    for r in t["rows"][:500]:
        out.append("<tr>")
        for i, (c, cfg) in enumerate(cols):
            v = r.get(c)
            kind = t["types"].get(c)
            if kind == "time" and isinstance(v, (int, float)):
                text = datetime.fromtimestamp(v / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                color = None
            else:
                lo, hi = _bounds(cfg, nums.get(c) or [])
                d = display(v, cfg, i, lo, hi) if (kind == "number" or cfg.get("mappings")) \
                    else {"text": "" if v is None else str(v), "color": None}
                text, color = d["text"], d["color"]
            cell = (cfg.get("custom") or {}).get("cellOptions") or {}
            ctype = cell.get("type") or (cfg.get("custom") or {}).get("displayMode") or "auto"
            fixed_transparent = ((cfg.get("color") or {}).get("fixedColor") == "transparent")
            style = ""
            if color and not fixed_transparent and ctype in ("color-background", "color-background-solid"):
                style = f' style="--c:{esc(color)}" class="cbg{" r" if kind == "number" else ""}"'
            elif color and not fixed_transparent and ctype == "color-text":
                style = f' style="color:{esc(color)}"{" class=r" if kind == "number" else ""}'
            elif ctype in ("gauge", "gradient-gauge", "lcd-gauge", "basic") and isinstance(v, (int, float)):
                lo, hi = _bounds(cfg, nums.get(c) or [])
                pct = max(0, min(100, (v - lo) / (hi - lo) * 100))
                text = Markup(f'<span class="cg" style="--c:{esc(color or "var(--accent)")};--p:{pct:.1f}%">'
                              f'<i></i></span><span class="cgv">{esc(text)}</span>')
                style = ' class="r"'
            elif kind == "number":
                style = ' class="r"'
            sort = f' data-sort="{esc(str(v))}"' if isinstance(v, (int, float)) else ""
            out.append(f"<td{style}{sort}>{text if isinstance(text, Markup) else esc(str(text))}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    if skipped:
        out.append(f'<div class="gp-note">not applied here: {esc(", ".join(skipped))}</div>')
    return Markup("".join(out))


# ── pie chart ───────────────────────────────────────────────────
def piechart(panel: dict, ss: list) -> Markup:
    ss = _named(panel, ss)
    calc = _calc(panel)
    vals = [(s, g.reduce(s["values"], calc)) for s in ss]
    vals = [(s, v) for s, v in vals if isinstance(v, (int, float)) and v > 0]
    if not vals:
        return _empty()
    total = sum(v for _, v in vals)
    donut = (panel["options"] or {}).get("pieType") == "donut"
    parts, a0 = [], 90.0
    for s, v in vals:
        frac = v / total
        color = field_color(s["cfg"], v, s["index"]) if (s["cfg"].get("color") or {}).get("mode") \
            not in (None, "thresholds") else PALETTE[s["index"] % len(PALETTE)]
        a1 = a0 - 360 * frac
        if frac >= 0.9999:
            parts.append(f'<circle cx="60" cy="60" r="50" fill="{esc(color)}"/>')
        else:
            x0, y0 = _pt(60, 60, 50, a0)
            x1, y1 = _pt(60, 60, 50, a1)
            parts.append(f'<path d="M60,60 L{x0:.2f},{y0:.2f} A50,50 0 {1 if frac > 0.5 else 0} 1 '
                         f'{x1:.2f},{y1:.2f} Z" fill="{esc(color)}"><title>{esc(s["display"])}: '
                         f'{esc(fmt(v, s["cfg"].get("unit") or "", s["cfg"].get("decimals")))}</title></path>')
        s["_c"] = color
        a0 = a1
    hole = '<circle cx="60" cy="60" r="28" class="gpie-hole"/>' if donut else ""
    legend = "".join(
        f'<span class="gl-i"><i style="background:{esc(s["_c"])}"></i>{esc(s["display"])} '
        f'<b>{esc(fmt(v, s["cfg"].get("unit") or "", s["cfg"].get("decimals")))}</b></span>'
        for s, v in vals[:30])
    return Markup(f'<div class="gpie"><svg viewBox="0 0 120 120" aria-hidden="true">{"".join(parts)}{hole}</svg>'
                  f'<div class="gl-list col">{legend}</div></div>')


# ── text ────────────────────────────────────────────────────────
_ALLOWED = {"a", "abbr", "b", "blockquote", "br", "center", "code", "dd", "details", "div",
            "dl", "dt", "em", "figcaption", "figure", "font", "h1", "h2", "h3", "h4", "h5",
            "h6", "hr", "i", "img", "li", "mark", "ol", "p", "pre", "s", "small", "span",
            "strong", "sub", "summary", "sup", "table", "tbody", "td", "tfoot", "th",
            "thead", "tr", "u", "ul"}
_VOID = {"br", "hr", "img"}
_DROP_WITH_BODY = {"script", "style", "iframe", "object", "embed", "noscript",
                   "template", "svg", "math", "frame", "frameset", "applet", "select",
                   "textarea", "title", "head"}
_ATTRS = {"title", "align", "colspan", "rowspan", "width", "height", "alt", "color",
          "size", "style", "href", "src", "target"}
_BAD_CSS = re.compile(r"url\s*\(|expression\s*\(|javascript:|@import|behavior\s*:|"
                      r"-moz-binding|\bposition\s*:|\bz-index\s*:", re.I)


class _Clean(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.stack, self.skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_WITH_BODY:
            self.skip += 1
            return
        if self.skip or tag not in _ALLOWED:
            return
        keep = []
        for k, v in attrs:
            k = (k or "").lower()
            v = v or ""
            if k.startswith("on") or k not in _ATTRS:
                continue
            if k == "style":
                # A declaration that can reach outside the panel -- a fixed or
                # absolute box laid over the portal's own buttons -- or fetch
                # something is dropped whole; the rest is presentation.
                decls = [d for d in v.split(";") if d.strip() and not _BAD_CSS.search(d)]
                v = ";".join(decls)
                if not v:
                    continue
            if k == "href":
                if not re.match(r"^(https?:|mailto:|#|/(?!/))", v.strip(), re.I):
                    continue
            if k == "src":
                if not re.match(r"^(https?:|data:image/(png|gif|jpe?g|webp);)", v.strip(), re.I):
                    continue
            if k == "target":
                v = "_blank"
            keep.append(f' {k}="{esc(v, quote=True)}"')
        if tag == "a":
            keep.append(' rel="noopener noreferrer"')
        self.out.append(f"<{tag}{''.join(keep)}>")
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in _DROP_WITH_BODY:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in _ALLOWED or tag in _VOID:
            return
        if tag in self.stack:
            while self.stack:
                t = self.stack.pop()
                self.out.append(f"</{t}>")
                if t == tag:
                    break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(esc(data))


def sanitize(markup: str) -> Markup:
    """Author HTML reduced to presentation: no script, no handler, no escape
    hatch out of the panel's box. An allowlist, so an element nobody thought of
    is dropped rather than trusted."""
    p = _Clean()
    try:
        p.feed(markup or "")
        p.close()
    except Exception:                                             # noqa: BLE001
        return Markup(esc(markup or ""))
    while p.stack:
        p.out.append(f"</{p.stack.pop()}>")
    return Markup("".join(p.out))


def text(panel: dict, mdlite) -> Markup:
    body = panel.get("content") or ""
    if not body.strip():
        return Markup("")
    if (panel.get("mode") or "markdown") == "html":
        return Markup(f'<div class="gtext html">{sanitize(body)}</div>')
    return Markup(f'<div class="gtext">{mdlite(body)}</div>')


# ── dispatch ────────────────────────────────────────────────────
DRAWN = {"stat", "singlestat", "gauge", "bargauge", "timeseries", "graph", "table",
         "table-old", "text", "piechart", "grafana-piechart-panel"}


def render(panel: dict, data: dict, trange: dict, mdlite, grafana_url: str = "") -> Markup:
    kind = panel["type"]
    if kind == "text":
        return text(panel, mdlite)
    if kind not in DRAWN:
        link = (f' <a href="{esc(grafana_url)}" target="_blank" rel="noopener">Open in Grafana ↗</a>'
                if grafana_url else "")
        return Markup(f'<div class="gp-empty">A “{esc(kind)}” panel is not drawn here yet.{link}</div>')
    errs = data.get("errors") or []
    frames = data.get("frames") or []
    if errs and not frames:
        return Markup(f'<div class="gp-empty bad" title="{esc(" · ".join(errs))}">⚠ '
                      f'{esc(errs[0][:180])}</div>')
    if kind in ("table", "table-old"):
        return table(panel, frames)
    ss = g.series(frames, panel)
    if not ss and not frames:
        return _empty()
    if kind in ("stat", "singlestat"):
        return stat(panel, ss)
    if kind == "gauge":
        return gauge(panel, ss)
    if kind == "bargauge":
        return bargauge(panel, ss)
    if kind in ("piechart", "grafana-piechart-panel"):
        return piechart(panel, ss)
    return timeseries(panel, ss, trange)


def sections(panels: list) -> list:
    """The dashboard as row sections, each laid out on its own 24-column grid.

    One grid per row, with every panel placed by its own gridPos relative to the
    row's top: exactly Grafana's layout, and a collapsed row's children -- whose
    y was recorded while the row was open -- cannot land on top of anything.
    """
    out, cur = [], {"row": None, "panels": [], "top": 0}
    for p in panels:
        if p["is_row"]:
            if cur["panels"] or cur["row"]:
                out.append(cur)
            cur = {"row": p, "panels": [], "top": p["grid"]["y"] + 1}
            continue
        cur["panels"].append(p)
    if cur["panels"] or cur["row"]:
        out.append(cur)
    for sec in out:
        top = min((p["grid"]["y"] for p in sec["panels"]), default=0)
        for p in sec["panels"]:
            p["_r"] = p["grid"]["y"] - top + 1
        sec["height"] = max((p["_r"] - 1 + p["grid"]["h"] for p in sec["panels"]), default=0)
    return out
