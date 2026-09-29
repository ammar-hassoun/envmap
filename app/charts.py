"""Inline SVG charts, generated server-side.

No chart library and no client-side rendering: the portal is server-rendered and
self-contained, and these shapes are simple enough that a dependency would cost
more than it saves. Colours are CSS variables, not literals, so the charts follow
the theme like everything else.
"""
import math
from html import escape

from markupsafe import Markup

# severity of a utilisation figure — one place, so gauges and bars agree
WARM, HOT = 65, 85


def load_color(pct: float) -> str:
    if pct >= HOT:
        return "var(--danger-ink)"
    if pct >= WARM:
        return "var(--warn-ink)"
    return "var(--accent-ink)"


def donut(pct: float, label: str = "", sub: str = "", size: int = 132,
          thickness: int = 11, color: str = "var(--ok-ink)") -> Markup:
    """Ring gauge with the figure in the middle."""
    pct = max(0.0, min(100.0, float(pct or 0)))
    r = (size - thickness) / 2
    c = 2 * math.pi * r
    on = c * pct / 100
    mid = size / 2
    # Escaped even though every caller passes a number or a literal today.
    # These return Markup, so the day somebody puts a cluster or service name
    # in a caption it lands in the DOM unescaped — and the rest of this file
    # already escapes, so the inconsistency is the hazard.
    label, sub = escape(str(label)), escape(str(sub))
    return Markup(f"""
<svg class="chart-donut" viewBox="0 0 {size} {size}" width="{size}" height="{size}"
     role="img" aria-label="{label} {pct:.0f}%">
  <circle cx="{mid}" cy="{mid}" r="{r:.2f}" fill="none"
          stroke="var(--well)" stroke-width="{thickness}"/>
  <circle cx="{mid}" cy="{mid}" r="{r:.2f}" fill="none"
          stroke="{color}" stroke-width="{thickness}" stroke-linecap="round"
          stroke-dasharray="{on:.2f} {c - on:.2f}"
          transform="rotate(-90 {mid} {mid})"/>
  <text x="{mid}" y="{mid - 1}" class="donut-n" text-anchor="middle"
        dominant-baseline="middle">{label}</text>
  {f'<text x="{mid}" y="{mid + 19}" class="donut-s" text-anchor="middle">{sub}</text>' if sub else ''}
</svg>""")


def ring(segments: list, centre: str = "", sub: str = "", size: int = 122,
         thickness: int = 14) -> Markup:
    """A donut of several parts — the mix, where donut() shows one fraction.

    segments: [(label, value, colour), …] in drawing order. Empty parts are
    dropped rather than drawn: at this radius a zero-length dash with a round
    cap still paints a dot, which reads as a real slice of something that does
    not exist. The gap between parts is dropped for a single part too, so "all
    of it is one thing" draws as a closed circle rather than a circle with a
    seam in it.
    """
    parts = [(str(label), float(value or 0), colour)
             for label, value, colour in (segments or []) if (value or 0) > 0]
    total = sum(v for _l, v, _c in parts)
    if not parts:
        return Markup('<div class="chart-empty">nothing to show</div>')
    r = (size - thickness) / 2
    circ = 2 * math.pi * r
    mid = size / 2
    gap = 2.5 if len(parts) > 1 else 0.0
    arcs, done = [], 0.0
    for label, value, colour in parts:
        length = circ * value / total
        drawn = max(length - gap, 0.8)
        arcs.append(
            f'<circle cx="{mid}" cy="{mid}" r="{r:.2f}" fill="none" '
            f'stroke="{colour}" stroke-width="{thickness}" '
            f'stroke-dasharray="{drawn:.2f} {circ - drawn:.2f}" '
            f'stroke-dashoffset="{-done:.2f}" '
            f'transform="rotate(-90 {mid} {mid})">'
            f'<title>{escape(label)}: {value:g}</title></circle>')
        done += length
    centre, sub = escape(str(centre)), escape(str(sub))
    return Markup(f"""
<svg class="chart-donut" viewBox="0 0 {size} {size}" width="{size}" height="{size}"
     role="img" aria-label="{escape(', '.join(f'{l} {v:g}' for l, v, _c in parts))}">
  <circle cx="{mid}" cy="{mid}" r="{r:.2f}" fill="none"
          stroke="var(--well)" stroke-width="{thickness}"/>
  {''.join(arcs)}
  {f'<text x="{mid}" y="{mid - (2 if sub else -5)}" class="donut-n" text-anchor="middle" dominant-baseline="middle">{centre}</text>' if centre else ''}
  {f'<text x="{mid}" y="{mid + 20}" class="donut-s" text-anchor="middle">{sub}</text>' if sub else ''}
</svg>""")


def gauge(pct: float, caption: str = "", detail: str = "") -> Markup:
    """Half-circle load gauge — reads faster than a bar for 'how full is this'."""
    pct = max(0.0, min(100.0, float(pct or 0)))
    w, h, r, sw = 108, 62, 44, 9
    cx, cy = w / 2, h - 8
    arc = math.pi * r                     # arc length of the semicircle
    on = arc * pct / 100
    col = load_color(pct)
    caption, detail = escape(str(caption)), escape(str(detail))
    return Markup(f"""
<svg class="chart-gauge" viewBox="0 0 {w} {h}" width="{w}" height="{h}"
     role="img" aria-label="{caption} {pct:.0f}%">
  <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}" fill="none"
        stroke="var(--well)" stroke-width="{sw}" stroke-linecap="round"/>
  <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}" fill="none"
        stroke="{col}" stroke-width="{sw}" stroke-linecap="round"
        stroke-dasharray="{on:.2f} {arc:.2f}"/>
  <text x="{cx}" y="{cy - 12}" class="gauge-n" text-anchor="middle">{pct:.0f}%</text>
  <text x="{cx}" y="{cy - 1}" class="gauge-c" text-anchor="middle">{caption}</text>
</svg>
{f'<div class="chart-cap">{detail}</div>' if detail else ''}""")


def sparkline(values: list, height: int = 40, color: str = "var(--accent-ink)",
              fill: bool = True, ceiling: float = 0) -> Markup:
    """Trend line that stretches to its container.

    Uses a fixed viewBox with non-uniform scaling, so stroke width is pinned
    with vector-effect — otherwise the line thins out as the card widens.
    """
    vals = [float(v or 0) for v in (values or [])]
    if len(vals) < 2:
        return Markup('<div class="chart-empty">collecting…</div>')
    w, pad = 240, 3
    inner = height - pad * 2
    step = w / (len(vals) - 1)

    lo, hi = min(vals), max(vals)
    if ceiling:
        hi = max(hi, float(ceiling))

    # A dead-flat series (e.g. a stable pod count) must read as "steady", so it
    # sits on the mid-line with no area fill. Filling from a flat top edge paints
    # the whole box solid, which looks like a bar chart rather than a trend.
    flat = hi <= lo
    if flat:
        ys = [pad + inner / 2] * len(vals)
    else:
        # widen a very narrow range so a one-pod wobble does not look dramatic
        span = max(hi - lo, hi * 0.04, 1e-9)
        ys = [min(height - pad, max(pad, pad + inner - ((v - lo) / span) * inner))
              for v in vals]

    pts = list(zip((i * step for i in range(len(vals))), ys))
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{line} {w:.1f},{height} 0,{height}"
    return Markup(f"""
<svg class="chart-spark" viewBox="0 0 {w} {height}" width="100%" height="{height}"
     preserveAspectRatio="none" role="img"
     aria-label="trend, latest {vals[-1]:g}{', steady' if flat else ''}">
  {f'<polygon points="{area}" fill="{color}" opacity=".13"/>' if fill and not flat else ''}
  <polyline points="{line}" fill="none" stroke="{color}" stroke-width="1.6"
            stroke-linejoin="round" stroke-linecap="round"
            {'stroke-dasharray="3 3" opacity=".65"' if flat else ''}
            vector-effect="non-scaling-stroke"/>
  <circle cx="{pts[-1][0]:.1f}" cy="{pts[-1][1]:.1f}" r="2.2" fill="{color}"
          vector-effect="non-scaling-stroke"/>
</svg>""")


def hbars(items: list, unit: str = "") -> Markup:
    """Ranked horizontal bars — HTML rather than SVG so long labels wrap and
    the layout stays responsive. items: [(label, value), …]"""
    if not items:
        return Markup('<div class="chart-empty">nothing to show</div>')
    top = max(v for _l, v in items) or 1
    rows = []
    for label, v in items:
        pct = v / top * 100
        # `label` is operator text -- a namespace, a cluster, a vendor -- and
        # this is wrapped in Markup(), which tells Jinja not to escape it. Same
        # shape as SEC-7 and the logos lettermark; found by the 23 September
        # sweep and missed when those two were fixed.
        safe = escape(label)
        rows.append(f"""<div class="hbar">
  <div class="hbar-l" title="{safe}">{safe}</div>
  <div class="hbar-t"><span style="width:{pct:.1f}%"></span></div>
  <div class="hbar-v">{v}{unit}</div>
</div>""")
    return Markup('<div class="hbars">' + "".join(rows) + "</div>")


def stack(segments: list, height: int = 8) -> Markup:
    """One proportional bar. segments: [(css-class, value), …]"""
    total = sum(v for _c, v in segments) or 1
    parts = "".join(f'<span class="{cls}" style="width:{v / total * 100:.2f}%"></span>'
                    for cls, v in segments if v)
    return Markup(f'<div class="podbar" style="height:{height}px">{parts}</div>')


def histogram(buckets: list, height: int = 96, overlay: str = "errors",
              base_key: str = "total", bar_class: str = "hb") -> Markup:
    """Volume over time, with a second series drawn inside the bars.

    Bars rather than a line: log volume is a count per interval, and a line
    implies a continuous value between samples. The overlay shares each bar so
    the eye compares error share against volume at the same instant, which a
    separate chart cannot do.
    """
    if not buckets:
        return Markup('<div class="chart-empty">no data in this window</div>')
    top = max((b.get(base_key, 0) for b in buckets), default=0) or 1
    n = len(buckets)
    gap = 1 if n <= 80 else 0
    w = 1000
    bw = max(1.0, (w - gap * (n - 1)) / n)
    bars, x = [], 0.0
    for b in buckets:
        tot, err = b.get(base_key, 0) or 0, b.get(overlay, 0) or 0
        th = (tot / top) * (height - 2)
        eh = min(th, (err / top) * (height - 2))
        y = height - th
        title = (f"{b.get('t','')[11:16]} · {tot:,}"
                 + (f" · {err:,} errors" if err and overlay in b else ""))
        bars.append(f'<g><title>{title}</title>'
                    f'<rect x="{x:.2f}" y="{y:.2f}" width="{bw:.2f}" height="{th:.2f}" '
                    f'class="{bar_class}"/>'
                    + (f'<rect x="{x:.2f}" y="{height - eh:.2f}" width="{bw:.2f}" '
                       f'height="{eh:.2f}" class="hb-err"/>' if eh > 0 else '')
                    + '</g>')
        x += bw + gap
    first = (buckets[0].get("t") or "")[11:16]
    last = (buckets[-1].get("t") or "")[11:16]
    return Markup(f"""
<svg class="chart-hist" viewBox="0 0 {w} {height}" width="100%" height="{height}"
     preserveAspectRatio="none" role="img"
     aria-label="volume over time, peak {top:,} per bucket">{''.join(bars)}</svg>
<div class="hist-axis"><span>{first}</span><span>peak {top:,}</span><span>{last}</span></div>""")


def cloud_map(account: str, provider: str, region: str, groups: list) -> Markup:
    """A map of one cloud account: the account, then a lane per resource kind.

    Laid out from the data rather than from a template — the number of lanes and
    the number of chips in each come from what the account holds, so an account
    with three EC2 instances and no databases draws exactly that. Long lanes are
    truncated with a counted remainder rather than overflowing, because a
    diagram that runs off the page is worse than one that says "+ 40 more".
    """
    PER_LANE = 8
    lane_h, chip_w, chip_h, gap = 74, 118, 34, 10
    width = 120 + PER_LANE * (chip_w + gap)
    height = 92 + max(1, len(groups)) * lane_h
    out = [f'<svg class="chart-cloudmap" viewBox="0 0 {width} {height}" '
           f'width="100%" height="{height}" role="img" '
           f'aria-label="resource map for {escape(account)}">']
    # the account itself
    out.append(
        f'<rect x="16" y="18" width="{width - 32}" height="46" rx="10" '
        f'fill="var(--well)" stroke="var(--accent)" stroke-width="1.5"/>'
        f'<text x="32" y="40" font-size="13" font-weight="650" '
        f'fill="var(--text)">{escape(provider)} · {escape(account)}</text>'
        f'<text x="32" y="56" font-size="11" fill="var(--muted)">'
        f'{escape(region or "no region reported")}</text>')
    y = 84
    for g in groups:
        items = g.get("rows") or []
        out.append(
            f'<line x1="34" y1="{y - 6}" x2="34" y2="{y + chip_h // 2}" '
            f'stroke="var(--line)" stroke-width="1.5"/>'
            f'<text x="16" y="{y + 4}" font-size="11" fill="var(--muted)">'
            f'{escape(g.get("icon", ""))}</text>'
            f'<text x="46" y="{y + 4}" font-size="11.5" font-weight="600" '
            f'fill="var(--muted)">{escape(g.get("label", ""))} '
            f'({len(items)})</text>')
        cy = y + 14
        for i, it in enumerate(items[:PER_LANE]):
            x = 46 + i * (chip_w + gap)
            state = (it.get("state") or "").lower()
            stroke = ("var(--ok-ink)" if state in ("running", "available", "succeeded")
                      else "var(--warn-ink)" if state else "var(--line)")
            name = escape(str(it.get("name", ""))[:15])
            sub = escape(str(it.get("kind", ""))[:16])
            out.append(
                f'<rect x="{x}" y="{cy}" width="{chip_w}" height="{chip_h}" rx="7" '
                f'fill="var(--panel)" stroke="{stroke}" stroke-width="1"/>'
                f'<text x="{x + 8}" y="{cy + 14}" font-size="10.5" '
                f'fill="var(--text)">{name}</text>'
                f'<text x="{x + 8}" y="{cy + 26}" font-size="9.5" '
                f'fill="var(--muted)">{sub}</text>')
        if len(items) > PER_LANE:
            x = 46 + PER_LANE * (chip_w + gap)
            out.append(f'<text x="{x}" y="{cy + 21}" font-size="11" '
                       f'fill="var(--faint)">+ {len(items) - PER_LANE} more</text>')
        y += lane_h
    if not groups:
        out.append(f'<text x="46" y="{y + 10}" font-size="11.5" '
                   f'fill="var(--faint)">nothing inventoried for this provider</text>')
    out.append("</svg>")
    return Markup("".join(out))


def cloud_topology(inv: dict) -> Markup:
    """The account's network as it actually is: VPCs, their subnets, and what
    sits in each one.

    Membership is worked out rather than asked for. The instance list gives a
    private address but not a subnet id, so each address is tested against every
    subnet's CIDR — 10.0.2.124 belongs to 10.0.2.0/24 and nothing else. That is
    cheaper than a describe call per instance and it cannot disagree with the
    addresses on screen.

    HTML rather than SVG: a diagram of boxes inside boxes is what CSS does well,
    it reflows on a narrow screen, and the labels stay selectable.
    """
    import ipaddress

    def rows(key):
        for g in inv.get("groups") or []:
            if g.get("key") == key:
                return g.get("rows") or []
        return []

    vpcs, subnets = rows("vpcs"), rows("subnets")
    if not vpcs and not subnets:
        return Markup('<div class="chart-empty">no network to draw</div>')

    def net(cidr):
        try:
            return ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            return None

    def addresses(text):
        out = []
        for part in str(text or "").replace("→", ",").split(","):
            part = part.strip().split(" ")[0]
            try:
                out.append(ipaddress.ip_address(part))
            except ValueError:
                continue
        return out

    # what lives where, decided by address
    members: dict = {}
    def place(row, icon, kind):
        for ip in addresses(row.get("extra")):
            for sn in subnets:
                n = net(sn.get("kind"))
                if n and ip in n:
                    members.setdefault(sn["id"], []).append(
                        (icon, row.get("name") or row.get("id", ""), kind,
                         row.get("state", "")))
                    return True
        return False

    # things known only by their VPC, which is still worth drawing in the right
    # VPC rather than in a bucket of leftovers
    at_vpc: dict = {}

    def place_by_vpc(row, icon, kind):
        for v in vpcs:
            if v["id"] and v["id"] in str(row.get("extra", "")):
                at_vpc.setdefault(v["id"], []).append(
                    (icon, row.get("name") or row.get("id", ""), kind,
                     row.get("state", "")))
                return True
        return False

    edge, homeless = [], []
    for r in rows("compute"):
        if not (place(r, "🖥", "instance") or place_by_vpc(r, "🖥", "instance")):
            homeless.append(("🖥", r.get("name", ""), "instance", r.get("state", "")))
    for r in rows("clb"):
        # an internet-facing balancer is on the edge by definition; only the
        # intranet ones live inside a subnet
        if "internet" in str(r.get("kind", "")).lower():
            edge.append(("⚖", r.get("name", ""), r.get("extra", "")))
        elif not (place(r, "⚖", "load balancer")
                  or place_by_vpc(r, "⚖", "load balancer")):
            homeless.append(("⚖", r.get("name", ""), "load balancer", r.get("state", "")))
    for r in rows("rds"):
        if not (place(r, "🗃", "database") or place_by_vpc(r, "🗃", "database")):
            homeless.append(("🗃", r.get("name", ""), "database", r.get("state", "")))
    for r in rows("redis"):
        if not (place(r, "⚡", "cache") or place_by_vpc(r, "⚡", "cache")):
            homeless.append(("⚡", r.get("name", ""), "cache", r.get("state", "")))

    for r in rows("eips"):
        edge.append(("🌐", r.get("name", ""), r.get("extra", "")))
    for r in rows("nat"):
        edge.append(("↔", r.get("name", ""), r.get("kind", "")))
    for r in rows("vpn"):
        edge.append(("🔒", r.get("name", ""), r.get("kind", "")))

    def chip(icon, name, sub, state=""):
        cls = "tp-chip"
        if state and state.lower() not in ("running", "available", "active",
                                           "inuse", "in_use"):
            cls += " tp-off"
        return (f'<div class="{cls}"><span>{icon}</span>'
                f'<b title="{name}">{name[:26]}</b>'
                f'<i>{sub}</i></div>')

    out = ['<div class="tp">']
    if edge:
        out.append('<div class="tp-edge"><div class="tp-lab">reachable from the '
                   'internet</div><div class="tp-chips">')
        out += [chip(i, n, s) for i, n, s in edge]
        out.append("</div></div>")

    for v in vpcs:
        mine = [s for s in subnets if v["id"] and v["id"] in str(s.get("extra", ""))]
        out.append(f'<div class="tp-vpc"><div class="tp-vpc-h">'
                   f'<b>{v.get("name", "")}</b>'
                   f'<code>{v.get("kind", "")}</code>'
                   f'<span>{len(mine)} subnet{"s" if len(mine) != 1 else ""}</span>'
                   f'</div><div class="tp-subnets">')
        if not mine:
            out.append('<div class="tp-none">no subnets in this VPC</div>')
        for sn in mine:
            n = net(sn.get("kind"))
            free = str(sn.get("extra", "")).split(" ")[0]
            used = ""
            if n is not None and free.isdigit():
                total = n.num_addresses - 5          # Alibaba reserves five
                pct = max(0, round((total - int(free)) / total * 100)) if total > 0 else 0
                used = f'<div class="tp-use"><span style="width:{pct}%"></span></div>'
            inside = members.get(sn["id"], [])
            out.append(f'<div class="tp-subnet"><div class="tp-sn-h">'
                       f'<b>{sn.get("name", "")}</b><code>{sn.get("kind", "")}</code>'
                       f'<span>{sn.get("zone", "")}</span>{used}</div>'
                       f'<div class="tp-chips">'
                       + ("".join(chip(i, nm, k, st) for i, nm, k, st in inside)
                          or '<div class="tp-none">empty</div>')
                       + "</div></div>")
        out.append("</div>")
        extra = at_vpc.get(v["id"]) or []
        if extra:
            out.append('<div class="tp-vpc-extra"><div class="tp-lab">in this VPC, '
                       'not tied to one subnet</div><div class="tp-chips">'
                       + "".join(chip(i, nm, k, st) for i, nm, k, st in extra)
                       + "</div></div>")
        out.append("</div>")

    if homeless:
        out.append('<div class="tp-edge"><div class="tp-lab">not matched to a '
                   'subnet by address</div><div class="tp-chips">')
        out += [chip(i, n, k, st) for i, n, k, st in homeless]
        out.append("</div></div>")
    out.append("</div>")
    return Markup("".join(out))
