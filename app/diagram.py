"""Render an environment topology as a self-contained, interactive SVG.

WHY THE SVG CARRIES ITS OWN CSS AND SCRIPT
    It is drawn on two pages (a cluster's Diagram tab and an environment's own
    page) and it is one string. Putting the interaction in the templates would
    mean two copies of it, and the drawing already knows things the page does
    not: which box connects to which, and where each box's detail lives.

WHAT THE INTERACTION IS FOR
    A topology picture with forty edges is a picture of a hairball. The question
    people actually bring to it is "what does THIS talk to" — so hovering or
    focusing a box dims everything that is not that box, its edges, and whatever
    sits at the other end of them. One path at a time, out of the same drawing.

    And a box is a thing in a cluster, so it is a link: a workload opens its own
    pods, an ingress host opens the routes table, an edge address opens the
    services. Nothing is a dead end that has a page of its own somewhere.

    Keyboard reachable for the same reason it is hover-reachable: the highlight
    is on `:focus-within` as well, so tabbing through the boxes walks the paths.
"""
from html import escape

from . import csp

COL_W, BOX_H, GAP_Y = 210, 46, 13
COL_X = [24, 268, 512, 756, 1000]
WIDTH = COL_X[-1] + COL_W + 24
PAD_TOP = 54

PALETTE = {
    "internet": ("#1e2a44", "#5b8def"),
    "edge": ("#1d2b3f", "#38bdf8"),
    "ingress": ("#22203f", "#8b6cf5"),
    "service": ("#152437", "#3ddc97"),
    "service_bad": ("#2a1a22", "#f57171"),
    "service_drift": ("#2b211a", "#fb923c"),  # runs in the cluster, not in git (orange, distinct from the amber external providers)
    "data": ("#1f2a1c", "#a3e635"),
    "provider": ("#2b2418", "#f5c451"),
    "database": ("#1a2632", "#60a5fa"),
    "cache": ("#2a1f2e", "#e879f9"),
    "queue": ("#231f2e", "#a78bfa"),
}

# The colour key, drawn at the foot for whichever kinds are actually present so
# a reader is not left decoding the palette. Order = how a reader triages: the
# app's own workloads first, then its dependencies.
LEGEND = [
    ("service", "#3ddc97", "healthy"),
    ("service_bad", "#f57171", "not ready"),
    ("service_drift", "#fb923c", "in cluster, not in git"),
    ("data", "#a3e635", "in-cluster data"),
    ("provider", "#f5c451", "external service"),
    ("database", "#60a5fa", "external DB"),
    ("cache", "#e879f9", "external cache"),
    ("queue", "#a78bfa", "external queue"),
]
LEG_H = 30

# The interaction, and the polish. Scoped under the drawing's own id so two of
# them on one page cannot style each other.
STYLE = """
.dg { --dg-ease: 140ms cubic-bezier(.2,.7,.3,1); }
.dg .dbox rect { transition: fill var(--dg-ease), stroke var(--dg-ease),
  filter var(--dg-ease); }
.dg .dbox { transition: opacity var(--dg-ease), transform var(--dg-ease); }
.dg .dedge { transition: opacity var(--dg-ease), stroke var(--dg-ease),
  stroke-width var(--dg-ease); }
.dg a { cursor: pointer; }
.dg a:hover .dbox, .dg a:focus .dbox { transform: translateY(-1.5px); }
.dg a:focus { outline: none; }
/* Hovering or focusing one box dims the rest of the drawing. `.hot` is put on by
   the script below, which is the only way to reach the boxes at the far end of an
   edge — CSS cannot select an element by "shares a data attribute with me". */
.dg.dg-lit .dbox, .dg.dg-lit .dedge { opacity: .16; }
.dg.dg-lit .dbox.hot, .dg.dg-lit .dedge.hot { opacity: 1; }
.dg.dg-lit .dedge.hot { stroke-width: 2.1; }
.dg .dbox.hot rect { filter: brightness(1.28); }
/* a PINNED box (clicked) keeps its path lit while you scroll the tall drawing to
   reach the far end of an edge — a plain hover would drop the moment the mouse
   left the box. A brighter, thicker ring marks which box is pinned. */
.dg .dbox.pinned rect { stroke-width: 2.6; filter: brightness(1.25); }
.dg .dot { transition: opacity var(--dg-ease); }
.dg .dhint { opacity: 0; transition: opacity var(--dg-ease); }
.dg:hover .dhint { opacity: 1; }
/* the edges flow left→right (clients → services → data), so the drawing reads as
   traffic in motion rather than a static wiring diagram. The dash travels toward
   the target; a lit path speeds up so the one you are following stands out. */
@keyframes dg-flow { to { stroke-dashoffset: -14; } }
.dg .dedge { stroke-dasharray: 5 5; animation: dg-flow .9s linear infinite; }
.dg.dg-lit .dedge.hot { animation-duration: .5s; }
@media (prefers-reduced-motion: reduce) {
  .dg .dedge { animation: none; stroke-dasharray: none; }
}
"""

SCRIPT = """
(function () {
  var svg = document.currentScript && document.currentScript.parentNode;
  if (!svg) return;
  var boxes = svg.querySelectorAll('.dbox');
  var edges = svg.querySelectorAll('.dedge');
  var pinned = null;                 // a clicked box; its highlight survives scroll
  function clear() {
    svg.classList.remove('dg-lit');
    boxes.forEach(function (b) { b.classList.remove('hot'); b.classList.remove('pinned'); });
    edges.forEach(function (e) { e.classList.remove('hot'); });
  }
  function light(box) {
    var id = box.getAttribute('data-id');
    // Everything one hop away, in either direction: an edge names its two ends,
    // so the neighbours are read off the edges rather than stored twice.
    var near = {};
    near[id] = 1;
    edges.forEach(function (e) {
      var a = e.getAttribute('data-a'), b = e.getAttribute('data-b');
      if (a === id || b === id) { e.classList.add('hot'); near[a] = 1; near[b] = 1; }
    });
    boxes.forEach(function (b) {
      if (near[b.getAttribute('data-id')]) b.classList.add('hot');
    });
    svg.classList.add('dg-lit');
  }
  function unpin() { pinned = null; clear(); }
  boxes.forEach(function (box) {
    // The whole box is a link. First click PINS its path (and does not navigate),
    // so you can scroll the tall drawing to the far end without losing the
    // highlight; clicking the SAME box again lets the link through and opens it.
    var link = box.closest('a') || box;
    link.addEventListener('click', function (e) {
      if (pinned === box) return;                 // second click → follow the link
      e.preventDefault(); e.stopPropagation();
      clear(); light(box); box.classList.add('pinned'); pinned = box;
    });
    // Hover is a live preview, but only while nothing is pinned.
    ['mouseenter', 'focusin'].forEach(function (ev) {
      box.addEventListener(ev, function () { if (!pinned) { clear(); light(box); } });
    });
    ['mouseleave', 'focusout'].forEach(function (ev) {
      box.addEventListener(ev, function () { if (!pinned) clear(); });
    });
  });
  // click on empty canvas, or Escape, releases the pin
  svg.addEventListener('click', function (e) { if (!e.target.closest('.dbox')) unpin(); });
  svg.addEventListener('mouseleave', function () { if (!pinned) clear(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') unpin(); });
})();
"""


def _col_layout(items: int, max_h: int) -> tuple[float, float]:
    """Return (start_y, step) so a column of N boxes is vertically centred."""
    h = items * BOX_H + max(0, items - 1) * GAP_Y
    return (PAD_TOP + max(0, (max_h - h) / 2), BOX_H + GAP_Y)


def _box(x, y, kind, title, sub="", w=COL_W, bid="", href="", tip="",
         dot=None):
    """One box. `bid` is what edges name it by; `href` makes it a link.

    `dot` draws a state light — a workload that is not fully ready is the thing
    a reader is looking for, and the border colour alone is a difference of two
    dark shades that nobody can see from across a room.
    """
    fill, stroke = PALETTE.get(kind, PALETTE["service"])
    t = escape(title[:30] + ("…" if len(title) > 30 else ""))
    s = escape(sub[:34] + ("…" if len(sub) > 34 else "")) if sub else ""
    pad = 13 + (13 if dot is not None else 0)
    out = [f'<g class="dbox" data-id="{bid}" tabindex="0">']
    if tip:
        out.append(f"<title>{escape(tip)}</title>")
    out.append(f'<rect x="{x}" y="{y:.0f}" width="{w}" height="{BOX_H}" rx="9" '
               f'fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
    if dot is not None:
        out.append(f'<circle class="dot" cx="{x + 15}" cy="{y + BOX_H / 2:.0f}" r="3.6" '
                   f'fill="{"#3ddc97" if dot else "#f57171"}"/>')
    out.append(f'<text x="{x + pad}" y="{y + (20 if s else 27):.0f}" fill="#e8edf6" '
               f'font-size="12.5" font-weight="600" '
               f'font-family="-apple-system,Inter,sans-serif">{t}</text>')
    if s:
        out.append(f'<text x="{x + pad}" y="{y + 34:.0f}" fill="#8a97b1" '
                   f'font-size="10.5" font-family="ui-monospace,Menlo,monospace">'
                   f'{s}</text>')
    out.append("</g>")
    body = "".join(out)
    if href:
        # target="_self" is deliberate: an SVG <a> without it inherits whatever
        # the document's base target is, and a diagram that opens new tabs per
        # click is a diagram nobody clicks twice.
        return (f'<a href="{escape(href, quote=True)}" target="_self">{body}</a>')
    return body


def _link(x1, y1, x2, y2, color="#2c3958", opacity=0.85, a="", b=""):
    mid = (x1 + x2) / 2
    return (f'<path class="dedge" data-a="{a}" data-b="{b}" '
            f'd="M{x1:.0f},{y1:.0f} C{mid:.0f},{y1:.0f} {mid:.0f},{y2:.0f} '
            f'{x2:.0f},{y2:.0f}" fill="none" stroke="{color}" '
            f'stroke-width="1.3" opacity="{opacity}"/>')


def _header(x, label):
    return (f'<text x="{x}" y="30" fill="#8a97b1" font-size="10.5" font-weight="700" '
            f'letter-spacing="1.4" font-family="-apple-system,Inter,sans-serif">'
            f'{escape(label.upper())}</text>')


def render(topo: dict, max_rows: int = 34, base: str = "") -> str:
    """The drawing. `base` is the cluster page's own URL, and without it the
    boxes are drawn exactly as before — inert, which is what the pages that have
    no cluster to link into want."""
    edge = [{"t": v["ip"], "s": f'{v["namespace"]}/{v["name"]}'} for v in topo["vips"]]
    ingress = topo["ingress"][:max_rows]
    services = topo["workloads"][:max_rows]
    right = (
        [{"t": d["label"], "s": f'{d["count"]} workload(s)', "k": "data",
          "ns": (d.get("namespaces") or [""])[0]}
         for d in topo["data"]]
        + [{"t": e["host"], "s": ", ".join(e["used_by"])[:34], "k": e["kind"],
            "ns": ""}
           for e in topo["external"][:max_rows]]
    )[:max_rows + 4]

    def to(where: str) -> str:
        return f"{base}&{where}" if base else ""

    # which kinds are on the drawing → which legend swatches to show
    def svc_kind(s):
        return ("service_bad" if not s["healthy"]
                else "service_drift" if s.get("undeclared") else "service")
    present = {svc_kind(s) for s in services} | {r["k"] for r in right}
    legend = [(c, lab) for k, c, lab in LEGEND if k in present]

    cols = [1, max(1, len(edge)), max(1, len(ingress)),
            max(1, len(services)), max(1, len(right))]
    max_h = max(n * BOX_H + (n - 1) * GAP_Y for n in cols)
    height = PAD_TOP + max_h + 30 + (LEG_H if legend else 0)

    svg = [f'<svg class="dg" viewBox="0 0 {WIDTH} {height:.0f}" width="100%" '
           f'xmlns="http://www.w3.org/2000/svg" style="min-width:940px">',
           f"<style>{STYLE}</style>"]
    labels = ["Clients", "Edge / LB", "Ingress hosts", "Workloads", "Data & external"]
    for x, lab in zip(COL_X, labels):
        svg.append(_header(x, lab))

    # positions per column
    pos: list[list[float]] = []
    for idx, n in enumerate(cols):
        start, step = _col_layout(n, max_h)
        pos.append([start + i * step for i in range(n)])

    def cy(col, i):
        return pos[col][i] + BOX_H / 2

    def bid(col, i):
        return f"b{col}-{i}"

    # links: clients -> edge -> ingress -> services -> right
    for i in range(len(edge) or 1):
        svg.append(_link(COL_X[0] + COL_W, cy(0, 0), COL_X[1], cy(1, i),
                         a=bid(0, 0), b=bid(1, i)))
    for i in range(len(ingress) or 1):
        svg.append(_link(COL_X[1] + COL_W, cy(1, 0), COL_X[2], cy(2, i),
                         opacity=0.55, a=bid(1, 0), b=bid(2, i)))

    svc_index = {s["name"]: i for i, s in enumerate(services)}
    for i, ing in enumerate(ingress):
        for b in ing["backends"]:
            core = b.replace("-service", "")
            j = next((k for name, k in svc_index.items()
                      if name == b or name == core or core.startswith(name)), None)
            if j is not None:
                svg.append(_link(COL_X[2] + COL_W, cy(2, i), COL_X[3], cy(3, j),
                                 color="#3a4a6b", opacity=0.7,
                                 a=bid(2, i), b=bid(3, j)))

    for i, r in enumerate(right):
        users = [u for u in (r["s"] or "").split(", ") if u]
        drawn = False
        for u in users:
            j = next((k for name, k in svc_index.items() if u and u in name), None)
            if j is not None:
                svg.append(_link(COL_X[3] + COL_W, cy(3, j), COL_X[4], cy(4, i),
                                 color="#3b3352", opacity=0.5,
                                 a=bid(3, j), b=bid(4, i)))
                drawn = True
        if not drawn and services:
            svg.append(_link(COL_X[3] + COL_W, cy(3, len(services) // 2),
                             COL_X[4], cy(4, i), color="#2c3958", opacity=0.28,
                             a=bid(3, len(services) // 2), b=bid(4, i)))

    # boxes
    n = topo["nodes"]
    svg.append(_box(COL_X[0], pos[0][0], "internet", "Internet / clients",
                    f'{n["total"]} nodes · {n["cp"]} cp · {n["workers"]} wk',
                    bid=bid(0, 0), href=to("tab=nodes"),
                    tip="the machines behind all of this"))
    if edge:
        for i, e in enumerate(edge):
            svg.append(_box(COL_X[1], pos[1][i], "edge", e["t"], e["s"],
                            bid=bid(1, i), href=to("tab=network&sec=services"),
                            tip=f'{e["s"]} — published at {e["t"]}'))
    else:
        svg.append(_box(COL_X[1], pos[1][0], "edge", "no LoadBalancer", "",
                        bid=bid(1, 0)))

    if ingress:
        for i, ing in enumerate(ingress):
            svg.append(_box(COL_X[2], pos[2][i], "ingress", ing["host"],
                            " → " + ", ".join(ing["backends"]), bid=bid(2, i),
                            href=to("tab=network&sec=routes"),
                            tip=f'{ing["host"]} → '
                                + ", ".join(ing["backends"])))
    else:
        svg.append(_box(COL_X[2], pos[2][0], "ingress", "no ingress routes", "",
                        bid=bid(2, 0)))

    if services:
        for i, s in enumerate(services):
            drift = s.get("undeclared")
            kind = ("service_bad" if not s["healthy"]
                    else "service_drift" if drift else "service")
            svg.append(_box(
                COL_X[3], pos[3][i], kind, s["name"],
                f'{s["ready"]}/{s["desired"]} ready · {s["namespace"]}'
                + ("  ⚠ not in git" if drift else ""),
                bid=bid(3, i), dot=bool(s["healthy"]),
                # Straight to this workload's own pods — the same filter the
                # Workloads table links to, so the drawing is a way INTO the
                # cluster rather than a picture beside it.
                href=to(f'tab=pods&ns={s["namespace"]}&workload={s["name"]}'),
                tip=f'{s["kind"]} {s["namespace"]}/{s["name"]} — '
                    f'{s["ready"]} of {s["desired"]} ready. Opens its pods.'
                    + (" This workload runs in the cluster but is not declared "
                       "in the environment's git config." if drift else "")))
    else:
        svg.append(_box(COL_X[3], pos[3][0], "service", "no workloads", "",
                        bid=bid(3, 0)))

    if right:
        for i, r in enumerate(right):
            # In-cluster dependencies have a namespace and so have pods to show;
            # a third-party host has neither and stays inert rather than
            # pretending to lead somewhere.
            href = to(f'tab=pods&ns={r["ns"]}') if r.get("ns") else ""
            svg.append(_box(COL_X[4], pos[4][i], r["k"], r["t"], r["s"],
                            bid=bid(4, i), href=href,
                            tip=(f'{r["t"]} — used by {r["s"]}' if r["s"]
                                 else r["t"])))
    else:
        svg.append(_box(COL_X[4], pos[4][0], "data", "none detected", "",
                        bid=bid(4, 0)))

    # the notes sit just above the legend band (or at the foot when there is none)
    foot_y = height - (LEG_H + 10 if legend else 8)
    extra = []
    if len(topo["workloads"]) > max_rows:
        extra.append(f'+{len(topo["workloads"]) - max_rows} more workloads')
    if len(topo["ingress"]) > max_rows:
        extra.append(f'+{len(topo["ingress"]) - max_rows} more hosts')
    if extra:
        svg.append(f'<text x="{COL_X[0]}" y="{foot_y:.0f}" fill="#8a97b1" '
                   f'font-size="11" font-family="-apple-system,Inter,sans-serif">'
                   f'{escape(" · ".join(extra))}</text>')
    if base:
        svg.append(f'<text class="dhint" x="{WIDTH - 24}" y="{foot_y:.0f}" '
                   f'text-anchor="end" fill="#8a97b1" font-size="11" '
                   f'font-family="-apple-system,Inter,sans-serif">'
                   f'hover to preview · click a box to pin its path (scroll freely) '
                   f'· click again to open · Esc clears</text>')

    # colour key — only the kinds actually on the drawing
    if legend:
        ly, lx = height - 10, COL_X[0]
        for color, lab in legend:
            svg.append(f'<circle cx="{lx + 4:.0f}" cy="{ly - 4:.0f}" r="4" fill="{color}"/>')
            svg.append(f'<text x="{lx + 13:.0f}" y="{ly:.0f}" fill="#8a97b1" font-size="10.5" '
                       f'font-family="-apple-system,Inter,sans-serif">{escape(lab)}</text>')
            lx += 13 + int(len(lab) * 6.0) + 20

    # The diagram is embedded INLINE in a page, so its script needs this
    # request's nonce or the browser refuses to run it and the topology
    # renders as a picture nothing can be clicked on.
    svg.append(f'<script nonce="{csp.nonce()}">{SCRIPT}</script>')
    svg.append("</svg>")
    return "".join(svg)
