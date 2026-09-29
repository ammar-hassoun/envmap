#!/usr/bin/env python3
"""Turn three icon packs into app/logodata.py, which is what actually ships.

WHY THE ARTEFACT IS COMMITTED AND THE PACKS ARE NOT
    The packs are 60MB of which this product uses about sixty files. Vendoring
    the built result is the same bargain already struck for xterm.js: the image
    stays small, the install needs no network and no npm, and an air-gapped
    customer gets the same page as everybody else. This script exists so the
    result is reproducible rather than a blob somebody once pasted in.

    Re-run it when a vendor is added:

        npm pack devicon simple-icons lucide-static
        # extract each into <dir>/{devicon,simple-icons,lucide-static}
        ./.venv/bin/python scripts/build_logos.py <dir>

WHERE EACH MARK COMES FROM, AND WHY IT MATTERS WHICH
    Devicon first, because those are the real multi-colour marks — the
    Kubernetes helm in its own blue, the Jenkins butler, the GitLab fox. Simple
    Icons second, for vendors Devicon has no art for; those are single-path
    silhouettes, so they are filled with the brand's own registered hex out of
    the pack's metadata rather than a colour picked here.

    Lucide is not brands at all. It is the line set for the things that have no
    vendor — a project, an environment, a sidebar entry — and it is what
    replaces the emoji those used to be.

TRADEMARKS
    These are other companies' marks, used to identify their own products in a
    list of integrations. That is nominative use and it is why nothing here
    recolours or restyles a mark, stretches one, or puts one in the brand slot
    a customer white-labels. The one exception is deliberate and narrow: see
    INVERT.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

# ── the marks, and which pack each comes from ──────────────────
# Devicon: full-colour original artwork. Value is the file stem inside
# icons/<name>/, because Devicon ships several cuts of each.
DEVICON = {
    "kubernetes": "kubernetes/kubernetes-original",
    "helm": "helm/helm-original",
    "docker": "docker/docker-original",
    "git": "git/git-original",
    "github": "github/github-original",
    "bitbucket": "bitbucket/bitbucket-original",
    "gitlab": "gitlab/gitlab-original",
    "jenkins": "jenkins/jenkins-original",
    "argocd": "argocd/argocd-original",
    "grafana": "grafana/grafana-original",
    "prometheus": "prometheus/prometheus-original",
    "elasticsearch": "elasticsearch/elasticsearch-original",
    "azure": "azure/azure-original",
    "gcp": "googlecloud/googlecloud-original",
    "postgres": "postgresql/postgresql-original",
    "mysql": "mysql/mysql-original",
    "couchbase": "couchbase/couchbase-original",
    "sonarqube": "sonarqube/sonarqube-original",
    "airflow": "apacheairflow/apacheairflow-original",
    "cloudflare": "cloudflare/cloudflare-original",
    "nginx": "nginx/nginx-original",
    "vault": "vault/vault-original",
    # Amazon withdrew its mark from Simple Icons, so this is the only pack that
    # still carries one. It is the wordmark cut because it is the only cut
    # Devicon ships — the smile and the letters, which is the real logo.
    "aws": "amazonwebservices/amazonwebservices-original-wordmark",
}

# Simple Icons: single-path silhouettes for vendors Devicon has no art for.
# Filled with the brand's own hex, read from the pack's metadata.
SIMPLE = {
    "flux": "flux",                    # cncf/artwork — FluxCD, not the JS one
    # Devicon ships this name too, but its "original" cut is the wordmark
    # letterforms spread across the viewBox, which at 20px is three specks.
    "proxmox": "proxmox",
    "temporal": "temporal",
    "vsphere": "vmware",
    "alibaba": "alibabacloud",
    "minio": "minio",
    "fastly": "fastly",
    "letsencrypt": "letsencrypt",
    "wg_easy": "wireguard",
    "openvpn_as": "openvpn",
    "synology": "synology",
    "truenas": "truenas",
    "opensearch": "opensearch",
}

# Marks that are black or near-black, which is invisible on this UI. Every one
# of these vendors publishes a mono light cut for dark backgrounds, which is
# exactly what this produces: the artwork is untouched, only a fill too dark to
# see is swapped for the light tone. Nothing else is ever recoloured.
# vsphere and synology are wordmarks in a grey that is legible on white and
# nearly gone on this surface; both vendors publish a light cut for exactly
# this case, which is what the swap produces.
INVERT = {"github", "temporal", "aws", "flux", "vsphere", "synology"}
INK_LIGHT = "#e8eef7"
TOO_DARK = 0.22                        # relative luminance, 0..1

# Lucide: the line set for everything that is not a vendor.
LUCIDE = [
    # sidebar
    "layout-grid", "history", "hourglass", "git-compare-arrows", "hexagon",
    "git-branch", "zap", "globe", "shield-check", "workflow", "shield",
    "scroll-text", "chart-line", "database", "lock", "server", "wallet",
    "hard-drive", "cpu", "layers", "cloud", "settings", "users",
    "clipboard-list", "search", "sparkles", "plus", "key-round",
    "user-cog", "folder-git-2", "square-terminal", "mail",
    # projects and environments
    "package", "flask-conical", "rocket", "life-buoy", "test-tube", "wrench",
    # cluster furniture
    "boxes", "git-merge", "activity", "receipt", "circle-check",
    "triangle-alert",
]


# ── turning one file into something that can be inlined ────────
def _luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    if len(h) != 6:
        return 1.0
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


# Presentation attributes that mean something when they sit on the root <svg>
# and are inherited by everything inside it.
_INHERITED = ("fill", "stroke", "fill-rule", "clip-rule", "fill-opacity",
              "stroke-width", "stroke-linecap", "stroke-linejoin", "color")


def _strip(svg: str) -> tuple[str, str]:
    """(viewBox, inner markup) — comments, titles and sizing removed.

    The root tag's own fill is carried onto a wrapper rather than dropped with
    the rest of it. Couchbase's mark is one path with no fill of its own and
    `fill="#EA2328"` on the <svg>; discarding that turned the whole logo black,
    and black on this surface reads as a rendering fault rather than a wrong
    colour — which is exactly how long it took to notice.
    """
    svg = re.sub(r"<\?xml.*?\?>", "", svg, flags=re.S)
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)
    svg = re.sub(r"<title>.*?</title>", "", svg, flags=re.S)
    root = re.search(r"<svg[^>]*>", svg, flags=re.S)
    root = root.group(0) if root else ""
    m = re.search(r'viewBox="([^"]+)"', root)
    box = m.group(1) if m else "0 0 24 24"
    inner = re.sub(r"^.*?<svg[^>]*>", "", svg, count=1, flags=re.S)
    inner = re.sub(r"</svg>\s*$", "", inner, flags=re.S)
    inner = re.sub(r">\s+<", "><", inner).strip()
    inner = re.sub(r"\s+", " ", inner)
    carry = " ".join(f'{a}="{v}"' for a in _INHERITED
                     for v in re.findall(rf'\b{a}="([^"]+)"', root))
    return box, (f"<g {carry}>{inner}</g>" if carry else inner)


def _namespace(inner: str, slug: str) -> str:
    """Prefix every internal id with the slug.

    Devicon's clip paths are referenced by id, and two different marks on one
    page with the same id is a mark that silently renders as a blank square —
    the kind of fault that only shows up on whichever page happens to put two
    logos side by side.
    """
    ids = set(re.findall(r'\bid="([^"]+)"', inner))
    for i in sorted(ids, key=len, reverse=True):
        safe = f"{slug}-{i}"
        inner = inner.replace(f'id="{i}"', f'id="{safe}"')
        inner = inner.replace(f"url(#{i})", f"url(#{safe})")
        inner = inner.replace(f'href="#{i}"', f'href="#{safe}"')
    return inner


def _lighten(inner: str, slug: str) -> str:
    if slug not in INVERT:
        return inner

    def swap(m):
        return (f'{m.group(1)}="{INK_LIGHT}"'
                if _luminance(m.group(2)) < TOO_DARK else m.group(0))
    return re.sub(r'\b(fill|stop-color)="(#[0-9a-fA-F]{3,6})"', swap, inner)


def main(root: str) -> int:
    src = pathlib.Path(root)
    hexes = {i["slug"]: i["hex"] for i in
             json.loads((src / "simple-icons/data/simple-icons.json").read_text())}
    brands, glyphs, missing = {}, {}, []

    for slug, stem in DEVICON.items():
        f = src / "devicon/icons" / f"{stem}.svg"
        if not f.exists():
            missing.append(str(f))
            continue
        box, inner = _strip(f.read_text())
        brands[slug] = (box, _lighten(_namespace(inner, slug), slug))

    for slug, name in SIMPLE.items():
        f = src / "simple-icons/icons" / f"{name}.svg"
        if not f.exists():
            missing.append(str(f))
            continue
        box, inner = _strip(f.read_text())
        colour = INK_LIGHT if slug in INVERT else "#" + hexes.get(name, "888888")
        # The pack's paths carry no fill of their own, so one wrapper colours
        # the whole mark and nothing has to be edited path by path.
        brands[slug] = (box, f'<g fill="{colour}">{_namespace(inner, slug)}</g>')

    for name in LUCIDE:
        f = src / "lucide-static/icons" / f"{name}.svg"
        if not f.exists():
            missing.append(str(f))
            continue
        box, inner = _strip(f.read_text())
        glyphs[name] = (box, inner)

    if missing:
        print("missing source files:", *missing, sep="\n  ")
        return 1

    out = pathlib.Path(__file__).resolve().parent.parent / "app" / "logodata.py"
    lines = ['"""Vendor marks and line icons, inlined.',
             "",
             "GENERATED by scripts/build_logos.py — do not edit by hand.",
             "Devicon (MIT), Simple Icons (CC0) and Lucide (ISC); see",
             "static/ICONS.LICENSE.txt for the notices these carry.",
             '"""',
             "",
             "# vendor marks: their own colours, never restyled at render time",
             "BRANDS = {"]
    for slug, (box, inner) in sorted(brands.items()):
        lines.append(f"    {slug!r}: ({box!r},")
        lines.append(f"        {inner!r}),")
    lines += ["}", "",
              "# line icons: stroked in currentColor, so they take the page's ink",
              "GLYPHS = {"]
    for name, (box, inner) in sorted(glyphs.items()):
        lines.append(f"    {name!r}: ({box!r},")
        lines.append(f"        {inner!r}),")
    lines += ["}", ""]
    out.write_text("\n".join(lines))
    print(f"wrote {out.relative_to(out.parent.parent)} — "
          f"{len(brands)} marks, {len(glyphs)} glyphs, "
          f"{out.stat().st_size / 1024:.0f}KB")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
