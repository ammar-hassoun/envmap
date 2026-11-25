"""Which mark stands for which service, and how one gets onto a page.

WHY A SPRITE AND NOT INLINE SVG
    Inlining looked obvious until it was measured. The Jenkins butler is 15KB
    of path data, Postgres 8.9KB, the Kubernetes helm 8.7KB — so a Pipelines
    page listing eight Jenkins servers would have carried the same butler eight
    times, 120KB of identical markup, on every load. The marks are therefore
    served once from /icons/logos.svg and referenced; the browser fetches that
    file on the first page of a session and never again.

    Built from logodata.py at request time rather than kept as a file in
    static/, because a second copy on disk is a second thing to forget to
    rebuild — and the symptom of forgetting is a blank square, which reads as a
    broken page rather than a stale asset.

WHY SOME SERVICES HAVE NO MARK, AND WHAT THEY GET INSTEAD
    Zabbix, Wazuh, DefectDojo, Dependency-Track, Pritunl, Netmaker, NS1, Bunny
    and Redfish publish no mark either pack carries, and Amazon has withdrawn
    its own from Simple Icons. Rather than draw approximations — which is the
    thing that made the emoji look cheap in the first place — those get a
    lettermark: the initial on a tile tinted from a hash of the name, so it is
    stable per service and distinguishable at a glance. It reads as a deliberate
    placeholder rather than a missing image.

    A customer can also register a provider we have never heard of. That path
    goes through the same lettermark, so an unknown service is never a broken
    square.

TRADEMARKS
    Every mark here belongs to somebody else and identifies their product in a
    list of integrations, which is what nominative use is for. Nothing is
    recoloured, restyled or stretched at render time; the marks never appear in
    the brand slot a customer white-labels; and none of it implies those
    companies endorse this product.
"""
from __future__ import annotations

import functools
import hashlib

from markupsafe import Markup, escape

from . import env
from .logodata import BRANDS, GLYPHS

# The sprite is cached hard, so the URL has to change when the marks do. Keyed
# on the running version because that is the only thing that can change them:
# they are built into the image. Without it an upgrade that fixes a wrong logo
# leaves every customer looking at the old one until their cache expires, which
# is a day of "you said you fixed it".
SPRITE = f"/icons/logos.svg?v={env.VERSION}"

# What each registered provider is a mark for. Keys are the provider ids the
# integration modules already use, so adding a provider means adding a line
# here — and tests/test_logos.py fails if one is added without it.
FOR_PROVIDER = {
    # gitops
    "argocd": "argocd", "flux": "flux",
    # ci
    "jenkins": "jenkins", "github": "github", "bitbucket": "bitbucket",
    "gitlab": "gitlab",
    # security scanners
    "sonarqube": "sonarqube",
    # monitoring. Alertmanager is part of the Prometheus project and ships no
    # separate mark of its own, so it wears the project's.
    "prometheus": "prometheus", "alertmanager": "prometheus",
    "grafana": "grafana",
    # workflow engines
    "temporal": "temporal", "airflow": "airflow",
    # hypervisors
    "proxmox": "proxmox", "vsphere": "vsphere",
    # vpn
    "openvpn_as": "openvpn_as", "wg_easy": "wg_easy",
    # edge
    "cloudflare": "cloudflare", "fastly": "fastly",
    # log stores. Loki is a Grafana Labs product and is shown as one.
    "elasticsearch": "elasticsearch", "loki": "grafana",
    "opensearch": "opensearch",
    # clouds
    "aws": "aws", "azure": "azure", "alibaba": "alibaba", "gcp": "gcp",
    # databases
    "postgres": "postgres", "mysql": "mysql", "couchbase": "couchbase",
    # storage. An S3 bucket is an AWS service even when the appliance is not.
    "synology": "synology", "truenas": "truenas", "minio": "minio",
    "s3": "aws",
    # things the portal itself is made of
    "kubernetes": "kubernetes", "helm": "helm", "docker": "docker",
    "git": "git", "vault": "vault", "nginx": "nginx",
    "letsencrypt": "letsencrypt",
}

# Providers we deliberately have no mark for. Listed rather than left to fall
# through, so the difference between "no art exists" and "somebody forgot" is
# written down — tests/test_logos.py holds both halves to it.
NO_MARK = {
    "zabbix", "wazuh", "defectdojo", "dependencytrack",   # publish none
    "pritunl", "netmaker",                                # publish none
    "bunny", "ns1", "redfish",                            # publish none
    "other", "nfs", "smb", "http",                        # not vendors at all
}

# Tints for the lettermark, stepped around the wheel at a lightness that sits
# on the dark surface without competing with a real mark beside it.
_TINTS = ("#4f7bd4", "#3f9e86", "#b5763c", "#9b6cc4", "#c4636b",
          "#3d8fb0", "#8a8f3f", "#a85f9a")


def known(name: str) -> bool:
    return name in FOR_PROVIDER and FOR_PROVIDER[name] in BRANDS


@functools.cache
def sprite() -> str:
    """Every mark as one <symbol> document, served from /icons/logos.svg.

    Cached: it is built from logodata.py, which is baked into the image, so it
    cannot change while the process lives. Rejoining 90KB of path data on every
    request bought nothing.
    """
    out = ['<svg xmlns="http://www.w3.org/2000/svg" '
           'xmlns:xlink="http://www.w3.org/1999/xlink">']
    for slug, (box, inner) in BRANDS.items():
        out.append(f'<symbol id="lg-{slug}" viewBox="{box}">{inner}</symbol>')
    out.append("</svg>")
    return "".join(out)


def _lettermark(name: str, label: str, size: int) -> Markup:
    """The stand-in for a service with no published mark."""
    text = (label or name).strip() or "?"
    initial = text[0].upper()
    # Hashed rather than assigned, so a new service gets a stable colour with
    # nobody having to pick one, and the same service is the same colour on
    # every page.
    # usedforsecurity=False: this picks a COLOUR, and saying so stops every
    # scanner reporting a weak-hash finding that has nothing to defend
    digest = hashlib.sha1(name.encode(), usedforsecurity=False).digest()[0]
    tint = _TINTS[digest % len(_TINTS)]
    # EVERY OPERATOR-TYPED VALUE IS ESCAPED, because `Markup` is a promise
    # that this string is already safe and Jinja will not check it again.
    # `text` is a connection's own name, so a connection called
    # `" onmouseover="alert(document.domain)` closed the title attribute and
    # added a live event handler to most operational pages in the product --
    # and with no CSP anywhere here (SEC-8) it ran. The size and tint are
    # ours (an int and a fixed tuple); the name is not.
    return Markup(
        f'<span class="logo lm" style="--lm:{tint};width:{int(size)}px;'
        f'height:{int(size)}px;font-size:{max(10, int(size * 0.5))}px" '
        f'title="{escape(text)}" aria-hidden="true">{escape(initial)}</span>')


def logo(name: str, label: str = "", size: int = 20) -> Markup:
    """The mark for a service, or a lettermark when none exists."""
    slug = FOR_PROVIDER.get(name or "")
    if not slug or slug not in BRANDS:
        return _lettermark(name or "?", label, size)
    # Escaped for the same reason as the lettermark above: `label` and `name`
    # are operator text, and this one reached an `aria-label`.
    return Markup(
        f'<svg class="logo" width="{int(size)}" height="{int(size)}" '
        f'role="img" aria-label="{escape(label or name)}">'
        f'<use href="{SPRITE}#lg-{slug}"></use></svg>')


def plogo(provider: dict | None, size: int = 20) -> Markup:
    """The mark for a PROVIDERS entry.

    Templates hold the provider dict far more often than the id — a card is
    built from `conn.provider`, and the id is several frames away — so asking
    each site to dig one out was six different guesses at what the loop
    variable was called. `key` is stamped onto every entry by
    logos.register(), so this works the same everywhere.
    """
    p = provider or {}
    return logo(p.get("key", ""), p.get("label", ""), size)


def register(*modules) -> None:
    """Stamp each PROVIDERS entry with its own id.

    Done centrally at startup rather than written into thirteen tables, where
    it would be thirteen chances to add a provider and forget the line — and a
    missing key is not an error, just a lettermark where a logo should be.
    """
    for mod in modules:
        for key, entry in getattr(mod, "PROVIDERS", {}).items():
            entry["key"] = key


def glyph(name: str, size: int = 18, cls: str = "") -> Markup:
    """A line icon — stroked in currentColor, so it takes the page's ink."""
    got = GLYPHS.get(name)
    if not got:
        return Markup("")
    box, inner = got
    return Markup(
        f'<svg class="ic {cls}" width="{size}" height="{size}" '
        f'viewBox="{box}" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        f"{inner}</svg>")


# What store.add_project() falls back to when nobody picks anything. Projects
# created before there was a line icon all carry it, so it means "unset" far
# more often than it means "somebody chose a box".
DEFAULT_PROJECT_ICON = "📦"


def project_icon(icon: str = "", size: int = 26) -> Markup:
    """A project's own icon when somebody chose one, the line icon otherwise.

    The emoji field on the wizard is deliberately still there and still
    honoured: a team that marked its billing project with a banknote meant it,
    and replacing that with a uniform glyph would be taking away a decision
    rather than tidying one up. Only the untouched default is replaced.
    """
    icon = (icon or "").strip()
    if icon and icon != DEFAULT_PROJECT_ICON:
        return Markup(f'<span class="pico" style="font-size:{size}px;'
                      f'line-height:1">{escape(icon)}</span>')
    return glyph("package", size, "pico")
