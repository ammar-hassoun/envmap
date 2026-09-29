#!/usr/bin/env python3
"""Vendor marks: that every registered service has one, and that serving them
did not quietly open a door.

WHY THIS EXISTS
    Two failures, both silent.

    The first is a service whose mark is simply never drawn. Every integration
    module keeps its own PROVIDERS table, and app/logos.py keeps the map from
    those ids to artwork. Add a provider to one and not the other and the page
    still renders, still lists the service, and shows a lettermark for ever —
    there is no error, no log line, and nothing looks broken enough to chase.
    So the two are compared here instead.

    The second is worse and actually happened. The sprite was first served from
    /assets/logos.svg, which meant adding "/assets" to rbac.ALWAYS so it could
    be fetched before sign-in. "/assets" is also the Server assets area's own
    prefix, so area_for_path started answering None for the entire hardware and
    VM inventory and every signed-in account could read it regardless of role.
    A static file must never share a prefix with a governed page, and that is
    checked below against the real area table rather than the one path that
    caused it.

    ./.venv/bin/python tests/test_logos.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("logos-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import logos, rbac                                    # noqa: E402
from app.logodata import BRANDS, GLYPHS                        # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def providers() -> dict:
    """Every provider id the integration modules register, read from their own
    PROVIDERS tables rather than listed here a second time."""
    found = {}
    for mod in ("gitops", "ci", "security", "monitoring", "workflows", "virt",
                "vpn", "edge", "bmc", "logstore", "cloud", "dbconn", "stordev"):
        src = (ROOT / "app" / f"{mod}.py").read_text()
        for key in re.findall(r'^\s{4}"([a-z0-9_]+)"\s*:\s*\{', src, re.M):
            found.setdefault(key, mod)
    return found


def main() -> int:
    print("every registered provider is accounted for")
    for key, mod in sorted(providers().items()):
        # Either it has a mark, or it is written down as having none. What must
        # not happen is a provider nobody decided about.
        decided = key in logos.FOR_PROVIDER or key in logos.NO_MARK
        check(f"{key} (app/{mod}.py) has a mark or is listed in NO_MARK",
              decided)
    for key, slug in sorted(logos.FOR_PROVIDER.items()):
        check(f"{key} points at artwork that exists ({slug})", slug in BRANDS)
    # Both halves, so NO_MARK cannot be used to silence a provider that does in
    # fact have artwork sitting unused in the sprite.
    for key in sorted(logos.NO_MARK):
        check(f"{key} is in NO_MARK and nowhere else",
              key not in logos.FOR_PROVIDER)

    print("the sprite is reachable without opening a governed page")
    path = logos.SPRITE.split("?")[0]
    check(f"{path} is governed by no area",
          rbac.area_for_path(path) is None)
    # The actual regression: an ungoverned prefix that swallows a real page.
    for area, (_label, _note, prefixes) in rbac.AREAS.items():
        for prefix in prefixes:
            if prefix == "/":
                continue
            check(f"{prefix} ({area}) is still governed — no ALWAYS entry "
                  f"swallows it", rbac.area_for_path(prefix) is not None)
    check("and Server assets in particular, which is how this was found",
          rbac.area_for_path("/assets") == "assets")

    print("marks are versioned, so an upgrade is not a day of stale logos")
    check("the sprite url carries a cache key", "?v=" in logos.SPRITE)
    check("the sprite holds a symbol per mark",
          logos.sprite().count("<symbol ") == len(BRANDS))

    print("nothing renders as a blank square")
    # A mark whose body is empty is the failure the eye cannot catch on a page
    # of forty logos, and it is exactly what dropping the root <svg>'s fill
    # produced for Couchbase.
    for slug, (box, inner) in sorted(BRANDS.items()):
        check(f"{slug} has geometry", "<path" in inner or "<circle" in inner)
        # Geometry alone is not enough. Couchbase's mark is one path with no
        # fill of its own and the colour on the root <svg>, which the extractor
        # used to throw away — leaving a correct shape painted in the default
        # black, invisible on this surface and indistinguishable from a mark
        # that failed to load.
        check(f"{slug} says what colour it is",
              'fill="' in inner or "stop-color" in inner)
        check(f"{slug} has a viewBox", bool(re.match(r"[\d.\- ]+$", box)))
        # Devicon namespaces its clip paths per file; two marks sharing an id
        # in one sprite document is a logo that renders empty on whichever
        # page happens to show both.
        for ident in re.findall(r'\bid="([^"]+)"', inner):
            check(f"{slug}'s id {ident} is namespaced to it",
                  ident.startswith(slug))
    for name, (_box, inner) in sorted(GLYPHS.items()):
        check(f"glyph {name} takes the page's ink",
              "currentColor" in inner or "stroke=" not in inner)

    print("an unknown service still gets something to look at")
    mark = str(logos.logo("something-we-never-heard-of", "Nessie"))
    check("it falls back to a lettermark rather than an empty box",
          "lm" in mark and ">N<" in mark)
    check("and the fallback is stable for the same name",
          mark == str(logos.logo("something-we-never-heard-of", "Nessie")))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
