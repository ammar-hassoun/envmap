#!/usr/bin/env python3
"""Every var() a template uses must be declared somewhere.

WHY THIS EXISTS
    An undeclared custom property does not fail loudly. `color: var(--ink3)` with
    no such property is an invalid declaration, so the browser drops it and the
    element quietly inherits its parent's colour. The page looks almost right,
    which is why five of these survived in this codebase for months:

        --warn-line     used in base.html and four other pages, declared nowhere
        --danger-line   the border on every "why it stopped" card
        --danger-wash   --accent-wash   --sans

    and three more that arrived with the Temporal pages, where --ink, --ink2 and
    --ink3 were invented for text colours the palette already had as --text,
    --text2 and --muted. Every "muted" rule on those pages was inert.

    Both themes are checked, because a property declared only in the dark :root
    leaves the light theme falling back to nothing — the same silent failure,
    visible to half the users.

    ./.venv/bin/python tests/test_css_vars.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "templates"
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def declared_in(text: str) -> set[str]:
    return set(re.findall(r"(--[a-z0-9-]+)\s*:", text))


def used_in(text: str) -> set[str]:
    return set(re.findall(r"var\((--[a-z0-9-]+)", text))


def block(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.S)
    return m.group(1) if m else ""


def main() -> int:
    # The palette moved to static/app.css when the stylesheet stopped riding
    # inline on every page. base.html keeps only what must stay inline.
    base = (TPL / "base.html").read_text()
    css = (ROOT / "static" / "app.css").read_text()
    global_names = declared_in(css) | declared_in(base)
    check("the stylesheet declares a palette at all", len(global_names) > 20)

    print("nothing uses a property that is declared nowhere")
    offenders: dict[str, list[str]] = {}
    for f in sorted(TPL.rglob("*.html")):
        text = f.read_text()
        # a page may declare its own locals — the sign-in shell does — and so
        # may a stylesheet the page LINKS. A page-specific file in static/ is a
        # real declaration site, not a gap in this check, and the first one
        # (the Grafana dashboard's) was reported here as undeclared.
        local = declared_in(text)
        for sheet in re.findall(r'href="/static/([\w.-]+\.css)', text):
            path = ROOT / "static" / sheet
            if path.exists():
                local |= declared_in(path.read_text())
        for name in used_in(text):
            if name not in global_names and name not in local:
                offenders.setdefault(name, []).append(f.name)
    for name, where in sorted(offenders.items()):
        check(f"{name} is used in {', '.join(where[:4])} and declared nowhere",
              False)
    check("no undeclared properties at all", not offenders)

    print("nothing is declared only for the light theme")
    dark = declared_in(block(css, r":root \{(.*?)\n    \}"))
    light = declared_in(block(css, r':root\[data-theme="light"\] \{(.*?)\n    \}'))
    check("the dark root was found", len(dark) > 20)
    check("the light root was found", len(light) > 20)
    # Only one direction is a bug, and it is not the obvious one. `:root` applies
    # to BOTH themes and the light block is an override layer, so a property in
    # dark and not light simply is not overridden — which is right for --mono and
    # --radius, and deliberate for the on-colour inks.
    #
    # The reverse is the silent failure: declared only under
    # :root[data-theme="light"], it resolves to nothing in the dark theme, which
    # is the default. That is what this asserts.
    for name in sorted(light - dark):
        check(f"{name} is declared only for light, so dark resolves it to nothing",
              False)

    print("the invented names are gone and stay gone")
    # These were used for text colours the palette already had. Named here so a
    # future page reaching for them fails in a test rather than on screen.
    for wrong, right in (("--ink", "--text"), ("--ink2", "--text2"),
                         ("--ink3", "--muted"), ("--surface", "--panel"),
                         ("--accent-on", "--ink-on-accent")):
        hits = [f.name for f in TPL.rglob("*.html")
                if f"var({wrong})" in f.read_text()]
        check(f"{wrong} is used in {hits} — the palette calls it {right}",
              not hits)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
