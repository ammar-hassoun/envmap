#!/usr/bin/env python3
"""A closed dialog must be invisible, and a name must belong to one thing.

WHY THIS EXISTS
    A `<dialog>` is hidden by the browser's own `dialog:not([open]) { display:
    none }`. That rule is in the user-agent stylesheet, so ANY author rule
    setting `display` on a selector that also matches the dialog beats it — and
    the dialog then renders inline, in the middle of the page, before anyone
    has opened it.

    That shipped. A new terminal was given `class="term"`, and `.term` was
    already the kubectl console on the Shell tab with `display:flex` on it. The
    modal appeared on the cluster page immediately on load, mid-layout, with no
    backdrop. The same mistake had already happened once with an id: a
    namespace picker was mounted on `#nspick`, which the Shell tab had taken
    first, so `getElementById` returned a `<select>` and the picker's markup was
    injected into it.

    Both are the same fault — a name reused for a second thing — and neither is
    visible by reading either file on its own. So this checks the templates as
    a set.

    THE `hidden` ATTRIBUTE IS THE SAME TRAP with a different built-in rule.
    `[hidden] { display: none }` also lives in the user-agent stylesheet, so a
    class with `display:grid` on it makes every `hidden` on that element inert.
    That shipped too: the service page's two sides both rendered their kinds at
    once, one strip under the other, because `.kgrid` was `display:grid` and the
    script was setting `.hidden = true` on something CSS had already decided was
    a grid. Nothing errors, and the JavaScript is correct — it is the stylesheet
    that ignores it.

    ./.venv/bin/python tests/test_dialogs.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "templates"

bad = 0


def css_only(text: str) -> str:
    """A stylesheet with its comments taken out.

    Every check in this file that looks for a RULE has to read it this way: the
    comment recording why a rule exists quotes the rule, so a check reading the
    raw file finds its own explanation and passes. That has happened repeatedly
    across this suite, in prose and in CSS both.
    """
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def css_rules() -> list:
    """(selector, declarations) for every rule in every <style> block."""
    out = []
    for path in sorted(TPL.glob("*.html")):
        for block in re.findall(r"<style>(.*?)</style>", path.read_text(), re.S):
            # comments first, or a selector inside one counts as a rule
            block = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
            for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", block):
                out.append((sel.strip(), body.strip(), path.name))
    return out


def main() -> int:
    dialogs = []          # (file, classes, id)
    for path in sorted(TPL.glob("*.html")):
        for tag in re.findall(r"<dialog\b[^>]*>", path.read_text()):
            cls = re.search(r'class="([^"]*)"', tag)
            ident = re.search(r'id="([^"]*)"', tag)
            dialogs.append((path.name, (cls.group(1).split() if cls else []),
                            ident.group(1) if ident else ""))
    print(f"{len(dialogs)} dialog(s) across the templates")
    check("there is at least one to check", bool(dialogs))

    rules = css_rules()

    print("no rule may force a closed dialog visible")
    for fname, classes, ident in dialogs:
        for cls in classes:
            for sel, body, where in rules:
                if "display" not in body:
                    continue
                # a BARE class selector matches the dialog too, and beats the
                # user-agent rule that hides it
                parts = [p.strip() for p in sel.split(",")]
                if f".{cls}" not in parts:
                    continue
                shown = re.search(r"display\s*:\s*([a-z-]+)", body)
                check(f"{fname}: <dialog class=\"{cls}\"> is forced "
                      f"display:{shown.group(1) if shown else '?'} by "
                      f"`{sel}` in {where}",
                      bool(shown) and shown.group(1) == "none")

    print("nor may a compound selector, which is how it happened the second time")
    # The check above only sees a BARE `.cls`, because that is the shape the
    # first occurrence had. The second was `dialog.psh.lgwin { display:flex }`
    # — added for a flex layout, aimed straight at the dialog, and invisible to
    # a test looking for a lone class. It left the log window drawn, unopened
    # and empty, in the page flow of every page that included it.
    #
    # So: any selector that can match the dialog itself and sets a display
    # other than `none` has to say [open] (or :modal), or it overrides the
    # user-agent rule that hides a closed one.
    for fname, classes, ident in dialogs:
        own = {f".{c}" for c in classes} | {"dialog"}
        if ident:
            own.add(f"#{ident}")
        for sel, body, where in rules:
            shown = re.search(r"display\s*:\s*([a-z-]+)", body)
            if not shown or shown.group(1) == "none":
                continue
            for part in (x.strip() for x in sel.split(",")):
                # A combinator means the rule is aimed at something inside the
                # dialog, not at the dialog.
                if re.search(r"[\s>+~]", re.sub(r"\[[^\]]*\]", "", part)):
                    continue
                guarded = "[open]" in part or ":modal" in part
                bare = re.sub(r"\[[^\]]*\]|:[a-z-]+(\([^)]*\))?", "", part)
                tokens = re.findall(r"(?:^|(?=[.#]))[^.#]+", bare)
                tokens = [t for t in tokens if t]
                if not tokens or not set(tokens) <= own:
                    continue          # cannot match this dialog
                check(f"{fname}: `{sel}` in {where} sets "
                      f"display:{shown.group(1)} on the dialog without [open] "
                      f"— a closed dialog would render in the page", guarded)

    print("a window pane that should scroll can actually shrink")
    # The describe window could not be scrolled: 173 lines of output, and the
    # bottom — the Events, which is the reason anybody runs describe — simply
    # unreachable. Two rules were missing and each is invisible on its own:
    #
    #   the dialog was not a flex COLUMN, so the pane's `flex:1` was inert and
    #   it took its full content height, which the dialog's own
    #   `overflow:hidden` then clipped;
    #
    #   and the pane had no `min-height:0`, so even inside a flex column it
    #   refuses to shrink below its content and `overflow:auto` never has
    #   anything to scroll.
    #
    # Sizing a pane with `height:calc(100% - …)` instead is equally valid — the
    # kubectl console does that — so this only holds windows that chose FLEX to
    # the rest of what flex needs.
    all_css = "\n".join(css_only(f.read_text())
                        for f in sorted((ROOT / "templates").glob("*.html")))
    windows = set()
    for f in sorted((ROOT / "templates").glob("*.html")):
        for m in re.finditer(r'class="psh\s+([a-z][\w-]*)"', f.read_text()):
            windows.add(m.group(1))
    check(f"the psh windows were found ({sorted(windows)})", len(windows) >= 2)
    for win in sorted(windows):
        # every rule scoped inside this window
        inside = re.findall(r"\.[\w-]*" + re.escape(win)
                            + r"[^{]*\{([^}]*)\}", all_css)
        if not any("flex:" in body for body in inside):
            continue                  # sized some other way; not this rule's business
        column = re.search(r"dialog\.psh\." + re.escape(win)
                           + r"\[open\][^{]*\{[^}]*display\s*:\s*flex", all_css)
        check(f".{win} uses flex, so the dialog must be a flex column when open",
              column is not None)
        check(f".{win}'s flex pane must be allowed to shrink (min-height:0)",
              any("flex:" in body and "min-height:0" in body.replace(" ", "")
                  for body in inside))

    print("the hidden attribute actually hides")
    # Same fault as the dialog above, for the other built-in rule, and it landed
    # three times: a closed dialog rendered mid-page (.term, display:flex), both
    # sides of the service page showed their kinds at once (.kgrid, display:grid),
    # and an empty coloured bar sat above the live-secret editor (.flash,
    # display:flex). Every one of them was found by somebody looking at the page.
    #
    # A per-class check cannot close it: the class is often assigned in
    # JavaScript, so there is nothing in the markup to pair with. One global rule
    # can, and asserting THAT is decisive where scanning for the symptom is not.
    # Comments stripped: see css_only. The comment recording WHY a rule exists
    # quotes the rule, so a check reading the raw file finds its own explanation
    # and passes.
    base = css_only((ROOT / "templates" / "base.html").read_text()
                    + (ROOT / "static" / "app.css").read_text())
    globals_hidden = re.findall(r"(?<![\w)\]])\[hidden\]\s*\{([^}]*)\}", base)
    check(f"base.html hides [hidden] globally ({globals_hidden})",
          any("display" in b and "none" in b for b in globals_hidden))
    # And it has to be able to win. Without !important an author rule on a class
    # outranks it, which is the whole bug.
    check("with !important, or an author display rule still beats it",
          any("!important" in b for b in globals_hidden))
    # Nothing may deliberately show something carrying the attribute — that would
    # be a contradiction the global rule now silently wins. `:not([hidden])` is
    # not one: it selects elements WITHOUT the attribute, hence the lookbehind.
    contradictions = []
    for f in sorted((ROOT / "templates").glob("*.html")):
        for m in re.finditer(r"(?<![)\]])\[hidden\][^{)]*\{([^}]*)\}",
                             css_only(f.read_text())):
            body = m.group(1)
            if "display" in body and "none" not in body:
                contradictions.append(f"{f.name}: {m.group(0)[:50]}")
    check(f"nothing asks for a hidden element to show ({contradictions})",
          not contradictions)

    print("a dialog's id and classes are not shared with anything else")
    everything = "\n".join(p.read_text() for p in sorted(TPL.glob("*.html")))
    for fname, classes, ident in dialogs:
        if ident:
            uses = len(re.findall(rf'id="{re.escape(ident)}"', everything))
            check(f"id \"{ident}\" is used once, not {uses} times", uses == 1)
        for cls in classes:
            # Whole tokens, not a \b match: "-" is a word boundary in regex, so
            # \bpsh\b happily matches inside "psh-body" and every prefixed
            # child class reads as a collision.
            others = [tag for tag, attr in
                      re.findall(r'<(?!dialog)([a-z]+)\b[^>]*class="([^"]*)"',
                                 everything)
                      if cls in attr.split()]
            check(f"class \"{cls}\" is not also on <{others[0]}>" if others
                  else f"class \"{cls}\" is the dialog's alone", not others)

    print("the theme button shows where it TAKES you, not where you are")
    # Reported: sign-in appeared dark, the page after it came up white, and the
    # theme had to be switched back. The cause was not the theme mechanism —
    # both shells set data-theme identically before the first paint, and both
    # stylesheets default to DARK on a bare :root, so a light page is only ever
    # an explicit choice. It was this button: on a dark page it showed a MOON,
    # which reads as a badge saying "dark mode is on", and clicking it went to
    # light. Confirming what you already have should not change it.
    shells = {f: (ROOT / "templates" / f).read_text()
              for f in ("base.html", "_auth_shell.html")}
    for name, src in shells.items():
        check(f"{name}: a dark page offers the SUN — the destination",
              "b.textContent = light ? '\\u263D' : '\\u263C';" in src)
        check(f"{name}: and the title agrees with the icon",
              "light ? 'Switch to the dark theme' : 'Switch to the light theme'"
              in src)

    print("and the two shells agree about the theme, so they cannot drift")
    # The sign-in pages and the signed-in pages carry their own copy of this —
    # a shell cannot import the other's <head>. Only the THEME lines are
    # compared: base.html also restores the collapsed sidebar, which a page
    # with no sidebar has no business doing, so the two are not meant to be
    # identical. The point of the check is the day somebody fixes one of them.
    def theme_boot(src):
        """The theme lines, or a marker. NOT an exception: a shell that has
        stopped following the OS is a FAILING CHECK, and a traceback here would
        read as a broken test rather than as the thing it caught — which is
        exactly what it did the first time this was bitten."""
        i = src.find("var saved = localStorage.getItem('portal-theme')")
        end = "setAttribute('data-theme', saved || os);"
        j = src.find(end, i) if i >= 0 else -1
        if i < 0 or j < 0:
            return "MISSING"
        return " ".join(src[i:j + len(end)].split())
    boot = {n: theme_boot(s2) for n, s2 in shells.items()}
    check(f"the theme bootstrap is the same in both "
          f"({len(set(boot.values()))} variant)", len(set(boot.values())) == 1)
    check("both default to the OS rather than to a hardcoded theme",
          all("saved || os" in b2 for b2 in boot.values()))
    # A bare :root that is LIGHT would make every page light until the script
    # ran, which is the flash this ordering exists to prevent.
    css = (ROOT / "static" / "app.css").read_text()
    check("app.css keys DARK on a bare :root and light on the attribute",
          "color-scheme: dark;" in css.split(":root[data-theme")[0]
          and ':root[data-theme="light"]' in css)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
