#!/usr/bin/env python3
"""The Overview's arrangement: what a saved panel remembers, and the catalogue.

WHAT IS EASY TO GET WRONG HERE
    A layout arrives from a browser, so every field is a suggestion:

      * an arrangement can never be emptied — that would be a blank landing page
        with no way back to the panels
      * a width off the grid snaps, because a drag handle produces those
      * a refresh interval is a menu choice, so an unlisted one is DROPPED rather
        than snapped to a neighbour: silently giving somebody 15s when they asked
        for 20 is worse than ignoring it

    And two things about the catalogue that only fail once somebody adds the
    panel, which may be months later:

      * every entry needs a template of the same name, or adding it raises
      * every `needs` key must be one the route can actually build, or the panel
        renders empty for a reason no message explains

    ./.venv/bin/python tests/test_panels.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("panels-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import layout as L                                     # noqa: E402

bad = 0
U = "user-1"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    print("a fresh person gets the default arrangement")
    check("which is not empty", len(L.get(U)) > 0)
    check("and is the DEFAULT list",
          [p["id"] for p in L.get(U)] == [p["id"] for p in L.DEFAULT])

    print("per-panel state survives a save and a read")
    L.save(U, [{"id": "alerts", "w": 6, "r": 15, "c": 1},
               {"id": "pipelines", "w": 4, "h": 3}])
    got = L.get(U)
    check(f"collapsed is kept, got {got}", got[0].get("c") == 1)
    check("so is the interval", got[0].get("r") == 15)
    check("and the fixed height", got[1].get("h") == 3)
    check("a panel with neither carries neither key",
          "c" not in got[1] and "r" not in got[1])
    check("order is preserved", [p["id"] for p in got] == ["alerts", "pipelines"])

    print("an interval not on the menu is dropped, not rounded")
    # 20 rather than 7: 7's nearest allowed value is 0, so dropping and snapping
    # are indistinguishable. 20's nearest is 15, so only this value can tell
    # "not on the menu" apart from "rounded to the menu".
    L.save(U, [{"id": "alerts", "w": 6, "r": 20}])
    check(f"20 is gone, not turned into 15, got {L.get(U)[0]}",
          "r" not in L.get(U)[0])
    L.save(U, [{"id": "alerts", "w": 6, "r": "nonsense"}])
    check("so is a non-number", "r" not in L.get(U)[0])
    for good in L.REFRESH:
        L.save(U, [{"id": "alerts", "w": 6, "r": good}])
        check(f"{good} is accepted", L.get(U)[0].get("r", 0) == (good or 0))

    print("a width off the grid snaps, because a drag handle produces those")
    for raw in (1, 5, 7, 11, 99):
        L.save(U, [{"id": "alerts", "w": raw}])
        check(f"{raw} snapped into the grid, got {L.get(U)[0]['w']}",
              L.get(U)[0]["w"] in L.WIDTHS)

    print("an arrangement can never be left blank")
    # Guarded twice on purpose — save() refuses to store an empty list and get()
    # falls back when it reads one — so removing either guard alone leaves this
    # passing. It asserts the outcome, which is the thing that matters: there is
    # no route to a blank landing page.
    L.save(U, [])
    check("it fell back to the default",
          [p["id"] for p in L.get(U)] == [p["id"] for p in L.DEFAULT])
    L.save(U, [{"id": "no-such-panel", "w": 6}])
    check("and an arrangement of only unknown panels does the same",
          [p["id"] for p in L.get(U)] == [p["id"] for p in L.DEFAULT])

    print("one measure, for every page")
    # 1040px was chosen when every page was a form or a paragraph. For a product
    # of cards, tables and meters it left about 800px of empty gutter on a 1900px
    # display. The Overview carried a `wide` opt-in while that was being judged;
    # keeping it would have meant the same block in forty templates, and a page
    # silently narrower than its neighbour whenever somebody forgot.
    import re
    base = ((ROOT / "templates" / "base.html").read_text()
            + (ROOT / "static" / "app.css").read_text())
    check("the content width is one named measure",
          "max-width:var(--measure)" in base)
    m = re.search(r":root \{ --measure:(\d+)px", base)
    check(f"and it is the wide one ({m.group(1) if m else '?'}px)",
          m is not None and int(m.group(1)) >= 1500)
    # Capped, not removed: past roughly 1600px a table row is a long walk from
    # the name to the action, and a paragraph stops being readable sooner.
    check(f"but still capped ({m.group(1) if m else '?'}px)",
          m is not None and int(m.group(1)) <= 1700)
    # No per-page opt-in left to forget, and none to go stale.
    for gone in ("content_width", "licbar_width", ".content.wide",
                 "--measure-wide"):
        check(f"no per-page width machinery left: {gone!r}", gone not in base)
    check("and no page asks for one",
          not any(gone in (ROOT / "templates" / f.name).read_text()
                  for f in (ROOT / "templates").glob("*.html")
                  for gone in ("content_width", "licbar_width")))

    print("a wide page does not make a wide text box")
    # The one thing the wider measure genuinely hurt: a plain text input came out
    # 932px across — a single-line field nearly a metre wide, no easier to type a
    # hostname into than a 560px one, with the label a long way from what it
    # labels. The VALUE COLUMN is capped rather than taking a share of the row.
    cols = re.search(r"\.field-row \{[^}]*grid-template-columns:([^;]+);",
                     base, re.S)
    check("the field row has a column template", cols is not None)
    if cols:
        spec = " ".join(cols.group(1).split())
        check(f"the value column is capped, not a share of the row ({spec})",
              "620px" in spec or re.search(r"minmax\([^)]*\d+px\)\s*$", spec))
    # ...and a textarea is exempt, because the cap is the grid track and a
    # kubeconfig is not a hostname. max-width on the element does nothing.
    check("a row holding a textarea opens back up",
          re.search(r"\.field-row:has\(textarea\)[^{]*\{[^}]*grid-template-columns",
                    base) is not None)

    print("two panels in one row end at the same place")
    # Pipelines carries a list of failing builds and Security does not, so side
    # by side they came out roughly 600px and 290px — a ragged edge with a void
    # beside the shorter one. `.board` already stretched the panel SLOTS; the
    # card inside kept its content height, because it sits in a `.pbody` wrapper
    # and the height was never passed through it.
    #
    # Measured after: both cards 470px, bottoms within 2px, headers unchanged at
    # 50px each — the slack went to the body rather than stretching a title bar.
    check("the board stretches its slots",
          re.search(r"\.board \{[^}]*align-items:stretch", base, re.S) is not None)
    chain = [
        (r"\.pbody \{[^}]*display:flex", "the wrapper is a column"),
        (r"\.panel > \.pbody \{[^}]*flex:1", "and takes the slot's height"),
        (r"\.panel > \.pbody > \.card \{[^}]*flex:1",
         "which it passes to the card"),
        (r"\.panel > \.pbody > \.card > \.card-b:last-child \{[^}]*flex:1",
         "and the card's BODY takes the slack, not its header"),
    ]
    for pattern, why in chain:
        check(why, re.search(pattern, base, re.S) is not None)

    print("no phantom grid tracks anywhere")
    # `auto-fill` keeps making EMPTY tracks once a row is wider than its items
    # need; `auto-fit` collapses them and lets the items take the room. At
    # 1040px the difference was usually invisible because the arithmetic came out
    # even. At 1560px it is not: four stat tiles came out at 199px each with
    # three phantom columns and 640px of dead space beside them.
    #
    # Every grid in the product, because the measure is now the same everywhere —
    # so a single auto-fill reintroduces the gap on whichever page holds it.
    offenders = []
    for f in sorted((ROOT / "templates").rglob("*.html")):
        body = re.sub(r"\{#.*?#\}", "", f.read_text(), flags=re.S)
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        if "auto-fill" in body:
            offenders.append(str(f.relative_to(ROOT / "templates")))
    check(f"nothing fits its tracks to the row instead of its items "
          f"({offenders})", not offenders)
    # And the cluster cards use the room for a second CLUSTER rather than
    # stretching one — nothing inside a cluster card reads better at 700px.
    clusters = (ROOT / "templates" / "panels" / "clusters.html").read_text()
    check("cluster cards are laid out as a grid of cards",
          'class="clustercards"' in clusters)
    check("...that collapses to one per row when narrow",
          re.search(r"\.clustercards[^{]*\{[^}]*auto-fit", base) is not None)

    print("unknown panels and duplicates are dropped, not trusted")
    L.save(U, [{"id": "alerts", "w": 6}, {"id": "made-up", "w": 6},
               {"id": "alerts", "w": 12}])
    check(f"one alerts, no made-up, got {L.get(U)}",
          [p["id"] for p in L.get(U)] == ["alerts"])
    check("and the first width won, not the duplicate's",
          L.get(U)[0]["w"] == 6)

    print("reset returns the default and forgets what was saved")
    L.save(U, [{"id": "logs", "w": 4}])
    check("reset gives the default back",
          [p["id"] for p in L.reset(U)] == [p["id"] for p in L.DEFAULT])
    check("and it stayed reset",
          [p["id"] for p in L.get(U)] == [p["id"] for p in L.DEFAULT])

    print("arrangements are per person")
    L.save(U, [{"id": "logs", "w": 4}])
    check("another user is unaffected",
          [p["id"] for p in L.get("user-2")] == [p["id"] for p in L.DEFAULT])

    print("every catalogue entry is complete and buildable")
    from app import main as M                                   # noqa: E402
    panels = ROOT / "templates" / "panels"
    for pid, meta in sorted(L.CATALOGUE.items()):
        check(f"{pid} has a template", (panels / f"{pid}.html").exists())
        for field in ("title", "icon", "w", "needs", "note"):
            check(f"{pid} declares {field}", field in meta)
        check(f"{pid}'s default width is on the grid", meta["w"] in L.WIDTHS)
        check(f"{pid}'s needs is a tuple", isinstance(meta["needs"], tuple))
        # The route must be able to answer every key a panel asks for. A panel
        # whose need nothing builds renders empty with no explanation.
        built = M._board_data(set(meta["needs"]))
        for key in meta["needs"]:
            check(f"{pid} needs {key!r}, which _board_data does not build",
                  key in built)

    print("the default arrangement only names panels that exist")
    for p in L.DEFAULT:
        check(f"{p['id']} is in the catalogue", p["id"] in L.CATALOGUE)
        check(f"{p['id']}'s width is on the grid", p["w"] in L.WIDTHS)

    print("available() offers what is not on the page, and nothing else")
    on = [{"id": "tiles", "w": 12}, {"id": "alerts", "w": 6}]
    spare = {x["id"] for x in L.available(on)}
    check("nothing already placed is offered", not spare & {"tiles", "alerts"})
    check(f"everything else is, got {len(spare)}",
          spare == set(L.CATALOGUE) - {"tiles", "alerts"})
    check("and each carries what the tray renders",
          all({"title", "icon", "note"} <= set(x) for x in L.available(on)))

    print("a panel degrades rather than taking the landing page down with it")
    # Every panel renders on what is REGISTERED and fills in from what
    # ANSWERED, so the two disagree for as long as something is unreachable —
    # which on a VPN estate is a normal Monday. The security panel reached for
    # platforms[0] to build its severity links and raised on the empty list,
    # and because this is the page /mfa redirects to, the whole of signing in
    # ended at a 500. Rendered here directly: the panel is included by the
    # Overview, so nothing else in the app has to be reachable to test it.
    from app import main as app_main                            # noqa: E402
    sec = {"conns": 2, "open": 100, "pending": 0, "stale": 0, "error": "",
           "broken": 2, "totals": {"critical": 3, "high": 4, "medium": 5,
                                   "low": 6, "info": 7},
           "platforms": []}          # registered, none of them answering
    try:
        out = app_main.templates.env.get_template(
            "panels/security.html").render(sec=sec)
        check("the security panel renders with no platform answering",
              len(out) > 400)
        # With nothing to filter by, the link has to go to the unfiltered page
        # rather than to `platform=`, which lands on "no such platform".
        check("and its severity links drop the platform filter",
              "/security?tab=findings" in out and "platform=&" not in out)
    except Exception as exc:                                   # noqa: BLE001
        check(f"the security panel must not raise ({exc})", False)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


# ── the fleet pods table: the two house rules it broke ────────────────────
# Both reported from the running portal, both standards this repo already
# writes down. Kept here rather than in a page test because they are template
# facts, and a template fact is cheap to assert and expensive to notice.
_FP = pathlib.Path(__file__).resolve().parent.parent / "templates" / "fleet_pods.html"
_fp = _FP.read_text()

check("the pods table's action row is `oneline` — this is an auto-layout "
      "table, so the column grows and the card scrolls; the wrapping default "
      "stacked logs/desc/shell into three rows and tripled every row's height",
      'class="actrow oneline"' in _fp)
check("and nothing re-declares a wrapping actrow on that page",
      'class="actrow"' not in _fp)

# ── the related-resources page: same rule, and the arithmetic behind it ────
# Reported from the running portal: on a Deployment the five buttons sat on two
# lines, and Service/Ingress put yaml and desc on separate lines. This is a
# table-layout:fixed table, where WRAPPING IS THE SAFE DEFAULT — a button that
# overflows a fixed cell paints over its neighbour — so `oneline` here is only
# correct together with a column wide enough to hold the set. Both halves are
# asserted, because either one alone is a bug.
_CR = pathlib.Path(__file__).resolve().parent.parent / "templates" / "cluster_related.html"
_cr = _CR.read_text()
check("every action row on the related page is oneline",
      'class="actrow"' not in _cr and _cr.count('class="actrow oneline"') == 3)
# The floor, from the CSS rather than from taste: .abtn is min-width 54px with
# 0 11px padding, .actrow's gap is 5px, a jenkins cell has 14px each side. Two
# plain buttons need 54+54+5+28 = 141; five with two wide labels need ~369.
_widths = [int(w) for w in re.findall(r'class="actcol" style="width:(\d+)px', _cr)]
_widths += [int(w) for w in re.findall(r'width:\{\{ (\d+)\s', _cr)]
_widths += [int(w) for w in re.findall(r'else (\d+) \}\}px', _cr)]
check(f"and no action column is narrower than two buttons need ({_widths})",
      _widths and min(_widths) >= 141)
check(f"the widest sets have room for five ({_widths})",
      len([w for w in _widths if w >= 342]) >= 2)
check("the cluster NAME links to the cluster, not to a describe window — "
      "following the name of a place should not hand you a document about one "
      "pod inside it; the row's own desc button does that",
      "&tab=pods\">" in _fp
      and "tab=pods&inspect=describe" not in _fp)
check("the row still offers describe, so the fix did not remove the feature",
      "&inspect=describe\"" in _fp)

# ── conventions that were documented but not enforced ─────────────────────
# CLAUDE.md has said "btn-ghost is not a button" for a long time and 22
# anchors had drifted anyway, because nothing checked. Measured in a browser
# against the real stylesheet: `<a class="btn-ghost">` came out with 0px
# radius, display:inline, font-weight 400 and 25px tall, next to the correct
# 9px / inline-flex / 600 / 30px. The reason only ANCHORS drifted is that
# app.css styles `button, .btn` — the element selector already covers a
# <button class="btn-ghost">, so the mistake is invisible until somebody uses
# an <a>.
import re as _re
_TPL = pathlib.Path(__file__).resolve().parent.parent / "templates"


def _bare_ghost_anchors(cls_name: str) -> list[str]:
    """Anchors carrying a colours-only class without `btn`.

    rglob, not glob: the first sweep used templates/*.html and missed
    dbtabs/table.html entirely. Jinja comments are stripped first — a `<form>`
    or a class named inside {# #} is documentation, not markup. The class
    attribute may be an EXPRESSION ({{ 'btn' if x else 'btn-ghost' }}), so the
    test looks for the word `btn` anywhere in it rather than for a literal
    prefix, and `\bbtn\b(?!-)` is what stops `btn-ghost` counting as `btn`.
    """
    out = []
    for f in sorted(_TPL.rglob("*.html")):
        plain = _re.sub(r"\{#.*?#\}", "", f.read_text(), flags=_re.S)
        for m in _re.finditer(r'<a [^>]*class="([^"]*' + cls_name + r'[^"]*)"',
                              plain):
            if _re.search(r"\bbtn\b(?!-)", m.group(1)):
                continue
            out.append(f"{f.relative_to(_TPL).as_posix()}:"
                       f"{plain[:m.start()].count(chr(10)) + 1}")
    return out


_ghosts = _bare_ghost_anchors("btn-ghost")
check(f"every ghost ANCHOR also carries `btn` ({', '.join(_ghosts) or 'none'})",
      not _ghosts)
_dangers = _bare_ghost_anchors("btn-danger")
check(f"and so does every danger anchor ({', '.join(_dangers) or 'none'})",
      not _dangers)

if __name__ == "__main__":
    sys.exit(1 if main() else 0)
