#!/usr/bin/env python3
"""Every level and every tab of the clusters page renders.

WHY THIS EXISTS
    The page has three levels — a box per project, a box per environment, then
    one cluster in depth — and only the third has read anything from a cluster.
    So `data` is None on the first two, and code written while looking at the
    third forgets that. It shipped exactly that way: a line reading the
    troubleshooting pods out of `data` turned /clusters into an internal server
    error for every level above the one being worked on.

    Nothing here needs a cluster, which is the point: an unknown project and an
    unknown cluster id exercise the same "there is no data" path, and every tab
    is asked to render against it. A tab that assumes a part arrived fails here
    rather than in front of somebody.

    ./.venv/bin/python tests/test_clusterpage.py
"""
from __future__ import annotations

import inspect
import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("clusterpage-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cluster as clusterview                         # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def css_only(text: str) -> str:
    """A stylesheet without its comments — a comment quoting a rule otherwise
    satisfies a check looking for that rule."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _timer_callbacks(body: str) -> list:
    """The source of every function a setTimeout/setInterval in `body` runs.

    Two shapes are in use and both have to be understood, because reading only
    the first one is how this test failed a file that was correct: an inline
    `setTimeout(function () {…})`, and a named `setInterval(tick, 1000)` whose
    function is declared above the line that arms it.
    """
    out = []
    for arm in ("setTimeout(", "setInterval("):
        at = body.find(arm)
        while at > -1:
            rest = body[at + len(arm):]
            if rest.lstrip().startswith(("function", "(", "()")):
                out.append(rest[:1200])                       # inline callback
            else:
                named = rest.split(",")[0].strip()
                decl = body.find(f"function {named}(")
                if decl > -1:
                    out.append(body[decl:decl + 1200])
            at = body.find(arm, at + 1)
    return out


_CLIENT = None


def client():
    global _CLIENT
    if _CLIENT is None:
        from fastapi.testclient import TestClient
        from app import auth, db, main
        email, pw = "clusters@test.local", "Every-Level-Renders-42"
        uid = auth.create_user(email, "CI", pw, role="admin")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uid))
        _CLIENT = TestClient(main.app)
        _CLIENT.__enter__()
        _CLIENT.post("/login", data={"email": email, "password": pw},
                     follow_redirects=False)
        _CLIENT.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
    return _CLIENT


def get(path: str):
    """(status, body) — and a server-side exception is a failed check rather
    than the end of the run, so one broken tab does not hide the other eleven."""
    try:
        r = client().get(path, follow_redirects=False)
        return r.status_code, r.text
    except Exception as e:                                     # noqa: BLE001
        return 500, f"{type(e).__name__}: {e}"


def main() -> int:
    print("the three levels")
    for label, path in (
            ("the hub, with no project chosen", "/clusters"),
            ("a project that does not exist", "/clusters?project=nope"),
            ("a cluster that does not exist",
             "/clusters?project=nope&cluster=nope"),
            ("the refresh button on the hub", "/clusters?refresh=1")):
        code, body = get(path)
        check(f"{label} → HTTP {code}", code == 200)
        # A 500 renders as a bare error page; a working page has the sidebar.
        check(f"{label} rendered a page", code == 200 and "Clusters" in body)

    print("every tab, with nothing read from any cluster")
    # The tab list is read from the app rather than written out here, so a tab
    # added later is covered without anybody remembering to add it.
    for key, label, _icon in clusterview.TABS:
        code, _body = get(f"/clusters?project=nope&cluster=nope&tab={key}")
        check(f"tab {key} ({label}) → HTTP {code}", code == 200)
    code, _b = get("/clusters?project=nope&cluster=nope&tab=not-a-tab")
    check(f"and a tab name that does not exist → HTTP {code}", code == 200)

    print("the deeper views that hang off a pod")
    for extra in ("&inspect=shell&target=default/anything",
                  "&inspect=logs&target=default/anything",
                  "&inspect=describe&target=default/anything",
                  "&ns=default", "&q=nothing-like-this"):
        code, _b = get(f"/clusters?project=nope&cluster=nope&tab=pods{extra}")
        check(f"pods{extra} → HTTP {code}", code == 200)

    print("the two Troubleshoot buttons wear the same mark, and it is their own")
    # Two mistakes in one place, both found by looking at the rendered page:
    # the in-page button kept an emoji long after the tab strip dropped them, and
    # the top-bar one wore `activity` — the Overview tab's own icon — so the two
    # most-clicked things on the page had the same mark.
    base_src = ((ROOT / "templates" / "base.html").read_text()
                + (ROOT / "static" / "app.css").read_text())
    page_txt = (ROOT / "templates" / "clusters.html").read_text()
    quick = re.search(r'data-quick="ts".*?</button>', base_src, re.S)
    inpage = re.search(r'id="tsBtn".*?</button>', page_txt, re.S)
    check("both buttons exist", bool(quick) and bool(inpage))
    marks = set()
    for what, blob in (("top bar", quick), ("the page", inpage)):
        if not blob:
            continue
        body = re.sub(r"\{#.*?#\}", "", blob.group(0), flags=re.S)
        got = re.search(r"glyph\('([a-z0-9-]+)'", body)
        check(f"{what}'s button draws a line icon, not an emoji ({got and got.group(1)})",
              got is not None
              and not re.search(r"[\U0001F300-\U0001FAFF]", body))
        if got:
            marks.add(got.group(1))
    check(f"and both wear the same one ({marks})", len(marks) == 1)
    # A mark another control on this page already owns is a mark that says
    # nothing. The tab strip is where the collision happened.
    taken = {icon for _k, _l, icon in clusterview.TABS}
    check(f"which no tab has taken ({marks & taken})", not (marks & taken))

    print("an action column can run out of room without painting over its neighbour")
    # A fixed-layout table gives a cell exactly the width its header declared. A
    # row of five buttons needing more than that used to spill LEFT — the cell is
    # sticky and right-aligned, its opaque background is only as wide as its box —
    # so the buttons painted over the Owner cell and "ArgoCD" showed through
    # "logs". Two rules make that impossible: the row may wrap, and the CELL no
    # longer forbids wrapping.
    css = css_only((ROOT / "templates" / "base.html").read_text()
                   + (ROOT / "static" / "app.css").read_text())
    row = re.search(r"\.actrow\s*\{([^}]*)\}", css)
    check("the action row may wrap", row is not None
          and "flex-wrap:wrap" in row.group(1).replace(" ", ""))
    cell = re.search(r"td\.actcol,\s*th\.actcol\s*\{([^}]*)\}", css)
    check("and the cell does not forbid it", cell is not None
          and "white-space:nowrap" not in cell.group(1).replace(" ", ""))
    # ...but a label still must not break mid-word, so nowrap moved onto the
    # buttons themselves.
    check("while a button's own label still never breaks",
          re.search(r"td\.actcol[^{]*\.abtn[^{]*\{[^}]*white-space:\s*nowrap",
                    css) is not None)
    # And the widest set on the related page gets a column sized for it, so the
    # wrap is the fallback rather than the normal case.
    rel = (ROOT / "templates" / "cluster_related.html").read_text()
    widths = [int(w) for w in re.findall(r'class="actcol" style="width:(\d+)', rel)]
    widths += [int(w) for w in re.findall(r"width:\{\{\s*(\d+)", rel)]
    check(f"the widest action column is sized for five buttons ({widths})",
          widths and max(widths) >= 300)

    print("the confirm on an action button is actually on the page")
    # The regression this exists for: the macros moved into a partial and the
    # pages imported it — but `{% import %}` brings in the macros and NOT the
    # file's body, so the <script> defining confirmAct() was included by nobody.
    # An exception in an inline onclick does not cancel a submit, so every action
    # button would have posted silently without ever asking.
    code, body = get("/clusters?project=nope&cluster=nope&tab=pods")
    check(f"the cluster page renders → HTTP {code}", code == 200)
    src = (ROOT / "templates" / "clusters.html").read_text()
    check("the page calls the script macro, not just the field ones",
          "act_script()" in src)
    shared = (ROOT / "templates" / "_cluster_actions.html").read_text()
    check("and the script lives inside a macro, which cannot be half-imported",
          "macro act_script" in shared
          and shared.index("macro act_script") < shared.index("function confirmAct"))

    print("no markup is smuggled into an attribute")
    # act_button puts its label inside onclick="return confirmAct(this, '…')", so
    # an icon passed AS the label lands as raw SVG inside a double-quoted
    # attribute — and ends it at the SVG's first quote. The button is then broken
    # markup that still looks fine until somebody clicks it.
    page_src = (ROOT / "templates" / "clusters.html").read_text()
    for m in re.finditer(r'onclick="([^"]*)"', re.sub(r"\{#.*?#\}", "", page_src,
                                                     flags=re.S)):
        check(f"no markup inside onclick ({m.group(1)[:48]})", "<" not in m.group(1))
    check("an icon-only action is asked for as an icon, not as a label",
          "icon='trash-2'" in page_src or 'icon="trash-2"' in page_src)

    print("the node strip is one aligned row per machine")
    # It was a card per node with three 56px rings in it. Five nodes wrapped to
    # three and two and left a third of the strip empty; every reading sat in a
    # different place, so comparing two nodes meant hunting for the number
    # rather than running an eye down a column; and ten nodes filled the screen
    # before the tabs. Measured after the change: 223px for five nodes against
    # roughly 430, every column on one x.
    page = (ROOT / "templates" / "clusters.html").read_text()
    base = ((ROOT / "templates" / "base.html").read_text()
            + (ROOT / "static" / "app.css").read_text())
    check("a node is a row, not a card",
          'class="ns-row' in page and "ns-card" not in page
          and "ns-card" not in base)
    check("and the meters are bars, not rings",
          'class="ns-bar"' in page and "<circle" not in page)
    # Each row is its own grid, and grid columns only align inside ONE
    # container — so a content-sized column resolves to that row's own text and
    # the strip goes ragged. Every column has to be fixed or fr.
    cols = re.search(r"\.ns-row\s*\{[^}]*grid-template-columns:([^;]+);",
                     base, re.S)
    check("the row has a column template", cols is not None)
    if cols:
        spec = " ".join(cols.group(1).split())
        check(f"no content-sized column, or the rows will not line up ({spec})",
              not re.search(r"(^|[\s,(])auto([\s,)]|$)", spec))
    # The percentage is not decoration: the colour ramp's own note records that
    # light mode's yellow and orange are the same colour under deuteranopia,
    # and the number is the documented relief.
    check("every meter still prints its number", "ns-pct" in page)
    check("and an unmeasured one is not coloured as if it were zero",
          "ns-ring.none" in base)

    print("an environment's services are one list, not two grids of tiles")
    # Each tile had a rainbow gradient behind two initials — hashed from the
    # filename, so it carried no information and thirteen services meant
    # thirteen saturated squares competing with the only thing that means
    # anything. The sealed count was a 🔒 emoji, drawn by whichever font the
    # reader's machine has: the same fault the vendor marks replaced everywhere
    # else on this product.
    # Comments stripped: the note recording WHY the emoji went away contains
    # the emoji, and a check reading the raw file fails on its own explanation.
    # That has now happened four times in this suite — prose about a fix keeps
    # standing in for the fix — so the rule is that every check on what a READER
    # sees reads the template without its comments.
    shown = re.sub(r"\{#.*?#\}", "", page, flags=re.S)
    check("no hashed gradient behind a service",
          "hue(sv.fname)" not in shown and 'class="ptile"' not in shown)
    check("and no emoji standing in for an icon", "🔒" not in shown)
    # The general form of that, over the whole page. Every icon on it is a line
    # icon from logodata for one reason: an emoji is drawn by whichever font the
    # reader's machine has, at whatever weight, and the tab strip was the most
    # visibly inconsistent thing in the product because of it. The Troubleshoot
    # button kept a 🧰 long after the strip stopped.
    #
    # Scoped to the pictographic block: ✕ – + ↻ ⚠ ✓ → are text glyphs in other
    # ranges, and they are used deliberately as text.
    import unicodedata
    pictos = sorted({ch for ch in shown if 0x1F300 <= ord(ch) <= 0x1FAFF})
    check("no pictographic emoji anywhere on the cluster page ("
          + ", ".join(f"{c} {unicodedata.name(c, '?')}" for c in pictos) + ")",
          not pictos)
    check("a service is a row", 'class="svcrow"' in page
          and 'class="svclist"' in page)
    # The two headings asked the reader to already know which half a service is
    # in before they could find it.
    for gone in ("Providers &amp; focused services",
                 "Platform &amp; shared services"):
        check(f"the categories are gone: {gone.split('&')[0].strip()!r}",
              gone not in shown)
    # The filename is what tells two same-named services apart — the two
    # bo-frontends in this estate — so it is on every row, not only the
    # colliding ones. A column that appears on some rows cannot be read down.
    check("every row carries its filename",
          "{{ sv.fname }}" in shown and "sv.ambiguous" not in shown)
    cols = re.search(r"\.svcrow\s*\{[^}]*grid-template-columns:([^;]+);",
                     base, re.S)
    check("the row has a column template", cols is not None)
    if cols:
        spec = " ".join(cols.group(1).split())
        check(f"and no content-sized column, so the rows line up ({spec})",
              not re.search(r"(^|[\s,(])auto([\s,)]|$)", spec))

    print("every wide table keeps its actions reachable")
    # Nine columns is wider than a laptop window, and an action you have to
    # scroll sideways to reach is an action nobody uses. The Pods table pinned
    # its action column; the Nodes table did not, so Cordon and Drain were off
    # the right edge. Measured after: the table overflows by 191px at 1500px
    # wide and the action cell does not move when it is scrolled.
    #
    # Checked as a rule over every table that HAS an action column, so the next
    # one is covered without anybody remembering.
    for m in re.finditer(r"<table class=\"jenkins\">(.*?)</table>", shown, re.S):
        body = m.group(1)
        head = re.search(r"<th[^>]*>(?:Manage|Actions)</th>", body)
        if not head:
            continue
        label = head.group(0)
        check(f"the {label[label.index('>') + 1:-5]} header is pinned",
              "actcol" in label)
    # and the cells under them
    manage_cells = re.findall(r'<td class="([^"]*)"[^>]*>\s*(?:<div class="actrow"|'
                              r'<form)', shown)
    check(f"the action cells are pinned too ({manage_cells})",
          manage_cells and all("actcol" in c for c in manage_cells))

    print("a node can be described without leaving the page")
    check("the nodes table has a describe button",
          "describe_attrs(pid, cid, '', n.name, 'node')" in shown)
    # A node is cluster-scoped: an empty namespace has to survive all the way to
    # kubectl, which appends `-n` only when there is one.
    from app import cluster as _cv2
    import inspect as _in
    src = _in.getsource(_cv2.describe)
    check("describe omits -n when there is no namespace",
          'if namespace else []' in src)

    print("a capacity meter reads as two things, not one word")
    # `.metric` and `.mrow` had no rules at all, so the label and the percentage
    # ran together: the Nodes table read "4 cores9%".
    mrow = re.search(r"\.mrow\s*\{([^}]*)\}", css_only(base))
    check("the meter row is a row", mrow is not None
          and "flex" in mrow.group(1))
    check("with the label and the number at opposite ends",
          mrow is not None and "space-between" in mrow.group(1))

    print("the slowest cluster read is not on the fastest clock")
    from app import cluster as _cv
    check(f"node disk has a lifetime of its own "
          f"({_cv.PART_TTL.get('nodedisk')}s vs the {_cv.TTL}s default)",
          _cv.PART_TTL.get("nodedisk", 0) >= 300)
    # ...and it has to be REACHABLE. PART_TTL is keyed on the part name, and the
    # disk part carries the node list — so keyed on the whole string it missed
    # the table entirely and silently took the 20s default, which is the
    # opposite of the point.
    src = inspect.getsource(_cv._cached)
    check("the lifetime is looked up by family, before the colon",
          'split(":", 1)[0]' in src)

    print("a page that never finishes collecting must stop reloading")
    # The bug: bits.collecting() reloaded every four seconds for as long as
    # anything was pending, on the reasoning that it "stops the instant the page
    # is complete". A cluster the portal cannot reach is NEVER complete — its
    # parts stay pending — so an estate with one unreachable cluster reloaded
    # its page every few seconds indefinitely. Measured on a live install at
    # 6.0s intervals, and it destroyed the kubectl console and the log window
    # every time, because a reload is a navigation and both come back empty.
    bits = (ROOT / "templates" / "_bits.html").read_text()
    macro = bits[bits.index("macro collecting"):]
    macro = macro[:macro.index("endmacro")]
    check("the reload is bounded by a try count",
          "TRIES" in macro and "sessionStorage" in macro)
    # An unconditional reload is the shape of the bug: a setTimeout whose only
    # guard is that something is pending.
    reloads = macro.count("location.reload")
    check(f"there is exactly one reload path ({reloads})", reloads == 1)
    check("and it stops rather than reloading for ever",
          "return" in macro and ">= TRIES" in macro)
    check("the reader is told why it stopped",
          "unreachable" in macro.lower() and "Refresh" in macro)

    print("nothing on a timer may reload over something open")
    # One reload is enough to lose a terminal somebody is typing in, so the cap
    # alone was not the whole fix: the troubleshooting flow lands on the pods tab
    # with a pod shell open, and that page was still collecting.
    #
    # And collecting() was not the only timer. env.html reloaded every 30s while
    # including the live log window; home.html and certs.html do the same. The
    # question "is it safe to reload right now" therefore belongs in one place
    # rather than being answered four times — base.html owns it, and this holds
    # every timer to asking it.
    base = (ROOT / "templates" / "base.html").read_text()
    guard = base[base.index("portalSafeToReload = function"):][:900]
    check("base.html refuses while any dialog is open",
          "dialog[open]" in guard)
    check("...while panels are being dragged", "arranging" in guard)
    check("...and while the assistant is mid-answer",
          "portalAssistantBusy" in guard)

    for name in ("_bits.html", "env.html", "home.html", "certs.html"):
        body = (ROOT / "templates" / name).read_text()
        if "location.reload" not in body:
            continue
        asks = body.count("portalSafeToReload")
        check(f"{name} asks the shared guard ({asks}×)", asks >= 1)
        # WHERE the guard sits is the whole fix, and getting it wrong looks
        # identical from a distance. The first attempt checked at SCHEDULE time —
        # but these scripts run while the document is still parsing and the
        # dialogs are opened further down the page, so nothing was open yet, the
        # timer was armed anyway, and seconds later it reloaded over a live
        # terminal. Exactly one reload, which is unmistakable to the person
        # typing into it. So: the guard has to be evaluated when the timer
        # FIRES, which means it sits with the reload inside the same callback.
        #
        # Asserted that way round rather than "the guard is textually after the
        # timer", which only holds for an inline callback and called env.html a
        # failure for arming a named function declared above it.
        for fired in _timer_callbacks(body):
            if "location.reload" not in fired:
                continue      # a countdown tick that only paints, not a reload
            check(f"{name}: the guard is in the same callback as the reload",
                  "portalSafeToReload" in fired
                  and fired.index("portalSafeToReload")
                  < fired.index("location.reload"))

    print("the troubleshoot shortcut cannot re-fire on a reload")
    # Same family: the flag arrived in the URL and stayed there, so a page that
    # reloaded underneath it started another troubleshooting pod each time.
    page = (ROOT / "templates" / "clusters.html").read_text()
    i = page.find("troubleshoot')")
    near = page[max(0, i - 400):i + 400]
    check("the flag is removed from the URL before the button is pressed",
          "replaceState" in near and "delete('troubleshoot')" in near)

    print("a settings action comes back to the page it was pressed on")
    # back() defaults to /settings, so a route that forgets `to=` throws the
    # reader out of the page they were working in and shows the result on the
    # hub. Pressing Test on a cluster did exactly that. Every sibling route
    # already passed it, which is why it read as a one-off rather than a rule —
    # so the rule is checked here against the live redirect, for all of them.
    from app import store as _store                            # noqa: E402
    pid = _store.add_project("Back")
    cid = _store.add_cluster(pid, "backc", "apiVersion: v1\n", "noctx")
    for path in (f"/settings/project/{pid}/cluster/{cid}/test",
                 f"/settings/project/{pid}/cluster/{cid}/delete"):
        r = client().post(path, follow_redirects=False)
        where = (r.headers.get("location") or "").split("?")[0]
        check(f"{path.rsplit('/', 1)[1]} returns to the clusters page "
              f"(got {where or r.status_code})",
              where == "/settings/clusters")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
