#!/usr/bin/env python3
"""A themed dropdown is as wide as the select it hides.

WHY THIS EXISTS
    Reported on /admin/audit, on Privileged Access (every project / every
    region / Apply, and the target catalogue's every environment / every
    protocol) and in Logs search: every dropdown in a filter row sat on a line
    of its own, and so did every date input. The same stacking was found in
    Monitoring, Server assets and the Instances tab of Infrastructure
    Provisioning.

    The themed dropdown wraps each <select> in `div.dd` and hides the select,
    and `.dd` was `width:100%` everywhere. That is right for a form field and
    wrong for a filter row, because every bar sizes its SELECT -- .placebar to
    185px, .pipefilters to 150px, .inv-bar to 168px, an inline width on many
    more -- and with the select hidden, none of those rules sized anything you
    could see. Five pages had already patched it for themselves by naming
    `.dd`; every row nobody patched stayed broken.

    THE FIX IS AT THE SOURCE. The wrapper reads the select's computed width
    once the select is inside it. That select is display:none, and for an
    element that is not rendered a browser answers with the DECLARED value --
    "100%", "auto", "168px" -- not a measurement. A percentage keeps the
    full-width form field; anything else is `.dd-fit`, sized from custom
    properties so that a page's own `.dd` rule still has the last word.

    Measured in a real browser before and after, at 1440px and 375px: the
    audit filter bar went from 8 lines to 2, the PAM catalogue's two dropdowns
    from stacked to side by side, Logs, Pipelines and the Instances bar to one
    line each, nothing overflowing sideways on a phone, and the rows a page
    had already tuned (Monitoring's rotation starter, Expiry, Timeline)
    unchanged to the pixel.

    The stub's getComputedStyle answers the way a browser does: the declared
    width only while the select is inside its wrapper, a measured pixel width
    before. So a width read BEFORE the move would turn every form field into a
    fit dropdown, and this file would fail. The cascade itself is CSS, held by
    reading base.html's rules.

    ./.venv/bin/python tests/test_ddfit_js.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ddfit-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


SETUP = r"""
const {El} = require(STUB);

// enhanceSelect writes its button as markup -- two spans -- and the stub keeps
// markup as a string. Build the two spans, or the label element is null before
// anything is sized and the test would be about the stub.
const make = document.createElement;
document.createElement = function (tag) {
  const el = make(tag);
  if (tag !== 'button') return el;
  Object.defineProperty(el, 'innerHTML', {
    get() { return this._html; },
    set(v) {
      this._html = v; this.children = [];
      for (const m of String(v).matchAll(/<span class="([^"]*)">([^<]*)<\/span>/g)) {
        const s = new El('span'); s.className = m[1]; s.textContent = m[2];
        this.appendChild(s);
      }
    }});
  return el;
};

// A BROWSER ANSWERS getComputedStyle TWO WAYS: the declared value for an
// element that is display:none, a measurement for one that is rendered.
// `.dd > select` is display:none, so the declared answer only exists once the
// select is INSIDE its wrapper; before the move it reads like any field.
global.getComputedStyle = function (el) {
  const hidden = !!(el.parentNode && el.parentNode.classList.contains('dd'));
  const d = el._declared || {};
  return {getPropertyValue: () => '',
          width: hidden ? d.width : '1124px',
          minWidth: hidden ? (d.minWidth || 'auto') : '0px',
          maxWidth: hidden ? (d.maxWidth || 'none') : 'none'};
};

function select(name, declared, inline, where) {
  const row = new El('div');
  (where || domRoot).appendChild(row);
  const s = new El('select');
  s.attributes.name = name;
  s._declared = declared;
  Object.assign(s.style, inline || {});
  const o = new El('option');
  o.value = ''; o.textContent = 'every ' + name;
  s.appendChild(o);
  s.selectedIndex = 0;
  row.appendChild(s);
  return s;
}
const S = {
  // .placebar select { width:auto; min-width:185px }
  bar: select('bar', {width: 'auto', minWidth: '185px'}),
  // .inv-bar select.inv-sel { width:168px }
  fixed: select('fixed', {width: '168px'}),
  // the rotation starter's playlist: min-width:0; max-width:340px, inline
  capped: select('capped', {width: 'auto', minWidth: '0px', maxWidth: '340px'},
                 {marginLeft: '10px'}),
  // the field rule's width:100%
  field: select('field', {width: '100%'}),
  fieldcap: select('fieldcap', {width: '100%', maxWidth: '320px'},
                   {maxWidth: '320px'}),
  flexed: select('flexed', {width: '100%'}, {flex: '1 1 170px'}),
  hidden: select('hidden', {width: 'auto'}),
};
S.hidden.hidden = true;
// Not in the document yet, as a cloned template is: a browser answers "" for
// every property of an element it has not styled.
const loose = new El('div');
const detached = select('detached', {width: ''}, null, loose);
"""

DRIVE = r"""
window.enhanceSelect(detached);

let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
const wrapOf = s => s.parentNode;
const fit = s => wrapOf(s).classList.contains('dd-fit');
const prop = (s, k) => wrapOf(s).style.getPropertyValue(k);

ok('the global sweep wrapped every select on the page',
   Object.values(S).every(s => wrapOf(s).classList.contains('dd')));

// THE REPORTED FAULT: a bar sizes its select, and the wrapper ignored it.
ok('a filter-row select whose width is auto is a fit dropdown', fit(S.bar));
ok('...carrying its width and its minimum (' + prop(S.bar, '--dd-w') + ', '
   + prop(S.bar, '--dd-min') + ')',
   prop(S.bar, '--dd-w') === 'auto' && prop(S.bar, '--dd-min') === '185px');
ok('a select sized in pixels keeps its pixels (' + prop(S.fixed, '--dd-w') + ')',
   fit(S.fixed) && prop(S.fixed, '--dd-w') === '168px');
ok('a fit select\'s own cap rides along (' + prop(S.capped, '--dd-max') + ')',
   fit(S.capped) && prop(S.capped, '--dd-max') === '340px');
ok('and no cap is invented where the select has none',
   prop(S.bar, '--dd-max') === '');

// FORM FIELDS ARE WHERE 100% IS RIGHT -- and this is the check that a width
// read before the move would fail, because there it measures as pixels.
ok('a form field stays full width', !fit(S.field) && prop(S.field, '--dd-w') === '');
ok('a select not in the document keeps the default rather than a guess',
   wrapOf(detached).classList.contains('dd') && !fit(detached));

// WHERE IT SAT IN ITS ROW MOVES WITH IT
ok('an inline flex moves to the wrapper (' + wrapOf(S.flexed).style.flex + ')',
   !fit(S.flexed) && wrapOf(S.flexed).style.flex === '1 1 170px');
ok('so does an inline margin (' + wrapOf(S.capped).style.marginLeft + ')',
   wrapOf(S.capped).style.marginLeft === '10px');
ok('and a form field\'s own cap (' + wrapOf(S.fieldcap).style.maxWidth + ')',
   !fit(S.fieldcap) && wrapOf(S.fieldcap).style.maxWidth === '320px');

// A hidden select still hides its wrapper; base.html's .dd[hidden] rule is
// what makes that win over the fit wrapper's own display, checked below.
ok('a hidden select hides its fit wrapper', fit(S.hidden) && wrapOf(S.hidden).hidden === true);

// and the control is still the control
ok('the button still reads the selected option',
   wrapOf(S.bar).querySelector('.dd-cur').textContent === 'every bar');

console.log(bad ? (bad + ' FAILED') : '  every dropdown is sized like its select');
process.exit(bad ? 1 : 0);
"""


def css_rules(css: str) -> list[tuple[str, str]]:
    """(selector, body) for every rule, whitespace folded, with CSS AND Jinja
    comments removed -- this component keeps its reasoning in Jinja comments
    so the reasoning does not ship on every page."""
    css = re.sub(r"\{#.*?#\}|/\*.*?\*/", "", css, flags=re.S)
    return [(" ".join(s.split()), " ".join(b.split()))
            for s, b in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def styles_of(page: pathlib.Path) -> list[tuple[str, str]]:
    out = []
    for block in re.findall(r"<style[^>]*>(.*?)</style>", page.read_text(), re.S):
        out += css_rules(block)
    return out


def decl(body: str, prop: str) -> str:
    m = re.search(r"(?:^|;)\s*" + re.escape(prop) + r"\s*:\s*([^;]+)", body)
    return m.group(1).strip() if m else ""


def drive() -> None:
    print("the wrapper takes the size of the select it hides, driven")
    node = shutil.which("node")
    if not node:
        print("  node is not installed -- skipping the driven half")
        return
    base = (ROOT / "templates" / "base.html").read_text()
    scripts = [s for s in re.findall(
        r'<script nonce="\{\{ csp_nonce\(\) \}\}">(.*?)</script>', base, re.S)
        if "function enhanceSelect(sel)" in s]
    check("base.html still defines the themed dropdown", len(scripts) == 1)
    if not scripts:
        return
    # The whole script, as the browser runs it, minus the Jinja comments the
    # renderer would have removed -- including its own sweep, which is what
    # wraps a page's selects without that page doing anything.
    work = pathlib.Path(tempfile.mkdtemp(prefix="ddfit-"))
    (work / "dd.js").write_text(re.sub(r"\{#.*?#\}", "", scripts[0], flags=re.S))
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({{}});\n"
        + SETUP
        + f"require({json.dumps(str(work / 'dd.js'))});\n"
        + DRIVE)
    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        sys.stdout.write(got.stderr[-1500:] + "\n")
    check("the dropdown sized every select like the select", got.returncode == 0)


def cascade() -> None:
    print("and the CSS does what the classes promise")
    rules = styles_of(ROOT / "templates" / "base.html")

    def body(selector: str) -> str:
        return next((b for s, b in rules if s == selector), "")

    check("a form field's wrapper is still full width",
          decl(body(".dd"), "width") == "100%")
    fit = body(".dd.dd-fit")
    check(".dd.dd-fit is defined", bool(fit))
    # The VALUES come through custom properties, never literals: a literal
    # width here would outrank nothing and fight every page that already
    # sizes its own `.dd`, which is the case the properties exist for.
    check(f"its width is the select's ({decl(fit, 'width')})",
          decl(fit, "width") == "var(--dd-w)")
    check(f"and so is its minimum ({decl(fit, 'min-width')})",
          decl(fit, "min-width") == "var(--dd-min)")
    check(f"its cap is the select's, never wider than the row ({decl(fit, 'max-width')})",
          "var(--dd-max" in decl(fit, "max-width") and "100%" in decl(fit, "max-width"))
    check("it sits in a line of text and controls like the select did",
          decl(fit, "display") == "inline-block")
    check("and does not grow or shrink in a flex row",
          decl(fit, "flex") == "0 0 auto")
    check("its button stands as tall as the fields beside it",
          decl(body(".dd.dd-fit > .dd-btn"), "padding-block") == "8px")
    # The fit wrapper sets display, and an author rule beats the browser's own
    # [hidden] rule -- so without this, hiding a select left its button up.
    check("a hidden wrapper stays hidden",
          decl(body(".dd[hidden]"), "display") == "none !important")
    dates = next((b for s, b in rules if "input[type=date]" in s
                  and all(bar in s for bar in (".placebar", ".pipefilters", ".inv-bar"))), "")
    check("a date input in each filter bar is its own width, not the row's",
          decl(dates, "width") == "auto")
    inline = next((b for s, b in rules
                   if 'form[style*="display:inline"] select' in s), "")
    check("a select in an inline form is its own width",
          decl(inline, "width") == "auto")

    print("and each named filter bar still sizes its select")
    # The bar's own rule on `select` is the half the wrapper now follows, so a
    # bar that went back to a percentage would put its dropdowns on lines of
    # their own again -- and say nothing anywhere about why.
    app = css_rules((ROOT / "static" / "app.css").read_text())
    tf = styles_of(ROOT / "templates" / "terraform.html")
    for rules_in, selector in ((app, ".placebar select"),
                               (app, ".pipefilters select"),
                               (tf, ".inv-bar select.inv-sel")):
        width = decl(next((b for s, b in rules_in if s == selector), ""), "width")
        check(f"{selector} declares a width that is not a percentage ({width or 'none'})",
              bool(width) and not width.endswith("%"))


def main() -> int:
    drive()
    cascade()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main())
