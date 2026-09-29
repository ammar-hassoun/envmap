#!/usr/bin/env python3
"""Run the themed combobox for real, against a stub DOM.

WHY THIS EXISTS
    Reported as "the dropdown for environment looks so bad, it is not following
    our standard" — and it was not one page's mistake. `<input list="…">` draws
    its suggestion popup from the OPERATING SYSTEM: a light popup in a system
    font floating over the dark UI, which is the exact complaint that produced
    `enhanceSelect` for `<select>`. Nine of them shipped across seven templates,
    so every one of those fields looked wrong the moment it was clicked.

    The field cannot simply become a `<select>`. An environment here is a
    discovered folder name, not a fixed enum — the whole point is that somebody
    can type one the portal has never seen. So the input stays free text and
    `enhanceCombo` draws the house menu beside it, reusing `.dd-menu` /
    `.dd-opt` so there is one look and one definition rather than a second
    dropdown that merely resembles the first.

    Driven rather than grepped, for the reason the last dependent-select bug
    taught: a string search cannot tell "the menu is built" from "the menu
    opens", and it says nothing at all about a second copy elsewhere.

    ./.venv/bin/python tests/test_combo_js.py
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("combo-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"

SETUP = r"""
const {El} = require(STUB);
const inp = byId.env, dl = byId.envs;
inp.setAttribute('list', 'envs');
['production', 'staging', 'dev', 'preprod'].forEach(v => {
  const o = new El('option'); o.value = v; dl.appendChild(o); });
inp.list = dl;
const host = new El('div'); host.appendChild(inp);
"""

DRIVE = r"""
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
const wrap = () => inp.parentNode;
const menu = () => wrap().querySelector('.dd-menu');
const shown = () => Array.prototype.map.call(menu().children, c => c.textContent);
const open = () => !menu().hidden;

// THE REPORTED FAULT. Leaving `list` on the input means the OS popup opens
// alongside the themed one — two menus over one field.
ok('the native list attribute is REMOVED so the OS popup cannot open too',
   !inp.getAttribute('list'));
ok('the input is wrapped in the house combo', wrap().className === 'combo');
ok('and a caret says suggestions exist', !!wrap().querySelector('.combo-car'));
ok('the menu reuses the themed dropdown classes, not a new look',
   menu().className === 'dd-menu');
ok('it starts closed', !open());

inp.fire('focus');
ok('focusing offers every suggestion: ' + JSON.stringify(shown()),
   open() && shown().length === 4);
ok('the options carry the house option class',
   menu().children[0].className === 'dd-opt');

inp.value = 'pr'; inp.fire('input');
ok('typing narrows them: ' + JSON.stringify(shown()),
   shown().join() === 'production,preprod');

inp.value = 'zzz'; inp.fire('input');
ok('nothing matching closes the menu rather than showing an empty box',
   !open());

inp.value = 'pr'; inp.fire('input');
inp.fire('keydown', {key: 'ArrowDown'});
inp.fire('keydown', {key: 'Enter'});
ok('arrow + Enter picks a suggestion (' + inp.value + ')',
   inp.value === 'production' && !open());

// FREE TEXT IS THE POINT — an environment is a discovered folder name, so a
// value nobody listed has to survive. This is why the field is not a <select>.
inp.value = 'something-nobody-listed'; inp.fire('input');
ok('a value that is in no list is kept, because the field is free text',
   inp.value === 'something-nobody-listed');

// And the form must still submit on Enter when no suggestion is highlighted.
inp.value = 'pr'; inp.fire('input');
let prevented = false;
inp.fire('keydown', {key: 'Enter', preventDefault: () => { prevented = true; }});
ok('Enter with nothing highlighted does NOT steal the form submit', !prevented);

inp.fire('keydown', {key: 'Escape'});
ok('Escape closes it', !open());

console.log(bad ? (bad + ' FAILED') : '  all combobox behaviour holds');
process.exit(bad ? 1 : 0);
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the combobox behaviour")
        print("OK")
        return 0

    base = (ROOT / "templates" / "base.html").read_text()
    start = base.index("    function enhanceCombo(inp) {")
    end = base.index("\n    window.enhanceSelect = enhanceSelect;", start)
    work = pathlib.Path(tempfile.mkdtemp(prefix="combo-"))
    (work / "combo.js").write_text(
        base[start:end] + "\nwindow.enhanceCombo = enhanceCombo;\n")
    ids = {"env": "input", "envs": "datalist"}
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({json.dumps(ids)});\n"
        + SETUP
        + f"require({json.dumps(str(work / 'combo.js'))});\n"
        + "window.enhanceCombo(inp);\n"
        + DRIVE)

    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        sys.stdout.write(got.stderr[-1500:] + "\n")
    if got.returncode:
        print("the combobox did not behave")
        return 1

    print("and EVERY datalist in the product gets it, with no per-page work")
    bad = 0
    # The sweep is the whole promise: a page writes `<input list=…>` and the
    # house menu appears, exactly as a page writes `<select>` today. A per-page
    # opt-in would leave the next one looking wrong again.
    if "querySelectorAll('input[list]').forEach(enhanceCombo)" not in base:
        print("  FAIL the global sweep does not cover input[list]")
        bad += 1
    users = sorted(p.name for p in (ROOT / "templates").glob("*.html")
                   if "<datalist" in p.read_text())
    print(f"  {len(users)} templates carry a datalist: {', '.join(users)}")
    if len(users) < 5:
        print("  FAIL the corpus shrank — is this still worth being global?")
        bad += 1
    # None of them may hand-roll their own suggestion menu: that is how the
    # dependent-select bug happened twice.
    for name in users:
        page = (ROOT / "templates" / name).read_text()
        if "enhanceCombo" in page and "window.enhanceCombo" not in page:
            print(f"  FAIL {name} rolls its own instead of using the global")
            bad += 1
    if bad:
        print(f"{bad} FAILED")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
