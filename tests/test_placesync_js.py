#!/usr/bin/env python3
"""Run the region-follows-project behaviour for real, against a stub DOM.

WHY THIS EXISTS
    Reported twice, months apart, and the second report is the reason this file
    is not another string search.

    A region `<select>` narrows to the project chosen beside it. The behaviour
    was written INLINE, twice — once in `_bits.html`'s `place_fields` (Ansible
    playbooks, Ansible groups, Terraform stacks) and once, separately, in the
    Privileged Access target form. Both copies had the same two faults:

      * they set `hidden` on the options. The themed dropdown builds its menu
        from the options it FINDS and skips only `disabled` ones, so hiding
        changed nothing about what was offered.
      * they toggled `disabled` on the native select and never called
        ddRefresh. The visible control is a button drawn beside that select and
        re-reads `disabled` only when refreshed, so it painted disabled at load
        (no project chosen yet) and stayed dead after one was.

    The macro was fixed when the bug was first reported. The PAM copy was not,
    and the identical symptom came back: "when I choose the project even though
    it has a region I'm not able to choose the region." The tests at the time
    read the MACRO'S SOURCE for the right strings — which passed, and could
    never have said anything about the other copy.

    So the behaviour is one function now (`window.placeSync` in base.html) and
    this drives it the way a person does. A source search cannot tell "the
    rebuild is written" from "the rebuild runs", and it cannot see a second
    implementation at all.

    ./.venv/bin/python tests/test_placesync_js.py
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("placesync-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"

# Two projects with regions and one with none — the third is not padding, it is
# the case that must explain itself rather than offer an empty list.
SETUP = r"""
const {El} = require(STUB);

function opt(value, text, proj) {
  const o = new El('option');
  o.value = value; o.textContent = text;
  if (proj) o.dataset.proj = proj;
  return o;
}
const proj = byId.proj, reg = byId.reg, note = byId.note;
proj.appendChild(opt('', '— none —'));
proj.appendChild(opt('p-pay', 'Payments'));
proj.appendChild(opt('p-cards', 'Cards'));
proj.appendChild(opt('p-empty', 'Nothing yet'));
reg.appendChild(opt('', '— region —'));
reg.appendChild(opt('r-ke', 'Kenya', 'p-pay'));
reg.appendChild(opt('r-tz', 'Tanzania', 'p-pay'));
reg.appendChild(opt('r-uae', 'UAE', 'p-cards'));

// The themed dropdown is not here, so stand in for it: what matters is that
// the control is TOLD to repaint after `disabled` changes, which is the half
// of the bug that left the button dead.
let refreshes = 0;
window.ddRefresh = function (el) { if (el === reg) refreshes++; };
"""

DRIVE = r"""
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
const offered = () => reg.options.map(o => o.value).filter(Boolean);
const choose = (v) => { proj.value = v; proj.fire('change'); };

// Nothing chosen yet: the region select is inert, and says why.
ok('with no project the region select is disabled', reg.disabled === true);
ok('and it says why rather than looking broken',
   /choose a project/i.test(note.textContent));

// THE REPORTED SYMPTOM. A project with regions must leave the control usable.
const before = refreshes;
choose('p-pay');
ok('choosing a project ENABLES the region select', reg.disabled === false);
ok('and the themed control is told to repaint (' +
   (refreshes - before) + ' refresh)', refreshes > before);
ok('only that project\'s regions are offered: ' + JSON.stringify(offered()),
   offered().length === 2 && offered().includes('r-ke')
   && offered().includes('r-tz'));
ok('the other project\'s region is GONE, not merely hidden',
   !offered().includes('r-uae'));
ok('the placeholder survives so "no region" stays choosable',
   reg.options.some(o => !o.value));

// A region can actually be picked and kept.
reg.value = 'r-tz';
choose('p-pay');
ok('re-syncing the same project keeps the chosen region',
   reg.value === 'r-tz');

// Switching project must not carry a region that belongs to the old one.
choose('p-cards');
ok('switching project drops a region that is no longer valid',
   reg.value === '' && offered().join() === 'r-uae');

// Going back must still offer the first project's regions — this is what a
// rebuild that loses options looks like from the outside.
choose('p-pay');
ok('going back offers the first project\'s regions again: ' +
   JSON.stringify(offered()), offered().length === 2);

// A project with no regions is normal, and must not read as a broken control.
choose('p-empty');
ok('a project with no regions explains itself',
   /no regions/i.test(note.textContent));
ok('and offers nothing rather than another project\'s regions',
   offered().length === 0);

// Back to none.
choose('');
ok('clearing the project disables it again', reg.disabled === true);

console.log(bad ? (bad + ' FAILED') : '  all placeSync behaviour holds');
process.exit(bad ? 1 : 0);
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the dependent-select behaviour")
        print("OK")
        return 0

    base = (ROOT / "templates" / "base.html").read_text()
    # placeSync is plain JavaScript inside base.html's dropdown script — no
    # Jinja in it, so it is lifted rather than rendered. Sliced by its own
    # assignment and closing line so the extraction cannot quietly take half.
    start = base.index("window.placeSync = function")
    end = base.index("\n    };", start) + len("\n    };")
    script = "window.placeSync = " + base[start:end].split("=", 1)[1].strip()

    work = pathlib.Path(tempfile.mkdtemp(prefix="placesync-"))
    (work / "place.js").write_text(script)
    ids = {"proj": "select", "reg": "select", "note": "div"}
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({json.dumps(ids)});\n"
        + SETUP
        + f"require({json.dumps(str(work / 'place.js'))});\n"
        + "window.placeSync(proj, reg, note);\n"
        + DRIVE)

    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        # A stub gap and a real fault look different: the stub raises a
        # TypeError, the behaviour prints its own FAIL lines. Show both.
        sys.stdout.write(got.stderr[-1500:] + "\n")
    if got.returncode:
        print("the dependent select did not behave")
        return 1

    print("and BOTH markups use it, so neither can drift again")
    bad = 0
    # ONE property the stub cannot show, asserted on the source instead, and
    # labelled as the compromise it is. `reg.options` is a LIVE collection in a
    # browser: clearing the select empties the collection itself, so the master
    # list has to be snapshotted into a real Array before the first rebuild.
    # The stub returns a fresh array each call, so it models a snapshot whether
    # or not the code takes one — and a stub that is wrong where a browser is
    # not costs more than the bug it was written to find, so this is not
    # "fixed" in the stub. Both bites of the behaviour version passed, which is
    # how the overclaiming comment that used to sit here was caught.
    base = (ROOT / "templates" / "base.html").read_text()
    sync = base[base.index("window.placeSync = function"):]
    sync = sync[:sync.index("\n    };")]
    if not ("Array.prototype.map.call" in sync or
            "Array.prototype.slice.call" in sync):
        print("  FAIL the master option list is not snapshotted out of the "
              "live collection")
        bad += 1
    for name in ("_bits.html", "pam_target.html", "pam.html"):
        page = (ROOT / "templates" / name).read_text()
        if "placeSync" not in page:
            print(f"  FAIL {name} does not use the shared behaviour")
            bad += 1
    # THE FAULT ITSELF, swept across every template rather than a named list.
    # The named list above was exactly two entries while a THIRD copy sat in
    # pam.html's own FILTER BAR, dead in the same two ways and reported the
    # same way — a list cannot find the copy nobody added to it.
    #
    # PRECISE on purpose. Two looser versions cried wolf: the first matched
    # `o.hidden` on drawer elements, `.disabled` on ordinary buttons, a
    # deliberate disable of hidden form fields, and this file's own comment
    # explaining the fix; the second matched any `.hidden =` within four lines
    # of anything mentioning `.options`, which is every page that has a select
    # near a popover. The bug is specifically `hidden` being set on the
    # variable that ITERATES a select's options, so that is what is looked
    # for — the loop, then its variable.
    for page in sorted((ROOT / "templates").glob("*.html")):
        body = re.sub(r"/\*.*?\*/|\{#.*?#\}", "", page.read_text(), flags=re.S)
        body = re.sub(r"(?m)^\s*//.*$", "", body)
        loops = re.findall(
            r"for\s*\(\s*(?:const|let|var)\s+(\w+)\s+of\s+[\w.\[\]']*\.options",
            body)
        loops += re.findall(
            r"\.options[\s\S]{0,120}?\.forEach\(\s*\(?\s*(\w+)", body)
        loops += re.findall(
            r"querySelectorAll\(\s*['\"][^'\"]*option[^'\"]*['\"]\s*\)"
            r"[\s\S]{0,120}?\.forEach\(\s*\(?\s*(\w+)", body)
        # `Array.prototype.forEach.call(sel.options, function (o) {…})` — the
        # ES5 shape, and the one a fourth copy would most likely take, because
        # it is the idiom placeSync itself is written in. Missed by the first
        # precise version, which only knew `sel.options.forEach(o => …)`.
        loops += re.findall(
            r"\.options\s*,\s*function\s*\(\s*(\w+)", body)
        loops += re.findall(
            r"\.options\s*,\s*\(?\s*(\w+)\s*\)?\s*=>", body)
        for var in set(loops):
            if re.search(r"\b" + re.escape(var) + r"\.hidden\s*=", body):
                print(f"  FAIL {page.name} sets `{var}.hidden` on a select's "
                      "options instead of rebuilding them")
                bad += 1
                break
    if bad:
        print(f"{bad} FAILED")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
