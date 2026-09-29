#!/usr/bin/env python3
"""The describe window's script, executed against a stub DOM.

WHY THIS EXISTS
    `desc` used to be a link that reloaded the whole cluster page with
    `inspect=describe` in the query — losing the pod list, the namespace filter
    and your place in a hundred-row table, to glance at one object. It is a
    window over the page now, and a window is all interaction: the markup can be
    perfect while the fetch goes to the wrong object, the filter hides
    everything, or the copy button copies the filtered view instead of the
    output.

    The one that would be silent and wrong: **a stale target**. The window holds
    one `where`. Open pod A, close it, open pod B, and a `where` that did not get
    replaced shows A's description under B's name — output that looks completely
    plausible and belongs to something else.

    ./.venv/bin/python tests/test_describe_js.py
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
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("describejs-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"

IDS = {"dsDlg": "dialog", "dsView": "div", "dsWhat": "span", "dsState": "span",
       "dsCount": "span", "dsFind": "input", "dsWrap": "button",
       "dsCopy": "button", "dsDownload": "button", "dsAgain": "button",
       "dsClose": "button"}

# The title-bar dots are reached by attribute, not by id, so they have to exist
# before the script runs — the stub answers a missing element with null, as a
# browser does.
SETUP = """
const {El} = require(STUB);
for (const which of ['close', 'maxi', 'mini']) {
  const dot = new El('button');
  dot.dataset.dsdot = which;
  byId.dsDlg.appendChild(dot);
}
// two rows that can open the window, the way a real page carries them
function descBtn(ns, name, kind) {
  const b = new El('a');
  b.dataset.poddesc = '';
  b.dataset.dsurl = '/clusters/describe.json?project=p&cluster=c';
  b.dataset.dskind = kind || 'pod';
  b.dataset.ns = ns;
  b.dataset.pod = name;
  domRoot.appendChild(b);
  return b;
}
global.rowA = descBtn('preprod', 'web-1');
global.rowB = descBtn('kube-system', 'coredns-abc', 'pod');
"""

DRIVE = r"""
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
const settle = () => new Promise(r => setTimeout(r, 20));
const view = byId.dsView;
const shown = () => view.children.filter(c => c.classList.contains('l'));

const DESC_A = ['Name:         web-1',
                'Namespace:    preprod',
                // kubectl pads a value to a fixed column, so a field with an
                // EMPTY value ends in whitespace after its colon. Real output
                // from a real pod, and the reason the header pattern may not
                // allow trailing space: this line is a field, not a section.
                'IP:           ',
                'Containers:',
                '  app:',
                '    Image:      registry/app:1.2',
                'Events:',
                '  Warning  BackOff  restarting failed container'].join('\n');
const DESC_B = ['Name:         coredns-abc', 'Namespace:    kube-system',
                'Events:', '  <none>'].join('\n');

(async () => {
  console.log('a row opens the window on its own object');
  fetchReplies['name=web-1'] = {error: '', text: DESC_A, title: 'pod/web-1'};
  fetchReplies['name=coredns-abc'] = {error: '', text: DESC_B};
  rowA.fire('click');
  await settle();
  ok('the window is modal', byId.dsDlg.open === true);
  const asked = fetched[fetched.length - 1].url;
  ok('it asked for that object (' + asked.split('?')[1] + ')',
     asked.includes('name=web-1') && asked.includes('namespace=preprod')
     && asked.includes('kind=pod'));
  ok('the title names it (' + byId.dsWhat.textContent + ')',
     byId.dsWhat.textContent === 'preprod/web-1');
  ok('every line is on screen (' + shown().length + ')', shown().length === 8);
  ok('and counted (' + byId.dsCount.textContent + ')',
     byId.dsCount.textContent === '8 lines');
  // A snapshot, not a stream — the reader has to know when it was true.
  ok('it says when it was read (' + byId.dsState.textContent + ')',
     byId.dsState.textContent.startsWith('read at '));

  console.log('section headers are marked so the output can be scanned');
  // Detected from the shape of the line, not from a list of kinds: every kind
  // has its own sections and kubectl adds more.
  const heads = shown().filter(l => l.classList.contains('h'))
    .map(l => l.textContent.trim());
  ok('Containers: and Events: are headers (' + heads.join(' ') + ')',
     heads.length === 2 && heads.includes('Containers:')
     && heads.includes('Events:'));
  // The one that was wrong on a real pod: a field with an empty value pads to
  // the value column, so it ends in whitespace after the colon.
  ok('a field with an empty value is NOT a header',
     !shown().find(l => l.textContent.startsWith('IP:'))
       .classList.contains('h'));
  ok('and an indented field is not',
     !shown().find(l => l.textContent.includes('Image:'))
       .classList.contains('h'));

  console.log('the filter narrows, and says how much');
  byId.dsFind.value = 'events';
  byId.dsFind.fire('input');
  ok('only matching lines remain (' + shown().length + ')', shown().length === 1);
  ok('the count says both numbers (' + byId.dsCount.textContent + ')',
     byId.dsCount.textContent === '1 of 8 lines');
  ok('and the match is highlighted', !!view.querySelector('mark'));
  byId.dsFind.value = 'nothing-like-this';
  byId.dsFind.fire('input');
  ok('a filter that matches nothing says so',
     shown().length === 0 && !!view.querySelector('.none'));
  byId.dsFind.value = '';
  byId.dsFind.fire('input');
  ok('clearing it brings every line back', shown().length === 8);

  console.log('copy takes the whole output, not the filtered view');
  // Filtering is a way of reading; copying half of what the cluster said,
  // because a filter happened to be typed, is the kind of thing that gets
  // pasted into an incident channel.
  byId.dsFind.value = 'events';
  byId.dsFind.fire('input');
  let copied = null;
  navigator.clipboard.writeText = t => { copied = t; return Promise.resolve(); };
  byId.dsCopy.fire('click');
  await settle();
  ok('the whole output was copied (' + (copied || '').split('\n').length + ')',
     (copied || '').split('\n').length === 8);
  byId.dsFind.value = '';
  byId.dsFind.fire('input');

  console.log('the stale-target fault: a second object in the same window');
  const before = fetched.length;
  rowB.fire('click');
  await settle();
  ok('it asked for the second object',
     fetched[fetched.length - 1].url.includes('name=coredns-abc'));
  ok('the title followed (' + byId.dsWhat.textContent + ')',
     byId.dsWhat.textContent === 'kube-system/coredns-abc');
  ok('and the body is the second object\'s (' + shown().length + ' lines)',
     shown().length === 4
     && shown()[0].textContent.includes('coredns-abc'));
  // ...and refresh has to follow the CURRENT target, not the first one opened.
  byId.dsAgain.fire('click');
  await settle();
  ok('refresh re-reads the object on screen',
     fetched[fetched.length - 1].url.includes('name=coredns-abc'));
  ok('and it re-read rather than reusing what it had',
     fetched.length > before + 1);

  console.log('the filter does not survive into the next object');
  byId.dsFind.value = 'events';
  byId.dsFind.fire('input');
  rowA.fire('click');
  await settle();
  ok('a fresh object opens unfiltered',
     byId.dsFind.value === '' && shown().length === 8);

  console.log('an error is shown, not swallowed');
  fetchReplies['name=web-1'] = {error: 'pods "web-1" not found', text: ''};
  rowA.fire('click');
  await settle();
  ok('the reason is on screen',
     view.textContent.includes('not found')
     && !!view.querySelector('.none'));
  ok('and no stale body is left underneath', shown().length === 0);

  console.log('wrap toggles, and closing closes');
  ok('long lines are not wrapped to begin with',
     !view.classList.contains('wrap'));
  byId.dsWrap.fire('click');
  ok('wrap turns on', view.classList.contains('wrap'));
  byId.dsWrap.fire('click');
  ok('and off again', !view.classList.contains('wrap'));
  byId.dsClose.fire('click');
  ok('close closes it', byId.dsDlg.open === false);

  console.log(bad ? bad + ' FAILED' : 'OK');
  process.exit(bad ? 1 : 0);
})();
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the describe window's script")
        print("OK")
        return 0

    from app import main as appmain
    page = appmain.templates.get_template("_describe_dialog.html").render()
    # The opening tag carries the CSP nonce now, so it is found by its end.
    start = page.index(">", page.index("<script")) + 1
    script = page[page.index("(function", start):page.rindex("</script>")]

    work = pathlib.Path(tempfile.mkdtemp(prefix="dswin-"))
    (work / "window.js").write_text(script)
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({json.dumps(IDS)});\n"
        + SETUP
        + f"require({json.dumps(str(work / 'window.js'))});\n" + DRIVE)

    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        sys.stdout.write(got.stderr[-1500:] + "\n")
    if got.returncode:
        print("the describe window's script did not behave")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
