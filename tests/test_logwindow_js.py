"""Run the live log window's script for real, against a stub DOM.

WHY THIS EXISTS
    The log window is the largest piece of JavaScript in the product — a live
    stream, a ring buffer, a filter, a pause, a follow button and a container
    picker, all sharing mutable state — and every test of it until now read the
    template as TEXT. A text test cannot tell "the guard is present" from "the
    guard runs", and the reload bug proved that difference costs a working day.

    So: render the template, stub enough DOM to execute it, drive it the way a
    person does, and assert on what the window ended up holding. It catches the
    class of fault a string search cannot — a control wired to the wrong
    function, a reset that misses a field, a reconnect that loses the container.

WHY NODE, AND WHY IT IS OPTIONAL
    The alternative is a headless browser, which is a hundred megabytes and a
    version to maintain for a script that touches no layout. Node is already on
    every machine that builds the logo sprite. Where it is missing this test says
    so and passes: a suite that cannot run on a fresh checkout gets deleted, and
    a test nobody can run is worth less than one that occasionally abstains.
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("logwindow-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The DOM the window runs against lives in tests/domstub.js — shared with
# tests/test_svcpage_js.py rather than copied, because two stubs drift and a stub
# that is wrong where a browser is not costs more than the bug it was written to
# find. Both of this one's own faults were exactly that.
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"

# The elements the window looks up by id, and what each has to behave as: the
# dialog needs showModal, the inputs need a value.
WINDOW_IDS = {"lgDlg": "dialog", "lgView": "div", "lgFilter": "input",
              "lgTail": "select", "lgContainer": "select", "lgPause": "button",
              "lgCount": "span", "lgState": "span", "lgPod": "span",
              "lgClear": "button", "lgCopy": "button", "lgWrap": "button",
              "lgDownload": "button", "lgFollow": "button", "lgClose": "button",
              "lgDot": "span"}

# The window also reaches for its own title-bar dots by attribute rather than by
# id. The shared stub answers a missing element with null, as a browser does — so
# they have to exist before the script runs, and building them here is how the
# test stays honest about what the markup has to provide.
SETUP = """
const {El} = require(STUB);
for (const which of ['close', 'maxi', 'mini']) {
  const dot = new El('button');
  dot.dataset.lgdot = which;
  byId.lgDlg.appendChild(dot);
}
byId.lgTail.value = '200';
"""

# What a person does to the window, and what must be true afterwards.
DRIVE = r"""
let bad = 0;
const ok = (what, cond) => { console.log((cond?'  ok   ':'  FAIL ')+what);
                             if (!cond) bad++; };
const settle = () => new Promise(r => setTimeout(r, 20));
const view = byId.lgView, picker = byId.lgContainer, count = byId.lgCount;

(async () => {
  console.log('opening the window on a pod');
  openPodLogs({stream: '/clusters/logstream?project=p&cluster=c'
                       + '&namespace=ns&pod=web-1',
               meta: '', namespace: 'ns', pod: 'web-1'});
  ok('connects exactly once ('+opened.length+')', opened.length === 1);
  ok('the stream names the pod', opened[0].includes('pod=web-1'));
  ok('and carries the tail length', opened[0].includes('tail=200'));
  ok('the window is modal', byId.lgDlg.open === true);
  ok('the title is the pod ('+byId.lgPod.textContent+')',
     byId.lgPod.textContent === 'ns/web-1');
  ok('the counter starts at zero ('+count.textContent+')',
     count.textContent === '0 lines');

  console.log('lines arrive');
  esList[0].emit('log', JSON.stringify(['line one','line two','line three']));
  await settle();
  ok('all three are on screen ('+view.children.length+')',
     view.children.length === 3);
  ok('and counted ('+count.textContent+')', count.textContent === '3 lines');

  console.log('follow keeps following, which is what tail -f means');
  // THE FAULT THIS EXISTS FOR
  //   `pinned` used to be recomputed from the scroll position on every scroll
  //   event: at the bottom meant following, anything else meant not. Pressing
  //   follow scrolls to the bottom and pins — but the scroll event that causes is
  //   delivered a frame later, and on a pod writing thousands of lines a second
  //   another flush has already landed by then. scrollHeight has grown, the view
  //   is no longer AT the bottom, and the handler turned following back off.
  //   Instantly, every time, on exactly the pods somebody needs to tail.
  //
  // The stub measures nothing, so the geometry is set by hand — which is what
  // makes the ORDER of the race explicit rather than incidental.
  const follow = byId.lgFollow;
  view.scrollHeight = 400;                       // taller than the viewport
  esList[0].emit('log', JSON.stringify(['a1', 'a2']));
  await settle();
  ok('it follows to begin with (' + follow.textContent.trim() + ')',
     follow.textContent.includes('following'));

  // the reader scrolls up to look at something
  view.scrollTop = 100;
  view.fire('scroll');
  ok('scrolling up stops it', !follow.textContent.includes('following'));
  esList[0].emit('log', JSON.stringify(['b1', 'b2', 'b3']));
  await settle();
  ok('and it counts what has arrived since (' + follow.textContent.trim() + ')',
     /3 new/.test(follow.textContent));

  // pressing follow goes back to the bottom
  follow.fire('click');
  ok('pressing it follows again', follow.textContent.includes('following'));
  ok('and jumps to the newest line', view.scrollTop === view.scrollHeight);

  // ...and now the race: a flush lands BEFORE the scroll event that jump caused.
  view.scrollHeight += 300;
  view.fire('scroll');
  ok('a flush arriving before that scroll event does not stop it',
     follow.textContent.includes('following'));
  esList[0].emit('log', JSON.stringify(['c1']));
  await settle();
  ok('so the next line still scrolls the view',
     view.scrollTop === view.scrollHeight);
  // Content growing under a pinned view is not the reader moving, and neither is
  // our own scroll — only scrolling UP is.
  view.scrollTop = view.scrollHeight - 500;
  view.fire('scroll');
  ok('and scrolling up still stops it, which is the other half',
     !follow.textContent.includes('following'));
  view.scrollTop = view.scrollHeight;
  view.fire('scroll');
  ok('reaching the bottom by hand resumes it',
     follow.textContent.includes('following'));

  console.log('switching container re-reads from the top');
  picker.value = 'sidecar';
  picker.fire('change');
  await settle();
  ok('the old stream was closed', esList[0].closed === true);
  ok('a new one opened ('+opened.length+')', opened.length === 2);
  ok('naming the container', opened[1].includes('container=sidecar'));
  ok('the view was emptied ('+view.children.length+')',
     view.children.length === 0);
  ok('and the count with it ('+count.textContent+')',
     count.textContent === '0 lines');

  console.log('changing the tail length does the same');
  byId.lgTail.value = '2000';
  byId.lgTail.fire('change');
  await settle();
  ok('reconnected with the new tail ('+opened.length+')',
     opened.length === 3 && opened[2].includes('tail=2000'));
  ok('and kept the container it was reading',
     opened[2].includes('container=sidecar'));

  console.log('clear empties the view WITHOUT reconnecting');
  esList[2].emit('log', JSON.stringify(['a','b']));
  await settle();
  const before = opened.length;
  byId.lgClear.fire('click');
  await settle();
  ok('the view is empty ('+view.children.length+')', view.children.length === 0);
  ok('and nothing reconnected ('+opened.length+' vs '+before+')',
     opened.length === before);

  console.log('opening a different pod resets everything');
  openPodLogs({stream: '/clusters/logstream?project=p&cluster=c'
                       + '&namespace=ns2&pod=db-0',
               meta: '', namespace: 'ns2', pod: 'db-0'});
  await settle();
  ok('the title followed ('+byId.lgPod.textContent+')',
     byId.lgPod.textContent === 'ns2/db-0');
  // The container belonged to the pod that was closed. Carrying it over asks
  // kubectl for a container this pod does not have, and the window stays empty.
  ok('the last pod\'s container is not carried over',
     !opened[opened.length-1].includes('container=sidecar'));
  ok('the counter was reset ('+count.textContent+')',
     count.textContent === '0 lines');

  console.log(bad ? bad + ' FAILED' : 'OK');
  process.exit(bad ? 1 : 0);
})();
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the log window's script")
        print("OK")
        return 0

    from app import main as appmain
    page = appmain.templates.get_template("_logs_dialog.html").render(bits=None)
    # The opening tag carries the CSP nonce now, so it is found by its end.
    start = page.index(">", page.index("<script")) + 1
    end = page.rindex("</script>")
    script = page[start:end]

    work = pathlib.Path(tempfile.mkdtemp(prefix="lgwin-"))
    (work / "window.js").write_text(script)
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({json.dumps(WINDOW_IDS)});\n"
        + SETUP
        + f"require({json.dumps(str(work / 'window.js'))});\n" + DRIVE)

    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        # A stub gap and a real fault look different: the stub raises a
        # TypeError, the window prints its own FAIL lines. Show both.
        sys.stdout.write(got.stderr[-1500:] + "\n")
    if got.returncode:
        print("the log window's script did not behave")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
