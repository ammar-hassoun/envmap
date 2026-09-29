#!/usr/bin/env python3
"""Editing a live object's YAML: the guards, and the window that drives them.

WHY THIS EXISTS
    This is the most powerful thing in the product. Every other write is a fixed
    verb on a named object — restart that, scale this to three, remove one
    ConfigMap key — and an applied document can do anything the API server
    allows, typed by hand into a textarea.

    Three guards, and each one is the whole feature if it is missing:

      1. **The same object.** The submitted document's kind, name and namespace
         must match the one the editor was opened on. Without that check, "edit
         this deployment" and "apply arbitrary YAML to my cluster" are the same
         button — paste a Secret into the box and it lands.

      2. **A dry run that really is dry.** `--dry-run=server` runs the whole
         admission path and changes nothing. If the flag were ever dropped from
         the argv, `check` would silently become `apply` and nothing about the
         page would look different.

      3. **The ordinary gates.** Management area, the cluster's own tick, and a
         typed cluster name on production. A read must NOT need them — an SRE
         reading a manifest at 02:00 is not making a change.

    And one thing that is not a guard but is worth keeping: `status:` is stripped
    before the document is shown. It is a third of a Deployment's YAML and every
    line of it is read-only.

    ./.venv/bin/python tests/test_yamledit_live.py
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("yamledit-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import kmanage                                        # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"
bad = 0

SAME = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: preprod
spec:
  replicas: 2
"""


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


IDS = {"ymDlg": "dialog", "ymText": "textarea", "ymWhat": "span", "ymEdit": "button",
       "ymState": "span", "ymDirty": "span", "ymOut": "div", "ymWrap": "div",
       "ymConfirmWrap": "span", "ymConfirm": "input", "ymApply": "button",
       "ymCheck": "button", "ymRevert": "button", "ymCopy": "button",
       "ymClose": "button"}

SETUP = """
const {El} = require(STUB);
for (const which of ['close', 'maxi', 'mini']) {
  const dot = new El('button');
  dot.dataset.ymdot = which;
  byId.ymDlg.appendChild(dot);
}
function yamlBtn(ns, name, kind) {
  const b = new El('button');
  b.dataset.podyaml = '';
  b.dataset.ymproject = 'p1';
  b.dataset.ymcluster = 'c1';
  b.dataset.ymkind = kind;
  b.dataset.ns = ns;
  b.dataset.pod = name;
  domRoot.appendChild(b);
  return b;
}
global.rowDeploy = yamlBtn('preprod', 'web', 'deployment');
global.rowProd = yamlBtn('prod', 'payments', 'deployment');
"""

DRIVE = r"""
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
const settle = () => new Promise(r => setTimeout(r, 20));
const body = i => new URLSearchParams(fetched[fetched.length - 1 - (i || 0)].body);

const DOC = 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n'
          + '  namespace: preprod\nspec:\n  replicas: 2\n';

(async () => {
  console.log('a row opens the object it belongs to');
  fetchReplies['name=web'] = {error: '', text: DOC, kind: 'deployment',
    name: 'web', namespace: 'preprod', may_write: true, confirm: '',
    cluster_name: 'ke-preprod'};
  fetchReplies['name=payments'] = {error: '', text: DOC, kind: 'deployment',
    name: 'payments', namespace: 'prod', may_write: true,
    confirm: 'ke-prod', cluster_name: 'ke-prod'};
  fetchReplies['/clusters/yaml/apply'] = {ok: true, dry_run: true,
    output: 'deployment.apps/web configured (server dry run)', error: ''};

  rowDeploy.fire('click');
  await settle();
  ok('the window is modal', byId.ymDlg.open === true);
  ok('it read that object (' + fetched[0].url.split('?')[1] + ')',
     fetched[0].url.includes('kind=deployment')
     && fetched[0].url.includes('name=web')
     && fetched[0].url.includes('namespace=preprod'));
  ok('the document is in the box', byId.ymText.value === DOC);
  ok('the title names it (' + byId.ymWhat.textContent + ')',
     byId.ymWhat.textContent === 'preprod/web');

  console.log('it opens as a VIEWER, even where writing is allowed');
  // Reading an object's YAML is the common reason to open this window — from a
  // pod row, a node row, a CRD — and a box that is live from the first keystroke
  // means a stray character in a production Deployment is one click from being
  // applied. Editing is a second, deliberate act.
  ok('the box cannot be typed into yet', byId.ymText.readOnly === true);
  ok('and it says so (' + byId.ymDirty.textContent + ')',
     byId.ymDirty.textContent.includes('read-only'));
  ok('there is nothing that writes on screen',
     byId.ymApply.hidden === true && byId.ymCheck.hidden === true);
  ok('but there is a way to start', byId.ymEdit.hidden === false);

  console.log('edit unlocks it, and only then');
  byId.ymEdit.fire('click');
  ok('the box takes typing', byId.ymText.readOnly === false);
  ok('save appears', byId.ymApply.hidden === false);
  ok('so does the dry run', byId.ymCheck.hidden === false);
  ok('and the edit button steps aside', byId.ymEdit.hidden === true);
  ok('nothing is marked as edited yet', byId.ymDirty.textContent === 'editing');

  console.log('check is a dry run, and says so');
  byId.ymText.value = DOC.replace('replicas: 2', 'replicas: 3');
  byId.ymText.fire('input');
  ok('editing marks the window', byId.ymDirty.textContent === 'edited');
  byId.ymCheck.fire('click');
  await settle();
  ok('the check posted dry=1', body().get('dry') === '1');
  ok('with the edited document', body().get('yaml').includes('replicas: 3'));
  ok('and it names the object it was opened on',
     body().get('kind') === 'deployment' && body().get('name') === 'web'
     && body().get('namespace') === 'preprod');
  ok('the reader is told nothing changed ('
     + byId.ymOut.textContent.slice(0, 26) + ')',
     byId.ymOut.textContent.includes('Nothing was changed')
     && byId.ymOut.textContent.includes('dry run'));
  ok('and it still reads as edited, because it is',
     byId.ymDirty.textContent === 'edited');

  console.log('save is the second button, and is confirmed');
  fetchReplies['/clusters/yaml/apply'] = {ok: true, dry_run: false,
    output: 'deployment.apps/web configured', error: ''};
  confirmAnswer = false;                     // the browser confirm() says no
  const before = fetched.length;
  byId.ymApply.fire('click');
  await settle();
  ok('saying no to the confirm posts nothing', fetched.length === before);
  confirmAnswer = true;
  byId.ymApply.fire('click');
  await settle();
  ok('saying yes writes it', fetched.length === before + 1);
  ok('and it is NOT a dry run', !body().has('dry'));
  // Locked again afterwards: the write landed, and the copy on screen is now the
  // older of the two — the server defaults and adds fields on the way in. A
  // second save has to start from a fresh read.
  ok('the window locks itself again once saved',
     byId.ymText.readOnly === true && byId.ymApply.hidden === true);
  ok('and offers the way back in', byId.ymEdit.hidden === false);
  ok('and says what was stored is not what is on screen',
     byId.ymOut.textContent.includes('re-read'));
  // Saving with nothing changed is not a write.
  byId.ymEdit.fire('click');
  const quiet = fetched.length;
  byId.ymApply.fire('click');
  await settle();
  ok('saving an unchanged document posts nothing',
     fetched.length === quiet
     && byId.ymOut.textContent.includes('Nothing has been changed'));

  console.log('a production cluster asks for its name first');
  byId.ymDlg.close();
  rowProd.fire('click');
  await settle();
  // The warning belongs to the moment of editing, not to opening: a window
  // opened to READ a manifest should not lead with a warning about writing.
  ok('opening it says nothing about production yet',
     !byId.ymOut.textContent.includes('production'));
  ok('and the confirm box is not on screen either',
     byId.ymConfirmWrap.hidden === true);
  byId.ymEdit.fire('click');
  ok('the confirm box is shown once editing', byId.ymConfirmWrap.hidden === false);
  ok('naming the cluster (' + byId.ymConfirm.placeholder + ')',
     byId.ymConfirm.placeholder.includes('ke-prod'));
  ok('and the reader is told why',
     byId.ymOut.textContent.includes('production'));
  byId.ymText.value = DOC.replace('replicas: 2', 'replicas: 4');
  byId.ymText.fire('input');
  byId.ymConfirm.value = 'ke-prod';
  byId.ymApply.fire('click');
  await settle();
  ok('the typed name is sent with the save',
     body().get('confirm') === 'ke-prod');

  console.log('read-only leaves no button to press');
  byId.ymDlg.close();
  fetchReplies['name=web'].may_write = false;
  rowDeploy.fire('click');
  await settle();
  ok('the box cannot be typed into', byId.ymText.readOnly === true);
  ok('save is withdrawn', byId.ymApply.hidden === true);
  ok('check is withdrawn too', byId.ymCheck.hidden === true);
  // The important one now: without the permission there is no way IN either, and
  // an edit button that unlocks a box whose save is refused is a trap.
  ok('and so is the edit button', byId.ymEdit.hidden === true);
  ok('so pressing it changes nothing', (() => {
       byId.ymEdit.fire('click');
       return byId.ymText.readOnly === true && byId.ymApply.hidden === true;
     })());
  ok('and the reason is given',
     byId.ymOut.textContent.includes('Cluster management'));

  console.log('a refusal is shown, not swallowed');
  byId.ymDlg.close();
  fetchReplies['name=web'].may_write = true;
  rowDeploy.fire('click');
  await settle();
  fetchReplies['/clusters/yaml/apply'] = {ok: false,
    error: 'error validating data: unknown field "spec.replicaz"'};
  byId.ymCheck.fire('click');
  await settle();
  ok('the API server\'s own words are on screen',
     byId.ymOut.textContent.includes('unknown field')
     && byId.ymOut.classList.contains('bad'));

  console.log(bad ? bad + ' FAILED' : 'OK');
  process.exit(bad ? 1 : 0);
})();
"""


def server_side() -> None:
    """The three guards, at the layer that enforces them."""
    print("the submitted document must be the object that was opened")
    cases = [
        (SAME, None, "the same object"),
        (SAME.replace("name: web", "name: other"), "called", "a different name"),
        (SAME.replace("namespace: preprod", "namespace: kube-system"),
         "namespace", "a different namespace"),
        (SAME.replace("kind: Deployment", "kind: Secret"), "is a",
         "a different kind — paste a Secret in and it must not land"),
        ("kind: Deployment\nmetadata:\n name: web\n  bad: indent\n",
         "not valid YAML", "a document that does not parse"),
        ("a bare string", "not a Kubernetes object", "not an object at all"),
    ]
    for doc, expect, why in cases:
        try:
            kmanage.apply_yaml({"context": "x"}, "deployment", "web", "preprod",
                               doc, dry_run=True, allow_write=False)
            check(f"{why} was accepted", expect is None)
        except kmanage.Refused as e:
            if expect is None:
                # the identity checks passed; it only failed on the fake cluster
                check(f"{why} passed the identity checks",
                      "kubeconfig" in str(e) or "context" in str(e))
            else:
                check(f"{why} → {str(e)[:52]}", expect in str(e))

    print("a real apply needs write; a dry run does not touch anything")
    try:
        kmanage.apply_yaml({"context": "x"}, "deployment", "web", "preprod",
                           SAME, dry_run=False, allow_write=False)
        check("applying without write was refused", False)
    except kmanage.Refused as e:
        check(f"applying without write is refused ({str(e)[:44]})",
              "read-only" in str(e))
    # ...and the flag that makes a dry run dry has to be in the argv. If it were
    # ever dropped, `check` would become `apply` and nothing would look different.
    # Asserted on the ARGV line, not on the whole function: the flag appears a
    # second time in the audit string, quite legitimately, and counting
    # occurrences failed on that.
    import inspect
    import re as _re
    src = inspect.getsource(kmanage.apply_yaml)
    argv = _re.search(r"argv = \[\"apply\".*", src)
    check("the apply builds its argv", argv is not None)
    if argv:
        line = argv.group(0)
        check(f"the dry run adds --dry-run=server ({line.strip()[:58]})",
              "--dry-run=server" in line)
        check("and only when it is a dry run", "if dry_run else []" in line)

    print("status is stripped, because none of it can be set")
    doc = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
           "  containers: []\nstatus:\n  phase: Running\n  conditions:\n"
           "    - type: Ready\n")
    out = kmanage._without_status(doc)
    check("the status block is gone", "phase: Running" not in out
          and "type: Ready" not in out)
    check("and everything above it is kept",
          "kind: Pod" in out and "containers: []" in out)
    # A key that merely starts with the same letters is not the status block.
    keep = "kind: Pod\nstatusCheckUrl: https://x/health\nspec: {}\n"
    check("a key that only looks like status is left alone",
          "statusCheckUrl" in kmanage._without_status(keep))


def window_side() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the YAML window's script")
        return 0
    from app import main as appmain
    page = appmain.templates.get_template("_yaml_dialog.html").render()
    script = page[page.index("(function", page.index("<script")):
                  page.rindex("</script>")]
    work = pathlib.Path(tempfile.mkdtemp(prefix="ymwin-"))
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
    return got.returncode


def main() -> int:
    server_side()
    rc = window_side()
    print("OK" if not (bad or rc) else f"{bad or 1} FAILED")
    return 1 if (bad or rc) else 0


if __name__ == "__main__":
    sys.exit(main())
