"""What you typed survives a refused save — driven, not grepped.

A sweep of the routes found forty-one POST handlers that answered 303 on a
validation failure, so the form re-read its values from the database and
everything the person had entered was gone. The fix is one mechanism in
base.html rather than forty-one bespoke re-renders, which means one place to
get wrong — and two of its rules are the kind a grep cannot check:

  * a pasted private key must NOT be kept, however convenient that would be;
  * values come back only when something was actually refused, or the script
    would fight somebody who opened the form to start again.

So the real script is pulled out of base.html and driven under node against a
small DOM of forms, exactly as the combobox test drives the real combobox.

    ./.venv/bin/python tests/test_retry_js.py
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("retry-test-")

ROOT = pathlib.Path(__file__).resolve().parent.parent

BAD = 0


def check(what: str, cond: bool) -> None:
    global BAD
    print(("  ok  " if cond else "  FAIL ") + what)
    if not cond:
        BAD += 1


# A DOM only as wide as the script actually uses. Hand-rolled rather than
# reusing domstub because this script needs sessionStorage and form element
# collections, and a stub that grows a feature per test stops being a stub.
HARNESS = r"""
class El {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this._a = Object.assign({}, attrs);
    this.value = attrs.value || '';
    this.checked = !!attrs.checked;
    this.disabled = !!attrs.disabled;
    this.type = attrs.type || (tag === 'textarea' ? 'textarea' : 'text');
    this.name = attrs.name || '';
    this.id = attrs.id || '';
    this.children = [];
    this.textContent = attrs.textContent || '';
    this.className = attrs.class || '';
  }
  getAttribute(k) { return k in this._a ? this._a[k] : null; }
  setAttribute(k, v) { this._a[k] = String(v); }
  hasAttribute(k) { return k in this._a; }
  add(child) { this.children.push(child); child.parent = this; return child; }
  querySelectorAll(sel) {
    // only the selector shapes the script uses
    const want = sel.split(',').map(s => s.trim().replace(/\[name\]$/, ''));
    return this.children.filter(c => want.includes(c.tagName.toLowerCase())
                                     && c.name);
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

const _store = {};
global.sessionStorage = {
  getItem: k => (k in _store ? _store[k] : null),
  setItem: (k, v) => { _store[k] = String(v); },
  removeItem: k => { delete _store[k]; },
  get length() { return Object.keys(_store).length; },
  key: i => Object.keys(_store)[i],
};
global.__store = _store;

const _listeners = {};
global.document = {
  readyState: 'complete',
  forms: [],
  flashes: [],
  addEventListener: (t, fn) => { (_listeners[t] = _listeners[t] || []).push(fn); },
  querySelector: sel => document.flashes.find(f => f.className === sel.slice(1).replace('.', ' ')) || null,
  querySelectorAll: sel => (sel.indexOf('form') === 0 ? document.forms : []),
};
global.fire = (type, target) => {
  for (const fn of (_listeners[type] || [])) fn({ target });
};
global.mkForm = (action, fields, id) => {
  const f = new El('form', { action, method: 'post', id: id || '' });
  for (const spec of fields) f.add(new El(spec.tag || 'input', spec));
  document.forms.push(f);
  return f;
};
global.El = El;
global.reset = () => { document.forms = []; document.flashes = []; };
global.flash = kind => {
  document.flashes.push({ className: 'flash ' + kind });
};
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the retry behaviour")
        print("OK")
        return 0

    # SERVED FROM /static, so it is fetched once and cached for a year rather
    # than five kilobytes on every page -- the page-weight budget in
    # test_speed.py caught that the moment it was inline.
    src = ROOT / "static" / "retry.js"
    if not src.exists():
        print("  FAIL static/retry.js is missing")
        return 1
    base = (ROOT / "templates" / "base.html").read_text()
    if "/static/retry.js" not in base:
        # A mechanism nothing loads is a mechanism that does not exist, and
        # this file would still pass every behaviour check below.
        print("  FAIL base.html does not load static/retry.js")
        return 1
    body = src.read_text()
    # The script is an IIFE that wires listeners and runs `restore()` at once;
    # expose the two entry points so a test can act as the two page loads.
    body = body.replace("  if (document.readyState === 'loading')\n"
                        "    document.addEventListener('DOMContentLoaded', restore);\n"
                        "  else restore();",
                        "  global.__restore = restore;")

    work = pathlib.Path(tempfile.mkdtemp(prefix="retry-"))
    drive = r"""
// ── page one: a form is filled in and submitted ──────────────────────
reset();
const f1 = mkForm('/ansible/playbook/save', [
  {name: 'name', value: ''},
  {name: 'body', tag: 'textarea', value: '- hosts: all\n  tasks: []'},
  {name: 'notes', value: 'keep me'},
  {name: 'pw', type: 'password', value: 'hunter2'},
  {name: 'secret_key', tag: 'textarea', value: 'PRIVATE-KEY-MATERIAL'},
  {name: 'nosaveme', value: 'nope', 'data-nosave': ''},
  {name: 'onbox', type: 'checkbox', value: '1', checked: true},
  {name: 'offbox', type: 'checkbox', value: '1'},
], 'pbform');
fire('submit', f1);

const raw = JSON.stringify(__store);
out.stashed = Object.keys(__store).length === 1;
out.keyNotStored = raw.indexOf('PRIVATE-KEY-MATERIAL') < 0;
out.passwordNotStored = raw.indexOf('hunter2') < 0;
out.nosaveNotStored = raw.indexOf('nope') < 0;
out.bodyStored = raw.indexOf('hosts: all') >= 0;

// ── page two: the same form, re-rendered with an error ───────────────
reset();
flash('err');
const f2 = mkForm('/ansible/playbook/save', [
  {name: 'name', value: ''},
  {name: 'body', tag: 'textarea', value: ''},
  {name: 'notes', value: ''},
  {name: 'secret_key', tag: 'textarea', value: ''},
  {name: 'onbox', type: 'checkbox', value: '1'},
  {name: 'offbox', type: 'checkbox', value: '1', checked: true},
], 'pbform');
__restore();
out.bodyRestored = f2.querySelector('textarea').value.indexOf('hosts: all') >= 0;
out.notesRestored = f2.querySelectorAll('input,textarea').find(e => e.name === 'notes').value === 'keep me';
out.keyStillEmpty = f2.querySelectorAll('input,textarea').find(e => e.name === 'secret_key').value === '';
out.checkedRestored = f2.querySelectorAll('input,textarea').find(e => e.name === 'onbox').checked === true;
out.uncheckedRestored = f2.querySelectorAll('input,textarea').find(e => e.name === 'offbox').checked === false;
out.stashCleared = Object.keys(__store).length === 0;

// ── a submission is NOT put back on an ordinary visit ────────────────
reset();
const f3 = mkForm('/x/save', [{name: 'a', value: 'typed'}], 'g');
fire('submit', f3);
reset();
const f4 = mkForm('/x/save', [{name: 'a', value: ''}], 'g');
__restore();                       // no error flash on this page
out.notRestoredWithoutError = f4.querySelector('input').value === '';
out.clearedOnCleanVisit = Object.keys(__store).length === 0;

// ── a success clears it, so it cannot come back later ────────────────
reset();
const f5 = mkForm('/y/save', [{name: 'a', value: 'typed'}], 'h');
fire('submit', f5);
reset();
flash('ok');
const f6 = mkForm('/y/save', [{name: 'a', value: ''}], 'h');
__restore();
out.notRestoredAfterSuccess = f6.querySelector('input').value === '';

// ── A SNAPSHOT DIES IF NOTHING CLAIMS IT ────────────────────────────
// The leak: restore() can only delete a key whose form is on the page, so a
// submission landing anywhere else left its values in storage for the life of
// the tab. Three real shapes did it -- a form fetched into a dialog after
// restore() ran, a SUCCESS redirecting to a page without the form, and a
// refusal redirecting elsewhere -- and between them they held a kubeconfig,
// an SSH private key, a TLS private key and a live Secret manifest.
reset();
const fA = mkForm('/settings/project/p1/cluster/new', [
  {name: 'name', value: 'prod-cluster'},
], 'clform');
fire('submit', fA);
out.storedBeforeSweep = Object.keys(__store).length === 1;
reset();
flash('err');
mkForm('/somewhere/else', [{name: 'z', value: ''}], 'other');
__restore();                       // the cluster form is NOT on this page
out.sweptWhenUnclaimed = Object.keys(__store).length === 0;

// ...and a form that IS present still gets its values back, so the sweep did
// not simply delete everything.
reset();
const fB = mkForm('/keepme', [{name: 'a', value: 'typed'}], 'K');
fire('submit', fB);
reset();
flash('err');
const fC = mkForm('/keepme', [{name: 'a', value: ''}], 'K');
__restore();
out.claimedStillRestores = fC.querySelector('input').value === 'typed';

// ── a different form does not eat another form's values ──────────────
reset();
const f7 = mkForm('/one/save', [{name: 'a', value: 'first'}], 'A');
fire('submit', f7);
reset();
flash('err');
const f8 = mkForm('/two/save', [{name: 'a', value: ''}], 'B');
__restore();
out.notCrossFed = f8.querySelector('input').value === '';

console.log(JSON.stringify(out));
"""
    (work / "drive.js").write_text(
        HARNESS + "\nconst out = {};\n" + body + "\n" + drive)
    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    if got.returncode:
        print("  FAIL the script threw under node")
        sys.stdout.write((got.stderr or "")[-1600:] + "\n")
        return 1
    try:
        r = json.loads(got.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        print("  FAIL no result from the driver")
        sys.stdout.write(got.stdout[-800:] + "\n")
        return 1

    print("a refused save hands the submission back")
    check("the submission is kept when a form is posted", r["stashed"])
    check("...the body of a playbook among it", r["bodyStored"])
    check("...and it comes back into the re-rendered form", r["bodyRestored"])
    check("...along with the other fields", r["notesRestored"])
    check("...and the ticks, both on and off", r["checkedRestored"]
          and r["uncheckedRestored"])
    check("...then the copy is dropped, not left lying about",
          r["stashCleared"])

    print("...but a SECRET is never kept, however convenient that would be")
    # A pasted key or token in storage to save somebody retyping is the wrong
    # trade: it is the one field on the form worth typing again.
    check("a pasted private key is not stored", r["keyNotStored"])
    check("...nor is a password field", r["passwordNotStored"])
    check("...nor anything marked data-nosave", r["nosaveNotStored"])
    check("...and the key field comes back EMPTY", r["keyStillEmpty"])

    print("...and it only fires when something was actually refused")
    # Otherwise it fights somebody who opened the form to start again.
    check("an ordinary visit gets no values put back",
          r["notRestoredWithoutError"])
    check("...and the stale copy is cleared", r["clearedOnCleanVisit"])
    check("a success clears it, so it cannot reappear later",
          r["notRestoredAfterSuccess"])
    check("and one form never eats another form's submission",
          r["notCrossFed"])

    print("...and a snapshot NOTHING claims is dropped, not kept for ever")
    # This is what bounds how long a value can sit in storage. It is defence
    # in depth: the marks above are what keep a private key out of storage at
    # all, and this is what stops anything else outliving one navigation.
    check("it is stored on submit", r["storedBeforeSweep"])
    check("...and swept when the next page has no such form",
          r["sweptWhenUnclaimed"])
    check("...while a form that IS there still gets its values back",
          r["claimedStillRestores"])

    # ── the half a driver cannot check ──────────────────────────────────
    # A `<textarea>` cannot be `type="password"`, so every pasted credential
    # in this product is in one -- and the script's name list caught three of
    # them while `kubeconfig`, `gitops_ssh_key`, `key_pem`, `creds` and the
    # GitOps editor's `text` (a live Secret's manifest) sailed through. Five
    # credentials in browser storage, and the mechanism's own header promises
    # the opposite. CLAUDE.md says the mark is a decision and not a regex; a
    # decision still needs something that notices when nobody made it.
    print("...and EVERY credential-bearing textarea is marked in the templates")
    import re as _re
    WORDS = ("key", "secret", "token", "kubeconfig", "pem", "creds",
             "credential", "passw", "private")
    # `text` is the GitOps resource editor, whose value is a live manifest and
    # may be a Secret. Named explicitly because no word in it says so.
    BY_NAME = {"text"}
    # Public material: a certificate is meant to be handed out.
    PUBLIC = {"sealing_cert", "ignore_cert", "no_host_key_check", "key_source",
              "same_key", "drop_key", "drop_creds", "key_id", "key_path",
              "hidden_key_prefixes", "token_days"}
    unmarked = []
    for tpl in sorted((ROOT / "templates").glob("*.html")):
        body = tpl.read_text()
        for tag in _re.findall(r"<textarea\b[^>]*>", body, _re.S):
            m = _re.search(r'name="([^"]+)"', tag)
            if not m:
                continue
            name = m.group(1)
            if name in PUBLIC or "{{" in name:
                continue
            risky = name in BY_NAME or any(w in name.lower() for w in WORDS)
            if risky and "data-nosave" not in tag:
                unmarked.append(f"{tpl.name}:{name}")
    check(f"none unmarked (swept {len(list((ROOT / 'templates').glob('*.html')))} templates)",
          not unmarked)
    if unmarked:
        for u in unmarked:
            print(f"       {u} -- add data-nosave to that textarea")

    print(f"{BAD} FAILED" if BAD else "OK")
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
