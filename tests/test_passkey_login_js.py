"""Sign in with a passkey — the browser's one slot, driven, not grepped.

A browser runs one WebAuthn request at a time and answers a second with
"A request is already pending". The sign-in page has two: the autofill one,
which starts on load and waits, and the button. The page cancels the first
before starting the second, and on a Mac that was enough. Chrome on Android
frees the slot only when the phone's passkey service confirms the cancel, so
the button's request arrived in between and people saw

    passkey sign-in failed: A request is already pending.

This test pulls the real script out of the rendered sign-in page and drives
it under node against a fake browser with one slot, in the shapes a real one
takes: a cancel that lands late, a cancelled request that settles late, a
slot that never frees, a challenge fetch still in flight when the button is
pressed, a prompt the person cancels, and a picked passkey that is refused.

    ./.venv/bin/python tests/test_passkey_login_js.py
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
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pk-login-js-")

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, main                                     # noqa: E402

BAD = 0


def check(what: str, cond: bool) -> None:
    global BAD
    print(("  ok  " if cond else "  FAIL ") + what)
    if not cond:
        BAD += 1


# A browser with one WebAuthn slot. `B` shapes it:
#   rejectAfterAbort  ms until a cancelled request's promise rejects
#   freeAfterAbort    ms until the slot is free again; -1 is never
#   modal             what each button request does in turn: ok | cancel
#   conditional       whether the autofill route exists at all
HARNESS = r"""
const SCEN = JSON.parse(process.argv[2]);
const B = Object.assign({rejectAfterAbort: 5, freeAfterAbort: 0, modal: ['ok'],
                         conditional: true, optionsDelay: 30, verify: 'ok'},
                        SCEN.browser || {});
const T0 = Date.now();
const at = () => Date.now() - T0;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const gets = [], net = [];
let slot = null, autofill = null, href = null;

const els = {};
const el = id => els[id] || (els[id] = {
  id, hidden: true, disabled: false, textContent: '', value: '', style: {},
  _h: {}, addEventListener(t, f) { this._h[t] = f; }});
const notes = [];
let noteText = '';
el('pk-note');
Object.defineProperty(els['pk-note'], 'textContent', {
  get: () => noteText, set: v => { noteText = v; notes.push(v); }});
global.document = {getElementById: el};
global.window = global;
global.location = {set href(v) { href = v; }, get href() { return href; }};

const buf = () => new Uint8Array([1, 2, 3]).buffer;
const cred = () => ({id: 'abc', rawId: buf(), type: 'public-key', response: {
  clientDataJSON: buf(), authenticatorData: buf(), signature: buf(),
  userHandle: null}});

global.PublicKeyCredential = {
  isConditionalMediationAvailable: async () => B.conditional};
let modalN = 0;
Object.defineProperty(global, 'navigator', {value: {credentials: {get(req) {
  const m = req.mediation || 'modal';
  const rec = {m, t: at(), end: null};
  gets.push(rec);
  if (slot) {
    rec.end = 'pending';
    return Promise.reject(new DOMException('A request is already pending.',
                                           'InvalidStateError'));
  }
  if (req.signal && req.signal.aborted) {
    rec.end = 'abort';
    return Promise.reject(new DOMException('signal is aborted', 'AbortError'));
  }
  const me = {};
  slot = me;
  return new Promise((res, rej) => {
    if (m === 'conditional') {
      autofill = () => { if (slot === me) slot = null; rec.end = 'picked';
                         autofill = null; res(cred()); };
      req.signal.addEventListener('abort', () => {
        autofill = null;
        setTimeout(() => { rec.end = rec.end || 'abort';
          rej(new DOMException('signal is aborted', 'AbortError')); },
          B.rejectAfterAbort);
        if (B.freeAfterAbort >= 0)
          setTimeout(() => { if (slot === me) slot = null; }, B.freeAfterAbort);
      });
    } else {
      const what = B.modal[Math.min(modalN++, B.modal.length - 1)];
      setTimeout(() => {
        if (slot === me) slot = null;
        rec.end = what;
        if (what === 'ok') res(cred());
        else rej(new DOMException('The operation either timed out or was not '
                                  + 'allowed.', 'NotAllowedError'));
      }, 20);
    }
  });
}}}});

global.fetch = async (url, init) => {
  const kind = url.includes('options') ? 'options' : 'verify';
  const rec = {kind, sent: at(), done: null};
  net.push(rec);
  await sleep(kind === 'options' ? B.optionsDelay : 30);
  rec.done = at();
  if (kind === 'options')
    return {json: async () => ({challenge: 'AAAA', allowCredentials: []})};
  return {json: async () => B.verify === 'ok' ? {ok: true, next: '/'}
    : {ok: false, error: 'that passkey is not registered here'}};
};
"""

DRIVER = r"""
(async () => {
  for (const step of SCEN.steps) {
    const [what, when] = step.split('@');
    const wait = Number(when) - at();
    if (wait > 0) await sleep(wait);
    if (what === 'click') el('pk-go')._h.click();
    if (what === 'pick' && autofill) autofill();
  }
  await sleep(SCEN.settle || 600);
  console.log(JSON.stringify({gets, net, href, notes, note: el('pk-note').textContent,
    disabled: el('pk-go').disabled, shown: !el('pk-wrap').hidden}));
})();
"""


def page_script() -> str:
    # With no account at all the sign-in page is the first-run screen.
    if not auth.by_email("someone@example.com"):
        auth.create_user("someone@example.com", "Someone", "Long-enough-pw-1234!")
    page = TestClient(main.app).get("/login", follow_redirects=False).text
    for body in re.findall(r"<script nonce=\"[^\"]*\">(.*?)</script>", page, re.S):
        if "pk-go" in body:
            return body
    raise SystemExit("the sign-in page has no passkey script")


def run(script: str, scen: dict) -> dict:
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "run.js"
        f.write_text(HARNESS + script + DRIVER)
        p = subprocess.run(["node", str(f), json.dumps(scen)],
                           capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        print(p.stderr[-2000:])
        return {"gets": [], "net": [], "href": None, "notes": [],
                "note": "(node failed)",
                "disabled": None, "shown": False}
    return json.loads(p.stdout.strip().splitlines()[-1])


def modal(r: dict) -> list:
    return [g for g in r["gets"] if g["m"] == "modal"]


def cond(r: dict) -> list:
    return [g for g in r["gets"] if g["m"] == "conditional"]


def main_test() -> int:
    if not shutil.which("node"):
        print("node is not installed; skipping")
        return 0
    js = page_script()

    print("a cancel that lands late (Chrome on Android)")
    r = run(js, {"browser": {"rejectAfterAbort": 5, "freeAfterAbort": 400},
                 "steps": ["click@200"], "settle": 1200})
    check(f"the button signs in, got href={r['href']!r} note={r['note']!r}",
          r["href"] == "/")
    check("no 'already pending' reaches the person",
          not any("pending" in n or "failed" in n for n in r["notes"]))
    check("the refusals while the cancel landed were asked again",
          modal(r) and modal(r)[-1]["end"] == "ok"
          and all(g["end"] == "pending" for g in modal(r)[:-1]))

    print("a cancelled request that settles late")
    r = run(js, {"browser": {"rejectAfterAbort": 300, "freeAfterAbort": 300},
                 "steps": ["click@200"], "settle": 1000})
    check("the button waits for it, so the browser never refuses",
          [g["end"] for g in modal(r)] == ["ok"] and r["href"] == "/")

    print("a slot that never frees")
    r = run(js, {"browser": {"rejectAfterAbort": 5, "freeAfterAbort": -1},
                 "steps": ["click@200"], "settle": 3000})
    check(f"the person is told to try again, got {r['note']!r}",
          "still busy" in r["note"] and r["href"] is None)
    check("the button works again", r["disabled"] is False)
    check(f"and it stopped asking ({len(modal(r))} attempts in two seconds)",
          2 <= len(modal(r)) <= 16)

    print("pressed while the autofill request is still fetching its challenge")
    r = run(js, {"browser": {"optionsDelay": 300},
                 "steps": ["click@100"], "settle": 1200})
    opts = [n for n in r["net"] if n["kind"] == "options"]
    check("the button's challenge is fetched after the autofill one landed, so "
          "the session keeps the button's",
          len(opts) == 2 and opts[1]["sent"] >= opts[0]["done"])
    check("one button request, and it signs in",
          [g["end"] for g in modal(r)] == ["ok"] and r["href"] == "/")
    check("the autofill request never held the slot",
          all(g["end"] == "abort" for g in cond(r)))

    print("a prompt the person cancels, then the button again")
    r = run(js, {"browser": {"freeAfterAbort": 100, "modal": ["cancel", "ok"]},
                 "steps": ["click@200", "click@900"], "settle": 1000})
    seen = [g["end"] for g in modal(r) if g["end"] != "pending"]
    check(f"the cancel is a calm note, not a failure, got {r['notes']!r}",
          seen == ["cancel", "ok"] and any(
              n.startswith("no passkey was used") for n in r["notes"])
          and not any("failed" in n for n in r["notes"]))
    check("the autofill route was put back exactly once in between",
          len(cond(r)) == 2)
    check("and the second press signs in", r["href"] == "/")

    print("a passkey picked from autofill")
    r = run(js, {"browser": {"verify": "refuse"},
                 "steps": ["pick@200"], "settle": 600})
    check(f"a refused one says so, got {r['note']!r}",
          r["note"] == "passkey sign-in failed: that passkey is not registered here")
    check("and leaves the button usable, with autofill armed again",
          r["disabled"] is False and len(cond(r)) == 2)
    r = run(js, {"steps": ["pick@200", "click@215"], "settle": 600})
    check("a press while it signs in starts nothing",
          r["href"] == "/" and modal(r) == [])

    print("a browser without the autofill route")
    r = run(js, {"browser": {"conditional": False},
                 "steps": ["click@200"], "settle": 600})
    check("the button alone signs in",
          cond(r) == [] and [g["end"] for g in modal(r)] == ["ok"]
          and r["href"] == "/" and r["shown"])

    print("OK" if not BAD else f"{BAD} FAILED")
    return BAD


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
