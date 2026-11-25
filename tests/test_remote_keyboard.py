#!/usr/bin/env python3
"""A page whose keyboard belongs to another machine keeps every key.

WHY THIS EXISTS
    Reported from the Privileged Access desktop console: the first "/" typed on
    a remote desktop moved focus into the portal's search box. The slash and
    the keys after it still reached the session -- Guacamole handles them and
    prevents their default -- but focus now sat in the search box, and from
    then on the shortcut did not fire, because focus was in an INPUT.

    The console binds Guacamole's keyboard to the whole DOCUMENT, so nothing is
    focused while somebody types on a desktop, and base.html's shortcut only
    stood aside for a focused field. Measured in a real browser with the tunnel
    faked so the client was connected: "/" sent keysym 47 to the session AND
    focused #globalsearch. Ctrl/Cmd+K was the same fault with the assistant: the
    keys reached the session and the panel opened and took focus -- in the
    console's own window too, where the "/" script is not rendered at all.

    ONE FLAG, set by the page beside the binding: `data-remote-keyboard` on the
    body, which both global shortcuts read. A watcher binds no keyboard, so it
    keeps both. An xterm terminal needs no flag: its own textarea has focus
    while it holds the keyboard, which already makes "/" stand aside --
    measured on the SSH workspace, where "/" and Ctrl+K both went to the shell.

    The shortcuts are driven under node; the console is rendered in all three
    of its modes through the real routes; and every template is swept for a
    keyboard bound to the document, because the next page to bind one will not
    be on any list.

    ./.venv/bin/python tests/test_remote_keyboard.py
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
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
os.environ["PORTAL_PAM"] = "1"          # Privileged Access is off by default
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("remote-kbd-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"
# The SETTER, never the name: base.html and the assistant both mention the
# attribute in order to read it, so its bare name is on every page.
FLAG_SET = "setAttribute('data-remote-keyboard'"
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _strip(text: str) -> str:
    """Comments out, so a sentence ABOUT the flag cannot stand in for it."""
    text = re.sub(r"/\*.*?\*/|\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


PRESS = r"""
const {El} = require(STUB);
const body = document.body;
const press = (key, extra) => {
  let prevented = false;
  body.fire('keydown', Object.assign({key: key, preventDefault() { prevented = true; }},
                                     extra || {}));
  return prevented;
};
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };
"""

SLASH = r"""
const box = byId.globalsearch;
document.activeElement = body;
ok('on an ordinary page "/" goes to the search box',
   press('/') && document.activeElement === box);
document.activeElement = body;
ok('and no other key does', !press('a') && document.activeElement === body);
const field = new El('input');
document.activeElement = field;
ok('a "/" typed into a field stays in that field',
   !press('/') && document.activeElement === field);

// THE REPORTED FAULT. Nothing is focused while somebody types on a desktop.
body.setAttribute('data-remote-keyboard', '');
document.activeElement = body;
const taken = press('/');
ok('with the page\'s keyboard on a remote machine, "/" is not swallowed', !taken);
ok('and focus stays on the desktop, not in the search box',
   document.activeElement === body);
body.removeAttribute('data-remote-keyboard');

// A role without the config area has no search box, and the shortcut used to
// prevent the key's default and then throw on the missing element.
delete byId.globalsearch;
document.activeElement = body;
let threw = '', ate = false;
try { ate = press('/'); } catch (e) { threw = String(e); }
ok('with no search box "/" neither throws nor eats the key'
   + (threw ? ' (' + threw + ')' : ''), !threw && !ate);
console.log(bad ? (bad + ' FAILED') : '  the search shortcut stands aside');
process.exit(bad ? 1 : 0);
"""

ASK = r"""
// The panel and its opener are the widget's own; only what the handler
// touches is stood in for.
global.panel = {hidden: true};
const calls = [];
global.setOpen = v => { calls.push(v); panel.hidden = !v; };
require(ASK_JS);

ok('on an ordinary page Ctrl+K opens the assistant',
   press('k', {ctrlKey: true}) && calls.join() === 'true');
calls.length = 0; panel.hidden = true;

// Kill-to-end-of-line in a shell; a chord prefix in an editor on the desktop.
body.setAttribute('data-remote-keyboard', '');
ok('with a remote keyboard Ctrl+K is left to the session',
   !press('k', {ctrlKey: true}) && calls.length === 0);
ok('and so is Cmd+K', !press('K', {metaKey: true}) && calls.length === 0);
// Escape was never the fault and must not become one: on its own, so that it
// passes against the old code and the new alike.
calls.length = 0; panel.hidden = false;
press('Escape');
ok('Escape still closes a panel somebody opened by clicking',
   calls.join() === 'false');
console.log(bad ? (bad + ' FAILED') : '  the assistant shortcut stands aside');
process.exit(bad ? 1 : 0);
"""


def _node(name: str, ids: dict, files: dict, body: str) -> None:
    node = shutil.which("node")
    if not node:
        print(f"  node is not installed -- skipping {name}")
        return
    work = pathlib.Path(tempfile.mkdtemp(prefix="remote-kbd-"))
    consts = ""
    for const, text in files.items():
        (work / f"{const}.js").write_text(text)
        consts += f"const {const} = {json.dumps(str(work / f'{const}.js'))};\n"
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"require(STUB).install({json.dumps(ids)});\n" + consts + PRESS + body)
    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ})
    sys.stdout.write(got.stdout)
    if got.returncode and got.stderr:
        sys.stdout.write(got.stderr[-1500:] + "\n")
    check(f"{name} behaves", got.returncode == 0)


def slash() -> None:
    print('"/" goes to the search box unless the page\'s keyboard is a remote machine\'s')
    base = (ROOT / "templates" / "base.html").read_text()
    scripts = [s for s in re.findall(
        r'<script nonce="\{\{ csp_nonce\(\) \}\}">(.*?)</script>', base, re.S)
        if "e.key === '/'" in s]
    check("base.html still carries the search shortcut", len(scripts) == 1)
    if scripts:
        # The script whole, as the browser runs it once Jinja has removed the
        # comments -- run, then driven by keystrokes.
        js = re.sub(r"\{#.*?#\}", "", scripts[0], flags=re.S)
        _node("the search shortcut", {"globalsearch": "input"},
              {"SLASH_JS": js}, "require(SLASH_JS);\n" + SLASH)


def assistant() -> None:
    print("and Ctrl/Cmd+K is left to the session the same way")
    widget = _strip((ROOT / "templates" / "_assistant_widget.html").read_text())
    at = widget.find("(e.metaKey || e.ctrlKey)")
    check("the assistant still has its shortcut", at > 0)
    if at < 0:
        return
    # The one handler, sliced by its own opening and closing lines: the rest of
    # the widget needs a page around it, and this needs only its two names.
    start = widget.rindex("document.addEventListener('keydown'", 0, at)
    end = widget.index("\n  });", at) + len("\n  });")
    _node("the assistant shortcut", {}, {"ASK_JS": widget[start:end]}, ASK)


def rendered() -> None:
    print("the console says so exactly when it binds the keyboard")
    from fastapi.testclient import TestClient

    from app import auth, db, main, pam

    email, pw = "keys@t.local", "Remote-Keys-Stay-Put-42"
    uid = auth.create_user(email, "K", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    pam.save_config(enabled=True, allow_connect=True, record_sessions=True,
                    guacd_host="127.0.0.1", guacd_port=9, require_reason="off")
    # The page refuses to render without a gateway to point at. Nothing here
    # connects to one: the socket is the browser's business, not this test's.
    keep = pam.guacd_reachable
    pam.guacd_reachable = lambda: True
    try:
        tid = pam.save_target("", {"name": "keys-desk", "protocol": "vnc",
                                   "address": "10.0.10.50", "env": "dev",
                                   "auth_kind": "none"}, "sys")
        for path, label in ((f"/pam/targets/{tid}/console", "the console"),
                            (f"/pam/targets/{tid}/console?win=1",
                             "the console in its own window")):
            r = c.get(path, follow_redirects=False)
            check(f"{label} renders with a keyboard bound ({r.status_code})",
                  r.status_code == 200
                  and "new Guacamole.Keyboard(document)" in r.text)
            check(f"{label} says the page's keyboard is the remote machine's",
                  FLAG_SET in r.text)

        pam.register_active("keys-live", {"who": "op@t.local", "target": "keys-desk",
                                          "target_id": tid, "address": "10.0.10.50",
                                          "protocol": "vnc"}, lambda: None)
        pam.set_guac_id("keys-live", "$keys")
        r = c.get("/pam/session/keys-live/shadow?mode=watch", follow_redirects=False)
        check(f"watching a live desktop renders ({r.status_code})",
              r.status_code == 200 and "Watching" in r.text)
        # A watcher has no keyboard, so the portal's own shortcuts are theirs.
        check("a watcher binds no keyboard and claims none",
              "new Guacamole.Keyboard(document)" not in r.text
              and FLAG_SET not in r.text)
        r = c.get("/pam/session/keys-live/shadow?mode=control", follow_redirects=False)
        check(f"taking control renders ({r.status_code})",
              r.status_code == 200 and "Taking" in r.text)
        check("taking control binds the keyboard, and says so",
              "new Guacamole.Keyboard(document)" in r.text and FLAG_SET in r.text)
        r = c.get("/pam?sec=targets")
        check("an ordinary page claims nothing",
              r.status_code == 200 and FLAG_SET not in r.text)
    finally:
        pam.guacd_reachable = keep
        pam.drop_active("keys-live")


def sweep() -> None:
    print("every page that gives the whole document's keyboard away says so")
    found = 0
    for page in sorted((ROOT / "templates").glob("*.html")):
        body = _strip(page.read_text())
        if re.search(r"new\s+Guacamole\.Keyboard\(\s*(document|window)\b", body):
            found += 1
            check(f"{page.name} binds a remote keyboard to the document and "
                  "sets data-remote-keyboard", FLAG_SET in body)
    check(f"the sweep found the console ({found} page)", found >= 1)


def main() -> int:
    slash()
    assistant()
    rendered()
    sweep()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main())
