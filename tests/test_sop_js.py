"""The SOP script, driven under node against an SOP the server rendered.

WHY THIS EXISTS
    Paste into shell types a command at a production prompt. What it types is
    decided in the browser, by the script in templates/_sop.html, and four of
    its rules are the kind a grep cannot check:

      * what reaches the prompt ends WITHOUT a newline -- nothing runs until
        the operator has read it and pressed Enter;
      * no control character reaches it, whatever the SOP says;
      * a command with a value still to fill in cannot be pasted at all,
        and says which value;
      * a block that is not a command (output, a config file) is offered for
        copying only.

    So the real script is rendered out of the real macro, the real markup is
    rendered from a real body by the server's own renderer, and both are
    driven under node against a DOM only as wide as the script uses.

    ./.venv/bin/python tests/test_sop_js.py
"""
from __future__ import annotations

import html.parser
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("sopjs-")

BAD = 0


def check(what: str, cond: bool, detail: str = "") -> None:
    global BAD
    print(("  ok  " if cond else "  FAIL ") + what
          + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        BAD += 1


# Every code point a script can hold as one character in the BMP, and the
# format characters beyond it (the tag block is the one a hidden instruction
# rides in), for the drift check below.
CPS = ([cp for cp in range(0x10000) if not 0xD800 <= cp <= 0xDFFF]
       + [0x110BD, 0x110CD, *range(0x13430, 0x13440), *range(0x1BCA0, 0x1BCA4),
          *range(0x1D173, 0x1D17B), *range(0xE0000, 0xE0080)])
LANGS = ["", "sh", "bash", "Bash", "shell", "zsh", "console", "output", "text",
         "nginx", "yaml", "json", "ps1", "fish"]

BODY = """\
Have the renewed files ready for {{DOMAIN}}.

## Check what is served
```
echo | openssl s_client -servername {{DOMAIN}} -connect 127.0.0.1:443
```

## Back up and look
```bash
cp -a {{CERT_PATH}} {{CERT_PATH}}.bak
ls -l {{CERT_PATH}}*
```

## What good looks like
```output
notAfter=Jan  1 00:00:00 2027 GMT
```

## No values needed
```
nginx -t
```"""


class Tree(html.parser.HTMLParser):
    """Markup -> {"t", "a", "c"} nodes and plain strings, for the stub DOM."""
    VOID = {"br", "img", "input", "hr", "meta", "link"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"t": "div", "a": {}, "c": []}
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"t": tag, "a": dict(attrs), "c": []}
        self.stack[-1]["c"].append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        while len(self.stack) > 1:
            if self.stack.pop()["t"] == tag:
                break

    def handle_data(self, data):
        self.stack[-1]["c"].append(data)


HARNESS = r"""
class N { constructor() { this.parentNode = null; this.childNodes = []; }
  get parentElement() { return this.parentNode; }
  remove() { const p = this.parentNode; if (!p) return;
    p.childNodes.splice(p.childNodes.indexOf(this), 1); this.parentNode = null; }
  replaceWith(n) { const p = this.parentNode, i = p.childNodes.indexOf(this);
    if (n.parentNode) n.remove(); p.childNodes.splice(i, 1, n);
    n.parentNode = p; this.parentNode = null; } }
class T extends N { constructor(v) { super(); this.nodeType = 3; this.nodeValue = v; }
  get textContent() { return this.nodeValue; } }
class E extends N {
  constructor(tag) { super(); this.nodeType = 1; this.tagName = tag.toUpperCase();
    this.dataset = {}; this.on = {}; this.className = ''; this.disabled = false;
    this.title = ''; this.value = ''; this.type = ''; }
  get classList() { const el = this, has = () => el.className.split(/\s+/).filter(Boolean);
    return { add: c => { if (!has().includes(c)) el.className = [...has(), c].join(' '); },
             remove: c => { el.className = has().filter(x => x !== c).join(' '); },
             contains: c => has().includes(c) }; }
  setAttribute(k, v) { v = String(v);
    if (k === 'class') this.className = v;
    else if (k.startsWith('data-')) this.dataset[k.slice(5).replace(/-(\w)/g, (m, c) => c.toUpperCase())] = v;
    else this[k] = v; }
  appendChild(n) { if (n.parentNode) n.remove(); n.parentNode = this; this.childNodes.push(n); return n; }
  append(...ns) { ns.forEach(n => this.appendChild(typeof n === 'string' ? new T(n) : n)); }
  insertBefore(n, ref) { if (n.parentNode) n.remove(); const i = this.childNodes.indexOf(ref);
    n.parentNode = this; this.childNodes.splice(i < 0 ? this.childNodes.length : i, 0, n); return n; }
  get textContent() { return this.childNodes.map(n => n.textContent).join(''); }
  set textContent(v) { this.childNodes.forEach(n => { n.parentNode = null; });
    this.childNodes = []; if (v !== '' && v != null) this.appendChild(new T(String(v))); }
  matches(sel) { return sel.split(',').some(s => { s = s.trim();
    return s[0] === '.' ? this.className.split(/\s+/).includes(s.slice(1))
                        : this.tagName === s.toUpperCase(); }); }
  closest(sel) { for (let e = this; e && e.nodeType === 1; e = e.parentNode)
    if (e.matches(sel)) return e; return null; }
  all() { const out = []; const walk = n => n.childNodes.forEach(c => {
    if (c.nodeType === 1) { out.push(c); walk(c); } }); walk(this); return out; }
  querySelectorAll(sel) { const p = sel.trim().split(/\s+/);
    if (p.length === 1) return this.all().filter(e => e.matches(p[0]));
    return this.all().filter(e => e.matches(p[1]) && e.parentNode && e.parentNode.closest(p[0])); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  addEventListener(t, f) { (this.on[t] = this.on[t] || []).push(f); }
  fire(t, extra) { (this.on[t] || []).forEach(f => f(Object.assign(
    {type: t, target: this, preventDefault() {}}, extra || {}))); }
  focus() { document.activeElement = this; } }

const texts = n => { const out = []; const walk = x => x.childNodes.forEach(c => {
  if (c.nodeType === 3) out.push(c); else walk(c); }); walk(n); return out; };
global.NodeFilter = {SHOW_TEXT: 4};
global.document = { body: new E('body'), activeElement: null,
  createElement: t => new E(t), createTextNode: v => new T(v),
  createTreeWalker: root => { const list = texts(root); let i = -1;
    return { get currentNode() { return list[i]; }, nextNode() { return list[++i] || null; } }; },
  execCommand: () => false };
global.window = global;
global.isSecureContext = true;
const copied = [];
Object.defineProperty(global, 'navigator', { value: { clipboard: {
  writeText: t => { copied.push(t); return Promise.resolve(); } } } });

function build(node) {
  if (typeof node === 'string') return new T(node);
  const el = new E(node.t);
  Object.entries(node.a).forEach(([k, v]) => el.setAttribute(k, v == null ? '' : v));
  node.c.forEach(c => el.appendChild(build(c)));
  return el;
}

const IN = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
eval(IN.script);
const kit = window.sopKit, out = {};

out.holes = kit.holes('a {{DOMAIN}} {{.Name}} {{end}} {{ lower }} {{DOMAIN}} {{KEY_PATH}}');
out.fill = kit.fill('cp {{A}} {{B}}', {A: '  /etc/x.pem ', B: '   '});
out.missing = kit.missing('cp {{A}} {{B}}', {A: 'x'});
out.forShell = kit.forShell('\n\nls\x1b[201~\r\nrm\x07 x\u202e\u200b\tz\n\n');
out.isCommand = ['', 'bash', 'SH', 'zsh', 'output', 'nginx', 'console'].map(kit.isCommand);

const root = build(IN.tree);
const pasted = [];
let why = '';
const api = window.sopWire(root, { paste: t => { pasted.push(t); return true; },
                                   pasteWhy: () => why });
out.wiredTwiceIsOnce = window.sopWire(root, {}) === api;
const boxes = root.querySelectorAll('.sop-cmd');
out.kinds = boxes.map(b => b.querySelector('.sop-kind').textContent);
out.copyButtons = root.querySelectorAll('.sop-copy').length;
out.pasteOn = boxes.map(b => !!b.querySelector('.sop-paste'));
const inputs = root.querySelector('.sop-fill').querySelectorAll('input');
out.fields = root.querySelector('.sop-fill').querySelectorAll('span').map(s => s.textContent);
const paste = i => boxes[i].querySelector('.sop-paste');
out.before = [0, 1, 3].map(i => [paste(i).disabled, paste(i).title]);

paste(0).fire('click');                       // disabled: the script itself refuses
out.pastedWhileDisabled = pasted.length;
out.notCommand = [paste(2).disabled, paste(2).title];
paste(2).fire('click');
out.pastedOutput = pasted.length;

inputs[0].value = 'wallet.example.test';  inputs[0].fire('input');
out.afterDomain = [0, 1].map(i => [paste(i).disabled, paste(i).title]);
paste(0).fire('click');
inputs[1].value = '/etc/nginx/ssl/site.crt'; inputs[1].fire('input');
paste(1).fire('click');
out.pasted = pasted.slice();
out.shown = boxes[0].querySelector('pre').textContent;
out.prose = root.querySelector('.sop-intro').textContent;

why = 'the focused tab is still connecting'; api.refresh();
out.whyWins = [paste(3).disabled, paste(3).title];
why = ''; api.refresh();
out.whyCleared = paste(3).disabled;

boxes[2].querySelector('.sop-copy').fire('click');
// The server's rules, asked of the browser's: which code points a paste drops,
// and which fence languages are commands.
out.dropped = IN.cps.map(cp => kit.clean(String.fromCodePoint(cp)) === '' ? '1' : '0').join('');
out.commands = IN.langs.map(kit.isCommand);
setTimeout(() => { out.copied = copied.slice(); console.log(JSON.stringify(out)); }, 20);
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the SOP script")
        print("OK")
        return 0
    from app import main as app_main, sops
    env = app_main.templates.env
    mod = env.get_template("_sop.html").module
    script = re.search(r"<script[^>]*>(.*)</script>", str(mod.script()), re.S)
    if not script:
        print("  FAIL _sop.html renders no script")
        return 1
    tree = Tree()
    tree.feed(str(mod.doc(sops.steps(BODY, app_main._mdlite))))

    work = pathlib.Path(tempfile.mkdtemp(prefix="sopjs-"))
    (work / "in.json").write_text(json.dumps({"script": script.group(1),
                                              "tree": tree.root,
                                              "cps": CPS, "langs": LANGS}))
    (work / "drive.js").write_text(HARNESS)
    got = subprocess.run([node, str(work / "drive.js"), str(work / "in.json")],
                         capture_output=True, text=True, timeout=30)
    if got.returncode != 0 or not got.stdout.strip():
        print("  FAIL the script threw under node\n" + got.stderr[-2000:])
        return 1
    o = json.loads(got.stdout.strip().splitlines()[-1])

    print("the helpers")
    check("a placeholder is UPPER_CASE in double braces, and only that",
          o["holes"] == ["DOMAIN", "KEY_PATH"], str(o["holes"]))
    check("filling trims, and leaves a blank value as its placeholder",
          o["fill"] == "cp /etc/x.pem {{B}}", o["fill"])
    check("it says which values are still missing", o["missing"] == ["B"],
          str(o["missing"]))
    check("what reaches the prompt has no control character and NO trailing "
          "newline", o["forShell"] == "ls[201~\nrm x\tz", repr(o["forShell"]))
    check("a command is a fence with no language or a shell's",
          o["isCommand"] == [True, True, True, True, False, False, False],
          str(o["isCommand"]))

    print("the wiring, on the server's own markup")
    check("wiring the same SOP twice wires it once", o["wiredTwiceIsOnce"])
    check("every block is labelled for what it is",
          o["kinds"] == ["command", "command", "output", "command"], str(o["kinds"]))
    check("every block can be copied", o["copyButtons"] == 4)
    check("every block has Paste where there is a shell, so Copy never moves",
          o["pasteOn"] == [True, True, True, True], str(o["pasteOn"]))
    check("and on one that is not a command it is disabled and says why",
          o["notCommand"] == [True, "this is output, not a command — copy it instead"],
          str(o["notCommand"]))
    check("so output is never pasted", o["pastedOutput"] == 0)
    check("one field per value, in the order the SOP first uses them",
          o["fields"] == ["DOMAIN", "CERT_PATH"], str(o["fields"]))
    check("a command waiting on a value cannot be pasted, and says which",
          o["before"][0] == [True, "fill in DOMAIN first"]
          and o["before"][1] == [True, "fill in CERT_PATH first"], str(o["before"]))
    check("one that needs nothing can", o["before"][2][0] is False,
          str(o["before"][2]))
    check("a disabled Paste pastes nothing even when clicked",
          o["pastedWhileDisabled"] == 0)
    check("filling a value frees the commands that wait on it — and only those",
          o["afterDomain"][0][0] is False and o["afterDomain"][1][0] is True,
          str(o["afterDomain"]))
    check("the command pasted carries the values, and no newline after it",
          o["pasted"] == [
              "echo | openssl s_client -servername wallet.example.test "
              "-connect 127.0.0.1:443",
              "cp -a /etc/nginx/ssl/site.crt /etc/nginx/ssl/site.crt.bak\n"
              "ls -l /etc/nginx/ssl/site.crt*"], json.dumps(o["pasted"]))
    check("the block shows what will be pasted", "wallet.example.test" in o["shown"]
          and "{{DOMAIN}}" not in o["shown"], o["shown"])
    check("a value written in the prose is filled in there too",
          "wallet.example.test" in o["prose"], o["prose"])
    check("the terminal's reason wins over everything",
          o["whyWins"] == [True, "the focused tab is still connecting"],
          str(o["whyWins"]))
    check("and clears with it", o["whyCleared"] is False)
    check("Copy takes the block as text",
          o["copied"] == ["notAfter=Jan  1 00:00:00 2027 GMT"], str(o["copied"]))

    print("the browser and the server agree")
    # The strip itself: the server's clean() also turns a CR into a newline
    # first, which the browser does in forShell(), not in clean().
    want = "".join("1" if sops._strip(chr(cp)) == "" else "0" for cp in CPS)
    off = [hex(CPS[i]) for i, (a, b) in enumerate(zip(o["dropped"], want)) if a != b]
    check(f"a paste drops exactly what a save strips ({want.count('1')} code "
          f"points)", not off and len(o["dropped"]) == len(want), str(off[:12]))
    check("and a command is the same fence language on both sides",
          o["commands"] == [sops.is_command(x) for x in LANGS], str(o["commands"]))
    print("OK" if not BAD else f"{BAD} FAILED")
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
