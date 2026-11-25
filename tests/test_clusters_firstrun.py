#!/usr/bin/env python3
"""A new installation can reach its first region and its first cluster.

WHY THIS EXISTS
    Settings → Clusters rendered a project with no clusters as `hidden` — the
    rule was meant for a filter or a search that leaves a project empty, and it
    caught the empty project as well. A project's "＋ add a cluster" and
    "regions & environments" sit on its own line, so on a fresh install — one
    project, nothing else — the page was a card with a search box in it and no
    way in at all. Every other route was broken the same day: "＋ Add region"
    linked to `#<pid>`, which nothing on the page answered; the message after
    creating a project said "now add a region" on a page that cannot add one;
    and opening the regions panel on a shut project un-hid it inside a body
    that stayed hidden, so the click drew nothing.

    So this walks the first run through the real routes and checks the page the
    way a person meets it: is the control there, and is anything above it
    hidden. Then the page's own script is run under node against the markup the
    server rendered, because whether an anchor opens what it names is
    behaviour, and a string search cannot tell "written" from "works".

    ./.venv/bin/python tests/test_clusters_firstrun.py
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
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("firstrun-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, main, store                          # noqa: E402

STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"
BAD = 0


def check(what: str, cond: bool, detail: str = "") -> None:
    global BAD
    print(("  ok   " if cond else "  FAIL ") + what
          + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        BAD += 1


class Tree(html.parser.HTMLParser):
    """Markup -> {"t", "a", "c"} nodes and strings, close to how a browser
    nests it: void elements never hold children, and a stray end tag closes
    nothing rather than everything."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"t": "body", "a": {}, "c": [], "up": None}
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"t": tag, "a": dict(attrs), "c": [], "up": self.stack[-1]}
        self.stack[-1]["c"].append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if tag in self.VOID or not any(n["t"] == tag for n in self.stack[1:]):
            return
        while self.stack.pop()["t"] != tag:
            pass

    def handle_data(self, data):
        self.stack[-1]["c"].append(data)


def parse(page: str) -> dict:
    t = Tree()
    t.feed(page)
    return t.root


def walk(n: dict):
    yield n
    for c in n["c"]:
        if isinstance(c, dict):
            yield from walk(c)


def find(root: dict, **want) -> list:
    """Elements whose attributes equal everything in `want` (`cls` matches
    one class; a value of None means the attribute must be absent)."""
    out = []
    for n in walk(root):
        a = n["a"]
        ok = True
        for k, v in want.items():
            if k == "cls":
                ok = v in (a.get("class") or "").split()
            elif k == "tag":
                ok = n["t"] == v
            elif v is None:
                ok = k.replace("_", "-") not in a
            else:
                ok = a.get(k.replace("_", "-")) == v
            if not ok:
                break
        if ok:
            out.append(n)
    return out


def hidden_on_the_way(n: dict) -> str:
    """The first element from `n` up to the root that is hidden, or ""."""
    while n:
        if "hidden" in n["a"]:
            return f'<{n["t"]} class="{n["a"].get("class", "")}" ' \
                   f'id="{n["a"].get("id", "")}">'
        n = n["up"]
    return ""


def inside(n: dict, anc: dict) -> bool:
    while n:
        if n is anc:
            return True
        n = n["up"]
    return False


def fragment(r) -> str:
    return urllib.parse.urlsplit(r.headers.get("location", "")).fragment


def ids(root: dict) -> set:
    return {n["a"]["id"] for n in walk(root) if n["a"].get("id")}


# ── the page's own script, run under node against the rendered markup ─────
DRIVE = r"""
const fs = require('fs'), vm = require('vm');
const {install, El} = require(STUB);
const TREE = JSON.parse(fs.readFileSync(TREEFILE, 'utf8'));
// the page exactly as a new installation first sees it: one empty project
const TREE0 = JSON.parse(fs.readFileSync(TREE0FILE, 'utf8'));
const CODE = fs.readFileSync(CODEFILE, 'utf8');
const K = JSON.parse(fs.readFileSync(KEYSFILE, 'utf8'));
let bad = 0;
const ok = (what, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + what);
                             if (!cond) bad++; };

const camel = s => s.replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
function build(n, parent) {
  if (typeof n === 'string') { parent._text += n; return; }
  if (n.t === 'script' || n.t === 'style') return;
  const el = new El(n.t);
  for (const [k, raw] of Object.entries(n.a)) {
    const v = raw === null ? '' : raw;
    el.attributes[k] = v;
    if (k === 'class') el.className = v;
    else if (k === 'id') byId[v] = el;
    else if (k === 'hidden') el.hidden = true;
    else if (k === 'value') el.value = v;
    else if (k === 'type') el.type = v;
    else if (k.startsWith('data-')) el.dataset[camel(k.slice(5))] = v;
  }
  parent.appendChild(el);
  n.c.forEach(c => build(c, el));
}

let scrolled = [], clicked = [];
function fresh(hash, q, tree) {
  install({});
  scrolled = []; clicked = [];
  El.prototype.scrollIntoView = function () { scrolled.push(this); };
  global.CSS = {escape: s => String(s)};
  location.hash = hash || '';
  (tree || TREE).c.forEach(n => build(n, domRoot));
  if (q !== undefined) byId.clfind.value = q;
  // what the cluster window would have been asked to open
  document.addEventListener('click', ev => {
    const b = ev.target.closest && ev.target.closest('[data-clform]');
    if (b) clicked.push(b.getAttribute('data-clcid') || 'add');
  });
  vm.runInThisContext(CODE, {filename: 'set_clusters.html'});
}
// Found by what exists before AND after the fix, so reverting it fails a
// check instead of throwing in the harness.
const proj = name => document.querySelector(`.cl-proj[data-project="${name}"]`);
const body = p => p.querySelector('.cl-projbody');
const panel = pid => byId['regenv-' + pid];
const seen = el => { for (let n = el; n; n = n.parentNode) if (n.hidden) return false;
                     return true; };
const addForm = pid => document.querySelector(
  `form[action="/settings/project/${pid}/region/new"]`);
const region = (pid, rgid) => document.querySelector(
  `form[action="/settings/project/${pid}/region/${rgid}/env/add"]`).closest('.cl-envregion');
const caretIn = form => !!document.activeElement
  && document.activeElement.getAttribute('name') === 'name'
  && document.activeElement.closest('form') === form;

console.log('a new installation: one project, nothing in it, nothing else');
fresh('', undefined, TREE0);
const P0 = proj(K.first_name);
ok('the project is on the page', !!P0 && !P0.hidden);
const tog0 = document.querySelector(`[data-for="regenv-${K.first}"]`);
tog0.click();
ok('"regions & environments" opens it, add-a-region form and all',
   !body(P0).hidden && seen(addForm(K.first)) && caretIn(addForm(K.first)));
const box0 = byId.clfind;
box0.value = 'anything';
box0.fire('input');
ok('a search finds nothing and says so', P0.hidden && !byId.clnone.hidden);
box0.value = '';
box0.fire('input');
ok('cleared, the project is back', P0.hidden === false);
ok('and "Nothing matches" is gone — with no clusters at all, an empty box is '
   + 'not a filter that failed', byId.clnone.hidden === true);

console.log('a project with no clusters arrives with its own way in');
fresh('');
let P = proj(K.empty_name);
ok('it is on the page', !!P && !P.hidden);
const add = document.querySelector(`[data-clform][data-clpid="${K.empty}"]`);
ok('its "＋ add a cluster" can be seen', !!add && seen(add)
   && !add.getAttribute('data-clcid'));
const tog = document.querySelector(`[data-for="regenv-${K.empty}"]`);
ok('and so can its "regions & environments"', !!tog && seen(tog));
ok('it still arrives SHUT — collapsible, like every other project',
   body(P).hidden === true);

console.log('the regions panel opens its project');
tog.click();
ok('pressing it on a shut project opens the project', !body(P).hidden);
ok('and the panel inside it can be seen', seen(panel(K.empty)));
ok('with the caret in the region name, not in a hidden field',
   caretIn(addForm(K.empty)));
tog.click();
ok('pressing it again shuts the panel', panel(K.empty).hidden === true);
ok('and leaves the project open, which is where the person still is',
   !body(P).hidden);
tog.click();
P.querySelector('.cl-projhead').click();
ok('(shutting the project hides the panel with it)', !seen(panel(K.empty)));
tog.click();
ok('a panel left open inside a project shut since is OPENED by the next press, '
   + 'not closed by it', seen(panel(K.empty)));

console.log('every anchor that lands here opens what it names');
fresh('#' + K.empty);
P = proj(K.empty_name);
ok('#<pid> opens that project', !P.hidden && !body(P).hidden
   && P.querySelector('.cl-projhead').getAttribute('aria-expanded') === 'true');
ok('and scrolls to it', scrolled.includes(P));
ok('and opens nothing else',
   body(proj(K.full_name)).hidden === true && panel(K.empty).hidden === true);

fresh('#regenv-' + K.empty);
ok('#regenv-<pid> opens the project AND its panel',
   !body(proj(K.empty_name)).hidden && seen(panel(K.empty)));

fresh('#newrg-' + K.empty);
const regionName = pid => addForm(pid).querySelector('input[name="name"]');
ok('#newrg-<pid> — a new project, and "＋ Add region" — shows the add-a-region '
   + 'form', seen(addForm(K.empty)));
ok('scrolled to its region-name field', scrolled.includes(regionName(K.empty)));
ok('with the caret in it', caretIn(addForm(K.empty)));

fresh('');
location.hash = '#newrg-' + K.empty;
dispatchWindow('hashchange');
ok('the same anchor followed WITHIN the page — a hash change, not a load — '
   + 'opens the form and puts the caret in it',
   seen(addForm(K.empty)) && caretIn(addForm(K.empty)));

fresh('#' + K.rgid);
const R = region(K.full, K.rgid);
ok('#<rgid> — after adding a region or declaring an environment — opens that '
   + 'region inside its panel', seen(R));
ok('and scrolls to the region itself', scrolled.includes(R));

fresh('#' + K.full);
ok('#<pid> on a project with clusters opens it too — every cluster save lands '
   + 'there', !body(proj(K.full_name)).hidden);

fresh('#ed-' + K.cid, 'zzz-matches-nothing');
ok('#ed-<cid> still clears a search that would hide it',
   byId.clfind.value === '');
ok('opens the project it is in', !body(proj(K.full_name)).hidden);
ok('and asks the window for that cluster', clicked.join() === K.cid);

fresh('#clusters');
ok('#clusters — the tiles — is left to the browser: nothing is opened',
   [...document.querySelectorAll('.cl-projbody')].every(b => b.hidden));

console.log('a search hides an empty project only while it is typed');
fresh('');
const box = byId.clfind;
box.value = 'zzz-matches-nothing';
box.fire('input');
ok('a search that leaves nothing in a project hides it',
   proj(K.empty_name).hidden === true && proj(K.full_name).hidden === true);
ok('and says nothing matches', byId.clnone.hidden === false);
box.value = K.cluster_name;
box.fire('input');
ok('a search that matches opens the project it matched in',
   !proj(K.full_name).hidden && !body(proj(K.full_name)).hidden);
ok('and hides the empty one, which has nothing to match',
   proj(K.empty_name).hidden === true);
box.value = '';
box.fire('input');
ok('clearing it gives the empty project back — it was never the search\'s to '
   + 'keep', proj(K.empty_name).hidden === false);
ok('and "Nothing matches" goes with the search, rather than staying on a page '
   + 'with nothing typed', byId.clnone.hidden === true);

console.log(bad ? (bad + ' FAILED') : '  the anchors and the panel behave');
process.exit(bad ? 1 : 0);
"""


def drive_js(first_page: str, page: str, keys: dict) -> None:
    node = shutil.which("node")
    if not node:
        print("node is not installed — skipping the in-page behaviour")
        return
    scripts = re.findall(r'<script nonce="[^"]+">(.*?)</script>', page, re.S)
    code = [s for s in scripts if "const openNamed" in s]
    check("the page carries its own script, nonce'd", len(code) == 1)
    if not code:
        return

    def plain(n):
        return n if isinstance(n, str) else {
            "t": n["t"], "a": n["a"], "c": [plain(c) for c in n["c"]]}

    work = pathlib.Path(tempfile.mkdtemp(prefix="firstrun-js-"))
    try:
        (work / "tree.json").write_text(json.dumps(plain(parse(page))))
        (work / "tree0.json").write_text(json.dumps(plain(parse(first_page))))
        (work / "code.js").write_text(code[0])
        (work / "keys.json").write_text(json.dumps(keys))
        (work / "drive.js").write_text(
            f"const STUB = {json.dumps(str(STUB))};\n"
            f"const TREEFILE = {json.dumps(str(work / 'tree.json'))};\n"
            f"const TREE0FILE = {json.dumps(str(work / 'tree0.json'))};\n"
            f"const CODEFILE = {json.dumps(str(work / 'code.js'))};\n"
            f"const KEYSFILE = {json.dumps(str(work / 'keys.json'))};\n"
            + DRIVE)
        got = subprocess.run([node, str(work / "drive.js")],
                             capture_output=True, text=True, timeout=120)
        sys.stdout.write(got.stdout)
        if got.returncode and got.stderr:
            # A stub gap throws; a real fault prints its own FAIL lines.
            sys.stdout.write(got.stderr[-1500:] + "\n")
        check("the page's script behaved under node", got.returncode == 0)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main_test() -> int:
    uid = auth.create_user("first@t.local", "N", "First-Run-Please-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "first@t.local",
                           "password": "First-Run-Please-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    print("a project, created the way a new installation creates its first")
    r = c.post("/settings/project/new", data={"name": "Payments"},
               follow_redirects=False)
    pid = next(p for p, v in store.projects().items()
               if v.get("name") == "Payments")
    loc = urllib.parse.unquote_plus(r.headers.get("location", ""))
    check("creating it says what is next", r.status_code == 303
          and "now add a region" in loc)
    check("and goes THERE — the clusters page, at the new project's add-a-region "
          "form — rather than back to a page with no way to add one",
          loc.startswith("/settings/clusters?")
          and fragment(r) == f"newrg-{pid}", loc)

    print("Settings → Clusters with one empty project and nothing else")
    page = first_page = c.get("/settings/clusters").text
    root = parse(page)
    projs = find(root, cls="cl-proj")
    check("the page renders one project", len(projs) == 1)
    P = next(iter(find(root, cls="cl-proj", data_project="payments")), None)
    check("the project is NOT hidden — empty is not the same as filtered out",
          P is not None and not hidden_on_the_way(P),
          P and hidden_on_the_way(P))
    adds = [n for n in find(root, data_clpid=pid, data_clcid=None)
            if "data-clform" in n["a"]]
    check("its '＋ add a cluster' is on the page", len(adds) == 1)
    above = hidden_on_the_way(adds[0]) if adds else "(no button)"
    check("and nothing above it is hidden", not above, above)
    togs = find(root, data_for=f"regenv-{pid}")
    check("its 'regions & environments' is on the page, nothing above it "
          "hidden", len(togs) == 1 and not hidden_on_the_way(togs[0]))
    pan = next(iter(find(root, id=f"regenv-{pid}")), None)
    check("the panel it opens holds the add-a-region form",
          pan is not None and any(inside(f, pan) for f in find(
              root, tag="form", action=f"/settings/project/{pid}/region/new")))
    # The anchor names the FIELD: a browser focuses a fragment's target itself
    # once it arrives, and a <form> cannot hold focus — so naming the form left
    # the caret nowhere, in a real browser, while every stub said otherwise.
    named = next(iter(find(root, id=f"newrg-{pid}")), None)
    rform = next(iter(find(root, tag="form",
                           action=f"/settings/project/{pid}/region/new")), None)
    check("and what the creation redirect names is that form's region-name "
          "field, which can take the caret",
          named is not None and rform is not None and named["t"] == "input"
          and named["a"].get("name") == "name" and inside(named, rform))
    flat = " ".join(page.split())
    check("opened, the empty project says what to do rather than showing a "
          "header row and nothing", "No clusters in Payments yet" in flat
          and "add its first region" in flat)
    none = next(iter(find(root, id="clnone")), None)
    check("'Nothing matches' is not shown — nothing was filtered",
          none is not None and "hidden" in none["a"])

    print("a tile filter still hides what it leaves empty — and says so")
    froot = parse(c.get("/settings/clusters?show=manage").text)
    fp = next(iter(find(froot, cls="cl-proj", data_project="payments")), None)
    check("under a filter the empty project is hidden, as before",
          fp is not None and "hidden" in fp["a"])
    fn = next(iter(find(froot, id="clnone")), None)
    check("and the page says nothing matches instead of showing an empty card",
          fn is not None and "hidden" not in fn["a"])

    print("the project page's '＋ Add region' goes to the add-a-region form")
    proot = parse(c.get(f"/p/{pid}").text)
    def text(n):
        return "".join(x for x in n["c"] if isinstance(x, str))

    links = [n["a"]["href"] for n in find(proot, tag="a")
             if "Add region" in text(n)]
    check(f"both of them ({links})", len(links) == 2 and all(
        h == f"/settings/clusters#newrg-{pid}" for h in links))

    print("each step of the first run lands where it was taken")
    r = c.post(f"/settings/project/{pid}/region/new",
               data={"name": "KE", "back": "/settings/clusters"},
               follow_redirects=False)
    rgid = fragment(r)
    check("adding a region lands on that region", rgid.startswith("rg-")
          and rgid in (store.get_project(pid) or {}).get("regions", {}))
    r = c.post(f"/settings/project/{pid}/region/{rgid}/env/add",
               data={"name": "dev", "gitops_path": "envs/dev"},
               follow_redirects=False)
    check("declaring an environment lands back on its region, not on a "
          "'#mapping' the page no longer has", fragment(r) == rgid,
          fragment(r))
    r = c.post(f"/settings/project/{pid}/region/{rgid}/env/add",
               data={"name": ""}, follow_redirects=False)
    check("and so does a refusal, where the form is", fragment(r) == rgid)
    r = c.post(f"/settings/project/{pid}/region/{rgid}/env/sync",
               data={"name": "dev"}, follow_redirects=False)
    check("syncing one lands on its region too", fragment(r) == rgid)
    r = c.post(f"/settings/project/{pid}/region/{rgid}/env/hide",
               data={"name": "dev"}, follow_redirects=False)
    check("as does undeclaring one", fragment(r) == rgid)
    spare = store.add_region(pid, "TZ")
    r = c.post(f"/settings/project/{pid}/region/{spare}/delete",
               follow_redirects=False)
    check("removing a region lands back in the panel it was removed from",
          fragment(r) == f"regenv-{pid}", fragment(r))
    r = c.post(f"/settings/project/{pid}/cluster/new",
               data={"name": "first-cluster"}, follow_redirects=False)
    check("adding a cluster lands on its project", fragment(r) == pid)
    cid = next(iter((store.get_project(pid) or {}).get("clusters", {})))
    landed = ids(parse(c.get("/settings/clusters").text))
    check("and every one of those anchors names something on the page — the "
          "project, its panel, its add-a-region form and the region",
          {pid, f"regenv-{pid}", f"newrg-{pid}", rgid} <= landed,
          sorted({pid, f"regenv-{pid}", f"newrg-{pid}", rgid} - landed))
    r = c.post(f"/settings/project/{pid}/cluster/{cid}/delete",
               follow_redirects=False)
    check("(removing that cluster lands on the project too)",
          fragment(r) == pid)

    print("the page's own script, driven against what the server rendered")
    # "Hollow" is the fresh-install shape — no region, no cluster — beside a
    # project with something in it: the anchors have to open the project they
    # NAME, and the search has to tell the two apart. Payments, emptied again
    # above, is a third: a region and no cluster.
    empty = store.add_project("Hollow")
    full = store.add_project("Ledger")
    frg = store.add_region(full, "UAE")
    fcid = store.add_cluster(full, "ledger-dev-cluster", "", "ctx-ledger")
    store.set_env_source(full, frg, "dev", {"path": "envs/dev"})
    store.map_env_cluster(full, frg, "dev", fcid)
    # the GitOps repos board says the same thing about a project with no
    # region, and its link has to land on the same form
    broot = parse(c.get("/repos").text)
    blinks = [n["a"].get("href") for n in find(broot, tag="a")
              if "add one in Settings" in text(n)]
    check(f"the repos board's 'add one in Settings' goes to the add-a-region "
          f"form ({blinks})", f"/settings/clusters#newrg-{empty}" in blinks)
    page = c.get("/settings/clusters").text
    drive_js(first_page, page, {
        "first": pid, "first_name": "payments", "empty": empty,
        "empty_name": "hollow", "full": full, "full_name": "ledger",
        "rgid": frg, "cid": fcid, "cluster_name": "ledger-dev"})

    print("\nFAILED" if BAD else "\nOK")
    return 1 if BAD else 0


if __name__ == "__main__":
    raise SystemExit(main_test())
