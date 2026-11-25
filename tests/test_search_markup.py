#!/usr/bin/env python3
"""A search result is text, and stays text when the match is highlighted.

The server escaped every hit correctly; the page's own highlighter then undid
it. It read each hit's textContent — which the browser has already DECODED,
so `&lt;img src=x&gt;` is `<img src=x>` again — wrapped the match in <mark>,
and assigned the result to innerHTML. A config value in somebody's repository
became markup on the page of whoever searched for it. The CSP stops an inline
handler running, but not an element being drawn, a form being planted, or a
link that is not what it says.

Checked in two halves, because neither alone says it: the server's page is
read for the escaping, and the page's REAL highlighter is run under node
against hits built from that page, then the DOM it leaves is inspected — no
innerHTML assigned, no element made from a value, the text exactly as it was,
and the match still wrapped in <mark>.

    ./.venv/bin/python tests/test_search_markup.py
"""
from __future__ import annotations

import html
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("searchmk-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = pathlib.Path(__file__).resolve().parent / "domstub.js"
sys.path.insert(0, str(ROOT))

from app import auth, db, main, store                          # noqa: E402

bad = 0
VALUE = "<img src=x onerror=alert(1)> welcome to the storefront"
FILE = f"""namespace: shop-dev
name: storefront
config:
  WELCOME_BANNER: "{VALUE}"
  OPENING: "Storefront hours, nine to five"
  TIMEOUT: "30"
"""

# The page's hits, rebuilt in the stub the way the browser holds them: each
# line is a DIV whose content is a text NODE, and the text is the decoded one.
DRIVE = r"""
const {El} = require(STUB);
require(STUB).install({});
const made = HITS.map(h => {
  const a = new El('a'); a.classList.add('hit'); domRoot.appendChild(a);
  return ['h1', 'h3'].filter(k => h[k] !== null).map(k => {
    const d = new El('div'); d.classList.add(k);
    d.appendChild(document.createTextNode(h[k]));
    a.appendChild(d);
    return d;
  });
});
require(SCRIPT);
const walk = n => n.children.map(c => ({tag: c.tagName, text: c.textContent,
                                        html: c._html, kids: walk(c)}));
console.log(JSON.stringify(made.map(row => row.map(el => ({
  html: el._html, text: el.textContent, kids: walk(el)})))));
"""


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def plant() -> None:
    pid = store.add_project("Shop")
    rgid = store.add_region(pid, "one-region")
    root = store.repo_dir(pid, rgid)
    (root / "dev").mkdir(parents=True, exist_ok=True)
    (root / "dev" / "storefront-values.yaml").write_text(FILE)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # no url on purpose: these files are planted by hand, and a url the
    # fixture does not serve would let the absorb migration move the tree
    store.set_region_repo(pid, rgid, {"protocol": "https", "values_path": ""})


def search_page(q: str) -> str:
    from fastapi.testclient import TestClient
    uid = auth.create_user("search@test.local", "CI", "Search-Markup-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "search@test.local",
                           "password": "Search-Markup-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c.get(f"/search?q={q}").text


def hits_of(page: str) -> list[dict]:
    """Each hit's two highlightable lines, as the browser would decode them."""
    out = []
    for block in re.findall(r'<a class="hit"[^>]*>(.*?)</a>', page, re.S):
        h1 = re.search(r'<div class="h1">(.*?)</div>', block, re.S)
        h3 = re.search(r'<div class="h3">(.*?)</div>', block, re.S)
        out.append({"h1": html.unescape(h1.group(1)) if h1 else None,
                    "h3": html.unescape(h3.group(1)) if h3 else None})
    return out


def flat(nodes: list) -> list:
    return [n for x in nodes for n in [x] + flat(x["kids"])]


def main_test() -> int:
    plant()
    page = search_page("storefront")

    print("the server sends the value as text")
    check("the value is in the page, escaped",
          html.escape(VALUE, quote=False) in page
          or VALUE.replace("<", "&lt;").replace(">", "&gt;") in page)
    # script bodies are raw text to the parser, so only the markup counts
    markup = re.sub(r"<script\b.*?</script>", "", page, flags=re.S)
    check("and never as markup", "<img src=x" not in markup)
    hits = hits_of(page)
    check(f"the planted value is one of the hits ({len(hits)} found)",
          any(h["h3"] == VALUE for h in hits))

    node = shutil.which("node")
    if not node:
        print("node is not installed — the highlighter half is skipped")
        print("OK" if not bad else f"{bad} FAILED")
        return bad

    print("the page's own highlighter, run against those hits")
    scripts = re.findall(r"<script nonce=\"[^\"]*\">(.*?)</script>", page, re.S)
    mine = [s for s in scripts if ".hit .h1, .hit .h3" in s]
    check("the highlighter is on the page, nonced", len(mine) == 1)
    work = pathlib.Path(tempfile.mkdtemp(prefix="searchmk-"))
    (work / "highlight.js").write_text(mine[0] if mine else "")
    (work / "drive.js").write_text(
        f"const STUB = {json.dumps(str(STUB))};\n"
        f"const SCRIPT = {json.dumps(str(work / 'highlight.js'))};\n"
        f"const HITS = {json.dumps(hits)};\n" + DRIVE)
    got = subprocess.run([node, str(work / "drive.js")], capture_output=True,
                         text=True, timeout=60)
    shutil.rmtree(work, ignore_errors=True)
    why = next((ln for ln in got.stderr.splitlines() if "Error" in ln),
               got.stderr[-300:])
    check(f"it ran: {why!r}", got.returncode == 0)
    rows = json.loads(got.stdout or "[]")
    lines = [el for row in rows for el in row]
    check(f"no hit had innerHTML assigned: "
          f"{[el['html'] for el in lines if el['html']][:2]}",
          lines and not any(el["html"] for el in lines))
    check("no element was made out of a value",
          not any(n["tag"] == "IMG" for el in lines for n in flat(el["kids"])))
    before = [h[k] for h in hits for k in ("h1", "h3") if h[k] is not None]
    check("every line still reads exactly as it did",
          [el["text"] for el in lines] == before)
    banner = next((el for el in lines if el["text"] == VALUE), None)
    marks = [n for n in flat(banner["kids"]) if n["tag"] == "MARK"] if banner else []
    check(f"the match is still highlighted: {marks}",
          [m["text"] for m in marks] == ["storefront"])
    check("and the markup around it is text beside the mark",
          banner and banner["kids"][0]["tag"] == "TEXT"
          and banner["kids"][0]["text"].startswith("<img src=x"))
    upper = [el for el in lines
             if el["text"] == "Storefront hours, nine to five"]
    check("a match in a different case is highlighted in its own case",
          upper and [n["text"] for n in flat(upper[0]["kids"])
                     if n["tag"] == "MARK"] == ["Storefront"])

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
