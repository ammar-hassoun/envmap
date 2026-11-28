#!/usr/bin/env python3
"""Search and filters on the Hypervisors and Server hardware lists (0.7.71).

Asked for on 25 November 2026: "in the VMs page and in the hardware page we
need some filters and search". The rule lives twice — app/listfilter.py
filters the first paint, static/listfilter.js filters as you type — so the
check that matters most is that the two agree:

  1. the bar is drawn with a count on every option
  2. a search, a facet, both, the address from before 0.7.71
     (?stopped_only=1) and an IP address each show the right rows, open the
     cards they matched and step the others aside
  3. a value the page does not offer (a hypervisor since removed) is ignored
  4. "One list" puts every guest in one table and is remembered
  5. nothing matching says so, and the charts' slices link to filters
  6. Server hardware: health, power, OS, the BMC's address, words in any
     order, and the Runs facet once the chain is known
  7. a hostile VM name stays text in the row, the haystack and the bar
  8. PARITY: the script's own core, run under node against the rows each
     page rendered, hides exactly the rows the server hid and counts every
     option the same — for every query here

    ./.venv/bin/python tests/test_list_filters.py
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
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("listfilter-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAILED: list[str] = []


def check(what: str, ok) -> None:
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        FAILED.append(what)


HOSTILE = '<b onmouseover=x>evil</b>'


def _guest(name, gid, host, state, kind="VM", ip="", mem=4.0, cpu=None):
    return {"name": name, "id": gid, "host": host, "kind": kind, "state": state,
            "cpu_pct": cpu, "cores": 2, "mem_gib": mem, "mem_pct": None,
            "disk_gib": 40.0, "uptime": "", "uptime_s": 0, "url": "", "ip": ip}


VIRT = {
    "esx-a": {"hosts": [{"name": "esx-a.lab", "state": "connected", "cpu_pct": 21.4,
                         "cores": 32, "mem_pct": 41.8, "mem_gib": 512.0,
                         "uptime": "3d", "extra": "", "url": ""}],
              "guests": [_guest("web-1", "vm-1", "esx-a.lab", "On", ip="10.1.2.3", mem=4, cpu=12.5),
                         _guest("db-1", "vm-2", "esx-a.lab", "Off", mem=16),
                         _guest("golden", "vm-3", "esx-a.lab", "Off", kind="template", mem=2),
                         _guest(HOSTILE, "vm-4", "esx-a.lab", "Off", mem=1)],
              "kind": "ESXi"},
    "pve-1": {"hosts": [{"name": "n1", "state": "online", "cpu_pct": 3.0, "cores": 8,
                         "mem_pct": 20.0, "mem_gib": 64.0, "uptime": "9d", "extra": "", "url": ""},
                        {"name": "n2", "state": "online", "cpu_pct": 4.0, "cores": 8,
                         "mem_pct": 30.0, "mem_gib": 64.0, "uptime": "9d", "extra": "", "url": ""}],
              "guests": [_guest("app-1", "101", "n1", "running", mem=8, cpu=40.0),
                         _guest("ct-1", "102", "n2", "stopped", kind="container", mem=1)],
              "kind": "Proxmox"},
}
for _d in VIRT.values():
    _d["running"] = sum(1 for g in _d["guests"] if g["state"].lower() in ("on", "running"))
    _d["stopped"] = len(_d["guests"]) - _d["running"]


def _bmc_info(vendor, model, serial, power, health, os_label="", hot=None, watts=None,
              hostname=""):
    return {"vendor": vendor, "model": model, "serial": serial, "sku": "", "uuid": "",
            "hostname": hostname, "os": os_label, "os_name": "", "os_version": "",
            "power": power, "health": health, "bios": "", "cpu_count": 2,
            "cpu_model": "", "memory_gib": 256, "leds": "", "sensors": [],
            "fans": [], "psus": [], "firmware": [], "url": "",
            "hottest": hot, "watts": watts, "ok": health.upper() in ("OK", "")}


BMC = {
    "db-01": _bmc_info("Dell Inc.", "PowerEdge R650", "ABC123", "On", "OK",
                       "Rocky Linux 9.4", 61, 420, hostname="db01.lab"),
    "db-02": _bmc_info("Dell Inc.", "PowerEdge R650", "DEF456", "On", "Warning", "", 70, 455),
    "esx-01": _bmc_info("HPE", "ProLiant DL380 Gen10", "GHI789", "Off", "OK",
                        "ESXi 8.0 U3", 30, 0),
}


# ── reading what a page rendered ───────────────────────────────

def rows_of(page: str) -> list[dict]:
    """Every [data-fr] row: its haystack, facets, name and whether it is
    hidden — the exact attributes the script reads."""
    out = []
    for m in re.finditer(r"<tr data-fr([^>]*)>", page):
        attrs = dict((k, html.unescape(v)) for k, v in
                     re.findall(r'\s([a-z][a-z0-9-]*)="([^"]*)"', m.group(1)))
        flags = re.findall(r"\s(hidden)\b(?!=)", m.group(1))
        out.append({"hay": attrs.get("data-hay", ""),
                    "f": {k[7:]: v for k, v in attrs.items() if k.startswith("data-f-")},
                    "name": attrs.get("data-s-name", ""), "hidden": bool(flags)})
    return out


def shown(page: str) -> set:
    return {r["name"] for r in rows_of(page) if not r["hidden"]}


def bar_state(page: str) -> dict:
    """The bar as rendered: the search, every facet's chosen value and every
    option's count."""
    bar = page.split("data-fbar", 1)[1].split("</form>", 1)[0]
    q = html.unescape(re.search(r'name="q" value="([^"]*)"', bar).group(1))
    want, counts = {}, {}
    for m in re.finditer(r'<div class="fseg" role="group" aria-label="[^"]*" data-fk="(\w+)">(.*?)</div>',
                         bar, re.S):
        k, body = m.group(1), m.group(2)
        counts[k] = {}
        for b in re.finditer(r'data-fv="([^"]*)"[^>]*aria-pressed="(true|false)">.*?data-fn>(\d+)<', body, re.S):
            counts[k][html.unescape(b.group(1))] = int(b.group(3))
            if b.group(2) == "true":
                want[k] = html.unescape(b.group(1))
    for m in re.finditer(r'<select name="(\w+)" data-fk="\w+"[^>]*>(.*?)</select>', bar, re.S):
        k, body = m.group(1), m.group(2)
        counts[k], want[k] = {}, ""
        for o in re.finditer(r'<option value="([^"]*)"[^>]*?(\sselected)?>[^<]*\((\d+)\)</option>', body):
            counts[k][html.unescape(o.group(1))] = int(o.group(3))
            if o.group(2):
                want[k] = html.unescape(o.group(1))
    return {"q": q, "want": want, "counts": counts}


NODE = r"""
global.window = {};
global.document = {querySelector: () => null};
require(process.argv[2]);
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = cases.map(c => window.listFilter.core(c.rows, c.q, c.want, c.keys));
process.stdout.write(JSON.stringify(out));
"""


def parity(label: str, pages: list[tuple[str, str]]) -> None:
    """Runs the script's core against what each page rendered and compares
    every row and every count with the server's."""
    node = shutil.which("node")
    if not node:
        check(f"{label}: node is installed to run the script's own core", False)
        return
    cases, expect = [], []
    for name, page in pages:
        rs, st = rows_of(page), bar_state(page)
        keys = list(st["counts"])
        cases.append({"rows": [{"hay": r["hay"], "f": r["f"]} for r in rs],
                      "q": st["q"], "want": st["want"], "keys": keys})
        expect.append((name, rs, st))
    tmp = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "parity.js"
    tmp.write_text(NODE)
    got = subprocess.run([node, str(tmp), str(ROOT / "static" / "listfilter.js")],
                         input=json.dumps(cases), capture_output=True, text=True, timeout=60)
    if got.returncode:
        check(f"{label}: the script's core runs under node ({got.stderr[-300:]})", False)
        return
    for (name, rs, st), js in zip(expect, json.loads(got.stdout)):
        rows_same = [not r["hidden"] for r in rs] == js["show"]
        counts_same = all(js["counts"][k].get(v, 0) == n
                          for k, opts in st["counts"].items() for v, n in opts.items())
        check(f"{label} {name}: the script shows the rows the server showed "
              f"({sum(js['show'])} of {len(rs)})", rows_same)
        check(f"{label} {name}: and counts every option the same", counts_same)


# ── the pages ──────────────────────────────────────────────────

def main() -> int:
    from fastapi.testclient import TestClient
    from app import auth, bmc, chain, db, main as portal, store, virt
    from app.bmc import BmcError

    store.add_conn("virt", "", {"type": "vsphere", "name": "esx-a",
                                "base_url": "https://10.0.0.5"})
    store.add_conn("virt", "", {"type": "proxmox", "name": "pve-1",
                                "base_url": "https://10.0.0.7:8006"})
    for name, addr in (("db-01", "10.9.9.1"), ("db-02", "10.9.9.2"),
                       ("esx-01", "10.9.9.3"), ("dead-01", "10.9.9.4")):
        store.add_conn("bmc", "", {"type": "redfish", "name": name,
                                   "base_url": f"https://{addr}"})
    ids = {c["name"]: c["id"] for c in store.all_virt() + store.all_bmc()}

    virt.read = lambda c, refresh=False: VIRT[c["name"]]
    virt._service = lambda c: {"apiType": "HostAgent"}

    def bmc_read(c, refresh=False, detail=True):
        if c["name"] == "dead-01":
            raise BmcError("timed out after 10s")
        return BMC[c["name"]]
    bmc.read = bmc_read
    chain.peek = lambda: None

    email, pw = "lf@test.local", "List-Filters-Agree-Both-Ways-42"
    uid = auth.create_user(email, "Lf", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    c = TestClient(portal.app, raise_server_exceptions=False)
    with c:
        c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
               follow_redirects=False)

        print("Hypervisors")
        pages: list = []

        def get(url):
            r = c.get(url)
            pages.append((url, r.text))
            return r

        r = get("/virt?view=group")
        t = r.text
        check(f"/virt answers 200 ({r.status_code})", r.status_code == 200)
        st = bar_state(t)
        check(f"the bar has a search, a state switch and the selects: {sorted(st['counts'])}",
              'data-fq' in t and set(st["counts"]) == {"state", "conn", "type", "kind"})
        check(f"every state counts its guests: {st['counts']['state']}",
              st["counts"]["state"] == {"": 6, "running": 2, "stopped": 4})
        check(f"and every kind: {st['counts']['kind']}",
              st["counts"]["kind"] == {"": 6, "VM": 4, "template": 1, "container": 1})
        check("a project select with one project is not drawn", "Project: any" not in t)
        check("nothing is hidden and no card is open", len(shown(t)) == 6
              and not re.search(r"<details[^>]*\sopen", t))
        check("the summary counts guests and hypervisors", "6 guests on 2 hypervisors" in t)

        r = get("/virt?q=web")
        check(f"a search shows its match: {shown(r.text)}", shown(r.text) == {"web-1"})
        cards = re.findall(r"<details class=\"card vcard\"[^>]*>", r.text)
        check("its card opens and the other steps aside",
              sum(1 for x in cards if re.search(r"\sopen\b", x)) == 1
              and sum(1 for x in cards if re.search(r"\shidden\b", x)) == 1)
        check("the card's header counts the match", " · 1 match<" in r.text)
        check("the summary says so", "1 of 6 guests on 1 of 2 hypervisors" in r.text)
        check("and Clear filters is offered, going back to the whole list",
              re.search(r'<a class="flink" href="/virt" data-fclear>Clear filters', r.text)
              and re.search(r'<a class="flink" href="/virt" data-fclear>Clear filters</a>\s*</div>\s*</div>', r.text))

        r = get("/virt?q=10.1.2")
        check(f"an IP address finds its guest: {shown(r.text)}", shown(r.text) == {"web-1"})
        r = get("/virt?q=ESX+db")
        check(f"words match in any order and all must: {shown(r.text)}", shown(r.text) == {"db-1"})
        r = get("/virt?state=stopped")
        check(f"not running: {sorted(shown(r.text))}",
              shown(r.text) == {"db-1", "golden", HOSTILE.lower(), "ct-1"})
        r2 = get("/virt?stopped_only=1")
        check("the address from before keeps working", shown(r2.text) == shown(r.text))
        r = get(f"/virt?conn={ids['pve-1']}&state=running")
        st = bar_state(r.text)
        check(f"a hypervisor and a state together: {shown(r.text)}", shown(r.text) == {"app-1"})
        check(f"each facet counts with the OTHER filters on: {st['counts']['state']}, {st['counts']['conn']}",
              st["counts"]["state"] == {"": 2, "running": 1, "stopped": 1}
              and st["counts"]["conn"] == {"": 2, ids["esx-a"]: 1, ids["pve-1"]: 1})
        r = get("/virt?conn=gone-since&kind=nonsense")
        check("a hypervisor the page does not offer is ignored, not an empty page",
              len(shown(r.text)) == 6 and "Clear filters</a>" in r.text
              and re.search(r'data-fclear hidden', r.text))
        r = get("/virt?q=zzzz")
        check("nothing matching says so", re.search(r'<div class="card fempty" data-fempty>', r.text)
              and "“zzzz”" in r.text and "0 of 6 guests on 0 of 2 hypervisors" in r.text)
        check("and the empty note is hidden when something matches",
              re.search(r'data-fempty hidden', c.get("/virt?q=web").text))
        r = get("/virt?sort=mem&dir=desc")
        check("a sort in the address marks its column",
              re.search(r'data-fsort="mem"[^>]*aria-sort="descending"', r.text))
        r = c.get("/virt?sort=mem%3Cx&dir=sideways")
        check("a sort it cannot read marks nothing", 'aria-sort="descending"' not in r.text
              and 'aria-sort="ascending"' not in r.text)
        check("the chart's slices are filters",
              'href="/virt?state=stopped"' in t and 'href="/virt?state=running"' in t)

        r = get("/virt?view=list")
        check("One list is one table of every guest, with the hypervisor named",
              "<details" not in r.text.split("data-fbar", 1)[1]
              and len(rows_of(r.text)) == 6 and ">Hypervisor</button>" in r.text)
        check("it is remembered", r.cookies.get("virt_view") == "list"
              or "virt_view=list" in r.headers.get("set-cookie", ""))
        r = get("/virt?q=n2")
        check(f"and comes back without asking: {shown(r.text)}",
              "<details" not in r.text.split("data-fbar", 1)[1] and shown(r.text) == {"ct-1"})
        check("a multi-host hypervisor names the host under it", ">n2</div>" in r.text)
        r = get("/virt?view=group&state=running")
        check("By hypervisor switches back", "<details" in r.text and shown(r.text) == {"web-1", "app-1"})

        r = c.get("/virt")
        check("a hostile VM name is text in its row, its haystack and nowhere markup",
              HOSTILE not in r.text and html.escape(HOSTILE, quote=False) in r.text
              and html.escape(HOSTILE.lower()) in r.text)
        parity("Hypervisors", pages)

        print("Server hardware")
        pages = []
        r = get("/bmc")
        t = r.text
        st = bar_state(t)
        check(f"/bmc answers 200 ({r.status_code})", r.status_code == 200)
        check(f"health counts every state: {st['counts'].get('health')}",
              st["counts"].get("health") == {"": 4, "ok": 2, "fault": 1, "unreachable": 1})
        check(f"power, OS, vendor and model are offered: {sorted(st['counts'])}",
              {"power", "os", "vendor", "model"} <= set(st["counts"]))
        check("a server with no OS reported is its own option",
              re.search(r'<option value="-"[^>]*>None reported \(2\)</option>', t))
        check("Runs is not offered before the chain is known", "Runs: any" not in t)
        check("the health chart's slices are filters",
              'href="/bmc?health=fault"' in t and 'href="/bmc?power=off"' in t)
        r = get("/bmc?health=fault")
        check(f"faults only: {shown(r.text)}", shown(r.text) == {"db-02"})
        r = get("/bmc?health=unreachable")
        check(f"unreachable only: {shown(r.text)}", shown(r.text) == {"dead-01"})
        r = get("/bmc?q=abc123")
        check(f"a serial, in any case: {shown(r.text)}", shown(r.text) == {"db-01"})
        r = get("/bmc?q=10.9.9.3")
        check(f"the BMC's address: {shown(r.text)}", shown(r.text) == {"esx-01"})
        r = get("/bmc?q=rocky+db01")
        check(f"the OS and the host name together: {shown(r.text)}", shown(r.text) == {"db-01"})
        r = get("/bmc?q=timed+out")
        check(f"why a BMC could not be read: {shown(r.text)}", shown(r.text) == {"dead-01"})
        r = get("/bmc?os=-")
        check(f"none reported: {sorted(shown(r.text))}", shown(r.text) == {"db-02", "dead-01"})
        r = get("/bmc?power=off&health=ok")
        check(f"power and health together: {shown(r.text)}", shown(r.text) == {"esx-01"})
        r = get("/bmc?health=fault&q=esx")
        check("no match says so", re.search(r'<div class="card fempty" data-fempty>', r.text)
              and "0 of 4 servers" in r.text)
        check("and both Clear filters links go back to the whole list",
              len(re.findall(r'<a class="flink" href="/bmc" data-fclear', r.text)) == 2)
        r = get("/bmc?sort=hot&dir=desc")
        check("a column sort is marked", re.search(r'data-fsort="hot"[^>]*aria-sort="descending"', r.text))
        r = c.get(f"/bmc?device={ids['db-01']}")
        check("a device's own page has no list bar", "data-fbar" not in r.text)

        chain.peek = lambda: {"seen": True}
        chain.summary_for_servers = lambda me, g=None: {ids["esx-01"]: "esx-01 · 5 VMs"}
        chain.why_empty = lambda me, g=None: {
            ids["db-01"]: {"text": "Rocky Linux 9.4", "sub": "db01.lab", "os": True},
            ids["db-02"]: {"text": "no hypervisor connected", "sub": "", "os": False}}
        r = get("/bmc")
        st = bar_state(r.text)
        check(f"once the chain is known, Runs is a filter: {st['counts'].get('runs')}",
              st["counts"].get("runs") == {"": 4, "vms": 1, "os": 1, "none": 2})
        r = get("/bmc?runs=vms")
        check(f"a connected hypervisor: {shown(r.text)}", shown(r.text) == {"esx-01"})
        r = get("/bmc?q=5+vms")
        check(f"and its Runs text is searched: {shown(r.text)}", shown(r.text) == {"esx-01"})
        parity("Server hardware", pages)

    print("OK" if not FAILED else f"{len(FAILED)} FAILED")
    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
