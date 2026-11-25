#!/usr/bin/env python3
"""Server hardware and Hypervisors open quickly, and hypervisor cards fold.

Reported 24 November 2026 on an estate with 16 iDRACs and 8 ESXi hosts, and
measured there inside the pod:

  * one iDRAC read took 9-11 seconds (one 23.5): up to 32 Redfish requests one
    after another, 25 of them the firmware inventory that only a device's own
    page shows. The page read six BMCs at a time, so 16 cost three rounds,
    longer than the page's three bounded reloads, and it never filled in.
  * an ESXi read took 0.2s, but every look after the first minute read every
    host again, so eight hosts six at a time outran the page's 0.4s first
    paint and the page reloaded itself to fill in.
  * a card per host, each open, made /virt a long scroll.

Checks:
  1. the list read of a BMC asks for no firmware, and its requests overlap
  2. a device's read gets the firmware in one $expand request when the BMC
     expands, and a few members at a time when it does not
  3. past CACHE_TTL a BMC read returns the last answer at once, and one
     refresh runs behind it, however many readers arrive
  4. the same for a hypervisor read
  5. across(workers=16) reads 16 slow boxes in one round
  6. /virt draws every card closed, a filter opens the cards it matched, and
     Expand all / Collapse all are there

    ./.venv/bin/python tests/test_hw_pages.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("hwpages-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import bmc, gather, virt                              # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


DELAY = 0.3
FW = 20
state = {"paths": [], "live": 0, "peak": 0, "expand": True}
lock = threading.Lock()
SYS = "/redfish/v1/Systems/System.Embedded.1"
CH = "/redfish/v1/Chassis/System.Embedded.1"
DOCS = {
    "/redfish/v1": {"Vendor": "Dell"},
    "/redfish/v1/Systems": {"Members": [{"@odata.id": SYS}]},
    SYS: {"Model": "PowerEdge R650", "SerialNumber": "ABC123",
          "PowerState": "On", "Status": {"Health": "OK"}},
    "/redfish/v1/Chassis": {"Members": [{"@odata.id": CH}]},
    CH + "/Thermal": {"Temperatures": [{"Name": "Inlet", "ReadingCelsius": 24},
                                       {"Name": "CPU1", "ReadingCelsius": 61}]},
    CH + "/Power": {"PowerControl": [{"PowerConsumedWatts": 312}]},
}
FWROOT = "/redfish/v1/UpdateService/FirmwareInventory"
FWDOCS = {f"{FWROOT}/c{i}": {"Name": f"Component {i}", "Version": f"1.{i}"}
          for i in range(FW)}


class FakeBmc(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        with lock:
            state["paths"].append(self.path)
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        try:
            time.sleep(DELAY)
            path, _, query = self.path.partition("?")
            if path == FWROOT and query:
                if not state["expand"]:
                    return self._send(400, {"error": "no $expand here"})
                return self._send(200, {"Members": [{"@odata.id": k, **v}
                                                    for k, v in FWDOCS.items()]})
            if path == FWROOT:
                return self._send(200, {"Members": [{"@odata.id": k}
                                                    for k in FWDOCS]})
            doc = DOCS.get(path) or FWDOCS.get(path)
            self._send(200 if doc else 404, doc or {})
        finally:
            with lock:
                state["live"] -= 1

    def _send(self, code, doc):
        raw = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def reset():
    with lock:
        state["paths"].clear()
        state["peak"] = 0


def test_bmc(base: str) -> None:
    conn = {"id": "b1", "name": "r650", "base_url": base, "username": "root",
            "token": "x", "skip_tls": 1}

    # 1. the list read
    bmc.invalidate(); reset()
    t = time.time()
    got = bmc.read(conn, detail=False)
    took = time.time() - t
    check(f"the list read has what the list shows: {got.get('model')}, "
          f"{got.get('hottest')} C, {got.get('watts')} W",
          got.get("model") == "PowerEdge R650" and got.get("hottest") == 61
          and got.get("watts") == 312 and got.get("power") == "On")
    check(f"the list read asks for no firmware: {state['paths']}",
          not any("Firmware" in p for p in state["paths"]))
    check(f"its six requests overlap: {took:.2f}s, under the "
          f"{6 * DELAY:.1f}s they cost one by one", took < 4 * DELAY)

    # 2a. a device's read, with $expand
    reset()
    t = time.time()
    got = bmc.read(conn)
    took = time.time() - t
    fw = [p for p in state["paths"] if "Firmware" in p]
    check(f"a device read gets {FW} firmware entries: {len(got['firmware'])}",
          len(got["firmware"]) == FW)
    check(f"in one $expand request: {fw}", len(fw) == 1 and "$expand" in fw[0])
    check(f"and in {took:.2f}s, not {(7 + FW) * DELAY:.1f}s", took < 4 * DELAY)

    # 2b. without $expand: the members, a few at a time
    bmc.invalidate(); reset(); state["expand"] = False
    t = time.time()
    got = bmc.read(conn)
    took = time.time() - t
    state["expand"] = True
    check(f"without $expand the members are still read: {len(got['firmware'])}",
          len(got["firmware"]) == FW)
    check(f"a few at a time: {took:.2f}s against {(7 + FW) * DELAY:.1f}s one "
          f"by one, at most {state['peak']} requests at once on the BMC",
          took < (3 + FW / bmc.FW_WORKERS + 1) * DELAY and state["peak"] <= 6)

    # 3. stale: served at once, one refresh behind, however many readers
    key = bmc._key(conn)
    t0, out, detail = bmc._cache[key]
    bmc._cache[key] = (t0 - bmc.CACHE_TTL - 5, out, detail)
    reset()
    t = time.time()
    again = [bmc.read(conn) for _ in range(5)]
    took = time.time() - t
    check(f"a stale answer comes back at once ({took:.3f}s)", took < 0.1)
    check("and it is the last answer", all(a is out for a in again))
    time.sleep(6 * DELAY + 0.5)
    reads = [p for p in state["paths"] if p == SYS]
    check(f"one refresh ran behind five readers: {len(reads)} reads",
          len(reads) == 1)
    check(f"and it went straight to the system, thermal and power, with the "
          f"paths remembered: {state['paths']}",
          "/redfish/v1" not in state["paths"]
          and "/redfish/v1/Systems" not in state["paths"])
    check("and its answer replaced the stale one",
          bmc._cache[key][0] > t0 - 1)

    # 3b. a list answer does not satisfy a device page
    bmc.invalidate(); reset()
    bmc.read(conn, detail=False)
    reset()
    got = bmc.read(conn)
    check("a device page after the list still reads the firmware",
          len(got["firmware"]) == FW)

    # 3c. too old to serve: read now
    t0, out, detail = bmc._cache[key]
    bmc._cache[key] = (t0 - bmc.STALE_MAX - 5, out, detail)
    reset()
    bmc.read(conn)
    check("past STALE_MAX it reads before answering", SYS in state["paths"])

    # 3d. a system that moved is found again; one that does not answer is
    # not waited out twice
    bmc._paths[bmc._where(conn)] = ("Dell", "/redfish/v1/Systems/Gone", CH)
    bmc._cache.pop(key, None)
    reset()
    got = bmc.read(conn, detail=False)
    check(f"a moved system is looked up again: {state['paths']}",
          got.get("model") == "PowerEdge R650"
          and "/redfish/v1/Systems" in state["paths"])


def test_virt() -> None:
    calls = {"n": 0}

    def slow(c):
        calls["n"] += 1
        time.sleep(0.4)
        return {"hosts": [], "guests": [{"name": f"vm-{calls['n']}", "id": "1",
                                         "host": "", "kind": "VM", "state": "On"}],
                "kind": "Fake"}

    virt._IMPL["fake"] = slow
    conn = {"id": "v1", "type": "fake", "base_url": "http://x"}
    virt.invalidate()
    first = virt.read(conn)
    key = f"read::{virt._who(conn)}"
    t0, out = virt._cache[key]
    virt._cache[key] = (t0 - virt.CACHE_TTL - 5, out)
    t = time.time()
    again = [virt.read(conn) for _ in range(5)]
    took = time.time() - t
    check(f"a stale hypervisor answer comes back at once ({took:.3f}s)",
          took < 0.1 and all(a is first for a in again))
    time.sleep(0.8)
    check(f"one refresh ran behind five readers: {calls['n']} reads in all",
          calls["n"] == 2)
    check("and the next look has it",
          virt.read(conn)["guests"][0]["name"] == "vm-2")
    virt._IMPL.pop("fake", None)


def test_across() -> None:
    conns = [{"id": f"c{i}", "name": f"c{i}"} for i in range(16)]

    def slow(c):
        time.sleep(0.5)
        return c["id"]

    t = time.time()
    got, _ = gather.across("hwtest", conns, slow, refresh=True, workers=16)
    took = time.time() - t
    check(f"16 slow boxes in one round with workers=16: {took:.2f}s",
          len(got) == 16 and took < 1.2)
    t = time.time()
    got, pending = gather.across("hwtest2", conns, slow, first_paint=1.5,
                                 workers=16)
    took = time.time() - t
    check(f"first paint has all 16 when they answer inside it: {len(got)} "
          f"in {took:.2f}s, pending {pending}", len(got) == 16 and not pending)


def test_page() -> None:
    from fastapi.testclient import TestClient
    from app import auth, db, main, store

    store.add_conn("virt", "", {"type": "vsphere", "name": "esx-a",
                                "base_url": "https://10.0.0.5"})
    store.add_conn("virt", "", {"type": "vsphere", "name": "esx-b",
                                "base_url": "https://10.0.0.6"})
    canned = {
        "esx-a": {"hosts": [{"name": "esx-a.lab", "state": "connected",
                             "cpu_pct": 21.4, "cores": 32, "mem_pct": 41.8,
                             "mem_gib": 512.0, "uptime": "3d 4h", "extra": "",
                             "url": ""}],
                  "guests": [{"name": "web-1", "id": "1", "host": "esx-a.lab",
                              "kind": "VM", "state": "On", "cpu_pct": 5.0,
                              "cores": 2, "mem_gib": 4.0, "mem_pct": 20.0,
                              "disk_gib": 40.0, "uptime": "2h", "url": ""},
                             {"name": "db-1", "id": "2", "host": "esx-a.lab",
                              "kind": "VM", "state": "Off", "cpu_pct": None,
                              "cores": 4, "mem_gib": 8.0, "mem_pct": None,
                              "disk_gib": 80.0, "uptime": "", "url": ""}],
                  "kind": "ESXi", "running": 1, "stopped": 1},
        "esx-b": {"hosts": [], "guests": [
                      {"name": "cache-1", "id": "3", "host": "", "kind": "VM",
                       "state": "On", "cpu_pct": None, "cores": 2,
                       "mem_gib": 2.0, "mem_pct": None, "disk_gib": None,
                       "uptime": "", "url": ""}],
                  "kind": "ESXi", "running": 1, "stopped": 0},
    }
    real = virt.read
    virt.read = lambda c, refresh=False: canned[c["name"]]

    email, pw = "hw@test.local", "Hardware-Pages-Open-Fast-42"
    uid = auth.create_user(email, "Hw", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app, raise_server_exceptions=False)
    try:
        with c:
            c.post("/login", data={"email": email, "password": pw},
                   follow_redirects=False)
            c.post("/mfa", data={"code": auth._totp_at(
                "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
                follow_redirects=False)
            r = c.get("/virt")
            cards = re.findall(r"<details class=\"card vcard\"[^>]*>", r.text)
            check(f"/virt answers 200 ({r.status_code})", r.status_code == 200)
            check(f"one folding card per connection: {len(cards)}", len(cards) == 2)
            check("every card is closed by default",
                  cards and not any(re.search(r"\sopen\b", x) for x in cards))
            check("Expand all and Collapse all are there",
                  'data-vcards="open"' in r.text and 'data-vcards="close"' in r.text)
            head = r.text.split('data-vcard="', 1)[-1].split("</summary>", 1)[0]
            check("a closed card still says what is in it",
                  "1 running" in head and "1 not running" in head
                  and "CPU 21.4%" in head and "memory 41.8%" in head)
            r = c.get("/virt?q=web")
            cards = re.findall(r"<details class=\"card vcard\"[^>]*>", r.text)
            opened = [x for x in cards if re.search(r"\sopen\b", x)]
            check(f"a filter opens only the card it matched: {opened}",
                  len(opened) == 1)
            check("and the match is counted in the header", "1 match" in r.text)
    finally:
        virt.read = real


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeBmc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    test_bmc(f"http://127.0.0.1:{srv.server_address[1]}")
    test_virt()
    test_across()
    test_page()
    srv.shutdown()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
