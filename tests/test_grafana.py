#!/usr/bin/env python3
"""A Grafana dashboard drawn in the portal reads the way Grafana reads it.

Most of what a dashboard looks like is decided in Grafana's BROWSER, not its
server, and every rule pinned here was confirmed against a real Grafana before
it was written -- then broken once, which is why each has a test:

  * variables resolve in DEPENDENCY order. A real dashboard declares `host`
    (which mentions `$job`) before `job`; in list order every panel queried
    `instance=~""` and was empty.
  * the query step never drops below the datasource's scrape interval. From
    pixel width alone a five-minute window asked for a 1s step: 301 points of
    each sample repeated fifteen times, drawn as cliffs.
  * series are named by the labels that DIFFER, which is what a panel's
    overrides are keyed on.
  * "table" format is a frontend pivot into `Value #A`, `Value #B` columns.
  * a legacy range map from "null" to "null" means "the value is null" -- read
    as an open range it turned every legacy tile into "N/A".
  * every renderer escapes, because a name here comes from a dashboard author or
    somebody's exporter and the markup is built by hand.

Synthetic fixtures only: a recording of a real Grafana holds an estate's
hostnames and addresses and never belongs in this repository.

    ./.venv/bin/python tests/test_grafana.py
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("grafana-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import grafana as g, grafview as v                    # noqa: E402

bad = 0


def check(name: str, ok: bool) -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok  " if ok else "  FAIL ") + name)


def frame(ref, labels, values, times=None, name=None):
    times = times or [1_000_000 + i * 15_000 for i in range(len(values))]
    return {"refId": ref, "name": "", "fields": [
        {"name": "Time", "type": "time", "labels": {}, "config": {}, "values": times},
        {"name": name or labels.get("__name__", "Value"), "type": "number",
         "labels": labels, "config": {}, "values": values}]}


def panel(kind="stat", **kw):
    p = {"id": 1, "type": kind, "title": "t", "description": "",
         "grid": {"x": 0, "y": 0, "w": 12, "h": 8}, "is_row": False, "row": None,
         "in_row": None, "hidden": False, "datasource": None,
         "targets": [{"refId": "A", "legendFormat": "__auto"}],
         "field_config": {"defaults": {}, "overrides": []}, "options": {},
         "transformations": [], "interval": "", "max_points": None, "content": "",
         "mode": "markdown"}
    p.update(kw)
    return p


def main() -> int:
    print("units read the way Grafana writes them")
    check("decbytes: 8.42e9 is 8.42 GB", v.fmt(8.42e9, "decbytes") == "8.42 GB")
    check("decbytes keeps a trailing zero: 2.40 GB", v.fmt(2.40e9, "decbytes") == "2.40 GB")
    check("bytes is IEC: 1 GiB", v.fmt(1024 ** 3, "bytes") == "1 GiB")
    check("percent", v.fmt(9.3, "percent") == "9.30%")
    check("percentunit", v.fmt(0.863, "percentunit") == "86.3%")
    check("dtdurations: three weeks", v.fmt(21 * 86400 + 5000, "dtdurations") == "3 weeks")
    check("s scales to the largest unit that keeps it small", v.fmt(90, "s") == "1.50 min")
    check("short scales by thousands", v.fmt(12_300, "short") == "12.3 K")
    check("bits per second", v.fmt(2_500_000, "bps") == "2.50 Mb/s")
    check("none leaves an integer alone", v.fmt(4, "none") == "4")
    check("unknown unit is a suffix", v.fmt(3, "widgets") == "3 widgets")

    print("value mappings and thresholds")
    maps = [{"type": "value", "options": {"0": {"text": "Down", "color": "red"},
                                          "1": {"text": "Up", "color": "green"}}}]
    cfg = {"mappings": maps, "thresholds": {"steps": [{"color": "green", "value": None}]}}
    d1, d0 = v.display(1, cfg), v.display(0, cfg)
    check("1 maps to Up, green", d1["text"] == "Up" and d1["color"] == v.NAMED["green"])
    check("0 maps to Down, red", d0["text"] == "Down" and d0["color"] == v.NAMED["red"])
    th = {"steps": [{"color": "green", "value": None}, {"color": "#EAB839", "value": 16},
                    {"color": "red", "value": 28}]}
    check("below the first step is the base colour", v.threshold_color(10, th) == v.NAMED["green"])
    check("a hex step passes through", v.threshold_color(20, th) == "#EAB839")
    check("above the last step", v.threshold_color(30, th) == v.NAMED["red"])
    pct = {"mode": "percentage", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 50}]}
    check("percentage thresholds are relative to min..max",
          v.threshold_color(60, pct, 0, 200) == v.NAMED["green"] and
          v.threshold_color(120, pct, 0, 200) == v.NAMED["red"])
    check("a colour that is not a colour does not reach the page",
          v.css_color('red;background:url(x)') == "var(--muted)")

    print("legacy panels convert the way Grafana converts them")
    legacy = {"type": "singlestat", "format": "bytes", "valueName": "current",
              "mappingType": 1, "valueMaps": [{"op": "=", "text": "N/A", "value": "null"}],
              "rangeMaps": [{"from": "null", "to": "null", "text": "N/A"}],
              "thresholds": "80,90", "colors": ["#299c46", "#e5ac0e", "#d44a3a"],
              "colorValue": True}
    m = g._modernize(legacy)
    dfl = m["fieldConfig"]["defaults"]
    check("format becomes the unit", dfl.get("unit") == "bytes")
    check("a real value is NOT mapped to N/A", v.map_value(123, dfl.get("mappings")) is None)
    check("...but null is", (v.map_value(None, dfl.get("mappings")) or {}).get("text") == "N/A")
    check("thresholds string becomes steps",
          [s["value"] for s in dfl["thresholds"]["steps"]] == [None, 80.0, 90.0])
    check("colorValue becomes colorMode value", m["options"]["colorMode"] == "value")
    graph = {"type": "graph", "yaxes": [{"format": "percent"}], "fill": 2, "stack": True,
             "aliasColors": {"idle": "#7EB26D"}}
    mg = g._modernize(graph)
    check("graph becomes timeseries", mg["type"] == "timeseries")
    check("yaxes format becomes the unit", mg["fieldConfig"]["defaults"]["unit"] == "percent")
    check("aliasColors become fixed-colour overrides",
          any(o["matcher"]["options"] == "idle" for o in mg["fieldConfig"]["overrides"]))
    rng = g._modernize({"type": "singlestat", "mappingType": 2,
                        "rangeMaps": [{"from": "null", "to": "null", "text": "N/A"},
                                      {"from": "0", "to": "50", "text": "low"}]})
    rmaps = rng["fieldConfig"]["defaults"]["mappings"]
    check("mappingType 2: a null-null range means null, not every value",
          (v.map_value(123, rmaps) or {}).get("text") != "N/A")
    check("...and a real range still maps", (v.map_value(25, rmaps) or {}).get("text") == "low")
    vmt = g._modernize({"type": "singlestat", "mappingType": 1,
                        "valueMaps": [{"op": "=", "text": "one", "value": "1"}],
                        "rangeMaps": [{"from": "0", "to": "50", "text": "low"}]})
    check("mappingType 1: range maps are ignored",
          v.map_value(25, vmt["fieldConfig"]["defaults"]["mappings"]) is None)
    check("a malformed range bound does not raise",
          v.map_value(5, [{"type": "range", "options": {"from": "x", "to": "9"}}]) is None)

    print("series are named by the labels that differ")
    p = panel("timeseries")
    ss = g.series([frame("A", {"__name__": "cpu", "cluster": "c1", "node": "n1"}, [1, 2]),
                   frame("A", {"__name__": "cpu", "cluster": "c1", "node": "n2"}, [3, 4])], p)
    check("one differing label: its value alone", [s["name"] for s in ss] == ["n1", "n2"])
    ss = g.series([frame("A", {"__name__": "rebalance_start", "cluster": "c1"}, [9]),
                   frame("B", {"__name__": "rebalance_failure", "cluster": "c1"}, [2])],
                  panel("bargauge", targets=[{"refId": "A"}, {"refId": "B"}]))
    check("__name__ counts, which is what overrides match on",
          [s["name"] for s in ss] == ["rebalance_start", "rebalance_failure"])
    ss = g.series([frame("A", {"host": "a", "mount": "/"}, [1])],
                  panel("timeseries", targets=[{"refId": "A", "legendFormat": "{{host}} - {{mount}}"}]))
    check("a legend template is applied", ss[0]["name"] == "a - /")

    print("table format pivots, and merge joins")
    tp = panel("table", targets=[{"refId": "A", "format": "table"}, {"refId": "B", "format": "table"}])
    frames = [frame("A", {"__name__": "disk", "bucket": "b1"}, [100]),
              frame("A", {"__name__": "disk", "bucket": "b2"}, [200]),
              frame("B", {"__name__": "mem", "bucket": "b1"}, [10]),
              frame("B", {"__name__": "mem", "bucket": "b2"}, [20])]
    tabs = g.tables(frames, tp)
    check("each query pivots into its own Value #ref column",
          sorted(c for t in tabs for c in t["columns"] if c.startswith("Value")) == ["Value #A", "Value #B"])
    merged, skipped = g.transform(tabs, [{"id": "merge"}])
    rows = {r["bucket"]: r for r in merged[0]["rows"]}
    check("merge joins the two queries on the shared label",
          len(merged) == 1 and rows["b1"]["Value #A"] == 100 and rows["b1"]["Value #B"] == 10)
    _, skipped = g.transform(g.tables(frames, tp), [{"id": "heatmapSomething"}])
    check("an unsupported transformation is NAMED, not silently faked", skipped == ["heatmapSomething"])

    print("variables resolve in dependency order")
    tpl = [{"name": "host", "type": "query", "definition": 'label_values(x{job="$job"},instance)'},
           {"name": "job", "type": "query", "definition": "label_values(y,job)"}]
    check("a variable comes after the one it mentions",
          [x["name"] for x in g._dependency_order(tpl)] == ["job", "host"])
    check("$jobname is not a mention of $job", not g._refs("$jobname", "job"))
    # END TO END: the ordering helper existing is not the same as variables()
    # using it -- the first version of this test passed with the call removed
    real_lookup, real_ds, real_cached = g._prom_lookup, g.datasources, g._cached
    g.datasources = lambda conn: [{"uid": "p1", "type": "prometheus", "name": "P", "isDefault": True}]
    g._cached = lambda conn, part, refresh, produce: produce()

    def lookup(conn, ds, text, trange):
        if "label_values(y,job)" in text:
            return ["api", "web"]
        return ["h1", "h2"] if 'job="api"' in text else []
    g._prom_lookup = lookup
    try:
        dash = {"uid": "d", "title": "d", "templating": tpl}
        vs = {x["name"]: x for x in g.variables({"id": "c"}, dash, {}, g.time_range("now-1h", "now"))}
        check("host resolves AFTER job, so its lookup sees job=api",
              vs["host"]["values"] == ["h1"] and [o["value"] for o in vs["host"]["options"]] == ["h1", "h2"])
        check("...and they are shown in the author's order",
              [x["name"] for x in g.variables({"id": "c"}, dash, {}, g.time_range("now-1h", "now"))] == ["host", "job"])
    finally:
        g._prom_lookup, g.datasources, g._cached = real_lookup, real_ds, real_cached

    print("interpolation matches Grafana's per-datasource formats")
    multi = {"name": "node", "multi": True, "include_all": True, "is_all": False,
             "all_value": None, "values": ["10.0.0.1:80", "10.0.0.2:80"]}
    got = g.interpolate('x{n=~"$node"}', {"node": multi}, {}, "prometheus")
    check("prometheus multi: an escaped alternation", got == 'x{n=~"(10\\\\.0\\\\.0\\\\.1:80|10\\\\.0\\\\.0\\\\.2:80)"}')
    single = {"name": "c", "multi": False, "include_all": False, "is_all": False,
              "all_value": None, "values": ["a.b"]}
    check("prometheus single: raw", g.interpolate('$c', {"c": single}, {}, "prometheus") == "a.b")
    allv = {**multi, "is_all": True, "all_value": ".*"}
    check("All with an allValue uses it raw", g.interpolate("$node", {"node": allv}, {}, "prometheus") == ".*")
    check("sql multi: quoted list", g.interpolate("$node", {"node": multi}, {}, "sql") ==
          "'10.0.0.1:80','10.0.0.2:80'")
    check("builtins win", g.interpolate("rate(x[$__rate_interval])", {}, {"__rate_interval": "1m"}) ==
          "rate(x[1m])")

    print("the step never goes below the scrape interval")
    tr = g.time_range("now-5m", "now")
    check("width alone would ask for a 1s step", g.interval_ms(tr, 350, "") < 15_000)
    fake = [{"uid": "p1", "type": "prometheus", "name": "Prom", "jsonData": {}}]
    g.datasources = lambda conn: fake
    check("unset timeInterval means 15s for Prometheus",
          g.scrape_ms({}, {"type": "prometheus", "uid": "p1"}) == 15_000)
    seen = {}

    def fake_query(conn, queries, trange):
        seen["q"] = queries
        return {}
    g._query = fake_query
    g._cached = lambda conn, part, refresh, produce: produce()
    g.run_panel({"id": "c", "base_url": "https://g"}, {"uid": "d", "title": "d"},
                panel("timeseries", datasource={"type": "prometheus", "uid": "p1"},
                      targets=[{"refId": "A", "expr": "up"}]), {}, tr, width_px=700)
    check("the query is sent with at least a 15s step", seen["q"][0]["intervalMs"] >= 15_000)

    print("a datasource resolves however it was stored")
    fake[:] = [{"uid": "p1", "type": "prometheus", "name": "Prom"},
               {"uid": "m1", "type": "mysql", "name": "db"}]
    scope = {"ds": {"name": "ds", "values": ["p1"], "multi": False, "include_all": False,
                    "is_all": False, "all_value": None}}
    check("a datasource variable", g.resolve_ds({}, {"type": "prometheus", "uid": "${ds}"}, scope)["uid"] == "p1")
    check("a bare uid string", g.resolve_ds({}, "p1")["type"] == "prometheus")
    check("a bare NAME string", g.resolve_ds({}, "Prom")["uid"] == "p1")
    check("a uid parked in the type slot", g.resolve_ds({}, {"type": "p1", "uid": ""})["uid"] == "p1")
    fake.append({"uid": "p2", "type": "prometheus", "name": "Prom2"})
    check("an unknown uid with several candidates is NOT guessed",
          g.resolve_ds({}, {"type": "prometheus", "uid": "gone"})["uid"] in ("", "gone"))

    print("every renderer escapes what it is given")
    evil = '"><img src=x onerror=alert(1)>'
    ev = [frame("A", {"__name__": "m", "node": evil}, [1, 2]),
          frame("A", {"__name__": "m", "node": "ok"}, [3, 4])]
    for kind, fn in (("stat", lambda p, s: v.stat(p, s)), ("gauge", lambda p, s: v.gauge(p, s)),
                     ("bargauge", lambda p, s: v.bargauge(p, s)),
                     ("timeseries", lambda p, s: v.timeseries(p, s, tr)),
                     ("piechart", lambda p, s: v.piechart(p, s))):
        p = panel(kind)
        out = str(fn(p, g.series(ev, p)))
        # escaped, the payload survives as TEXT ("&lt;img ... onerror=...");
        # what must never appear is a live tag
        check(f"{kind}: no live tag", "<img" not in out and "onerror=alert(1)>" not in out)
    tt = panel("table", targets=[{"refId": "A", "format": "table"}])
    out = str(v.table(tt, [frame("A", {"__name__": "m", "bucket": evil}, [1])]))
    check("table: no live tag", "<img" not in out and "onerror=alert(1)>" not in out)

    print("text panels keep presentation and lose everything else")
    dirty = ('<div style="position:fixed;top:0;color:green">hi</div><script>alert(1)</script>'
             '<a href="javascript:alert(1)">x</a><img src=x onerror=alert(1)>'
             '<iframe src="https://evil"></iframe><b onclick="x()">b</b>')
    clean = str(v.sanitize(dirty))
    check("no script", "<script" not in clean and "alert(1)</" not in clean)
    check("no event handler", "onclick" not in clean and "onerror" not in clean)
    check("no javascript: url", "javascript:" not in clean)
    check("no iframe", "<iframe" not in clean)
    check("position cannot escape the panel", "position" not in clean)
    check("...while the harmless style survives", "color:green" in clean)

    print("layout: one grid per row, positions relative to it")
    ps = [panel(id=1, grid={"x": 0, "y": 0, "w": 12, "h": 4}),
          {**panel(id=2), "is_row": True, "grid": {"x": 0, "y": 4, "w": 24, "h": 1},
           "row": {"collapsed": False}},
          panel(id=3, grid={"x": 0, "y": 5, "w": 24, "h": 6})]
    secs = v.sections(ps)
    check("a row starts a new section", len(secs) == 2 and secs[1]["row"]["id"] == 2)
    check("rows are relative to the section", secs[1]["panels"][0]["_r"] == 1)

    print("the y axis always covers the data")
    t = v._ticks(5.2, 10.4, 5, "percent", None)
    check("last tick is at or above the maximum", t[-1]["v"] >= 10.4)

    print("a playlist is a filter over the dashboards list")
    items = [{"uid": "a", "title": "Alpha", "folder": "DB", "tags": ["uat"], "platform": "grafana"},
             {"uid": "b", "title": "Beta", "folder": "Hosts", "tags": [], "platform": "grafana"},
             {"uid": "", "title": "No uid", "folder": "DB", "tags": [], "platform": "grafana"},
             {"uid": "z", "title": "Zabbix", "folder": "DB", "tags": [], "platform": "zabbix"},
             {"uid": "c", "title": "Gamma", "folder": "DB", "tags": ["prod"], "platform": "grafana"}]
    check("all: only what the portal can draw, in list order",
          [d["uid"] for d in g.playlist(items, "all")] == ["a", "b", "c"])
    check("folder", [d["uid"] for d in g.playlist(items, "folder:DB")] == ["a", "c"])
    check("tag", [d["uid"] for d in g.playlist(items, "tag:uat")] == ["a"])
    check("search matches title, folder or tag", [d["uid"] for d in g.playlist(items, "q:host")] == ["b"])

    route_tests()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


def route_tests() -> None:
    """A rotation walked through the real routes, signed in."""
    import re
    import time
    import urllib.parse
    from fastapi.testclient import TestClient
    from app import auth, db, main, store

    print("the rotation, through the routes")
    email, pw = "play@test.local", "Rotation-Walks-Through-7"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?", ("TESTSECRET", uid))
    cid = store.add_mon("", {"name": "G", "type": "grafana", "base_url": "https://grafana.test",
                             "token": "", "skip_tls": False}) or store.all_mon()[0]["id"]
    listing = [{"uid": "d1", "title": "One", "folder": "Ops", "tags": ["tv"], "url": "https://grafana.test/d/d1"},
               {"uid": "d2", "title": "Two", "folder": "Ops", "tags": [], "url": "https://grafana.test/d/d2"},
               {"uid": "d3", "title": "Three", "folder": "DB", "tags": ["tv"], "url": "https://grafana.test/d/d3"}]
    real_list, real_dash = main.monitoring.dashboards, main.grafana.dashboard
    main.monitoring.dashboards = lambda conn, refresh=False: listing

    def fake_dash(conn, u, refresh=False):
        title = next(d["title"] for d in listing if d["uid"] == u)
        return {"uid": u, "title": title, "description": "", "tags": [], "refresh": "",
                "folder": "Ops", "url": f"https://grafana.test/d/{u}",
                "time": {"from": "now-1h", "to": "now"}, "timezone": "browser",
                "templating": [], "panels": []}
    main.grafana.dashboard = fake_dash
    try:
        c = TestClient(main.app)
        with c:
            c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
            c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))},
                   follow_redirects=False)
            r = c.get("/monitoring/play?plist=all&every=30", follow_redirects=False)
            loc = r.headers.get("location", "")
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(loc).query))
            check(f"starting a playlist lands on its first dashboard, got {loc[:80]}",
                  r.status_code == 303 and q.get("uid") == "d1" and q.get("pi") == "0" and q.get("every") == "30")

            def page(url):
                html = c.get(url).text
                m = re.search(r'class="gplay[^"]*"([^>]*)>', html)
                attrs = dict(re.findall(r'data-([\w-]+)="([^"]*)"', m.group(1))) if m else {}
                return html, {k: v.replace("&amp;", "&") for k, v in attrs.items()}
            html, bar = page(loc)
            nq = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(bar.get("next", "")).query))
            check("the page carries a playlist bar that counts down", bar.get("every") == "30")
            check("...whose next step is the second dashboard", nq.get("uid") == "d2" and nq.get("pi") == "1")
            check("...and says where it is", "1 of 3" in html and "All dashboards" in html)
            _, last = page(_url(cid, "d3", "all", 2, 30))
            lq = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(last.get("next", "")).query))
            check("the last dashboard wraps round to the first", lq.get("uid") == "d1" and lq.get("pi") == "0")
            html, stale = page(_url(cid, "d2", "all", 0, 30))
            check("a stale index is re-found by identity", "2 of 3" in html)
            html, tv = page(_url(cid, "d1", "all", 0, 30) + "&kiosk=1")
            check("TV mode marks the dashboard for the kiosk styles", 'class="gdash kiosk"' in html)
            check("...and the next step stays in TV mode", "kiosk=1" in tv.get("next", ""))
            check("...while leaving TV mode keeps the rotation and drops the kiosk",
                  "plist=all" in tv.get("tv-off", "") and "kiosk" not in tv.get("tv-off", "kiosk"))
            check("stop lands on the same dashboard with no rotation",
                  "uid=d1" in tv.get("stop", "") and "plist" not in tv.get("stop", "plist"))
            _, ft = page(_url(cid, "d1", "tag:tv", 0, 30))
            fq = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(ft.get("next", "")).query))
            check("a tag playlist skips what the tag does not select", fq.get("uid") == "d3")
            r = c.get("/monitoring/play?plist=tag:nothing", follow_redirects=False)
            check("an empty playlist says so instead of spinning",
                  r.status_code == 303 and "sec=dashboards" in r.headers.get("location", "")
                  and "err=" in r.headers.get("location", ""))
            _, sc = page(_url(cid, "d1", "all", 0, 30))
            check("scrolling is on by default, with a 5s wait at the end",
                  sc.get("scroll") == "1" and sc.get("hold") == "5")
            check("...and the default is not spelled out in the next link",
                  "scroll=" not in sc.get("next", "") and "hold=" not in sc.get("next", ""))
            _, off = page(_url(cid, "d1", "all", 0, 30) + "&scroll=0&hold=10")
            check("scrolling off is carried to the next dashboard",
                  off.get("scroll") == "0" and "scroll=0" in off.get("next", ""))
            check("...and so is the wait at the end", "hold=10" in off.get("next", "")
                  and "hold=10" in off.get("prev", ""))
            _, big = page(_url(cid, "d1", "all", 0, 30) + "&hold=999")
            check(f"the wait at the end is clamped, got {big.get('hold')}", big.get("hold") == "120")
            r = c.get("/monitoring/play?plist=all&every=30&scroll=0&scroll=1&hold=3", follow_redirects=False)
            check("a ticked box beats the hidden 0 in front of it",
                  "scroll=" not in r.headers.get("location", "") and "hold=3" in r.headers.get("location", ""))
            r = c.get("/monitoring/play?plist=all&every=30&scroll=0", follow_redirects=False)
            check("...and an unticked box sends only the 0", "scroll=0" in r.headers.get("location", ""))
            _, auto = page(_url(cid, "d1", "all", 0, 30))
            check("the scroll speed defaults to auto, and auto is not spelled out",
                  auto.get("speed") == "auto" and "speed=" not in auto.get("next", ""))
            _, sp = page(_url(cid, "d1", "all", 0, 30) + "&speed=90")
            check("a chosen speed is on the bar", sp.get("speed") == "90")
            check("...and rides on next, previous and leaving TV mode",
                  all("speed=90" in sp.get(k, "") for k in ("next", "prev", "tv-off")))
            for asked, want in (("5", "10"), ("9999", "600"), ("fast-please", "auto")):
                _, cl = page(_url(cid, "d1", "all", 0, 30) + f"&speed={asked}")
                check(f"speed {asked!r} is read as {want}, got {cl.get('speed')}", cl.get("speed") == want)
            r = c.get("/monitoring/play?plist=all&every=30&speed=25", follow_redirects=False)
            check("starting with a speed carries it", "speed=25" in r.headers.get("location", ""))
            real_over = main.monitoring.overview
            main.monitoring.overview = lambda conn, refresh=False: {
                "counts": {"critical": 0, "warning": 0, "info": 0}, "alerts": [],
                "dashboards": listing, "item_count": 3, "unit": "dashboard", "note": ""}
            try:
                tab = c.get("/monitoring?sec=dashboards").text
            finally:
                main.monitoring.overview = real_over
            check("the starter offers the speed, auto first",
                  re.search(r'<select name="speed"[^>]*>\s*<option value="auto"', tab) is not None
                  and 'value="250"' in tab)
            _, fast = page(_url(cid, "d1", "all", 0, 1))
            check(f"a one-second rotation is clamped, got {fast.get('every')}", fast.get("every") == "10")
            check("no inline handler on the page",
                  not re.search(r"\son(click|change|submit|keydown|load)=", html))
    finally:
        main.monitoring.dashboards, main.grafana.dashboard = real_list, real_dash


def _url(cid, uid, plist, pi, every):
    import urllib.parse
    return "/monitoring/dashboard?" + urllib.parse.urlencode(
        {"conn": cid, "uid": uid, "plist": plist, "pi": pi, "every": every})


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
