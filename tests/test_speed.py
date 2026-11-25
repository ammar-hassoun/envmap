#!/usr/bin/env python3
"""The properties that make the portal feel instant, held so they stay held.

WHY THIS EXISTS
    The backend renders a page in 2-3 milliseconds; what a person felt as lag
    was the wire. Measured before anything was changed: ~230kB of uncompressed
    HTML per navigation, none of it cacheable, because the whole stylesheet
    rode inline in base.html. Three properties fixed it and each is one
    careless edit from quietly coming back:

      1. **Responses are compressed** — and the event streams are NOT, because
         gzip without a per-event flush holds live log lines inside the
         compressor until it feels full. This starlette's responder excludes
         text/event-stream; that exclusion is exactly what this file pins.
      2. **The stylesheet is a versioned, immutably-cached file.** Inline it is
         most of every page; as a file it downloads once per release. The ?v=
         is what makes the year-long cache safe.
      3. **Hover prefetch** warms the next page — and must never touch /logout
         (a GET that ends the session) or a ?refresh= link (cache invalidation
         is work, not a read).

    ./.venv/bin/python tests/test_speed.py
"""
from __future__ import annotations

import gzip as gzipmod
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("speed-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    from fastapi.testclient import TestClient

    from app import auth, db, main

    email, pw = "speed@test.local", "No-Lag-Anywhere-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    print("pages travel compressed")
    r = c.get("/ansible", headers={"Accept-Encoding": "gzip"})
    check(f"the page is gzipped ({r.headers.get('content-encoding')})",
          r.headers.get("content-encoding") == "gzip")
    # TestClient hands back the decoded body; the wire size is what matters
    wire = len(gzipmod.compress(r.content, 9))
    check(f"and small on the wire ({wire:,} bytes from {len(r.content):,})",
          wire < 60_000)
    # explicitly identity: the TestClient itself asks for gzip by default,
    # which is how the first version of this check tested nothing
    plain = c.get("/ansible", headers={"Accept-Encoding": "identity"})
    check("a client that cannot take gzip still gets the page",
          plain.status_code == 200
          and plain.headers.get("content-encoding") in (None, "identity"))

    print("the event streams are NOT compressed")
    # gzip without a per-event flush would hold live log lines inside the
    # compressor — the follow button working is the reason for this exclusion.
    import inspect
    streams = inspect.getsource(main).count('media_type="text/event-stream"')
    check(f"there are streams to protect ({streams})", streams >= 2)
    src = pathlib.Path(__import__("starlette.middleware.gzip",
                                  fromlist=["x"]).__file__).read_text()
    check("this starlette excludes event streams from gzip",
          "text/event-stream" in src)

    print("the stylesheet is a file the browser keeps")
    base = (ROOT / "templates" / "base.html").read_text()
    check("base.html links it with the version as cache-buster",
          re.search(r'href="/static/app\.css\?v=\{\{ portal_version\(\) \}\}"',
                    base) is not None)
    check("and carries no big inline stylesheet any more",
          all(len(b) < 4000 for b in
              re.findall(r"<style>(.*?)</style>", base, re.S)))
    css = ROOT / "static" / "app.css"
    check("the file exists and is the real sheet",
          css.exists() and css.stat().st_size > 100_000)
    got = c.get("/static/app.css?v=test")
    check(f"served immutably for a year ({got.headers.get('cache-control')})",
          "immutable" in (got.headers.get("cache-control") or "")
          and "max-age=31536000" in (got.headers.get("cache-control") or ""))
    page = c.get("/ansible")
    # 121k, not 120k: the CSP nonce is ~30 bytes on each of the page's ten
    # <script> tags, and that 300 bytes is the mechanism itself rather than
    # slack to spend on markup. The dispatcher that replaced 112 inline
    # handlers is in static/ precisely so it does not land here.
    check(f"a page is a fraction of its old self ({len(page.content):,} bytes)",
          len(page.content) < 121_000)

    print("a row carries identifiers, not five copies of the same URL")
    # Measured on the real fleet: the pods table serialised project, cluster,
    # namespace and pod about five times per row — once per href plus one per
    # data-URL — which made the ACTION CELL 72% of every row and the page
    # 1.4MB. 150kB re-parsed per navigation was once the entire perceived lag
    # here, so this is the same mistake an order of magnitude larger. The URL
    # is a template and belongs in the dialog that uses it; the row carries
    # the four identifiers. This asserts the SHAPE, not a byte count, because
    # a byte count would fail for every legitimate new column.
    bits = (ROOT / "templates" / "_bits.html").read_text()
    for macro in ("cluster_podlog_attrs", "describe_attrs"):
        body = bits.split("macro " + macro, 1)[1].split("endmacro", 1)[0]
        check(f"{macro} emits identifiers", "data-pid=" in body
              and "data-cid=" in body)
        check(f"{macro} does not stamp a built URL into every row",
              "/clusters/" not in body)
    for dlg, key in (("_logs_dialog.html", "dataset.stream ||"),
                     ("_describe_dialog.html", "dataset.dsurl ||")):
        text = (ROOT / "templates" / dlg).read_text()
        check(f"{dlg} builds the URL, and still accepts one outright "
              f"(env.html passes its own)", key in text)

    print("hover prefetch, with the two carve-outs that matter")
    check("the script ships on every page", "rel = 'prefetch'" in base
          or "l.rel = 'prefetch'" in base)
    # /logout is a GET that ends the session: prefetching it on a stray hover
    # would sign somebody out mid-thought. refresh= links do invalidation work.
    check("it will never prefetch a logout",
          "/logout" in base.split("prefetch")[0][-2000:]
          or "'/logout'" in base)
    check("nor a refresh link", "refresh=" in base)
    check("and same-origin only — no protocol-relative escape",
          "startsWith('//')" in base)

    no_page_waits_out_a_live_read()

    print("OK" if not bad else f"{bad} FAILED")
    return bad


# ── the deadline on every read of somebody else's system ───────
def no_page_waits_out_a_live_read() -> None:
    """No page is allowed to be as slow as the slowest thing it reads.

    WHY THIS EXISTS
        Measured against a real estate of 24 clusters and 10 connections, with
        nothing warmed — which is the state after every deploy, pod restart and
        upgrade, so it is not an unusual state:

            /gitops   19.6s        /            10.4s
            /bmc      16.1s        /nodes       14.1s
                                   /pods        10.8s

        Every one of those was under 15ms warm. The whole cost was the FIRST
        read, waited out in full, and each page had arrived there independently
        by writing `_pmap(...)` over its connections and joining every thread.
        The warmer could not save them either: it starts when the process
        starts, so the person who opens the portal first is racing it and
        loses.

        The rule this pins is that a page paints from what has ARRIVED and says
        what has not. Three deadlines implement it — fleet.FIRST_PAINT for the
        snapshot, cluster._gather_fleet for the fleet-wide cluster reads, and
        gather._ACROSS for the per-connection pages — and this checks the
        BEHAVIOUR of each rather than that the constants exist, because a
        constant nothing consults is not a deadline.
    """
    import time

    from app import cluster, fleet, gather

    print("a cold fleet snapshot paints instead of waiting")
    slow_calls = {"n": 0}

    def slow_health(pid, project, cid, c):
        slow_calls["n"] += 1
        time.sleep(3.0)                      # an unreachable cluster's timeout
        return {"pid": pid, "project": "P", "icon": "📦", "cid": cid,
                "name": c.get("name", cid), "context": "", "reachable": True,
                "error": "", "nodes": {"total": 3, "ready": 3},
                "pods": {"total": 9, "running": 9, "bad": 0, "pending": 0},
                "cpu": None, "mem": None, "problems": [], "used_by": [],
                "top_ns": [], "namespaces": 1}

    real_health, real_projects = fleet._cluster_health, fleet._projects
    real_store = fleet.store.projects
    fleet._cluster_health = slow_health
    fleet._projects = lambda: [{"id": "p1", "name": "Payments", "icon": "📦",
                                "tagline": "", "regions": 1, "clusters": 2,
                                "envs": 2, "services": 7}]
    # The sandbox database is empty, so without an inventory to read _collect()
    # finishes instantly and the deadline is never exercised — the test would
    # pass against the unbounded code it exists to catch.
    fleet.store.projects = lambda: {"p1": {
        "name": "Payments", "icon": "📦", "regions": {},
        "clusters": {"c1": {"name": "one"}, "c2": {"name": "two"}}}}
    try:
        fleet.invalidate()
        t = time.monotonic()
        got = fleet.overview()
        took = time.monotonic() - t
        check(f"it returns in about the first paint, not the read "
              f"({took * 1000:.0f}ms, deadline {fleet.FIRST_PAINT}s)",
              took < fleet.FIRST_PAINT + 0.6)
        check(f"and says the live parts are still coming ({got.get('pending')})",
              got.get("pending") is True and got.get("stale") is True)
        # THE FAILURE THAT WOULD BE WORSE THAN BEING SLOW. home.html draws
        # "Nothing connected yet" from an empty project list, so a skeleton
        # without one tells somebody with four projects that they have none.
        check(f"the projects it already knows are on the page "
              f"({len(got['projects'])})", len(got["projects"]) == 1)
        check(f"as is the true cluster count, which is free "
              f"({got['totals']['clusters']})",
              got["totals"]["clusters"] == 2)
        # and the collection it started is still running, so the next look has it
        time.sleep(3.4)
        after = fleet.overview()
        check(f"the read it kicked off lands behind the page "
              f"({len(after['clusters'])} clusters, pending="
              f"{after.get('pending')})",
              len(after["clusters"]) == 2 and not after.get("pending"))

        print("Refresh still means wait — it is somebody asking for fresh data")
        fleet.invalidate()
        t = time.monotonic()
        forced = fleet.overview(force=True)
        check(f"force=True waits for the real numbers "
              f"({(time.monotonic() - t) * 1000:.0f}ms)",
              len(forced["clusters"]) == 2 and not forced.get("pending"))
    finally:
        fleet._cluster_health, fleet._projects = real_health, real_projects
        fleet.store.projects = real_store
        fleet.invalidate()

    print("reading every connection is bounded, and names what is missing")
    conns = [{"id": "c1", "name": "fast one"}, {"id": "c2", "name": "slow one"}]

    def read(c):
        if c["id"] == "c2":
            time.sleep(3.0)
        return {"conn": c, "rows": [1, 2]}

    t = time.monotonic()
    rows, pending = gather.across("test-across", conns, read)
    took = time.monotonic() - t
    check(f"it does not wait for the slow connection ({took * 1000:.0f}ms)",
          took < 1.2)
    check(f"the one that answered is on the page ({len(rows)})", len(rows) == 1)
    # Named, not silently absent: a page that quietly drops a controller reads
    # as an estate with fewer controllers in it.
    check(f"and the one that did not is NAMED ({pending})",
          pending == ["slow one"])

    print("...and Refresh on those pages waits too")
    t = time.monotonic()
    rows, pending = gather.across("test-across-2", conns, read, refresh=True)
    check(f"refresh=True returns everything ({len(rows)} rows, "
          f"{(time.monotonic() - t):.1f}s)", len(rows) == 2 and not pending)

    print("order is stable, so rows do not reshuffle between loads")
    many = [{"id": f"c{i}", "name": f"conn {i}"} for i in range(6)]
    rows, _p = gather.across("test-order", many,
                             lambda c: {"id": c["id"]}, refresh=True)
    check(f"rows come back in the order the connections were given "
          f"({[r['id'] for r in rows]})",
          [r["id"] for r in rows] == [c["id"] for c in many])

    print("the fleet-wide cluster reads have their own, shorter deadline")
    # Borrowing the cluster TAB's 1.3s was measured spending it for nothing:
    # twenty-four clusters never finish inside it, so /nodes and /pods paid the
    # wait and drew the skeleton anyway.
    check(f"it is the fleet's deadline, not the tab's "
          f"({cluster._gather_fleet.first_paint} vs {cluster._gather.first_paint})",
          cluster._gather_fleet.first_paint == fleet.FIRST_PAINT
          and cluster._gather_fleet.first_paint < cluster._gather.first_paint)
    check("and everywhere() reports what it could not read",
          callable(getattr(cluster, "pending_clusters", None)))

    print("every page that can be short SAYS it is short")
    # The banner is the honest half of the deadline. Without it the page is
    # simply wrong: a table of 8 clusters on an estate of 24, with nothing to
    # say the other 16 are still coming.
    for tmpl in ("fleet_nodes.html", "fleet_pods.html", "gitops.html",
                 "bmc.html", "virt.html", "workflows.html"):
        body = (ROOT / "templates" / tmpl).read_text()
        check(f"{tmpl} renders the collecting banner",
              "bits.collecting(pending" in body)
        check(f"{tmpl} imports the macros it uses",
              '"_bits.html" as bits' in body)


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
