#!/usr/bin/env python3
"""The Clouds account page says what the provider said, and nothing else.

WHY THIS EXISTS
    The network map put provider names into the page raw. A VPC, subnet or
    instance name is whatever somebody typed into the provider's console, and
    `charts.cloud_topology` returns Markup, which Jinja trusts as written — so a
    name like `<b onmouseover=x>evil</b>` became an element on the page. The CSP
    refused the handler, and that was all it refused: in Chrome an injected
    `<img src=x>` still fetched /x, and a name cut at 26 characters in the middle
    of a tag swallowed the `</b>` after it and nested every chip that followed.

    So the main assertion is about SHAPE, not about one payload: rendering
    hostile names must produce exactly the same element tree as rendering plain
    ones. Data may change the text and the attribute values; it may never add,
    remove or rename an element or an attribute. That holds for every field the
    map draws, so a field missed by an escape fails here whichever payload it
    was handed.

    The compute card compared states against Alibaba's spelling, "Running", so
    every AWS account ("running") read "0 running, N stopped". And four views
    each kept their own list of states that mean "up", no two alike: an AWS
    volume "in-use" was amber on the account page, uncoloured on its own page,
    while an unattached one ("available") was green on both. So the counts are
    checked against both providers' spellings, and the same rows against both
    pages.

    The storage card's bucket count linked to /oss, Alibaba's group, for every
    provider: on AWS, whose buckets are the "buckets" group, it was a 404. It
    links to the bucket group the inventory actually holds, and to nothing when
    there is none, and the list it opens must have the number it promised.

    And an Azure account's page did not open at all: its inventory carries no
    billing key, and the spend card read one of its fields, so Azure — the one
    provider with resources and no bucket group — answered 500.

    ./.venv/bin/python tests/test_cloud_page.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time
from html import escape
from html.parser import HTMLParser

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("cloudpage-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import charts, cloud                                   # noqa: E402

EVIL = "<b onmouseover=x>evil</b>"
HOSTILE = [EVIL, "<img src=x onerror=alert(1)>", '"><script>alert(1)</script>',
           "' onmouseover='x", "<i>zone</i>", "a&b<c>d"]
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


class _Shape(HTMLParser):
    """The element tree as (tag, attribute names) in document order, plus every
    text node and attribute value, decoded."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tree, self.text, self.values = [], [], []

    def handle_starttag(self, tag, attrs):
        self.tree.append((tag, tuple(sorted(k for k, _v in attrs))))
        self.values += [v or "" for _k, v in attrs]

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self.tree.append(("/" + tag, ()))

    def handle_data(self, data):
        self.text.append(data)


def shape(markup) -> _Shape:
    p = _Shape()
    p.feed(str(markup))
    p.close()
    return p


def network(name) -> dict:
    """An inventory exercising every field cloud_topology draws, with `name(n)`
    supplying each provider-owned string. Addresses, CIDRs used for placement,
    ids and states stay real, so both renders place things identically."""
    def row(n, rid, kind, state, extra, zone=""):
        return {"name": name(n), "id": rid, "kind": kind, "state": state,
                "extra": extra, "zone": zone}

    groups = [
        {"key": "vpcs", "rows": [
            {"name": name(0), "id": "vpc-1", "kind": name(1), "state": "Available",
             "extra": "", "zone": ""}]},
        {"key": "subnets", "rows": [
            {"name": name(2), "id": "sn-a", "kind": "10.0.1.0/24", "state": "",
             "extra": "250 free IPs · vpc-1", "zone": name(3)},
            {"name": name(4), "id": "sn-b", "kind": "10.0.2.0/24", "state": "",
             "extra": "240 free IPs · vpc-1", "zone": name(5)},
            # not a CIDR in either render, so it holds nothing and draws no bar
            {"name": name(6), "id": "sn-c", "kind": "no-cidr-" + name(7),
             "state": "", "extra": "x free IPs · vpc-1", "zone": ""}]},
        {"key": "compute", "rows": [
            row(8, "i-1", "t3.small", "running", "10.0.1.10"),
            row(9, "i-2", "t3.small", "stopped", "10.0.2.20, 52.0.0.1"),
            row(10, "i-3", "t3.small", "Running", "vpc-1 only"),
            row(11, "i-4", "t3.small", "running", "192.168.9.9")]},
        {"key": "clb", "rows": [
            row(12, "lb-1", "APPLICATION · internet-facing", "active", name(13)),
            row(14, "lb-2", "NETWORK · internal", "active", "10.0.2.30")]},
        {"key": "rds", "rows": [row(15, "db-1", "postgres 16", "available", "10.0.2.40")]},
        {"key": "redis", "rows": [row(16, "r-1", "redis", "available", "nowhere")]},
        {"key": "eips", "rows": [row(17, "eip-1", "vpc", "", name(18))]},
        {"key": "nat", "rows": [{"name": name(19), "id": "nat-1", "kind": name(20),
                                 "state": "available", "extra": "vpc-1", "zone": ""}]},
        {"key": "vpn", "rows": [{"name": name(21), "id": "vpn-1", "kind": name(22),
                                 "state": "active", "extra": "", "zone": ""}]},
    ]
    for g in groups:
        g.update(label=g["key"].upper(), icon="•")
    return {"groups": groups}


def plain(n: int) -> str:
    return f"name-{n}"


def hostile(n: int) -> str:
    return HOSTILE[n % len(HOSTILE)] + f"-{n}"


def same_shape(what: str, benign, evil) -> None:
    a, b = shape(benign), shape(evil)
    check(f"{what}: hostile text changes no element or attribute",
          a.tree == b.tree)
    check(f"{what}: no event handler attribute survives",
          not any(k.startswith("on") for _t, keys in b.tree for k in keys))


def test_network_map() -> None:
    benign = charts.cloud_topology(network(plain))
    evil = charts.cloud_topology(network(hostile))
    same_shape("network map", benign, evil)
    page = shape(evil)
    shown = "".join(page.text) + "".join(page.values)
    check("every hostile name is still shown, as text",
          all(hostile(n)[:20] in shown for n in range(23)))
    check("a name like <b onmouseover=x>evil</b> comes out escaped",
          escape(EVIL) in str(evil) and "<b onmouseover" not in str(evil))

    # the chip shows 26 characters; cutting AFTER escaping splits an entity
    long = "a" * 24 + "&<b>tail"
    got = charts.cloud_topology({"groups": [
        {"key": "subnets", "rows": [{"name": "s", "id": "s", "kind": "10.0.0.0/24",
                                     "extra": "1 free IPs · vpc-1", "zone": ""}]},
        {"key": "vpcs", "rows": [{"name": "v", "id": "vpc-1", "kind": ""}]},
        {"key": "compute", "rows": [{"name": long, "id": "i", "state": "running",
                                     "extra": "10.0.0.5"}]}]})
    p = shape(got)
    check("a long name is cut to 26 characters and then escaped",
          long[:26] in p.text)
    check("the whole name stays in the chip's title", long in p.values)


def test_other_builders() -> None:
    # cloud_map already escaped; this keeps it that way
    def drawn(name):
        return charts.cloud_map(name(0), name(1), name(2), [
            {"key": "compute", "label": name(3), "icon": name(4), "rows": [
                {"name": name(5), "kind": name(6), "state": "running"}]}])
    same_shape("account map", drawn(plain), drawn(hostile))

    # the log histogram's times are the log store's own key_as_string
    def hist(t):
        return charts.histogram([{"t": "2026-10-02T" + t + "Z", "total": 5,
                                  "errors": 1}, {"t": "", "total": 2}])
    same_shape("histogram", hist("10:15"), hist("<img>"))
    check("a histogram time comes out escaped", "&lt;img&gt;" in str(hist("<img>")))

    # colours, classes and units come from templates today; the escape is what
    # keeps that from mattering the day one comes from data
    x = '"><script>x</script>'
    for what, fine, evil in (
            ("donut colour", charts.donut(40, color="var(--ok)"), charts.donut(40, color=x)),
            ("ring colour", charts.ring([("a", 1, "var(--ok)")]), charts.ring([("a", 1, x)])),
            ("sparkline colour", charts.sparkline([1, 2], color="red"),
             charts.sparkline([1, 2], color=x)),
            ("stack class", charts.stack([("ok", 1)]), charts.stack([(x, 1)])),
            ("stack height", charts.stack([("ok", 1)], height=8),
             charts.stack([("ok", 1)], height=x)),
            ("bar unit", charts.hbars([("a", 1)], unit="%"), charts.hbars([("a", 1)], unit=x)),
            ("histogram class", charts.histogram([{"t": "", "total": 1}], bar_class="hb"),
             charts.histogram([{"t": "", "total": 1}], bar_class=x))):
        same_shape(what, fine, evil)


# ── the page itself, rendered through the app ─────────────────────────────
def _offline(*_a, **_k):
    return 599, "offline: this test never reaches a provider"


def plant(acc: str, inv: dict) -> dict:
    """Seed the inventory cache under both keys a page and its links ask for."""
    inv = {"notes": [], "error": "", "stale_for": 0, "billing": {}, "security": {},
           **inv}
    inv["total"] = sum(len(g["rows"]) for g in inv["groups"])
    for region in ("", inv.get("region", "")):
        cloud._inv[cloud._inv_key({"id": acc}, region)] = (time.time(), inv)
    return inv


def account(kind: str, name: str = "", **extra) -> str:
    from app import store
    return store.add_cloud("", {"type": kind, "name": name or f"{kind} account",
                                "key_id": f"KEY-{kind}-{time.time_ns()}", "secret": "s",
                                **extra})


def card(page: str, heading: str) -> str:
    """One card of the summary strip, from its heading to the next card."""
    at = page.find(f"{heading}</span>")
    return page[at:page.find('<div class="card"', at)] if at >= 0 else ""


def page_network(c) -> None:
    aws = account("aws", hostile(30), region="eu-west-1")
    plant(aws, {**network(hostile), "region": "eu-west-1"})
    r = c.get(f"/clouds?account={aws}")
    check("the AWS account page renders", r.status_code == 200)
    page = r.text
    net = page[page.find('<div class="tp">'):]
    net = net[:net.find("Account map by resource kind")]
    check("the page carries the network map", '<div class="tp-vpc">' in net)
    for evil in HOSTILE:
        check(f"{evil!r} never reaches the page as markup", evil not in page)
    check("and it is on the map, escaped", escape(EVIL) in net)


def instances(*states: str) -> dict:
    return {"key": "compute", "label": "Instances", "icon": "🖥", "rows": [
        {"name": f"vm-{i}", "id": f"i-{i}", "kind": "small", "state": s,
         "extra": f"10.9.0.{i + 10}", "zone": "a"} for i, s in enumerate(states)]}


def test_state_rule() -> None:
    # each provider's own spelling of "up", and of not
    for s in ("Running", "running", "RUNNING", " running ", "Available", "available",
              "active", "Active", "In_use", "in-use", "InUse", "ok", "Succeeded"):
        check(f"{s!r} reads as up", cloud.state_ok(s))
    for s in ("Stopped", "stopped", "terminated", "shutting-down", "Starting",
              "pending", "Pending", "failed", "", None):
        check(f"{s!r} does not read as up", not cloud.state_ok(s))


def test_one_rule() -> None:
    """The network map and the account map ask cloud.state_ok, like the pages."""
    states = ["Running", "running", "active", "in-use", "In_use", "InUse", "ok",
              "Succeeded", "available", "Stopped", "terminated", "Starting",
              "deleting", "pending"]
    topo = str(charts.cloud_topology({"groups": [
        {"key": "vpcs", "rows": [{"name": "v", "id": "vpc-1", "kind": "10.0.0.0/16"}]},
        {"key": "subnets", "rows": [{"name": "s", "id": "sn", "kind": "10.0.0.0/24",
                                     "extra": "200 free IPs · vpc-1", "zone": "a"}]},
        {"key": "compute", "rows": [{"name": f"vm{i}", "id": f"i{i}", "state": s,
                                     "extra": f"10.0.0.{i + 10}"}
                                    for i, s in enumerate(states)]}]}))
    lanes = [{"key": f"k{n}", "label": "x", "icon": "", "rows": [
        {"name": f"vm{i}", "kind": "", "state": s}
        for i, s in enumerate(states) if i // 7 == n]} for n in range(2)]
    amap = str(charts.cloud_map("a", "p", "r", lanes))
    for i, s in enumerate(states):
        up = cloud.state_ok(s)
        chip = re.search(rf'<div class="(tp-chip[^"]*)"><span>[^<]*</span>'
                         rf'<b title="vm{i}">', topo)
        check(f"network map: {s!r} is {'drawn' if up else 'faded'}",
              chip is not None and ("tp-off" in chip.group(1)) != up)
        rect = re.search(rf'stroke="([^"]+)" stroke-width="1"/><text[^>]*>vm{i}</text>',
                         amap)
        check(f"account map: {s!r} is outlined {'ok' if up else 'warn'}",
              rect is not None and (rect.group(1) == "var(--ok-ink)") == up)


def page_compute(c) -> None:
    # AWS spells its states in lower case, Alibaba capitalises them, and each
    # has states that are neither running nor stopped
    for kind, states, running, stopped in (
            ("aws", ("running", "running", "stopped", "terminated", "running",
                     "pending"), 3, 1),
            ("alibaba", ("Running", "Stopped", "Starting", "Running"), 2, 1)):
        acc = account(kind, region="r-1")
        plant(acc, {"groups": [instances(*states)], "region": "r-1"})
        r = c.get(f"/clouds?account={acc}")
        box = card(r.text, "compute")
        check(f"{kind}: the account page renders", r.status_code == 200 and box)
        check(f"{kind}: the compute card counts {running} running",
              re.search(rf"(?<!\d){running} running<", box) is not None)
        pct = round(running / len(states) * 100)
        check(f"{kind}: the ring is {pct}% full, with {running} in its centre",
              f'aria-label="{running} {pct}%"' in box)
        check(f"{kind}: {stopped} stopped, and only the stopped ones",
              re.search(rf"(?<!\d){stopped} stopped, still billed for storage", box)
              is not None)


def page_states(c) -> None:
    """One rule for "up": the account page's tables and the resource page agree."""
    acc = account("aws", region="eu-west-1")
    disks = {"key": "disks", "label": "EBS volumes", "icon": "💽", "rows": [
        {"name": "root", "id": "vol-1", "kind": "gp3 · 8 GiB", "state": "in-use",
         "extra": "i-1", "zone": "a"},
        {"name": "spare", "id": "vol-2", "kind": "gp3 · 8 GiB", "state": "available",
         "extra": "not attached", "zone": "a"},
        {"name": "old", "id": "vol-3", "kind": "gp3 · 8 GiB", "state": "deleting",
         "extra": "not attached", "zone": "a"}]}
    lbs = {"key": "clb", "label": "Load balancers", "icon": "⚖", "rows": [
        {"name": "edge", "id": "lb-1", "kind": "APPLICATION · internal",
         "state": "active", "extra": "10.9.0.99", "zone": ""}]}
    plant(acc, {"groups": [instances("running", "stopped"), disks, lbs],
                "region": "eu-west-1"})
    account_page = c.get(f"/clouds?account={acc}").text
    for group, state, up in (("disks", "in-use", True), ("disks", "available", True),
                             ("disks", "deleting", False), ("clb", "active", True),
                             ("compute", "stopped", False)):
        cls = re.search(rf'<span class="sv (sv-\w+)"[^>]*>{state}</span>', account_page)
        check(f"account page: {state} is {'up' if up else 'not up'}",
              cls and cls.group(1) == ("sv-ok" if up else "sv-medium"))
        listing = c.get(f"/clouds/r/{acc}/{group}").text
        style = re.search(rf'<span\s+style="([^"]*)">{state}</span>', listing)
        check(f"/{group} page: {state} is {'up' if up else 'not up'}, as on the account page",
              style and ("ok-ink" in style.group(1)) == up)
    check("the account map strokes an active balancer as up",
          re.search(r'stroke="var\(--ok-ink\)" stroke-width="1"/><text[^>]*>edge<',
                    account_page) is not None)


def buckets(key: str, n: int) -> dict:
    return {"key": key, "label": "Buckets", "icon": "🪣", "rows": [
        {"name": f"bucket-{i}", "id": f"bucket-{i}", "kind": "bucket", "state": "",
         "extra": "", "zone": ""} for i in range(n)]}


def bucket_line(page: str) -> str:
    box = card(page, "storage")
    got = re.search(r'<div class="statsub" style="margin:4px 0 0;">(.*?)</div>', box, re.S)
    return got.group(1) if got else ""


def page_buckets(c) -> None:
    """The storage card's bucket count opens that provider's own bucket list."""
    for kind, key, n in (("aws", "buckets", 3), ("alibaba", "oss", 2)):
        acc = account(kind, region="r-1")
        plant(acc, {"groups": [instances("running"), buckets(key, n)], "region": "r-1"})
        line = bucket_line(c.get(f"/clouds?account={acc}").text)
        link = re.search(r'<a href="([^"]+)">(\d+) buckets?</a>', line)
        check(f"{kind}: the bucket count is a link to /clouds/r/<account>/{key}",
              link is not None and link.group(1) == f"/clouds/r/{acc}/{key}?region=r-1")
        if not link:
            continue
        r = c.get(link.group(1))
        rows = r.text.count('<td class="jname">')
        check(f"{kind}: the link opens the bucket list ({r.status_code})",
              r.status_code == 200)
        check(f"{kind}: and the list has exactly the {link.group(2)} it promised",
              rows == int(link.group(2)) == n)
        if kind == "aws":
            check("aws: there is no /oss group to link to (what the card did)",
                  c.get(f"/clouds/r/{acc}/oss?region=r-1").status_code == 404)

    # S3 refused (no s3:ListAllMyBuckets): no bucket group, so nothing to open
    acc = account("aws", region="r-1")
    plant(acc, {"groups": [instances("running")], "region": "r-1",
                "notes": ["S3 buckets: HTTP 403 — the key needs s3:ListAllMyBuckets"]})
    line = bucket_line(c.get(f"/clouds?account={acc}").text)
    check("no bucket group: the count is shown", "0 buckets" in line)
    check("and it is not a link to a page that does not exist", "<a" not in line)


def page_azure(c) -> None:
    """An Azure account opens. Its inventory has no billing key, and the spend
    card read a field of the missing one: the whole page was a 500. Only the
    two ARM calls are faked, so this is the real reader's shape, not a plant."""
    import json

    def arm(url, headers=None, data=None, tries=2):
        if "login.microsoftonline.com" in url:
            return 200, json.dumps({"access_token": "t"})
        if "/resources" in url:
            return 200, json.dumps({"value": [
                {"type": "Microsoft.Compute/virtualMachines", "name": f"vm-{i}",
                 "id": f"/subscriptions/s/vm-{i}", "location": "westeurope",
                 "sku": {"name": "Standard_B2s"}} for i in range(2)] + [
                {"type": "Microsoft.Storage/storageAccounts", "name": "st01",
                 "id": "/subscriptions/s/st01", "location": "westeurope",
                 "sku": {"name": "Standard_LRS"}}]})
        return _offline()

    acc = account("azure", tenant="t-1", region="sub-1")
    cloud._get = arm
    try:
        r = c.get(f"/clouds?account={acc}")
    finally:
        cloud._get = _offline
    check(f"the Azure account page renders ({r.status_code})", r.status_code == 200)
    check("its virtual machines are listed", "vm-1" in r.text)
    line = bucket_line(r.text)
    check("Azure has no bucket group, so the count is not a link",
          "bucket" in line and "<a" not in line)


def test_pages() -> None:
    from fastapi.testclient import TestClient
    from app import auth, db, main

    # Nothing here may reach a cloud: the warmer stays off, and every network
    # seam answers "offline". Not restored afterwards — threads the page starts
    # (the bills trend) may still be running when this returns.
    cloud._warm_started = True
    cloud.aws_signed = _offline
    cloud._get = _offline
    cloud._oss_get = _offline
    cloud._alibaba_rpc = lambda *a, **k: (403, {"Code": "Offline", "Message": "offline"})

    email, pw = "clouds@test.local", "Clouds-Page-Says-What-It-Read-42"
    uid = auth.create_user(email, "Clouds", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    # a 500 is an answer to check, not an exception that ends the run
    c = TestClient(main.app, raise_server_exceptions=False)
    with c:
        c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
        page_network(c)
        page_compute(c)
        page_states(c)
        page_buckets(c)
        page_azure(c)


def main() -> int:
    test_network_map()
    test_other_builders()
    test_state_rule()
    test_one_rule()
    test_pages()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
