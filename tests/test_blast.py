#!/usr/bin/env python3
"""What breaks if this certificate is not renewed — and the one reverse index.

Two things ship together here because they are the same question from two
ends. `store.serves()` is the single cluster-to-environments index that six
pages each built inline in a different shape; `expiry.blast_radius()` is the
first reader that needed it for something other than a label.

The load-bearing checks are the ones about being WRONG in a particular
direction:

  * a wildcard must match ONE label (RFC 6125). Matching by suffix overstates
    the blast radius, and somebody reads this to decide whether a renewal is
    urgent -- a list padded with hosts the certificate does not serve is how a
    number stops being trusted.
  * an unreachable cluster must NOT come back as "nothing uses it". That is
    the same right answer as a certificate nobody needs, on the page where the
    difference decides whether somebody works this evening.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_blast.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("blast-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import cluster as REAL_CLUSTER                        # noqa: E402
from app import expiry, store                                  # noqa: E402

# HELD BEFORE ANYTHING SWAPS `sys.modules`. `expiry_part_swap` below replaces
# the entry with a stub so the walk can be driven without a cluster, so a
# later `from app import cluster` hands back the STUB -- which has no `kube`
# and no `_part_tls`. The module object itself stays valid, so a reference
# taken now is the real one for the whole run.

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    print(("  ok  " if cond else "  FAIL ") + what)
    if not cond:
        bad += 1


VIEW = {
    "p1": {
        "name": "Estate",
        "clusters": {"c1": {"id": "c1", "name": "dev"},
                     "c2": {"id": "c2", "name": "lonely"}},
        "regions": {
            "r1": {"name": "KE", "flag": "\U0001F1F0\U0001F1EA",
                   "env_clusters": {"preprod": "c1", "test": "c1"},
                   "envs": {"preprod": ["a.yaml", "b.yaml"], "test": []},
                   "bind": {"preprod": {"url": "git@x/y", "branch": "main"}}},
            "r2": {"name": "TZ", "env_clusters": {"dev": "c1", "gone": ""},
                   "envs": {}, "bind": {}},
        },
    },
    "p2": {"name": "Other", "clusters": {"c9": {"id": "c9"}},
           "regions": {"r9": {"name": "ZA", "env_clusters": {"prod": "c9"}}}},
}


def main() -> int:
    print("ONE cluster-to-environments index, where six used to be")
    got = store.serves(VIEW)
    check("a cluster serving three environments lists three",
          len(got.get("c1") or []) == 3)
    check("...sorted by region then environment, so a page is stable",
          [(r["region"], r["env"]) for r in got["c1"]]
          == [("KE", "preprod"), ("KE", "test"), ("TZ", "dev")])
    # A cluster nothing points at is ABSENT, not present-and-empty: "unmapped"
    # is a word several of these pages render deliberately, and it is theirs.
    check("a cluster nothing points at is absent, not empty", "c2" not in got)
    check("a blank mapping is not an environment called ''",
          not any(r["env"] == "gone" for r in got["c1"]))
    check("scoping to a project drops the others",
          set(store.serves(VIEW, "p1")) == {"c1"})

    print("...carrying every shape the six call sites wanted")
    row = next(r for r in got["c1"] if r["env"] == "preprod")
    check("the label spelling (cluster card, used_by)", row["label"] == "KE / preprod")
    check("the where spelling (top bar column)", row["where"] == "KE/preprod")
    check("the url", row["url"] == "/p/p1/r1/preprod")
    check("the region, rgid, flag and env", row["region"] == "KE"
          and row["rgid"] == "r1" and row["env"] == "preprod" and row["flag"])
    # `bind`/`files` come from the ENRICHED view only. A caller that has not
    # read the checkout gets {} and 0 -- exactly what the inline versions did.
    check("bind and files come through an enriched view",
          row["bind"].get("branch") == "main" and row["files"] == 2)
    plain = store.serves({"p1": {"name": "E", "clusters": {"c1": {}},
                                 "regions": {"r1": {"name": "KE",
                                             "env_clusters": {"preprod": "c1"}}}}})
    check("...and are empty, not absent, without one",
          plain["c1"][0]["bind"] == {} and plain["c1"][0]["files"] == 0)

    print("a wildcard covers ONE label — RFC 6125, and the safe direction")
    for san, host, want in (
            ("api.example.com", "api.example.com", "exact"),
            ("API.Example.COM", "api.example.com.", "exact"),
            ("*.example.com", "api.example.com", "wildcard"),
            ("*.example.com", "api.eu.example.com", ""),
            ("*.example.com", "example.com", ""),
            ("*.example.com", "", ""),
            ("", "api.example.com", ""),
            ("*.example.com", ".example.com", ""),
    ):
        check(f"covers({san!r}, {host!r}) is {want!r}",
              expiry.covers(san, host) == want)

    print("the walk answers about hosts, routes and services")
    net = {"routes": [
        {"kind": "Ingress", "api": "ingress", "namespace": "shop",
         "name": "web", "hosts": ["api.example.com"],
         "tls_hosts": ["api.example.com"], "tls": True, "class": "nginx",
         "services": ["web:80", "web-canary:80"]},
        {"kind": "IngressRoute", "api": "ingressroute", "namespace": "shop",
         "name": "admin", "hosts": ["admin.example.com"], "tls_hosts": [],
         "tls": True, "class": "", "services": ["admin"]},
        {"kind": "Ingress", "api": "ingress", "namespace": "other",
         "name": "nope", "hosts": ["elsewhere.test"], "tls_hosts": [],
         "tls": False, "class": "", "services": ["nope"]},
    ], "services": []}

    calls = []
    real_part, real_get, real_projects = (
        expiry_part_swap(net, calls), store.get_cluster, store.projects)
    store.get_cluster = lambda pid, cid: (VIEW.get(pid, {})
                                          .get("clusters", {}).get(cid))
    store.projects = lambda: VIEW
    try:
        b = expiry.blast_radius("p1", "c1",
                                ["*.example.com", "unrouted.example.com"])
        check("both routed hosts are found",
              [h["host"] for h in b["hosts"]]
              == ["admin.example.com", "api.example.com"])
        check("...each labelled as covered by the wildcard",
              {h["how"] for h in b["hosts"]} == {"wildcard"})
        # hosts and tls_hosts overlap on a TLS ingress; counting both would
        # report the same host twice.
        check("a host on both hosts and tls_hosts is counted once",
              len([h for h in b["hosts"] if h["host"] == "api.example.com"]) == 1)
        check("the backend services come through",
              b["services"] == ["admin", "web-canary:80", "web:80"])
        check("a route in an unrelated namespace is not dragged in",
              b["namespaces"] == ["shop"])
        check("a name on the certificate that routes nowhere is reported",
              b["unmatched"] == ["unrouted.example.com"])
        check("the denominator is stated", b["routes_seen"] == 3)
        check("the environments the CLUSTER serves ride along",
              [r["env"] for r in b["environments"]] == ["preprod", "test", "dev"])
        check("ONE cluster read, not a fan-out", len(calls) == 1)

        # An exact match is a better explanation than a wildcard one.
        b2 = expiry.blast_radius("p1", "c1",
                                 ["*.example.com", "api.example.com"])
        hit = next(h for h in b2["hosts"] if h["host"] == "api.example.com")
        check("an exact name wins the label over a wildcard that also covers it",
              hit["how"] == "exact")

        # ── the direction that must never be wrong ───────────────────────
        expiry_part_swap({"error": "unreachable", "routes": []}, calls)
        b3 = expiry.blast_radius("p1", "c1", ["*.example.com"])
        check("an UNREACHABLE cluster is an error, not 'nothing uses it'",
              b3["error"] == "unreachable" and not b3["hosts"])
        b4 = expiry.blast_radius("p1", "nosuch", ["*.example.com"])
        check("an unregistered cluster says so", bool(b4["error"]))
        b5 = expiry.blast_radius("p1", "c1", [])
        check("a certificate with no names says so, rather than tracing nothing",
              bool(b5["error"]))
    finally:
        store.get_cluster, store.projects = real_get, real_projects
        del real_part

    print("the page offers it, and disables it rather than hiding it")
    tpl = (ROOT / "templates" / "expiry.html").read_text()
    body = re.sub(r"\{#.*?#\}", "", tpl, flags=re.S)   # comments are not code
    check("the row carries a what-breaks control", "data-blast=" in body)
    check("...disabled with a reason when it cannot be traced",
          "disabled" in body and "not on a registered cluster" in body)
    check("...and the window is included once",
          body.count('_blast_dialog.html') == 1)
    win = re.sub(r"\{#.*?#\}", "",
                 (ROOT / "templates" / "_blast_dialog.html").read_text(),
                 flags=re.S)
    # `.psh-body` is pre-wrap in app.css for the LOG window; a window of
    # ordinary markup must opt out or every newline becomes ~40px of gap.
    check("the window opts out of psh-body's pre-wrap",
          "white-space: normal" in win)
    check("...numbers its opens, so two clicks cannot cross-fill it",
          "seq" in win and "mine !== seq" in win)

    print("the four page-lies are fixed")
    # COMMENTS STRIPPED FIRST. The comment explaining this fix names the
    # wrong spelling it replaced, so an un-stripped read fails a CORRECT
    # implementation -- the mirror image of a test its own documentation can
    # satisfy, and this codebase has been bitten by both directions.
    ex = "\n".join(re.sub(r"#.*$", "", ln) for ln
                    in (ROOT / "app" / "expiry.py").read_text().splitlines())
    check("the warranty row reads `env`, not `environment`",
          'a.get("env")' in ex and 'a.get("environment")' not in ex)
    asst = (ROOT / "app" / "assistant.py").read_text()
    check("the briefing counts physical/virtual out of `classes`",
          'cls.get(\'physical\'' in asst or 'cls.get("physical"' in asst)
    pm = (ROOT / "app" / "pam.py").read_text()
    check("pam_targets.asset_id finally has a reader",
          "_asset_facts" in pm and "hostname_from" in pm)

    print("in-cluster names are answered too, which is most of a real estate")
    # The reported symptom: every row on a customer's radar was a
    # CloudNativePG internal certificate, and the walk matched only ingress
    # hosts -- so it answered "nothing matched" for all of them and read as a
    # broken button. `_part_network` already returns every Service and this
    # ignored the list entirely.
    check("a Service's in-cluster DNS ladder, longest first",
          expiry.service_names("cnpg-system-ae", "cnpg-webhook-service")
          == ["cnpg-webhook-service.cnpg-system-ae.svc.cluster.local",
              "cnpg-webhook-service.cnpg-system-ae.svc",
              "cnpg-webhook-service.cnpg-system-ae",
              "cnpg-webhook-service"])
    check("...and nothing at all without both parts",
          expiry.service_names("", "x") == []
          and expiry.service_names("ns", "") == [])

    NS = "acme-datalake-dev"
    svc_net = {"routes": [], "services": [
        {"namespace": NS, "name": "postgres-airflow-rw", "type": "ClusterIP",
         "published": False, "ports": ["5432"]},
        {"namespace": "other", "name": "shared", "type": "ClusterIP",
         "published": False, "ports": ["80"]},
        {"namespace": "second", "name": "shared", "type": "LoadBalancer",
         "published": True, "ports": ["80"]},
    ]}
    calls2 = []
    expiry_part_swap(svc_net, calls2)
    store.get_cluster = lambda pid, cid: (VIEW.get(pid, {})
                                          .get("clusters", {}).get(cid))
    store.projects = lambda: VIEW

    # exactly the SAN ladder CloudNativePG puts on a server certificate
    ladder = ["postgres-airflow-rw", f"postgres-airflow-rw.{NS}",
              f"postgres-airflow-rw.{NS}.svc",
              f"postgres-airflow-rw.{NS}.svc.cluster.local",
              "nothing-answers-to-this.example"]
    b = expiry.blast_radius("p1", "c1", ladder)
    check("a CloudNativePG server certificate resolves to its Service",
          [(r["namespace"], r["service"]) for r in b["services_in"]]
          == [(NS, "postgres-airflow-rw")])
    check("...credited to the most specific name that matched",
          b["services_in"][0]["form"]
          == f"postgres-airflow-rw.{NS}.svc.cluster.local")
    check("...and it is marked in-cluster only, not published",
          b["services_in"][0]["published"] is False)
    # THE WHOLE LADDER NAMES ONE SERVICE. Scoring `unmatched` from the single
    # kept form reported the other three as "routed nowhere" -- four names,
    # one service, three of them alarming for no reason.
    check("every form of the same name counts as matched, not just the kept one",
          b["unmatched"] == ["nothing-answers-to-this.example"])
    check("...and the window knows it has an internal answer to show",
          b["internal"] is True)

    print("...and it refuses to guess when a bare name is genuinely ambiguous")
    b = expiry.blast_radius("p1", "c1", ["shared"])
    check("two namespaces offering the name resolves to NEITHER",
          b["services_in"] == [])
    check("...it is reported as undecidable, naming both",
          len(b["ambiguous"]) == 1
          and b["ambiguous"][0]["could_be"] == ["other/shared", "second/shared"])
    # Overstating the radius is the one direction this must never be wrong in,
    # so an undecided name contributes to no tally at all.
    check("...and contributes to no service or namespace count",
          not b["services"] and not b["namespaces"])

    print("...but ONE candidate is resolved, not warned about")
    # A bare name is on every CNPG certificate, so treating single-candidate
    # as ambiguous put a warning beside every ordinary row.
    only = {"routes": [], "services": [svc_net["services"][0]]}
    expiry_part_swap(only, calls2)
    b = expiry.blast_radius("p1", "c1", ["postgres-airflow-rw"])
    check("a bare name with one candidate resolves",
          [(r["namespace"], r["service"]) for r in b["services_in"]]
          == [(NS, "postgres-airflow-rw")])
    check("...with nothing reported as undecidable", b["ambiguous"] == [])

    print("...and the empty state says WHY, rather than looking broken")
    body = re.sub(r"\{#.*?#\}", "",
                  (ROOT / "templates" / "_blast_body.html").read_text(),
                  flags=re.S)
    flat0 = " ".join(body.split())
    check("it names both passes it made", "every ingress host" in flat0
          and "every Service name" in flat0)
    # WHITESPACE NORMALISED: the sentence is line-wrapped in the template, so
    # a contiguous-substring check fails a correct template -- the same trap
    # as reading source without stripping comments, one layer along.
    flat = " ".join(body.split())
    check("...and says the answer is not a failure",
          "not broken and neither is this answer" in flat)
    check("the in-cluster rows are their own labelled section",
          "In-cluster names" in body and "bl-sec" in body)
    check("...and the external table is not rendered as a bare header",
          "{% if b.hosts %}" in body)

    print("a FAILED cluster read is not a clean cluster")
    # `_text` returned "" for every failure -- a denied `secrets -A`, a wrong
    # template, a timeout -- and `_part_tls` turned that into
    # {present: True, certs: [], manual: 0}. The radar then rendered that
    # cluster as having nothing that needs attention, on the page whose whole
    # job is to say what nobody is watching.
    import subprocess as _sp
    expiry_part_restore()
    _cl = REAL_CLUSTER
    real_run, real_reach = _sp.run, _cl.kube.reachable
    real_base = _cl.base_args
    try:
        _cl.base_args = lambda c: ["kubectl"]
        _cl.kube.reachable = lambda c: (True, "")

        class _R:
            returncode = 1
            stdout = ""
            stderr = ('Error from server (Forbidden): secrets is forbidden: '
                      'User "sa" cannot list resource "secrets" at the '
                      'cluster scope')
        _sp.run = lambda *a, **k: _R()
        got = _cl._part_tls({"id": "c1"})
        check("a forbidden list is reported as an error", bool(got.get("error")))
        check("...naming what the server said",
              "Forbidden" in (got.get("error") or ""))
        check("...and NOT as a present cluster with zero certificates",
              got.get("present") is False)
    finally:
        _sp.run, _cl.kube.reachable, _cl.base_args = (real_run, real_reach,
                                                      real_base)

    print("a renewer is only claimed for an operator we know renews")
    # An owner reference is PROVENANCE -- who made this object. The tag on the
    # page is a claim about LIVENESS. Keying "renews itself" on the mere
    # existence of an owner would flip any Helm-installed StatefulSet's secret
    # to auto while nothing renewed it, and that failure is silent until TLS
    # breaks.
    check("CloudNativePG's API group is known, with its published policy",
          _cl.RENEWERS.get("postgresql.cnpg.io", ("", 0, 0))[0]
          == "CloudNativePG")
    check("...and nothing else is",
          set(_cl.RENEWERS) == {"postgresql.cnpg.io"})
    src = "\n".join(re.sub(r"#.*$", "", ln) for ln
                     in (ROOT / "app" / "cluster.py").read_text().splitlines())
    check("the owner columns are read before the blob, which stays last",
          src.index("ownerReferences") < src.index(".data.tls"))
    check("...and the column count is a named constant the guard uses",
          "_TLS_COLS = 8" in src and "len(parts) < _TLS_COLS" in src)

    print("...and an overdue renewer reads as needing a person")
    ex = "\n".join(re.sub(r"#.*$", "", ln) for ln
                    in (ROOT / "app" / "expiry.py").read_text().splitlines())
    check("an overdue certificate is MANUAL, never AUTOMATIC",
          'renewal=(MANUAL if (not c.get("auto") or c.get("overdue"))' in ex)
    check("...and says which renewer failed", "has not renewed it" in ex)

    print("a dual-use class answers what the button rule sets")
    # `.ex-open` is on an <a> and a <button>; app.css styles a bare `button`
    # as the PRIMARY control, so a class that sets only colour leaves grey
    # text on a blue gradient. Reported from a screenshot as unreadable.
    exp = (ROOT / "templates" / "expiry.html").read_text()
    rule = exp[exp.index(".ex-open {"):exp.index(".ex-open:hover")]
    for prop in ("background", "box-shadow", "font-weight", "font-family"):
        check(f"...ex-open answers {prop}", prop in rule)
    shell = (ROOT / "templates" / "_auth_shell.html").read_text()
    sso = shell[shell.index(".sso {"):shell.index(".sso:hover")]
    for prop in ("font-family", "box-shadow", "line-height"):
        check(f"...the sign-in sso answers {prop}", prop in sso)
    css = (ROOT / "static" / "app.css").read_text()
    btn = css[css.index("button, .btn {"):css.index("button:hover, .btn:hover")]
    check("...and a bare button finally inherits the page font",
          "font-family:inherit" in btn)

    print("...and it does not make the radar heavy")
    # MEASURED, on a page nothing was watching. `tests/test_speed.py` caps a
    # page at 120,000 bytes but only ever measures /ansible, so /expiry had no
    # budget at all -- and this change adds a per-ROW control whose attribute
    # carries the certificate's whole SAN list.
    #
    #   1 certificate row   128,883 bytes raw    33,542 gzipped
    #  60 certificate rows  248,107 bytes raw    37,260 gzipped
    # 250 certificate rows  625,129 bytes raw    45,894 gzipped
    #
    # So the button is ~170 bytes a row raw and almost free on the wire, being
    # near-identical between rows -- gzip is on for HTML and `test_speed.py`
    # holds that. The 625kB raw page at 250 rows is the radar's own weight and
    # predates this; what is asserted here is the SHARE this feature may take,
    # so a future version that inlines the answer into every row fails.
    shell = (ROOT / "templates" / "_blast_dialog.html").read_text()
    check(f"the window is a fixed cost, once per page ({len(shell):,} bytes)",
          len(shell) < 9_000)
    blocks = re.findall(r"<style>(.*?)</style>", shell, re.S)
    check(f"...and its style block is under the 4000-char cap "
          f"({max(len(b) for b in blocks):,})",
          all(len(b) < 4000 for b in blocks))
    body = (ROOT / "templates" / "_blast_body.html").read_text()
    check("the per-row control is an attribute, not a rendered answer",
          "data-blast=" not in body)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


def expiry_part_swap(answer, calls):
    """Stand in for cluster.part so the walk is driven without a cluster.

    BOTH THE MODULE ENTRY AND THE PACKAGE ATTRIBUTE. `blast_radius` does
    `from . import cluster as clusterview`, and for an already-imported
    submodule that reads the ATTRIBUTE `app.cluster` -- not
    `sys.modules["app.cluster"]`. Swapping only the module entry worked by
    accident, while nothing had imported `app.cluster` yet; the moment this
    file held a reference to the real module for another check, every swap
    silently stopped taking effect and eight assertions failed at once.
    """
    import types
    import app as _pkg
    fake = types.ModuleType("app.cluster")

    def part(cluster, name, refresh=False):
        calls.append((cluster.get("id"), name, refresh))
        return answer
    fake.part = part
    sys.modules["app.cluster"] = fake
    _pkg.cluster = fake
    return fake


def expiry_part_restore():
    """Put the real module back, both places."""
    import app as _pkg
    sys.modules["app.cluster"] = REAL_CLUSTER
    _pkg.cluster = REAL_CLUSTER


if __name__ == "__main__":
    sys.exit(main())
