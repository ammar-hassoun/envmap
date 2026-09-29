#!/usr/bin/env python3
"""Comparing every service in two environments at once.

WHY A SWEEP AND NOT A LOOP OVER pair()
    The comparison itself is shared — _two() is the whole of one pair's answer,
    and both pair() and sweep() call it, so one service compared alone can never
    disagree with the same service inside a sweep. What the sweep adds is the
    part that cannot come from comparing pairs one at a time: which services are
    on one side and not the other, and an ORDER that puts the interesting one
    first. Sorting by name buries the single row worth reading.

THE PROPERTY THAT MATTERS MOST
    An environment compared with itself must report nothing. It is the one
    assertion that catches a whole class of mistake — matching services by
    filename instead of display name, comparing the wrong side, counting a
    present key as absent — because every one of those shows up as a difference
    where there cannot be one.

    ./.venv/bin/python tests/test_sweep.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import types

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("sweep-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import compare, repo, store                            # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── a fake region: two environments, overlapping services ──────
# preprod has an extra service; prod has an extra key on one of the shared ones.
FILES = {
    "preprod": ["api.yaml", "worker.yaml", "reporting.yaml"],
    "prod": ["api.yaml", "worker.yaml"],
}
BODIES = {
    ("preprod", "api.yaml"): {
        "service_config": {"LOG_LEVEL": "debug", "TIMEOUT": "30"},
        "platform_config": {"REGION": "ke"},
        "secret_keys": ["DB_PASSWORD"],
        "meta": {"image_tag": "1.4.0", "replicaCount": 1},
    },
    ("prod", "api.yaml"): {
        "service_config": {"LOG_LEVEL": "info", "TIMEOUT": "30",
                           "RATE_LIMIT": "100"},
        "platform_config": {"REGION": "ke"},
        "secret_keys": ["DB_PASSWORD", "SIGNING_KEY"],
        "meta": {"image_tag": "1.3.9", "replicaCount": 3},
    },
    ("preprod", "worker.yaml"): {
        "service_config": {"QUEUE": "jobs"}, "platform_config": {},
        "secret_keys": [], "meta": {"image_tag": "2.0.0"},
    },
    ("prod", "worker.yaml"): {
        "service_config": {"QUEUE": "jobs"}, "platform_config": {},
        "secret_keys": [], "meta": {"image_tag": "2.0.0"},
    },
    ("preprod", "reporting.yaml"): {
        "service_config": {"CRON": "0 2 * * *"}, "platform_config": {},
        "secret_keys": [], "meta": {},
    },
}
PID, RG = "p-test", "rg-test"


def install_fakes() -> None:
    """Stand in for the repository. A sweep's job is the shape of the answer, and
    that has to be assertable without a checked-out estate on disk."""
    repo.list_envs = lambda pid, rgid, include_hidden=False: dict(FILES)
    repo.display = lambda pid, fname: fname.replace(".yaml", "")
    def load(pid, rgid, env, fname):
        got = BODIES.get((env, fname))
        if got is None:
            raise FileNotFoundError(fname)
        return got
    repo.load_service = load
    store.get_region = lambda pid, rgid: {"name": "KE"}
    store.get_project = lambda pid: {"name": "Test"}


def route(**qs):
    """Ask the Compare route what it would hand the page.

    Called as a function rather than through a client because the assertions are
    about what the page is GIVEN — which fields a token filled in, which services
    came out ticked, whether a reason was set — and that is the context, not the
    rendered HTML. The template is stubbed out for the same reason.
    """
    from app import main as M                                     # noqa: E402
    svc = qs.pop("svc", [])
    req = types.SimpleNamespace(
        query_params=types.SimpleNamespace(
            getlist=lambda k: list(svc) if k == "svc" else []),
        url=types.SimpleNamespace(path="/compare"), session={},
        state=types.SimpleNamespace(user={"id": "user-1"}))
    seen: dict = {}
    real = M.templates.TemplateResponse
    M.templates.TemplateResponse = lambda *a, **k: seen.update(
        a[-1] if a and isinstance(a[-1], dict) else k) or "rendered"
    try:
        M.compare_page(req, **qs)
    finally:
        M.templates.TemplateResponse = real
    return ({**seen["sel"], "mode": seen["mode"]}, seen["result"], seen["why"])


def main() -> int:
    install_fakes()

    print("an environment compared with itself reports nothing")
    same = compare.sweep(PID, RG, "prod", RG, "prod")
    t = same["totals"]
    check(f"nothing differs, got {t['differing']}", t["differing"] == 0)
    check(f"everything is identical, got {t['identical']}/{t['services']}",
          t["identical"] == t["services"] == 2)
    check("no service is missing from either side",
          t["only_a"] == 0 and t["only_b"] == 0)
    check(f"no keys or secrets differ, got {t.get('key_diffs')}/"
          f"{t.get('secret_diffs')}",
          t.get("key_diffs") == 0 and t.get("secret_diffs") == 0)

    print("two environments, and the extra service is found")
    got = compare.sweep(PID, RG, "preprod", RG, "prod")
    t = got["totals"]
    check(f"three services compared, got {t['services']}", t["services"] == 3)
    check(f"one only on side A, got {t['only_a']}", t["only_a"] == 1)
    check("and none only on side B", t["only_b"] == 0)
    names = [r["service"] for r in got["services"]]
    # A service on one side only sorts first: it is frequently the answer, and
    # sorting by name would put it wherever its initial happens to fall.
    check(f"the missing one is first, got {names}", names[0] == "reporting")
    check("and is marked as only on A",
          got["services"][0]["only"] == "A")
    check("its row carries no key comparison, because there is nothing to line up",
          got["services"][0]["rows"] == []
          and got["services"][0]["counts"] is None)

    print("then the rest, most different first")
    rest = [r for r in got["services"] if not r["only"]]
    check(f"api before worker, got {[r['service'] for r in rest]}",
          [r["service"] for r in rest] == ["api", "worker"])
    api = rest[0]
    c = api["counts"]
    # LOG_LEVEL differs; RATE_LIMIT is only in prod; TIMEOUT is the same.
    check(f"one key differs in value, got {c['diff']}", c["diff"] == 2)
    check(f"one key is only on B, got {c['only_b']}", c["only_b"] == 1)
    check("the identical key is counted as such", c["same"] == 2)
    check(f"a secret only on B is counted, got {c['secret_diff']}",
          c["secret_diff"] == 1)
    check(f"image tag and replicas differ, got {c['meta_diff']}",
          c["meta_diff"] == 2)
    worker = rest[1]
    check("an identical service reports nothing",
          worker["counts"]["diff"] == 0
          and worker["counts"]["secret_diff"] == 0
          and worker["counts"]["meta_diff"] == 0)

    print("one service ticked gives exactly what that service got among them all")
    # This is now the whole of the one-service comparison — there used to be a
    # pair() beside it with its own result shape, and the page had a mode for
    # each. Both went, so this is the assertion that has to hold: narrowing
    # changes WHICH services are answered and nothing about the answer.
    only = compare.sweep(PID, RG, "preprod", RG, "prod", ["api"])
    check(f"one service, got {[r['service'] for r in only['services']]}",
          [r["service"] for r in only["services"]] == ["api"])
    alone = only["services"][0]
    check("the same key counts", alone["counts"] == c)
    check("the same rows, in the same order",
          [r["key"] for r in alone["rows"]] == [r["key"] for r in api["rows"]])
    check("and the same secrets",
          [r["key"] for r in alone["secrets"]]
          == [r["key"] for r in api["secrets"]])
    check("a name nobody has returns nothing rather than everything",
          compare.sweep(PID, RG, "preprod", RG, "prod",
                        ["no-such-service"])["services"] == [])

    print("one unreadable side does not lose the other services")
    BODIES.pop(("prod", "worker.yaml"))
    hurt = compare.sweep(PID, RG, "preprod", RG, "prod")
    check(f"still three rows, got {len(hurt['services'])}",
          len(hurt["services"]) == 3)
    broken = [r for r in hurt["services"] if r["error"]]
    check(f"one is flagged unreadable, got {len(broken)}", len(broken) == 1)
    check("and it names the service", broken[0]["service"] == "worker")
    check("the totals say so rather than hiding it",
          hurt["totals"]["unreadable"] == 1)
    check("api is still compared",
          any(r["service"] == "api" and r["counts"] for r in hurt["services"]))
    BODIES[("prod", "worker.yaml")] = {
        "service_config": {"QUEUE": "jobs"}, "platform_config": {},
        "secret_keys": [], "meta": {"image_tag": "2.0.0"}}

    print("services are matched by the name a person sees, not by filename")
    # The file behind a service differs between regions often enough that
    # matching on filename would report every service as missing from the other
    # side. Renaming the file must not change the pairing.
    FILES["prod"] = ["api-prod.yaml", "worker.yaml"]
    BODIES[("prod", "api-prod.yaml")] = BODIES.pop(("prod", "api.yaml"))
    old_display = repo.display
    repo.display = lambda pid, fname: (fname.replace("-prod", "")
                                       .replace(".yaml", ""))
    renamed = compare.sweep(PID, RG, "preprod", RG, "prod")
    check(f"api is still paired, got {[r['service'] for r in renamed['services']]}",
          any(r["service"] == "api" and r["counts"] for r in renamed["services"]))
    check("and is not reported as missing",
          renamed["totals"]["only_a"] == 1)      # only reporting, as before
    repo.display = old_display
    # Put the fixture back. Restoring only `repo.display` left prod's api file
    # named api-prod.yaml, which the real display function reads as a different
    # service — so every assertion after this one was quietly comparing an
    # estate where api existed on one side only.
    FILES["prod"] = ["api.yaml", "worker.yaml"]
    BODIES[("prod", "api.yaml")] = BODIES.pop(("prod", "api-prod.yaml"))

    print("no field name shadows a dict attribute")
    # `{{ totals.keys }}` resolved to the dict's own .keys METHOD, so the page
    # printed "<built-in method keys of dict object at 0x…>" where a number
    # belonged — and the tile stayed amber for ever, because a bound method is
    # truthy. Jinja tries the attribute before the item, so any field named after
    # one of dict's methods is invisible from a template. Checked over every
    # structure a template touches rather than the one that was noticed.
    fresh = compare.sweep(PID, RG, "preprod", RG, "prod")
    def shadowed(obj, where):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and hasattr({}, k):
                    check(f"{where}.{k} shadows dict.{k}", False)
                shadowed(v, f"{where}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:4]):
                shadowed(v, f"{where}[{i}]")
    shadowed(fresh, "sweep")
    shadowed(compare.matrix(PID, RG, "api", ["preprod", "prod"],
                            {"preprod": "api.yaml", "prod": "api.yaml"}),
             "matrix")
    # and the totals the tiles read are numbers, not methods
    for field in ("services", "differing", "identical", "only_a", "only_b",
                  "key_diffs", "secret_diffs", "unreadable"):
        val = fresh["totals"].get(field)
        check(f"totals.{field} is a number, got {type(val).__name__}",
              isinstance(val, int))

    print("the form submits every field the route requires")
    # The sweep came back blank because the page never submitted a project: in
    # pair mode the project rides inside the a/b tokens, so no separate field
    # existed and nothing noticed. The route now names what is missing, and this
    # asserts the form carries all of it — checked against the template rather
    # than against a copy of the list, so adding a required field to one and not
    # the other fails here.
    tpl = (ROOT / "templates" / "compare.html").read_text()
    for field in ("pid", "rga", "ea", "rgb", "eb", "mode"):
        check(f"compare.html submits {field!r}",
              f'name="{field}"' in tpl)
    combo = (ROOT / "templates" / "_combobox.html").read_text()
    # Submitting it is not enough — something has to fill it in.
    # Two separate places have to write it, and each fails differently: without
    # the first, choosing a project submits nothing; without the second, a
    # submitted URL comes back with the pickers empty.
    check("choosing a project fills the field",
          "f.value = SHARED.pid" in combo)
    check("and a submitted URL restores it",
          "field.value = pid" in combo)
    check("and a sweep cannot be submitted without it",
          "const pid = (document.getElementById('p_pid')" in combo)

    print("the service picker can be filled and emptied in one click")
    check("there is a select-all", 'id="svcall"' in tpl)
    check("and a clear", 'id="svcnone"' in tpl)
    check("a filter, because one environment here has fifty services",
          'id="svcfilter"' in tpl)
    check("and the ticked count is shown, since ticking none means ALL",
          'id="svcticked"' in tpl)
    script = tpl.split("<script>")[-1]
    # This is the one that actually broke: countTicked was defined inside the
    # page's IIFE while fillServiceList lives at the script's top level, so the
    # call from there could never resolve and the count went stale the moment the
    # environments changed. Declared at column zero it is hoisted into scope.
    check("countTicked is declared at the script's top level, not in the IIFE",
          "\nfunction countTicked(" in script)
    combo = (ROOT / "templates" / "_combobox.html").read_text()
    check("rebuilding the chips refreshes the count",
          "countTicked();" in combo)
    check("and each chip carries a name the filter can match",
          "data-name=" in combo)

    print("the page that replaced the one-service mode still answers its links")
    # There were two modes and now there is one, because a sweep with a single
    # service ticked IS the one-service comparison. What that could have broken
    # is everything holding a link to the mode that went: the "Compare with…"
    # button on a service page, and anybody's bookmark. Both send a/b tokens, so
    # the route translates them into this page's fields instead of refusing.
    tok_a = compare.encode(PID, RG, "preprod", "api.yaml")
    tok_b = compare.encode(PID, RG, "prod", "api.yaml")

    sel, res, reason = route(a=tok_a, b=tok_b)
    check(f"the project comes out of the token, got {sel['pid']}",
          sel["pid"] == PID)
    check(f"and each side's region and environment, got "
          f"{sel['rga']}/{sel['ea']} and {sel['rgb']}/{sel['eb']}",
          (sel["rga"], sel["ea"], sel["rgb"], sel["eb"])
          == (RG, "preprod", RG, "prod"))
    check(f"the service itself is ticked, got {sel['svc']}",
          sel["svc"] == ["api"])
    check("so the comparison runs rather than showing an empty form",
          bool(res) and [r["service"] for r in res["services"]] == ["api"])
    check("and nothing is complained about", reason == "")

    # The service page sends ONE side. That cannot run, and the page used to come
    # back looking unsubmitted; it now says which half is missing.
    sel, res, reason = route(a=tok_a)
    check("one side alone fills that side in",
          (sel["pid"], sel["rga"], sel["ea"]) == (PID, RG, "preprod"))
    check(f"and says what is missing, got {reason!r}",
          "B's region" in reason and "B's environment" in reason
          and "project" not in reason)
    check("without pretending to have compared anything", res is None)

    # A bookmark naming the mode that no longer exists is answered, not refused.
    sel, res, reason = route(mode="pair", a=tok_a, b=tok_b)
    check("an old bookmark still renders", bool(res))
    check(f"through this page, got {sel['mode']}", sel["mode"] == "sweep")

    print("and the page itself offers no mode to choose")
    # The toggle is gone from the markup, not merely hidden: a stylesheet rule
    # that stops applying would bring both forms back on top of each other.
    for gone in ("cmpmode", "onlypair", "onlysweep", "sweepmode"):
        check(f"{gone!r} is gone from the template", gone not in tpl)

    print("the keys that match are in the page, not thrown away")
    # The sweep's per-service table filtered to state == 'diff' in the template,
    # so a key that matched on both sides was never rendered at all — and "is
    # this one really the same in both?" had no answer short of opening the two
    # files. The rows are all rendered now and the stylesheet decides; that
    # matters because filtering server-side leaves nothing for a control to
    # reveal, and rerunning the whole comparison to show a row it already
    # computed would be the wrong trade.
    check("every row is rendered, whatever its state",
          "{% for row in r.rows %}" in tpl
          and "{% for row in r.rows if row.state == 'diff' %}" not in tpl)
    check("and every secret row too",
          "{% for row in r.secrets %}" in tpl
          and "{% for row in r.secrets if row.state == 'diff' %}" not in tpl)
    check("the row carries its state as a class, which is what hides it",
          'class="row {{ row.state }}"' in tpl)
    check("the control exists", 'id="showSame"' in tpl)
    check("differences only is the default — the class is added, never removed",
          "#sweepres:not(.withsame) tr.row.same { display:none; }" in tpl)
    script = tpl.split("<script>")[-1]
    check("the control toggles that class", "classList.toggle('withsame'" in script)
    # A sweep is submitted as a whole new page, so a choice held only in the DOM
    # is reset by the act of comparing again — which is exactly when it is wanted.
    check("and the choice survives the next comparison",
          "localStorage.setItem" in script and "compare.showSame" in script)
    check("a service with nothing to show loses the empty table, not the note",
          "#sweepres:not(.withsame) .svcrow.allsame table.cmp { display:none; }"
          in tpl and "allsame' if r.rows and not diff_n" in tpl)
    # The count in the note is per service. Both services in the fixture happen
    # to have five matching rows, so a total-instead-of-per-service bug would
    # look right here — hence this is asserted against the data, not the page.
    per = {r["service"]: sum(1 for x in r["rows"] + r["secrets"]
                             if x["state"] == "same")
           for r in fresh["services"] if r["rows"]}
    check(f"each service knows its own identical count, got {per}",
          per == {"api": 5, "worker": 5})
    check("and the ones that differ are counted apart",
          {r["service"]: r["counts"]["diff"] for r in fresh["services"]
           if r["counts"]} == {"api": 2, "worker": 0})

    print("the server's complaint does not outlive the state it describes")
    # It is rendered from the request that produced it, so once the missing field
    # is supplied it describes a state that no longer exists. Left on screen it
    # made a form that had just been fixed look like it was still refusing —
    # which is exactly how this was reported the second time.
    check("the banner is only rendered when there is a reason",
          "{% if why %}" in tpl)
    check("it is addressable", 'id="whybanner"' in tpl)
    script = tpl.split("<script>")[-1]
    check("and the page removes it on the first change",
          "whybanner" in script and "banner.remove()" in script)
    check("including a click on a picker, which is not a form change event",
          ".combo" in script)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
