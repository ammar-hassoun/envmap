#!/usr/bin/env python3
"""The assistant must not answer a question nobody asked.

WHY THIS EXISTS
    Asked "i need just bitbucket pipeline" on an estate whose only CI
    connection is Jenkins, the assistant replied with one row: a Jenkins
    pipeline, presented as the answer. Two independent faults produced it, and
    both are the same class of bug — a word in the question was thrown away and
    the result still looked confident:

      1. "just" was on the superlative list ("it just ran"), so the question
         was read as "the most recent pipeline" and forty rows became one.
      2. "bitbucket" was only a ROUTING word. It chose the pipelines query and
         then vanished; nothing ever filtered by provider, because the provider
         lives on the connection and was never copied onto the row.

    A wrong answer with a table under it is worse than "I don't know", so the
    rule these tests hold is: a constraint the question names is either applied
    or reported as impossible. Never dropped.

    The shaping is pure, so every case here runs on synthetic rows — no
    connections, no network, no cluster.

    ./.venv/bin/python tests/test_answers.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("answers-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import answers, rbac                                  # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def jenkins_only(n: int = 6) -> dict:
    """What the estate in the bug report actually looks like: one Jenkins
    connection, several pipelines, nothing else."""
    return {
        "columns": ["connection", "pipeline", "status", "branch"],
        "note": "pipelines", "time_field": "started_at",
        "rows": [{"connection": "Central Jenkins Server", "provider": "jenkins",
                  "pipeline": f"svc-{i}", "status": "success",
                  "branch": "develop", "started_at": f"2026-08-0{i+1}T10:00:00"}
                 for i in range(n)],
    }


def mixed() -> dict:
    return {
        "columns": ["connection", "pipeline", "status"],
        "note": "pipelines", "time_field": "started_at",
        "rows": [
            {"connection": "Central Jenkins Server", "provider": "jenkins",
             "pipeline": "auth", "status": "failed",
             "started_at": "2026-08-01T10:00:00"},
            {"connection": "Payments Pipelines", "provider": "bitbucket",
             "pipeline": "payment-gateway-api", "status": "success",
             "started_at": "2026-08-06T10:00:00"},
            {"connection": "Payments Pipelines", "provider": "bitbucket",
             "pipeline": "mock-payment-provider", "status": "success",
             "started_at": "2026-08-05T10:00:00"},
        ],
    }


def main() -> int:
    print("the question from the bug report")
    got = answers.shape(jenkins_only(), "i need just bitbucket pipeline")
    # The one thing that must never happen again: a Jenkins row offered as the
    # answer to a question about Bitbucket.
    check(f"no rows are returned (got {got['count']})", got["count"] == 0)
    check(f"and it says why: {got['note']!r}", "bitbucket" in got["note"])
    check("naming what IS connected instead", "jenkins" in got["note"])
    check("no Jenkins row is presented as the answer",
          not any("svc-" in str(r) for r in got["rows"]))

    print("the sentence above the table says the same thing as the table")
    # The table was right and the sentence was wrong: with the provider filter
    # returning nothing, the headline fell through to a canned line and
    # announced "No pipeline is failing." — a different claim, and false.
    got = answers.shape(jenkins_only(), "i need just bitbucket pipeline")
    said = answers.headline({**got, "query": "pipelines", "rows": got["rows"],
                             "count": got["count"]})
    check(f"it repeats the real reason: {said!r}", "bitbucket" in said.lower())
    check("and does not invent a claim about failures",
          "failing" not in said.lower())

    print("“just” means only, not most recent")
    check("it is off the superlative list",
          "just" not in answers.SUPERLATIVE_NEW)
    got = answers.shape(jenkins_only(), "just show me the pipelines")
    check(f"six pipelines stay six (got {got['count']})", got["count"] == 6)
    check("and nothing claims to be the most recent",
          "most recent" not in got["note"])
    # the reading that IS a superlative still works
    got = answers.shape(jenkins_only(), "what ran just now")
    check(f"“just now” still means one (got {got['count']})", got["count"] == 1)
    check("and says so", "most recent" in got["note"])

    print("a provider that is present")
    got = answers.shape(mixed(), "show me the bitbucket pipelines")
    check(f"narrows to the two Bitbucket ones (got {got['count']})",
          got["count"] == 2)
    check("and no Jenkins row survives",
          all(r["provider"] == "bitbucket" for r in got["rows"]))
    got = answers.shape(mixed(), "the last bitbucket pipeline")
    check(f"combined with a superlative: one row (got {got['count']})",
          got["count"] == 1)
    check("and it is the newest BITBUCKET one, not the newest overall",
          got["rows"] and got["rows"][0]["pipeline"] == "payment-gateway-api")

    print("a provider that matches everything is still a match")
    # The first fix broke this: when every row is Jenkins, "narrowed" is the
    # whole set, which read as "no match" and reported "nothing here is
    # jenkins" on an estate that is entirely Jenkins.
    got = answers.shape(jenkins_only(), "show me jenkins pipelines")
    check(f"all six come back (got {got['count']})", got["count"] == 6)
    check("with no complaint", "nothing here is" not in got["note"])

    print("narrowing is exact, never a guess")
    rows = {"columns": ["cluster", "pod"], "note": "pods",
            "rows": [{"cluster": "ke-preprod", "pod": "a"},
                     {"cluster": "tz-preprod", "pod": "b"}]}
    got = answers.shape(dict(rows), "pods on ke-preprod")
    check(f"an exact cluster name narrows (got {got['count']})",
          got["count"] == 1)
    got = answers.shape(dict(rows), "pods on preprod")
    check(f"a partial one does not silently pick a side (got {got['count']})",
          got["count"] == 2)

    print("plurals fold, meanings do not")
    kinds = {"columns": ["kind", "what"], "note": "changes",
             "rows": [{"kind": "build", "what": "x"},
                      {"kind": "deploy", "what": "y"},
                      {"kind": "commit", "what": "z"}]}
    got = answers.shape(dict(kinds), "show me the builds")
    check(f"“builds” finds kind “build” (got {got['count']})", got["count"] == 1)
    got = answers.shape(dict(kinds), "show me everything")
    check(f"and nothing narrows without a reason (got {got['count']})",
          got["count"] == 3)

    print("a state that is not there is still reported honestly")
    got = answers.shape(jenkins_only(), "which pipelines are failing")
    check(f"no rows (got {got['count']})", got["count"] == 0)
    check(f"and the note says what states exist: {got['note'][:60]!r}",
          "success" in got["note"])

    print("the provider vocabulary is read off the modules, not typed out")
    # It WAS typed out, and a hand-written list is wrong the day somebody adds
    # an integration: measured against the real registries it was missing nine
    # products a customer could name, so a site running Pritunl would have hit
    # the Bitbucket fault under a different name.
    vocab = answers.provider_words()
    for known in ("jenkins", "bitbucket", "argocd", "pritunl", "netmaker",
                  "vsphere", "truenas", "wazuh", "alibaba"):
        check(f"{known} is in the vocabulary", known in vocab)
    # a provider id that means nothing as a filter must stay out, or it refuses
    # perfectly good questions
    for junk in ("http", "other", "easy", "file", "api", "default", "local"):
        check(f"{junk!r} is not treated as a product name", junk not in vocab)

    # Every module that defines a provider table must be one this reads. Found
    # by scanning the source rather than by trusting the list to be complete —
    # a new integration module is exactly the thing that gets forgotten.
    root = pathlib.Path(__file__).resolve().parent.parent
    defines = set()
    for path in sorted((root / "app").glob("*.py")):
        if re.search(r"^PROVIDERS\s*=", path.read_text(), re.M):
            defines.add(path.stem)
    # the assistant's own providers are models it calls, not systems it reads
    unread = defines - set(answers._VOCAB_MODULES) - {"assistant"}
    check(f"every module with a provider table is read: missing {sorted(unread)}",
          not unread)

    print("an alias resolves, it does not merely get recognised")
    hosts = {"columns": ["host", "type"], "note": "hypervisors",
             "rows": [{"host": "esx-01", "type": "vsphere"},
                      {"host": "pve-01", "type": "proxmox"}]}
    got = answers.shape(dict(hosts), "show me the esxi hosts")
    check(f"“esxi” finds the vsphere row (got {got['count']})",
          got["count"] == 1 and got["rows"][0]["type"] == "vsphere")
    check("and does not refuse the question",
          "nothing here is" not in got["note"])
    got = answers.shape(dict(hosts), "the pritunl hosts")
    check(f"a product that is genuinely absent still refuses (got {got['count']})",
          got["count"] == 0 and "pritunl" in got["note"])

    print("every area is answerable, or declared not to be")
    # The guarantee the Timeline needed and did not have: it shipped as a page
    # the assistant had never heard of. A new area now fails here until
    # somebody either writes a query or writes down why there is none.
    cov = answers.coverage()
    check(f"nothing is merely forgotten: {sorted(cov['missing'])}",
          not cov["missing"])
    check("the timeline is answerable",
          "timeline" in cov["covered"])
    for area in ("settings", "users", "manage"):
        check(f"{area} is deliberately out of reach",
              area in answers.NOT_ANSWERABLE)
    check("every declared area gives a reason",
          all(len(v) > 20 for v in answers.NOT_ANSWERABLE.values()))
    check("nothing is declared that does not exist",
          set(answers.NOT_ANSWERABLE) <= set(rbac.AREAS))
    check("and nothing is both covered and declared",
          not (cov["covered"] & cov["declared"]))

    print("every catalogue entry is wired up")
    for name, spec in answers.CATALOGUE.items():
        check(f"{name} has a runner", callable(spec.get("run")))
        check(f"{name} names an area that exists",
              spec.get("area") in rbac.AREAS)
        check(f"{name} has words to match on", bool(spec.get("words")))
        check(f"{name} has help text", bool(spec.get("help")))

    print("\"unreachable\" is a claim about reaching, not about being unwell")
    # Both faults this covers produced a confident wrong answer rather than an
    # error, which is the worst kind for a tool people trust:
    #
    #   * "unreachable" was one of a bag of words meaning "in any way unwell",
    #     so a cluster whose API server answers fine, with four bad pods, was
    #     returned as unreachable — a wrong answer to a precise question
    #   * the word was then applied a SECOND time by the generic value filter
    #     in shape(), as a literal match against a column that says yes and no.
    #     Nothing matched, so a correct result was emptied and the reader was
    #     told: nothing with reachable "unreachable" — the values present
    #     are: yes
    from app import fleet, rbac as _rbac                       # noqa: E402
    real_over, real_vis = fleet.overview, _rbac.visible_clusters
    _rbac.visible_clusters = lambda u: None
    fleet.overview = lambda force=False: {"clusters": [
        {"cid": "c1", "name": "Answers Reachable", "project": "T",
         "reachable": True, "nodes": {"ready": 2, "total": 2},
         "pods": {"running": 68, "total": 72, "bad": 4, "pending": 0},
         "cpu": {"pct": 2}, "mem": {"pct": 78}, "error": ""},
        {"cid": "c2", "name": "Answers Down", "project": "T",
         "reachable": False, "nodes": {"ready": 0, "total": 3},
         "pods": {"running": 0, "total": 0, "bad": 0, "pending": 0},
         "cpu": {}, "mem": {}, "error": "dial tcp timeout"}]}
    try:
        def ask(q):
            r = answers.q_clusters(None, q, "")
            shaped = answers.shape({**r, "query": "clusters",
                                    "label": "Clusters",
                                    "count": len(r["rows"]),
                                    "cluster_phrase": ""}, q)
            return ([x["cluster"] for x in shaped["rows"]],
                    answers.headline(shaped))

        names, line = ask("which clusters are unreachable")
        check(f"only the unreachable one is returned ({names})",
              names == ["Answers Down"])
        check(f"and the reachable-but-degraded one is not ({names})",
              "Answers Reachable" not in names)

        names, line = ask("which clusters need attention")
        check(f"but 'needs attention' still includes it ({names})",
              set(names) == {"Answers Down", "Answers Reachable"})

        # The healthy estate: the answer must be a sentence, not a description
        # of a failed string match.
        fleet.overview = lambda force=False: {"clusters": [
            {"cid": "c1", "name": "Answers Reachable", "project": "T",
             "reachable": True, "nodes": {"ready": 2, "total": 2},
             "pods": {"running": 68, "total": 72, "bad": 4, "pending": 0},
             "cpu": {"pct": 2}, "mem": {"pct": 78}, "error": ""}]}
        names, line = ask("which clusters are unreachable")
        check(f"none unreachable says so plainly ({line[:52]})",
              names == [] and line.lower().startswith("no cluster is unreachable"))
        check("and never quotes the failed match back at the reader",
              "values present" not in line and "nothing with" not in line.lower())
        # And the guard that stops a word being spent twice, on a column whose
        # vocabulary is not yes/no — where the value fix above cannot help.
        # A query that has already narrowed on "failing" must not have shape()
        # narrow on it again against a status column that never says "failing".
        base = {"query": "pipelines", "label": "Pipelines", "note": "builds",
                "columns": ["job", "status"], "cluster_phrase": "",
                "rows": [{"job": "build", "status": "broken"}], "count": 1}
        kept = answers.shape({**base, "consumed": ["failing"]},
                             "which builds are failing")
        check(f"a consumed word is not spent twice ({kept['count']} row)",
              kept["count"] == 1)
        spent = answers.shape({**base, "consumed": []},
                              "which builds are failing")
        check("and without the guard it would empty the result",
              spent["count"] == 0)
    finally:
        fleet.overview, _rbac.visible_clusters = real_over, real_vis

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
