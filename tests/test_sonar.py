#!/usr/bin/env python3
"""SonarQube, read well enough that its own UI is not needed.

The cases here are the ones where a plausible reading is the wrong one: a
project with no vulnerabilities and a failing quality gate is not healthy, a
rating is a letter and not the number 3.0, and a code smell must never be added
to a security severity total that the hub then quotes beside DefectDojo's.

    ./.venv/bin/python tests/test_sonar.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("sonar-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import security                                       # noqa: E402

bad = 0
CONN = {"type": "sonarqube", "name": "Sonar", "token": "t",
        "base_url": "https://sonar.example.com", "skip_tls": False, "id": "s1"}


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── a SonarQube that answers like the real one ─────────────────────────────
PROJECTS = [
    {"key": "svc-a", "name": "payments-api"},
    {"key": "svc-b", "name": "web-client"},
]
MEASURES = {
    "svc-a": {"alert_status": "ERROR", "bugs": "20", "vulnerabilities": "5",
              "code_smells": "539", "security_hotspots": "7", "coverage": "0.0",
              "duplicated_lines_density": "5.63241", "ncloc": "28797",
              "sqale_index": "2400", "reliability_rating": "3.0",
              "security_rating": "5.0", "sqale_rating": "1.0",
              "security_review_rating": "5.0"},
    # a clean project: no vulnerabilities, gate passing, and 228 code smells
    # that must not turn it into a security problem anywhere
    "svc-b": {"alert_status": "OK", "bugs": "2", "vulnerabilities": "0",
              "code_smells": "228", "security_hotspots": "0", "coverage": "78.4",
              "duplicated_lines_density": "0.0", "ncloc": "11748",
              "sqale_index": "45", "reliability_rating": "3.0",
              "security_rating": "1.0", "sqale_rating": "1.0",
              "security_review_rating": "1.0"},
}
GATES = {
    "svc-a": {"status": "ERROR", "conditions": [
        {"status": "ERROR", "metricKey": "new_coverage", "comparator": "LT",
         "errorThreshold": "80", "actualValue": "0.0"},
        {"status": "ERROR", "metricKey": "new_duplicated_lines_density",
         "comparator": "GT", "errorThreshold": "3", "actualValue": "16.64746"},
        {"status": "ERROR", "metricKey": "new_security_rating",
         "comparator": "GT", "errorThreshold": "1", "actualValue": "4"},
        {"status": "OK", "metricKey": "new_violations", "comparator": "GT",
         "errorThreshold": "0", "actualValue": "0"}],
     "period": {"date": "2026-06-21T11:44:03+0000"}},
    "svc-b": {"status": "OK", "conditions": [], "period": {}},
}
# per project: vulnerabilities by legacy severity, and every unresolved issue
VULNS = {"svc-a": {"BLOCKER": 1, "CRITICAL": 2, "MAJOR": 2}, "svc-b": {}}
ALL_ISSUES = {"svc-a": {"types": {"CODE_SMELL": 539, "BUG": 20,
                                  "VULNERABILITY": 5},
                        "severities": {"MAJOR": 500, "MINOR": 62, "BLOCKER": 2}},
              "svc-b": {"types": {"CODE_SMELL": 228}, "severities": {"MINOR": 228}}}

calls: list = []


def fake_get(url: str, headers: dict, verify: bool = True):
    calls.append(url)
    path, _, query = url.partition("?")
    qs = urllib.parse.parse_qs(query)
    one = lambda k, d="": (qs.get(k) or [d])[0]                # noqa: E731

    if path.endswith("/api/components/search"):
        return {"components": PROJECTS, "paging": {"total": len(PROJECTS)}}

    if path.endswith("/api/measures/search"):
        out = []
        for key in one("projectKeys").split(","):
            for metric, value in MEASURES.get(key, {}).items():
                out.append({"metric": metric, "value": value, "component": key})
        return {"measures": out}

    if path.endswith("/api/qualitygates/project_status"):
        return {"projectStatus": GATES.get(one("projectKey"), {})}

    if path.endswith("/api/issues/search"):
        key = one("componentKeys")
        if one("types") == "VULNERABILITY":
            vals = [{"val": k, "count": n}
                    for k, n in VULNS.get(key, {}).items()]
            return {"total": sum(VULNS.get(key, {}).values()),
                    "facets": [{"property": "severities", "values": vals}],
                    "issues": []}
        got = ALL_ISSUES.get(key, {"types": {}, "severities": {}})
        return {
            "total": sum(got["types"].values()),
            "facets": [
                {"property": "types",
                 "values": [{"val": k, "count": n} for k, n in got["types"].items()]},
                {"property": "severities",
                 "values": [{"val": k, "count": n}
                            for k, n in got["severities"].items()]}],
            "issues": [{"key": "AX1", "message": "Remove this unused import",
                        "severity": "MINOR", "type": "CODE_SMELL",
                        "rule": "python:S1128", "component": f"{key}:src/app.py",
                        "line": 12, "effort": "2min", "project": key,
                        "creationDate": "2026-07-01T10:00:00+0000",
                        "status": "OPEN"}],
        }

    # the token this portal is given is usually not allowed to list hotspots
    if "/api/hotspots/search" in path:
        raise security.SecError("authentication rejected (403)")
    raise security.SecError(f"unexpected call: {path}")


def main() -> int:
    security._get = fake_get
    security.invalidate()

    print("measures become the things people actually say")
    check("a rating is a letter, not 3.0", security._rating("3.0") == "C")
    check("the best rating is A", security._rating("1.0") == "A")
    check("the worst is E", security._rating("5.0") == "E")
    check("a missing rating is blank rather than a guess",
          security._rating(None) == "" and security._rating("x") == "")
    # Sonar counts technical debt in minutes and nobody reads it that way
    check(f"45 minutes stays minutes, got {security._debt('45')}",
          security._debt("45") == "45min")
    check(f"2400 minutes is 5 working days, got {security._debt('2400')}",
          security._debt("2400") == "5d")
    check("no debt reported is blank", security._debt(None) == "")
    check(f"16.64746 reads as 16.6, got {security._tidy('16.64746')}",
          security._tidy("16.64746") == "16.6")
    check(f"0.0 reads as 0, got {security._tidy('0.0')}",
          security._tidy("0.0") == "0")
    check("one vulnerability is not 'vulnerabilitys'",
          security._plural("vulnerability", 1) == "vulnerability"
          and security._plural("vulnerability", 5) == "vulnerabilities")
    check("and a bug is just a bug", security._plural("bug", 2) == "bugs")

    print("a project is read as a quality gate, not as a severity count")
    got = security._sonarqube(CONN)
    by = {r["id"]: r for r in got["products"]}
    a, b = by["svc-a"], by["svc-b"]
    check("both projects are read", len(got["products"]) == 2)
    check(f"the failing gate is reported, got {a['quality']['gate']}",
          a["quality"]["gate"] == "ERROR")
    check("and the passing one", b["quality"]["gate"] == "OK")
    check(f"{got['gates']} counts the failing gates",
          got["gates"] == {"failing": 1, "total": 2})
    # the whole point of the ordering: a broken build comes before a tidy one
    check("a failing gate sorts above a passing one",
          got["products"][0]["id"] == "svc-a")

    check("the measures are carried through",
          (a["quality"]["bugs"], a["quality"]["smells"],
           a["quality"]["hotspots"]) == (20, 539, 7))
    check(f"as letters, got R={a['quality']['reliability']} "
          f"S={a['quality']['security']} M={a['quality']['maintainability']}",
          (a["quality"]["reliability"], a["quality"]["security"],
           a["quality"]["maintainability"]) == ("C", "E", "A"))
    check("coverage and duplication are numbers, not strings",
          a["quality"]["coverage"] == 0.0
          and abs(a["quality"]["duplication"] - 5.63241) < 1e-6)
    check("size and debt are there", a["quality"]["ncloc"] == 28797
          and a["quality"]["debt"] == "5d")

    print("why the gate failed, without opening SonarQube")
    why = {c["metric"]: c for c in a["gate_why"]}
    check(f"only the failing conditions are listed, got {sorted(why)}",
          sorted(why) == ["new_coverage", "new_duplicated_lines_density",
                          "new_security_rating"])
    check("a metric key is turned into words",
          why["new_coverage"]["label"] == "coverage on new code")
    check("with the comparison the right way round",
          why["new_coverage"]["op"] == "must be at least"
          and why["new_duplicated_lines_density"]["op"] == "must not exceed")
    check(f"numbers are tidied, got {why['new_duplicated_lines_density']['actual']}",
          why["new_duplicated_lines_density"]["actual"] == "16.6")
    # a rating condition compares 1–5, so printing the raw number would be a
    # scale nobody reading the Sonar UI has ever seen
    check(f"a rating condition reads in letters, got "
          f"{why['new_security_rating']['actual']} / {why['new_security_rating']['want']}",
          (why["new_security_rating"]["actual"],
           why["new_security_rating"]["want"]) == ("D", "A"))
    check("a passing project lists no reasons", not b["gate_why"])

    print("a code smell is not a vulnerability")
    # svc-a has 539 code smells and 5 vulnerabilities. The severity buckets feed
    # the security hub, where they are added to DefectDojo's findings — so they
    # have to count the 5, not the 564.
    check(f"the severity buckets count vulnerabilities only, got {a['sev']}",
          sum(a["sev"].values()) == 5)
    check("mapped from Sonar's own scale",
          a["sev"]["critical"] == 1 and a["sev"]["high"] == 2
          and a["sev"]["medium"] == 2)
    check(f"a project with 228 smells and no vulnerabilities is clean here, "
          f"got {b['sev']}", sum(b["sev"].values()) == 0)
    check("but its smells are still reported as smells",
          b["quality"]["smells"] == 228)
    check(f"so the connection total is 5, not 767, got {got['totals']}",
          sum(got["totals"].values()) == 5)

    print("one project, in full")
    security.invalidate()
    d = security.sonar_detail(CONN, "svc-a")
    check("the gate comes with every condition, passing ones included",
          len(d["gate"]["conditions"]) == 4)
    check("and the period it is measured against",
          d["gate"]["period"] == "2026-06-21")
    check(f"issues are counted by type, got {d['facets']['types']}",
          d["facets"]["types"] == {"code smells": 539, "bugs": 20,
                                   "vulnerabilities": 5})
    check(f"and totalled, got {d['facets']['total']}",
          d["facets"]["total"] == 564)
    check("the issue list carries what a reader needs to place it",
          d["issues"] and d["issues"][0]["component"] == "src/app.py"
          and d["issues"][0]["line"] == 12
          and d["issues"][0]["type"] == "code smell")
    check("a link back to Sonar for the ones we do not render",
          d["url"].startswith("https://sonar.example.com/dashboard?id="))

    print("a token without hotspot permission does not break the page")
    # the real token here is refused by /api/hotspots/search; the count still
    # comes from the measure, so the page reports 7 rather than nothing
    check("the hotspot count survives a 403 on the hotspot list",
          d["quality"]["hotspots"] == 7)
    check("and nothing tried to list them",
          not any("hotspots/search" in u for u in calls))

    print("the bulk call is used, not one request per project")
    security.invalidate()
    calls.clear()
    security._sonarqube(CONN)
    n = sum(1 for u in calls if "/api/measures/search" in u)
    check(f"measures for every project in one call, got {n}", n == 1)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
