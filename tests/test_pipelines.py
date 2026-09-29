#!/usr/bin/env python3
"""One CI connection covering many repositories.

GitHub's and Bitbucket's run feeds are per repository, so naming one repository
per connection meant a connection per service — forty tokens to rotate, and a new
service invisible until someone added it by hand. Both providers accept just the
owner or workspace now and discover the repositories themselves.

The HTTP layer is stubbed: these cases are about what the portal does with the
answers, including the ones that fail.
"""
from __future__ import annotations

import os
import pathlib
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ci-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ci                                              # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def run(name: str, number: int, when: str, concl: str = "success",
        status: str = "completed") -> dict:
    return {"name": name, "run_number": number, "conclusion": concl,
            "status": status, "head_branch": "main",
            "run_started_at": when, "created_at": when,
            "html_url": f"https://github.com/x/y/actions/runs/{number}",
            "actor": {"login": "someone"}}


def main() -> int:
    calls: list[str] = []

    ORG_REPOS = [
        {"full_name": "acme/api", "archived": False},
        {"full_name": "acme/web", "archived": False},
        {"full_name": "acme/old", "archived": True},          # must be skipped
        {"full_name": "acme/secret", "archived": False},      # token cannot read
    ]

    def fake_get(url, headers, verify, *a, **kw):
        calls.append(url)
        if url.endswith("/user"):
            # the token belongs to somebody else, so the owner is looked up as an
            # organisation and then as a user — the not-my-own-account path
            return {"login": "someone-else", "type": "User"}
        if "/orgs/acme/repos" in url:
            return ORG_REPOS
        if "/orgs/solo/repos" in url:
            raise ci.CIError("GitHub said 404 Not Found")
        if "/users/solo/repos" in url:
            return [{"full_name": "solo/tools", "archived": False}]
        if "/repos/acme/secret/actions/runs" in url:
            raise ci.CIError("GitHub said 403 Forbidden")
        if "/repos/acme/api/actions/runs" in url:
            return {"workflow_runs": [run("build", 12, "2026-07-30T09:00:00Z"),
                                      run("build", 11, "2026-07-29T09:00:00Z",
                                          concl="failure")]}
        if "/repos/acme/web/actions/runs" in url:
            return {"workflow_runs": [run("deploy", 5, "2026-07-30T11:00:00Z",
                                          concl=None, status="in_progress")]}
        if "/repos/solo/tools/actions/runs" in url:
            return {"workflow_runs": [run("test", 3, "2026-07-28T08:00:00Z")]}
        if "/repos/acme/api/" in url:                          # single-repo mode
            return {"workflow_runs": [run("build", 12, "2026-07-30T09:00:00Z")]}
        raise AssertionError(f"unexpected call: {url}")

    ci._get = fake_get                     # the network is not what is under test
    conn = {"type": "github", "repo": "acme", "token": "t", "skip_tls": False}

    # ── an organisation, in one connection ────────────────────────────────
    rows = ci._github(conn)
    names = [r["name"] for r in rows]
    check("runs come from every readable repository", len(rows) == 3)
    check("each run says which repository it came from",
          names == ["web · deploy", "api · build", "api · build"])
    check("newest first across the whole owner", rows[0]["number"] == 5)
    check("an in-progress run reads as running", rows[0]["status"] == "running")
    check("a failed run keeps its status",
          [r["status"] for r in rows] == ["running", "success", "failed"])
    check("an archived repository is not fetched",
          not any("acme/old" in u for u in calls))
    check("a repository the token cannot read is skipped, not fatal",
          any("acme/secret" in u for u in calls))
    check("no more than RUNS_PER_REPO runs are asked for per repository",
          all(f"per_page={ci.RUNS_PER_REPO}" in u for u in calls
              if "/actions/runs" in u))
    check("the internal sort key is not leaked to the page",
          all("_ts" not in r for r in rows))

    # ── a user account, reached by falling back ──────────────────────────
    calls.clear()
    rows = ci._github({**conn, "repo": "solo"})
    repo_lookups = [u for u in calls if "/repos" in u and "/actions/" not in u]
    check("an organisation is tried before a user account",
          repo_lookups and "/orgs/solo/repos" in repo_lookups[0])
    check("a user account is found on the second try",
          any("/users/solo/repos" in u for u in calls))
    check("the user's repositories are read", len(rows) == 1
          and rows[0]["name"] == "tools · test")

    # ── one repository, exactly as before ────────────────────────────────
    calls.clear()
    rows = ci._github({**conn, "repo": "acme/api"})
    check("owner/repo still pins a single repository",
          len(calls) == 1 and "/repos/acme/api/actions/runs" in calls[0]
          and not any(u.endswith("/user") for u in calls))
    check("a single repository is not prefixed", rows[0]["name"] == "build")

    # ── an owner that does not exist says so ─────────────────────────────
    def not_found(url, headers, verify, *a, **kw):
        raise ci.CIError("GitHub said 404 Not Found")
    ci._get = not_found
    try:
        ci._github({**conn, "repo": "nobody"})
        check("a missing owner is reported", False)
    except ci.CIError as e:
        check("a missing owner is reported in plain language",
              "no GitHub user or organisation" in str(e))

    # ── folding: many repos, one row per workflow ────────────────────────
    ci._get = fake_get
    folded = ci._fold_runs(ci._github(conn))
    check("each workflow appears once after folding", len(folded) == 2)
    check("folding keeps the repository in the name",
          sorted(f["name"] for f in folded) == ["api · build", "web · deploy"])

    # ── GitLab: a group covers its projects, subgroups included ──────────
    gl_calls: list[str] = []

    def gl_get(url, headers, verify, *a, **kw):
        gl_calls.append(url)
        if "/groups/platform/projects" in url:
            return [{"id": 7, "path": "api"}, {"id": 9, "path": "web"}]
        if "/groups/" in url:
            raise ci.CIError("GitLab said 404 Not Found")
        if "/projects/7/pipelines" in url:
            return [{"id": 71, "status": "success", "ref": "main",
                     "created_at": "2026-07-30T10:00:00Z"}]
        if "/projects/9/pipelines" in url:
            return [{"id": 91, "status": "running", "ref": "main",
                     "created_at": "2026-07-30T12:00:00Z"}]
        if "/projects/123/pipelines" in url:
            return [{"id": 1, "status": "success", "ref": "main",
                     "created_at": "2026-07-01T10:00:00Z"}]
        if "/projects/lonely/pipelines" in url:
            return [{"id": 5, "status": "failed", "ref": "dev",
                     "created_at": "2026-07-29T10:00:00Z"}]
        raise AssertionError(f"unexpected call: {url}")

    ci._get = gl_get
    gl = {"type": "gitlab", "base_url": "https://gitlab.com", "token": "t"}
    rows = ci._gitlab({**gl, "project": "platform"})
    check("a group covers every project in it",
          [r["name"] for r in rows] == ["web · main", "api · main"])
    check("subgroups are included in the request",
          any("include_subgroups=true" in u for u in gl_calls))
    check("archived projects are excluded in the request",
          any("archived=false" in u for u in gl_calls))
    gl_calls.clear()
    rows = ci._gitlab({**gl, "project": "123"})
    check("a numeric project id pins one project",
          len(gl_calls) == 1 and rows[0]["name"] == "main")
    gl_calls.clear()
    rows = ci._gitlab({**gl, "project": "lonely"})
    check("a bare name that is a project, not a group, still works",
          rows[0]["name"] == "dev" and any("/groups/" in u for u in gl_calls))

    # ── an own account: private repositories must be found ───────────────
    # /users/{me}/repos returns public repositories only, so an account whose
    # work is all private looked empty and the connection said "connected, no
    # pipelines" — which reads as "nothing is building".
    own_calls: list[str] = []

    def own_get(url, headers, verify, *a, **kw):
        own_calls.append(url)
        if url.endswith("/user"):
            return {"login": "exampleorg", "type": "User"}
        if "/user/repos" in url:
            return [{"full_name": "exampleorg/gitops", "archived": False,
                     "private": True}]
        if "/users/exampleorg/repos" in url:
            return []                       # the public-only view: empty
        if "/orgs/exampleorg/repos" in url:
            raise ci.CIError("GitHub said 404 Not Found")
        if "/repos/exampleorg/gitops/actions/runs" in url:
            return {"workflow_runs": [run("deploy", 3, "2026-07-30T07:00:00Z")]}
        raise AssertionError(f"unexpected call: {url}")

    ci._get = own_get
    rows = ci._github({"type": "github", "repo": "exampleorg", "token": "t"})
    check("the token is asked who it is", any(u.endswith("/user") for u in own_calls))
    check("an own account uses /user/repos, which includes private ones",
          any("/user/repos" in u for u in own_calls))
    check("a private repository's runs are found",
          len(rows) == 1 and rows[0]["name"] == "gitops · deploy")

    # ── a token that can see nothing says so, instead of reporting silence ─
    def blind(url, headers, verify, *a, **kw):
        if url.endswith("/user"):
            return {"login": "someone", "type": "User"}
        if "/orgs/" in url:
            raise ci.CIError("GitHub said 404 Not Found")
        return []
    ci._get = blind
    ci.invalidate()          # the repository list is cached; this is a fresh look
    try:
        ci._github({"type": "github", "repo": "exampleorg", "token": "t"})
        check("an empty result is explained", False)
    except ci.CIError as e:
        msg = str(e)
        check("the message names the cause, not the symptom",
              "can see no repositories" in msg and "fine-grained" in msg
              and "'repo' scope" in msg)

    # ── stages of one run, per provider ──────────────────────────────────
    ci._STAGE_CACHE.clear()
    stage_calls: list[str] = []

    def stage_get(url, headers, verify, *a, **kw):
        stage_calls.append(url)
        if "/actions/runs/99/jobs" in url:
            return {"jobs": [
                {"name": "build", "conclusion": "success", "status": "completed",
                 "started_at": "2026-07-30T10:00:00Z",
                 "completed_at": "2026-07-30T10:02:30Z", "html_url": "u1",
                 "steps": [{"name": "checkout", "conclusion": "success"},
                           {"name": "npm ci", "conclusion": "success"}]},
                {"name": "deploy", "conclusion": "failure", "status": "completed",
                 "started_at": "2026-07-30T10:03:00Z",
                 "completed_at": "2026-07-30T10:03:40Z", "html_url": "u2",
                 "steps": [{"name": "kubectl apply", "conclusion": "failure"},
                           {"name": "smoke test", "conclusion": "skipped"}]}]}
        if "/pipelines/55/jobs" in url:
            return [{"stage": "test", "name": "unit", "status": "success",
                     "duration": 30, "web_url": "g1"},
                    {"stage": "test", "name": "lint", "status": "success",
                     "duration": 10, "web_url": "g2"},
                    {"stage": "deploy", "name": "to-uat", "status": "failed",
                     "duration": 12, "web_url": "g3"}]
        if "/pipelines/%7Buuid%7D/steps/" in url or "/pipelines/uuid-1/steps/" in url:
            return {"values": [
                {"name": "Build", "state": {"name": "COMPLETED",
                                            "result": {"name": "SUCCESSFUL"}},
                 "duration_in_seconds": 42},
                {"name": "Deploy", "state": {"name": "COMPLETED",
                                             "result": {"name": "FAILED"}},
                 "duration_in_seconds": 7}]}
        raise AssertionError(f"unexpected call: {url}")

    ci._get = stage_get
    gh = {"id": "c-gh", "type": "github", "token": "t"}
    got = ci.stages(gh, "acme/api#99")
    check("GitHub jobs become stages",
          [s["name"] for s in got["stages"]] == ["build", "deploy"])
    check("a job's duration is derived from its timestamps",
          got["stages"][0]["duration"] == "2m 30s")
    check("the failing stage and step are named",
          got["failed"] == {"stage": "deploy", "step": "kubectl apply", "url": "u2"})

    before = len(stage_calls)
    ci.stages(gh, "acme/api#99")
    check("a second look is served from cache", len(stage_calls) == before)
    ci.stages(gh, "acme/api#99", refresh=True)
    check("refresh goes back to the provider", len(stage_calls) > before)

    got = ci.stages({"id": "c-gl", "type": "gitlab", "token": "t",
                     "base_url": "https://gitlab.com"}, "77#55")
    check("GitLab jobs are grouped into their stages",
          [s["name"] for s in got["stages"]] == ["test", "deploy"])
    check("a stage holding several jobs lists them",
          [j["name"] for j in got["stages"][0]["steps"]] == ["unit", "lint"])
    check("a stage fails when a job in it fails",
          got["stages"][1]["status"] == "failed"
          and got["failed"]["stage"] == "deploy")

    got = ci.stages({"id": "c-bb", "type": "bitbucket", "token": "t",
                     "username": "u"}, "team/repo#uuid-1")
    check("Bitbucket steps become stages",
          [s["name"] for s in got["stages"]] == ["Build", "Deploy"])
    check("a Bitbucket failure is found", got["failed"]["stage"] == "Deploy")

    got = ci.stages({"id": "c-x", "type": "jenkins", "token": "t"}, "")
    check("a run with no handle is not requested",
          got["stages"] == [] and "does not report stages" in got["note"])

    # ── Jenkins: rows must carry a handle at all, which they did not ──────
    job = ci._jenkins_job(
        {"lastBuild": {"number": 7, "url": "https://j.example.com/job/app/7/",
                       "result": "FAILURE", "timestamp": 1750000000000,
                       "duration": 65000},
         "lastSuccessfulBuild": {"number": 6, "timestamp": 1749000000000},
         "lastFailedBuild": {"number": 7, "timestamp": 1750000000000},
         "url": "https://j.example.com/job/app/"},
        "app", "", "https://j.example.com")
    check("a Jenkins row carries the handle its stages need",
          job.get("ref") == "https://j.example.com/job/app/7/")
    check("a job that has never built has no handle, and no button",
          ci._jenkins_job({"url": "https://j.example.com/job/new/"}, "new", "",
                          "https://j.example.com").get("ref") == "")

    jenkins_calls: list[str] = []

    def wf_get(url, headers, verify, *a, **kw):
        jenkins_calls.append(url)
        if url.endswith("/7/wfapi/describe"):
            return {"stages": [
                {"name": "Checkout", "status": "SUCCESS", "durationMillis": 4000,
                 "_links": {"self": {"href": "/job/app/7/execution/node/6/wfapi/describe"}}},
                {"name": "Deploy", "status": "FAILED", "durationMillis": 9000,
                 "_links": {"self": {"href": "/job/app/7/execution/node/19/wfapi/describe"}}}]}
        if "node/19" in url:
            return {"stageFlowNodes": [
                {"parameterDescription": "helm upgrade", "status": "FAILED"},
                {"name": "notify", "status": "NOT_EXECUTED"}]}
        raise AssertionError(f"unexpected call: {url}")

    ci._get = wf_get
    ci._STAGE_CACHE.clear()
    got = ci.stages({"id": "c-j", "type": "jenkins", "username": "u",
                     "token": "t"}, job["ref"])
    check("Jenkins stages are read from the stage view",
          [s["name"] for s in got["stages"]] == ["Checkout", "Deploy"])
    check("the failed Jenkins stage lists its steps",
          [s["name"] for s in got["stages"][1]["steps"]] == ["helm upgrade", "notify"])
    check("the failing Jenkins step is named",
          got["failed"]["stage"] == "Deploy"
          and got["failed"]["step"] == "helm upgrade")
    check("only the failed stage costs an extra call", len(jenkins_calls) == 2)

    def no_wfapi(url, headers, verify, *a, **kw):
        raise ci.CIError("Jenkins said 404 Not Found")
    ci._get = no_wfapi
    ci._STAGE_CACHE.clear()
    got = ci.stages({"id": "c-j2", "type": "jenkins", "username": "u",
                     "token": "t"}, "https://j.example.com/job/legacy/3/")
    check("a freestyle job says it has no stages rather than reporting none",
          "freestyle" in got["note"])

    # ── reading the build log here rather than on the provider ──────────
    print("a build log is read in the portal")
    real_get, real_text = ci._get, ci._get_text
    conn = {"id": "c9", "type": "github", "repo": "acme", "token": "t"}

    ci._get = lambda url, headers, verify, *a, **kw: {"jobs": [
        {"id": 11, "name": "build", "conclusion": "failure", "status": "completed",
         "started_at": "2026-08-01T10:00:00Z",
         "completed_at": "2026-08-01T10:01:15Z", "html_url": "https://gh/j/11"},
        {"id": 12, "name": "scan", "conclusion": "success", "status": "completed",
         "started_at": "2026-08-01T10:00:00Z",
         "completed_at": "2026-08-01T10:00:09Z", "html_url": "https://gh/j/12"}]}

    asked = {}

    def fake_text(url, headers, verify=True):
        asked["url"] = url
        return ("2026-08-01T10:00:01.0Z \x1b[36mnpm install\x1b[0m\n"
                "2026-08-01T10:00:02.0Z added 400 packages\n"
                "2026-08-01T10:01:10.0Z ##[error]buildx failed with: exit code 1\n"
                "2026-08-01T10:01:11.0Z Post job cleanup.\n")
    ci._get_text = fake_text

    got = ci.log(conn, "acme/web#77", refresh=True)
    check(f"the failed job is the one opened, got {got['job']['name']!r}",
          got["job"]["name"] == "build")
    check("both jobs are offered", len(got["jobs"]) == 2)
    check(f"it fetched that job's log, got {asked.get('url')}",
          "/actions/jobs/11/logs" in asked.get("url", ""))
    check(f"four lines, got {len(got['lines'])}", len(got["lines"]) == 4)
    check("colour codes are stripped",
          all("\x1b" not in ln for ln in got["lines"]))
    check(f"timestamps are split off, got {got['stamps'][:1]}",
          got["stamps"][0] == "10:00:01")
    check(f"and out of the text, got {got['lines'][0]!r}",
          got["lines"][0] == "npm install")
    check(f"the failure is found, got line {got['first_error']}",
          got["first_error"] == 2)

    # asking for a specific job overrides the failed-first choice
    got = ci.log(conn, "acme/web#77", job="12", refresh=True)
    check("a named job is honoured", got["job"]["name"] == "scan")
    check("and its log is the one fetched", "/jobs/12/logs" in asked["url"])

    # a log longer than the cap keeps the end, where the failure is
    ci._get_text = lambda url, headers, verify=True: "x" * (ci.LOG_BYTES + 5000)
    got = ci.log(conn, "acme/web#78", refresh=True)
    check("an oversized log is capped", got["truncated"])
    check("and it is the tail that is kept",
          sum(len(x) for x in got["lines"]) <= ci.LOG_BYTES)

    # a provider that refuses says so instead of showing an empty page
    def refuse(url, headers, verify=True):
        raise ci.CIError("authentication rejected (403) — the token needs "
                         "read access to build logs")
    ci._get_text = refuse
    got = ci.log(conn, "acme/web#79", refresh=True)
    check("a refused log reports why", "403" in got["note"])
    check("and shows no lines", not got["lines"])

    # ── the caches must not outrank Refresh ──────────────────────────────
    # Two caches were added under stages() and log() to stop the same call
    # being made twice. A shared cache that ignores Refresh makes the button
    # lie, which is worse than the duplicate call it saved.
    hits = []

    def counted(url, headers, verify, *a, **kw):
        hits.append(url)
        return {"jobs": [{"id": 1, "name": "build", "conclusion": "success",
                          "status": "completed", "steps": []}]}
    ci._get = counted
    gh2 = {"id": "c-refresh", "type": "github", "repo": "acme", "token": "t"}
    ci.invalidate()
    ci.stages(gh2, "acme/api#5", refresh=True)
    first = len(hits)
    ci.stages(gh2, "acme/api#5")
    check("a second look is served from cache", len(hits) == first)
    ci.run_jobs(gh2, "acme/api#5")
    check("and the log's job list reuses the same answer", len(hits) == first)
    ci.stages(gh2, "acme/api#5", refresh=True)
    check("but Refresh goes back to the provider", len(hits) > first)
    second = len(hits)
    ci.log(gh2, "acme/api#5", refresh=True)
    check("and so does refreshing a log", len(hits) > second)
    print("  Refresh still reaches the provider through the shared caches")

    # ── the other three providers ────────────────────────────────────────
    # Only GitHub has been run against a real server. These pin the shape of
    # the other three — the endpoint each one is asked for and what it makes of
    # the answer — so a wrong URL or a renamed field fails here rather than in
    # front of whoever has a Jenkins.
    print("every provider has a log reader, not just the one that was to hand")

    def replies(jobs_doc, text):
        seen = {}

        def g(url, headers, verify, *a, **kw):
            seen.setdefault("json", []).append(url)
            return jobs_doc

        def t(url, headers, verify=True):
            seen["text"] = url
            return text
        ci._get, ci._get_text = g, t
        return seen

    # GitLab: jobs on the pipeline, then that job's trace
    seen = replies([{"id": 55, "name": "test", "status": "failed",
                     "duration": 12, "web_url": "https://gl/j/55"}],
                   "running tests\nERROR: 1 test failed\n")
    got = ci.log({"id": "g1", "type": "gitlab", "base_url": "https://gl",
                  "project": "grp/app", "token": "t"}, "grp/app#900",
                 refresh=True)
    check(f"gitlab lists the pipeline's jobs, got {seen.get('json')}",
          any("/pipelines/900/jobs" in u for u in seen.get("json", [])))
    check(f"and reads that job's trace, got {seen.get('text')}",
          "/jobs/55/trace" in seen.get("text", ""))
    check("with the failure found", got["first_error"] == 1)

    # Bitbucket: the pipeline's steps, then that step's log
    seen = replies({"values": [{"uuid": "{s1}", "name": "Build",
                                "duration_in_seconds": 30,
                                "state": {"name": "COMPLETED",
                                          "result": {"name": "FAILED"}}}]},
                   "+ npm ci\nnpm ERR! missing script: build\n")
    got = ci.log({"id": "b1", "type": "bitbucket", "repo": "ws/app",
                  "username": "u", "token": "t"}, "ws/app#{p1}", refresh=True)
    check(f"bitbucket lists the pipeline's steps, got {seen.get('json')}",
          any("/pipelines/%7Bp1%7D/steps/" in u or "/pipelines/{p1}/steps/" in u
              for u in seen.get("json", [])))
    check(f"and reads that step's log, got {seen.get('text')}",
          "/steps/%7Bs1%7D/log" in (seen.get("text") or "")
          or "/steps/{s1}/log" in (seen.get("text") or ""))
    check(f"naming the step, got {got['job'] and got['job']['name']!r}",
          got["job"] and got["job"]["name"] == "Build")
    check("with the failure found", got["first_error"] == 1)

    # Jenkins: one console per build, and the ref is the build URL itself
    seen = replies({}, "Started by user\nBUILD FAILURE\nFinished: FAILURE\n")
    got = ci.log({"id": "j1", "type": "jenkins", "base_url": "https://ci",
                  "username": "u", "token": "t"},
                 "https://ci/job/app/42/", refresh=True)
    check(f"jenkins reads the build console, got {seen.get('text')}",
          seen.get("text") == "https://ci/job/app/42/consoleText")
    check("presented as a single job", len(got["jobs"]) == 1)
    check(f"named for what it is, got {got['job']['name']!r}",
          got["job"]["name"] == "Console output")
    check(f"with the failure found, got {got['first_error']}",
          got["first_error"] >= 0)

    # a provider with no reader says so rather than showing an empty page
    got = ci.log({"id": "z", "type": "teamcity"}, "x#1", refresh=True)
    check(f"an unknown provider explains itself, got {got['note']!r}",
          "no log reader" in got["note"])

    ci._get, ci._get_text = real_get, real_text
    print("  the failed job opens first, colour and timestamps handled, "
          "the failure located")

    # ── the rendered form itself ─────────────────────────────────────────
    # Two inputs sharing a name is invisible in the template and fatal in the
    # browser: the form parser keeps the last value, so a hidden empty field
    # overwrote the owner someone had just typed and the page reported it
    # missing. Checked on the rendered page, not the template, because the
    # template's branches never render together.
    bad_form = check_rendered_form()
    globals()["bad"] = bad + bad_form

    print("OK" if not bad else f"{bad} FAILED")
    return bad


def check_rendered_form() -> int:
    import re
    import time
    from fastapi.testclient import TestClient
    from app import auth, db, main

    problems = 0
    email, pw = "ci@test.local", "Pipelines-Are-Fine-42"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    with c:
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        html = c.get("/settings/pipelines").text
        form = next((m.group(0) for m in
                     re.finditer(r'<form\b.*?</form>', html, re.S)
                     if "/settings/ci/new" in m.group(0)), "")
        if not form:
            print("  FAIL the add-a-connection form is not on the page")
            return 1
        names = re.findall(
            r'<(?:input|select|textarea)\b[^>]*\bname="([^"]+)"', form)
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            print(f"  FAIL the form has duplicate field names: {dupes}")
            problems += 1
        for want in ("type", "repo", "project", "token"):
            if want not in names:
                print(f"  FAIL the form no longer has a '{want}' field")
                problems += 1

        # and the owner actually reaches the provider
        from app import ci as cimod
        seen = {}

        def spy(url, headers, verify, *a, **kw):
            seen["url"] = url
            raise cimod.CIError("stubbed")
        cimod._get = spy
        c.post("/settings/ci/new",
               data={"type": "github", "repo": "exampleorg", "token": "x",
                     "name": "GitHub"}, follow_redirects=False)
        if "exampleorg" not in seen.get("url", ""):
            print(f"  FAIL the owner did not reach GitHub: {seen}")
            problems += 1
        if "/orgs/exampleorg/repos" not in seen.get("url", ""):
            print(f"  FAIL owner mode did not run: {seen.get('url')}")
            problems += 1
    return problems


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
