"""CI/CD pipeline status from Jenkins, GitHub Actions, Bitbucket Pipelines or
GitLab CI, normalised to one shape so the UI does not care which it is.

Read-only: every call is a GET. Nothing here triggers, cancels or changes a
build — the portal reports, it does not drive.

Normalised run:
    {name, status, branch, number, started, duration, url, author}
status is one of: success | failed | running | cancelled | pending | unknown
"""
import base64
import json
import re
import ssl
import threading
import time

from . import urlguard
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TIMEOUT = 15

PROVIDERS = {
    "jenkins": {
        "label": "Jenkins",
        "icon": "🧰",
        "url_hint": "https://jenkins.example.com",
        "needs": ["base_url", "username", "token"],
        "note": "Username plus an API token from your Jenkins user settings "
                "(not your password). Optionally set a folder path to scope it.",
    },
    "github": {
        "label": "GitHub Actions",
        "icon": "🐙",
        "url_hint": "owner  —  or owner/repo for just one repository",
        "needs": ["repo", "token"],
        "note": "Give the owner — a user or an organisation — and the portal "
                "discovers its repositories itself: one connection covers every "
                "repository, and a new one appears on its own. owner/repo still "
                "works for pinning a single repository. Needs a PAT with read "
                "access to Actions; a fine-grained token must list every "
                "repository you want covered, or be scoped to all of them.",
    },
    "bitbucket": {
        "label": "Bitbucket Pipelines",
        "icon": "🪣",
        "url_hint": "workspace  —  or workspace/repo for just one repository",
        # username is deliberately NOT required: an access token has no user,
        # and demanding one made project and workspace tokens unusable
        "needs": ["repo", "token"],
        "note": "Two credential types work, and they differ. A project or "
                "workspace ACCESS TOKEN (Repositories: Read, Pipelines: Read) "
                "needs NO username — leave it blank and it is sent as a Bearer "
                "token. An Atlassian API token or app password identifies a "
                "person, so put the account email or Bitbucket username "
                "alongside it. "
                "Give just the workspace name and the portal discovers its "
                "repositories itself — one connection covers every repo, the "
                "way one Jenkins URL covers every job. workspace/repo still "
                "works for pinning a single repository.",
    },
    "gitlab": {
        "label": "GitLab CI",
        "icon": "🦊",
        "url_hint": "https://gitlab.com  ·  a group, or a project id",
        "needs": ["base_url", "project", "token"],
        "note": "Give a group and the portal covers every project in it, "
                "subgroups included — one connection instead of one per "
                "project. A project id or group%2Fproject still pins a single "
                "project. Needs a token with read_api scope over what you want "
                "covered.",
    },
}


class CIError(Exception):
    pass


# view order per fetch, consumed immediately by fetch()
_VIEW_ORDER: dict[int, list[str]] = {}


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _get(url: str, headers: dict, verify: bool = True) -> dict | list:
    """GET JSON. `verify=False` skips TLS checks for this request only —
    used for internal servers with an expired or self-signed certificate."""
    req = urllib.request.Request(
        urlguard.check(url), headers={"Accept": "application/json",
                                              **headers})
    ctx = None if verify else _INSECURE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:160]
        except Exception:
            pass
        if e.code in (401, 403):
            raise CIError(f"authentication rejected ({e.code}) — check the token "
                          f"and its scopes") from e
        if e.code == 404:
            raise CIError("not found (404) — check the URL / repo / project") from e
        raise CIError(f"HTTP {e.code} {detail}") from e
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason or "SSLCertVerification" in reason:
            raise CIError(
                f"TLS certificate rejected: {reason}. If this is an internal "
                "server with an expired or self-signed certificate, tick "
                "'skip TLS verification' on the connection.") from e
        raise CIError(f"cannot reach the server: {reason}") from e
    except json.JSONDecodeError:
        raise CIError("the server did not return JSON — is the base URL right?")
    except Exception as e:                      # noqa: BLE001
        # e.g. http.client.BadStatusLine when a plain-HTTP request hits a TLS
        # port. Never let a transport-level oddity escape as a 500.
        raise CIError(f"{type(e).__name__}: {e}".strip()[:200]
                      or "unexpected transport error") from e


def _basic(user: str, secret: str) -> dict:
    tok = base64.b64encode(f"{user}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {tok}"}



def _bb_auth(c: dict) -> dict:
    """Bitbucket's two credential shapes, told apart by whether a user was given.

    Bitbucket Cloud has both, and they are not interchangeable:

      * an app password or an Atlassian API token identifies a PERSON, so it
        needs a username alongside it and goes over Basic;
      * a repository, project or workspace access token identifies ITSELF, has
        no user, and is only accepted as a Bearer token. Sending one over Basic
        returns 401 with no hint that the scheme was the problem.

    So a blank username means "this is an access token". That is also the better
    credential for a shared portal: it is not tied to somebody who may leave,
    and its scope is one project or workspace, read-only.
    """
    user = (c.get("username") or "").strip()
    if user:
        return _basic(user, c.get("token") or "")
    return {"Authorization": f"Bearer {c.get('token') or ''}"}
def _ago(iso: str) -> str:
    if not iso:
        return ""
    try:
        s = iso.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        d = datetime.now(timezone.utc) - dt
        if d.days > 0:
            return f"{d.days}d ago"
        h = d.seconds // 3600
        if h:
            return f"{h}h ago"
        m = d.seconds // 60
        return f"{m}m ago" if m else "just now"
    except Exception:
        return ""


def _ms(ms) -> str:
    try:
        s = int(ms) // 1000
    except (TypeError, ValueError):
        return ""
    return f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"


# ── Jenkins ────────────────────────────────────────────────────
_J_FIELDS = ("name,url,color,inQueue,queueItem[why],"
             "healthReport[score,description],"
             "lastBuild[number,building,result,timestamp,duration,url,"
             "actions[lastBuiltRevision[branch[name]],parameters[name,value]]],"
             "lastSuccessfulBuild[number,timestamp],"
             "lastFailedBuild[number,timestamp]")


def _jenkins_views(base: str, auth: dict, verify: bool) -> list[dict]:
    """Jenkins' own views, with the job names each contains."""
    try:
        data = _get(f"{base}/api/json?tree="
                    f"{urllib.parse.quote('views[name,url,jobs[name]]')}",
                    auth, verify)
    except CIError:
        return []
    out = []
    for v in (data.get("views") or []):
        out.append({"name": v.get("name", "?"), "url": v.get("url", ""),
                    "jobs": [j.get("name") for j in (v.get("jobs") or [])]})
    return out


def _jenkins(c: dict) -> list[dict]:
    verify = not c.get("skip_tls")
    base = c["base_url"].rstrip("/")
    if c.get("folder"):
        base += "/job/" + "/job/".join(p for p in c["folder"].strip("/").split("/") if p)
    auth = _bb_auth(c)

    inner = f"jobs[{_J_FIELDS},jobs[{_J_FIELDS}]]"
    data = _get(f"{base}/api/json?tree={urllib.parse.quote(inner)}", auth, verify)

    out = []

    def walk(items, prefix="", folder=""):
        for j in (items or []):
            nested = j.get("jobs")
            name = prefix + j.get("name", "?")
            if nested:                       # folder or multibranch project
                walk(nested, name + "/", j.get("name", ""))
                continue
            out.append(_jenkins_job(j, name, folder, base))

    walk(data.get("jobs"))

    # views become tabs; map each job to the views that contain it
    views = _jenkins_views(base, auth, verify)
    for job in out:
        top = job["name"].split("/")[0]
        job["views"] = [v["name"] for v in views
                        if top in v["jobs"] or job["name"] in v["jobs"]]
    # Jenkins ships a built-in "all" view; we render our own All tab
    _VIEW_ORDER[id(out)] = [v["name"] for v in views
                            if v["name"].lower() not in ("all", "todos")]

    # stage detail only for builds that are actually running — keeps this cheap
    live = [j for j in out if j["status"] == "running" and j.get("build_url")]
    if live:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(6, len(live))) as pool:
            for job, stages in zip(live, pool.map(
                    lambda j: _jenkins_stages(j["build_url"], auth, verify), live)):
                job["stages"] = stages
    return out


def _jenkins_stages(build_url: str, auth: dict, verify: bool) -> list[dict]:
    """Stage-by-stage progress from the Pipeline Stage View API."""
    try:
        data = _get(build_url.rstrip("/") + "/wfapi/describe", auth, verify)
    except CIError:
        return []
    out = []
    for st in (data.get("stages") or []):
        s = (st.get("status") or "").upper()
        out.append({"name": st.get("name", "?"),
                    "status": {"SUCCESS": "success", "FAILED": "failed",
                               "IN_PROGRESS": "running", "PAUSED_PENDING_INPUT": "pending",
                               "ABORTED": "cancelled", "NOT_EXECUTED": "pending",
                               "UNSTABLE": "failed", "QUEUED": "pending"}.get(s, "unknown"),
                    "duration": _ms(st.get("durationMillis"))})
    return out


_DEFAULT_BRANCHES = {"main", "master", "HEAD", "trunk"}


def _jenkins_branch(b: dict, name: str) -> tuple[str, list[str]]:
    """Best-guess branch for a build, plus every branch it checked out.

    A pipeline usually records several revisions: one per SCM checkout. The
    first is typically the repo holding the Jenkinsfile or a shared library on
    the default branch, and a later one is the application code. Picking the
    first therefore reports 'main' when the job really built 'test-env', so
    prefer the last non-default branch and keep the full list for the tooltip.
    """
    seen: list[str] = []
    for a in (b.get("actions") or []):
        rev = (a or {}).get("lastBuiltRevision") or {}
        for br in (rev.get("branch") or []):
            raw = (br.get("name") or "").strip()
            if not raw:
                continue
            for prefix in ("refs/remotes/origin/", "refs/heads/", "origin/", "refs/tags/"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
                    break
            else:
                raw = raw.split("/")[-1] if raw.startswith("refs/") else raw
            if raw and raw not in seen:
                seen.append(raw)

    if not seen:
        # multibranch pipelines encode the branch in the job name
        return (name.rsplit("/", 1)[1] if "/" in name else ""), []

    interesting = [x for x in seen if x not in _DEFAULT_BRANCHES]
    return (interesting[-1] if interesting else seen[0]), seen


def _jenkins_job(j: dict, name: str, folder: str = "", base: str = "") -> dict:
    b = j.get("lastBuild") or {}
    if b.get("building"):
        status = "running"
    else:
        status = {"SUCCESS": "success", "FAILURE": "failed", "ABORTED": "cancelled",
                  "UNSTABLE": "failed", None: "pending"}.get(b.get("result"), "unknown")
    _branch_pick = _jenkins_branch(b, name)
    queued = bool(j.get("inQueue"))
    why = ((j.get("queueItem") or {}).get("why") or "").strip()
    if queued:
        status = "pending"
    ok, bad = j.get("lastSuccessfulBuild") or {}, j.get("lastFailedBuild") or {}
    health = None
    for h in (j.get("healthReport") or []):
        if isinstance(h.get("score"), int):
            health = h["score"] if health is None else min(health, h["score"])
    return {"name": name, "status": status, "health": health, "folder": folder,
            "last_success": {"when": _epoch_ago(ok.get("timestamp")),
                             "number": ok.get("number")},
            "last_failure": {"when": _epoch_ago(bad.get("timestamp")),
                             "number": bad.get("number")},
            "duration": _ms(b.get("duration")),
            "number": b.get("number"),
            "branch": _branch_pick[0], "branches": _branch_pick[1],
            "started": _epoch_ago(b.get("timestamp")),
            # sortable, for questions like "the last one that ran"
            "started_at": _iso(b.get("timestamp")),
            "url": _rebase(j.get("url") or b.get("url", ""), base),
            "build_url": _rebase(b.get("url", ""), base),
            # the handle the stage lookup needs. Jenkins rows do not pass through
            # _fold_runs, which is where the other providers pick this up, so a
            # Jenkins pipeline had no way to be asked about its stages and the
            # button sat disabled.
            "ref": _rebase(b.get("url", ""), base),
            "stages": [], "views": [], "queued": queued, "queue_why": why}


def _rebase(url: str, base: str) -> str:
    """Rewrite a Jenkins-reported URL onto the base URL we were configured with.

    Jenkins echoes back whatever its own "Jenkins URL" setting says, which is
    frequently wrong (e.g. http:// on a TLS port). Keep the path, take the
    scheme/host/port from the connection so links and API calls actually work.
    """
    if not url:
        return ""
    try:
        u, b = urllib.parse.urlsplit(url), urllib.parse.urlsplit(base)
        return urllib.parse.urlunsplit((b.scheme, b.netloc, u.path, u.query, ""))
    except Exception:
        return url


def _iso(ms) -> str:
    """An epoch-milliseconds timestamp as ISO 8601, or "" — sortable, unlike the
    relative wording people read ("17h ago"). Needed to answer "which one ran
    last"."""
    if not ms:
        return ""
    try:
        return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return ""


def _epoch_ago(ms) -> str:
    if not ms:
        return ""
    try:
        return _ago(datetime.fromtimestamp(int(ms) / 1000, timezone.utc).isoformat())
    except Exception:
        return ""


# ── GitHub Actions ─────────────────────────────────────────────
def _github(c: dict) -> list[dict]:
    """One repository, or every repository under an owner.

    GitHub's runs feed is per repository, so a portal that only accepted
    `owner/repo` needed one connection per repository — for an estate with forty
    services that is forty connections, forty tokens to rotate, and a new service
    invisible until somebody remembers to add it. Naming just the owner (a user
    or an organisation) makes the portal discover the repositories itself, the
    way the Bitbucket workspace mode already does.
    """
    target = c["repo"].strip("/")
    if "/" in target:
        return _github_repo(c, target)
    return _github_owner(c, target)


def _gh_headers(c: dict) -> dict:
    return {"Authorization": f"Bearer {c['token']}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github+json"}


def _github_repo(c: dict, repo: str, per_page: int = 20,
                 prefix: str = "") -> list[dict]:
    verify = not c.get("skip_tls")
    data = _get(f"https://api.github.com/repos/{repo}/actions/runs"
                f"?per_page={per_page}",
                _gh_headers(c), verify)
    out = []
    for r in (data.get("workflow_runs") or []):
        concl, st = r.get("conclusion"), r.get("status")
        status = ("running" if st in ("in_progress", "queued", "requested", "waiting")
                  else {"success": "success", "failure": "failed",
                        "cancelled": "cancelled", "timed_out": "failed",
                        "skipped": "cancelled"}.get(concl, "unknown"))
        base_name = r.get("name") or r.get("display_title", "?")
        out.append({"name": f"{prefix} · {base_name}" if prefix else base_name,
                    # what the stage lookup needs to find this run again
                    "ref": f"{repo}#{r.get('id', '')}",
                    "_ts": (r.get("run_started_at") or r.get("created_at", "")),
                    "status": status, "branch": r.get("head_branch", ""),
                    "number": r.get("run_number", ""),
                    "started": _ago(r.get("run_started_at") or r.get("created_at", "")),
                    "started_at": (r.get("run_started_at")
                                   or r.get("created_at", "")),
                    "duration": "", "url": r.get("html_url", ""),
                    "author": ((r.get("actor") or {}).get("login", ""))})
    if not prefix:
        for r in out:
            r.pop("_ts", None)
    return out


def _github_repos_of(c: dict, owner: str) -> list[str]:
    """The owner's repositories, most recently pushed first.

    Three endpoints, because GitHub has three answers and none of them covers the
    others:

      /user/repos          the authenticated account's own repositories, and the
                           ONLY one that includes its private ones. This is the
                           case that matters most and the one the first version
                           got wrong: /users/{me}/repos returns public
                           repositories only, so an account whose work is all
                           private looked completely empty.
      /orgs/{org}/repos    an organisation, including private repositories the
                           token may read
      /users/{user}/repos  somebody else's public repositories

    Which of the three applies is not knowable from the input, so the token is
    asked who it belongs to first — one cheap call that removes the guesswork.

    Held for REPOS_TTL. Those two calls were two of the five seconds a refresh
    took, spent rediscovering a list that changes when somebody creates a
    repository — not when a build runs.
    """
    cache_key = f"{c.get('id') or c.get('token', '')[:8]}:{owner}"
    hit = _REPOS.get(cache_key)
    if hit and time.time() - hit[0] < REPOS_TTL:
        return hit[1]
    verify = not c.get("skip_tls")
    q = f"?per_page={WORKSPACE_REPOS}&sort=pushed&direction=desc"
    who = urllib.parse.quote(owner)

    me = ""
    try:
        me = str((_get("https://api.github.com/user", _gh_headers(c), verify)
                  or {}).get("login", ""))
    except CIError:
        pass                      # a token that cannot introspect still works below

    urls = []
    if me and me.lower() == owner.lower():
        urls.append("https://api.github.com/user/repos"
                    + q + "&affiliation=owner,collaborator,organization_member")
    urls += [f"https://api.github.com/orgs/{who}/repos{q}",
             f"https://api.github.com/users/{who}/repos{q}"]

    doc, last = None, ""
    for url in urls:
        try:
            doc = _get(url, _gh_headers(c), verify)
            if doc:
                break
        except CIError as e:
            last = str(e)
            if "404" not in last:
                raise
    if doc is None:
        raise CIError(f"no GitHub user or organisation called '{owner}'"
                      + (f" ({last})" if last else ""))
    items = doc if isinstance(doc, list) else (doc.get("items") or [])
    names = [r["full_name"] for r in items
             if r.get("full_name") and not r.get("archived")
             and not r.get("disabled")]
    if not names:
        # Silence here is the unhelpful answer: "connected, no pipelines" reads
        # as "nothing is building" when the truth is "this token cannot see your
        # repositories". Say which it is.
        raise CIError(
            f"the token can see no repositories under '{owner}'"
            + (f" (it authenticates as '{me}')" if me else "")
            + ". A fine-grained token must list the repositories it may read — "
              "set Repository access to All repositories, or select them — and "
              "an organisation's owner has to approve it. A classic token needs "
              "the 'repo' scope.")
    # only a good answer is kept: caching "this token sees nothing" for half an
    # hour would outlive fixing the token's scopes
    _REPOS[cache_key] = (time.time(), names)
    return names


def _github_owner(c: dict, owner: str) -> list[dict]:
    names = _github_repos_of(c, owner)
    if not names:
        return []

    from .fleet import _pmap

    def one(full_name):
        # a repository with Actions switched off, or one this token cannot read,
        # is skipped rather than sinking the whole owner's view
        try:
            return _github_repo(c, full_name, per_page=RUNS_PER_REPO,
                                prefix=full_name.split("/", 1)[1])
        except CIError:
            return []
    merged = []
    for rows in _pmap(one, names, workers=min(8, len(names))):
        merged.extend(rows or [])
    # newest first across every repository, so _fold_runs sees each workflow's
    # latest run first — the same contract the single-repo feed has
    merged.sort(key=lambda r: r.get("_ts", ""), reverse=True)
    for r in merged:
        r.pop("_ts", None)
    return merged


# ── Bitbucket Pipelines ────────────────────────────────────────
# Bitbucket has no server-wide pipeline feed — pipelines hang off repositories.
# So a connection that names only the workspace gets one the portal builds
# itself: list the workspace's most recently active repositories, pull each
# one's latest pipelines in parallel, and merge. One connection covers every
# repo, the way one Jenkins URL covers every job; new repositories appear on
# their own because the repo list is fetched fresh each time, never stored.
# shared by the Bitbucket workspace and GitHub owner modes
WORKSPACE_REPOS = 30      # most recently updated; a repo idle for months has
                          # no recent pipelines to show anyway
RUNS_PER_REPO = 8


def _bitbucket(c: dict) -> list[dict]:
    repo = c["repo"].strip("/")
    if "/" in repo:
        return _bitbucket_repo(c, repo)
    return _bitbucket_workspace(c, repo)


def _bitbucket_workspace(c: dict, workspace: str) -> list[dict]:
    verify = not c.get("skip_tls")
    auth = _bb_auth(c)
    doc = _get("https://api.bitbucket.org/2.0/repositories/"
               f"{urllib.parse.quote(workspace)}?pagelen={WORKSPACE_REPOS}"
               "&sort=-updated_on&fields=values.full_name,values.updated_on",
               auth, verify)
    names = [r.get("full_name") for r in (doc.get("values") or [])
             if r.get("full_name")]
    if not names:
        return []

    from .fleet import _pmap

    def one(full_name):
        # a repository the token cannot see, or one with pipelines disabled,
        # is skipped rather than sinking the whole workspace view
        try:
            return _bitbucket_repo(c, full_name, pagelen=RUNS_PER_REPO,
                                   prefix=full_name.split("/", 1)[1])
        except CIError:
            return []
    merged = []
    for rows in _pmap(one, names, workers=min(8, len(names))):
        merged.extend(rows or [])
    # newest activity first across the whole workspace, so _fold_runs sees each
    # pipeline's latest run first — same contract as the single-repo feed
    merged.sort(key=lambda r: r.get("_ts", ""), reverse=True)
    for r in merged:
        r.pop("_ts", None)
    return merged


def _bitbucket_repo(c: dict, repo: str, pagelen: int = 20,
                    prefix: str = "") -> list[dict]:
    verify = not c.get("skip_tls")
    data = _get(f"https://api.bitbucket.org/2.0/repositories/{repo}/pipelines/"
                f"?pagelen={pagelen}&sort=-created_on",
                _bb_auth(c), verify)
    out = []
    for p in (data.get("values") or []):
        st = p.get("state") or {}
        name = (st.get("name") or "").upper()
        result = ((st.get("result") or {}).get("name") or "").upper()
        if name in ("IN_PROGRESS", "PENDING"):
            status = "running"
        else:
            status = {"SUCCESSFUL": "success", "FAILED": "failed",
                      "ERROR": "failed", "STOPPED": "cancelled"}.get(result, "unknown")
        target = p.get("target") or {}
        base_name = (target.get("selector") or {}).get("pattern") \
            or target.get("ref_name") or "pipeline"
        out.append({"name": f"{prefix} · {base_name}" if prefix else base_name,
                    "ref": f"{repo}#{p.get('uuid', '')}",
                    "_ts": p.get("created_on", ""),
                    "status": status, "branch": target.get("ref_name", ""),
                    "number": p.get("build_number", ""),
                    "started": _ago(p.get("created_on", "")),
                    "started_at": p.get("created_on", ""),
                    "duration": _ms((p.get("duration_in_seconds") or 0) * 1000),
                    "url": f"https://bitbucket.org/{repo}/pipelines/results/"
                           f"{p.get('build_number','')}",
                    "author": ((p.get("creator") or {}).get("display_name", ""))})
    if not prefix:
        for r in out:
            r.pop("_ts", None)
    return out


# ── GitLab CI ──────────────────────────────────────────────────
# Same reasoning as the GitHub owner and Bitbucket workspace modes: pipelines
# hang off projects, so a group named on its own is expanded here rather than
# turning into one connection per project.
def _gitlab(c: dict) -> list[dict]:
    target = str(c.get("project", "")).strip("/")
    if c.get("group") or (not target.isdigit() and c.get("scope") == "group"):
        return _gitlab_group(c, c.get("group") or target)
    if target and not target.isdigit() and "/" not in target \
            and "%2F" not in target.lower():
        # a bare name is ambiguous: a group is the more useful reading, and if it
        # is really a project the group call 404s and the project is tried
        try:
            return _gitlab_group(c, target)
        except CIError:
            pass
    return _gitlab_project(c, target)


def _gitlab_project(c: dict, proj: str, per_page: int = 20,
                    prefix: str = "") -> list[dict]:
    verify = not c.get("skip_tls")
    base = c["base_url"].rstrip("/")
    ident = urllib.parse.quote(str(proj), safe="")
    data = _get(f"{base}/api/v4/projects/{ident}/pipelines?per_page={per_page}",
                {"PRIVATE-TOKEN": c["token"]}, verify)
    out = []
    for p in (data if isinstance(data, list) else []):
        st = p.get("status")
        status = ("running" if st in ("running", "pending", "created", "preparing")
                  else {"success": "success", "failed": "failed",
                        "canceled": "cancelled", "skipped": "cancelled"}
                  .get(st, "unknown"))
        base_name = p.get("ref") or "pipeline"
        out.append({"name": f"{prefix} · {base_name}" if prefix else base_name,
                    "ref": f"{proj}#{p.get('id', '')}",
                    "_ts": p.get("created_at", ""),
                    "status": status,
                    "branch": p.get("ref", ""), "number": p.get("id", ""),
                    "started": _ago(p.get("created_at", "")),
                    "started_at": p.get("created_at", ""), "duration": "",
                    "url": p.get("web_url", ""), "author": ""})
    if not prefix:
        for r in out:
            r.pop("_ts", None)
    return out


def _gitlab_group(c: dict, group: str) -> list[dict]:
    verify = not c.get("skip_tls")
    base = c["base_url"].rstrip("/")
    ident = urllib.parse.quote(str(group), safe="")
    doc = _get(f"{base}/api/v4/groups/{ident}/projects"
               f"?per_page={WORKSPACE_REPOS}&order_by=last_activity_at"
               "&include_subgroups=true&archived=false",
               {"PRIVATE-TOKEN": c["token"]}, verify)
    projects = [(p["id"], p.get("path") or p.get("name") or str(p["id"]))
                for p in (doc if isinstance(doc, list) else []) if p.get("id")]
    if not projects:
        return []

    from .fleet import _pmap

    def one(item):
        pid, name = item
        try:
            return _gitlab_project(c, pid, per_page=RUNS_PER_REPO, prefix=name)
        except CIError:
            return []
    merged = []
    for rows in _pmap(one, projects, workers=min(8, len(projects))):
        merged.extend(rows or [])
    merged.sort(key=lambda r: r.get("_ts", ""), reverse=True)
    for r in merged:
        r.pop("_ts", None)
    return merged


_IMPL = {"jenkins": _jenkins, "github": _github,
         "bitbucket": _bitbucket, "gitlab": _gitlab}


def _fold_runs(runs: list[dict]) -> list[dict]:
    """Providers that expose a run feed rather than jobs: group by pipeline name
    and derive the same columns Jenkins gives us directly."""
    order, groups = [], {}
    for r in runs:
        key = r["name"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)
    out = []
    for key in order:
        g = groups[key]
        latest = g[0]
        ok = next((r for r in g if r["status"] == "success"), None)
        bad = next((r for r in g if r["status"] == "failed"), None)
        recent = g[:5]
        good = sum(1 for r in recent if r["status"] == "success")
        health = round(good / len(recent) * 100) if recent else None
        out.append({
            "name": key, "status": latest["status"], "health": health,
            "last_success": {"when": ok["started"] if ok else "",
                             "number": ok["number"] if ok else None},
            "last_failure": {"when": bad["started"] if bad else "",
                             "number": bad["number"] if bad else None},
            "duration": latest.get("duration", ""), "number": latest.get("number"),
            "branch": latest.get("branch", ""), "url": latest.get("url", ""),
            "started": latest.get("started", ""),
            "started_at": latest.get("started_at", ""),
            "build_url": latest.get("url", ""),
            "ref": latest.get("ref", ""),
            "stages": [], "views": [], "folder": "",
            "queued": False, "queue_why": "",
            "branches": [latest.get("branch")] if latest.get("branch") else [],
        })
    return out


# WHY THE PAGE NEVER WAITS FOR THIS
#     Reading an owner's pipelines is twelve API calls and five seconds: two to
#     work out which repositories exist, then one per repository. With a plain
#     sixty-second cache anybody arriving more than a minute after the last
#     visitor paid the whole five seconds with a blank page in front of them,
#     which is what "the pipelines page is slow" was.
#
#     So a cached answer is served immediately and a fresh one is collected
#     behind it. Past CACHE_HARD the answer is too old to show and the caller
#     waits — an hour-old build list presented as current would be worse than a
#     slow page.
CACHE_TTL = 90                 # fresh: serve it and ask nobody
CACHE_HARD = 15 * 60           # too old to show; collect before answering
_CACHE: dict[str, tuple[float, dict]] = {}
_REFRESHING: set = set()
_REFRESH_LOCK = threading.Lock()

# The repository list is the expensive half and the half that barely changes:
# a new repository appears occasionally, a build runs constantly. Cached apart
# from the runs so a background refresh costs one call per repository instead
# of two seconds of rediscovery first.
REPOS_TTL = 30 * 60
_REPOS: dict[str, tuple[float, list]] = {}


# ── stages of one run ──────────────────────────────────────────────────────
# Fetched only when asked for. A stage list is a second request per run, so
# pulling it for every pipeline on the page would multiply a fourteen-row table
# into fifteen API calls before anyone had clicked anything — and on GitHub that
# is rate limit spent on information nobody looked at.
_STAGE_CACHE: dict = {}
_STAGE_TTL = 45


def _stage_status(*candidates) -> str:
    for c in candidates:
        v = (c or "").lower()
        if v in ("success", "successful", "passed"):
            return "success"
        if v in ("failure", "failed", "error", "timed_out", "unstable"):
            return "failed"
        if v in ("in_progress", "running", "pending", "queued", "waiting",
                 "created", "preparing", "requested", "manual"):
            return "running" if v in ("in_progress", "running") else "pending"
        if v in ("cancelled", "canceled", "stopped", "skipped", "neutral"):
            return "cancelled"
    return "unknown"


def stages(conn: dict, ref: str, refresh: bool = False) -> dict:
    """{"stages": [...], "failed": {...}} for one run.

    Every provider is asked its own way and the answers are normalised to the
    same shape, so the page has one thing to render. `failed` names the first
    stage that failed, and where a provider exposes steps, the step inside it —
    "build → npm ci" answers "where did it break" without opening the log.
    """
    key = (conn.get("id"), ref)
    now = time.time()
    if not refresh and key in _STAGE_CACHE:
        when, got = _STAGE_CACHE[key]
        if now - when < _STAGE_TTL:
            return got
    kind = conn.get("type")
    if refresh and kind == "github":
        # the run's jobs are shared with the log reader, and a shared cache
        # that ignores Refresh makes the button lie
        _GH_JOBS.pop((conn.get("id"), *_split_ref(ref)), None)
    fn = {"github": _github_stages, "gitlab": _gitlab_stages,
          "bitbucket": _bitbucket_stages, "jenkins": _jenkins_run_stages}.get(kind)
    if not fn or not ref:
        return {"stages": [], "failed": None,
                "note": f"{kind or 'this provider'} does not report stages"}
    try:
        rows = fn(conn, ref)
        out = {"stages": rows, "failed": _first_failure(rows), "note": ""}
    except CIError as e:
        out = {"stages": [], "failed": None, "note": str(e)}
    _STAGE_CACHE[key] = (now, out)
    return out


def _first_failure(rows: list[dict]) -> dict | None:
    for r in rows:
        if r["status"] == "failed":
            step = next((s["name"] for s in (r.get("steps") or [])
                         if s.get("status") == "failed"), "")
            return {"stage": r["name"], "step": step, "url": r.get("url", "")}
    return None


def _split_ref(ref: str) -> tuple[str, str]:
    left, _, right = ref.rpartition("#")
    return left, right


# The stage strip and the log list are the same GitHub call. Opening a log
# after looking at the stages fetched it twice — a second 1.3s wait for an
# answer already in hand.
_GH_JOBS: dict = {}
_GH_JOBS_TTL = 45


def _gh_run_jobs(c: dict, repo: str, run_id: str, refresh: bool = False) -> dict:
    key = (c.get("id"), repo, str(run_id))
    hit = _GH_JOBS.get(key)
    if hit and not refresh and time.time() - hit[0] < _GH_JOBS_TTL:
        return hit[1]
    doc = _get(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
               "?per_page=50", _gh_headers(c), not c.get("skip_tls"))
    _GH_JOBS[key] = (time.time(), doc)
    return doc


def _github_stages(c: dict, ref: str) -> list[dict]:
    repo, run_id = _split_ref(ref)
    doc = _gh_run_jobs(c, repo, run_id)
    out = []
    for j in (doc.get("jobs") or []):
        steps = [{"name": st.get("name", "?"),
                  "status": _stage_status(st.get("conclusion"), st.get("status"))}
                 for st in (j.get("steps") or [])]
        out.append({"name": j.get("name", "?"),
                    "status": _stage_status(j.get("conclusion"), j.get("status")),
                    "duration": _between(j.get("started_at"), j.get("completed_at")),
                    "url": j.get("html_url", ""), "steps": steps,
                    # so a stage row can open its own log rather than the
                    # run's first failing one
                    "job": str(j.get("id") or "")})
    return out


def _gitlab_stages(c: dict, ref: str) -> list[dict]:
    proj, pipeline = _split_ref(ref)
    verify = not c.get("skip_tls")
    base = c["base_url"].rstrip("/")
    doc = _get(f"{base}/api/v4/projects/{urllib.parse.quote(str(proj), safe='')}"
               f"/pipelines/{pipeline}/jobs?per_page=100",
               {"PRIVATE-TOKEN": c["token"]}, verify)
    # GitLab has real stages, with jobs inside them: group rather than flatten,
    # because "which stage failed" is the question and a stage can hold ten jobs
    order, groups = [], {}
    for j in (doc if isinstance(doc, list) else []):
        st = j.get("stage") or "stage"
        if st not in groups:
            groups[st] = []
            order.append(st)
        groups[st].append(j)
    out = []
    for st in order:
        jobs = groups[st]
        statuses = [_stage_status(j.get("status")) for j in jobs]
        status = ("failed" if "failed" in statuses else
                  "running" if "running" in statuses else
                  "pending" if "pending" in statuses else
                  "success" if all(x == "success" for x in statuses) else
                  statuses[0] if statuses else "unknown")
        out.append({"name": st, "status": status,
                    "duration": _ms(int((jobs[0].get("duration") or 0) * 1000)),
                    "url": jobs[0].get("web_url", ""),
                    "steps": [{"name": j.get("name", "?"),
                               "status": _stage_status(j.get("status"))}
                              for j in jobs]})
    return out


def _bitbucket_stages(c: dict, ref: str) -> list[dict]:
    repo, uuid = _split_ref(ref)
    verify = not c.get("skip_tls")
    doc = _get(f"https://api.bitbucket.org/2.0/repositories/{repo}/pipelines/"
               f"{urllib.parse.quote(uuid)}/steps/",
               _bb_auth(c), verify)
    out = []
    for st in (doc.get("values") or []):
        state = st.get("state") or {}
        out.append({"name": st.get("name") or "step",
                    "status": _stage_status((state.get("result") or {}).get("name"),
                                            state.get("name")),
                    "duration": _ms((st.get("duration_in_seconds") or 0) * 1000),
                    "url": "", "steps": []})
    return out


_WF_STATUS = {"SUCCESS": "success", "FAILED": "failed", "IN_PROGRESS": "running",
              "PAUSED_PENDING_INPUT": "pending", "ABORTED": "cancelled",
              "NOT_EXECUTED": "pending", "UNSTABLE": "failed", "QUEUED": "pending"}


def _jenkins_run_stages(c: dict, ref: str) -> list[dict]:
    """Stages of one Jenkins build, with the steps of the one that failed.

    Only Pipeline jobs have stages. A freestyle job has no wfapi at all, and
    saying "this run reported no stages" about one is misleading — it never had
    any and never will.
    """
    verify = not c.get("skip_tls")
    auth = _basic(c.get("username", ""), c["token"])
    try:
        doc = _get(ref.rstrip("/") + "/wfapi/describe", auth, verify)
    except CIError as e:
        if "404" in str(e):
            raise CIError("only Pipeline jobs report stages — this looks like a "
                          "freestyle job") from e
        raise

    origin = "/".join(ref.split("/")[:3])          # scheme://host[:port]
    rows, failed_at = [], None
    for st in (doc.get("stages") or []):
        status = _WF_STATUS.get((st.get("status") or "").upper(), "unknown")
        href = (((st.get("_links") or {}).get("self") or {}).get("href") or "")
        row = {"name": st.get("name", "?"), "status": status,
               "duration": _ms(st.get("durationMillis")),
               "url": (origin + href) if href.startswith("/") else href,
               "steps": []}
        rows.append(row)
        if status == "failed" and failed_at is None and href:
            failed_at = (row, origin + href if href.startswith("/") else href)

    # one more call, for the failed stage only: the step that broke is the answer
    # to the question, and fetching every stage's steps would be a call per stage
    if failed_at:
        row, url = failed_at
        try:
            detail = _get(url.rstrip("/") + "/describe", auth, verify)
            for node in (detail.get("stageFlowNodes") or []):
                row["steps"].append({
                    "name": (node.get("parameterDescription")
                             or node.get("name") or "step"),
                    "status": _WF_STATUS.get(
                        (node.get("status") or "").upper(), "unknown")})
        except CIError:
            pass                    # the stage list alone is still worth showing
    return rows


def _between(start: str, end: str) -> str:
    """A duration from two timestamps, which is all GitHub gives per job."""
    if not start or not end:
        return ""
    try:
        a = datetime.fromisoformat(start.replace("Z", "+00:00"))
        b = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return _ms(int((b - a).total_seconds() * 1000))
    except (ValueError, TypeError):
        return ""


def invalidate() -> None:
    _CACHE.clear()
    _STAGE_CACHE.clear()
    _GH_JOBS.clear()
    _LOG_CACHE.clear()
    _REPOS.clear()


def fetch(conn: dict, refresh: bool = False) -> dict:
    """{"jobs": [...], "views": [...]} — views come straight from the provider
    so adding or deleting one in Jenkins is reflected on the next page load,
    including views that currently hold no jobs.

    Serves what it has and refreshes behind the page; see the note above the
    cache constants for why.
    """
    kind = conn.get("type")
    fn = _IMPL.get(kind)
    if not fn:
        raise CIError(f"unknown provider '{kind}'")
    key = conn.get("id") or f"{kind}:{conn.get('base_url') or conn.get('repo','')}"
    hit = _CACHE.get(key)
    if hit and not refresh:
        age = time.time() - hit[0]
        if age < CACHE_TTL:
            return hit[1]
        if age < CACHE_HARD:
            _revalidate(conn, key)
            return {**hit[1], "stale_for": round(age)}
    return _collect(conn, key)


def _collect(conn: dict, key: str) -> dict:
    kind = conn.get("type")
    got = _IMPL[kind](conn)
    if kind != "jenkins":
        out = {"jobs": _fold_runs(got), "views": [], "stale_for": 0}
    else:
        out = {"jobs": got, "views": _VIEW_ORDER.pop(id(got), []), "stale_for": 0}
    _CACHE[key] = (time.time(), out)
    return out


def _revalidate(conn: dict, key: str) -> None:
    """Collect a fresh answer behind whoever is reading the stale one. One at a
    time per connection: a page with three panels asking at once would other
    otherwise start three identical pulls."""
    with _REFRESH_LOCK:
        if key in _REFRESHING:
            return
        _REFRESHING.add(key)

    def run():
        try:
            _collect(conn, key)
        except Exception:                                      # noqa: BLE001
            # leave the stale answer in place: a blip must not empty the page
            pass
        finally:
            with _REFRESH_LOCK:
                _REFRESHING.discard(key)
    threading.Thread(target=run, name="ci-revalidate", daemon=True).start()


def peek(conn: dict) -> dict | None:
    """Whatever is already cached for this connection, or None. Never calls
    out — for callers that want a detail if it is free and can do without it,
    such as a page heading."""
    key = conn.get("id") or (f"{conn.get('type')}:"
                             f"{conn.get('base_url') or conn.get('repo', '')}")
    hit = _CACHE.get(key)
    return hit[1] if hit else None


def jobs(conn: dict, refresh: bool = False) -> list[dict]:
    return fetch(conn, refresh=refresh)["jobs"]


def runs(conn: dict) -> list[dict]:
    fn = _IMPL.get(conn.get("type"))
    if not fn:
        raise CIError(f"unknown provider '{conn.get('type')}'")
    return fn(conn)


def test(conn: dict) -> tuple[bool, str]:
    try:
        got = jobs(conn, refresh=True)         # never validate against a cache
    except CIError as e:
        return False, str(e)
    except Exception as e:                      # noqa: BLE001 - surface anything
        return False, f"{type(e).__name__}: {e}"
    if not got:
        return True, "connected — no pipelines found yet"
    bad = sum(1 for r in got if r["status"] == "failed")
    return True, (f"connected — {len(got)} pipeline(s)"
                  + (f", {bad} failing" if bad else ", all green"))


def summarise(all_runs: list[dict]) -> dict:
    c = {"success": 0, "failed": 0, "running": 0, "cancelled": 0,
         "pending": 0, "unknown": 0}
    for r in all_runs:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def weather(score) -> tuple[str, str]:
    """Jenkins-style build-health icon from a 0-100 score."""
    if score is None:
        return "—", "no health data"
    if score >= 80:
        return "☀️", f"{score}% — healthy"
    if score >= 60:
        return "🌤", f"{score}% — mostly healthy"
    if score >= 40:
        return "⛅", f"{score}% — unstable"
    if score >= 20:
        return "🌧", f"{score}% — failing often"
    return "⛈", f"{score}% — mostly failing"


# ── logs ───────────────────────────────────────────────────────────────────
# WHY THE LOG BELONGS HERE
#     The stage strip answers "where did it break". The next question is always
#     "why", and until now the only answer was a link out to GitHub — which
#     means leaving the portal, finding the run again, and expanding the right
#     job. The log is the whole point of a failed build, so it is fetched here.
#
# WHAT IS AND IS NOT KEPT
#     Nothing. A log is read on demand and handed straight to the page; none of
#     it is written to the portal's database. Build output routinely contains
#     tokens echoed by careless scripts, and a copy of that sitting in a second
#     system is a liability nobody asked for.
# Providers whose logs this module knows how to fetch. Checked up front so a
# provider with no reader says so, rather than reporting that the run had no
# jobs — which is what an empty dispatch looks like from the outside, and is a
# different problem entirely.
LOG_PROVIDERS = ("github", "gitlab", "bitbucket", "jenkins")
LOG_BYTES = 400_000          # per job, from the end: the tail is the failure
LOG_TTL = 60                 # a finished run's log does not change
_LOG_CACHE: dict = {}

# GitHub, GitLab and Jenkins all colour their output. Left in, it renders as
# literal escape gibberish; the sequences carry no information a reader needs.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b\x0c\x0e-\x1f]")

# GitHub prefixes every line with an RFC3339 timestamp. Useful for timing, in
# the way and unreadable when you are looking for an error, so it is split off
# and offered as a toggle rather than deleted.
_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s?")


class _KeepRedirect(urllib.request.HTTPRedirectHandler):
    """Stop at the redirect instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get_text(url: str, headers: dict, verify: bool = True) -> str:
    """GET plain text. Logs are not JSON, and asking for JSON gets a 406.

    A log is rarely served by the API itself. GitHub answers 302 with a signed
    URL on a storage host; following that with urllib's default handler
    re-sends the Authorization header to it, which is both why the first
    attempt came back 401 and a good way to hand a personal access token to
    somebody else's domain. So the redirect is caught rather than followed,
    and the signed URL is fetched with no credentials on it — it carries its
    own, in the query string, which is the entire point of signing it.
    """
    ctx = None if verify else _INSECURE
    opener = urllib.request.build_opener(
        _KeepRedirect, urllib.request.HTTPSHandler(context=ctx) if ctx
        else urllib.request.HTTPSHandler())
    req = urllib.request.Request(
        urlguard.check(url), headers={"Accept": "*/*", **headers})
    try:
        try:
            with opener.open(req, timeout=TIMEOUT * 2) as r:
                raw = r.read(LOG_BYTES * 4)
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            target = e.headers.get("Location") or ""
            e.close()
            if not target:
                raise CIError("the provider redirected the log request but "
                              "said nowhere") from e
            signed = urllib.request.Request(
                urlguard.check(urllib.parse.urljoin(url, target)),
                headers={"Accept": "*/*"})
            with urllib.request.urlopen(signed, timeout=TIMEOUT * 2,
                                        context=ctx) as r:
                raw = r.read(LOG_BYTES * 4)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise CIError(f"authentication rejected ({e.code}) — the token "
                          f"needs read access to build logs") from e
        if e.code == 404:
            raise CIError("no log there — it may have expired, or the run was "
                          "cancelled before it produced one") from e
        if e.code == 410:
            raise CIError("the provider has expired this log") from e
        raise CIError(f"HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise CIError(f"cannot reach the server: {e.reason}") from e
    except Exception as e:                                     # noqa: BLE001
        raise CIError(f"{type(e).__name__}: {e}"[:200]) from e
    return raw.decode("utf-8", "replace")


def _tidy(text: str) -> dict:
    """The log as the page wants it: clean, tail-capped, and with the first
    failure located so the reader is not left scrolling for it."""
    text = _ANSI.sub("", text or "")
    truncated = False
    if len(text) > LOG_BYTES:
        text = text[-LOG_BYTES:]
        text = text.split("\n", 1)[-1]          # never start mid-line
        truncated = True
    lines, stamps = [], []
    for raw in text.splitlines():
        m = _STAMP.match(raw)
        stamps.append(m.group(1)[11:19] if m else "")
        lines.append(raw[m.end():] if m else raw)
    return {"lines": lines, "stamps": stamps, "truncated": truncated,
            "first_error": _first_error(lines)}


# Deliberately a small, boring list. A log is full of the word "error" in
# passing; these are the shapes that actually mark the failure, and getting it
# wrong sends the reader to the wrong line, which is worse than not jumping.
_ERROR_HINTS = (
    "##[error]", "fatal:", "error:", "err!", "npm err", "exit code 1",
    "exited with code", "build failed", "test failed", "failure:",
    "traceback (most recent call last)", "panic:", "segmentation fault",
    "no such file or directory", "permission denied", "command not found",
    "cannot find module", "unauthorized", "forbidden",
    # Jenkins says it its own way, and saying it in none of the above meant
    # "jump to the failure" never worked on a Jenkins build
    "build failure", "finished: failure", "finished: unstable",
    "marked build as failure", "make: ***", "assertionerror",
)


def _first_error(lines: list[str]) -> int:
    """The line a reader should be taken to, or -1.

    Searched from the end: a long build logs plenty of noise on the way, and
    the failure that stopped it is near the bottom.
    """
    for i in range(len(lines) - 1, -1, -1):
        low = lines[i].lower()
        if any(h in low for h in _ERROR_HINTS):
            return i
    return -1


def run_jobs(conn: dict, ref: str) -> list[dict]:
    """The units one run's log is divided into, each with an id to fetch by.

    Not `jobs()` — that is already the list of pipelines this connection can
    see, and two functions a letter apart returning different things is how a
    caller ends up with the wrong one.
    """
    kind = conn.get("type")
    verify = not conn.get("skip_tls")
    if kind == "github":
        repo, run_id = _split_ref(ref)
        # the same call the stage strip makes; shared so opening a log after
        # looking at the stages does not pay for it twice
        doc = _gh_run_jobs(conn, repo, run_id)
        return [{"id": str(j.get("id")), "name": j.get("name", "?"),
                 "status": _stage_status(j.get("conclusion"), j.get("status")),
                 "duration": _between(j.get("started_at"), j.get("completed_at")),
                 "url": j.get("html_url", "")}
                for j in (doc.get("jobs") or [])]
    if kind == "gitlab":
        proj, pipeline = _split_ref(ref)
        base = conn["base_url"].rstrip("/")
        doc = _get(f"{base}/api/v4/projects/"
                   f"{urllib.parse.quote(str(proj), safe='')}"
                   f"/pipelines/{pipeline}/jobs?per_page=100",
                   {"PRIVATE-TOKEN": conn["token"]}, verify)
        return [{"id": str(j.get("id")), "name": j.get("name", "?"),
                 "status": _stage_status(j.get("status")),
                 "duration": _ms((j.get("duration") or 0) * 1000),
                 "url": j.get("web_url", "")}
                for j in (doc if isinstance(doc, list) else [])]
    if kind == "bitbucket":
        repo, uuid = _split_ref(ref)
        doc = _get(f"https://api.bitbucket.org/2.0/repositories/{repo}"
                   f"/pipelines/{uuid}/steps/?pagelen=50",
                   _bb_auth(conn), verify)
        out = []
        for s in (doc.get("values") or []):
            out.append({"id": str(s.get("uuid", "")),
                        "name": (s.get("name") or "step"),
                        "status": _stage_status(
                            (s.get("state") or {}).get("result", {}).get("name"),
                            (s.get("state") or {}).get("name")),
                        "duration": _ms((s.get("duration_in_seconds") or 0) * 1000),
                        "url": ""})
        return out
    if kind == "jenkins":
        # a Jenkins build is one console, so it is one "job"
        return [{"id": "console", "name": "Console output", "status": "",
                 "duration": "", "url": f"{ref.rstrip('/')}/console"}]
    return []


def log_shell(conn: dict, ref: str, job: str = "") -> dict:
    """Everything the page can show before the log itself arrives.

    Reading the text is a two-and-a-half second download from the provider's
    storage; the job list is usually already in hand. Splitting them lets the
    page appear with its tabs and a spinner instead of a blank wait.
    """
    out = {"jobs": [], "job": None, "note": ""}
    if conn.get("type") not in LOG_PROVIDERS:
        out["note"] = (f"{conn.get('type') or 'this provider'} has no log "
                       f"reader here yet")
        return out
    try:
        found = run_jobs(conn, ref)
        out["jobs"] = found
        pick = next((j for j in found if j["id"] == job), None) if job else None
        if pick is None:
            pick = next((j for j in found if j["status"] == "failed"),
                        found[0] if found else None)
        out["job"] = pick
        if pick is None:
            out["note"] = "this run reported no jobs to read a log from"
    except CIError as e:
        out["note"] = str(e)
    except Exception as e:                                     # noqa: BLE001
        out["note"] = f"{type(e).__name__}: {e}"[:200]
    return out


def log(conn: dict, ref: str, job: str = "", refresh: bool = False) -> dict:
    """One job's output, cleaned up, plus the list of jobs to choose from.

    The failed job is chosen when none is asked for: on a build that broke,
    that is the only one anybody opens first.
    """
    key = (conn.get("id"), ref, job)
    now = time.time()
    if not refresh and key in _LOG_CACHE:
        when, got = _LOG_CACHE[key]
        if now - when < LOG_TTL:
            return got
    out = {"jobs": [], "job": None, "lines": [], "stamps": [],
           "truncated": False, "first_error": -1, "note": ""}
    if conn.get("type") not in LOG_PROVIDERS:
        out["note"] = (f"{conn.get('type') or 'this provider'} has no log "
                       f"reader here yet")
        _LOG_CACHE[key] = (now, out)
        return out
    if refresh and conn.get("type") == "github":
        _GH_JOBS.pop((conn.get("id"), *_split_ref(ref)), None)
    try:
        found = run_jobs(conn, ref)
        out["jobs"] = found
        pick = next((j for j in found if j["id"] == job), None) if job else None
        if pick is None:
            pick = next((j for j in found if j["status"] == "failed"),
                        found[0] if found else None)
        out["job"] = pick
        if pick is None:
            out["note"] = "this run reported no jobs to read a log from"
        else:
            out.update(_tidy(_fetch_log(conn, ref, pick["id"])))
    except CIError as e:
        out["note"] = str(e)
    except Exception as e:                                     # noqa: BLE001
        out["note"] = f"{type(e).__name__}: {e}"[:200]
    _LOG_CACHE[key] = (now, out)
    return out


def _fetch_log(conn: dict, ref: str, job: str) -> str:
    kind = conn.get("type")
    verify = not conn.get("skip_tls")
    if kind == "github":
        repo, _ = _split_ref(ref)
        # answers 302 to a signed blob; urllib follows it, and the Accept
        # header must not ask for JSON or the redirect target refuses
        return _get_text(f"https://api.github.com/repos/{repo}/actions/jobs/"
                         f"{job}/logs", _gh_headers(conn), verify)
    if kind == "gitlab":
        proj, _ = _split_ref(ref)
        base = conn["base_url"].rstrip("/")
        return _get_text(f"{base}/api/v4/projects/"
                         f"{urllib.parse.quote(str(proj), safe='')}"
                         f"/jobs/{job}/trace", {"PRIVATE-TOKEN": conn["token"]},
                         verify)
    if kind == "bitbucket":
        repo, uuid = _split_ref(ref)
        return _get_text(f"https://api.bitbucket.org/2.0/repositories/{repo}"
                         f"/pipelines/{uuid}/steps/{job}/log",
                         _bb_auth(conn), verify)
    if kind == "jenkins":
        return _get_text(f"{ref.rstrip('/')}/consoleText",
                         _basic(conn.get("username", ""), conn.get("token", "")),
                         verify)
    raise CIError(f"{kind or 'this provider'} has no log reader here yet")
