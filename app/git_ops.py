"""Git status / diff / discard inside the portal workspace.

Keyed on (project, region, environment). The environment matters: it carries the
binding that says which checkout its values live in, so a status read for an
environment on its own branch has to run in ITS working copy. Passing no
environment means the region's own checkout, which is what the pages that ask
about a region want.
"""
import subprocess

from . import store
from .env import GIT, TOOL_PATH


def _dir(pid: str, rgid: str, env: str = ""):
    from . import repo as repomod
    return repomod.checkout(pid, rgid, env)


def _run(pid: str, rgid: str, *args: str, env: str = "") -> str:
    d = _dir(pid, rgid, env)
    if not (d / ".git").is_dir():
        return ""
    # same binary and PATH as every other git call, so a deployment that ships
    # git somewhere unusual works everywhere or nowhere, never half
    r = subprocess.run([GIT, "-C", str(d), *args],
                       capture_output=True, text=True, timeout=30,
                       env={"PATH": TOOL_PATH, "GIT_TERMINAL_PROMPT": "0"})
    return r.stdout + r.stderr


def region_status(pid: str, rgid: str, check_remote: bool = True,
                  env: str = "") -> dict:
    from . import gitrepo
    if not (_dir(pid, rgid, env) / ".git").is_dir():
        return {"branch": "-", "head": "not cloned", "dirty": "", "stale": False}
    branch = _run(pid, rgid, "rev-parse", "--abbrev-ref", "HEAD", env=env).strip()
    local = _run(pid, rgid, "rev-parse", "HEAD", env=env).strip()
    st = {"branch": branch,
          "head": _run(pid, rgid, "log", "-1", "--oneline", env=env).strip(),
          "dirty": _run(pid, rgid, "status", "--porcelain", env=env).strip(),
          "stale": False, "remote_sha": ""}
    if check_remote:
        # region-form calls (env="") have no repository to ask any more; the
        # local read above still answers, the staleness check is env-only
        conf = gitrepo.env_repo(pid, rgid, env) if env else {}
        remote = (gitrepo.remote_head(pid, rgid, conf, branch)
                  if conf.get("url") else "")
        st["remote_sha"] = remote[:7]
        # stale = the remote has a commit we don't have locally
        if remote and remote != local:
            known = _run(pid, rgid, "cat-file", "-e", remote, env=env).strip()
            st["stale"] = bool(known) or True
    return st


def commits(pid: str, rgid: str, since: str = "", limit: int = 60,
            env: str = "") -> list[dict]:
    """Recent commits on the checked-out branch, newest first.

    %cI rather than %cd: it carries the committer's own UTC offset, so a reader
    that has to place this next to timestamps from other systems can convert
    instead of guessing which clock it speaks. Fields are separated by the unit
    separator, not a pipe or a space — a commit subject may contain either, and
    splitting on one silently truncates the message it appears in.
    """
    if not (_dir(pid, rgid, env) / ".git").is_dir():
        return []
    args = ["log", f"-{max(1, min(int(limit or 60), 500))}",
            "--pretty=format:%H%x1f%cI%x1f%an%x1f%s"]
    if since:
        args.append(f"--since={since}")
    out = []
    for line in _run(pid, rgid, *args, env=env).splitlines():
        parts = line.split("\x1f")
        if len(parts) != 4:            # git's own stderr shares this stream
            continue
        sha, when, who, subject = parts
        out.append({"sha": sha[:12], "at": when.strip(),
                    "who": who.strip(), "subject": subject.strip()})
    return out


def dirty_paths(pid: str, rgid: str, env: str = "") -> set:
    """Repository-relative paths with uncommitted changes.

    The path is taken as whatever follows the status code rather than by a fixed
    offset: the code column is two characters plus a space, but the leading
    space of an unstaged change is lost as soon as the output is stripped, and
    slicing a fixed number of characters then eats the first letter of the path.
    """
    out = set()
    for line in _run(pid, rgid, "status", "--porcelain", env=env).splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        path = (parts[1] if len(parts) > 1 else parts[0]).strip()
        if "->" in path:                      # a rename: the new name is ours
            path = path.split("->")[-1].strip()
        out.add(path.strip('"'))
    return out


def diff_file(pid: str, rgid: str, rel: str, env: str = "") -> str:
    return _run(pid, rgid, "diff", "--", rel, env=env)


def discard_file(pid: str, rgid: str, rel: str, env: str = "") -> str:
    return _run(pid, rgid, "checkout", "--", rel, env=env)
