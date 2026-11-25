"""Connect to an environment's GitOps repo over HTTPS or SSH: clone, refresh,
commit, push.

Every operation takes its settings from the ENVIRONMENT's binding
(`env_repo`) — url, branch, credentials — and its working copy from
`repo.checkout`, shared per (repository, branch). Credentials are never
written into the clone's git config — HTTPS creds are injected into a single
command's URL, SSH uses GIT_SSH_COMMAND with a key file stored 0600 under
data/secrets/.
"""
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

from . import secretbox, store
from .env import GIT, TOOL_PATH

VALUES_GLOB = "*-values*.yaml"
# PATH comes from the process, not from a list written here: a hardcoded
# macOS-flavoured PATH cannot find git inside a container, and an image is free
# to put it anywhere. GIT_TERMINAL_PROMPT stays 0 so a bad credential fails
# instead of hanging on a prompt nobody can answer.
GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "PATH": TOOL_PATH,
}


class GitError(Exception):
    pass


def redact(text: str) -> str:
    return re.sub(r"://[^@\s]+@", "://***@", text)


def _https_url(url: str, username: str, secret: str) -> str:
    if not secret:
        return url
    p = urlparse(url)
    # No host to put a credential in front of — a local mirror path, or an scp
    # style address. Splicing one in anyway produces a URL git cannot use, and
    # the failure blames the repository rather than the rewrite.
    if not p.scheme or not p.hostname:
        return url
    netloc = f"{quote(username or 'x-token-auth', safe='')}:{quote(secret, safe='')}@{p.hostname}"
    if p.port:
        netloc += f":{p.port}"
    return urlunparse(p._replace(netloc=netloc))


def _env_for(pid: str, rgid: str, repo: dict) -> tuple[dict, str]:
    """Return (env, effective_url) for git commands.

    `repo["secret"]` arrives SEALED (region and environment credentials are
    both stored that way) and is unsealed here, at the one place it is actually
    handed to git — never earlier, never logged, never returned. `repo` may
    carry `_ssh_key_path`: an environment with its own key sets it so this uses
    THAT file rather than the region's; every other caller omits it and gets
    the region's path, unchanged.
    """
    env = dict(GIT_ENV)
    url = repo.get("url", "").strip()
    if repo.get("protocol") == "ssh":
        key = repo.get("_ssh_key_path") or store.ssh_key_path(pid, rgid)
        opts = ["-o StrictHostKeyChecking=accept-new", "-o BatchMode=yes"]
        if key.exists():
            opts.append(f"-i {key}")
        env["GIT_SSH_COMMAND"] = "ssh " + " ".join(opts)
        return env, url
    secret = secretbox.unseal(repo.get("secret", "") or "")
    return env, _https_url(url, repo.get("username", ""), secret)


def _run(args: list[str], env: dict, cwd: Path | None = None,
         timeout: int = 240) -> str:
    r = subprocess.run(args, cwd=str(cwd) if cwd else None, env=env,
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise GitError(redact((r.stderr or r.stdout).strip())[:400])
    return r.stdout


def clone_or_pull(pid: str, rgid: str, repo: dict, force: bool = False,
                  dest: Path | None = None) -> str:
    """Bring a working copy to the remote's state.

    `dest` overrides where — an environment bound to its own repository or
    branch has its own checkout, and it wants exactly this behaviour: the same
    dirty guard, the same shallow clone, the same scrub of the credential out of
    `origin` afterwards. Duplicating that for bindings is how one of the two
    copies ends up leaving a token in `.git/config`.
    """
    dest = dest or store.repo_dir(pid, rgid)
    env, url = _env_for(pid, rgid, repo)
    branch = repo.get("branch", "").strip()

    if (dest / ".git").is_dir():
        dirty = _run([GIT, "status", "--porcelain"], env, cwd=dest).strip()
        if dirty and not force:
            raise GitError(
                "there are uncommitted changes in this region — commit or discard "
                "them first, or use 'Sync (discard local)' to overwrite them:\n"
                + dirty[:300])
        _run([GIT, "remote", "set-url", "origin", url], env, cwd=dest)
        try:
            _run([GIT, "fetch", "--prune", "origin"], env, cwd=dest)
            head = branch or _run([GIT, "rev-parse", "--abbrev-ref", "HEAD"],
                                  env, cwd=dest).strip()
            _run([GIT, "reset", "--hard", f"origin/{head}"], env, cwd=dest)
        finally:
            _run([GIT, "remote", "set-url", "origin", repo["url"]], env, cwd=dest)
        invalidate_remote(pid, rgid)
        return "updated"

    if dest.is_dir() and any(dest.iterdir()):
        # a tree with files but no .git — hand-planted demo values, or a moved
        # checkout whose .git never existed. Cloning over it fails anyway, and
        # the old delete-on-failure below would then ERASE those files: a
        # failed clone of an unreachable remote destroyed a working copy once.
        raise GitError("the checkout directory already has files but is not a "
                       "git repository — move it aside before syncing")
    dest.parent.mkdir(parents=True, exist_ok=True)
    created = not dest.exists()
    args = [GIT, "clone", "--depth", "50"]
    if branch:
        args += ["--branch", branch]
    args += [url, str(dest)]
    try:
        _run(args, env)
    except Exception:
        # remove only what THIS clone created — never a directory that was
        # already there, whatever it held
        if created:
            shutil.rmtree(dest, ignore_errors=True)
        raise
    _run([GIT, "remote", "set-url", "origin", repo["url"]], env, cwd=dest)
    return "cloned"


def env_repo(pid: str, rgid: str, env: str) -> dict:
    """The repository settings for ONE environment — its own binding, whole.

    Nothing is merged in from anywhere else: the binding carries the url, the
    branch and the credentials, because `store.set_env_source` writes shared
    credentials INTO each environment (sibling copy on declare, propagation on
    rotation) rather than leaving them somewhere a form cannot show. `secret`
    travels SEALED; `_env_for` is the only reader that unseals it.
    """
    from . import repo as repomod
    b = repomod.binding(pid, rgid, env)          # runs the absorb migration
    dec = store.env_sources(pid, rgid).get(env) or {}
    # `b["url"]` has had any inline userinfo stripped for display; recover it
    # here so a row written before the split can still authenticate. The
    # recovered password is plaintext, so it is sealed to match what every
    # other path stores — `_env_for` unseals whatever it is given.
    _, inline_user, inline_pw = store.split_credentials(dec.get("url") or "")
    secret = dec.get("secret") or (secretbox.seal(inline_pw) if inline_pw else "")
    out = {"url": b["url"], "branch": b["branch"],
           "protocol": dec.get("protocol") or "https",
           "username": dec.get("username") or inline_user,
           "secret": secret}
    key = store.ssh_key_path(pid, rgid, env)
    if key.exists():
        out["_ssh_key_path"] = key
    return out


def fetch_needed(pid: str, rgid: str, env: str, typed_url: str = "",
                 typed_branch: str = "") -> bool:
    """Should declaring (or re-saving) this environment fetch, right now?

    ONE definition, because the cluster form and the MCP verb both have to
    answer it and a rule that drifted between them would be a bug in whichever
    was used less. The rule: fetch when the binding names a repository and its
    checkout does not exist yet. Two consequences worth spelling out:

    - a checkout that already has a `.git` is NEVER re-fetched here — the
      cluster form now submits the binding's stored values on every save (they
      prefill), and cloning on every unrelated save would put a network round
      trip inside "rename the cluster". The per-row ↻ does refreshes.
    - a binding with no repository fetches nothing, which also keeps
      `clone_or_pull`'s delete-on-failed-clone away from the region's legacy
      directory — the one place hand-planted demo files live.

    The typed_* parameters are accepted for callers that pass them, but the
    stored binding decides — what was typed is already in it by the time this
    is asked.
    """
    from . import repo as repomod
    b = repomod.binding(pid, rgid, env)
    if not b["url"]:
        return False
    d = repomod.checkout(pid, rgid, env)
    # anything already there counts — a real clone (has .git) or a plain tree
    # of values files (a migrated demo, hand-planted). Fetching over the
    # latter cannot succeed and used to destroy it; reading it works fine.
    return not (d.is_dir() and any(d.iterdir()))


def sync_env(pid: str, rgid: str, env: str, force: bool = False) -> str:
    """Clone or update the checkout ONE environment reads from."""
    from . import repo as repomod
    b = repomod.binding(pid, rgid, env)
    if not b["url"]:
        raise GitError("no repository is set for this environment or its region")
    return clone_or_pull(pid, rgid, env_repo(pid, rgid, env), force=force,
                         dest=repomod.checkout(pid, rgid, env))


def commit_and_push(pid: str, rgid: str, repo: dict, paths: list[str],
                    message: str, new_branch: str = "",
                    author: str = "Config Portal <config-portal@localhost>",
                    env_name: str = "") -> dict:
    """Stage the given paths, commit, and push. Returns {branch, sha, pushed}.

    `env_name` picks the working copy: an environment's checkout is its own
    (shared per repository+branch), so a commit for env X must land in X's
    clone — the region directory is only the legacy fallback for environments
    with no repository. `repo` should be `env_repo(pid, rgid, env_name)` so the
    push authenticates as that environment does.
    """
    from . import repo as repomod
    dest = repomod.checkout(pid, rgid, env_name)
    if not (dest / ".git").is_dir():
        raise GitError("repository is not cloned")
    if not paths:
        raise GitError("nothing to commit")
    if not message.strip():
        raise GitError("a commit message is required")

    env, url = _env_for(pid, rgid, repo)
    current = _run([GIT, "rev-parse", "--abbrev-ref", "HEAD"], env, cwd=dest).strip()
    branch = new_branch.strip() or current

    if new_branch.strip():
        _run([GIT, "checkout", "-B", branch], env, cwd=dest)

    _run([GIT, "add", "--"] + paths, env, cwd=dest)
    staged = _run([GIT, "diff", "--cached", "--name-only"], env, cwd=dest).strip()
    if not staged:
        # Nothing new to commit. Either it was already committed and pushed
        # (a double submit), or it is committed locally but not yet pushed.
        env2, url2 = _env_for(pid, rgid, repo)
        try:
            remote = _run([GIT, "ls-remote", url2, f"refs/heads/{branch}"],
                          env2, timeout=60).split()
        except GitError:
            remote = []
        local = _run([GIT, "rev-parse", "HEAD"], env, cwd=dest).strip()
        short = local[:7]
        if remote and remote[0] == local:
            return {"branch": branch, "sha": short, "pushed": False,
                    "remote_sha": short, "noop": True,
                    "files": [], "note": "already committed and pushed"}
        raise GitError("nothing new to commit — this change is already committed. "
                       "If it has not reached the remote, use Sync on the region.")

    _run([GIT, "-c", f"user.name={author.split('<')[0].strip()}",
          "-c", f"user.email={author.split('<')[1].rstrip('>')}",
          "commit", "-m", message], env, cwd=dest)
    sha = _run([GIT, "rev-parse", "--short", "HEAD"], env, cwd=dest).strip()

    _run([GIT, "remote", "set-url", "origin", url], env, cwd=dest)
    try:
        _run([GIT, "push", "-u", "origin", branch], env, cwd=dest, timeout=180)
        # don't trust the exit code alone — confirm the remote really moved.
        # A protected branch or a server-side hook can leave the local ref ahead.
        remote = _run([GIT, "ls-remote", url, f"refs/heads/{branch}"],
                      env, timeout=60).split()
        remote_sha = remote[0] if remote else ""
    finally:
        _run([GIT, "remote", "set-url", "origin", repo["url"]], env, cwd=dest)

    full = _run([GIT, "rev-parse", "HEAD"], env, cwd=dest).strip()
    if not remote_sha:
        raise GitError(f"push reported success but branch '{branch}' is not on the "
                       f"remote — commit {sha} is only local")
    if remote_sha != full:
        raise GitError(
            f"push did not land: remote '{branch}' is at {remote_sha[:7]}, not {sha}. "
            f"The branch is likely protected — push to a new branch and open a pull "
            f"request instead. Your commit is safe locally.")
    return {"branch": branch, "sha": sha, "pushed": True,
            "remote_sha": remote_sha[:7], "files": staged.splitlines()}


_remote_cache: dict[str, tuple[float, str]] = {}
REMOTE_TTL = 45.0  # seconds


def remote_head(pid: str, rgid: str, repo: dict, branch: str,
                force: bool = False) -> str:
    """Remote sha for a branch, cached briefly so page loads stay fast."""
    import time
    key = f"{pid}/{rgid}/{branch}"
    hit = _remote_cache.get(key)
    now = time.monotonic()
    if hit and not force and now - hit[0] < REMOTE_TTL:
        return hit[1]
    if not repo.get("url"):
        return ""
    try:
        env, url = _env_for(pid, rgid, repo)
        out = _run([GIT, "ls-remote", url, f"refs/heads/{branch}"],
                   env, timeout=25).split()
        sha = out[0] if out else ""
    except Exception:
        sha = hit[1] if hit else ""
    _remote_cache[key] = (now, sha)
    return sha


def invalidate_remote(pid: str, rgid: str) -> None:
    for k in [k for k in _remote_cache if k.startswith(f"{pid}/{rgid}/")]:
        _remote_cache.pop(k, None)


def head_info(pid: str, rgid: str, env_name: str = "") -> dict:
    from . import repo as repomod
    d = repomod.checkout(pid, rgid, env_name)
    if not (d / ".git").is_dir():
        return {"branch": "-", "head": "not cloned", "dirty": "", "cloned": False,
                "sha": "", "subject": "", "author": "", "when": ""}
    def g(*a):
        r = subprocess.run([GIT, "-C", str(d), *a], capture_output=True,
                           text=True, timeout=30)
        return (r.stdout or r.stderr).strip()
    branch = g("rev-parse", "--abbrev-ref", "HEAD")
    dirty = g("status", "--porcelain")
    # one call for every commit field (US separator \x1f can't appear in them):
    # short sha, subject, author name, relative age ("3 days ago")
    parts = g("log", "-1", "--format=%h%x1f%s%x1f%an%x1f%cr").split("\x1f")
    sha, subject, author, when = (parts + ["", "", "", ""])[:4]
    return {"branch": branch, "dirty": dirty, "cloned": True,
            # `head` (sha + subject) kept for callers that show the one-liner
            "head": (sha + " " + subject).strip() or "no commits yet",
            "sha": sha, "subject": subject, "author": author, "when": when}


def web_url(git_url: str) -> str:
    """Browser URL for a repo, from an https or ssh remote (no credentials).
    Returns "" for anything that would not open in a browser, so callers can
    render the link only when it is real."""
    u = (git_url or "").strip()
    if u.startswith("git@"):                       # git@host:org/repo.git
        host, _, path = u[4:].partition(":")
        u = f"https://{host}/{path}"
    elif u.startswith("ssh://"):                   # ssh://git@host[:port]/org/repo.git
        p = urlparse(u)
        if not p.hostname:
            return ""
        host = f"{p.hostname}:{p.port}" if p.port else p.hostname
        u = f"https://{host}{p.path}"
    if not u.startswith(("http://", "https://")):
        return ""
    u = re.sub(r"^(https?://)[^@/]+@", r"\1", u)   # drop user[:token]@
    return re.sub(r"\.git/?$", "", u)


def commit_url(git_url: str, sha: str) -> str:
    base = web_url(git_url)
    if not base or not sha:
        return ""
    seg = "commit" if "github.com" in base else "commits"
    return f"{base}/{seg}/{sha}"


def default_name(url: str) -> str:
    return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1]) or "repo"
