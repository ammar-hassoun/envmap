"""The external binaries the portal needs, checked once at startup.

WHY THIS EXISTS
    The portal shells out to kubectl, kubeseal and git. When one is missing the
    symptom appears far from the cause: a cluster reads as "unreachable", a
    repository "cannot be cloned", sealing "failed". That is a miserable way to
    learn that an image was built without git in it.

    So each one is run once at startup and the result is remembered: what was
    found, at which path, and which version. The Deployment settings page shows
    it, and a missing *required* tool is fatal — a portal that cannot read a
    cluster or a repository has nothing to show, and failing at startup with a
    clear message is kinder than failing per-page forever.

REQUIRED VERSUS OPTIONAL
    kubectl and git are required: without them the two things this portal is for
    do not work. kubeseal is optional — it is only needed to seal a secret, so a
    deployment that never does that should not be blocked, but the page says the
    feature is unavailable rather than letting it fail when someone tries.
"""
import re
import subprocess

from . import env

TOOLS = (
    # binary, what it is for, required, how to get its version
    ("kubectl", env.KUBECTL, "reading and managing clusters", True,
     ["version", "--client=true", "-o", "yaml"]),
    ("git", env.GIT, "cloning and committing GitOps repositories", True,
     ["--version"]),
    ("kubeseal", env.KUBESEAL, "sealing secrets for SealedSecrets", False,
     ["--version"]),
    # git shells out to this for an ssh:// or git@ remote. Listed here so a
    # build without it says so at startup and on the deployment page, instead
    # of every ssh repository failing with "Could not read from remote
    # repository" — which reads like a rejected deploy key and sends you to
    # check the key, the known_hosts and the repository permissions before it
    # occurs to you that the binary is simply absent. Not required: an install
    # that only uses https remotes has no need of it.
    ("ssh", env.SSH, "ssh:// and git@ repository remotes", False,
     ["-V"]),
)

_state: list = []


def _version_of(text: str) -> str:
    """A version out of whatever the tool printed.

    Each of these says it differently — `gitVersion: v1.34.1` in kubectl's yaml,
    `git version 2.51.1`, `kubeseal version: 0.27.1` — so look for the number,
    preferring a full three-part version over a partial match.

    ssh is the awkward one: it prints "OpenSSH_10.2p1, LibreSSL 3.3.6" to
    stderr, and the generic search below picks 3.3.6 — the TLS library, not the
    program — because 10.2p1 is not three-part. Its own token is tried first.
    """
    text = (text or "").strip()
    for pattern in (r"OpenSSH_(\d+\.\d+[\w.]*)",
                    r"v?(\d+\.\d+\.\d+[\w.+-]*)", r"v?(\d+\.\d+)"):
        m = re.search(pattern, text)
        if m:
            return m.group(1)
    return (text.splitlines() or [""])[0][:60]


def check(force: bool = False) -> list:
    """Run each tool once. The result is cached for the life of the process."""
    global _state
    if _state and not force:
        return _state
    out = []
    for name, binary, purpose, required, args in TOOLS:
        row = {"name": name, "binary": binary, "purpose": purpose,
               "required": required, "found": False, "version": "", "error": ""}
        try:
            r = subprocess.run([binary, *args], capture_output=True, text=True,
                               timeout=20,
                               env={"PATH": env.TOOL_PATH, "HOME": "/tmp"})
            if r.returncode == 0 or r.stdout:
                row["found"] = True
                row["version"] = _version_of(r.stdout or r.stderr)
            else:
                row["error"] = (r.stderr or r.stdout).strip()[:200]
        except FileNotFoundError:
            row["error"] = f"not found on PATH ({env.TOOL_PATH})"
        except Exception as e:                                # noqa: BLE001
            row["error"] = f"{type(e).__name__}: {e}"
        out.append(row)
    _state = out
    return out


def missing_required() -> list:
    return [t for t in check() if t["required"] and not t["found"]]


def verify_or_die() -> None:
    """Refuse to start when a required tool is absent, saying which and how.

    Called from the app's startup. The message names the binary, the variable
    that points at it, and the PATH that was searched, because those three
    together are the whole answer.
    """
    bad = missing_required()
    if not bad:
        return
    lines = [f"  {t['name']} — {t['purpose']}: {t['error']}" for t in bad]
    raise RuntimeError(
        "the portal cannot start because a required tool is missing:\n"
        + "\n".join(lines)
        + f"\n\nPATH searched: {env.TOOL_PATH}"
        + "\nOverride the binary with PORTAL_KUBECTL / PORTAL_GIT / "
          "PORTAL_KUBESEAL, or the search path with PORTAL_TOOL_PATH."
          "\nIf you are running the container image, this means it was built "
          "without them — rebuild from the project's Dockerfile.")
