"""Everything the deployment can decide, read from the environment in one place.

WHY ONE MODULE
    The portal is meant to be installed by a Helm chart into somebody else's
    cluster. That means every value which depends on *where* it runs — the data
    directory, whether it may bind a shared interface, where kubectl and git
    live, how long a session lasts — has to come from outside the code. Reading
    them here rather than at each use site means the chart's values.yaml and this
    file are a single, checkable contract.

WHAT DOES NOT BELONG HERE
    Anything describing the deployment's *content* — projects, regions, clusters,
    connections, credentials. Those are configured in the running portal and
    stored in its database, because they change while it is running and a chart
    upgrade should never rewrite them.

RULES
    * every setting has a default that works for a laptop
    * nothing here names an organisation, a cluster or a host
    * a path is a path, not a guess: PORTAL_DATA_DIR is where state lives, and a
      container mounts a volume there
"""
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent


def _version() -> str:
    """The release this build is. One file, so the image tag, the chart's
    appVersion and what the UI shows can never disagree."""
    for candidate in (BASE / "VERSION", Path("/app/VERSION")):
        try:
            return candidate.read_text().strip()
        except OSError:
            continue
    return "0.0.0-dev"


VERSION = _version()


def text(name: str, default: str = "") -> str:
    return (os.environ.get(name) or "").strip() or default


def flag(name: str, default: bool = False) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def number(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


# ── where state lives ──────────────────────────────────────────
# One directory holds the database, the git working copies and the secret files.
# A chart mounts a PersistentVolume here; a laptop leaves it next to the code.
DATA_DIR = Path(text("PORTAL_DATA_DIR", str(BASE / "data")))

# ── how it is served ───────────────────────────────────────────
HOST = text("PORTAL_HOST")
PORT = int(number("PORTAL_PORT", 8471))
# The portal holds git tokens, kubeconfigs and sealing keys, so binding anything
# but loopback is a deliberate act. In a cluster it is a Service behind an
# authenticating ingress, and the chart sets this.
ALLOW_NETWORK = flag("PORTAL_ALLOW_NETWORK")
# Served under a path prefix by an ingress? Set it, or leave it alone.
ROOT_PATH = text("PORTAL_ROOT_PATH")
# Behind TLS the session cookie should refuse to travel in clear.
COOKIE_SECURE = flag("PORTAL_COOKIE_SECURE")
SESSION_HOURS = number("PORTAL_SESSION_HOURS", 8)

# ── the tools it shells out to ─────────────────────────────────
# Named, not assumed: an image may ship them anywhere, and a distribution may
# want a wrapper. PATH is inherited from the process rather than invented, which
# is what was wrong before — a hardcoded macOS PATH cannot find git in a
# container.
KUBECTL = text("PORTAL_KUBECTL", "kubectl")
KUBESEAL = text("PORTAL_KUBESEAL", "kubeseal")
GIT = text("PORTAL_GIT", "git")
SSH = text("PORTAL_SSH", "ssh")
SFTP = text("PORTAL_SFTP", "sftp")
# ansible-playbook and its inventory reader. Optional: an install that never
# opens the Ansible page needs neither, and the page says so rather than every
# run failing with "not found".
ANSIBLE = text("PORTAL_ANSIBLE", "ansible-playbook")
ANSIBLE_INVENTORY = text("PORTAL_ANSIBLE_INVENTORY", "ansible-inventory")
# terraform (or an OpenTofu binary in its place). Optional, same as ansible: an
# install that never opens the Terraform page needs neither.
TERRAFORM = text("PORTAL_TERRAFORM", "terraform")
# Passkeys derive the site's identity from the request, which is right
# everywhere except behind a proxy that does not forward the real host. These
# exist for that install and have no UI on purpose — a feature whose appeal is
# "nothing to set up" must not ship a settings page.
PASSKEY_RPID = text("PORTAL_PASSKEY_RPID", "")
PASSKEY_ORIGIN = text("PORTAL_PASSKEY_ORIGIN", "")
TOOL_PATH = text("PORTAL_TOOL_PATH", os.environ.get("PATH", "/usr/bin:/bin"))

# Where the cluster page fetches metrics-server from when a cluster has no
# metrics API. `latest`, which is what upstream's own install instructions say:
# a version pinned in here ages into the wrong answer, and the version that
# actually landed is read back out of the manifest and named in the audit line
# rather than being assumed. An install with no route to github points this at
# its own mirror; the manifest is checked either way before anything is applied.
METRICS_URL = text("PORTAL_METRICS_URL",
                   "https://github.com/kubernetes-sigs/metrics-server/releases/"
                   "latest/download/components.yaml")

# ── updating this installation from its own page ───────────────
# Off unless the chart turned it on. When it is on, the chart also names the
# Deployment and container the pod belongs to, because a pod discovering that for
# itself means chasing ReplicaSet owner references — and the chart already knows.
SELF_UPDATE = flag("PORTAL_SELF_UPDATE")
SELF_DEPLOYMENT = text("PORTAL_SELF_DEPLOYMENT")
SELF_CONTAINER = text("PORTAL_SELF_CONTAINER", "portal")
SELF_NAMESPACE = text("PORTAL_SELF_NAMESPACE")

# ── looking up DNS, for certificate validation ─────────────────
# Comma-separated resolver addresses. Empty means /etc/resolv.conf first and then
# well-known public resolvers, which is right nearly everywhere: the certificate
# page needs to see a TXT record the way the internet sees it, and a cluster's own
# resolver frequently cannot. A site whose egress on port 53 goes to one appliance
# names it here instead.
DNS_RESOLVERS = text("PORTAL_DNS_RESOLVERS")

# ── the assistant's model ──────────────────────────────────────
# The chart ships an Ollama alongside the portal, so the deployment can point the
# assistant at it without anyone typing anything. These are *defaults*: whatever
# an administrator saves in Settings wins, so a deployment that later moves to a
# hosted model does not need a chart change, and a chart upgrade never overwrites
# a deliberate choice.
ASSISTANT_PROVIDER = text("PORTAL_ASSISTANT_PROVIDER")
ASSISTANT_URL = text("PORTAL_ASSISTANT_URL")
ASSISTANT_MODEL = text("PORTAL_ASSISTANT_MODEL")
ASSISTANT_ENABLED = flag("PORTAL_ASSISTANT_ENABLED")

# The key that encrypts stored credentials. Set it and the key lives in a
# Kubernetes Secret while the database lives on a volume, so a leaked volume is
# not a leaked credential. Leave it and a key file is generated beside the
# database, which still protects every copy of portal.db taken on its own.
SECRET_KEY = text("PORTAL_SECRET_KEY")


# The address this portal is reached at, e.g. https://portal.acme.com. Used to
# build the links that go into invitation and password-reset emails.
#
# It has to be configured rather than taken from the request: request.base_url
# is the Host header, and /forgot is unauthenticated — so anybody could post a
# reset request with a forged Host and the link mailed to the victim would
# point at their server. Set this and the header cannot influence it.
BASE_URL = text("PORTAL_BASE_URL")


# Where to look for a newer release. Unset means no check and no network call —
# the same bargain the update check keeps. See updates.py.
UPDATE_URL = text("PORTAL_UPDATE_URL")


# ── branding ───────────────────────────────────────────────────
# Read by store.brand(), which also lets the running portal override them.
BRAND_NAME = text("PORTAL_BRAND_NAME")
BRAND_ORG = text("PORTAL_BRAND_ORG")
BRAND_SHORT = text("PORTAL_BRAND_SHORT")


def summary() -> list:
    """Every setting and where its value came from, for the settings page.

    Shown rather than hidden: "why is it behaving like that" should be answerable
    without reading the chart.
    """
    rows = [
        ("(version)", VERSION, "the release this build is"),
        ("PORTAL_DATA_DIR", str(DATA_DIR), "database, git clones and secrets"),
        ("PORTAL_HOST", HOST or "(loopback)", "interface to bind"),
        ("PORTAL_PORT", str(PORT), "port to listen on"),
        ("PORTAL_ALLOW_NETWORK", "yes" if ALLOW_NETWORK else "no",
         "permit a non-loopback bind"),
        ("PORTAL_ROOT_PATH", ROOT_PATH or "(none)", "path prefix behind an ingress"),
        ("PORTAL_COOKIE_SECURE", "yes" if COOKIE_SECURE else "no",
         "session cookie requires HTTPS"),
        ("PORTAL_SESSION_HOURS", f"{SESSION_HOURS:g}", "session lifetime"),
        ("PORTAL_KUBECTL", KUBECTL, "kubectl binary"),
        ("PORTAL_KUBESEAL", KUBESEAL, "kubeseal binary"),
        ("PORTAL_GIT", GIT, "git binary"),
        ("PORTAL_SSH", SSH, "ssh binary, for ssh:// git remotes"),
        ("PORTAL_SFTP", SFTP, "sftp binary, for session file transfer"),
        ("PORTAL_ANSIBLE", ANSIBLE, "ansible-playbook binary"),
        ("PORTAL_TERRAFORM", TERRAFORM, "terraform (or tofu) binary"),
        ("PORTAL_ANSIBLE_INVENTORY", ANSIBLE_INVENTORY,
         "ansible-inventory binary, for checking an inventory"),
        ("PORTAL_TOOL_PATH", TOOL_PATH, "PATH given to git and kubectl"),
        ("PORTAL_METRICS_URL", METRICS_URL,
         "the metrics-server manifest the cluster page offers to install"),
        ("PORTAL_DNS_RESOLVERS", DNS_RESOLVERS or "(resolv.conf, then public)",
         "who to ask when checking a certificate's TXT record"),
        ("PORTAL_SELF_UPDATE", "yes" if SELF_UPDATE else "no",
         "may this installation update itself from its own page"),
        ("PORTAL_SELF_DEPLOYMENT", SELF_DEPLOYMENT or "(unset)",
         "the deployment it would patch — set by the chart"),
        ("PORTAL_SELF_CONTAINER", SELF_CONTAINER,
         "the container inside it whose image would move"),
        ("PORTAL_SELF_NAMESPACE", SELF_NAMESPACE or "(read from the pod)",
         "the namespace it runs in"),
        ("PORTAL_ASSISTANT_PROVIDER", ASSISTANT_PROVIDER or "(unset)",
         "default assistant provider"),
        ("PORTAL_ASSISTANT_URL", ASSISTANT_URL or "(unset)",
         "default assistant endpoint"),
        ("PORTAL_ASSISTANT_MODEL", ASSISTANT_MODEL or "(unset)",
         "default assistant model"),
        ("PORTAL_ASSISTANT_ENABLED", "yes" if ASSISTANT_ENABLED else "no",
         "assistant on by default"),
        ("PORTAL_SECRET_KEY", "set" if SECRET_KEY else "(a key file beside "
         "the database)", "encrypts stored credentials"),
        ("PORTAL_BASE_URL", BASE_URL or "(unset)",
         "public address, used for the links inside emails"),
        ("PORTAL_UPDATE_URL", UPDATE_URL or "(unset)",
         "where to look for a newer release — unset means no check at all"),
        ("PORTAL_BRAND_NAME", BRAND_NAME or "(unset)", "name shown in the UI"),
        ("PORTAL_BRAND_ORG", BRAND_ORG or "(unset)", "subtitle under the name"),
        ("PORTAL_BRAND_SHORT", BRAND_SHORT or "(unset)",
         "issuer shown in authenticator apps"),
    ]
    return [{"key": k, "value": v, "note": n,
             "set": bool(os.environ.get(k))} for k, v, n in rows]
