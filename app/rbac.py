"""Roles: what a person may see, and which clusters and projects they may see it in.

THE MODEL, IN THREE SENTENCES
    An **area** is a page group — logs, monitoring, clouds, hypervisors. A
    **role** grants a set of areas, and optionally narrows them to particular
    projects and particular clusters. A **user** holds any number of roles, and
    what they may do is the union of them.

WHY UNION AND NOT INTERSECTION
    Because roles are handed out additively ("give her the Kenya on-call role
    too"), and an intersection would make each extra role *reduce* access, which
    nobody expects. So an empty scope means "everything in this area": a role
    listing no projects is fleet-wide, and one listing two projects is confined
    to them. That way the simple case — "read-only on everything" — needs no
    lists at all.

ADMIN IS NOT A ROLE HERE
    A user with role == "admin" (the account field, which predates this module)
    bypasses every check. That is deliberate: the portal must never be able to
    lock its own administrators out of the page where roles are fixed. Everyone
    else is governed by their roles, and a user with no roles can see the
    Overview and their own account, nothing more.

ENFORCEMENT IS IN ONE PLACE
    The middleware maps the request path to an area and asks may_area(); the
    cluster and project pages additionally ask may_cluster()/may_project() for
    the specific thing being opened. Hiding a link is presentation — the check
    is what actually stops the request, and the two read the same functions, so
    a hidden page is also a forbidden one.
"""
import contextlib
import contextvars
import json

from . import db

# ── the areas a role can grant ─────────────────────────────────
# key: (label, note, the URL prefixes it governs)
# The prefixes are how the middleware decides, so adding an area to this table
# is what makes a new page governable — there is no second list to update.
AREAS = {
    # "/" matches only itself, so the panel-layout endpoint needs naming: it
    # writes what the landing page shows and was governed by nothing.
    "overview": ("Overview", "the fleet landing page and its panels",
                 ("/", "/overview/")),
    "clusters": ("Clusters", "cluster drill-down, nodes, pods, events, storage",
                 ("/clusters", "/nodes", "/pods")),
    "config": ("Configuration", "values files, editing, comparing, committing",
               ("/p/", "/compare", "/repos", "/search")),
    "pipelines": ("Pipelines", "CI builds and their history", ("/pipelines",)),
    # The page itself is a join, so this area only opens the door: every source
    # on it is gated a second time by the area that governs its own page, and a
    # role holding this and nothing else sees an empty timeline that says so.
    "timeline": ("Timeline", "what changed recently, merged from the systems "
                 "this role can already see", ("/timeline",)),
    # Same shape as the timeline: this only opens the door. Every source on the
    # radar is gated again by the area that owns it, so a role holding this and
    # nothing else sees an empty page that says so.
    "expiry": ("Expiry radar", "certificates, warranties, subscriptions and "
               "licences, counted down in one place", ("/expiry",)),
    "security": ("Security", "scan findings and the cluster audit", ("/security",)),
    "logs": ("Logs", "log search across the connected stores", ("/logs",)),
    "monitoring": ("Monitoring", "alerts and dashboards", ("/monitoring",)),
    "assets": ("Server assets", "the hardware and VM inventory", ("/assets",)),
    "spend": ("IT spend", "the subscription register, renewals and what IT "
              "costs — money, so it is its own area rather than part of assets",
              ("/spend",)),
    "clouds": ("Cloud accounts", "cloud inventory and diagrams", ("/clouds",)),
    "storage": ("Storage devices", "backup target health", ("/storage",)),
    "gitops": ("GitOps", "Argo CD and Flux applications", ("/gitops",)),
    "edge": ("Edge & DNS", "zones, DNS records, certificates and cache state",
             ("/edge",)),
    # Its own area rather than part of edge: this one holds private keys and can
    # download them, which is a different thing to grant than "may read the CDN's
    # configuration".
    "certs": ("TLS certificates", "requesting and renewing certificates from "
              "Let's Encrypt, and downloading the keys they belong to",
              ("/certs",)),
    "workflows": ("Workflow engines", "Temporal and Airflow", ("/workflows",)),
    "bmc": ("Server hardware", "iDRAC, iLO and other BMCs", ("/bmc",)),
    "virt": ("Hypervisors", "Proxmox, ESXi and vCenter", ("/virt",)),
    "vpn": ("VPN portals", "which tunnels are up and who is connected",
            ("/vpn",)),
    "db": ("Databases", "the database console — browsing schemas and running "
           "queries with the operator's own database account. Read-only "
           "unless they switch the session to write mode, which is audited",
           ("/db",)),
    "assistant": ("Assistant", "the AI assistant and what it may read",
                  ("/assistant",)),
    # Connecting an AI client over MCP. Its own area rather than part of
    # "assistant" because it is a different shape of access: a long-lived bearer
    # token, used from outside the browser and outside MFA. It grants nothing on
    # its own — every tool call is filtered by the rest of this person's areas,
    # so an MCP client sees exactly the pages its owner sees — but WHETHER
    # somebody may hold such a token at all is a decision worth making once.
    "mcp": ("MCP access", "connecting an AI client to this portal over MCP — a "
            "token that reads, on their behalf, only what their other areas "
            "already allow", ("/mcp",)),
    "ansible": ("Ansible", "playbooks, the host groups they run against, and "
                "the output of every run — read-only on its own",
                ("/ansible",)),
    "terraform": ("Terraform", "the stacks, their .tf and the output of every "
                  "run — read-only on its own", ("/terraform",)),
    # ── the Administration entries in the sidebar ──────────────────────────
    # Two of the three can be delegated. The third cannot, and it is worth
    # being plain about why: whoever may edit a role definition may add
    # Settings to their own role, so "may edit roles" and "is an administrator"
    # are the same permission wearing different names. Roles therefore stay
    # with administrators and are deliberately absent from this list.
    "users": ("User accounts", "inviting people, issuing reset links and "
              "assigning roles. Cannot create administrators, cannot touch an "
              "administrator's account, and cannot hand out Settings or User "
              "accounts — each of those is a way to become one",
              ("/admin/users",)),
    "audit": ("Audit log", "who did what, and when — read-only",
              ("/admin/audit",)),
    "manage": ("Cluster management", "running kubectl and the fixed actions "
               "— separate from reading, because it changes things",
               ()),
    # Separate from reading, and separate from cluster management, because it is
    # neither: a playbook run is arbitrary code as whatever user the group
    # connects as — root, wherever `become` is on. Granting this is granting a
    # shell on every host in the inventory, so it is named that way in the role
    # editor rather than hiding inside "Ansible".
    "ansible_run": ("Ansible: run playbooks", "starting a run — this is "
                    "arbitrary commands on every host in the group, as the user "
                    "it connects as", ()),
    # Running terraform — init, plan, apply or destroy. Even a plan executes the
    # provider's code with the stack's credential and refreshes real state, and
    # apply/destroy change infrastructure. Same escalating class as running a
    # playbook. Empty prefix — enforced in the handler, not the path middleware.
    "terraform_apply": ("Terraform: apply", "running terraform — init, plan, "
                        "apply or destroy: provider code with the stack's "
                        "credential, and apply/destroy change real "
                        "infrastructure", ()),
    # Privileged Access — the PAM. The catalog of targets and the recordings of
    # every session are read-only on their own; a person can see WHAT can be
    # reached and review WHAT WAS DONE without being able to open a live door.
    "pam": ("Privileged Access", "the target catalogue and every recorded "
            "session — the screen and the commands — read-only on its own",
            ("/pam",)),
    # Opening a live session — SSH, RDP, VNC — as the credential the target
    # brokers, and deleting the recording of one. This is the escalating half:
    # it is an interactive shell or desktop on the target as whatever the vault
    # connects as, the same class of grant as running a playbook. Empty prefix,
    # so it is enforced inside the connect handlers, not by the path middleware.
    "pam_connect": ("Privileged Access: connect", "opening a live session on a "
                    "target and managing its recordings — an interactive shell "
                    "or desktop as the brokered credential", ()),
    # /setup is the new-project wizard. The sidebar always said it belonged to
    # Settings; the route said nothing, and a route governed by no area is
    # checked by nothing — so anybody signed in could create a project by
    # typing the URL the hidden link pointed at.
    "settings": ("Settings", "every connection and configuration page, and "
                 "creating a project — grant with care: settings hold "
                 "credentials",
                 ("/settings", "/setup")),
}

# Reachable by anyone signed in: their own account, signing out, the health
# probe. Never governed, or a user with no roles could not even leave.
ALWAYS = ("/me", "/logout", "/healthz", "/static", "/icons", "/login",
          "/mfa", "/bootstrap", "/favicon.ico", "/assistant/ask")

# Holding any of these is equivalent to holding all of them, because each is a
# route to granting yourself the rest. Somebody managing users who is not an
# administrator may not hand them out.
# ansible_run belongs here for the same reason "manage" does: a playbook can
# read the portal's own filesystem and write anywhere its hosts allow, so
# somebody holding it can reach whatever the portal holds.
ESCALATING = frozenset({"settings", "users", "manage", "ansible_run",
                        "terraform_apply", "pam_connect"})


def escalating(role: dict) -> bool:
    """Whether granting this role would hand over the keys."""
    return bool(ESCALATING & set(role.get("areas") or ()))

SCHEMA = ["""CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    note TEXT,
    areas TEXT,
    projects TEXT,
    clusters TEXT,
    created TEXT)""",
          """CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id))"""]


def _migrate(c) -> None:
    for stmt in SCHEMA:
        c.execute(stmt)
    # `targets` scopes Privileged Access to particular targets, the way
    # `projects`/`clusters` scope their areas. Added after the table shipped, so
    # it arrives as an additive column; an empty list means "every target".
    have = {r["name"] for r in c.execute("PRAGMA table_info(roles)")}
    if "targets" not in have:
        c.execute("ALTER TABLE roles ADD COLUMN targets TEXT DEFAULT '[]'")


db.register(_migrate)


def _row(r) -> dict:
    d = dict(r)
    for key in ("areas", "projects", "clusters", "targets"):
        try:
            d[key] = json.loads(d.get(key) or "[]")
        except json.JSONDecodeError:
            d[key] = []
    return d


# ── roles ──────────────────────────────────────────────────────
def roles() -> list[dict]:
    return [_row(r) for r in db.q("SELECT * FROM roles ORDER BY name")]


def get(rid: str) -> dict | None:
    r = db.one("SELECT * FROM roles WHERE id = ?", (rid,))
    return _row(r) if r else None


def save(rid: str, name: str, note: str, areas, projects, clusters,
         targets=None) -> str:
    """Create or replace a role. Unknown area keys are dropped rather than
    stored — a role is data from a browser like any other."""
    import secrets
    import time
    keep = [a for a in (areas or []) if a in AREAS]
    rid = rid or f"r-{secrets.token_hex(4)}"
    db.run("INSERT INTO roles (id, name, note, areas, projects, clusters, "
           "targets, created) VALUES (?,?,?,?,?,?,?,?) "
           "ON CONFLICT(id) DO UPDATE SET name=excluded.name, note=excluded.note, "
           "areas=excluded.areas, projects=excluded.projects, "
           "clusters=excluded.clusters, targets=excluded.targets",
           (rid, name.strip() or "unnamed role", note.strip(),
            json.dumps(keep), json.dumps(list(projects or [])),
            json.dumps(list(clusters or [])), json.dumps(list(targets or [])),
            time.strftime("%Y-%m-%d %H:%M:%S")))
    return rid


def delete(rid: str) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM roles WHERE id = ?", (rid,))
        c.execute("DELETE FROM user_roles WHERE role_id = ?", (rid,))


# ── assignment ─────────────────────────────────────────────────
def of_user(uid: str) -> list[dict]:
    return [_row(r) for r in db.q(
        "SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id "
        "WHERE ur.user_id = ? ORDER BY r.name", (uid or "",))]


def holders(rid: str) -> list[str]:
    return [r["user_id"] for r in db.q(
        "SELECT user_id FROM user_roles WHERE role_id = ?", (rid,))]


def set_for_user(uid: str, role_ids) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM user_roles WHERE user_id = ?", (uid,))
        for rid in set(role_ids or []):
            if get(rid):
                c.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id) "
                          "VALUES (?, ?)", (uid, rid))


def counts() -> dict:
    """role id -> how many users hold it, for the roles page."""
    return {r["role_id"]: r["n"] for r in db.q(
        "SELECT role_id, COUNT(*) AS n FROM user_roles GROUP BY role_id")}


# ── the questions the app asks ─────────────────────────────────
def is_admin(user: dict | None) -> bool:
    return bool(user and user.get("role") == "admin")


# ── narrowing a credential below its holder ────────────────────
# A person's roles say what they may reach. A CREDENTIAL they issue can be
# narrower than that — an MCP token scoped to "clusters only" is the case this
# exists for — and narrowing has to hold for everything reached during that
# call, not just the first check.
#
# It is applied HERE, at the source, rather than by each caller: `may_area` is
# one line over this function, and the two places that read areas_of directly
# (the timeline and the expiry radar) use it as a CACHE KEY — so a narrowed
# read cannot be served from, or poison, an unnarrowed cache. Plumbing a filter
# through every query instead would have missed exactly those two, which are
# the joins that span the most areas.
#
# It narrows an ADMIN too. The scope is a property of the credential, not of the
# person, so the bypass below must not outrank it.
_narrowed: contextvars.ContextVar[frozenset | None] = contextvars.ContextVar(
    "rbac_narrowed", default=None)


@contextlib.contextmanager
def narrowed(areas):
    """Confine everything inside this block to `areas`. None/empty means "do
    not narrow", so a caller with nothing to say passes its scope straight
    through rather than accidentally granting nothing."""
    token = _narrowed.set(frozenset(areas) if areas else None)
    try:
        yield
    finally:
        _narrowed.reset(token)


def narrowing() -> frozenset | None:
    """What the current call is confined to, if anything."""
    return _narrowed.get()


def areas_of(user: dict | None) -> set:
    """Every area this user may enter. Admins get all of them."""
    got = set(AREAS) if is_admin(user) else set()
    if not got:
        for r in of_user((user or {}).get("id", "")):
            got |= set(r["areas"])
        got.add("overview")  # everyone who can sign in can see the landing page
    if (only := _narrowed.get()) is not None:
        got &= only
    return got


def may_area(user: dict | None, area: str) -> bool:
    return area in areas_of(user)


def _scope(user: dict | None, area: str, field: str) -> set | None:
    """The ids this user is confined to for `field` within `area`, or None for
    "not confined". None is the permissive answer, so a role that names nothing
    grants the whole area — see the module header on why that is the right
    default."""
    if is_admin(user):
        return None
    allowed = None
    for r in of_user((user or {}).get("id", "")):
        if area not in r["areas"]:
            continue
        if not r[field]:
            return None                  # one unrestricted role opens it all
        allowed = (allowed or set()) | set(r[field])
    return allowed


def may_cluster(user: dict | None, cid: str, area: str = "clusters") -> bool:
    if not may_area(user, area):
        return False
    allowed = _scope(user, area, "clusters")
    return allowed is None or cid in allowed


def may_project(user: dict | None, pid: str, area: str = "config") -> bool:
    if not may_area(user, area):
        return False
    allowed = _scope(user, area, "projects")
    return allowed is None or pid in allowed


def visible_clusters(user: dict | None, area: str = "clusters") -> set | None:
    """None means every cluster — callers use it to filter listings."""
    return _scope(user, area, "clusters")


def visible_projects(user: dict | None, area: str = "config") -> set | None:
    return _scope(user, area, "projects")


def may_target(user: dict | None, tid: str, area: str = "pam") -> bool:
    """Whether this person may see (area='pam') or open (area='pam_connect') one
    Privileged-Access target. Scoped by the role's `targets` list — empty means
    every target, so the simple 'all devices' role needs no list."""
    if not may_area(user, area):
        return False
    allowed = _scope(user, area, "targets")
    return allowed is None or tid in allowed


def may_pam_full(user: dict | None) -> bool:
    """Whether this person holds the WHOLE of Privileged Access, unconfined.

    WHY DELETING A RECORDING NEEDS MORE THAN OPENING A SESSION. Every other
    action here is scoped: somebody granted two targets may open those two and
    read their recordings, which is the point of the scoping. Deletion is not
    like that. A recording is the EVIDENCE that a session happened, and the
    person with the strongest reason to remove one is the person who did
    something in it -- so the ability to delete cannot be part of the same
    grant as the ability to do the thing. That is the whole reason an audit
    trail is worth keeping.

    Full means: both halves of the area (seeing the catalogue and opening
    sessions) AND confined to nothing in either. A role restricted to a subset
    of targets is precisely the role that must not be able to clear the record,
    and an unconfined role is the one an install gives to whoever is
    accountable for the trail. Admins qualify by being admins.
    """
    if is_admin(user):
        return True
    if not (may_area(user, "pam") and may_area(user, "pam_connect")):
        return False
    # None from _scope means "not confined" -- see the module header on why
    # that is the permissive answer.
    return (_scope(user, "pam", "targets") is None
            and _scope(user, "pam_connect", "targets") is None)


def visible_targets(user: dict | None, area: str = "pam") -> set | None:
    """The target ids this user is confined to, or None for every target."""
    return _scope(user, area, "targets")


def area_for_path(path: str) -> str | None:
    """Which area governs this URL, or None when nothing does.

    Longest prefix wins, so /clusters/shell/run is governed by "clusters" and a
    future /clusters/something-else is governed by default rather than
    forgotten.
    """
    if path.startswith(ALWAYS):
        return None
    best, best_len = None, -1
    for key, (_label, _note, prefixes) in AREAS.items():
        for p in prefixes:
            if p == "/":
                if path == "/" and best_len < 0:
                    best, best_len = key, 0
                continue
            if path.startswith(p) and len(p) > best_len:
                best, best_len = key, len(p)
    return best


def describe(role: dict, project_names: dict, cluster_names: dict) -> str:
    """One human sentence for a role, used on the users page."""
    n = len(role["areas"])
    bits = [f"{n} area{'s' if n != 1 else ''}"]
    if role["projects"]:
        bits.append("projects: " + ", ".join(
            project_names.get(p, p) for p in role["projects"]))
    if role["clusters"]:
        bits.append("clusters: " + ", ".join(
            cluster_names.get(c, c) for c in role["clusters"]))
    if role.get("targets"):
        n = len(role["targets"])
        bits.append(f"{n} PAM target{'s' if n != 1 else ''}")
    if not role["projects"] and not role["clusters"] and not role.get("targets"):
        bits.append("fleet-wide")
    return " · ".join(bits)
