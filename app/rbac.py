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

A ROLE'S TWO LISTS NARROW TOGETHER
    Within ONE role the project list and the cluster list are both narrowings,
    so a cluster is inside the role only when it passes both: a role for the
    Kenya project opens Kenya's clusters and no others, even with no cluster
    ticked. Across roles it is still the union. The project list used to be
    ignored for clusters altogether, so a role pinned to one project read every
    project's pods.

ENFORCEMENT IS IN ONE PLACE
    The middleware maps the request path to an area and asks may_area(); the
    cluster and project pages additionally ask may_cluster()/may_project() for
    the specific thing being opened. Hiding a link is presentation — the check
    is what actually stops the request, and the two read the same functions, so
    a hidden page is also a forbidden one.

    Neither of those two had a caller until October 2026: a role pinned to one
    cluster opened every cluster's pages, logs and YAML, because nothing asked.
    They are asked now, in main.py's middleware for an id in the path or the
    query string, and by the handlers that read one out of a form or a socket.
"""
import contextlib
import contextvars
import json

from . import db, env

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
    # The ACTING half of Cloud accounts, and its own grant because it is a very
    # different thing to hand over than reading an inventory. "Cloud accounts"
    # above is inventory and diagrams — reading — so acting through it was a
    # GAP, never a capability anyone was relying on, which is why it is NOT
    # backfilled onto existing roles: a read-only cloud role must not silently
    # gain the power to stop an instance or mint an access key on upgrade.
    # Creating IAM/RAM users and their access keys is a route to the account
    # itself, so this is ESCALATING. Empty prefix: enforced in the handlers,
    # not by the path middleware, exactly like terraform_apply.
    "clouds_act": ("Cloud accounts: act", "changing what a cloud account runs "
                   "— instance power, tags and snapshots; security groups and "
                   "their inbound rules; IAM/RAM users, their policies and "
                   "access keys; container registries; subnets and elastic "
                   "IPs; and the console (VNC) session — plus running commands "
                   "on an instance through SSM or Cloud Assistant, which is a "
                   "root shell on the machine", ()),
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
    # Deleting an order deletes the private key with it, and there is no
    # second copy -- so it is its own grant, never part of using the area.
    # Empty prefix: enforced in the handler, not by the path middleware.
    "certs_delete": ("TLS certificates: delete", "deleting a certificate order, "
                     "and with it the only copy of its private key", ()),
    "workflows": ("Workflow engines", "Temporal and Airflow", ("/workflows",)),
    "bmc": ("Server hardware", "iDRAC, iLO and other BMCs", ("/bmc",)),
    # Managing servers through their BMCs, gated like the hypervisor areas:
    # handler-enforced (bmcops.gate), and the connection must allow it.
    "bmc_console": ("Server hardware: console", "a server's screen and "
                    "keyboard through its iDRAC, in the browser", ()),
    "bmc_power": ("Server hardware: power", "power on, shut down, restart, "
                  "power off, reset and power cycle servers; the identify "
                  "light", ()),
    "bmc_admin": ("Server hardware: administer", "one-time boot devices, "
                  "virtual media, clearing the event log, restarting the BMC "
                  "and turning its console on or off; includes power and "
                  "console", ()),
    "virt": ("Hypervisors", "Proxmox, ESXi and vCenter", ("/virt",)),
    # Managing hypervisors. Empty prefixes: the pages live under /virt, which
    # `virt` already opens for reading; each action checks its own area in
    # virtops.gate, and a connection must also allow management. Administer
    # includes power and console (virtops.may).
    "virt_console": ("Hypervisors: console", "open a virtual machine's screen "
                     "and keyboard in the browser", ()),
    "virt_power": ("Hypervisors: power and snapshots", "start, shut down, "
                   "restart, power off, reset and suspend VMs; take, revert "
                   "and delete snapshots", ()),
    "virt_admin": ("Hypervisors: administer", "create, change and delete VMs, "
                   "insert ISOs, upload and delete datastore files, host "
                   "maintenance, reboot and shutdown, services and port "
                   "groups; includes power and console", ()),
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
    # The provisioning wizard is the Terraform engine with a guided front end, so
    # reading its pages (hosts, inventory, images) belongs with Terraform. The
    # /provision prefix was governed by NOTHING — area_for_path returned None, so
    # anybody signed in could read it — and the acting routes under it are gated
    # a second time in the handlers by `terraform_apply` (changing a Proxmox
    # host, uploading or deleting a datastore file, generating a stack that
    # stores a sealed credential), the same split as /terraform's own routes.
    "terraform": ("Terraform", "the stacks, their .tf, the provisioning wizard "
                  "and the output of every run — read-only on its own",
                  ("/terraform", "/provision")),
    # ── the Administration entries in the sidebar ──────────────────────────
    # Two of the three can be delegated. The third cannot, and it is worth
    # being plain about why: whoever may edit a role definition may add
    # Settings to their own role, so "may edit roles" and "is an administrator"
    # are the same permission wearing different names. Roles therefore stay
    # with administrators and are deliberately absent from this list.
    "users": ("User accounts", "inviting people, issuing reset links and "
              "assigning roles. Cannot create administrators, cannot touch an "
              "administrator's account or one holding Settings, User accounts "
              "or another area only an administrator hands out, and cannot "
              "hand those out — each of those is a way to become one",
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
    # WHERE A BROKERED CREDENTIAL IS SENT. A target's address, port and
    # protocol decide who is handed its password or key at the next session,
    # so changing one is choosing the recipient. Saving a target checked only
    # the read-only `pam` area above, with no target scope, so any reader of
    # the catalogue could point any target at a host of their own. That was a
    # bug and not a capability, so no existing role is backfilled with this:
    # `pam` is documented as read-only, and a role that has been editing
    # targets was doing what its own description says it cannot. Creating a
    # target needs it unconfined, because a new target is in nobody's list.
    # Empty prefix: handler-enforced.
    "pam_targets": ("Privileged Access: manage targets", "adding targets and "
                    "changing them — address, port, protocol and the "
                    "credential each one brokers", ()),
    # Opening a live session — SSH, RDP, VNC — as the credential the target
    # brokers, and deleting the recording of one. This is the escalating half:
    # it is an interactive shell or desktop on the target as whatever the vault
    # connects as, the same class of grant as running a playbook. Empty prefix,
    # so it is enforced inside the connect handlers, not by the path middleware.
    "pam_connect": ("Privileged Access: connect", "opening a live session on a "
                    "target — an interactive shell or desktop as the brokered "
                    "credential", ()),
    # REMOVING A RECORD IS NEVER PART OF THE GRANT THAT USES IT. With only the
    # read-only `pam` area a role could delete any target by id -- one outside
    # its own scope included -- and an unconfined `pam` + `pam_connect` role
    # could delete and clear the recordings that are the evidence of what it
    # did. This is the separate grant for all of that, re-trusting a changed
    # host key included (it deletes the pin). Empty prefix: handler-enforced.
    "pam_delete": ("Privileged Access: delete", "deleting targets, SOPs and "
                   "session recordings, clearing recordings, and re-trusting a "
                   "changed host key", ()),
    # WHAT OPERATORS WILL RUN. The SOPs a terminal shows are pasted at the
    # prompts of production shells by people who trust them, so writing one
    # reaches every target anybody pastes it on -- including targets the
    # writer cannot open. Reading them is the `pam` area; this is the writing.
    # Escalating, and not confined by a role's targets: an SOP belongs to no
    # target. Empty prefix: handler-enforced.
    "pam_sops": ("Privileged Access: write SOPs", "writing and changing the "
                 "SOPs every terminal shows beside the shell — what operators "
                 "paste at the prompt, on any target", ()),
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
                        "terraform_apply", "pam_connect", "pam_delete",
                        "pam_sops", "pam_targets", "certs_delete",
                        "clouds_act", "virt_console", "virt_power",
                        "virt_admin", "bmc_console", "bmc_power",
                        "bmc_admin"})


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
    # ONE-TIME DATA MIGRATIONS, recorded by name so each runs exactly once per
    # database. The schema steps above are safe to repeat; a GRANT is not -- a
    # backfill that ran on every start would quietly hand back whatever an
    # administrator had since taken away.
    c.execute("CREATE TABLE IF NOT EXISTS rbac_migrations "
              "(name TEXT PRIMARY KEY, at TEXT)")
    _once(c, "delete-grants", _backfill_delete_grants)


def _once(c, name: str, fn) -> None:
    import time
    if c.execute("SELECT 1 FROM rbac_migrations WHERE name = ?",
                 (name,)).fetchone():
        return
    fn(c)
    c.execute("INSERT INTO rbac_migrations (name, at) VALUES (?, ?)",
              (name, time.strftime("%Y-%m-%d %H:%M:%S")))


def _backfill_delete_grants(c) -> None:
    """Deleting became its own grant (`pam_delete`, `certs_delete`), and an
    upgrade must take nothing away: a role holding `pam` could delete targets
    with nothing more, one holding `certs` could delete certificate orders, so
    each keeps that. Roles made afterwards start without it -- which is the
    point -- and an administrator withdrawing it is never undone, because this
    runs once."""
    for r in c.execute("SELECT id, areas FROM roles").fetchall():
        try:
            areas = json.loads(r["areas"] or "[]")
        except json.JSONDecodeError:
            continue
        add = [grant for base, grant in (("pam", "pam_delete"),
                                         ("certs", "certs_delete"))
               if base in areas and grant not in areas]
        if add:
            c.execute("UPDATE roles SET areas = ? WHERE id = ?",
                      (json.dumps(areas + add), r["id"]))


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
    if env.pam_only():
        # The editor on a PAM-only installation shows only the PAM's areas and
        # no project or cluster pickers. What it cannot show it must not
        # erase: an area it did not offer is kept as stored, and so are the
        # project and cluster lists -- an empty one means "every project", so
        # clearing them would WIDEN the role the day the install is switched
        # back to the full product.
        old = get(rid) if rid else None
        keep = ([a for a in keep if a in offered()]
                + [a for a in (old or {}).get("areas", []) if a not in offered()])
        projects = (old or {}).get("projects", [])
        clusters = (old or {}).get("clusters", [])
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
# ── what a PAM-only installation offers ────────────────────────
# PORTAL_MODE=pam (see env.py). Everything outside this set does not exist on
# such an installation, for anybody -- an administrator included -- because
# areas_of() is the one thing the sidebar, the middleware and every handler's
# own check read. Users, roles and the audit log stay: the PAM needs them.
# `settings` stays because Settings -> Privileged Access and Email live there;
# main.py narrows /settings to the pages a PAM uses.
PAM_ONLY_AREAS = frozenset({"pam", "pam_targets", "pam_connect", "pam_delete",
                            "pam_sops", "users", "audit", "settings"})


def offered() -> frozenset:
    """Every area this installation has at all."""
    return PAM_ONLY_AREAS if env.pam_only() else frozenset(AREAS)


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
    # Before the credential's own narrowing and over an admin too: an area this
    # installation does not offer is not anybody's to hold.
    got &= offered()
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


def _granting(user: dict | None, area: str) -> list | None:
    """The roles that grant `area`, or None for an administrator, whom no list
    confines."""
    if is_admin(user):
        return None
    return [r for r in of_user((user or {}).get("id", "")) if area in r["areas"]]


def _cluster_homes() -> dict:
    """cid -> pid for every cluster. Read when asked rather than imported at
    the top: store is a heavier module than this one, and a cluster moved to
    another project must be judged by where it is now."""
    from . import store
    return {cid: pid for pid, p in store.projects().items()
            for cid in (p.get("clusters") or {})}


def _unconfined(roles: list) -> bool:
    return any(not r["clusters"] and not r["projects"] for r in roles)


def may_cluster(user: dict | None, cid: str, area: str = "clusters") -> bool:
    if not may_area(user, area):
        return False
    allowed = visible_clusters(user, area)
    return allowed is None or cid in allowed


def may_project(user: dict | None, pid: str, area: str = "config") -> bool:
    if not may_area(user, area):
        return False
    allowed = _scope(user, area, "projects")
    return allowed is None or pid in allowed


def visible_clusters(user: dict | None, area: str = "clusters") -> set | None:
    """None means every cluster — callers use it to filter listings.

    A role admits a cluster that passes BOTH of its lists (see the module
    header). Somebody holding no role that grants `area` gets the empty set,
    never None: "not confined" is an answer about a role, and there is none."""
    roles = _granting(user, area)
    if roles is None or _unconfined(roles):
        return None
    homes = _cluster_homes()
    return {cid for cid, pid in homes.items() for r in roles
            if (not r["clusters"] or cid in r["clusters"])
            and (not r["projects"] or pid in r["projects"])}


def cluster_projects(user: dict | None, area: str = "clusters") -> set | None:
    """The projects a cluster listing may show this person, or None for all.

    Not visible_projects: a role pinned to one cluster names no project, and
    would otherwise list every project as an empty card. So a project is shown
    when it holds a cluster the person may open, or when a role names it
    outright — a project with no clusters yet is still one somebody was given."""
    roles = _granting(user, area)
    if roles is None or _unconfined(roles):
        return None
    homes = _cluster_homes()
    out: set = set()
    for r in roles:
        if not r["clusters"]:
            out |= set(r["projects"])
            continue
        held = {homes[c] for c in r["clusters"] if c in homes}
        out |= held & set(r["projects"]) if r["projects"] else held
    return out


def visible_projects(user: dict | None, area: str = "config") -> set | None:
    return _scope(user, area, "projects")


def may_target(user: dict | None, tid: str, area: str = "pam") -> bool:
    """Whether this person may see (area='pam'), open (area='pam_connect') or
    change (area='pam_targets') one Privileged-Access target. Scoped by the
    role's `targets` list — empty means every target, so the simple 'all
    devices' role needs no list."""
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
    sessions), the explicit `pam_delete` grant, AND confined to nothing in
    either. A role restricted to a subset of targets is precisely the role that
    must not be able to clear the record, and an unconfined role holding the
    delete grant is the one an install gives to whoever is accountable for the
    trail. Admins qualify by being admins.
    """
    if is_admin(user):
        return True
    if not (may_area(user, "pam") and may_area(user, "pam_connect")
            and may_area(user, "pam_delete")):
        return False
    # None from _scope means "not confined" -- see the module header on why
    # that is the permissive answer.
    return (_scope(user, "pam", "targets") is None
            and _scope(user, "pam_connect", "targets") is None)


def visible_targets(user: dict | None, area: str = "pam") -> set | None:
    """The target ids this user is confined to, or None for every target."""
    return _scope(user, area, "targets")


def may_add_target(user: dict | None) -> bool:
    """Whether this person may CREATE a Privileged-Access target.

    Changing one is `may_target(user, tid, "pam_targets")`, scoped like
    everything else here. Creating cannot be scoped that way: a new target is
    in no role's list, so a confined role that could create one would be
    making targets outside its own reach -- and could not even see them
    afterwards. So it takes the grant unconfined. `_scope` answers None both
    for "unconfined" and for "does not hold the area at all", which is why the
    area is asked first."""
    return (may_area(user, "pam_targets")
            and _scope(user, "pam_targets", "targets") is None)


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
