"""Playbooks, an inventory to run them against, and a record of every run.

WHAT THIS IS FOR
    Somebody already has playbooks and already has hosts. What they do not have
    is a place where the two meet that other people can use: the playbook lives
    on one laptop, the inventory is a file next to it, and the record of what was
    run last Tuesday is a scrollback buffer that has since closed.

    So three things are stored here, and nothing else:

      * **Playbooks** — the YAML, with every version kept. Editing one is a save,
        not a commit, and the previous text is still there afterwards.
      * **Groups of hosts** — a name, the hosts in it, how to reach them. A host
        may be typed in or taken from the server inventory the portal already
        holds, in which case its address follows the inventory rather than being
        copied and going stale.
      * **Runs** — who ran which playbook against which group, when, whether it
        was a check or the real thing, what ansible printed, and what it decided.

THE SHAPE OF A RUN, AND WHY IT IS THIS SHAPE
    `ansible-playbook` is a long-lived process that prints as it goes and means
    something by its exit code. So a run is a row that exists *before* the
    process does, is appended to while it lives, and is finished exactly once.
    That is what makes the page able to show a run in progress, a run that was
    cancelled, and a run whose portal restarted underneath it — the last of which
    is why `status` is written to the database and not held in memory.

    Nothing is ever passed through a shell. The playbook is a file, the inventory
    is a file, extra variables are a JSON file handed over with `@`, and every
    limit and tag is checked against a pattern before it becomes an argument. A
    playbook can of course do anything it likes on the hosts it reaches — that is
    what a playbook is — but the portal must not be the thing that turns a host
    name into shell.

CHECK FIRST, DELIBERATELY
    `--check` is offered as the first button and the real run as the second, the
    same way the cluster YAML editor offers a server-side dry run before an
    apply. It is not a guarantee: a playbook full of `command:` tasks cannot be
    checked meaningfully and ansible says so in its own output. It is still the
    difference between finding out about a typo now and finding out about it on
    forty hosts.

WHAT IS NOT HERE
    No Vault integration, no roles/collections management, no AWX-style
    workflow graphs. Everything above could be added on top of this table;
    none of it can be taken back out once somebody depends on it.

    THERE IS A SCHEDULER, and this said there was not. `scheduler_start()`
    runs a daemon ticker unless `PORTAL_SCHEDULER=0`, and `scheduler_tick()`
    passes `check=bool(s["check_mode"])` -- a stored column, not a forced dry
    run -- so a scheduled row fires a REAL run with nobody watching. This
    docstring claimed "a run is started by a person who is looking at the
    page" for at least a release while a schedule row existed that had already
    fired. Worth knowing because that sentence is the product's own claim
    about not acting on a timer, and somebody will quote it.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone

from . import db, env, secretbox, store
from .paths import DATA

# Playbook text and run output live in the database rather than on disk: a run's
# output is the evidence for a change and belongs in the file that gets backed
# up, not in a directory that a container rebuild forgets.
PLAYBOOK_MAX = 512_000              # a playbook, not a tarball
OUTPUT_MAX = 4_000_000              # ~4MB of output per run, then it is trimmed
RUNS_KEEP = 500                     # rows kept per playbook before the oldest go


# A run that has printed nothing for this long is not going to. Ansible's own
# SSH timeouts are shorter than this; the cap is here for the pathological case
# — a task waiting on a prompt that will never come — so a stuck process cannot
# hold a slot for ever.
RUN_TIMEOUT = 3600.0
IDLE_TIMEOUT = 900.0
MAX_CONCURRENT = 4

# Inventory names, limits and tags become arguments, so they are checked rather
# than trusted. Ansible itself allows more than this in a host name; what it
# allows and what is safe to hand to a process are different questions, and the
# narrower answer has never been the thing standing in somebody's way.
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# A MACHINE'S OWN NAME, which may be a fully qualified one -- so not NAME_OK,
# whose 63 characters is a single label's limit and would refuse a perfectly
# ordinary `host.sub.example.internal`.
HOST_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
LIMIT_OK = re.compile(r"^[A-Za-z0-9_.:,!*\[\]&-]{1,200}$")
TAGS_OK = re.compile(r"^[A-Za-z0-9_,.-]{1,200}$")

STATUS_RUNNING = "running"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    return db.connect()


def _migrate(c: sqlite3.Connection) -> None:
    """Four tables, created and then extended additively.

    `ansible_revs` is separate from `ansible_playbooks` on purpose: the current
    text is read on every page and the history is read almost never, and keeping
    them apart means the common read does not carry every past version with it.
    """
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_playbooks (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT, body TEXT,
        group_id TEXT,                       -- the group it usually runs against
        env TEXT DEFAULT '',                 -- environment label for its place
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_revs (
        id TEXT PRIMARY KEY, pb_id TEXT NOT NULL, body TEXT,
        at TEXT, by TEXT, note TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_groups (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT,
        ssh_user TEXT, ssh_port INTEGER, become_root INTEGER DEFAULT 0,
        key_sealed TEXT,                     -- the private key, via secretbox
        key_path TEXT,                       -- ...or a path mounted into the pod
        host_key_checking INTEGER DEFAULT 1,
        group_vars TEXT,                     -- YAML, handed to ansible as-is
        is_prod INTEGER DEFAULT 0,
        env TEXT DEFAULT '',                 -- environment (prod/staging/… )
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_hosts (
        id TEXT PRIMARY KEY, group_id TEXT NOT NULL, name TEXT NOT NULL,
        address TEXT, asset_id TEXT,         -- set when it came from the inventory
        ssh_user TEXT, ssh_port INTEGER, host_vars TEXT,
        env TEXT DEFAULT '',                 -- per-host env; falls back to group
        label TEXT DEFAULT '',               -- what people call it, free text
        created TEXT, created_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_runs (
        id TEXT PRIMARY KEY, pb_id TEXT, pb_name TEXT, group_id TEXT,
        group_name TEXT, hosts INTEGER DEFAULT 0, check_mode INTEGER DEFAULT 1,
        limit_to TEXT, tags TEXT, extra_vars TEXT, cmd TEXT,
        status TEXT, rc INTEGER, stats TEXT, output TEXT, why TEXT,
        started TEXT, finished TEXT, by TEXT, pid INTEGER)""")
    # Where a thing belongs. Added after the tables shipped, so they arrive as
    # additive columns: groups and playbooks live in the same projects and
    # regions as everything else in the portal, and a run keeps the pair it had
    # when it happened — reassigning a group later must not rewrite history.
    #
    # The runs table gets DIFFERENT names, because `pid` was already taken: it
    # is the PROCESS id of the running ansible, written when the run starts and
    # nulled when it finishes. The first version reused it for the project and
    # the project id was silently overwritten by a number and then by NULL —
    # found by a test reading the row back, not by reading this code.
    for table in ("ansible_playbooks", "ansible_groups"):
        have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        for col in ("pid", "rgid"):
            if col not in have:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT DEFAULT ''")
    for table in ("ansible_groups", "ansible_playbooks", "ansible_hosts"):
        have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        if "env" not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN env TEXT DEFAULT ''")
    have = {r["name"] for r in c.execute("PRAGMA table_info(ansible_hosts)")}
    if "label" not in have:
        c.execute("ALTER TABLE ansible_hosts ADD COLUMN label TEXT DEFAULT ''")
    # THE MACHINE'S OWN NAME, which is neither its inventory name nor its
    # address. An inventory entry is often just an IP, so the catalogue in
    # Privileged Access shows a row of numbers with no hostname and no label --
    # which is exactly what somebody needs to recognise which machine it is.
    if "hostname" not in have:
        c.execute("ALTER TABLE ansible_hosts "
                  "ADD COLUMN hostname TEXT DEFAULT ''")
    have = {r["name"] for r in c.execute("PRAGMA table_info(ansible_runs)")}
    for col in ("proj_id", "rgn_id"):
        if col not in have:
            c.execute(f"ALTER TABLE ansible_runs ADD COLUMN {col} TEXT DEFAULT ''")
    # A schedule is a stored intention to run: which playbook, against which
    # group, how, and when next. `next_at` carries the whole clock — the ticker
    # only ever asks "is anything due", and firing moves it forward.
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_schedules (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, pb_id TEXT NOT NULL,
        group_id TEXT NOT NULL, check_mode INTEGER DEFAULT 1,
        limit_to TEXT, tags TEXT, extra_vars TEXT,
        kind TEXT NOT NULL,                  -- minutes | hours | daily | weekly
        every INTEGER DEFAULT 0,             -- for minutes/hours
        at TEXT,                             -- HH:MM, for daily/weekly
        weekday INTEGER DEFAULT 0,           -- Monday=0, for weekly
        enabled INTEGER DEFAULT 1,
        confirmed INTEGER DEFAULT 0,         -- the production name was typed
        next_at TEXT, last_at TEXT, last_run_id TEXT, last_error TEXT,
        created TEXT, created_by TEXT)""")
    # A recording of one interactive terminal on one host: who, where, when, how
    # long, how much came back, and the commands they finished typing. The cast
    # itself (what the screen showed, replayable) lives in a file under DATA and
    # is pointed at by `cast_rel`; the row is the index and the transcript. Same
    # proj_id/rgn_id pair as a run so a recording files under the same project.
    c.execute("""CREATE TABLE IF NOT EXISTS ansible_sessions (
        id TEXT PRIMARY KEY, group_id TEXT, group_name TEXT, host TEXT,
        who TEXT, proj_id TEXT DEFAULT '', rgn_id TEXT DEFAULT '',
        started TEXT, ended TEXT, seconds INTEGER DEFAULT 0,
        out_bytes INTEGER DEFAULT 0, cmd_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'closed', ip TEXT DEFAULT '',
        cast_rel TEXT DEFAULT '', commands TEXT DEFAULT '')""")
    for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_ans_revs_pb ON ansible_revs(pb_id)",
            "CREATE INDEX IF NOT EXISTS idx_ans_hosts_g ON ansible_hosts(group_id)",
            "CREATE INDEX IF NOT EXISTS idx_ans_runs_pb ON ansible_runs(pb_id)",
            "CREATE INDEX IF NOT EXISTS idx_ans_runs_at ON ansible_runs(started)",
            "CREATE INDEX IF NOT EXISTS idx_ans_sched_due "
            "ON ansible_schedules(enabled, next_at)",
            "CREATE INDEX IF NOT EXISTS idx_ans_sess_who ON ansible_sessions(who)",
            "CREATE INDEX IF NOT EXISTS idx_ans_sess_at "
            "ON ansible_sessions(started)"):
        c.execute(stmt)


db.register(_migrate)


class Refused(Exception):
    """A run that will not be started, with the reason a reader needs."""


# ── the installation's own settings ────────────────────────────
# `allow_real` is off until somebody turns it on, the same posture as a cluster's
# "allow management": an install that has just been given an inventory and a set
# of playbooks can be explored — check runs work — without one mis-click
# changing forty hosts. The page that refuses says where the switch is.
DEFAULTS = {"allow_real": False, "forks": 5, "ssh_timeout": 20,
            "record_sessions": True}


def config() -> dict:
    got = {**DEFAULTS, **(store._setting("ansible") or {})}
    got["allow_real"] = bool(got.get("allow_real"))
    got["record_sessions"] = bool(got.get("record_sessions"))
    for num, low, high in (("forks", 1, 100), ("ssh_timeout", 1, 300)):
        try:
            got[num] = max(low, min(high, int(got.get(num) or DEFAULTS[num])))
        except (TypeError, ValueError):
            got[num] = DEFAULTS[num]
    return got


def save_config(**fields) -> None:
    store._set_setting("ansible", {k: fields.get(k, DEFAULTS[k])
                                   for k in DEFAULTS})


# What a new playbook starts as. Not a blank box: the first thing anybody needs
# is the shape — a list of plays, `hosts: all` so the group decides who it lands
# on, and a task that proves the connection works before anything is changed.
EXAMPLE = """---
- name: what this playbook does
  hosts: all
  become: false
  gather_facts: true

  tasks:
    - name: check we can reach the host
      ansible.builtin.ping:

    - name: show what we are talking to
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }} is running {{ ansible_distribution | default('?') }}"
"""


# ── the tool ───────────────────────────────────────────────────
_probe: dict = {}


def tool(force: bool = False) -> dict:
    """Whether ansible-playbook is here, and which version.

    Cached: this shells out, and the answer cannot change while the process
    lives — the binary is baked into the image alongside the portal.
    """
    global _probe
    if _probe and not force:
        return _probe
    row = {"found": False, "version": "", "path": "", "error": ""}
    path = shutil.which(env.ANSIBLE, path=env.TOOL_PATH) or env.ANSIBLE
    try:
        got = subprocess.run([path, "--version"], capture_output=True, text=True,
                             timeout=30, env={"PATH": env.TOOL_PATH,
                                              "HOME": os.environ.get("HOME", "/tmp")})
        if got.returncode == 0:
            first = (got.stdout or "").splitlines()[0] if got.stdout else ""
            # ansible prints "ansible-playbook [core 2.20.1]" — the name goes,
            # and so do the brackets: "[core 2.20.1]" on a settings page reads
            # like a placeholder nobody filled in.
            row.update(found=True, path=path,
                       version=re.sub(r"^ansible-playbook\s*", "",
                                      first).strip().strip("[]").strip()
                       or first.strip())
        else:
            row["error"] = (got.stderr or got.stdout).strip()[:300]
    except FileNotFoundError:
        row["error"] = (f"{env.ANSIBLE} is not on the portal's PATH "
                        f"({env.TOOL_PATH})")
    except Exception as e:                                       # noqa: BLE001
        row["error"] = f"{type(e).__name__}: {e}"
    _probe = row
    return row


# ── playbooks ──────────────────────────────────────────────────
def playbooks() -> list:
    """Every playbook, newest change first, with its last run beside it.

    One query rather than one per row: the list page shows the last run's status
    for each playbook, and reading that in a loop is how a page with forty
    playbooks becomes forty-one queries.
    """
    c = _conn()
    last = {}
    for r in c.execute(
            """SELECT pb_id, status, rc, check_mode, started, by FROM ansible_runs
               WHERE rowid = (SELECT MAX(rowid) FROM ansible_runs x
                              WHERE x.pb_id IS ansible_runs.pb_id)"""):
        last[r["pb_id"]] = dict(r)
    counts = {r["pb_id"]: r["n"] for r in c.execute(
        "SELECT pb_id, COUNT(*) n FROM ansible_revs GROUP BY pb_id")}
    names = {r["id"]: r["name"] for r in
             c.execute("SELECT id, name FROM ansible_groups")}
    out = []
    for r in c.execute("SELECT * FROM ansible_playbooks ORDER BY name"):
        row = dict(r)
        row["last"] = last.get(row["id"])
        if row["last"]:
            row["last"]["ago"] = ago(row["last"].get("started"))
        row["versions"] = counts.get(row["id"], 0)
        row["tasks"] = _count_tasks(row.get("body") or "")
        row["group_name"] = names.get(row.get("group_id") or "", "")
        out.append(row)
    return _placed(out)


# Playbooks the product ships, addressed by id like any other. One so far, and
# it answers the only question an inventory page is really about: can the portal
# reach these machines, as this user, with this key. Writing a playbook to find
# that out is a chore, and everybody's first one is this.
BUILTINS = {
    "builtin:ping": {
        "id": "builtin:ping", "name": "connection test", "group_id": "",
        "notes": "reaches every host in the group and asks it to answer",
        "body": """---
- name: can the portal reach these hosts
  hosts: all
  gather_facts: false
  tasks:
    - name: answer if you are there
      ansible.builtin.ping:
""",
    },
}


def playbook(pb_id: str) -> dict | None:
    """One playbook, stored or built in.

    Built-ins resolve here rather than at each call site, so a run of one is a
    run like any other: same argv, same gates, same record afterwards.
    """
    if pb_id in BUILTINS:
        return dict(BUILTINS[pb_id])
    r = _conn().execute("SELECT * FROM ansible_playbooks WHERE id = ?",
                        (pb_id,)).fetchone()
    return dict(r) if r else None


def _count_tasks(body: str) -> int:
    """How many tasks, counted from the text rather than by parsing YAML.

    A playbook that does not parse still has to be countable — the editor shows
    this beside a syntax error — so this reads the text.

    The indentation is what tells a task from a play. Both are `- name:`, and
    counting every one of them called the two-task example "3 tasks": the play's
    own name is the shallowest, so anything deeper than the shallowest is a task.
    A playbook whose only names are plays honestly counts zero.
    """
    depths = [len(m.group(1)) for m in
              re.finditer(r"^([ \t]*)-\s+name:\s*\S", body, re.M)]
    if not depths:
        return 0
    return sum(1 for d in depths if d > min(depths))


def place_of(fields: dict) -> tuple[str, str]:
    """The (pid, rgid) a form asked for, checked against the portal's own map.

    Checked here rather than trusted: the selects on the page are built from the
    same map, so anything else arriving means the request was not built by the
    page — and a group filed under a project that does not exist would simply
    vanish from every filtered view.
    """
    pid = (fields.get("pid") or "").strip()
    rgid = (fields.get("rgid") or "").strip()
    if not pid:
        if rgid:
            raise Refused("a region needs its project")
        return "", ""
    proj = store.get_project(pid)
    if not proj:
        raise Refused("that project does not exist")
    if rgid and rgid not in (proj.get("regions") or {}):
        raise Refused(f"that region is not part of {proj.get('name', pid)}")
    return pid, rgid


def _placed(rows: list) -> list:
    """Attach project_name / region_name to anything carrying pid/rgid."""
    projects = store.projects()
    for r in rows:
        proj = projects.get(r.get("pid") or "")
        r["project_name"] = (proj or {}).get("name", "")
        r["region_name"] = ((proj or {}).get("regions", {})
                            .get(r.get("rgid") or "", {}) or {}).get("name", "")
    return rows


def save_playbook(pb_id: str, name: str, body: str, notes: str, who: str,
                  group_id: str = "", pid: str = "", rgid: str = "",
                  env: str = "") -> str:
    """Create or update, keeping the previous text as a revision.

    The revision is written from what is in the database *before* the update, so
    the history is what was actually saved rather than what the editor thought
    was there.
    """
    if pb_id in BUILTINS:
        raise Refused("that playbook ships with the product and cannot be "
                      "edited — copy it into one of your own instead")
    name = (name or "").strip()
    if not name:
        raise Refused("a playbook needs a name")
    if len(body or "") > PLAYBOOK_MAX:
        raise Refused(f"a playbook is capped at {PLAYBOOK_MAX // 1000}kB")
    pid, rgid = place_of({"pid": pid, "rgid": rgid})
    env = (env or "").strip().lower()[:40]
    body = body or ""
    with db.tx() as c:
        if pb_id:
            was = c.execute("SELECT body FROM ansible_playbooks WHERE id = ?",
                            (pb_id,)).fetchone()
            if not was:
                raise Refused("that playbook no longer exists")
            if (was["body"] or "") != body:
                c.execute("""INSERT INTO ansible_revs
                             (id, pb_id, body, at, by, note)
                             VALUES (?,?,?,?,?,?)""",
                          (uuid.uuid4().hex, pb_id, was["body"] or "", _now(),
                           who, "replaced"))
            c.execute("""UPDATE ansible_playbooks SET name=?, body=?, notes=?,
                         group_id=?, pid=?, rgid=?, env=?, updated=?, updated_by=?
                         WHERE id=?""",
                      (name, body, notes or "", group_id or "", pid, rgid, env,
                       _now(), who, pb_id))
        else:
            pb_id = "pb-" + uuid.uuid4().hex[:10]
            c.execute("""INSERT INTO ansible_playbooks
                         (id, name, notes, body, group_id, pid, rgid, env, created,
                          updated, created_by, updated_by)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (pb_id, name, notes or "", body, group_id or "", pid,
                       rgid, env, _now(), _now(), who, who))
    return pb_id


def delete_playbook(pb_id: str) -> None:
    """Remove a playbook and its versions — but never its runs.

    A built-in is not deletable: it is part of the product, and the runs of it
    are somebody's record of whether a host answered.

    A run is the record that something happened on real hosts. Deleting the
    playbook it came from does not make that untrue, so the runs keep the name
    they were run under and lose only the link.
    """
    if pb_id in BUILTINS:
        raise Refused("that playbook ships with the product")
    with db.tx() as c:
        c.execute("DELETE FROM ansible_revs WHERE pb_id = ?", (pb_id,))
        c.execute("DELETE FROM ansible_playbooks WHERE id = ?", (pb_id,))


def revisions(pb_id: str) -> list:
    return [dict(r) for r in _conn().execute(
        "SELECT id, at, by, note, LENGTH(body) len FROM ansible_revs "
        "WHERE pb_id = ? ORDER BY at DESC, rowid DESC", (pb_id,))]


def revision_body(rev_id: str) -> str:
    r = _conn().execute("SELECT body FROM ansible_revs WHERE id = ?",
                        (rev_id,)).fetchone()
    return (r["body"] if r else "") or ""


# ── inventory ──────────────────────────────────────────────────
def groups(with_hosts: bool = True) -> list:
    c = _conn()
    out = [dict(r) for r in c.execute("SELECT * FROM ansible_groups ORDER BY name")]
    if not with_hosts:
        # decorated on BOTH paths: the schedules list takes this one, and its
        # Place column read a dash for every row until it did
        return _placed(out)
    by_group: dict = {}
    for r in c.execute("SELECT * FROM ansible_hosts ORDER BY name"):
        by_group.setdefault(r["group_id"], []).append(dict(r))
    for g in out:
        g["hosts"] = by_group.get(g["id"], [])
        g["has_key"] = bool(g.get("key_sealed") or g.get("key_path"))
        live = _asset_addresses(g["hosts"])
        for h in g["hosts"]:
            h["live_address"] = live.get(h.get("asset_id") or "", "")
    return _placed(out)


def inventory_targets() -> list:
    """Every inventory host, flattened into the descriptor a PAM target needs.

    The host's own id (ah-…) is the stable key, so it can be named in a role's
    target scope and reached from the catalogue without being entered a second
    time. The credential and the production flag are the group's — a host is
    read-only in PAM and edited in Ansible.
    """
    gs = groups(with_hosts=True)
    # ONE asset read for the whole inventory, not one per host: this runs on
    # every Privileged Access page load.
    facts = _asset_facts([h for g in gs for h in g.get("hosts", [])])
    out = []
    for g in gs:
        for h in g.get("hosts", []):
            addr = (h.get("live_address") or h.get("address")
                    or h.get("name") or "")
            # a host's own environment wins; otherwise it inherits the group's
            env = (h.get("env") or "").strip() or g.get("env") or ""
            out.append({
                "id": h["id"], "name": h["name"], "protocol": "ssh",
                "address": addr,
                "port": h.get("ssh_port") or g.get("ssh_port") or 22,
                "username": h.get("ssh_user") or g.get("ssh_user") or "",
                "proj_id": g.get("pid") or "", "rgn_id": g.get("rgid") or "",
                # a production environment — the group's or the host's own —
                # switches on the typed-name confirm even if the group flag is off
                "is_prod": 1 if (g.get("is_prod")
                                 or env.lower() in ("prod", "production")) else 0,
                "env": env,
                "auth_kind": "key" if g.get("has_key") else "none",
                "tags": (g.get("name") or ""),          # the group reads as a tag
                "label": h.get("label") or "",
                # WHAT SOMEBODY TYPED WINS. The order is: the hostname set on
                # this row by a person, then the asset inventory's (which is
                # where a machine's name is normally recorded), then the host's
                # own inventory name -- and that last only when it is not
                # merely the address, because an inventory pasted in as a list
                # of IPs has no host name anywhere and an empty column is more
                # honest than printing the address twice under two headings.
                #
                # THE EXPLICIT ONE IS FIRST because it is the one somebody
                # entered on purpose, from a page where they were looking at a
                # column of bare addresses. Anything derived is a guess beside
                # that. This key used to appear TWICE in this literal, and the
                # second silently won -- which is how a typed hostname
                # vanished with no error anywhere.
                "hostname": ((h.get("hostname") or "").strip()
                             or facts.get(h.get("asset_id") or "", {}).get("hostname")
                             or ((h.get("name") or "")
                                 if (h.get("name") or "") != addr else "")),
                "source": "ansible", "group_id": g["id"],
                "group_name": g.get("name") or "",
            })
    return out


def group(gid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM ansible_groups WHERE id = ?",
                        (gid,)).fetchone()
    if not r:
        return None
    g = dict(r)
    g["hosts"] = hosts_of(gid)
    g["has_key"] = bool(g.get("key_sealed") or g.get("key_path"))
    return g


def hosts_of(gid: str) -> list:
    return [dict(r) for r in _conn().execute(
        "SELECT * FROM ansible_hosts WHERE group_id = ? ORDER BY name", (gid,))]


def save_group(gid: str, fields: dict, who: str) -> str:
    """Create or update a group. A blank key field leaves the stored key alone.

    That last part matters more than it looks: the form cannot show the key it
    holds, so if an empty field meant "no key", editing the SSH user would
    silently throw the key away and every run afterwards would fail
    authentication for a reason nothing on the page explains.
    """
    name = (fields.get("name") or "").strip()
    if not NAME_OK.match(name):
        raise Refused("a group name may hold letters, digits, dot, dash and "
                      "underscore, and must start with a letter or digit")
    port = fields.get("ssh_port") or 0
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        raise Refused("the SSH port has to be a number")
    if port and not 1 <= port <= 65535:
        raise Refused("the SSH port has to be between 1 and 65535")
    key = (fields.get("key") or "").strip()
    if key:
        # Parsed, not pattern-matched: a key that is stored and cannot be read is
        # a group that looks ready and fails on every host at run time.
        got = read_key(key)
        if not got["ok"]:
            raise Refused(f"that key was not stored — {got['why']}")
    pid, rgid = place_of(fields)
    genv = (fields.get("env") or "").strip().lower()[:40]
    row = {"name": name, "notes": (fields.get("notes") or "").strip(),
           "pid": pid, "rgid": rgid, "env": genv,
           "ssh_user": (fields.get("ssh_user") or "").strip(),
           "ssh_port": port or None,
           "become_root": 1 if fields.get("become_root") else 0,
           "host_key_checking": 0 if fields.get("no_host_key_check") else 1,
           "group_vars": fields.get("group_vars") or "",
           "key_path": (fields.get("key_path") or "").strip(),
           # a prod-class environment turns on the typed-name confirm by itself
           "is_prod": 1 if (fields.get("is_prod")
                            or genv in ("prod", "production")) else 0}
    with db.tx() as c:
        if gid:
            if not c.execute("SELECT 1 FROM ansible_groups WHERE id = ?",
                             (gid,)).fetchone():
                raise Refused("that group no longer exists")
            sets = ", ".join(f"{k}=?" for k in row)
            args = [*row.values(), _now(), who, gid]
            c.execute(f"UPDATE ansible_groups SET {sets}, updated=?, "
                      f"updated_by=? WHERE id=?", args)
            if key:
                c.execute("UPDATE ansible_groups SET key_sealed=? WHERE id=?",
                          (secretbox.seal(key), gid))
            elif fields.get("drop_key"):
                c.execute("UPDATE ansible_groups SET key_sealed='' WHERE id=?",
                          (gid,))
        else:
            gid = "ag-" + uuid.uuid4().hex[:10]
            cols = ["id", *row, "key_sealed", "created", "updated",
                    "created_by", "updated_by"]
            args = [gid, *row.values(), secretbox.seal(key) if key else "",
                    _now(), _now(), who, who]
            # counted from the list, not from len(row) + a number I have to keep
            # in step with the list above — which is exactly what was wrong here
            marks = ", ".join("?" * len(cols))
            c.execute(f"INSERT INTO ansible_groups ({', '.join(cols)}) "
                      f"VALUES ({marks})", args)
    return gid


HDR_LINE = re.compile(r"^[A-Za-z][A-Za-z-]*:\s")


def key_text(raw: str) -> str:
    """A pasted or uploaded private key, in the shape ssh will actually read.

    ONE definition, because both forms take a key — a target in Privileged
    Access and a host group here — and two normalisers would be one of them
    drifting.

    Three manglings, each measured in the portal's own image rather than
    guessed at:

    * **Anything before `-----BEGIN` breaks an OpenSSH-format key and NOTHING
      ELSE DOES.** A UTF-8 BOM (what a Windows editor writes), a leading blank
      line, or a line of notes above the key: `cryptography` loads all of them
      happily and ssh answers `error in libcrypto`. That combination is the
      one that gets past a validator and fails at connect time, and it is
      exactly what a customer hit — while the same key worked from their own
      shell, where the file had no BOM. A PEM key tolerates the same leading
      bytes, which is why this looks so arbitrary from the outside.
    * **CRLF**, because an HTML `<textarea>` posts CRLF by specification. ssh
      refuses such a key with `invalid format`; cryptography does not mind.
    * **A missing trailing newline**, same refusal.

    Repaired rather than refused: every one of these is the browser's or the
    editor's doing, and telling somebody their correct key is invalid because
    of how it travelled would be blaming them for our plumbing.
    """
    text = (raw or "").replace("\ufeff", "").replace("\r\n", "\n").replace("\r", "\n")
    # Trim to the key itself. Anything above the header is not part of it, and
    # ssh will not look past it.
    cut = text.find("-----BEGIN")
    if cut > 0:
        text = text[cut:]
    text = text.strip()
    if not text:
        return ""
    # BLANK LINES INSIDE THE BODY, which is the shape a real customer's key
    # arrived in and the one this function previously could not repair. Their
    # file separated lines with LF-then-CR — reversed CRLF, which nothing here
    # produces on purpose but files in the world do. A textarea's value
    # sanitisation turns CRLF into LF and then a LONE CR into LF as well, so
    # every separator became TWO newlines and the body reached us with a blank
    # line between every line of base64. ssh answers `error in libcrypto`;
    # reproduced end to end in the portal's own image.
    #
    # A key body never contains a blank line — EXCEPT after the headers of an
    # old encrypted PEM (`Proc-Type:` / `DEK-Info:`), where the blank line is
    # structural. So they are dropped only when there are no such headers, or
    # a passphrase-protected key would be mangled into a worse error than the
    # accurate one it already gets.
    lines = text.split("\n")
    body = lines[1:-1]
    headered = any(HDR_LINE.match(ln) for ln in body)
    if not headered:
        lines = [ln for ln in lines if ln.strip()]
    return "\n".join(lines) + "\n"


def read_key(text: str) -> dict:
    """Parse a pasted private key, and say precisely what is wrong with it.

    This used to test for `-----BEGIN` and `-----END` and nothing else, which
    every mangled key passes: a key whose body lost its line breaks in a
    copy-paste, an encrypted key with no passphrase to give, or a public key
    pasted by mistake all have both markers. The result was a group that looked
    configured and a RUN that failed, on every host at once, with ssh's own
    unhelpful `Load key "…/id_key": invalid format`.

    So the key is really parsed, here, while somebody is looking at the form that
    produced it. `public` comes back too, because the public half is what has to
    reach a host's authorized_keys and deriving it needs the same parse.
    """
    from cryptography.hazmat.primitives import serialization

    raw = key_text(text)
    out = {"ok": False, "why": "", "public": "", "kind": ""}
    if not raw:
        out["why"] = "there is nothing there"
        return out
    # A public key is the commonest wrong paste, and its failure is otherwise
    # reported as a format error — which sends somebody looking for a corrupt
    # file rather than for the other half of the pair.
    if raw.startswith(("ssh-", "ecdsa-", "sk-ssh-")) or "PUBLIC KEY" in raw:
        out["why"] = ("that is a PUBLIC key. The portal needs the private half "
                      "— the file without .pub, beginning -----BEGIN")
        return out
    data = (raw + "\n").encode()
    err = ""
    for load in (serialization.load_ssh_private_key,
                 serialization.load_pem_private_key):
        try:
            key = load(data, password=None)
        except TypeError:
            # cryptography raises TypeError when a passphrase is needed
            out["why"] = ("that key is protected by a passphrase, and a run has "
                          "nobody to type it. Store a key with no passphrase, "
                          "or use “Set up key access” below to have one made")
            return out
        except Exception as e:                                 # noqa: BLE001
            err = str(e) or type(e).__name__
            continue
        out["ok"] = True
        out["kind"] = type(key).__name__.replace("PrivateKey", "")
        out["public"] = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH).decode()
        # cryptography is not the parser that will read this key at run time, and
        # the two disagree: a key whose line breaks were lost in a paste loads
        # here and is refused by ssh with "invalid format" — measured, both ways.
        # So ssh is asked as well, because ssh has the last word.
        sok, swhy, spub = _ssh_can_load(raw)
        if not sok:
            out.update(ok=False, why=swhy or "ssh will not load that key")
        elif spub:
            out["public"] = spub
        return out
    if "-----BEGIN" not in raw or "-----END" not in raw:
        out["why"] = ("a private key begins with -----BEGIN and ends with "
                      "-----END, and this has neither")
    else:
        # The line-breaks case, which is what a paste through a chat window or a
        # spreadsheet cell does, and which reads as "corrupt" to ssh.
        body = [ln for ln in raw.splitlines() if "-----" not in ln]
        out["why"] = (f"the markers are there but the key will not parse "
                      f"({err[:90]})"
                      + (" — it is one long line, so the line breaks were lost "
                         "in the paste" if len(body) <= 1 else ""))
    return out


def _ssh_can_load(text: str) -> tuple[bool, str, str]:
    """Whether ssh itself will read this key, asked by making it read one.

    `ssh-keygen -y` loads a private key and prints its public half, using exactly
    the parser `ssh -i` uses during a run — so this is the only check whose answer
    is the one that matters. When ssh-keygen is not installed the check is skipped
    rather than failing a key that is probably fine: a source install without
    openssh-client cannot run a playbook at all, and that is said elsewhere.
    """
    tool = shutil.which("ssh-keygen", path=env.TOOL_PATH)
    if not tool:
        return True, "", ""
    work = tempfile.mkdtemp(prefix="keycheck-", dir=str(DATA))
    try:
        os.chmod(work, 0o700)
        path = os.path.join(work, "k")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        got = subprocess.run([tool, "-y", "-f", path], capture_output=True,
                             text=True, timeout=20)
        if got.returncode == 0:
            return True, "", (got.stdout or "").strip()
        said = (got.stderr or got.stdout or "").strip().splitlines()
        why = said[-1] if said else "ssh refused the key"
        # The same hint, from the side that actually rejects it.
        body = [ln for ln in text.splitlines() if "-----" not in ln]
        low = why.lower()
        # CHECKED BEFORE the message is read, because which words ssh picks
        # for a one-line key depend on its build: `invalid format` against
        # LibreSSL, `error in libcrypto` against OpenSSL. The shape is the
        # same fault either way and the shape is what can be acted on.
        if len(body) <= 1:
            why = ("ssh cannot read it: the key is one long line, so the line "
                   "breaks were lost in the paste. Paste it again from the file")
        elif "libcrypto" in low:
            # `error in libcrypto` READS LIKE A CRYPTO FAULT AND IS NOT ONE.
            # Measured in the portal's own image against OpenSSH 10 /
            # OpenSSL 3.5: plain text, an empty file, a `.pub`, a PuTTY `.ppk`,
            # a certificate and a truncated key ALL produce it. It is simply
            # ssh saying "this is not a private key I recognise" — so say that,
            # and name the files people actually pick by mistake. Passing the
            # raw text through sent somebody hunting for a broken cipher.
            why = ("ssh does not recognise that as a private key. It is the "
                   "answer ssh gives for the .pub half, a PuTTY .ppk, a "
                   "certificate, or a file that was cut short — check you "
                   "picked the private key itself, the file with no "
                   "extension. A .ppk must be converted first: PuTTYgen → "
                   "Conversions → Export OpenSSH key")
        elif "passphrase" in low:
            why = ("that key is protected by a passphrase, and a session has "
                   "nobody to type it. Store a key with no passphrase — "
                   "`ssh-keygen -p -f <key>` and an empty new passphrase "
                   "removes one from a copy")
        else:
            why = f"ssh cannot read it — {why.replace(path, 'the key')}"
        return False, why, ""
    except Exception as e:                                     # noqa: BLE001
        return True, f"{type(e).__name__}: {e}", ""
    finally:
        shutil.rmtree(work, ignore_errors=True)


def key_health(g: dict) -> dict:
    """What the group's stored key is, or what is wrong with it.

    On the group's own page, so a key that cannot be read is reported where it can
    be replaced — rather than at the top of a failed run, against a temporary file
    whose name means nothing to anybody.
    """
    if not g.get("key_sealed"):
        return {"state": "none" if not g.get("key_path") else "file",
                "why": "", "public": "", "kind": ""}
    got = read_key(secretbox.unseal(g["key_sealed"]))
    return {"state": "ok" if got["ok"] else "broken", "why": got["why"],
            "public": got["public"], "kind": got["kind"]}


KEY_KINDS = ("ed25519", "rsa")


def new_keypair(kind: str = "ed25519") -> tuple[str, str]:
    """A fresh pair: the private half in OpenSSH format, and the public line to
    append to a host's authorized_keys.

    ed25519 by default because it is short, fast, and accepted by every OpenSSH
    since 6.5. RSA because "every OpenSSH" is not the same as "every host": a
    build under a FIPS or hardened crypto policy leaves ed25519 out of
    PubkeyAcceptedAlgorithms, and then the key installs perfectly and the login is
    still refused. That failure is unreadable from the client side, so the choice
    exists — and the diagnosis further down names it when it happens.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    if kind == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} envmap-{_now()[:10]}"


def public_key_of(g: dict) -> tuple[str, str]:
    """The public half of whatever this group holds, or why there is none."""
    if not g.get("key_sealed"):
        return "", ("this group has no stored key" if not g.get("key_path")
                    else f"the key is a file on disk ({g['key_path']}); its "
                         f"public half is beside it, ending .pub")
    got = read_key(secretbox.unseal(g["key_sealed"]))
    return got["public"], got["why"]


# ── making a host reachable by key, given a password once ──────
# WHY THIS EXISTS
#     Every other route to key access asks somebody to do the work by hand:
#     generate a pair, paste the private half in here without breaking it, copy
#     the public half to every host. The pasted key is where it goes wrong — a
#     line-wrapped paste fails with ssh's "invalid format" on every host at once,
#     and the error names a temporary file nobody can look at.
#
#     So: give the portal the password once, and it does what ssh-copy-id does.
#     The password is used, never stored, never audited and never written to
#     disk; what remains afterwards is a key the runs already know how to use.
#
# HOW THE PASSWORD REACHES ssh
#     Not on the command line. `sshpass` puts it in argv, where every process on
#     the machine can read it out of `ps`, and that is not a thing to ship.
#
#     Not through a pty either, though that was the first attempt: ssh reads a
#     password from its CONTROLLING terminal, and a child started with
#     start_new_session has none — so it never prompted, and every host came back
#     "password refused" while the password was never asked for. Giving the child
#     a controlling terminal means setsid + TIOCSCTTY between fork and exec, which
#     in a process that runs playbooks on threads is exactly the kind of trick
#     that works until it deadlocks.
#
#     So: ssh's own hook for this. SSH_ASKPASS names a program ssh runs to obtain
#     the password, SSH_ASKPASS_REQUIRE=force makes it use that program rather
#     than a terminal, and the program is a two-line script in the same 0700
#     directory the private key is already written into — removed with it. Plain
#     subprocess, no fork hooks, no terminal, and nothing in argv.
PROMPT_YES = re.compile(rb"(?i)\(yes/no(/\[fingerprint\])?\)\?")
DENIED = re.compile(rb"(?i)permission denied|authentication failed")


def _askpass(work: str, password: str) -> str:
    """A program that prints the password, and the file it reads it from.

    The password is on disk for as long as the private key beside it is: a 0600
    file inside a 0700 directory that a `finally` removes. That is the boundary
    this module already lives with rather than a new one.
    """
    pw_path = os.path.join(work, "pw")
    fd = os.open(pw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(password)
    script = os.path.join(work, "askpass")
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"#!/bin/sh\nexec cat {shlex.quote(pw_path)}\n")
    return script


def _ssh_password(host: str, port: int, user: str, password: str, argv_tail: list,
                  known_hosts: str, work: str, askpass: str = "",
                  timeout: int = 30) -> tuple[int, str]:
    """One ssh command, authenticated by password. Returns (code, transcript).

    The transcript is what a person is shown when it fails, so the password is
    scrubbed from it — ssh does not echo it, but a transcript that carried one
    because some future prompt changed is not a thing to learn about later.
    """
    argv = [env.SSH, "-p", str(port or 22),
            # No key, no agent: this is the password path, and letting ssh try a
            # broken stored key first is how "invalid format" ends up in the
            # middle of a transcript about a password.
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no",
            "-o", f"ConnectTimeout={max(5, timeout // 3)}",
            # A throwaway known_hosts, so a first connection neither hangs on a
            # prompt nor writes into a file shared with everything else.
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts}",
            f"{user}@{host}"] + argv_tail
    runenv = {"PATH": env.TOOL_PATH, "HOME": work,
              "SSH_ASKPASS": askpass or _askpass(work, password),
              "SSH_ASKPASS_REQUIRE": "force",
              # For an ssh older than 8.4, which ignores REQUIRE and asks for a
              # DISPLAY before it will use an askpass program at all.
              "DISPLAY": os.environ.get("DISPLAY", ":0")}
    try:
        got = subprocess.run(argv, input="", capture_output=True, text=True,
                             timeout=timeout, env=runenv)
        rc, text = got.returncode, (got.stdout or "") + (got.stderr or "")
    except subprocess.TimeoutExpired:
        rc, text = 124, f"no answer within {timeout}s"
    except Exception as e:                                     # noqa: BLE001
        rc, text = 1, f"{type(e).__name__}: {e}"
    if password:
        text = text.replace(password, "********")
    return rc, text.replace("\r\n", "\n").strip()


# What sshd is asked when a key that IS in authorized_keys is still refused.
# Read-only, over the password connection that already works, because the client
# side of a refused public key says only "Permission denied" — the reason lives in
# sshd's config and its log, on the host.
DIAGNOSE = r"""
echo "## selinux"; getenforce 2>/dev/null || echo "not enabled"
echo "## home"; ls -ld ~ ~/.ssh 2>&1
echo "## file"; ls -l ~/.ssh/authorized_keys 2>&1
echo "## context"; (ls -ldZ ~/.ssh ~/.ssh/authorized_keys 2>/dev/null || echo none)
echo "## sshd"; (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null || echo "cannot read sshd config") | grep -Ei '^(authorizedkeysfile|pubkeyauthentication|pubkeyacceptedalgorithms|strictmodes|authorizedkeyscommand|permitrootlogin) ' || true
echo "## log"; (journalctl -u sshd -n 40 --no-pager 2>/dev/null || tail -n 60 /var/log/secure 2>/dev/null || tail -n 60 /var/log/auth.log 2>/dev/null || echo "no log readable") | grep -Ei 'refus|denied|invalid|not in|key type|authentication' | tail -5 || true
"""


def _why_refused(pub: str, facts: str) -> str:
    """Turn what the host said into the one sentence that names the cause.

    Four causes account for nearly every refused key, and each has a different
    fix — so "still fails" is not an answer worth printing when the host will say
    which one it is.
    """
    low = facts.lower()
    kind = pub.split()[0] if pub else ""
    # A key type and the signature algorithms it can produce are NOT the same
    # names: an RSA key is `ssh-rsa`, and a modern sshd accepts it under
    # `rsa-sha2-512`/`rsa-sha2-256`. Comparing the key type against the algorithm
    # list directly reported "this host does not accept ssh-rsa keys" about a host
    # that accepts them fine — measured, and a wrong diagnosis is worse than none.
    SIGS = {"ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
            "ssh-ed25519": ("ssh-ed25519",)}
    algs = ""
    for line in facts.splitlines():
        if line.lower().startswith("pubkeyacceptedalgorithms"):
            algs = line.split(" ", 1)[1] if " " in line else ""
    if kind and algs and not any(s in algs for s in SIGS.get(kind, (kind,))):
        return (f"this host does not accept {kind} keys: its "
                f"PubkeyAcceptedAlgorithms leaves them out, which is what a FIPS "
                f"or hardened crypto policy does. Choose "
                f"{'RSA' if kind == 'ssh-ed25519' else 'ed25519'} above and press "
                f"it again")
    if "not in pubkeyacceptedalgorithms" in low or "key type" in low:
        return (f"sshd refused the key's type ({kind or 'unknown'}). Choose the "
                f"other key type above and press it again")
    # Read from the listing rather than from a log: sshd's reason for this one is
    # only ever in its log, and plenty of hosts keep no log this can reach — but
    # the mode that causes it is right there in `ls -ld`.
    for line in facts.splitlines():
        bits_ = line.split()
        if (len(bits_) >= 9 and line.startswith("d")
                and bits_[-1].rstrip("/").endswith(("/root", "/home", ".ssh"))
                or (len(bits_) >= 9 and line.startswith("d")
                    and bits_[-1] in ("~", "."))):
            mode = line[:10]
            if mode[5] == "w" or mode[8] == "w":
                who_ = ("its group and everybody else"
                        if mode[5] == "w" and mode[8] == "w"
                        else "its group" if mode[5] == "w" else "everybody")
                return (f"sshd ignores the file because {bits_[-1]} is writable "
                        f"by {who_} ({mode}) — StrictModes refuses a home "
                        f"directory anyone else can write to. "
                        f"`chmod go-w {bits_[-1]}` on the host")
    if "bad ownership or modes" in low or "authentication refused" in low:
        return ("sshd will not read the file because of the permissions on it or "
                "on the home directory above it — StrictModes. The home "
                "directory must not be writable by group or other")
    if "enforcing" in low and "ssh_home_t" not in low and "## context" in facts:
        return ("SELinux is enforcing and the file is not labelled ssh_home_t, "
                "so sshd cannot read it. `restorecon -R -v ~/.ssh` on the host "
                "fixes it — the portal tried, and either it is not installed or "
                "the label is set by policy")
    for line in facts.splitlines():
        if line.lower().startswith("authorizedkeysfile") \
                and ".ssh/authorized_keys" not in line:
            return (f"sshd does not read keys from ~/.ssh/authorized_keys on this "
                    f"host — it is configured as `{line.strip()}`")
        if line.lower().startswith("authorizedkeyscommand") \
                and "none" not in line.lower():
            return (f"this host gets its keys from a command rather than a file "
                    f"(`{line.strip()}`), so a key written into "
                    f"authorized_keys is ignored")
        if line.lower().startswith("pubkeyauthentication no"):
            return "sshd has PubkeyAuthentication switched off entirely"
    return ""


def authorize_command(public: str) -> str:
    """The shell that puts one public key in place, idempotently.

    Matched on the key MATERIAL — the type and the base64 blob — and not on the
    whole line, which is also how sshd decides whether a key is authorised: the
    trailing comment is not part of the key. Whole-line matching looked stricter
    and was wrong twice over. A key installed here carries an `envmap-<date>`
    comment, while the same key derived from storage afterwards carries none, so
    `grep -qxF` missed it and appended a SECOND copy of the same key on every
    press — measured, two identical lines in authorized_keys. And a key somebody
    else had already installed with their own comment would never be recognised.

    The relabel at the end is not decoration either: on a RHEL-family host with
    SELinux enforcing, a .ssh created by this very command can end up labelled
    user_home_t, sshd runs as sshd_t and cannot read it, and the login is refused
    with the key sitting in the file and the permissions perfect. No-op elsewhere.
    """
    material = shlex.quote(" ".join(public.split()[:2]))
    whole = shlex.quote(public)
    return ("set -e; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
            "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; "
            f"if grep -qF {material} ~/.ssh/authorized_keys; then echo ALREADY; "
            f"else printf '%s\\n' {whole} >> ~/.ssh/authorized_keys; "
            "echo ADDED; fi; "
            "command -v restorecon >/dev/null 2>&1 && "
            "restorecon -R -F ~/.ssh >/dev/null 2>&1; true")


def refused_state(out: str, who: str) -> tuple[str, str]:
    """Why a login was refused, from what ssh printed.

    ssh names the methods the SERVER offered: "Permission denied (publickey)"
    with no `password` in that list means passwords are switched off entirely —
    a different problem with a different answer from a password that was simply
    wrong. Reported as one thing, it sends somebody to check a password that was
    never going to be read.
    """
    methods = re.search(r"Permission denied \(([^)]*)\)", out or "")
    offered = methods.group(1) if methods else ""
    if offered and "password" not in offered \
            and "keyboard-interactive" not in offered:
        return "no-password", (
            f"this host does not accept passwords at all (sshd offers only "
            f"{offered}), so a key cannot be installed this way — add the public "
            f"key by hand, it is on this page")
    return "denied", f"the password was refused for {who}"


def verify_or_explain(t: dict, keyfile: str, known: str, work: str, asker: str,
                      user: str, password: str, public: str) -> tuple[str, str]:
    """Log in with the key alone, and when that fails, say why.

    Separated from install_key so the failing path can be tested without a host
    that fails in that particular way: the client only ever says "Permission
    denied", and which of four things it is decides what somebody does next.
    """
    vrc, vout = _ssh_password_free_check(t, keyfile, known, user)
    if vrc == 0:
        return "", ""
    facts = ""
    if password:
        _drc, facts = _ssh_password(t["address"], t["port"], t["user"] or user,
                                   password, [DIAGNOSE], known, work, asker,
                                   timeout=40)
    named = _why_refused(public, facts)
    if named:
        return (f"the key is in authorized_keys but sshd will not accept it — "
                f"{named}"), facts
    return (f"the key is in authorized_keys but logging in with it still fails, "
            f"and the host did not say why — "
            f"{vout.splitlines()[-1][:110] if vout else ''}"), facts


def install_key(gid: str, user: str, password: str, who: str = "",
                confirm: str = "", key_type: str = "",
                only_hosts=()) -> dict:
    """Put this group's public key on its hosts, using the password once.

    Every host in the group by default, because that is the job — twenty machines
    is why this exists rather than twenty ssh-copy-id invocations. `only_hosts`
    narrows it to a chosen few, which is what an estate actually looks like: these
    six share a password, those two were built by somebody else and have another.
    Doing them one at a time meant typing the same password once per machine.

    Idempotent on the host: the key is appended only if it is not already there,
    so pressing the button twice changes nothing the second time. And it verifies
    afterwards with the key itself — "appended a line to a file" is not the same
    claim as "the portal can now log in", and only the second one is worth
    reporting.
    """
    g = group(gid)
    if not g:
        raise Refused("that group is gone")
    user = (user or g.get("ssh_user") or "").strip()
    if not user:
        raise Refused("which user should the key be installed for? Set the "
                      "group's ssh user, or name one here")
    if not password:
        raise Refused("the password is needed once, to install the key")
    if g.get("is_prod") and confirm.strip() != g["name"]:
        raise Refused(f"{g['name']} is marked production — type its name to "
                      f"confirm installing a key on its hosts")
    targets = _targets(g)
    want = [h for h in ([only_hosts] if isinstance(only_hosts, str)
                        else list(only_hosts)) if h]
    if want:
        known = {t["name"] for t in targets}
        # Named, not silently dropped: a checkbox for a host that has since been
        # removed must not turn into "the key went on everything".
        if (strays := [h for h in want if h not in known]):
            raise Refused(f"not in {g['name']}: {', '.join(sorted(strays)[:4])}")
        targets = [t for t in targets if t["name"] in set(want)]
    if not targets:
        raise Refused("this group has no hosts to install a key on")

    # An existing key is reused, so a group that already works keeps working and
    # a second host joins the same pair rather than a second one. Asking for a
    # different type replaces it, because the reason to ask is that the one stored
    # does not work on these hosts — and every host in the group is done in this
    # same pass, so none is left holding only the old one.
    public, why = public_key_of(g)
    kind = (key_type or "").strip().lower()
    if kind and kind not in KEY_KINDS:
        raise Refused(f"a key is {' or '.join(KEY_KINDS)}, not {kind!r}")
    wrong_kind = bool(kind and public and not public.split()[0].endswith(
        "ed25519" if kind == "ed25519" else "rsa"))
    generated = False
    if not public or wrong_kind:
        private, public = new_keypair(kind or "ed25519")
        with db.tx() as c:
            c.execute("UPDATE ansible_groups SET key_sealed = ?, key_path = '' "
                      "WHERE id = ?", (secretbox.seal(private), gid))
        generated = True

    remote = authorize_command(public)

    work = tempfile.mkdtemp(prefix="ansible-keys-", dir=str(DATA))
    os.chmod(work, 0o700)
    # One askpass program for the whole pass: it was created per connection, and
    # the second connection to the same host — the diagnosis below — raised
    # FileExistsError on its own O_EXCL.
    asker = _askpass(work, password)
    keyfile = os.path.join(work, "id_key")
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        text = secretbox.unseal(group(gid)["key_sealed"])
        fh.write(text if text.endswith("\n") else text + "\n")

    def one(t: dict) -> tuple:
        """One host, start to finish: install, then prove it, then explain.

        Its OWN known_hosts file. `accept-new` writes to that file, and twenty
        hosts writing to one file at the same time is twenty appends racing over
        the same offsets — the kind of corruption that shows up later as a host
        key warning nobody can explain.
        """
        mine = os.path.join(work, f"kh-{abs(hash(t['name'])) % 10**9}")
        # The key first, and only then the password. Pressing this again on a host
        # that is already keyed used to authenticate with the password all over
        # again — so a wrong password reported `denied` about a host that was
        # working perfectly, and a host that had since switched password auth OFF
        # (which is the point of installing a key) could never be confirmed again.
        # Skipped right after generating a key, because nothing can be holding one
        # that was made a moment ago.
        if not generated:
            vrc, _vout = _ssh_password_free_check(t, keyfile, mine, user)
            if vrc == 0:
                return {**t, "state": "already",
                        "note": "the key already works here"}, ""
        rc, out = _ssh_password(t["address"], t["port"], t["user"] or user,
                                password, [remote], mine, work, asker)
        state, note = "failed", out.splitlines()[-1][:180] if out else "no output"
        if rc == 0 and "ALREADY" in out:
            state, note = "already", "the key was already authorised"
        elif rc == 0 and "ADDED" in out:
            state, note = "installed", "the key was added"
        elif DENIED.search(out.encode()):
            state, note = refused_state(out, t["user"] or user)
        facts = ""
        # Say it works, rather than saying a line was appended: the verify is the
        # only step whose success means what the page claims.
        if state in ("installed", "already"):
            trouble, facts = verify_or_explain(
                t, keyfile, mine, work, asker, user, password, public)
            if trouble:
                state, note = "half", trouble
        return {**t, "state": state, "note": note}, facts

    # All the hosts at once. Each one is an SSH handshake, a password exchange, a
    # remote shell and a second handshake to verify — about two seconds of waiting
    # per host, and a group is a fleet. Bounded, because a hundred hosts should not
    # be a hundred simultaneous connections from one pod.
    try:
        from . import fleet
        got = fleet._pmap(one, targets, workers=min(8, len(targets)))
        # `res`, not `g`: `g` is the group two dozen lines up, and reusing the
        # name here rebound it to a tuple — which the audit line then indexed by
        # string. The same shadowing this file has been bitten by before.
        rows = [res[0] for res in got if res]
        rows_facts = [(res[0]["name"], res[1]) for res in got if res and res[1]]
        # A thread that died leaves None in its slot; a host silently dropped from
        # the report is worse than one reported as failed.
        for target, res in zip(targets, got):
            if not res:
                rows.append({**target, "state": "failed",
                             "note": "the portal lost track of this one"})
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = [r for r in rows if r["state"] in ("installed", "already")]
    if who:
        # The password is not in here, and neither is the key: what is auditable
        # is that this account authorised itself on these machines.
        from . import auth as _auth
        _auth.audit({"email": who}, "ansible_key_installed", g["name"],
                    f"{len(ok)}/{len(rows)} host(s)"
                    + (" · key generated" if generated else " · existing key"))
    return {"rows": rows, "public": public, "generated": generated,
            "ok": len(ok), "total": len(rows), "why": why,
            # the raw answers, so a cause the rules above do not recognise is
            # still in front of somebody rather than thrown away
            "facts": dict(rows_facts)}


def _ssh_password_free_check(t: dict, keyfile: str, known: str,
                             user: str) -> tuple[int, str]:
    """Can the portal log in with the key alone. BatchMode so it cannot fall
    back to a prompt and appear to succeed because somebody typed something."""
    argv = [env.SSH, "-p", str(t["port"] or 22), "-i", keyfile,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known}",
            f"{t['user'] or user}@{t['address']}", "true"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        return r.returncode, (r.stderr or r.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as e:                                     # noqa: BLE001
        return 1, f"{type(e).__name__}: {e}"


def _targets(g: dict) -> list:
    """Every host in the group as something to connect to.

    The same rule the inventory file uses — a typed address, else the address the
    server inventory holds, else the name for DNS to resolve — because a key
    installed on whatever answers a different address is a key installed nowhere
    useful.
    """
    hosts = g.get("hosts") or hosts_of(g["id"])
    live = _asset_addresses(hosts)
    out = []
    for h in hosts:
        addr = (h.get("address") or "").strip() or live.get(h.get("asset_id") or "")
        out.append({"name": h["name"], "address": addr or h["name"],
                    "user": (h.get("ssh_user") or "").strip(),
                    "port": h.get("ssh_port") or g.get("ssh_port") or 22})
    return out



# ── an interactive shell on an inventory host ──────────────────
# WHY THIS EXISTS
#     The cluster page already gives a real terminal into a pod, and the
#     machinery — a pty wrapping an argv, a websocket, xterm.js — is generic.
#     A DevOps person spends as much time on the VMs in an Ansible group as in
#     any pod, and reaching them meant leaving the portal for a terminal with
#     the key in hand. This is the same door, onto a host instead of a pod.
#
# THE KEY IS THE GROUP'S
#     No password path here: a terminal is interactive and long-lived, and the
#     answer to "how do I get on this box" the portal already holds is the
#     group's key. A group with no key cannot open one — the message says to set
#     one up, which is the button already on the group's page.
#
# GATED LIKE A RUN
#     Opening a shell on a host is at least what running a playbook against it
#     is, so it takes the ansible_run area, and a production group demands its
#     name typed — the same confirm a real run does.
def host_shell_argv(g: dict, host: str, keyfile: str, known: str) -> list:
    """The ssh command for an interactive session, or raise Refused.

    Built as a list, never a string: the host name and user come from the
    group's own inventory, but they are still shaped-checked, because a shell is
    the one place a smuggled `-o ProxyCommand=…` would be a remote command
    execution rather than a broken connection.
    """
    target = next((t for t in _targets(g) if t["name"] == host), None)
    if not target:
        raise Refused(f"{host} is not a host in {g['name']}")
    addr = target["address"]
    user = target["user"] or g.get("ssh_user") or ""
    if not user:
        raise Refused("no SSH user is set for this host or its group")
    for label, v in (("address", addr), ("user", user)):
        # addresses and names from the inventory; anything with a space, a flag
        # dash at the front, or shell metacharacters was not built by the page
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,253}", v or ""):
            raise Refused(f"the {label} {v!r} is not one ssh will take safely")
    return [env.SSH, "-tt", "-i", keyfile,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",          # never fall back to a password prompt
            "-o", "PreferredAuthentications=publickey",
            "-o", f"ConnectTimeout={config()['ssh_timeout']}",
            "-o", ("StrictHostKeyChecking=accept-new"
                   if g.get("host_key_checking") is None
                   or g.get("host_key_checking") else "StrictHostKeyChecking=no"),
            "-o", f"UserKnownHostsFile={known}",
            "-p", str(target["port"] or 22), f"{user}@{addr}"]


def _term_scratch() -> str:
    """A 0700 directory for one terminal session's key and known_hosts, on a
    path with NO spaces.

    ssh's `-o UserKnownHostsFile` takes its value as a space-separated LIST of
    files, so a data dir like '/Users/…/Claude Folder Main/…' is torn into three
    filenames and the host key is written to the wrong one — the symptom is
    "Failed to add the host to the list of known hosts (/Users/…/Claude)". The
    run path already dodges the same edge for ControlPath by living under /tmp;
    a terminal's scratch does too. The data dir is preferred when it happens to
    be clean, so a container install (DATA=/data) keeps the key inside its own
    volume rather than in /tmp.
    """
    bases = ([str(DATA)] if " " not in str(DATA) else []) + ["/tmp", None]
    for base in bases:
        try:
            d = tempfile.mkdtemp(prefix="ansible-term-", dir=base)
        except OSError:
            continue
        if " " not in d:
            os.chmod(d, 0o700)
            return d
        shutil.rmtree(d, ignore_errors=True)         # the default tmp had a space
    raise Refused("no space-free scratch directory is available for a terminal")


def drop_session_dir(path: str) -> None:
    """Remove a terminal session's scratch dir — only ever one _term_scratch made.

    Guarded by the prefix rather than by "is it under DATA", because the scratch
    now lives under /tmp on any install whose data path has a space in it.
    """
    if path and os.path.basename(path).startswith("ansible-term-") \
            and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def host_shell(g: dict, host: str, rows: int = 24, cols: int = 100):
    """A pty running ssh into one host of a group. Same _Pty the pod shell uses,
    but raw_master=False — see kmanage._Pty for why ssh needs the slave cooked.

    Writes the key to a 0600 file in a per-session scratch dir that the caller
    removes when the socket closes (drop_session_dir) — the key is on disk only
    while the terminal is open, exactly as a run's key is only on disk while the
    run goes.
    """
    from . import kmanage           # the pty lives with the other pty
    if not g:
        raise Refused("that group is gone")
    work = _term_scratch()
    try:
        if g.get("key_sealed"):
            keyfile = os.path.join(work, "id_key")
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                text = secretbox.unseal(g["key_sealed"])
                fh.write(text if text.endswith("\n") else text + "\n")
        elif g.get("key_path"):
            keyfile = g["key_path"]
        else:
            raise Refused("this group has no key — set one up on its page, then "
                          "a terminal can use it")
        known = os.path.join(work, "known_hosts")
        argv = host_shell_argv(g, host, keyfile, known)
        term = kmanage._Pty(argv, rows, cols, raw_master=False)
    except Exception:
        drop_session_dir(work)
        raise
    # the directory rides on the terminal so the socket handler can drop it when
    # the session ends, and never before
    term.workdir = work
    return term


def delete_group(gid: str) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM ansible_hosts WHERE group_id = ?", (gid,))
        c.execute("DELETE FROM ansible_groups WHERE id = ?", (gid,))


def _label(v) -> str:
    """A host's human label: free text, but not a newline and not a novel.

    Deliberately NOT `NAME_OK` — the whole point of a label is that it says
    something an inventory name cannot ("KE preprod WAF, rack 4"), so spaces
    and punctuation are the feature. Control characters go because this is
    rendered in tables and written into inventory files.
    """
    txt = "".join(" " if ch.isspace() else ch for ch in str(v or "")
                  if ch.isprintable() or ch.isspace())
    return " ".join(txt.split())[:120]


def add_host(gid: str, name: str, address: str, who: str, asset_id: str = "",
             ssh_user: str = "", ssh_port: int = 0, host_vars: str = "",
             env: str = "", label: str = "") -> str:
    name = (name or "").strip()
    if not NAME_OK.match(name):
        raise Refused(f"{name or 'that'} is not a usable inventory name — "
                      "letters, digits, dot, dash and underscore")
    if not _conn().execute("SELECT 1 FROM ansible_groups WHERE id = ?",
                           (gid,)).fetchone():
        raise Refused("that group no longer exists")
    hid = "ah-" + uuid.uuid4().hex[:10]
    with db.tx() as c:
        if c.execute("SELECT 1 FROM ansible_hosts WHERE group_id=? AND name=?",
                     (gid, name)).fetchone():
            raise Refused(f"{name} is already in this group")
        c.execute("""INSERT INTO ansible_hosts (id, group_id, name, address,
                     asset_id, ssh_user, ssh_port, host_vars, env, label,
                     created, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (hid, gid, name, (address or "").strip(), asset_id or "",
                   (ssh_user or "").strip(), int(ssh_port or 0) or None,
                   host_vars or "", (env or "").strip().lower()[:40],
                   _label(label), _now(), who))
    return hid


def host(hid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM ansible_hosts WHERE id = ?",
                        (hid,)).fetchone()
    return dict(r) if r else None


def describe_host(hid: str, hostname: str, label: str, who: str) -> dict:
    """Set only the two fields that DESCRIBE a host: its own name and a label.

    WHY THIS IS SEPARATE FROM `update_host`. An inventory host is edited in
    Ansible and read-only in Privileged Access, because its address, port,
    user and credential are the group's business and changing them there would
    move what a playbook runs against. But the catalogue in Privileged Access
    is where somebody is actually looking at a row of IP addresses trying to
    work out which machine it is -- and a hostname and a label change nothing
    about how anything connects. So those two, and only those two, can be set
    from either page.

    WRITTEN BACK TO THE INVENTORY, not kept beside it. One row, so the label
    somebody types in Privileged Access is the label the Ansible page shows,
    and there is no second copy to disagree.
    """
    row = host(hid)
    if not row:
        raise Refused("that host no longer exists")
    hostname = (hostname or "").strip()[:253]
    label = (label or "").strip()[:120]
    # A hostname is a name, not a sentence: it goes into inventory output and
    # into ssh's own known_hosts handling, so the shape is checked.
    if hostname and not HOST_OK.match(hostname):
        raise Refused("a hostname may hold letters, digits, dot, dash and "
                      "underscore, and must start with a letter or digit")
    with db.tx() as c:
        c.execute("UPDATE ansible_hosts SET hostname=?, label=? WHERE id=?",
                  (hostname, label, hid))
    return {"id": hid, "name": row["name"],
            "hostname": hostname, "label": label}


def update_host(hid: str, fields: dict, who: str) -> None:
    """Edit an existing inventory host — its name, address, ssh user/port,
    environment and variables. The name stays unique within its group."""
    row = host(hid)
    if not row:
        raise Refused("that host no longer exists")
    name = (fields.get("name") or "").strip()
    if not NAME_OK.match(name):
        raise Refused(f"{name or 'that'} is not a usable inventory name — "
                      "letters, digits, dot, dash and underscore")
    port = fields.get("ssh_port") or 0
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        raise Refused("the SSH port has to be a number")
    if port and not 1 <= port <= 65535:
        raise Refused("the SSH port has to be between 1 and 65535")
    with db.tx() as c:
        clash = c.execute("SELECT 1 FROM ansible_hosts WHERE group_id=? AND "
                          "name=? AND id<>?", (row["group_id"], name, hid)).fetchone()
        if clash:
            raise Refused(f"{name} is already in this group")
        c.execute("""UPDATE ansible_hosts SET name=?, address=?, ssh_user=?,
                     ssh_port=?, host_vars=?, env=?, label=? WHERE id=?""",
                  (name, (fields.get("address") or "").strip(),
                   (fields.get("ssh_user") or "").strip(), port or None,
                   fields.get("host_vars") or "",
                   (fields.get("env") or "").strip().lower()[:40],
                   _label(fields.get("label")), hid))


def add_hosts_text(gid: str, text: str, who: str) -> tuple[int, list]:
    """Hosts pasted in, one per line, as `name address` or just one of the two.

    WHY A TEXTAREA AND NOT ONLY THE PER-HOST FORM
        A group is created and then has hosts added to it, and the create form
        said nothing about the second half — so the first question anybody asked
        after making a group was "where do I put the addresses". Somebody who
        already has an inventory has the addresses in a list; typing them into
        four fields each is work the page invented.

    Deliberately forgiving about the separator (space, tab or comma) and about
    which of the two is present:

        web-1 10.20.0.11     a name and where to reach it
        web-2                a name ansible will resolve by itself
        10.20.0.13           an address, which is also its name in the inventory

    Anything that cannot be a host name is skipped and named, rather than
    failing the whole paste: half a list rejected because line nine had a typo
    means retyping the eight that were fine.
    """
    added, skipped = 0, []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p for p in re.split(r"[,\s]+", line) if p]
        name, address = parts[0], (parts[1] if len(parts) > 1 else "")
        if len(parts) > 2:
            skipped.append(f"{line[:40]}: more than a name and an address")
            continue
        try:
            add_host(gid, name, address, who)
            added += 1
        except Refused as e:
            skipped.append(f"{name}: {e}")
    return added, skipped


def delete_host(hid: str) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM ansible_hosts WHERE id = ?", (hid,))


def from_inventory(gid: str, asset_ids: list, who: str) -> tuple[int, list]:
    """Add hosts from the server inventory the portal already holds.

    The asset id is kept, so `inventory_text` reads the address out of the
    inventory at run time. An address copied at import is an address that is
    right until somebody re-IPs a machine and then quietly points a playbook at
    whatever answers on the old one.
    """
    from . import assets
    added, skipped = 0, []
    for aid in asset_ids:
        row = assets.get(aid)
        if not row:
            skipped.append(f"{aid}: no longer in the inventory")
            continue
        name = (row.get("hostname") or "").strip()
        if not NAME_OK.match(name or ""):
            skipped.append(f"{name or aid}: not a usable inventory name")
            continue
        try:
            add_host(gid, name, "", who, asset_id=aid)
            added += 1
        except Refused as e:
            skipped.append(f"{name}: {e}")
    return added, skipped


def _asset_facts(hosts: list) -> dict:
    """{asset_id: {"address", "hostname"}} for the hosts that came from the
    inventory, in ONE query rather than a `get()` each."""
    ids = [h["asset_id"] for h in hosts if h.get("asset_id")]
    if not ids:
        return {}
    from . import assets
    return {aid: {"address": (a.get("ip") or a.get("hostname") or "").strip(),
                  "hostname": (a.get("hostname") or "").strip()}
            for aid, a in assets.many(ids).items()}


def _asset_addresses(hosts: list) -> dict:
    """{asset_id: address} — the shape the inventory writer reads."""
    return {k: v["address"] for k, v in _asset_facts(hosts).items()}


def inventory_text(g: dict) -> str:
    """The group as a YAML inventory — exactly what ansible is given.

    Shown on the page as well as written to the temp file, because "what does
    ansible actually think my inventory is" is the first question of every
    Ansible problem, and the honest answer is this file.
    """
    hosts = g.get("hosts") or hosts_of(g["id"])
    live = _asset_addresses(hosts)
    lines = ["all:", "  children:", f"    {g['name']}:", "      hosts:"]
    if not hosts:
        lines[-1] = "      hosts: {}"
    for h in hosts:
        lines.append(f"        {h['name']}:")
        addr = (h.get("address") or "").strip() or live.get(h.get("asset_id") or "")
        if addr:
            lines.append(f"          ansible_host: {addr}")
        if h.get("ssh_user"):
            lines.append(f"          ansible_user: {h['ssh_user']}")
        if h.get("ssh_port"):
            lines.append(f"          ansible_port: {h['ssh_port']}")
        for line in _indent_block(h.get("host_vars") or "", 10):
            lines.append(line)
    gvars = ["      vars:"]
    if g.get("ssh_user"):
        gvars.append(f"        ansible_user: {g['ssh_user']}")
    if g.get("ssh_port"):
        gvars.append(f"        ansible_port: {g['ssh_port']}")
    if g.get("become_root"):
        gvars.append("        ansible_become: true")
    gvars.extend(_indent_block(g.get("group_vars") or "", 8))
    if len(gvars) > 1:
        lines.extend(gvars)
    return "\n".join(lines) + "\n"


def _indent_block(text: str, spaces: int) -> list:
    """A user's `key: value` lines, re-indented to sit under a host or group.

    Blank lines and comments are dropped rather than indented: a comment at the
    wrong indentation is still a comment, but a blank line inside a mapping is
    how a hand-built YAML file becomes two documents.
    """
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(" " * spaces + line)
    return out


# ── runs ───────────────────────────────────────────────────────
def runs(limit: int = 100, pb_id: str = "", group_id: str = "") -> list:
    """The run history, newest first, optionally for one playbook or one group.

    `group_id` filters on the id rather than on the name the run was recorded
    with: a group that has been renamed since still owns its runs, and matching
    on the name would quietly drop them from its page.
    """
    q = ("SELECT id, pb_id, pb_name, group_id, group_name, hosts, check_mode,"
         " status, rc, limit_to, tags, started, finished, by,"
         # aliased: the bare `pid` column on THIS table is the process id
         " proj_id AS pid, rgn_id AS rgid,"
         " LENGTH(output) len, stats, why FROM ansible_runs")
    where, args = [], []
    if pb_id:
        where.append("pb_id = ?")
        args.append(pb_id)
    if group_id:
        where.append("group_id = ?")
        args.append(group_id)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY started DESC, rowid DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    out = []
    for r in _conn().execute(q, args):
        row = dict(r)
        row["stats"] = json.loads(row.get("stats") or "{}")
        row["took"] = _took(row.get("started"), row.get("finished"))
        row["ago"] = ago(row.get("started"))
        out.append(row)
    return out


def run(run_id: str, since: int = 0) -> dict | None:
    """One run, with its output from `since` bytes on.

    The offset is what makes the window able to follow a run without re-reading
    a megabyte a second: the page asks for what it has not seen, and gets that
    plus where to ask from next time.
    """
    r = _conn().execute("SELECT * FROM ansible_runs WHERE id = ?",
                        (run_id,)).fetchone()
    if not r:
        return None
    row = dict(r)
    text = row.pop("output", "") or ""
    row["stats"] = json.loads(row.get("stats") or "{}")
    row["took"] = _took(row.get("started"), row.get("finished"))
    row["text"] = text[since:] if since and since < len(text) else (
        "" if since >= len(text) else text)
    row["at"] = len(text)
    row["done"] = row.get("status") != STATUS_RUNNING
    return row


def _dur_words(secs: int) -> str:
    """A duration as "3h 4m" / "4m 20s" / "8s". Used by the PAM session views,
    which import it — it lives here with the other time helpers."""
    secs = max(0, int(secs or 0))
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def ago(ts: str) -> str:
    """How long ago, in the shortest form that is still unambiguous."""
    if not ts:
        return ""
    try:
        then = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    secs = max(0, int((datetime.now(timezone.utc) - then).total_seconds()))
    if secs < 60:
        return "just now"
    for size, unit in ((3600, "m"), (86400, "h"), (86400 * 30, "d")):
        if secs < size:
            step = size // (60 if unit == "m" else (3600 if unit == "h" else 86400))
            return f"{secs // (size // step)}{unit} ago"
    return then.date().isoformat()


def _took(started: str, finished: str) -> str:
    if not started:
        return ""
    try:
        a = datetime.fromisoformat(started)
        b = datetime.fromisoformat(finished) if finished else datetime.now(timezone.utc)
    except ValueError:
        return ""
    secs = max(0, int((b - a).total_seconds()))
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m {secs % 60}s"


def running() -> list:
    return [dict(r) for r in _conn().execute(
        "SELECT id, pb_name, group_name, started, by, pid FROM ansible_runs "
        "WHERE status = ? ORDER BY started", (STATUS_RUNNING,))]


_live: dict = {}                    # run id → Popen, for cancelling
_lock = threading.Lock()


def start(pb_id: str, gid: str, who: str, check: bool = True,
          limit_to: str = "", tags: str = "", extra_vars: str = "",
          allow_real: bool = True, confirm: str = "") -> str:
    """Validate everything, write the run row, then start the process.

    The order is deliberate. Every reason to refuse is found before anything is
    written, so a refusal leaves no half-run behind; and the row exists before
    the process does, so a run can never be alive with nothing to attach it to.
    """
    probe = tool()
    if not probe["found"]:
        raise Refused(probe["error"] or "ansible-playbook is not installed")
    pb = playbook(pb_id)
    if not pb:
        raise Refused("that playbook no longer exists")
    if not (pb.get("body") or "").strip():
        raise Refused("that playbook is empty")
    g = group(gid)
    if not g:
        raise Refused("choose a group of hosts to run against")
    if not g["hosts"]:
        raise Refused(f"{g['name']} has no hosts in it yet")
    if limit_to and not LIMIT_OK.match(limit_to):
        raise Refused("a limit may hold host names, groups and the usual "
                      "patterns — nothing else")
    if tags and not TAGS_OK.match(tags):
        raise Refused("tags are a comma-separated list of names")
    if extra_vars:
        try:
            parsed = json.loads(extra_vars)
        except ValueError as e:
            raise Refused(f"the extra variables are not valid JSON: {e}")
        if not isinstance(parsed, dict):
            raise Refused("the extra variables have to be a JSON object")
    if not check:
        if not allow_real:
            raise Refused("real runs are switched off for this installation — "
                          "Settings → Ansible. A check run still works.")
        if g["is_prod"] and confirm.strip() != g["name"]:
            raise Refused(f"{g['name']} is marked production: type its name to "
                          f"confirm a real run")
    with _lock:
        if len(running()) >= MAX_CONCURRENT:
            raise Refused(f"{MAX_CONCURRENT} runs are already going — wait for "
                          f"one to finish")
        same = _conn().execute(
            "SELECT id FROM ansible_runs WHERE status=? AND pb_id=? AND group_id=?",
            (STATUS_RUNNING, pb_id, gid)).fetchone()
        if same:
            raise Refused("this playbook is already running against this group")
        run_id = "ar-" + uuid.uuid4().hex[:12]
        with db.tx() as c:
            # The group's CURRENT place, frozen onto the run: reassigning the
            # group to another project later must not rewrite what this run
            # belonged to when it happened.
            c.execute("""INSERT INTO ansible_runs
                (id, pb_id, pb_name, group_id, group_name, hosts, check_mode,
                 limit_to, tags, extra_vars, cmd, status, output, started, by,
                 proj_id, rgn_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (run_id, pb_id, pb["name"], gid, g["name"],
                       len(g["hosts"]), 1 if check else 0, limit_to, tags,
                       extra_vars, "", STATUS_RUNNING, "", _now(), who,
                       g.get("pid") or "", g.get("rgid") or ""))
    threading.Thread(target=_execute, name=f"ansible-{run_id}",
                     args=(run_id, pb, g, check, limit_to, tags, extra_vars),
                     daemon=True).start()
    return run_id


def _adhoc_group(name: str, hosts: list, private_key: str, become: bool,
                 ssh_user: str) -> dict:
    """A throwaway group dict for an ad-hoc run — the runner is driven entirely by
    a group dict (inventory_text / argv_for / _execute all read it), so a run
    against hosts that are NOT in any saved group is just this dict, never
    persisted. `host_key_checking` is off because a freshly-built VM's host key
    has never been seen before."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name or "provisioned") or "provisioned"
    return {"id": "", "name": safe, "hosts": hosts, "become_root": bool(become),
            "ssh_user": ssh_user, "ssh_port": 22, "host_key_checking": False,
            "is_prod": False, "group_vars": "", "pid": "", "rgid": "",
            "key_sealed": secretbox.seal(private_key) if private_key else ""}


def run_adhoc(pb_id: str, name: str, hosts: list, private_key: str, who: str,
              become: bool = True, ssh_user: str = "", allow_real: bool = True) -> str:
    """Run a playbook against ad-hoc hosts (an IP + user + a supplied private key),
    NOT a saved group — used by the provisioner to configure a fresh VM the moment
    it is reachable. Same runner, inventory format and follow API (`run()`) as
    `start()`; the group is the throwaway dict above. `hosts` is a list of
    `{name, address, ssh_user?}`. Returns the run id."""
    probe = tool()
    if not probe["found"]:
        raise Refused(probe["error"] or "ansible-playbook is not installed")
    if not allow_real:
        raise Refused("real Ansible runs are switched off for this installation — "
                      "Settings → Ansible")
    pb = playbook(pb_id)
    if not pb:
        raise Refused("that playbook no longer exists")
    if not (pb.get("body") or "").strip():
        raise Refused("that playbook is empty")
    hosts = [h for h in (hosts or []) if (h.get("address") or "").strip()]
    if not hosts:
        raise Refused("no reachable host to run the playbook against")
    if not (private_key or "").strip():
        raise Refused("no SSH key to reach the host with")
    g = _adhoc_group(name, hosts, private_key, become, ssh_user)
    with _lock:
        if len(running()) >= MAX_CONCURRENT:
            raise Refused(f"{MAX_CONCURRENT} runs are already going — wait for one to finish")
        run_id = "ar-" + uuid.uuid4().hex[:12]
        with db.tx() as c:
            c.execute("""INSERT INTO ansible_runs
                (id, pb_id, pb_name, group_id, group_name, hosts, check_mode,
                 limit_to, tags, extra_vars, cmd, status, output, started, by,
                 proj_id, rgn_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (run_id, pb_id, pb["name"], "", g["name"], len(hosts), 0,
                       "", "", "", "", STATUS_RUNNING, "", _now(), who, "", ""))
    threading.Thread(target=_execute, name=f"ansible-{run_id}",
                     args=(run_id, pb, g, False, "", "", ""), daemon=True).start()
    return run_id


def cancel(run_id: str, who: str) -> bool:
    """Stop a run. SIGTERM to the process group, so a task's ssh dies with it.

    A cancelled run is finished with its output intact — half a run is still the
    record of what reached the hosts before somebody pressed stop, and that is
    exactly what you want to read afterwards.
    """
    proc = _live.get(run_id)
    if not proc:
        return False
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:                                        # noqa: BLE001
            return False
    _append(run_id, f"\n[cancelled by {who}]\n")
    return True


def _write_files(work: str, pb: dict, g: dict, extra_vars: str) -> dict:
    """The playbook, the inventory, the key and the variables, on disk.

    In a 0700 directory that is removed in a `finally`. The key is written with
    0600 before anything is written into it — creating it readable and then
    tightening it leaves a window, however short, in which another process on
    the host could read a private key out of a temp file.
    """
    paths = {}
    pb_path = os.path.join(work, "playbook.yml")
    with open(pb_path, "w") as fh:
        fh.write(pb.get("body") or "")
    paths["playbook"] = pb_path

    inv_path = os.path.join(work, "inventory.yml")
    with open(inv_path, "w") as fh:
        fh.write(inventory_text(g))
    paths["inventory"] = inv_path

    if g.get("key_sealed"):
        key_path = os.path.join(work, "id_key")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            text = secretbox.unseal(g["key_sealed"])
            fh.write(text if text.endswith("\n") else text + "\n")
        paths["key"] = key_path
    elif g.get("key_path"):
        paths["key"] = g["key_path"]

    if extra_vars:
        var_path = os.path.join(work, "extra.json")
        with open(var_path, "w") as fh:
            fh.write(extra_vars)
        paths["vars"] = var_path
    return paths


def argv_for(pb: dict, g: dict, paths: dict, check: bool, limit_to: str,
             tags: str) -> list:
    """The command, built as a list and never as a string.

    Separated out so a test can read the argv without running anything — the
    guarantee worth testing is that `--check` is present when it should be and
    that nothing a person typed can become another flag.
    """
    argv = [tool()["path"] or env.ANSIBLE, "-i", paths["inventory"],
            paths["playbook"], "--forks", str(config()["forks"])]
    if check:
        argv.append("--check")
    if g.get("become_root"):
        argv.append("--become")
    if paths.get("key"):
        argv += ["--private-key", paths["key"]]
    if limit_to:
        argv += ["--limit", limit_to]
    if tags:
        argv += ["--tags", tags]
    if paths.get("vars"):
        argv += ["--extra-vars", "@" + paths["vars"]]
    return argv


# The longest a unix socket path may be: 104 bytes on macOS and the BSDs, 108 on
# Linux. ssh refuses a ControlPath over the limit before it dials anything, so it
# is the smaller number that matters.
SOCK_MAX = 104
# ssh's own hash of (local host, remote host, port, user) — 64 hex characters,
# the same length whatever the host is called. The default name carries the
# hostname instead, so a long FQDN alone can push a socket over the limit.
CP_NAME = "%(directory)s/%%C"


def control_path_dir(work: str) -> str:
    """Where ssh keeps its multiplexing sockets for one run.

    NOT under `work`, which is what it used to be by inheriting HOME. A run
    directory sits inside the portal's data directory, and the whole path plus
    ansible's socket name went past 104 bytes on any install whose data lives
    somewhere with a real name — a Mac checkout, or /var/lib/something/data.
    ssh then answers "ControlPath too long" and every host in the group comes
    back UNREACHABLE, which reads exactly like the hosts being down.

    So: a short directory of our own, per run, created 0700 by mkdtemp — which
    refuses to reuse an existing path, so a symlink planted in a shared /tmp is
    not something to be careful about. Falls back to `work` only if /tmp cannot
    be used at all, because the old behaviour is still better than no run.
    """
    for base in ("/tmp", None):
        try:
            got = tempfile.mkdtemp(prefix="envmap-cp-", dir=base) if base \
                else os.path.join(work, "cp")
            if not base:
                os.makedirs(got, mode=0o700, exist_ok=True)
            # A socket that will not fit is not worth having: say so here rather
            # than letting ssh say it once per host.
            if len(got) + 1 + 64 <= SOCK_MAX:
                return got
        except OSError:
            continue
    return os.path.join(work, "cp")


def env_for(g: dict, work: str) -> dict:
    """Ansible's environment: predictable output, no writing outside `work`.

    `ANSIBLE_CONFIG` is pointed at nothing on purpose. Otherwise ansible walks up
    from the working directory looking for an `ansible.cfg` and can pick up
    whatever happens to be in the portal's data volume — which is a
    configuration nobody chose and cannot see.
    """
    out = {
        "PATH": env.TOOL_PATH,
        "HOME": work,
        "TMPDIR": work,
        "ANSIBLE_CONFIG": os.path.join(work, "ansible.cfg"),
        "ANSIBLE_LOCAL_TEMP": os.path.join(work, ".ansible-tmp"),
        # Multiplexing stays on — it is most of the reason a playbook with twenty
        # tasks is not twenty SSH handshakes — but the socket lives somewhere
        # short. See control_path_dir().
        "ANSIBLE_SSH_CONTROL_PATH_DIR": control_path_dir(work),
        "ANSIBLE_SSH_CONTROL_PATH": CP_NAME,
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_NOCOWS": "1",
        "ANSIBLE_RETRY_FILES_ENABLED": "0",
        # The page shows one stream of text, so the callback has to be the plain
        # one. A default of `yaml` or a fancy callback in an image would turn
        # every run's output into something the page's own parsing cannot read.
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_HOST_KEY_CHECKING":
            "False" if not g.get("host_key_checking") else "True",
        # A host that is down must not hold the run for ansible's default 10s
        # ×3 retries per task; this is the one knob that decides how long a
        # playbook takes to fail against a machine that is simply off.
        "ANSIBLE_TIMEOUT": str(config()["ssh_timeout"]),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    with open(out["ANSIBLE_CONFIG"], "w") as fh:
        fh.write("[defaults]\nlocal_tmp = "
                 + out["ANSIBLE_LOCAL_TEMP"] + "\n")
    return out


def _execute(run_id: str, pb: dict, g: dict, check: bool, limit_to: str,
             tags: str, extra_vars: str) -> None:
    """The run itself, on its own thread: start, stream, finish exactly once."""
    work = tempfile.mkdtemp(prefix="ansible-run-", dir=str(DATA))
    os.chmod(work, 0o700)
    proc, runenv = None, {}
    try:
        paths = _write_files(work, pb, g, extra_vars)
        argv = argv_for(pb, g, paths, check, limit_to, tags)
        shown = " ".join(a if a != paths.get("key") else "<key>" for a in argv)
        _set(run_id, cmd=shown)
        _append(run_id, f"$ {shown}\n\n")
        runenv = env_for(g, work)
        proc = subprocess.Popen(argv, cwd=work, env=runenv,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                bufsize=1, start_new_session=True)
        _live[run_id] = proc
        _set(run_id, pid=proc.pid)
        rc = _pump(run_id, proc)
        text = _output(run_id)
        _finish(run_id, rc, _stats(text))
    except Refused as e:
        _append(run_id, f"\n{e}\n")
        _finish(run_id, -1, {}, why=str(e))
    except Exception as e:                                       # noqa: BLE001
        _append(run_id, f"\n{type(e).__name__}: {e}\n")
        _finish(run_id, -1, {}, why=f"{type(e).__name__}: {e}")
    finally:
        _live.pop(run_id, None)
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:                                    # noqa: BLE001
                pass
        shutil.rmtree(work, ignore_errors=True)
        # The socket directory sits outside `work` on purpose, so it has to be
        # removed on purpose too — otherwise every run leaves one behind.
        cp = runenv.get("ANSIBLE_SSH_CONTROL_PATH_DIR", "")
        if cp and not cp.startswith(work):
            shutil.rmtree(cp, ignore_errors=True)


def _pump(run_id: str, proc: subprocess.Popen) -> int:
    """Read the process line by line, appending as it goes.

    Batched by time rather than per line: a playbook over forty hosts prints
    thousands of lines and one UPDATE per line would spend the run writing to
    SQLite. Half a second is under what a reader notices and two orders of
    magnitude fewer writes.
    """
    began = last_out = time.time()
    buf: list = []
    flushed = began
    while True:
        line = proc.stdout.readline() if proc.stdout else ""
        now = time.time()
        if line:
            buf.append(line)
            last_out = now
        elif proc.poll() is not None:
            break
        if buf and (now - flushed > 0.5 or len(buf) > 400):
            _append(run_id, "".join(buf))
            buf, flushed = [], now
        if now - began > RUN_TIMEOUT or now - last_out > IDLE_TIMEOUT:
            reason = ("it has run for over an hour"
                      if now - began > RUN_TIMEOUT
                      else "it has printed nothing for fifteen minutes")
            _append(run_id, f"\n[stopped: {reason}]\n")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:                                    # noqa: BLE001
                proc.terminate()
            break
    if buf:
        _append(run_id, "".join(buf))
    try:
        return proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        return -1


_RECAP = re.compile(
    r"^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)",
    re.M)


def _stats(text: str) -> dict:
    """Ansible's own recap, per host, read back out of what it printed.

    Parsed rather than asked for: `--stats` has no machine-readable form without
    a callback plugin, and installing one to learn what the recap already says
    would be a second thing to keep working.
    """
    hosts, totals = {}, {"ok": 0, "changed": 0, "unreachable": 0, "failed": 0}
    for m in _RECAP.finditer(text):
        row = {"ok": int(m.group(2)), "changed": int(m.group(3)),
               "unreachable": int(m.group(4)), "failed": int(m.group(5))}
        hosts[m.group(1)] = row
        for k in totals:
            totals[k] += row[k]
    return {"hosts": hosts, "totals": totals} if hosts else {}


def _output(run_id: str) -> str:
    r = _conn().execute("SELECT output FROM ansible_runs WHERE id = ?",
                        (run_id,)).fetchone()
    return (r["output"] if r else "") or ""


def _append(run_id: str, text: str) -> None:
    """Append to a run's output, capped.

    The cap matters: a playbook in a retry loop can print without end, and the
    portal's database is the thing that would fill up. The trim keeps the TAIL,
    because the end of a run is where the recap and the failure are.
    """
    with db.tx() as c:
        row = c.execute("SELECT output FROM ansible_runs WHERE id = ?",
                        (run_id,)).fetchone()
        if not row:
            return
        out = ((row["output"] or "") + text)
        if len(out) > OUTPUT_MAX:
            out = ("[earlier output dropped — this run printed more than "
                   f"{OUTPUT_MAX // 1_000_000}MB]\n") + out[-OUTPUT_MAX:]
        c.execute("UPDATE ansible_runs SET output = ? WHERE id = ?",
                  (out, run_id))


def _set(run_id: str, **fields) -> None:
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    with db.tx() as c:
        c.execute(f"UPDATE ansible_runs SET {sets} WHERE id = ?",
                  [*fields.values(), run_id])


def _finish(run_id: str, rc: int, stats: dict, why: str = "") -> None:
    """Close a run once, whatever happened.

    `status` is derived from the exit code rather than from how the thread got
    here: ansible means something specific by 2 (a task failed), 4 (a host was
    unreachable) and 0, and a reader wants those told apart.
    """
    status = {0: "ok", 2: "failed", 4: "unreachable"}.get(rc, "failed")
    if rc == -1 and why:
        status = "refused"
    with db.tx() as c:
        c.execute("""UPDATE ansible_runs SET status=?, rc=?, stats=?, why=?,
                     finished=?, pid=NULL
                     WHERE id=? AND status=?""",
                  (status, rc, json.dumps(stats), why, _now(), run_id,
                   STATUS_RUNNING))
    _trim()


def _trim() -> None:
    """Keep the newest RUNS_KEEP runs per playbook."""
    with db.tx() as c:
        for row in c.execute("SELECT DISTINCT pb_id FROM ansible_runs"):
            c.execute("""DELETE FROM ansible_runs WHERE id IN (
                           SELECT id FROM ansible_runs WHERE pb_id IS ?
                           ORDER BY rowid DESC LIMIT -1 OFFSET ?)""",
                      (row["pb_id"], RUNS_KEEP))


def adopt_orphans() -> int:
    """Close runs whose process died with the portal.

    Called at startup. Without this a restart in the middle of a run leaves a
    row that says `running` for ever — the page shows a spinner that will never
    stop, and the playbook cannot be run again because a run is "already going".
    """
    orphans = running()
    for r in orphans:
        _append(r["id"], "\n[the portal restarted while this was running — "
                         "whether it finished on the hosts is not recorded "
                         "here]\n")
        _finish(r["id"], -1, {}, why="the portal restarted mid-run")
    return len(orphans)


# ── checking a playbook without running it ─────────────────────
def syntax_check(body: str, g: dict | None = None) -> dict:
    """`--syntax-check`: does this parse, and do its plays make sense.

    Offered on save rather than enforced. A playbook that references a role the
    portal has not got fails this check while being perfectly correct on the
    host that has the role, and refusing to save it would make the editor
    useless for exactly the people who use roles.
    """
    probe = tool()
    if not probe["found"]:
        return {"ok": False, "checked": False,
                "error": probe["error"] or "ansible-playbook is not installed"}
    work = tempfile.mkdtemp(prefix="ansible-syn-", dir=str(DATA))
    os.chmod(work, 0o700)
    try:
        pb_path = os.path.join(work, "playbook.yml")
        with open(pb_path, "w") as fh:
            fh.write(body or "")
        inv_path = os.path.join(work, "inventory.yml")
        with open(inv_path, "w") as fh:
            fh.write(inventory_text(g) if g else "all:\n  hosts: {}\n")
        got = subprocess.run(
            [probe["path"] or env.ANSIBLE, "-i", inv_path, "--syntax-check",
             pb_path], capture_output=True, text=True, timeout=60,
            cwd=work, env=env_for(g or {}, work))
        return {"ok": got.returncode == 0, "checked": True,
                "error": "" if got.returncode == 0
                         else _first_fault(got.stderr, got.stdout)}
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "checked": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _first_fault(stderr: str, stdout: str) -> str:
    """What ansible objected to, with its own preamble taken off the front.

    A syntax check runs against an empty inventory, so ansible opens with
    `[WARNING]: provided hosts list is empty…` — which was the first thing the
    editor showed somebody whose playbook had a typo on line 9. The warnings are
    kept, at the end, because occasionally one of them IS the answer.
    """
    text = ((stderr or "") + ("\n" + stdout if stdout else "")).strip()
    lines = text.splitlines()
    noise = [ln for ln in lines if ln.startswith("[WARNING]")
             or ln.startswith("[DEPRECATION")]
    real = [ln for ln in lines if ln not in noise]
    out = "\n".join(real).strip() or text
    if real and noise:
        out += "\n\nalso: " + "\n".join(noise)
    return out[:2000]



# ── schedules: a stored intention to run ───────────────────────
# WHY THIS EXISTS
#     A host report somebody has to remember to run is a host report that stops
#     being run. The runner, the gates and the record all exist; a schedule is
#     only the decision to press the button on a clock instead of by hand.
#
# THE CLOCK
#     `next_at` carries the whole state. The ticker asks "is anything due",
#     fires it, and computes the next occurrence FROM NOW — so an installation
#     that was down over the weekend runs each missed schedule once when it
#     comes back, not thirty times to catch up.
#
# TWO REPLICAS
#     Firing is claim-based: the ticker advances next_at with
#     `UPDATE … WHERE id=? AND next_at=?` and only the claimer runs the
#     playbook. Two portals over one database fire each schedule once.
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday", "Sunday")
SCHEDULE_KINDS = ("minutes", "hours", "daily", "weekly")
MIN_MINUTES = 5          # below this a mistyped schedule is a load test
TICK_SECONDS = 20.0


def _local_tz():
    # Resolved per call rather than at import: the container's TZ is fixed, but
    # a laptop's can change under a long-lived process.
    return datetime.now().astimezone().tzinfo


def next_fire(kind: str, every: int = 0, at: str = "", weekday: int = 0,
              after: datetime | None = None) -> datetime:
    """The next moment this cadence fires after `after` (now, normally).

    Daily and weekly are computed in the PORTAL'S LOCAL time and stored as UTC:
    "every day at 03:30" means the quiet hours wherever this runs, and a person
    typing a time is thinking in the clock on their wall. The page says which
    timezone that is rather than leaving it to be guessed.
    """
    now = (after or datetime.now(timezone.utc)).astimezone(_local_tz())
    if kind == "minutes":
        target = now + timedelta(minutes=max(MIN_MINUTES, int(every or 0)))
    elif kind == "hours":
        target = now + timedelta(hours=max(1, int(every or 0)))
    else:
        hh, mm = (at or "03:00").split(":")
        target = now.replace(hour=int(hh), minute=int(mm), second=0,
                             microsecond=0)
        if kind == "weekly":
            target += timedelta(days=(int(weekday) - target.weekday()) % 7)
            if target <= now:
                target += timedelta(days=7)
        elif target <= now:
            target += timedelta(days=1)
    return target.astimezone(timezone.utc)


def cadence_words(s: dict) -> str:
    """"every 30 minutes", "every day at 03:30", "Mondays at 06:00"."""
    kind = s.get("kind")
    if kind == "minutes":
        return f"every {s.get('every')} minutes"
    if kind == "hours":
        n = int(s.get("every") or 1)
        return "every hour" if n == 1 else f"every {n} hours"
    if kind == "daily":
        return f"every day at {s.get('at')}"
    return f"{DAYS[int(s.get('weekday') or 0)]}s at {s.get('at')}"


def until_words(ts: str) -> str:
    """"in 25 min", "in 3 h", "in 6 days" — or "due now" once it has passed."""
    if not ts:
        return ""
    try:
        then = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    secs = (then - datetime.now(timezone.utc)).total_seconds()
    if secs <= 30:
        return "due now"
    if secs < 3600:
        return f"in {round(secs / 60)} min"
    if secs < 86400:
        h = int(secs // 3600)
        m = round((secs % 3600) / 60)
        return f"in {h} h" + (f" {m} min" if m else "")
    return f"in {round(secs / 86400)} days"


def _cadence_of(fields: dict) -> dict:
    kind = (fields.get("kind") or "").strip()
    if kind not in SCHEDULE_KINDS:
        raise Refused(f"how often? one of {', '.join(SCHEDULE_KINDS)}")
    every, at, weekday = 0, "", 0
    if kind in ("minutes", "hours"):
        try:
            every = int(fields.get("every") or 0)
        except (TypeError, ValueError):
            raise Refused("the interval has to be a number")
        low, high = (MIN_MINUTES, 24 * 60) if kind == "minutes" else (1, 24 * 7)
        if not low <= every <= high:
            raise Refused(f"every N {kind} takes {low} to {high}")
    else:
        at = (fields.get("at") or "").strip()
        if not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", at):
            raise Refused("the time is HH:MM, on a 24-hour clock")
        at = f"{int(at.split(':')[0]):02d}:{at.split(':')[1]}"
        if kind == "weekly":
            try:
                weekday = int(fields.get("weekday"))
            except (TypeError, ValueError):
                raise Refused("which weekday?")
            if not 0 <= weekday <= 6:
                raise Refused("which weekday?")
    return {"kind": kind, "every": every, "at": at, "weekday": weekday}


def save_schedule(sid: str, fields: dict, who: str) -> str:
    """Create or update a schedule, with every gate a manual run has.

    The production confirmation happens HERE, once, and is stored: a ticker has
    nobody to type a name at 03:30, so the typing moves to the moment the
    schedule is made — which is also the moment somebody is looking.
    """
    name = (fields.get("name") or "").strip()
    if not NAME_OK.match(name or ""):
        raise Refused("a schedule name may hold letters, digits, dot, dash "
                      "and underscore, and must start with a letter or digit")
    pb = playbook((fields.get("pb_id") or "").strip())
    if not pb:
        raise Refused("choose a playbook")
    g = group((fields.get("group_id") or "").strip())
    if not g:
        raise Refused("choose a group of hosts")
    check = bool(fields.get("check_mode"))
    limit_to = (fields.get("limit_to") or "").strip()
    tags = (fields.get("tags") or "").strip()
    if limit_to and not LIMIT_OK.match(limit_to):
        raise Refused("a limit may hold host names, groups and the usual "
                      "patterns — nothing else")
    if tags and not TAGS_OK.match(tags):
        raise Refused("tags are a comma-separated list of names")
    extra_vars = (fields.get("extra_vars") or "").strip()
    if extra_vars:
        try:
            if not isinstance(json.loads(extra_vars), dict):
                raise ValueError("not an object")
        except ValueError as e:
            raise Refused(f"the extra variables are not a JSON object: {e}")
    cad = _cadence_of(fields)
    confirmed = 0
    if not check and g.get("is_prod"):
        if (fields.get("confirm") or "").strip() != g["name"]:
            raise Refused(f"{g['name']} is marked production: type its name to "
                          f"schedule a real run against it")
        confirmed = 1
    nxt = next_fire(**cad).isoformat(timespec="seconds")
    row = {"name": name, "pb_id": pb["id"], "group_id": g["id"],
           "check_mode": 1 if check else 0, "limit_to": limit_to,
           "tags": tags, "extra_vars": extra_vars, **cad,
           "confirmed": confirmed, "next_at": nxt}
    with db.tx() as c:
        if sid:
            if not c.execute("SELECT 1 FROM ansible_schedules WHERE id = ?",
                             (sid,)).fetchone():
                raise Refused("that schedule no longer exists")
            sets = ", ".join(f"{k}=?" for k in row)
            c.execute(f"UPDATE ansible_schedules SET {sets}, last_error='' "
                      f"WHERE id=?", [*row.values(), sid])
        else:
            sid = "as-" + uuid.uuid4().hex[:10]
            cols = ", ".join(row)
            marks = ", ".join("?" * len(row))
            c.execute(f"INSERT INTO ansible_schedules "
                      f"(id, {cols}, enabled, created, created_by) "
                      f"VALUES (?, {marks}, 1, ?, ?)",
                      [sid, *row.values(), _now(), who])
    return sid


def schedules() -> list:
    pbs = {r["id"]: r["name"] for r in _conn().execute(
        "SELECT id, name FROM ansible_playbooks")}
    gs = {g["id"]: g for g in groups(with_hosts=False)}
    out = []
    for r in _conn().execute("SELECT * FROM ansible_schedules ORDER BY name"):
        s = dict(r)
        s["pb_name"] = pbs.get(s["pb_id"], "")
        g = gs.get(s["group_id"]) or {}
        s["group_name"] = g.get("name", "")
        s["is_prod"] = bool(g.get("is_prod"))
        s["pid"], s["rgid"] = g.get("pid") or "", g.get("rgid") or ""
        s["project_name"] = g.get("project_name", "")
        s["region_name"] = g.get("region_name", "")
        s["words"] = cadence_words(s)
        s["due"] = until_words(s.get("next_at") or "")
        s["last_ago"] = ago(s.get("last_at") or "")
        # a schedule whose playbook or group is gone cannot fire; say so on the
        # row rather than waiting for the ticker to find out
        if not s["pb_name"]:
            s["broken"] = "its playbook was deleted"
        elif not s["group_name"]:
            s["broken"] = "its group was deleted"
        else:
            s["broken"] = ""
        out.append(s)
    return out


def schedule(sid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM ansible_schedules WHERE id = ?",
                        (sid,)).fetchone()
    return dict(r) if r else None


def delete_schedule(sid: str) -> dict | None:
    got = schedule(sid)
    if got:
        with db.tx() as c:
            c.execute("DELETE FROM ansible_schedules WHERE id = ?", (sid,))
    return got


def toggle_schedule(sid: str, enabled: bool) -> dict | None:
    got = schedule(sid)
    if not got:
        return None
    # Re-enabled means "from now": next_at is recomputed, or a schedule that sat
    # off for a month would fire the moment the switch flips.
    nxt = (next_fire(got["kind"], got["every"] or 0, got["at"] or "",
                     got["weekday"] or 0).isoformat(timespec="seconds")
           if enabled else got["next_at"])
    with db.tx() as c:
        c.execute("UPDATE ansible_schedules SET enabled=?, next_at=?, "
                  "last_error='' WHERE id=?",
                  (1 if enabled else 0, nxt, sid))
    return got


def scheduler_tick() -> list:
    """Fire whatever is due. Returns what happened, for the log and the tests."""
    fired = []
    due = [dict(r) for r in _conn().execute(
        "SELECT * FROM ansible_schedules WHERE enabled=1 AND next_at <= ?",
        (_now(),))]
    for s in due:
        nxt = next_fire(s["kind"], s["every"] or 0, s["at"] or "",
                        s["weekday"] or 0).isoformat(timespec="seconds")
        with db.tx() as c:
            claimed = c.execute(
                "UPDATE ansible_schedules SET next_at=? "
                "WHERE id=? AND next_at=? AND enabled=1",
                (nxt, s["id"], s["next_at"])).rowcount
        if not claimed:
            continue                       # another replica got there first
        outcome = {"id": s["id"], "name": s["name"]}
        try:
            g = group(s["group_id"]) or {}
            run_id = start(
                s["pb_id"], s["group_id"], f"schedule:{s['name']}",
                check=bool(s["check_mode"]),
                limit_to=s.get("limit_to") or "",
                tags=s.get("tags") or "",
                extra_vars=s.get("extra_vars") or "",
                allow_real=config()["allow_real"],
                # typed once, at creation, by somebody who was looking
                confirm=g.get("name", "") if s.get("confirmed") else "")
            with db.tx() as c:
                c.execute("UPDATE ansible_schedules SET last_at=?, "
                          "last_run_id=?, last_error='' WHERE id=?",
                          (_now(), run_id, s["id"]))
            outcome["run_id"] = run_id
        except Refused as e:
            why = str(e)
            # A missing playbook or group will refuse for ever; switch the
            # schedule off with the reason on it rather than failing every
            # twenty seconds until somebody notices the log. Anything else —
            # already running, the concurrency cap, real runs switched off — is
            # this fire skipped, and the next one may well work.
            gone = ("no longer exists" in why or "choose a group" in why
                    or "is empty" in why or "no hosts" in why)
            with db.tx() as c:
                c.execute("UPDATE ansible_schedules SET last_error=?, "
                          "enabled=? WHERE id=?",
                          (why[:300], 0 if gone else 1, s["id"]))
            outcome["error"], outcome["disabled"] = why, gone
        fired.append(outcome)
    return fired


_scheduler_on = threading.Event()


def scheduler_start(interval: float = TICK_SECONDS) -> bool:
    """Start the ticker, once. PORTAL_SCHEDULER=0 keeps it off — for a test
    harness, or an operator draining a pod without letting it fire anything."""
    if _scheduler_on.is_set() or os.environ.get("PORTAL_SCHEDULER") == "0":
        return False
    _scheduler_on.set()

    def loop():
        while True:
            time.sleep(interval)
            try:
                scheduler_tick()
            except Exception:                                  # noqa: BLE001
                # the ticker must survive anything one tick does; the failure
                # is on the schedule row where somebody will read it
                pass

    threading.Thread(target=loop, name="ansible-scheduler",
                     daemon=True).start()
    return True


# ── clearing the record ────────────────────────────────────────
def delete_run(run_id: str) -> dict | None:
    """Forget one run. A run still going is refused rather than orphaned.

    The row is what the output lives in and what the live window polls, so
    deleting one mid-flight would leave a thread writing to nothing and a page
    asking about a run that no longer exists. Cancel it first.
    """
    row = _conn().execute("SELECT id, pb_name, group_name, status FROM "
                          "ansible_runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return None
    got = dict(row)
    if got["status"] == STATUS_RUNNING:
        raise Refused("that run is still going — cancel it first")
    with db.tx() as c:
        c.execute("DELETE FROM ansible_runs WHERE id = ?", (run_id,))
    return got


def clear_runs(which: str = "finished") -> int:
    """Delete a whole class of run and say how many went.

    `which` is deliberately a small vocabulary rather than a WHERE clause from
    the page: the page asks for "the failed ones", not for SQL. A run in flight
    is never included, whatever is asked for — the same reason delete_run refuses
    one.
    """
    # "finished" is everything that is NOT still going, rather than a list of the
    # statuses that existed the day this was written. A run can also end
    # `refused` — the production confirm, or an installation with real runs off —
    # and a hardcoded ("ok", "failed", "unreachable") left those behind after a
    # "clear all" that said it took every finished run. Measured, in this suite.
    where = {"finished": ("status != ?", (STATUS_RUNNING,)),
             "failed": ("status IN (?,?)", ("failed", "unreachable")),
             "ok": ("status = ?", ("ok",))}
    got = where.get(which)
    if not got:
        raise Refused(f"clear what? one of {', '.join(sorted(where))}")
    clause, args = got
    with db.tx() as c:
        n = c.execute(f"DELETE FROM ansible_runs WHERE {clause}", args).rowcount
    return max(0, int(n or 0))


def history(days: int = 14, reg: str = "") -> dict:
    """The shape of recent activity, for the overview: a column per day, the
    outcome mix, the busiest playbooks, and what the tasks themselves did.

    Counted from the rows rather than kept as a running total, because a total
    that is maintained separately is a total that drifts from the table it claims
    to describe — and this table is small. `reg` scopes the charts to one region
    (a run's region is its own `rgn_id` column), same contract as summary()."""
    today = date.today()
    span = [today - timedelta(days=n) for n in range(max(1, days) - 1, -1, -1)]
    # `short` is what fits under a bar, and it carries the month on the 1st and
    # on the first column — "31 1 2 3" across a month boundary is a row of
    # numbers nobody can place.
    slots = {d.isoformat(): {"day": d.isoformat(), "label": d.strftime("%-d %b"),
                             "short": (d.strftime("%-d %b")
                                       if d.day == 1 or d == span[0]
                                       else d.strftime("%-d")),
                             "ok": 0, "bad": 0, "check": 0, "total": 0}
             for d in span}
    mix = {"ok": 0, "failed": 0, "unreachable": 0, "running": 0, "other": 0}
    tasks = {"ok": 0, "changed": 0, "failed": 0, "unreachable": 0}
    by_pb: dict = {}
    seconds = 0.0
    rows = _conn().execute(
        "SELECT pb_name, status, started, finished, stats, check_mode "
        "FROM ansible_runs" + (" WHERE rgn_id = ?" if reg else "")
        + " ORDER BY started DESC LIMIT 500",
        (reg,) if reg else ()).fetchall()
    for r in rows:
        row = dict(r)
        day = (row.get("started") or "")[:10]
        status = row.get("status") or "other"
        mix[status if status in mix else "other"] += 1
        if day in slots:
            slot = slots[day]
            slot["total"] += 1
            if status == "ok":
                slot["ok"] += 1
            elif status in ("failed", "unreachable"):
                slot["bad"] += 1
            if row.get("check_mode"):
                slot["check"] += 1
        name = row.get("pb_name") or "—"
        pb = by_pb.setdefault(name, {"name": name, "runs": 0, "bad": 0})
        pb["runs"] += 1
        if status in ("failed", "unreachable"):
            pb["bad"] += 1
        got = json.loads(row.get("stats") or "{}")
        for k in tasks:
            tasks[k] += int((got.get("totals") or {}).get(k) or 0)
        seconds += _seconds(row.get("started"), row.get("finished"))
    days_list = list(slots.values())
    top = max([d["total"] for d in days_list] or [0]) or 1
    for d in days_list:
        d["pct"] = round(d["total"] / top * 100)
        d["okpct"] = round(d["ok"] / d["total"] * 100) if d["total"] else 0
    done = mix["ok"] + mix["failed"] + mix["unreachable"]
    return {"days": days_list, "peak": top, "mix": mix, "tasks": tasks,
            "playbooks": sorted(by_pb.values(),
                                key=lambda p: (-p["runs"], p["name"]))[:6],
            "counted": len(rows), "seconds": round(seconds),
            # The number people actually ask for, and the honest denominator:
            # runs that finished. A run still going has no outcome yet, and
            # counting it as anything makes the percentage move on its own.
            "rate": round(mix["ok"] / done * 100) if done else None,
            "finished": done}


def _seconds(started: str, finished: str) -> float:
    if not started or not finished:
        return 0.0
    try:
        return max(0.0, (datetime.fromisoformat(finished)
                         - datetime.fromisoformat(started)).total_seconds())
    except ValueError:
        return 0.0


# ── what the page counts ───────────────────────────────────────
def summary(reg: str = "") -> dict:
    """The overview counts. `reg` scopes them to a region so the tiles/badges track
    the portal-wide region filter: "" = every region, else that region id. Each
    table names its place column differently (playbooks/groups use `rgid`, runs use
    `rgn_id`, a host's region is its group's), so the filter is per-table.
    reg="" leaves every query byte-identical to the unscoped version."""
    c = _conn()
    one = lambda q, a=(): (c.execute(q, a).fetchone() or [0])[0]  # noqa: E731

    def rw(col: str):
        if reg:
            return f"{col} = ?", (reg,)
        return "", ()

    def cnt(table: str, col: str, cond: str = "") -> int:
        w, a = rw(col)
        clauses = " AND ".join(x for x in (w, cond) if x)
        return one(f"SELECT COUNT(*) FROM {table}" + (f" WHERE {clauses}" if clauses else ""), a)

    def host_cnt() -> int:                    # a host has no place column of its own
        if not reg:
            return one("SELECT COUNT(*) FROM ansible_hosts")
        w, a = rw("g.rgid")
        return one("SELECT COUNT(*) FROM ansible_hosts h JOIN ansible_groups g "
                   "ON h.group_id = g.id WHERE " + w, a)
    return {
        "playbooks": cnt("ansible_playbooks", "rgid"),
        "groups": cnt("ansible_groups", "rgid"),
        "hosts": host_cnt(),
        "runs": cnt("ansible_runs", "rgn_id"),
        "running": cnt("ansible_runs", "rgn_id", f"status = '{STATUS_RUNNING}'"),
        "ok": cnt("ansible_runs", "rgn_id", "status = 'ok'"),
        "failed": cnt("ansible_runs", "rgn_id", "status IN ('failed','unreachable')"),
        "tool": tool(),
    }
