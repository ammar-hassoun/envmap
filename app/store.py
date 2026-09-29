"""Portal settings: projects, regions, clusters and external connections.

MODEL
  project
    ├── clusters   {cid: name, context, status, kubeconfig_file, cert_file}
    ├── regions    {rgid: name, flag, label, envs{name: binding},
    │               env_clusters{env: cid}}
    └── ci/sec/log/mon  connections scoped to this project

Each ENVIRONMENT declares its own complete binding — repository, branch, path,
credentials — on its region row (`envs`). There is no region-level repository:
one used to exist as an inherited default, and `repo._absorb` migrated it into
the bindings when its settings page was retired (a legacy `repo` key may still
sit on a region row until that migration has run). Clusters sit at project
level so one shared cluster can serve environments in several regions. A
connection is either global (the usual case — one central Jenkins, one
scanner) or project-scoped.

HOW IT IS STORED
  Rows in the portal database (db.py), one per project, region, cluster and
  connection. The public functions below still hand out and accept the nested
  dictionaries the rest of the portal is written against — the shape callers see
  has not changed — but a write now touches a single row inside a transaction.
  That matters: the previous settings.json was read whole and written whole, so
  two people saving different settings at the same moment lost one of the edits.

  Columns exist for what is queried or sorted; everything else lives in a `data`
  JSON column. That keeps provider-specific connection fields, naming
  conventions and repository details from needing a schema change each time one
  is added, while ids and ownership stay real columns with real indexes.

  Reads are served from an in-memory copy that is rebuilt when a write bumps the
  version counter — load() is called many times per request, and the assembled
  document is a few kilobytes.

  A GitOps repo's password/token is sealed with `secretbox` before it lands in
  the `data` column — the same treatment `conns` gets, applied to one field
  rather than the whole blob so every other reader of `region.repo`/`env`
  keeps working unchanged. `secretbox.seal` is idempotent and a value without
  its prefix passes through `unseal` unchanged, so an install upgrading from
  when this field was plain text needs no migration: it reads correctly today
  and is sealed the next time it is saved. Kubeconfigs, sealing certificates
  and deploy keys stay as files under data/secrets/ because the tools that
  consume them take a path, not a string.
"""
import hashlib
from urllib.parse import unquote, urlparse, urlunparse
import json
import base64
import os
import tempfile
import subprocess
import shutil
import re
import secrets
import threading
from pathlib import Path

from . import db, secretbox, env
from .paths import BASE, DATA, REPOS, SECRETS

LEGACY_SETTINGS = DATA / "settings.json"   # pre-database location, imported once

_lock = threading.Lock()


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


# ── tables ─────────────────────────────────────────────────────
# `ord` preserves the order things were added, which is the order the sidebar
# and every listing shows them in. Without it rows would come back in whatever
# order the engine finds convenient.
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT)""",
    """CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT, icon TEXT, tagline TEXT,
        ord INTEGER, data TEXT)""",
    """CREATE TABLE IF NOT EXISTS regions (
        id TEXT PRIMARY KEY, pid TEXT NOT NULL, name TEXT, flag TEXT,
        label TEXT, ord INTEGER, data TEXT)""",
    """CREATE TABLE IF NOT EXISTS clusters (
        id TEXT PRIMARY KEY, pid TEXT NOT NULL, name TEXT, context TEXT,
        status TEXT, kubeconfig_file TEXT, cert_file TEXT,
        ord INTEGER, data TEXT)""",
    """CREATE TABLE IF NOT EXISTS conns (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, pid TEXT NOT NULL DEFAULT '',
        ord INTEGER, data TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_regions_pid ON regions(pid)",
    "CREATE INDEX IF NOT EXISTS idx_clusters_pid ON clusters(pid)",
    "CREATE INDEX IF NOT EXISTS idx_conns_kind ON conns(kind, pid)",
]

# columns per table; anything a caller sets that is not here goes to `data`
_COLS = {
    "projects": ("name", "icon", "tagline"),
    "regions": ("pid", "name", "flag", "label"),
    "clusters": ("pid", "name", "context", "status", "kubeconfig_file",
                 "cert_file"),
    "conns": ("kind", "pid"),
}


def _migrate(c) -> None:
    for stmt in SCHEMA:
        c.execute(stmt)
    _import_legacy(c)


db.register(_migrate)


def _import_legacy(c) -> None:
    """Load a settings.json written before the move to the database.

    Only when there is nothing here yet, so it can never overwrite live data.
    The file is renamed rather than removed: an upgrade that goes wrong should
    still be recoverable by hand.
    """
    if not LEGACY_SETTINGS.exists():
        return
    if c.execute("SELECT 1 FROM projects LIMIT 1").fetchone():
        return
    if c.execute("SELECT 1 FROM conns LIMIT 1").fetchone():
        return
    try:
        doc = json.loads(LEGACY_SETTINGS.read_text() or "{}")
    except json.JSONDecodeError:
        return
    n = 0
    for key in ("brand",):
        if doc.get(key):
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)",
                      (key, json.dumps(doc[key])))
    for pid, p in (doc.get("projects") or {}).items():
        n += 1
        _insert(c, "projects", pid, n, dict(p, id=pid))
        for i, (rgid, rg) in enumerate((p.get("regions") or {}).items(), 1):
            _insert(c, "regions", rgid, i, dict(rg, id=rgid, pid=pid))
        for i, (cid, cl) in enumerate((p.get("clusters") or {}).items(), 1):
            _insert(c, "clusters", cid, i, dict(cl, id=cid, pid=pid))
        for kind in CONN_KINDS:
            for i, (cid, conn) in enumerate((p.get(kind) or {}).items(), 1):
                _insert(c, "conns", cid, i, dict(conn, id=cid, pid=pid, kind=kind))
    for kind in CONN_KINDS:
        for i, (cid, conn) in enumerate((doc.get(kind) or {}).items(), 1):
            _insert(c, "conns", cid, i,
                    dict(conn, id=cid, pid=GLOBAL, kind=kind))
    LEGACY_SETTINGS.rename(LEGACY_SETTINGS.with_suffix(".json.migrated"))


def _split(table: str, fields: dict) -> tuple[dict, dict]:
    """Separate real columns from everything else, which becomes JSON."""
    cols = _COLS[table]
    return ({k: v for k, v in fields.items() if k in cols},
            {k: v for k, v in fields.items()
             if k not in cols and k not in ("id", "ord")})


# The whole `data` blob of a connection is sealed, not a list of field names.
# A list is a thing to keep up to date, and the day somebody adds "api_secret"
# to a provider and does not think about this file, that credential is in the
# clear. Sealing the blob has no such failure mode — and nothing queries inside
# it in SQL, so there is nothing to lose by making it opaque.
SEALED_TABLES = ("conns",)


def _pack(table: str, extra: dict) -> str:
    body = json.dumps(extra)
    return secretbox.seal(body) if table in SEALED_TABLES else body


def _unpack(table: str, raw) -> dict:
    body = secretbox.unseal(raw or "") if table in SEALED_TABLES else (raw or "")
    try:
        return json.loads(body or "{}")
    except json.JSONDecodeError:
        # an unreadable blob means the key changed; one connection losing its
        # settings must not take down every page that lists connections
        return {}


def _insert(c, table: str, rid: str, order: int, fields: dict) -> None:
    col, extra = _split(table, fields)
    names = ["id", "ord", "data"] + list(col)
    vals = [rid, order, _pack(table, extra)] + [col[k] for k in col]
    c.execute(f"INSERT OR REPLACE INTO {table} ({', '.join(names)}) "
              f"VALUES ({', '.join('?' * len(names))})", vals)


def _update(table: str, rid: str, fields: dict) -> None:
    """Apply a partial change to one row, merging into `data` as needed."""
    col, extra = _split(table, fields)
    with db.tx() as c:
        row = c.execute(f"SELECT data FROM {table} WHERE id = ?",
                        (rid,)).fetchone()
        if row is None:
            return
        sets, vals = [], []
        for k, v in col.items():
            sets.append(f"{k} = ?")
            vals.append(v)
        if extra:
            merged = _unpack(table, row["data"])
            merged.update(extra)
            sets.append("data = ?")
            vals.append(_pack(table, merged))
        if sets:
            c.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id = ?",
                      vals + [rid])
    _bump()


def _next_ord(c, table: str, where: str = "", params=()) -> int:
    sql = f"SELECT COALESCE(MAX(ord), 0) + 1 AS n FROM {table}"
    if where:
        sql += f" WHERE {where}"
    return c.execute(sql, params).fetchone()["n"]


def _row(table: str, row) -> dict:
    """A row back in the nested shape callers expect."""
    d = _unpack(table, row["data"])
    for k in row.keys():
        if k not in ("data", "ord"):
            d[k] = row[k]
    return d


# ── the assembled document ─────────────────────────────────────
# One in-memory copy per process, revalidated against a shared revision row on
# every load(). The counter is the cross-process invalidation signal: process A
# writes and bumps it; process B's next load() sees a number it does not
# recognise and rebuilds. The check is a single indexed read of a one-row
# table — microseconds — which is what lets load() stay in every page render.
_cache: dict | None = None
_cache_rev = -1


def _rev() -> int:
    row = db.one("SELECT n FROM rev WHERE id = 1")
    return int(row["n"]) if row else 0


def _bump() -> None:
    global _cache
    with _lock:
        db.run("INSERT INTO rev (id, n) VALUES (1, 1) "
               "ON CONFLICT(id) DO UPDATE SET n = n + 1")
        _cache = None


def invalidate() -> None:
    """Drop the cached document — for a process that changed rows directly."""
    _bump()


def load() -> dict:
    global _cache, _cache_rev
    now = _rev()
    cached = _cache
    if cached is not None and _cache_rev == now:
        return cached
    doc = {"projects": {}}
    for r in db.q("SELECT * FROM settings"):
        raw = r["value"]
        if r["key"] in SEALED_SETTINGS:
            raw = secretbox.unseal(raw or "")
        try:
            doc[r["key"]] = json.loads(raw)
        except json.JSONDecodeError:
            pass
    for r in db.q("SELECT * FROM projects ORDER BY ord, name"):
        p = _row("projects", r)
        p.setdefault("hidden_services", [])
        p.setdefault("hidden_key_prefixes", [])
        p.setdefault("strip_suffixes", [])
        p.setdefault("env_aliases", {})
        p["regions"], p["clusters"] = {}, {}
        doc["projects"][r["id"]] = p
    for r in db.q("SELECT * FROM regions ORDER BY ord, name"):
        p = doc["projects"].get(r["pid"])
        if p is None:
            continue                      # orphan: its project was deleted
        rg = _row("regions", r)
        rg.setdefault("repo", {})
        rg.setdefault("env_clusters", {})
        p["regions"][r["id"]] = rg
    for r in db.q("SELECT * FROM clusters ORDER BY ord, name"):
        p = doc["projects"].get(r["pid"])
        if p is not None:
            p["clusters"][r["id"]] = _row("clusters", r)
    for r in db.q("SELECT * FROM conns ORDER BY ord, id"):
        conn = _row("conns", r)
        kind = conn.pop("kind", "")
        target = doc["projects"].get(r["pid"]) if r["pid"] else doc
        if target is not None:
            target.setdefault(kind, {})[r["id"]] = conn
    with _lock:
        _cache, _cache_rev = doc, now
    return doc


# ── branding ───────────────────────────────────────────────────
# The portal carries no organisation's name in its source. Whoever deploys it
# sets these, by environment variable (handy for a Helm chart) or in settings.
BRAND_DEFAULT = {"name": "DevOps EnvMap", "org": "environments, mapped",
                 "short": "EnvMap"}


def _setting(key: str) -> dict:
    return load().get(key) or {}


# Settings that carry a credential. Unlike conns, this table is mostly
# harmless configuration — branding, layout — and sealing all of it would make
# the database needlessly unreadable when something goes wrong at 2am.
# The assistant's key joined this late: it is an API credential that was being
# written to a table chosen for NOT being sealed, so an install that had one
# configured had it sitting in plaintext in portal.db. _seal_existing migrates
# and vacuums, so an upgrade fixes it rather than only new saves.
SEALED_SETTINGS = ("smtp", "assistant")


def _seal_existing(c) -> None:
    """Encrypt what earlier versions wrote in the clear.

    Runs once at startup rather than waiting for each row to be edited: a
    credential stored last month is exactly the one that has been copied into a
    backup, and "it will be encrypted next time you save it" protects nobody.
    """
    try:
        rows = c.execute("SELECT id, data FROM conns").fetchall()
    except Exception:                                          # noqa: BLE001
        return                       # table not created yet on a first run
    n = 0
    for r in rows:
        if r["data"] and not secretbox.sealed(r["data"]):
            c.execute("UPDATE conns SET data = ? WHERE id = ?",
                      (secretbox.seal(r["data"]), r["id"]))
            n += 1
    for key in SEALED_SETTINGS:
        got = c.execute("SELECT value FROM settings WHERE key = ?",
                        (key,)).fetchone()
        if got and got["value"] and not secretbox.sealed(got["value"]):
            c.execute("UPDATE settings SET value = ? WHERE key = ?",
                      (secretbox.seal(got["value"]), key))
            n += 1
    if n:
        # VACUUM, or the encryption is theatre. SQLite marks the old pages free
        # and leaves their contents in the file, so the plaintext an UPDATE
        # replaced is still sitting there for anybody who copies portal.db —
        # verified by grepping a migrated file and finding the old token.
        # The connection runs with isolation_level=None, so this is allowed.
        c.execute("VACUUM")
        print(f"[store] encrypted {n} stored credential blob(s) at rest, "
              f"and vacuumed the file so the old plaintext is gone")


db.register(_seal_existing)


def _set_setting(key: str, value: dict) -> None:
    body = json.dumps(value)
    if key in SEALED_SETTINGS:
        body = secretbox.seal(body)
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
           (key, body))
    _bump()


def brand() -> dict:
    data = _setting("brand")
    out = {
        "name": env.BRAND_NAME or data.get("name") or BRAND_DEFAULT["name"],
        # The subtitle is optional, and "set to nothing" has to be different
        # from "never set" or it can only ever be changed, never removed —
        # which is what happens when a falsy value falls through to a default.
        "org": env.BRAND_ORG or (data["org"] if "org" in data
                                 else BRAND_DEFAULT["org"]),
    }
    # what an authenticator app shows next to the code; kept short because it
    # goes into the QR payload and a longer string means a denser grid
    out["short"] = env.BRAND_SHORT or data.get("short") or out["name"]
    # Whether this install is wearing somebody else's name. Decided on the
    # resolved name rather than on "was anything set", because an install can
    # have the product's own name saved explicitly — the demo one does — and
    # that is not a rebrand. Only this tells the mark apart from an initial:
    # our logo over a customer's name would be worse than no logo at all.
    out["branded"] = (out["name"].strip().casefold()
                      != BRAND_DEFAULT["name"].casefold())
    return out


def set_brand(**fields) -> None:
    """Any field given is written, including an empty one — see brand()."""
    _set_setting("brand", {**_setting("brand"),
                           **{k: v for k, v in fields.items() if v is not None}})


# ── projects ───────────────────────────────────────────────────
def projects() -> dict:
    return load()["projects"]


def get_project(pid: str) -> dict | None:
    return load()["projects"].get(pid)


def add_project(name: str, icon: str = "📦", tagline: str = "") -> str:
    pid = new_id("p")
    with db.tx() as c:
        _insert(c, "projects", pid, _next_ord(c, "projects"), {
            "name": name, "icon": icon or "📦", "tagline": tagline,
            # naming conventions, empty by default: a new project shows exactly
            # what is in its repository until someone configures otherwise
            "hidden_services": [],      # glob patterns to leave out of listings
            "hidden_key_prefixes": [],  # config keys that are platform-level
            "strip_suffixes": [],       # suffixes to drop from display names
            "env_aliases": {},          # folder name -> display name
            # repo LAYOUT, so discovery is not hardcoded to one convention:
            "values_globs": [],   # glob(s) for a service file in the default (env=folder) layout; empty = *-values*.yaml
            "layout_pattern": "",  # general escape hatch: a path pattern with {env} and {svc} over the path
                                   # under values_path — covers flat, service-first, nested, anything. empty = default.
        })
    _bump()
    return pid


def update_project(pid: str, **fields) -> None:
    _update("projects", pid, fields)


def delete_project(pid: str) -> None:
    """Remove the project and everything that belonged to it.

    One transaction, so a project never half-exists — a region pointing at a
    project that is gone would show up as an empty page rather than an error.
    """
    with db.tx() as c:
        for cl in c.execute("SELECT kubeconfig_file, cert_file FROM clusters "
                            "WHERE pid = ?", (pid,)).fetchall():
            for f in (cl["kubeconfig_file"], cl["cert_file"]):
                if f:
                    Path(f).unlink(missing_ok=True)
        for table in ("regions", "clusters", "conns"):
            c.execute(f"DELETE FROM {table} WHERE pid = ?", (pid,))
        c.execute("DELETE FROM projects WHERE id = ?", (pid,))
    _bump()


# ── regions ────────────────────────────────────────────────────
def add_region(pid: str, name: str, flag: str = "", label: str = "") -> str:
    rgid = new_id("rg")
    with db.tx() as c:
        _insert(c, "regions", rgid,
                _next_ord(c, "regions", "pid = ?", (pid,)),
                {"pid": pid, "name": name, "flag": flag, "label": label,
                 "repo": {}, "env_clusters": {}})
    _bump()
    return rgid


def get_region(pid: str, rgid: str) -> dict | None:
    return (get_project(pid) or {}).get("regions", {}).get(rgid)


def update_region(pid: str, rgid: str, **fields) -> None:
    _update("regions", rgid, fields)


def set_region_repo(pid: str, rgid: str, repo: dict) -> None:
    """LEGACY writer: the region-level repository this model no longer has.

    Nothing in the app writes here any more — environments carry their own
    bindings. It survives for the upgrade path and its tests: fixtures write
    the old shape through it, and `repo._absorb` reads it back once to fold it
    into the bindings. `secret` is sealed on the way in so even the legacy
    shape never holds a plaintext credential.
    """
    rg = get_region(pid, rgid)
    if rg is None:
        return
    repo = dict(repo)
    if repo.get("url"):
        clean, user, pw = split_credentials(str(repo["url"]))
        repo["url"] = clean
        if user and not repo.get("username"):
            repo["username"] = user
        if pw and not repo.get("secret"):
            repo["secret"] = pw
    if repo.get("secret"):
        repo["secret"] = secretbox.seal(str(repo["secret"]))
    _update("regions", rgid, {"repo": {**rg.get("repo", {}), **repo}})


def delete_region(pid: str, rgid: str) -> None:
    # its deploy keys go too — files named {rgid}-*-id under the project's
    # secrets dir would otherwise outlive the region that owned them
    for key in (SECRETS / pid).glob(f"{rgid}-*"):
        key.unlink(missing_ok=True)
    (SECRETS / pid / f"{rgid}-id").unlink(missing_ok=True)
    db.run("DELETE FROM regions WHERE id = ?", (rgid,))
    _bump()


def map_env_cluster(pid: str, rgid: str, env: str, cid: str) -> None:
    rg = get_region(pid, rgid)
    if rg is None:
        return
    mapping = dict(rg.get("env_clusters") or {})
    if cid:
        mapping[env] = cid
    else:
        mapping.pop(env, None)
    _update("regions", rgid, {"env_clusters": mapping})


# ── environment declarations ───────────────────────────────────
# An environment is DECLARED, not discovered. Each one carries where its values
# live — repository, branch, path — and any field left blank inherits the
# region's, which is what makes the common case (one repo, one branch, a folder
# per environment) a single line of typing while still allowing an environment
# on a different branch, or in a different repository altogether.
#
# The scan this replaced could only ever describe one shape: one repo, one
# branch, folders under one values path. It was a good guess and it was still a
# guess — nobody could correct it, and it was wrong for anyone whose
# environments are split across branches or repositories. Declarations are
# typed by the person who knows, so there is nothing to guess.
#
# `protocol`/`username`/`secret` let ONE environment authenticate differently
# from its region — a genuinely different host, not just a different branch —
# without a separate settings page: they are declared right where the rest of
# the binding is. Blank means inherit, same as `url`/`branch`. An ssh key is
# NOT here — like the region's, it is a 0600 file (`ssh_key_path`), because
# what consumes it wants a path, not a string.
ENV_FIELDS = ("url", "branch", "path", "recurse", "pattern",
              "protocol", "username", "secret")


def split_credentials(url: str) -> tuple[str, str, str]:
    """(address without userinfo, username, secret) for a clone URL.

    `https://bot:ghp_xxx@host/org/repo.git` is the shape people paste, and it
    puts a live token in the ONE field this portal displays and exports: the
    repository address appears on the repos board, in the cluster form, in
    assistant answers and over MCP to somebody's AI client. There is already a
    sealed place for that secret, so it is moved there and the address is
    stored clean — done at the point of WRITE, so every reader is safe without
    having to know this can happen.

    Only http/https/ssh URLs with real userinfo are touched. `git@host:org/x`
    is left exactly as it is: that `git` is the ssh account, not a secret, and
    rewriting it would break the address.
    """
    raw = (url or "").strip()
    if "@" not in raw:
        return raw, "", ""
    try:
        p = urlparse(raw)
    except ValueError:
        return raw, "", ""
    if p.scheme not in ("http", "https", "ssh") or not p.username:
        return raw, "", ""
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return (urlunparse(p._replace(netloc=host)),
            unquote(p.username or ""), unquote(p.password or ""))


def env_sources(pid: str, rgid: str) -> dict:
    """name -> binding, for every environment this region declares.

    `secret`, if set, comes back SEALED — nothing reads it as a password here.
    The one place that needs the real value (`gitrepo.env_repo`) unseals it at
    the point of use, the same discipline `region.repo.secret` already follows.
    """
    rg = get_region(pid, rgid) or {}
    out = {}
    for name, b in (rg.get("envs") or {}).items():
        if str(name).strip():
            out[str(name).strip()] = {k: (b or {}).get(k) or ""
                                      for k in ENV_FIELDS}
    return out


def set_env_source(pid: str, rgid: str, env: str, binding: dict) -> str:
    """Declare (or re-point) one environment. Merges, so an edit that omits a
    field keeps it — the cluster form does not carry every field on every
    submit.

    `secret` is WRITE-ONLY like every other credential field in the portal: a
    blank/absent value means "leave it alone", never "clear it" — a browser
    cannot re-populate a secret it was never shown, so blank is what submitting
    the form without touching that field looks like. It is sealed here, before
    it reaches the JSON blob.

    Two sharing rules replace the region-level default this module used to
    keep. Both write INTO the environments, so a form always shows the whole
    truth — the difference between sharing and inheriting is that shared state
    is visible on every row it applies to:

    - A blank `url` COPIES the repository the region's other environments use
      — url, branch, credentials, deploy key — when they all use the same one.
      Ambiguous (two different repos among the siblings) or no siblings means
      the environment is declared without a repository, which its row shows.
    - A new `secret` PROPAGATES to every sibling environment on the same
      repository url: one token per repository per region, so a rotation typed
      once reaches all of them instead of silently expiring on the rest.

    Two names bound to the SAME repository, branch and path are the same files
    listed twice, and a list you cannot trust to have one row per thing is worse
    than a list that is missing a row. So declaring B where A already points
    undeclares A, and says so: returns the name it displaced, or "".
    """
    env = str(env).strip()
    if not env:
        return ""
    envs = dict((get_region(pid, rgid) or {}).get("envs") or {})
    cur = dict(envs.get(env) or {})
    binding = dict(binding)
    # a credential pasted INSIDE the url is moved to the sealed field before
    # anything is stored, so the address that gets displayed and exported is
    # never the address that carries the token
    if binding.get("url"):
        clean, user, pw = split_credentials(str(binding["url"]))
        binding["url"] = clean
        if user and not binding.get("username"):
            binding["username"] = user
        if pw and not binding.get("secret"):
            binding["secret"] = pw
    for k in ENV_FIELDS:
        if k == "secret":
            continue
        if k in binding:
            cur[k] = str(binding[k] or "").strip()
    if binding.get("secret"):
        cur["secret"] = secretbox.seal(str(binding["secret"]))

    if not cur.get("url"):
        donors = {(b.get("url"), b.get("branch") or ""): n
                  for n, b in envs.items()
                  if n != env and (b or {}).get("url")}
        if len({u for u, _ in donors}) == 1:
            (d_url, d_branch), donor = next(iter(donors.items()))
            cur["url"] = d_url
            # fill the blank only — an environment that TYPED its branch is
            # naming a different branch of the shared repository, which is
            # precisely the case this model exists to express
            cur["branch"] = cur.get("branch") or d_branch
            d = envs.get(donor) or {}
            for k in ("protocol", "username", "secret"):
                if d.get(k) and not cur.get(k):
                    cur[k] = d[k]          # sealed stays sealed — a blob copy
            dkey = ssh_key_path(pid, rgid, donor)
            ekey = ssh_key_path(pid, rgid, env)
            if dkey.exists() and not ekey.exists():
                ekey.write_text(dkey.read_text())
                os.chmod(ekey, 0o600)

    if binding.get("secret") and cur.get("url"):
        for n, b in envs.items():
            if n != env and (b or {}).get("url") == cur["url"]:
                b["secret"] = cur["secret"]
                for k in ("protocol", "username"):
                    if cur.get(k):
                        b[k] = cur[k]

    envs[env] = cur
    here = (cur.get("url", ""), cur.get("branch", ""), cur.get("path", ""))
    displaced = ""
    if any(here):
        for other, b in list(envs.items()):
            if other != env and (b or {}).get("path") and \
                    ((b.get("url", ""), b.get("branch", ""), b.get("path", ""))
                     == here):
                envs.pop(other)
                displaced = other
    _update("regions", rgid, {"envs": envs})
    _bump()
    return displaced


def drop_env_source(pid: str, rgid: str, env: str) -> None:
    """Undeclare an environment. The repository is untouched — this is the
    portal forgetting about it, which is why it is not a typed-Delete."""
    envs = dict((get_region(pid, rgid) or {}).get("envs") or {})
    if envs.pop(str(env).strip(), None) is None:
        return
    _update("regions", rgid, {"envs": envs})
    _bump()


# ── clusters (project-level pool) ───────────────────────────────
def add_cluster(pid: str, name: str, kubeconfig: str, context: str,
                sealing_cert: str = "") -> str:
    cid = new_id("c")
    with db.tx() as c:
        _insert(c, "clusters", cid,
                _next_ord(c, "clusters", "pid = ?", (pid,)),
                {"pid": pid, "name": name, "context": context, "status": "",
                 "kubeconfig_file": "", "cert_file": ""})
    _bump()
    write_cluster_files(pid, cid, kubeconfig, sealing_cert)
    return cid


def write_cluster_files(pid: str, cid: str, kubeconfig: str = "",
                        sealing_cert: str = "") -> None:
    """Store the kubeconfig and sealing certificate as files.

    They stay on disk rather than in the database because kubectl and kubeseal
    take a path, not a string; the row keeps the path.
    """
    d = SECRETS / pid
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    fields = {}
    if kubeconfig.strip():
        f = d / f"{cid}-kubeconfig.yaml"
        f.write_text(kubeconfig)
        os.chmod(f, 0o600)
        fields["kubeconfig_file"] = str(f)
    if sealing_cert.strip():
        f = d / f"{cid}-sealing.pem"
        f.write_text(sealing_cert)
        os.chmod(f, 0o600)
        fields["cert_file"] = str(f)
    if fields:
        _update("clusters", cid, fields)


def update_cluster(pid: str, cid: str, **fields) -> None:
    _update("clusters", cid, fields)


def get_cluster(pid: str, cid: str) -> dict | None:
    return (get_project(pid) or {}).get("clusters", {}).get(cid)


def move_cluster(pid: str, cid: str, new_pid: str) -> list[str]:
    """Move a cluster to another project. Returns the mappings it gave up.

    Three things have to move together or the move is a slow-acting bug:

    - the ROW's `pid`, which is what every listing reads;
    - its SECRET FILES, which live under `SECRETS/<pid>/`. The row stores
      absolute paths, so leaving them behind would keep working — right up
      until the old project is deleted, which removes that whole directory and
      takes this cluster's kubeconfig with it;
    - the ENV→CLUSTER MAPPINGS in the OLD project's regions. An environment in
      project A pointing at a cluster now in project B is not a relationship
      the portal has anywhere to show, so those are cleared and NAMED, rather
      than left to read as "nothing deployed" with no explanation.

    Its `id` is kept: that is what `cluster_update` keeps too, and for the same
    reason — a new id is a new cluster as far as every other reference goes.
    """
    if not new_pid or new_pid == pid or get_project(new_pid) is None:
        return []
    dropped: list[str] = []
    # COPY, commit, then remove the originals. A move done the other way round
    # leaves the two halves able to disagree: the transaction rolls the ROW back
    # on any failure, but a file already moved does not come back with it, and
    # the row would then name a kubeconfig that is not there. Copying first
    # means the worst case is a stray duplicate under the new project, which
    # nothing reads and the next move overwrites.
    with db.tx() as c:
        row = c.execute("SELECT kubeconfig_file, cert_file FROM clusters "
                        "WHERE id = ? AND pid = ?", (cid, pid)).fetchone()
        if row is None:
            return []
        dest = SECRETS / new_pid
        dest.mkdir(parents=True, exist_ok=True)
        os.chmod(dest, 0o700)
        copied, originals = {}, []
        for col in ("kubeconfig_file", "cert_file"):
            src = Path(row[col]) if row[col] else None
            if src is None or not src.exists():
                continue
            tgt = dest / src.name
            shutil.copy2(str(src), str(tgt))
            os.chmod(tgt, 0o600)
            copied[col] = str(tgt)
            originals.append(src)
        sets = ", ".join(["pid = ?"] + [f"{k} = ?" for k in copied])
        c.execute(f"UPDATE clusters SET {sets} WHERE id = ?",
                  [new_pid, *copied.values(), cid])
        for rg in c.execute("SELECT id, name, data FROM regions WHERE pid = ?",
                            (pid,)).fetchall():
            extra = json.loads(rg["data"] or "{}")
            mapping = extra.get("env_clusters") or {}
            kept = {k: v for k, v in mapping.items() if v != cid}
            if kept != mapping:
                dropped += [f"{rg['name']}/{e}" for e, v in mapping.items()
                            if v == cid]
                extra["env_clusters"] = kept
                c.execute("UPDATE regions SET data = ? WHERE id = ?",
                          (json.dumps(extra), rg["id"]))
    # committed: the row now names the copies, so the originals are dead weight
    # and leaving them would leave a readable credential in the old project's
    # directory
    for src in originals:
        src.unlink(missing_ok=True)
    _bump()
    return dropped


def delete_cluster(pid: str, cid: str) -> None:
    """Drop the cluster, its secret files, and any environment mapped to it."""
    with db.tx() as c:
        row = c.execute("SELECT kubeconfig_file, cert_file FROM clusters "
                        "WHERE id = ?", (cid,)).fetchone()
        if row is None:
            return
        for f in (row["kubeconfig_file"], row["cert_file"]):
            if f:
                Path(f).unlink(missing_ok=True)
        c.execute("DELETE FROM clusters WHERE id = ?", (cid,))
        # an environment left pointing at a deleted cluster would silently read
        # as "no cluster", so the mapping goes with it
        for rg in c.execute("SELECT id, data FROM regions WHERE pid = ?",
                            (pid,)).fetchall():
            extra = json.loads(rg["data"] or "{}")
            mapping = extra.get("env_clusters") or {}
            kept = {k: v for k, v in mapping.items() if v != cid}
            if kept != mapping:
                extra["env_clusters"] = kept
                c.execute("UPDATE regions SET data = ? WHERE id = ?",
                          (json.dumps(extra), rg["id"]))
    _bump()


def _tok(*parts: str) -> set:
    """Split on non-alphanumerics. Matching whole tokens rather than substrings
    is what stops a 'prod' environment from claiming a 'preprod' cluster."""
    return {t for t in re.split(r"[^a-z0-9]+", " ".join(parts).lower()) if t}


def _cluster_by_name(pid: str, rg: dict, env: str) -> dict | None:
    """Find the cluster whose name or context names both this region and this
    environment — e.g. region TZ + env preprod matches the cluster
    region 'eu' + env 'staging' matches a cluster named 'eu-staging'
    or context 'eu-staging-prod-cluster'.

    Deliberately conservative: both parts must appear as whole tokens, so a
    near-miss resolves to nothing rather than to the wrong cluster.
    """
    rname = (rg.get("name") or "").lower()
    want = _tok(env)
    if not rname or not want:
        return None
    for c in (get_project(pid) or {}).get("clusters", {}).values():
        toks = _tok(c.get("name", ""), c.get("context", ""))
        if rname in toks and want <= toks:
            return {**c, "matched_by": "name"}
    return None


def cluster_for_env(pid: str, rgid: str, env: str) -> dict | None:
    """The cluster serving this environment.

    An explicit env_clusters entry always wins. Without one, fall back to
    matching on name so a cluster added today is usable immediately instead of
    reading as "no cluster" until someone wires the mapping by hand.
    """
    rg = get_region(pid, rgid) or {}
    cid = rg.get("env_clusters", {}).get(env)
    if cid:
        return get_cluster(pid, cid)
    return _cluster_by_name(pid, rg, env)


def serves(view: dict | None = None, pid: str = "") -> dict:
    """cid -> the environments that cluster serves. The reverse of
    `cluster_for_env`, and the ONE implementation of it.

    WHY THIS EXISTS. Six pages needed this and each built it inline, in a
    slightly different shape: the top bar wanted "KE/preprod" label strings,
    the cluster card wanted {label, url}, the settings page wanted the binding
    and a file count, and the expiry radar wanted just the set of region names.
    Fifteen inline walks of `env_clusters` outside this module against seven
    uses of the named accessor -- so the forward direction had one definition
    and the reverse had six, which is five of them free to drift. It is also
    the first thing "what breaks if this cluster goes" needs, and that question
    is now on the expiry radar.

    It lives HERE, next to `cluster_for_env`, rather than in the module that
    wanted it most. A canonical index inside a new optional module cannot be
    adopted by the top bar, by `fleet` or by `expiry` without those depending
    on it -- and an index only some readers use is the six copies again with
    extra steps.

    THE VIEW IS AN ARGUMENT, not something this reaches for. `bind` and
    `files` come from `repo.list_envs`/`repo.binding`, which read the git
    checkout: pulling them in here would put a disk read behind the top bar
    and make `store` import `repo`. So a caller that already holds an enriched
    view (`main._project_view`) passes it and gets those fields; a caller that
    does not gets `{}` and `0`, exactly as the inline versions did.

    A cluster nothing points at is ABSENT from the result rather than present
    and empty -- "unmapped" is a real state that several of these pages render
    deliberately, and it is the caller's word for it, not this function's.
    """
    view = projects() if view is None else view
    out: dict = {}
    for p_id, p in view.items():
        if pid and p_id != pid:
            continue
        for rgid, rg in (p.get("regions") or {}).items():
            region = rg.get("name") or rgid
            declared = rg.get("envs") or {}
            binds = rg.get("bind") or {}
            for env, cid in (rg.get("env_clusters") or {}).items():
                if not cid:
                    continue
                out.setdefault(cid, []).append({
                    "pid": p_id, "cid": cid, "rgid": rgid,
                    "region": region, "flag": rg.get("flag", ""), "env": env,
                    "bind": binds.get(env) or {},
                    "files": len(declared.get(env) or []),
                    # Both spellings the six call sites used, so a caller
                    # projects rather than reformats.
                    "label": f"{region} / {env}",
                    "where": f"{region}/{env}",
                    "url": f"/p/{p_id}/{rgid}/{env}",
                })
    for rows in out.values():
        rows.sort(key=lambda r: (r["region"].lower(), r["env"].lower()))
    return out


# ── paths ──────────────────────────────────────────────────────
def repo_dir(pid: str, rgid: str) -> Path:
    return REPOS / pid / rgid


def source_dir(url: str, branch: str) -> Path:
    """The working copy for one (repository, branch) pair.

    Keyed by content, not by owner, so twenty clusters reading the same monorepo
    branch share one checkout instead of cloning it twenty times. A branch gets
    its own directory because one working copy cannot be on two branches at
    once — which is the whole reason environments needed their own bindings.

    Sharing is safe: nothing here decides who may read what. Access is checked
    against (project, region, environment) long before a path is resolved, and
    two bindings that hash together are the same repository at the same branch,
    so there is no content one of them should not see.
    """
    key = hashlib.sha256(f"{url.strip()}\n{branch.strip()}".encode()).hexdigest()
    return REPOS / "_src" / key[:16]


def ssh_key_path(pid: str, rgid: str, env: str = "") -> Path:
    """The region's own deploy key, or one environment's — a distinct file, so
    an environment on a genuinely different host is not stuck reusing a key
    that would not even be offered to that host."""
    d = SECRETS / pid
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    env = str(env or "").strip()
    return d / (f"{rgid}-{env}-id" if env else f"{rgid}-id")


def normalise_ssh_key(key: str) -> str:
    """A pasted private key, as OpenSSH will accept it.

    A browser textarea submits CRLF, and ssh refuses such a file outright with
    "invalid format" — which then surfaces as a permission-denied against the
    remote, blaming the deploy key for a line-ending problem. So: CR stripped,
    trailing spaces off each line (some clients pad the base64 body), and exactly
    one newline at the end, which OpenSSH also requires.
    """
    text = (key or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in text.strip().split("\n")]
    return "\n".join(ln for ln in lines if ln) + "\n"


def _encrypted(body: str) -> bool:
    """Does this private key have a passphrase?

    Read from the key rather than inferred from ssh-keygen's behaviour: an
    OpenSSH key is base64 of "openssh-key-v1\\0" followed by the cipher name,
    and "none" means unencrypted. Asking ssh-keygen meant asking a program that
    prompts for a passphrase, whose blocking depended on what stdin was.
    """
    if "Proc-Type: 4,ENCRYPTED" in body or "ENCRYPTED PRIVATE KEY" in body:
        return True                       # traditional PEM, and PKCS#8
    lines = [ln for ln in body.split("\n") if ln and not ln.startswith("---")]
    try:
        raw = base64.b64decode("".join(lines), validate=False)
    except Exception:                                          # noqa: BLE001
        return False
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return False
    rest = raw[len(magic):]
    if len(rest) < 4:
        return False
    n = int.from_bytes(rest[:4], "big")
    cipher = rest[4:4 + n].decode("ascii", "replace")
    return cipher not in ("none", "")


def ssh_key_problem(key: str) -> str:
    """"" when this is a usable private key, else what is wrong with it.

    Checked at the point of paste rather than at the point of clone, because the
    error git gives is about access rights and sends you looking at GitHub.
    """
    body = normalise_ssh_key(key)
    if not body.strip():
        return "no key given"
    if "PRIVATE KEY" not in body.split("\n")[0]:
        return ("this does not start with a BEGIN … PRIVATE KEY line — paste the "
                "private half of the key, not the .pub file")
    if "PUBLIC KEY" in body or body.startswith(("ssh-", "ecdsa-")):
        return "this is the public key; the portal needs the private one"
    if not body.rstrip().endswith("PRIVATE KEY-----"):
        return "the END … PRIVATE KEY line is missing — paste the whole block"
    if _encrypted(body):
        return ("this key has a passphrase. The portal runs git without a "
                "terminal, so it cannot be unlocked — use a key with no "
                "passphrase")
    # the real check, when ssh-keygen is available: it parses what ssh parses
    exe = shutil.which("ssh-keygen")
    if exe:
        with tempfile.NamedTemporaryFile("w", suffix="-id", delete=False) as fh:
            fh.write(body)
            tmp = fh.name
        try:
            os.chmod(tmp, 0o600)
            # stdin closed and no askpass helper: ssh-keygen prompts for a
            # passphrase otherwise, and whether it blocks or returns depends on
            # what stdin happens to be — which made this check pass or fail by
            # luck. The passphrase case is already decided above, from the key
            # itself.
            env = {**os.environ, "SSH_ASKPASS": "", "DISPLAY": ""}
            env.pop("SSH_ASKPASS_REQUIRE", None)
            r = subprocess.run([exe, "-y", "-f", tmp], capture_output=True,
                               text=True, timeout=10,
                               stdin=subprocess.DEVNULL, env=env)
            if r.returncode != 0:
                detail = (r.stderr or r.stdout).strip().splitlines()
                why = detail[-1] if detail else "ssh-keygen rejected it"
                return f"ssh could not read this key: {why}"
        except (OSError, subprocess.SubprocessError):
            pass                      # cannot verify here; git will say
        finally:
            os.unlink(tmp)
    return ""


def write_ssh_key(pid: str, rgid: str, key: str, env: str = "") -> str:
    p = ssh_key_path(pid, rgid, env)
    p.write_text(normalise_ssh_key(key))
    os.chmod(p, 0o600)
    return str(p)


# ── external connections (CI/CD, scanners, log and metric stores) ──
# A connection is either global (pid == "") — the usual case for one central
# Jenkins or one DefectDojo serving every project — or scoped to a project.
# `kind` selects which page it belongs to.
GLOBAL = ""
CONN_KINDS = ("ci", "sec", "log", "mon", "stor", "cloud",
              "gitops", "wf", "bmc", "virt", "edge")

# Fields whose stored value is never rendered back into the form: the input
# shows "stored — type to replace" and submits EMPTY when the user leaves it
# alone. Applying that empty would wipe a working credential on an unrelated
# edit, so for these — and only these — an empty submission means "keep".
# Every other field is the user's to clear. Keep this in step with the
# write-only inputs in the templates; test_writeonly.py fails if it drifts.
WRITE_ONLY = ("token", "secret", "client_secret", "password",
              "private_key", "api_key")


def add_conn(kind: str, pid: str, conn: dict) -> str:
    cid = new_id(kind)
    with db.tx() as c:
        _insert(c, "conns", cid,
                _next_ord(c, "conns", "kind = ?", (kind,)),
                {**conn, "kind": kind, "pid": pid})
    _bump()
    return cid


def get_conn(kind: str, pid: str, cid: str) -> dict | None:
    row = db.one("SELECT * FROM conns WHERE id = ? AND kind = ? AND pid = ?",
                 (cid, kind, pid))
    if row is None:
        return None
    conn = _row("conns", row)
    conn.pop("kind", None)
    return conn


def update_conn(kind: str, pid: str, cid: str, **fields) -> None:
    """Apply an edit. A blank usually means "leave as is" — but not always.

    The blank-means-keep rule exists for one field: the secret. Its input shows
    "stored — type to replace" and submits empty when untouched, so applying
    that empty would wipe a working credential on every unrelated edit.

    It was applied to EVERY field, which made anything optional impossible to
    clear. Bitbucket is where that surfaced: an access token has no user and
    must be sent as Bearer, which the portal decides by the username being
    blank — and blanking it silently kept the old value, so the connection
    could not be moved off Basic auth at all. The field just refilled itself
    on save, which reads as the form ignoring you.

    So the exception list is now the other way round: the secret-ish fields keep
    their stored value when submitted empty, and everything else is applied as
    given, including empty.
    """
    _update("conns", cid,
            {k: v for k, v in fields.items()
             if v != "" or k not in WRITE_ONLY})


def delete_conn(kind: str, pid: str, cid: str) -> None:
    db.run("DELETE FROM conns WHERE id = ? AND kind = ?", (cid, kind))
    _bump()


def all_conns(kind: str) -> list[dict]:
    """Every connection of this kind, global first, each carrying its owning
    pid ("" = global)."""
    out = []
    for r in db.q("SELECT * FROM conns WHERE kind = ? "
                  "ORDER BY CASE WHEN pid = '' THEN 0 ELSE 1 END, ord, id",
                  (kind,)):
        conn = _row("conns", r)
        conn.pop("kind", None)
        out.append(conn)
    return out


# CI/CD
def add_ci(pid: str, conn: dict) -> str:
    return add_conn("ci", pid, conn)


def get_ci(pid: str, cid: str) -> dict | None:
    return get_conn("ci", pid, cid)


def update_ci(pid: str, cid: str, **fields) -> None:
    update_conn("ci", pid, cid, **fields)


def delete_ci(pid: str, cid: str) -> None:
    delete_conn("ci", pid, cid)


def all_ci() -> list[dict]:
    return all_conns("ci")


# security scan platforms
def add_sec(pid: str, conn: dict) -> str:
    return add_conn("sec", pid, conn)


def get_sec(pid: str, cid: str) -> dict | None:
    return get_conn("sec", pid, cid)


def update_sec(pid: str, cid: str, **fields) -> None:
    update_conn("sec", pid, cid, **fields)


def delete_sec(pid: str, cid: str) -> None:
    delete_conn("sec", pid, cid)


def all_sec() -> list[dict]:
    return all_conns("sec")


# log platforms
def add_log(pid: str, conn: dict) -> str:
    return add_conn("log", pid, conn)


def get_log(pid: str, cid: str) -> dict | None:
    return get_conn("log", pid, cid)


def update_log(pid: str, cid: str, **fields) -> None:
    update_conn("log", pid, cid, **fields)


def delete_log(pid: str, cid: str) -> None:
    delete_conn("log", pid, cid)


def all_log() -> list[dict]:
    return all_conns("log")


# GitOps controllers (Argo CD, Flux)
def add_gitops(pid: str, conn: dict) -> str:
    return add_conn("gitops", pid, conn)


def get_gitops(pid: str, cid: str) -> dict | None:
    return get_conn("gitops", pid, cid)


def update_gitops(pid: str, cid: str, **fields) -> None:
    update_conn("gitops", pid, cid, **fields)


def delete_gitops(pid: str, cid: str) -> None:
    delete_conn("gitops", pid, cid)


def all_gitops() -> list[dict]:
    return all_conns("gitops")


# edge and DNS (Cloudflare, Fastly, Bunny, NS1)
def add_edge(pid: str, conn: dict) -> str:
    return add_conn("edge", pid, conn)


def get_edge(pid: str, cid: str) -> dict | None:
    return get_conn("edge", pid, cid)


def update_edge(pid: str, cid: str, **fields) -> None:
    update_conn("edge", pid, cid, **fields)


def delete_edge(pid: str, cid: str) -> None:
    delete_conn("edge", pid, cid)


def all_edge() -> list[dict]:
    return all_conns("edge")


# workflow engines (Temporal, Airflow)
def add_wf(pid: str, conn: dict) -> str:
    return add_conn("wf", pid, conn)


def get_wf(pid: str, cid: str) -> dict | None:
    return get_conn("wf", pid, cid)


def update_wf(pid: str, cid: str, **fields) -> None:
    update_conn("wf", pid, cid, **fields)


def delete_wf(pid: str, cid: str) -> None:
    delete_conn("wf", pid, cid)


def all_wf() -> list[dict]:
    return all_conns("wf")


# server BMCs (iDRAC, iLO — Redfish)
def add_bmc(pid: str, conn: dict) -> str:
    return add_conn("bmc", pid, conn)


def get_bmc(pid: str, cid: str) -> dict | None:
    return get_conn("bmc", pid, cid)


def update_bmc(pid: str, cid: str, **fields) -> None:
    update_conn("bmc", pid, cid, **fields)


def delete_bmc(pid: str, cid: str) -> None:
    delete_conn("bmc", pid, cid)


def all_bmc() -> list[dict]:
    return all_conns("bmc")


# hypervisors (Proxmox, vCenter/ESXi)
def add_virt(pid: str, conn: dict) -> str:
    return add_conn("virt", pid, conn)


def get_virt(pid: str, cid: str) -> dict | None:
    return get_conn("virt", pid, cid)


def update_virt(pid: str, cid: str, **fields) -> None:
    update_conn("virt", pid, cid, **fields)


def delete_virt(pid: str, cid: str) -> None:
    delete_conn("virt", pid, cid)


def all_virt() -> list[dict]:
    return all_conns("virt")


# cloud accounts (AWS, Azure, Alibaba, GCP, anything with an API)
def add_cloud(pid: str, conn: dict) -> str:
    return add_conn("cloud", pid, conn)


def get_cloud(pid: str, cid: str) -> dict | None:
    return get_conn("cloud", pid, cid)


def update_cloud(pid: str, cid: str, **fields) -> None:
    update_conn("cloud", pid, cid, **fields)


def delete_cloud(pid: str, cid: str) -> None:
    delete_conn("cloud", pid, cid)


def all_cloud() -> list[dict]:
    return all_conns("cloud")


# storage devices (backup targets: NAS boxes, object stores, plain shares)
def add_stor(pid: str, conn: dict) -> str:
    return add_conn("stor", pid, conn)


def get_stor(pid: str, cid: str) -> dict | None:
    return get_conn("stor", pid, cid)


def update_stor(pid: str, cid: str, **fields) -> None:
    update_conn("stor", pid, cid, **fields)


def delete_stor(pid: str, cid: str) -> None:
    delete_conn("stor", pid, cid)


def all_stor() -> list[dict]:
    return all_conns("stor")


# monitoring platforms
def add_mon(pid: str, conn: dict) -> str:
    return add_conn("mon", pid, conn)


def get_mon(pid: str, cid: str) -> dict | None:
    return get_conn("mon", pid, cid)


def update_mon(pid: str, cid: str, **fields) -> None:
    update_conn("mon", pid, cid, **fields)


def delete_mon(pid: str, cid: str) -> None:
    delete_conn("mon", pid, cid)


def all_mon() -> list[dict]:
    return all_conns("mon")


# database servers (PostgreSQL, MySQL/MariaDB)
# The one connection kind that stores no credentials: see dbconn.py for why.
def add_db(pid: str, conn: dict) -> str:
    return add_conn("db", pid, conn)


def get_db(pid: str, cid: str) -> dict | None:
    return get_conn("db", pid, cid)


def update_db(pid: str, cid: str, **fields) -> None:
    update_conn("db", pid, cid, **fields)


def delete_db(pid: str, cid: str) -> None:
    delete_conn("db", pid, cid)


def all_db() -> list[dict]:
    return all_conns("db")


# VPN portals (Pritunl, OpenVPN Access Server, wg-easy, Netmaker)
def add_vpn(pid: str, conn: dict) -> str:
    return add_conn("vpn", pid, conn)


def get_vpn(pid: str, cid: str) -> dict | None:
    return get_conn("vpn", pid, cid)


def update_vpn(pid: str, cid: str, **fields) -> None:
    update_conn("vpn", pid, cid, **fields)


def delete_vpn(pid: str, cid: str) -> None:
    delete_conn("vpn", pid, cid)


def all_vpn() -> list[dict]:
    return all_conns("vpn")
