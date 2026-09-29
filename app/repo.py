"""Read/write service values files, preserving YAML format.

Every environment DECLARES where its values live — repository, branch, path,
credentials — as a complete, explicit binding on its region row. There is no
region-level repository any more: an earlier model kept one as an invisible
default that environments inherited from, and once its settings page was
retired it became configuration nothing could show or edit — a diagram that
kept rendering from a repo no form admitted to knowing about. `_absorb` is the
one-time migration that folded those defaults into the bindings.
"""
import io
import os
import re
import shutil
from fnmatch import fnmatch
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.constructor import DuplicateKeyError

from . import values
from . import secretbox, store, yamledit

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096  # never wrap long sealed blobs
# Helm reads values files through sigs.k8s.io/yaml, which tolerates a repeated
# key and keeps the last one. Refusing to parse what Helm happily deploys would
# make the portal blind to exactly the files most worth looking at, so match
# Helm's behaviour here and report the duplicate as a warning instead.
yaml.allow_duplicate_keys = True

# a second, strict parser used only to detect what the lenient one forgave
_strict = YAML()
_strict.allow_duplicate_keys = False


def lint(text: str) -> list[str]:
    """Problems worth telling the user about in a file that still parses.

    Currently duplicate keys: legal to Helm but almost always a mistake, since
    the earlier definition is silently discarded.
    """
    try:
        _strict.load(text)
        return []
    except DuplicateKeyError as e:
        m = re.search(r'duplicate key "([^"]+)"', str(e))
        line = re.search(r"line (\d+)", str(e).split("original")[-1])
        key = m.group(1) if m else "a key"
        where = f" (line {line.group(1)})" if line else ""
        return [f'duplicate key "{key}"{where} — Helm keeps the last one and '
                f"silently discards the earlier definition"]
    except Exception:
        return []

# Naming conventions are per-project settings, never constants here. An earlier
# version of this module carried one team's service names, key prefixes and
# filename quirks as module-level lists, which made the portal silently wrong for
# anyone else's repository. Those values now live in each project's settings
# (hidden_services, hidden_key_prefixes, strip_suffixes) and default to empty:
# nothing is hidden or rewritten unless a project asks for it.


# ── schema helpers (repos differ in shape) ─────────────────────
def _config_section(data):
    cm = data.get("configMap")
    if isinstance(cm, dict) and isinstance(cm.get("data"), dict):
        return cm["data"]
    if isinstance(data.get("config"), dict):
        return data["config"]
    return None


def _sealed_section(data):
    sec = data.get("secret")
    if isinstance(sec, dict) and isinstance(sec.get("SealedSecret"), dict):
        return sec["SealedSecret"]
    if isinstance(data.get("SealedSecret"), dict):
        return data["SealedSecret"]
    return None


def _secret_name(data):
    sec = data.get("secret")
    if isinstance(sec, dict) and sec.get("secretName"):
        return sec["secretName"]
    return data.get("secretName")


# ── naming ─────────────────────────────────────────────────────
def _base(fname: str) -> str:
    """Service name from a values filename.

    Matches any `values*.yaml` suffix generically — `-values.yaml`,
    `-values02.yaml`, `-values-eu.yaml`, and `.values.yaml`/`_values.yaml` too —
    rather than listing the variants one repository happens to use. A `<svc>.yaml`
    with no `values` marker falls back to the filename stem.
    """
    return re.sub(r"[-_.]values[^.]*\.ya?ml$", "", fname).removesuffix(".yaml")


def service_display(fname: str, strip: tuple = ()) -> str:
    """Display name for the default (env=folder) layout. `strip` holds
    project-configured suffixes to drop (e.g. "-worker"); with none configured the
    filename's own name is shown as-is. (Custom layouts derive the name from the
    pattern in `display()`.)"""
    return _strip_suffixes(_base(fname), strip)


def is_service_file(fname: str, hidden: tuple = ()) -> bool:
    """Whether to list this file. `hidden` holds project-configured glob
    patterns matched against the service name — "mock*", "*-worker",
    "bff-backoffice". Empty means show everything."""
    return not _hidden(_base(fname), hidden)


def is_platform_key(key: str, prefixes: tuple = ()) -> bool:
    """Whether a config key is platform-level rather than service-level.
    `prefixes` is project-configured; empty means every key is a service key."""
    return any(key.startswith(str(p)) for p in (prefixes or ()) if str(p).strip())


def display(pid: str, fname: str) -> str:
    """Display name using this project's configured suffix stripping.

    Every caller must go through here: the service list, the search index, the
    compare matrix and the URL-to-file lookup all compare display names, so a
    project that strips a suffix has to strip it everywhere or those links stop
    resolving.
    """
    conv = naming(pid)
    return display_name(fname, conv["strip"], conv["pattern"])


def display_name(fname: str, strip: tuple = (), pattern: str = "") -> str:
    """The service display name from a fname, given the project's strip suffixes
    and layout pattern. With a pattern the name comes from its {svc} capture (over
    the decoded rel path); otherwise from the filename's `-values*` strip. Shared
    by `display()` and the `service_display` template global."""
    if pattern:
        _, svc = _pattern_split(pattern, _dec(fname))
        if svc:
            return _strip_suffixes(svc, strip)
    return service_display(fname, strip)


def naming(pid: str) -> dict:
    """The calling project's naming + LAYOUT conventions, with safe empty defaults.
    `globs` is which files count as a service file in the default (env=folder)
    layout; `pattern` is the general escape hatch — a path pattern with {env} and
    {svc} over the path under values_path, covering flat / service-first / nested /
    any structure. Empty pattern = the default subdir layout."""
    p = store.get_project(pid) or {}
    globs = tuple(g.strip() for g in (p.get("values_globs") or ()) if str(g).strip())
    return {
        "hidden": tuple(p.get("hidden_services") or ()),
        "prefixes": tuple(p.get("hidden_key_prefixes") or ()),
        "strip": tuple(p.get("strip_suffixes") or ()),
        "aliases": dict(p.get("env_aliases") or {}),
        "globs": globs or (VALUES_GLOB,),
        "pattern": (p.get("layout_pattern") or "").strip(),
    }


# the default: a values file is `*-values*.yaml`. Overridable per project via
# `values_globs` (subdir layout) or `layout_pattern` (any layout).
VALUES_GLOB = "*-values*.yaml"

# a rel path can hold `/`, but `fname` is a single URL segment (`…/s/{fname}/save`),
# so custom-layout fnames carry the path with `/` swapped for `~`. The swap lives
# ENTIRELY inside repo.py — every caller treats fname as an opaque token, so routes,
# templates and handlers are untouched. `~` is effectively never in a GitOps path.
_SEP = "~"


def _enc(rel: str) -> str:
    return rel.replace("/", _SEP)


def _dec(fname: str) -> str:
    return fname.replace(_SEP, "/")


def _service_globs(conv: dict) -> tuple:
    return conv.get("globs") or (VALUES_GLOB,)


def _strip_suffixes(name: str, strip: tuple) -> str:
    for suffix in strip or ():
        s = str(suffix).strip()
        if s and name.endswith(s) and name != s:
            return name[: -len(s)]
    return name


# ── the layout pattern engine (covers every repo structure) ────
# A pattern is a path template relative to values_path. Tokens:
#   {env}            the environment name (one path segment / part)
#   {svc}/{service}  the service name
#   *                wildcard within a path segment
#   **               matches across segments (** / = zero-or-more leading segments)
#   anything else    literal (so `-values.yaml`, `/`, `.` anchor the captures)
# Examples: `{env}/{svc}-values*.yaml` (classic) · `{svc}-{env}-values.yaml` (flat)
#   · `{svc}/{env}/values.yaml` (service-first) · `*/{env}/{svc}-values.yaml` (nested).
def _compile_pattern(pat: str):
    out, i, n = ["^"], 0, len(pat)
    while i < n:
        if pat.startswith("{env}", i):
            out.append(r"(?P<env>[^/]+)"); i += 5
        elif pat.startswith("{svc}", i):
            out.append(r"(?P<svc>[^/]+?)"); i += 5
        elif pat.startswith("{service}", i):
            out.append(r"(?P<svc>[^/]+?)"); i += 9
        elif pat.startswith("**/", i):
            out.append(r"(?:[^/]+/)*"); i += 3
        elif pat.startswith("**", i):
            out.append(r".*"); i += 2
        elif pat[i] == "*":
            out.append(r"[^/]*"); i += 1
        else:
            out.append(re.escape(pat[i])); i += 1
    out.append("$")
    try:
        return re.compile("".join(out))
    except re.error:
        return None


def _pattern_split(pat: str, rel: str) -> tuple:
    """(env, service) for one rel path against the pattern, or (None, None)."""
    rx = _compile_pattern(pat)
    if rx is None:
        return (None, None)
    m = rx.match(rel)
    if not m:
        return (None, None)
    gd = m.groupdict()
    svc = gd.get("svc") or _base(rel.rsplit("/", 1)[-1])
    return (gd.get("env"), svc)


def _pattern_build(pat: str, env: str, svc: str) -> str | None:
    """Where a NEW (env, svc) file lives per the pattern — substitute {env}/{svc}.
    None when the pattern has a wildcard (ambiguous, can't place a new file)."""
    if "*" in pat:
        return None
    rel = pat.replace("{service}", "{svc}").replace("{env}", env).replace("{svc}", svc)
    return rel if "{" not in rel else None


def _pattern_entries(root: Path, pat: str):
    """(env, svc, rel-posix) for every file under root matching the pattern.
    Bounded and skips .git; walks the whole tree so any depth is covered."""
    rx = _compile_pattern(pat)
    if rx is None or not root.is_dir():
        return []
    out = []
    for f in root.rglob("*"):
        if ".git" in f.parts or not f.is_file():
            continue
        rel = f.relative_to(root).as_posix()
        m = rx.match(rel)
        if not m:
            continue
        env = m.groupdict().get("env")
        if env:
            out.append((env, m.groupdict().get("svc") or _base(f.name), rel))
    return out


# ── auto-detect the layout from the repo tree ──────────────────
# Ordered candidate layouts, tried against the checkout to SUGGEST a config so a
# user need not write a pattern. Directory-based (unambiguous) first; the flat
# `svc-env` forms are last, because a hyphenated name is inherently ambiguous.
_DETECT_GLOBS = [VALUES_GLOB, "*.values.yaml", "values*.yaml", "*.yaml"]
_DETECT_PATTERNS = [
    "{env}/{svc}/values.yaml", "{env}/{svc}/values*.yaml",
    "{svc}/{env}/values.yaml", "{svc}/values-{env}.yaml",
    "*/{env}/{svc}-values.yaml", "*/{env}/{svc}.yaml",
    "**/{env}/{svc}-values.yaml",
    "{svc}-{env}-values.yaml", "{svc}-{env}.yaml",
]
# common environment names — used only to DISAMBIGUATE which captured dimension is
# the env when a structure fits both `{env}/{svc}` and `{svc}/{env}` (a pure guess
# otherwise). Region-named envs (KE, UG…) won't match, so the suggestion is shown
# with its env list for the user to correct.
_ENV_VOCAB = {"dev", "develop", "development", "staging", "stage", "stg", "prod",
              "production", "prd", "uat", "test", "testing", "qa", "sit", "preprod",
              "pre-prod", "pp", "live", "sandbox", "sbx", "demo", "int",
              "integration", "perf", "dr", "local", "nonprod", "canary"}


def _tree_rels(root: Path, cap: int = 20000) -> list[str]:
    out = []
    for f in root.rglob("*"):
        if ".git" in f.parts or not f.is_file():
            continue
        out.append(f.relative_to(root).as_posix())
        if len(out) >= cap:
            break
    return out


def _subdir_scan(rels: list[str], glob: str) -> dict[str, int]:
    """env -> file count for the default env=folder layout: a file directly under
    a single env folder (two path segments) matching `glob`."""
    out: dict = {}
    for r in rels:
        parts = r.split("/")
        if len(parts) == 2 and fnmatch(parts[1], glob):
            out[parts[0]] = out.get(parts[0], 0) + 1
    return out


def detect_layout(pid: str, rgid: str) -> dict | None:
    """Scan a region's checkout and SUGGEST a layout. Returns {kind, pattern,
    globs, envs, count} — kind 'default' (blank config already works), 'glob'
    (env folders, non-default file names), or 'pattern' (any other structure) —
    or None if nothing values-file-shaped was found. A suggestion, not gospel:
    the caller shows the envs so the user can sanity-check it."""
    root = env_root(pid, rgid)
    if not root.is_dir():
        return None
    rels = _tree_rels(root)
    for g in _DETECT_GLOBS:                       # env = folder, file directly inside
        envs = _subdir_scan(rels, g)
        if envs:
            return {"kind": "default" if g == VALUES_GLOB else "glob",
                    "pattern": "", "globs": [] if g == VALUES_GLOB else [g],
                    "envs": sorted(envs), "count": sum(envs.values())}
    best = None                                   # otherwise a general pattern
    for pat in _DETECT_PATTERNS:
        rx = _compile_pattern(pat)
        if rx is None:
            continue
        hits = [m.group("env") for r in rels
                if (m := rx.match(r)) and m.groupdict().get("env")]
        if not hits:
            continue
        distinct = set(hits)
        # prefer: recognisable env names (settles env-vs-svc position) > more files
        # matched > fewer distinct envs (the env dimension is usually the smaller
        # one) > fewer wildcards.
        vocab = sum(1 for e in distinct if e.lower() in _ENV_VOCAB)
        key = (vocab, len(hits), -len(distinct), -pat.count("*"))
        if best is None or key > best[0]:
            best = (key, pat, hits)
    if not best:
        return None
    return {"kind": "pattern", "pattern": best[1], "globs": [],
            "envs": sorted(set(best[2])), "count": len(best[2])}


def detect_layout_project(pid: str) -> dict | None:
    """Detect from the first region of the project that has a checkout — the
    layout is a project-wide convention, so any cloned region will do."""
    proj = store.get_project(pid) or {}
    for rgid, rg in (proj.get("regions") or {}).items():
        if env_root(pid, rgid).is_dir():
            d = detect_layout(pid, rgid)
            if d and d.get("count"):
                d["region"] = rg.get("name", rgid)
                return d
    return None


# ── paths ──────────────────────────────────────────────────────
# ── where one environment's values live ────────────────────────
# Every path in this module resolves through `binding` and `env_dir`. That is
# deliberate: the question "which checkout, which branch, which folder" now has
# one answer in one place, so an environment on its own branch or in its own
# repository works everywhere the portal reads values — pages, search, answers,
# the diagram, MCP — without any of them knowing that bindings exist.
def _absorb(pid: str, rgid: str) -> None:
    """Fold the legacy region-level repository into the environment bindings.

    One-time, lazy, per region — the same pattern as `_materialise`. Until
    August 2026 a region carried a default repository (url, branch, values
    path, credentials) that environments inherited from when their own fields
    were blank. Its settings page was then retired, which left it INVISIBLE:
    the diagram kept rendering from a repository no form admitted to knowing
    about, and there was nowhere left to fix a stale token. So the default is
    written INTO every environment that was inheriting it — url, branch,
    credentials (ciphertext-to-ciphertext where already sealed), deploy key —
    and then blanked, so what a form shows is the whole truth.

    The region's clone MOVES to the shared per-(repository, branch) checkout,
    preserving any uncommitted edits. If that checkout already exists (a
    sibling region absorbed first), the extra clone is left in place when it
    is not empty rather than deleted — a directory nothing reads is clutter; a
    deleted uncommitted edit is data loss.

    Runs only AFTER `_materialise` has written the declarations (`envs` is not
    None), because materialising needs the legacy values path this blanks.
    """
    rg = store.get_region(pid, rgid) or {}
    legacy = rg.get("repo") or {}
    url = (legacy.get("url") or "").strip()
    if not url or rg.get("envs") is None:
        return
    # a legacy address may carry its credential inline; split it here or the
    # migration fans one token out across every environment it touches, into
    # every surface that displays or exports a repository address
    url, legacy_user, legacy_pw = store.split_credentials(url)
    if legacy_user and not legacy.get("username"):
        legacy = {**legacy, "username": legacy_user}
    if legacy_pw and not legacy.get("secret"):
        legacy = {**legacy, "secret": legacy_pw}
    branch = (legacy.get("branch") or "").strip()
    region_key = store.ssh_key_path(pid, rgid)
    envs = {}
    for name, dec in (rg.get("envs") or {}).items():
        dec = dict(dec or {})
        if not (dec.get("url") or "").strip():
            dec["url"] = url
            dec["branch"] = (dec.get("branch") or "").strip() or branch
            for k in ("protocol", "username"):
                if legacy.get(k) and not dec.get(k):
                    dec[k] = legacy[k]
            if legacy.get("secret") and not dec.get("secret"):
                # seal() passes an already-sealed value through untouched and
                # seals a plaintext one from before credentials were sealed
                dec["secret"] = secretbox.seal(str(legacy["secret"]))
            ekey = store.ssh_key_path(pid, rgid, name)
            if region_key.exists() and not ekey.exists():
                ekey.write_text(region_key.read_text())
                os.chmod(ekey, 0o600)
        envs[name] = dec
    src, dst = store.repo_dir(pid, rgid), store.source_dir(url, branch)
    try:
        if src.is_dir() and any(src.iterdir()) and not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
    except OSError:
        pass          # sync_env re-clones on demand; the bindings still land
    store.update_region(pid, rgid, envs=envs, repo={})


def binding(pid: str, rgid: str, env: str) -> dict:
    """One environment's binding: repository, branch, path, auth — explicit.

    Exactly what is stored, nothing resolved from anywhere else: there is no
    region default left to inherit from, so a blank url is an environment with
    no repository, and the form that shows this binding shows the whole truth.

    `has_secret`/`has_ssh_key`/`has_own_auth` are booleans, never the credential
    itself — this is the view a TEMPLATE reads, and a template that could print
    a real secret is a template that eventually will. The one place that needs
    the actual value is `gitrepo.env_repo`, which reads the sealed field off
    `store.env_sources` directly rather than through here.

    Materialise-then-absorb runs here as well as in `list_envs`: this is the
    other entry point into the model, and a caller that asks for one binding
    before any page has listed the environments must not read a pre-migration
    region differently from a post-migration one.
    """
    _materialise(pid, rgid, naming(pid))
    _absorb(pid, rgid)
    dec = store.env_sources(pid, rgid).get(env) or {}
    own_ssh_key = store.ssh_key_path(pid, rgid, env).exists()
    # Writes strip a credential out of the address, but a row stored before
    # that did — or written straight into the database — must not hand one to
    # a template or an MCP client either. `url` is the DISPLAYED address, with
    # any userinfo removed; `_env_for` reassembles the real one from the
    # username and secret fields when it talks to git.
    clean, inline_user, inline_pw = store.split_credentials(dec.get("url") or "")
    return {"url": clean,
            "branch": dec.get("branch") or "",
            "path": (dec.get("path") or "").strip("/"),
            "recurse": bool(dec.get("recurse")),
            "pattern": dec.get("pattern") or "",
            "declared": bool(dec),
            "protocol": dec.get("protocol") or "",
            "username": dec.get("username") or inline_user,
            "has_secret": bool(dec.get("secret") or inline_pw),
            "has_ssh_key": own_ssh_key,
            "has_own_auth": bool(dec.get("protocol") or dec.get("username")
                                  or dec.get("secret") or own_ssh_key)}


def checkout(pid: str, rgid: str, env: str = "") -> Path:
    """The git working copy an environment reads from.

    Shared per (repository, branch): environments naming the same repo at the
    same branch read one clone, whatever region or project they sit in. An
    environment with no repository falls back to the region's legacy directory
    — that is where a demo install's hand-planted files live, and where a
    not-yet-absorbed region's clone still is.
    """
    if not env:
        return store.repo_dir(pid, rgid)
    b = binding(pid, rgid, env)
    if not b["url"]:
        return store.repo_dir(pid, rgid)
    return store.source_dir(b["url"], b["branch"])


def env_dir(pid: str, rgid: str, env: str) -> Path:
    """The directory holding that environment's values files."""
    b = binding(pid, rgid, env)
    return (checkout(pid, rgid, env) / b["path"]) if b["path"] else checkout(pid, rgid, env)


def env_root(pid: str, rgid: str, env: str = "") -> Path:
    """The values path (region-wide), or one environment's own directory.

    Kept for the callers that ask "where does this region's tree start"; a path
    for one environment should come from `env_dir`.
    """
    if env:
        return env_dir(pid, rgid, env)
    rg = store.get_region(pid, rgid) or {}
    return store.repo_dir(pid, rgid) / (rg.get("repo", {}).get("values_path") or "")


def env_overrides(pid: str, rgid: str) -> tuple[dict, set]:
    """(extra environments, environment names to drop) for this region.

    THE SCAN IS A GUESS, and a good one, but it is still a guess: a folder that
    looks like an environment and is not, or an environment whose values live
    somewhere the globs do not reach. Both were unfixable from the portal — the
    list was whatever the repository walk produced.

    So a region may carry two overrides beside its repo settings:
    `env_extra` {name: directory relative to the values path} adds one the scan
    missed, and `env_hidden` [name…] drops one it should not have found. They
    are applied HERE because `list_envs` is the single place every page, query
    and mapping reads environments from — corrected in one place, correct
    everywhere.
    """
    rg = store.get_region(pid, rgid) or {}
    extra = {str(k).strip(): str(v or "").strip().strip("/")
             for k, v in (rg.get("env_extra") or {}).items() if str(k).strip()}
    hidden = {str(x).strip() for x in (rg.get("env_hidden") or []) if str(x).strip()}
    return extra, hidden


def _svc_entries(root: Path, pat: str):
    """(svc, rel-posix) for every file under root matching a pattern that has
    no {env} — the per-environment form of `_pattern_entries`, used when an
    environment's files sit at pattern-shaped paths under its own directory."""
    rx = _compile_pattern(pat)
    if rx is None or not root.is_dir():
        return []
    out = []
    for f in root.rglob("*"):
        if ".git" in f.parts or not f.is_file():
            continue
        rel = f.relative_to(root).as_posix()
        if rx.match(rel):
            out.append((_pattern_split(pat, rel)[1] or _base(f.name), rel))
    return out


def env_files(pid: str, rgid: str, env: str, include_hidden: bool = False,
              conv: dict | None = None) -> list[str]:
    """The values file names in ONE environment, read from its own binding.

    Two shapes, because repositories have two shapes: a folder of values files
    (the common case — fname is the basename, byte-for-byte what this returned
    before bindings existed), or files at pattern-shaped paths under the
    environment's directory (fname carries the relative path, encoded).
    """
    conv = conv or naming(pid)
    b = binding(pid, rgid, env)
    d = env_dir(pid, rgid, env)
    if not d.is_dir():
        return []
    if b["pattern"]:
        return sorted(_enc(rel) for svc, rel in _svc_entries(d, b["pattern"])
                      if include_hidden or not _hidden(svc, conv["hidden"]))
    globs = _service_globs(conv)
    names = {f.name for g in globs for f in d.glob(g)}
    return sorted(fn for fn in names
                  if include_hidden or is_service_file(fn, conv["hidden"]))


def list_envs(pid: str, rgid: str, include_hidden: bool = False) -> dict[str, list[str]]:
    """env -> [values file names] for this region — the DECLARED environments.

    Every page, query, mapping and MCP answer reads environments from here, so
    what is declared is what exists, everywhere, and correcting a declaration
    corrects the whole portal at once.

    By default this is the project's *focused* list: whatever `hidden_services`
    matches is left out, which is how a team keeps a listing about the services
    they work on. `include_hidden=True` returns every values file, for the pages
    whose job is to show the whole environment — nothing in the repository
    should be unreachable from the portal just because it is not the focus.
    """
    conv = naming(pid)
    _materialise(pid, rgid, conv)
    _absorb(pid, rgid)
    return {env: env_files(pid, rgid, env, include_hidden, conv)
            for env in sorted(store.env_sources(pid, rgid))}


def _materialise(pid: str, rgid: str, conv: dict) -> None:
    """Freeze what the old scan found into declarations — once, per region.

    Removing a guess must not remove anybody's data. The first time a region is
    asked for its environments after the upgrade, the scan runs one last time
    and its answer is written down as declarations; from then on the
    declarations are the truth and the scan is only ever a suggestion somebody
    asked for. Nothing disappears, and everything the scan produced is now
    editable — which it never was.
    """
    rg = store.get_region(pid, rgid) or {}
    if rg.get("envs") is not None:
        return
    extra, hidden = env_overrides(pid, rgid)
    vpath = ((rg.get("repo") or {}).get("values_path") or "").strip("/")
    # Don't freeze an empty list just because the checkout is not there yet: a
    # region whose clone is missing would lose every environment it has.
    if (rg.get("repo") or {}).get("url") and not extra \
            and not store.repo_dir(pid, rgid).is_dir():
        return
    found = _scan_envs(pid, rgid, conv, include_hidden=True)
    envs: dict = {}
    for env in sorted(set(found) | set(extra)):
        if env in hidden:
            continue
        if env in extra:
            rel = extra[env]
            path = "/".join(x for x in (vpath, rel) if x)
        elif conv["pattern"]:
            path = vpath          # the pattern walks from the values path
        else:
            path = "/".join(x for x in (vpath, env) if x)
        b = {"url": "", "branch": "", "path": path}
        if conv["pattern"]:
            # {env} is bound now, so the remaining pattern is per-environment
            b["pattern"] = conv["pattern"].replace("{env}", env)
            b["recurse"] = "1"
        envs[env] = b
    store.update_region(pid, rgid, envs=envs)


def candidates(pid: str, rgid: str) -> list[dict]:
    """What this region's checkouts LOOK like they hold, as declarations to
    accept.

    The scan, offered rather than applied. Somebody with an existing repository
    should not have to type six paths from memory, and a suggestion they accept
    is a different thing from a guess the portal acts on by itself: this returns
    candidates, and nothing changes until one is declared.

    One walk per DISTINCT (repository, branch) among the region's bindings —
    environments can live in different repositories now, so there is no single
    tree to scan. Each candidate carries the url and branch of the checkout it
    was found in, so accepting one declares a complete binding, never a name
    that means "whichever repo". Already-declared names are marked rather than
    dropped, because "the scan agrees with what I declared" is worth seeing.
    """
    conv = naming(pid)
    have = store.env_sources(pid, rgid)
    globs = _service_globs(conv)
    roots: list[tuple[Path, str, str]] = []
    seen: set = set()
    for env in have:
        b = binding(pid, rgid, env)
        root = checkout(pid, rgid, env)
        if str(root) not in seen and root.is_dir():
            seen.add(str(root))
            roots.append((root, b["url"], b["branch"]))
    legacy = store.repo_dir(pid, rgid)
    if str(legacy) not in seen and legacy.is_dir():
        roots.append((legacy, "", ""))    # demo/hand-planted files, no repo
    out = []
    for root, url, branch in roots:
        hits: dict[str, int] = {}
        for rel in _tree_rels(root):
            d, _, fn = rel.rpartition("/")
            if any(fnmatch(fn, g) for g in globs):
                hits[d] = hits.get(d, 0) + 1
        for d, n in hits.items():
            if not d:
                continue              # files at the very root name no environment
            out.append({"env": d.rsplit("/", 1)[-1], "path": d, "files": n,
                        "url": url, "branch": branch,
                        "declared": d.rsplit("/", 1)[-1] in have})
    return sorted(out, key=lambda c: (c["env"], c["path"]))


def _scan_envs(pid: str, rgid: str, conv: dict,
               include_hidden: bool = False) -> dict[str, list[str]]:
    """What the repository LOOKS like it holds — a suggestion, never the truth.

    This was `list_envs` until environments became declarations. It survives for
    two jobs: the one-time migration above, and the "find environments in this
    repository" button, which offers what it finds for somebody to accept.
    """
    root = env_root(pid, rgid)
    extra, drop = env_overrides(pid, rgid)
    if not root.is_dir():
        # a hand-added environment still exists even when the checkout does
        # not, so it can be mapped to a cluster before the repo is cloned
        return {e: [] for e in sorted(extra) if e not in drop}
    out: dict = {}
    if conv["pattern"]:
        # a custom layout: walk the whole tree, the pattern says which files are
        # services and what (env, svc) each is. fname carries the rel path (encoded).
        for env, svc, rel in _pattern_entries(root, conv["pattern"]):
            if include_hidden or not _hidden(svc, conv["hidden"]):
                out.setdefault(env, []).append(_enc(rel))
        out = _apply_overrides(pid, rgid, out, conv, include_hidden)
        return {e: sorted(fs) for e, fs in sorted(out.items())}
    # default: each folder under the path is an environment; fname = basename.
    # Byte-for-byte the old behaviour when globs is the default ("*-values*.yaml").
    globs = _service_globs(conv)
    keep = lambda fn: include_hidden or is_service_file(fn, conv["hidden"])
    for d in sorted(x for x in root.iterdir() if x.is_dir()):
        names = {f.name for g in globs for f in d.glob(g)}
        files = sorted(fn for fn in names if keep(fn))
        if files:
            out[d.name] = files
    out = _apply_overrides(pid, rgid, out, conv, include_hidden)
    return dict(sorted(out.items()))


def _apply_overrides(pid: str, rgid: str, found: dict, conv: dict,
                     include_hidden: bool) -> dict:
    """Drop what the region says is not an environment, add what it says is.

    An extra's files are read from ITS directory with the same globs, and its
    names are stored as encoded relative paths so `service_file` can resolve
    them whatever the project's layout is. An extra with no files yet is kept —
    an environment nobody has committed values for is still an environment
    somebody wants to point at a cluster.
    """
    extra, drop = env_overrides(pid, rgid)
    out = {e: fs for e, fs in found.items() if e not in drop}
    root = env_root(pid, rgid)
    globs = _service_globs(conv)
    keep = lambda fn: include_hidden or is_service_file(fn, conv["hidden"])
    for env, rel in extra.items():
        if env in drop:
            continue
        here = (root / rel).resolve() if rel else root
        # the same containment guard service_file uses: a path out of the
        # checkout is a path somebody should not be reading
        inside = str(here).startswith(str(store.repo_dir(pid, rgid).resolve()))
        files: list[str] = []
        if inside and here.is_dir():
            names = {f.name for g in globs for f in here.glob(g)}
            files = sorted(_enc(f"{rel}/{fn}" if rel else fn)
                           for fn in names if keep(fn))
        # a hand-added environment REPLACES what the scan found under that name,
        # because the person naming a path is the more specific answer
        out[env] = files
    return out


def _hidden(svc: str, hidden: tuple) -> bool:
    """Whether the SERVICE name matches a project hide pattern (used by the
    pattern layout, where the service is already extracted)."""
    return any(fnmatch(svc, str(p).strip()) for p in (hidden or ()) if str(p).strip())


def split_services(pid: str, rgid: str, env: str) -> dict:
    """Every values file in one environment, in two groups.

    `focus` is what this project's naming settings put front and centre;
    `other` is everything else — platform services, back-office, mocks. Both are
    editable; the split only decides what is shown first.
    """
    conv = naming(pid)
    def keep(fname):
        if conv["pattern"]:
            _, svc = _pattern_split(conv["pattern"], _dec(fname))
            return not _hidden(svc or _base(fname), conv["hidden"])
        return is_service_file(fname, conv["hidden"])
    focus, other = [], []
    for fname in all_files(pid, rgid, env):
        (focus if keep(fname) else other).append(fname)
    # two files can strip down to the same display name (bo-frontend-values.yaml
    # and bo-frontend-values02.yaml both read "bo-frontend"), which makes two
    # tiles look like a duplicate. Name them so the listing stays truthful.
    seen: dict = {}
    for fname in focus + other:
        name = display(pid, fname)
        seen[name] = seen.get(name, 0) + 1
    return {"focus": focus, "other": other, "all": focus + other,
            "ambiguous": {n for n, c in seen.items() if c > 1},
            "hidden_patterns": list(conv["hidden"])}


def all_files(pid: str, rgid: str, env: str) -> list[str]:
    """Every values file in one environment, hidden ones included.

    Delegates to `env_files`, which resolves through the environment's own
    binding. It used to build `env_root(pid, rgid) / env` itself — the old
    model's "region root plus the environment's name" — and once an
    environment could name its own repository, branch and path, that guess
    pointed at a directory which no longer existed. It returned [] rather than
    raising, so the service list, the diagram and the Argo namespace matcher
    all showed EMPTY on a correctly-configured environment.
    """
    return env_files(pid, rgid, env, include_hidden=True)


def service_file(pid: str, rgid: str, env: str, fname: str) -> Path:
    """Physical path of a service's values file, from the environment's binding.

    `fname` is a basename in the common case and an encoded relative path when
    the environment's files sit at pattern-shaped paths; both resolve under the
    environment's own directory, so an environment on another branch or in
    another repository reads and writes in the right checkout.

    The guard is against THAT environment's checkout, not the region's: sharing
    one working copy per (repository, branch) means the region's directory is
    the wrong fence for an environment that has its own.
    """
    b = binding(pid, rgid, env)
    root = checkout(pid, rgid, env)
    p = (env_dir(pid, rgid, env) / _dec(fname)).resolve()
    if not str(p).startswith(str(root.resolve())):
        raise ValueError("invalid path")
    return p


def values_path(pid: str, rgid: str, env: str, fname: str) -> Path:
    return service_file(pid, rgid, env, fname)


def rel_path(pid: str, rgid: str, env: str, fname: str) -> str:
    """The file's path inside its own checkout — which is what git speaks.

    Relative to the environment's checkout, not the region's: `git status` in a
    binding's working copy reports paths from that copy's root, and comparing
    them against region-relative paths is how "edited" markers and diffs go
    silently blank for an environment on its own branch.
    """
    return str(values_path(pid, rgid, env, fname)
               .relative_to(checkout(pid, rgid, env).resolve()))


# ── read ───────────────────────────────────────────────────────
def _names_under(node) -> list:
    """Resource names out of a chart value, whichever shape it took.

    Charts write a list of resources three ways — bare strings, `{name: x}`
    entries, and a single string — and which one appears is the chart author's
    taste. All three mean the same thing here.
    """
    out = []
    if isinstance(node, str) and node.strip():
        out.append(node.strip())
    elif isinstance(node, dict):
        for key in ("name", "secretName", "configMapName"):
            if isinstance(node.get(key), str) and node[key].strip():
                out.append(node[key].strip())
    elif isinstance(node, list):
        for item in node:
            out += _names_under(item)
    return out


# What a values file says its service is made of, by the key that says it.
#
# WHY THIS BEATS GUESSING FROM THE CLUSTER
#     Ownership was inferred from the SERVICE name, and the service name came
#     from the filename. `pay-za-worker-values.yaml` therefore looked for
#     `pay-za-worker*` while the chart declares `fullnameOverride:
#     payza-worker` and `configMap.name: payza-worker-config` — so the
#     ConfigMap this service reads its whole configuration from was filed under
#     "also in this namespace, nothing links these". The file knew all along.
#
#     Paths, not a scan of every `name:` in the document: `image.repository` and
#     `imagePullSecrets[].name` are not this service's ConfigMap, and a walker
#     that collected every name-shaped string would claim half the namespace.
_DECLARES = {
    "base": (("fullnameOverride",), ("name",), ("nameOverride",)),
    "service": (("serviceName",), ("service", "name")),
    "configmap": (("configMap", "name"), ("configmap", "name"),
                  ("configMaps",), ("envFrom", "configMaps"),
                  ("envFrom", "configMapRef")),
    "secret": (("secret", "secretName"), ("secretName",), ("secret", "name"),
               ("secrets",), ("envFrom", "secrets"), ("envFrom", "secretRef"),
               ("imagePullSecrets",)),
}


def _dig(data, path: tuple):
    node = data
    for step in path:
        if not isinstance(node, dict):
            return None
        node = node.get(step)
    return node


def declares(data) -> dict:
    """{"base": str, "service": [...], "configmap": [...], "secret": [...]}"""
    out = {"base": ""}
    for kind, paths in _DECLARES.items():
        found = []
        for path in paths:
            found += _names_under(_dig(data, path))
        if kind == "base":
            out["base"] = found[0] if found else ""
        else:
            # order kept, duplicates dropped: a name in both `configMap.name` and
            # `envFrom.configMaps` is one resource mentioned twice
            out[kind] = list(dict.fromkeys(found))
    return out


def load_service(pid: str, rgid: str, env: str, fname: str) -> dict:
    text = values_path(pid, rgid, env, fname).read_text()
    data = yaml.load(text)
    service_cfg, platform_cfg = {}, {}
    cfg = _config_section(data)
    if cfg:
        prefixes = naming(pid)["prefixes"]      # read once, not per key
        for k, v in cfg.items():
            (platform_cfg if is_platform_key(str(k), prefixes) else service_cfg)[k] = v
    sealed = _sealed_section(data)
    return {
        "meta": {
            "image_repo": (data.get("image") or {}).get("repository"),
            "image_tag": (data.get("image") or {}).get("tag"),
            "replicaCount": data.get("replicaCount"),
            "namespace": data.get("namespace"),
            "name": data.get("name") or data.get("fullnameOverride"),
            "secret_name": _secret_name(data),
            # Everything the file says this service consists of, so the live
            # side can match on declarations instead of guessing from names.
            "declares": declares(data),
        },
        "service_config": service_cfg,
        "platform_config": platform_cfg,
        "secret_keys": list(sealed.keys()) if sealed else [],
        "warnings": lint(text),
    }


def service_summary(pid: str, rgid: str, env: str, fname: str) -> dict:
    """Counts for a service card.

    A file that could not be read reports `error`, never a count of zero — the
    two look identical on screen but mean opposite things, and the silent zero
    hid unreadable files instead of flagging them.
    """
    try:
        d = load_service(pid, rgid, env, fname)
        # Every editable value, not only the config block: a file with no config
        # section still has an image tag, replicas, resources and ingress hosts
        # to manage, and "0 config keys" made those files look empty.
        try:
            editable = sum(1 for r in load_values(pid, rgid, env, fname)["rows"]
                           if r["editable"])
        except Exception:                                     # noqa: BLE001
            editable = 0
        return {"cfg_count": len(d["service_config"]),
                "val_count": editable,
                "secret_count": len(d["secret_keys"]),
                "warnings": d["warnings"], "error": ""}
    except Exception as e:                                    # noqa: BLE001
        return {"cfg_count": 0, "val_count": 0, "secret_count": 0, "warnings": [],
                "error": f"{type(e).__name__}: {str(e).splitlines()[0][:120]}"}


def namespaces(pid: str, rgid: str, env: str) -> list[str]:
    """Which namespaces this environment deploys into.

    Two places, because repositories put it in two places and only one of them
    was being read.

    A values file may carry a top-level `namespace:`. Plenty do. But in a repo
    where the chart is shared and the environments are separated by Argo CD
    Applications, the values file says nothing about where it lands — the
    Application does, in spec.destination.namespace. That was this estate's
    layout, so every values file parsed fine, produced no namespace, and the
    topology drawing reported "no namespaces found" for an environment with
    seven services in it.

    Reading both means the answer comes from wherever the repository actually
    states it, rather than from the one shape this function happened to know.
    """
    out = set()
    for f in all_files(pid, rgid, env):
        try:
            ns = load_service(pid, rgid, env, f)["meta"]["namespace"]
        except Exception:                                      # noqa: BLE001
            ns = None
        if ns:
            out.add(str(ns))
    out.update(_argocd_namespaces(pid, rgid, env))
    return sorted(out)


def _argocd_namespaces(pid: str, rgid: str, env: str) -> set[str]:
    """Namespaces named by Argo CD Applications that point at this environment.

    An Application is matched to an environment by the values files it names,
    so a repository holding dev, uat and prod side by side does not report all
    three for each. Applications live anywhere in the tree, so the whole
    checkout is scanned — bounded, and skipping .git and the environment
    folders themselves.
    """
    root = store.repo_dir(pid, rgid)
    if not root.is_dir():
        return set()
    # Where this environment's values files actually live, relative to the
    # checkout. An Application names its values files relative to its own
    # source path, so the two resolve against each other exactly — matching on
    # the file's bare name instead reported every environment for every one of
    # them, because the same service is called the same thing in dev and uat.
    try:
        env_dir_path = env_dir(pid, rgid, env).resolve()
    except Exception:                                          # noqa: BLE001
        return set()
    try:
        env_files = {f.lower() for f in all_files(pid, rgid, env)}
    except Exception:                                          # noqa: BLE001
        env_files = set()
    found: set[str] = set()
    for path in list(root.rglob("*.yaml"))[:4000] + list(root.rglob("*.yml"))[:1000]:
        if ".git" in path.parts:
            continue
        try:
            if path.stat().st_size > 512_000:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if "argoproj.io" not in text or "kind: Application" not in text:
            continue
        try:
            docs = list(yaml.load_all(text))
        except Exception:                                      # noqa: BLE001
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "Application":
                continue
            spec = doc.get("spec") or {}
            ns = ((spec.get("destination") or {}).get("namespace") or "").strip()
            if not ns:
                continue
            sources = spec.get("sources") or [spec.get("source") or {}]
            for src in sources:
                if not isinstance(src, dict):
                    continue
                base = str(src.get("path") or "").strip("/")
                files = [str(f) for f in
                         ((src.get("helm") or {}).get("valueFiles") or [])]
                if _points_at(root, base, files, env_dir_path, env_files):
                    found.add(ns)
                    break
    return found


def _points_at(root: Path, base: str, files: list[str], env_dir: Path,
               env_files: set[str]) -> bool:
    """Whether an Application's values files belong to this environment."""
    placed = False
    for f in files:
        try:
            whole = (root / base / f).resolve()
        except Exception:                                      # noqa: BLE001
            continue
        if whole.parent == env_dir:
            return True
        # This path says where it lives. Whether or not that directory exists
        # in the checkout, it is not this environment's — matching on the file
        # name after that let a prod Application be claimed by dev, because
        # both call the service the same thing.
        if "/" in f.replace("\\", "/") or base:
            placed = True
    if placed:
        return False
    # Bare file names, no directories anywhere: the repository does not
    # separate environments by path, so the name is all there is to go on.
    names = {f.rsplit("/", 1)[-1].lower() for f in files}
    return bool(names & env_files)


# ── write ──────────────────────────────────────────────────────
def _write(path: Path, data) -> None:
    buf = io.StringIO()
    yaml.dump(data, buf)
    path.write_text(buf.getvalue())


def save_config_changes(pid, rgid, env, fname, new_config: dict) -> list[str]:
    """Update existing config values with a minimal, line-level diff."""
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    data = yamledit.parse(text)
    cfg = _config_section(data)
    if cfg is None:
        raise ValueError("file has no config section")
    changed = []
    for k, v in new_config.items():
        if k in cfg and str(cfg[k]) != v:
            text = yamledit.set_value(text, cfg, k, v)
            changed.append(k)
    if changed:
        path.write_text(text)
    return changed


def read_raw(pid, rgid, env, fname) -> str:
    """The values file exactly as it sits on disk — comments, order, blank lines.

    The structured readers (`load_service`, `load_values`) answer "what does
    this file MEAN"; this one answers "what does it SAY", which is the question
    somebody editing it is asking.
    """
    return values_path(pid, rgid, env, fname).read_text()


def save_raw(pid, rgid, env, fname, text: str) -> list[str]:
    """Write the file back verbatim. Returns lint warnings, refuses broken YAML.

    Two decisions here, both about which loader gets a veto:

    It must PARSE, or it is not saved. A values file that Helm cannot read is
    not an edit, it is an outage waiting for the next sync, and the whole point
    of holding it in a working copy is that the mistake stops here rather than
    at the cluster. The tolerant loader is the judge, because it is the one
    whose answer matches Helm's.

    A DUPLICATE KEY is reported, not refused. `yamledit.parse` rejects them
    because the line-accurate editor cannot model a document with two of the
    same key — but plenty of real files already have one, and refusing to save
    those would make this editor unable to fix the very thing it is warning
    about. So `lint` says so and the writing continues; that is the same split
    `config_read` makes for the MCP surface.

    Nothing is normalised or re-emitted: the text goes down as typed, so a
    comment, a deliberate blank line and a hand-aligned block all survive. The
    structural writer (`_write`) is for the key-level editors, and running it
    here would rewrite the whole document on every save.
    """
    body = text if text.endswith("\n") else text + "\n"
    try:
        yaml.load(body)
    except Exception as e:                                    # noqa: BLE001
        first = str(e).strip().splitlines()
        raise ValueError("that is not valid YAML, so it was not saved — "
                         + " ".join(first[:3])[:300]) from e
    values_path(pid, rgid, env, fname).write_text(body)
    return lint(body)


def load_values(pid, rgid, env, fname) -> dict:
    """Every value in the file, flattened for display.

    Separate from load_service on purpose: that one answers "what is this
    service", with the config block split from the platform keys. This one
    answers "what is in this file", and makes no judgement about which parts
    matter.
    """
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    data = yamledit.parse(text)
    return {"rows": values.rows(data), "sections": values.sections(data),
            "lines": len(text.split("\n"))}


def save_value_changes(pid, rgid, env, fname, changes: dict) -> list[str]:
    """Apply {json path: new text} to the file, one line each.

    The document is re-parsed between edits because every edit shifts the line
    numbers recorded for everything below it — batching them against one parse
    wrote later changes to the wrong lines.
    """
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    changed = []
    for raw, new in changes.items():
        want = values.decode(raw)
        data = yamledit.parse(text)
        before = values.current(data, want)
        if values.display(before) == new:
            continue
        text = values.set_at(text, data, want, new)
        changed.append(" → ".join(str(s) for s in want))
    if changed:
        path.write_text(text)
    return changed


def add_value(pid, rgid, env, fname, parent_raw: str, key: str,
              value: str) -> str:
    """Add one value. Returns what it did.

    `key` may be a dotted path — `resources.limits.cpu` — and any level of it
    that the file does not have yet is created. That replaced a "where"
    dropdown listing every mapping in the file: accurate, and unusable, because
    it turned adding a CPU limit into a question about the shape of a Helm chart.

    `parent_raw` is still honoured for the one case a path cannot express:
    appending to a LIST, where there is no key to name. The rows offering that
    pass the encoded path of the list itself.
    """
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    if parent_raw.strip():
        parent = values.decode(parent_raw)
        text = values.add_at(text, yamledit.parse(text), parent, key, value)
        did = f"{key or 'item'} added to " + " → ".join(str(s) for s in parent)
    else:
        text = values.add_dotted(text, yamledit.parse(text), key, value)
        did = f"{key} added"
    yamledit.parse(text)          # refuse to write a file that no longer parses
    path.write_text(text)
    return did


def delete_value(pid, rgid, env, fname, raw: str) -> str:
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    want = values.decode(raw)
    text = values.delete_at(text, yamledit.parse(text), want)
    yamledit.parse(text)
    path.write_text(text)
    return " → ".join(str(s) for s in want)


def add_config_keys(pid, rgid, env, fname, config: dict) -> list[str]:
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    data = yamledit.parse(text)
    cfg = _config_section(data)
    if cfg is None:
        raise ValueError("file has no config section")
    clash = [k for k in config if k in cfg]
    if clash:
        raise ValueError(f"keys already exist: {', '.join(clash)}")
    path.write_text(yamledit.add_keys(text, cfg, config))
    return list(config)


def delete_config_key(pid, rgid, env, fname, key: str) -> None:
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    cfg = _config_section(yamledit.parse(text))
    if cfg is None or key not in cfg:
        raise ValueError(f"'{key}' is not in this file's config")
    path.write_text(yamledit.remove_key(text, cfg, key))


def delete_secret_key(pid, rgid, env, fname, key: str) -> None:
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    sealed = _sealed_section(yamledit.parse(text))
    if sealed is None or key not in sealed:
        raise ValueError(f"'{key}' is not in this file's secrets")
    path.write_text(yamledit.remove_key(text, sealed, key))


def save_sealed_secrets(pid, rgid, env, fname, sealed: dict) -> list[str]:
    path = values_path(pid, rgid, env, fname)
    text = path.read_text()
    existing = _sealed_section(yamledit.parse(text))
    if existing is not None:
        updates = {k: v for k, v in sealed.items() if k in existing}
        adds = {k: v for k, v in sealed.items() if k not in existing}
        for k, v in updates.items():
            text = yamledit.set_value(text, existing, k, v)
        if adds:
            text = yamledit.add_keys(text, existing, adds)
        path.write_text(text)
        return list(sealed)

    # no SealedSecret block yet — fall back to structural insert
    data = yaml.load(text)
    target = _sealed_section(data)
    if target is None:
        if data.get("secretName"):
            data["SealedSecret"] = target = CommentedMap()
        else:
            name = data.get("fullnameOverride") or data.get("name") or "app"
            data["secret"] = sec = CommentedMap()
            sec["enabled"] = True
            sec["secretName"] = f"{name}-secret"
            sec["SealedSecret"] = target = CommentedMap()
            ef = data.setdefault("envFrom", CommentedMap())
            lst = ef.setdefault("secrets", [])
            if sec["secretName"] not in lst:
                lst.append(sec["secretName"])
    for k, v in sealed.items():
        target[k] = v
    _write(path, data)
    return list(sealed)


def create_service(pid, rgid, env, name, image_repo, image_tag, port,
                   namespace, config: dict) -> str:
    name = re.sub(r"[^a-z0-9-]", "", name.lower())
    if not name:
        raise ValueError("invalid service name")
    conv = naming(pid)
    if conv["pattern"]:                         # place the new file per the layout
        rel = _pattern_build(conv["pattern"], env, name)
        if not rel:
            raise ValueError("this project's layout pattern uses a wildcard, so a new "
                             "service can't be placed automatically — add its file to the repo by hand")
        fname = _enc(rel)
    else:
        fname = f"{name}-values.yaml"
    path = values_path(pid, rgid, env, fname)
    if path.exists():
        raise ValueError(f"{fname} already exists in {env}")
    data = CommentedMap()
    data["fullnameOverride"] = name
    data["name"] = name
    data["replicaCount"] = 1
    data["serviceName"] = f"{name}-service"
    data["namespace"] = namespace
    data["image"] = {"repository": image_repo, "tag": image_tag,
                     "pullPolicy": "IfNotPresent"}
    data["service"] = {"enabled": True, "type": "ClusterIP",
                       "port": 80, "targetPort": port}
    data["configMap"] = {"enabled": True, "name": f"{name}-config",
                         "data": dict(config)}
    data["envFrom"] = {"configMaps": [f"{name}-config"]}
    path.parent.mkdir(parents=True, exist_ok=True)
    _write(path, data)
    return fname
