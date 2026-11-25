"""Terraform: declarative infrastructure runs from the portal.

WHAT THIS IS, AND HOW IT RELATES TO ANSIBLE
    The Ansible page runs a playbook against a group of hosts and keeps the
    output. This is the same shape for Terraform: a **stack** holds the `.tf`
    code, its variables and the provider's brokered credential; a **run** is one
    `terraform init | plan | apply | destroy`, executed on a background thread,
    its output captured and polled by the page. A stack is to Terraform what a
    playbook+group is to Ansible.

WHY A STACK HAS A PERSISTENT WORKING DIRECTORY (the one real difference)
    An Ansible run is stateless — a fresh temp dir per run, deleted after. A
    Terraform stack is NOT: `terraform init` downloads the providers into
    `.terraform/`, and every run reads and writes `terraform.tfstate` — the
    record of what actually exists. Lose that between runs and Terraform forgets
    what it built. So each stack keeps a persistent directory under
    `DATA/tf-stacks/<id>/`; the `.tf` files are rewritten there from the database
    (the source of truth) on every run, and the state and provider cache live
    beside them.

WHERE THE CREDENTIAL GOES
    The provider secret (a Proxmox API token, vSphere password, …) is sealed with
    secretbox exactly like an Ansible group key, and — unlike the key, which
    needs a file — it is injected into the run as ENVIRONMENT VARIABLES and never
    written to disk. `PROXMOX_VE_API_TOKEN=…` reaches the provider and nothing
    else; the process dies and it is gone.

THE SAFETY POSTURE, SAME AS ANSIBLE
    `init` and `plan` read and refresh but change nothing — they are the `--check`
    of Terraform. `apply` and `destroy` change real infrastructure: they are
    gated by the installation's `allow_apply` switch (off by default) AND, for a
    stack marked production, by typing the stack's name. Running anything at all
    needs the escalating `Terraform: apply` area — a `.tf` body is arbitrary code
    to a provider, the same trust an Ansible playbook carries.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid

from . import db, env, secretbox, store
from .ansible import Refused, _placed, place_of      # reuse the placement machinery
from .paths import DATA

# Caps, mirrored from ansible.py so the two pages behave the same.
BODY_MAX = 512_000              # one stack's .tf text
VARS_MAX = 128_000             # its variables
OUTPUT_MAX = 4_000_000         # kept run output, tail preserved past this
RUNS_KEEP = 500               # newest runs kept per stack
RUN_TIMEOUT = 3600.0          # a single run's hard ceiling
IDLE_TIMEOUT = 900.0          # no output for this long → killed
MAX_CONCURRENT = 4

STATUS_RUNNING = "running"
ACTIONS = ("init", "plan", "apply", "destroy")
CHANGING = ("apply", "destroy")     # these touch real infrastructure

# A name is shown and used to build a directory path, so it is checked, not
# trusted — letters, digits, space, dot, dash, underscore, starting alnum.
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
# One credential line: KEY=value. The KEY becomes an environment variable name.
CRED_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# The stacks' persistent working directories live here.
STACKS = DATA / "tf-stacks"

# Where a run parses its own summary from Terraform's output.
_PLAN = re.compile(r"Plan:\s*(\d+)\s+to add,\s*(\d+)\s+to change,\s*(\d+)\s+to destroy")
_APPLY = re.compile(r"Resources:\s*(\d+)\s+added,\s*(\d+)\s+changed,\s*(\d+)\s+destroyed")

_live: dict = {}                # run_id -> Popen, for cancel/kill
_lock = threading.Lock()


# ── schema ─────────────────────────────────────────────────────
def _migrate(c) -> None:
    # A stack: the code, its variables, where it belongs, and the sealed
    # provider credential. `provider` is a label (proxmox/vsphere/…) for display
    # and for knowing which env-var names the credential fills.
    c.execute("""CREATE TABLE IF NOT EXISTS tf_stacks (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT DEFAULT '',
        body TEXT DEFAULT '',                -- the .tf (HCL) text
        tfvars TEXT DEFAULT '',              -- terraform.tfvars text
        provider TEXT DEFAULT 'proxmox',
        creds_sealed TEXT DEFAULT '',        -- KEY=value env lines, via secretbox
        proj_id TEXT DEFAULT '', rgn_id TEXT DEFAULT '',
        env TEXT DEFAULT '', is_prod INTEGER DEFAULT 0,
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    # History of the .tf body, kept apart from the current text so the common
    # read does not carry every past version (same as ansible_revs).
    c.execute("""CREATE TABLE IF NOT EXISTS tf_revs (
        id TEXT PRIMARY KEY, stack_id TEXT NOT NULL, body TEXT,
        at TEXT, by TEXT, note TEXT)""")
    # A run: the row exists before the process. `pid` is the OS process id;
    # `resources` is the parsed add/change/destroy summary.
    c.execute("""CREATE TABLE IF NOT EXISTS tf_runs (
        id TEXT PRIMARY KEY, stack_id TEXT, stack_name TEXT,
        action TEXT, proj_id TEXT DEFAULT '', rgn_id TEXT DEFAULT '',
        cmd TEXT, status TEXT, rc INTEGER, resources TEXT DEFAULT '',
        output TEXT DEFAULT '', why TEXT DEFAULT '',
        started TEXT, finished TEXT, by TEXT, pid INTEGER)""")
    for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_tf_runs_stack ON tf_runs(stack_id)",
            "CREATE INDEX IF NOT EXISTS idx_tf_runs_at ON tf_runs(started)",
            "CREATE INDEX IF NOT EXISTS idx_tf_stacks_place "
            "ON tf_stacks(proj_id, rgn_id)"):
        c.execute(stmt)
    # spec_json (additive): the Provision wizard's answers, so a generated stack
    # can be re-opened and edited in the wizard instead of by hand-editing HCL.
    # Secrets (the OS password) are stripped before it is stored — see provision.
    have = {r["name"] for r in c.execute("PRAGMA table_info(tf_stacks)")}
    if "spec_json" not in have:
        c.execute("ALTER TABLE tf_stacks ADD COLUMN spec_json TEXT DEFAULT ''")


db.register(_migrate)


def _conn():
    return db.connect()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ── the installation's settings ────────────────────────────────
# allow_apply is off until switched on — the same posture as Ansible's allow_real
# and a cluster's "allow management". A stack can be written and PLANNED (which
# changes nothing) with it off; apply/destroy need it on.
DEFAULTS = {"allow_apply": False, "parallelism": 10}


def config() -> dict:
    got = {**DEFAULTS, **(store._setting("terraform") or {})}
    got["allow_apply"] = bool(got.get("allow_apply"))
    try:
        got["parallelism"] = max(1, min(100, int(got.get("parallelism") or 10)))
    except (TypeError, ValueError):
        got["parallelism"] = 10
    return got


def save_config(**fields) -> None:
    store._set_setting("terraform", {k: fields.get(k, DEFAULTS[k]) for k in DEFAULTS})


# ── the binary ─────────────────────────────────────────────────
_probe: dict | None = None


def tool(refresh: bool = False) -> dict:
    """Whether terraform (or an OpenTofu binary in its place) is on PATH, and its
    version — cached, so the page can show it without a subprocess each load."""
    global _probe
    if _probe is not None and not refresh:
        return _probe
    row = {"found": False, "version": "", "path": "", "error": "", "flavour": ""}
    candidates = [env.TERRAFORM] if env.TERRAFORM != "terraform" else ["terraform", "tofu"]
    for cand in candidates:
        path = shutil.which(cand, path=env.TOOL_PATH) or (
            cand if os.path.isabs(cand) and os.path.exists(cand) else "")
        if not path:
            continue
        try:
            out = subprocess.run([path, "version"], capture_output=True, text=True,
                                 timeout=8, env={"PATH": env.TOOL_PATH}).stdout
            first = (out.splitlines() or [""])[0].strip()
            row.update(found=True, path=path, version=first,
                       flavour="opentofu" if "opentofu" in first.lower() else "terraform")
            break
        except (OSError, subprocess.SubprocessError) as e:
            row["error"] = f"{type(e).__name__}: {e}"
    if not row["found"] and not row["error"]:
        row["error"] = (f"no terraform (or tofu) binary on PATH — set "
                        f"PORTAL_TERRAFORM, or PORTAL_TOOL_PATH to where it lives")
    _probe = row
    return row


# ── stacks ─────────────────────────────────────────────────────
def _stack_view(rows: list) -> list:
    out = []
    for r in rows:
        r = dict(r)
        r.pop("creds_sealed", None)         # the secret never rides into a page
        r["pid"], r["rgid"] = r.get("proj_id", ""), r.get("rgn_id", "")
        r["has_creds"] = bool(r.get("_has_creds"))
        r.pop("_has_creds", None)
        # "Edit in wizard" is offered only for stacks the wizard generated
        # (single query gives spec_json itself; the list gives the _has_spec flag)
        r["has_spec"] = bool(r.get("_has_spec") or r.get("spec_json"))
        r.pop("_has_spec", None)
        # a Talos cluster stack yields a kubeconfig/talosconfig output — offer the
        # downloads (the list query flags it; the single query carries the body)
        r["has_kube"] = bool(r.get("_has_kube") or
                             ("talos_cluster_kubeconfig" in (r.get("body") or "")))
        r.pop("_has_kube", None)
        from . import pam
        r["env_label"] = pam.env_label(r.get("env", ""))
        r["env_tone"] = pam.env_tone(r.get("env", ""))
        out.append(r)
    return _placed(out)


def stacks(pid: str = "", rgid: str = "") -> list:
    clauses, args = [], []
    if pid:
        clauses.append("proj_id = ?"); args.append(pid)
    if rgid:
        clauses.append("rgn_id = ?"); args.append(rgid)
    sql = ("SELECT id, name, notes, provider, proj_id, rgn_id, env, is_prod, "
           "updated, (creds_sealed <> '') AS _has_creds, "
           "(spec_json <> '') AS _has_spec, "
           "(body LIKE '%talos_cluster_kubeconfig%') AS _has_kube, "
           "LENGTH(body) AS body_len FROM tf_stacks")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY name COLLATE NOCASE"
    rows = _stack_view(_conn().execute(sql, tuple(args)).fetchall())
    for r in rows:
        r["last"] = _last_run(r["id"])
    return rows


def stack(sid: str) -> dict | None:
    r = _conn().execute("SELECT *, (creds_sealed <> '') AS _has_creds "
                        "FROM tf_stacks WHERE id = ?", (sid,)).fetchone()
    return _stack_view([r])[0] if r else None


def _stack_raw(sid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM tf_stacks WHERE id = ?", (sid,)).fetchone()
    return dict(r) if r else None


def _clean_creds(text: str) -> str:
    """Validate the credential block: KEY=value lines, KEY an env-var name. A bad
    line is refused rather than silently dropped — a token that does not reach the
    provider is a run that fails for a reason nothing explains."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise Refused(f"credential line {line!r} is not KEY=value")
        k, v = line.split("=", 1)
        if not CRED_KEY.match(k.strip()):
            raise Refused(f"{k.strip()!r} is not a usable environment variable name")
        out.append(f"{k.strip()}={v.strip()}")
    return "\n".join(out)


def save_stack(sid: str, fields: dict, who: str) -> str:
    name = (fields.get("name") or "").strip()
    if not NAME_OK.match(name):
        raise Refused("a stack needs a name — letters, digits, space, dot, dash, "
                      "underscore, starting with a letter or digit")
    body = fields.get("body") or ""
    if len(body) > BODY_MAX:
        raise Refused(f"the .tf is capped at {BODY_MAX // 1000}kB")
    tfvars = fields.get("tfvars") or ""
    if len(tfvars) > VARS_MAX:
        raise Refused(f"the variables are capped at {VARS_MAX // 1000}kB")
    provider = (fields.get("provider") or "proxmox").strip().lower()[:40]
    pid, rgid = place_of(fields)
    env_norm = (fields.get("env") or "").strip().lower()[:40]
    existing = _stack_raw(sid) if sid else None

    # A blank credentials field on an edit KEEPS the stored one (the form cannot
    # show it back), exactly like the Ansible group key. A sentinel clears it.
    creds_field = fields.get("creds")
    if fields.get("drop_creds"):
        sealed = ""
    elif (creds_field or "").strip():
        sealed = secretbox.seal(_clean_creds(creds_field))
    else:
        sealed = (existing or {}).get("creds_sealed", "")

    # spec_json is preserved on an edit that does not carry one — a hand-edit
    # through the raw stack form leaves the wizard spec intact rather than wiping
    # it (which would strip the stack's "Edit in wizard" ability).
    spec_json = fields.get("spec_json")
    if spec_json is None:
        spec_json = (existing or {}).get("spec_json", "")

    row = dict(name=name, notes=(fields.get("notes") or "").strip(), body=body,
               tfvars=tfvars, provider=provider, creds_sealed=sealed,
               proj_id=pid, rgn_id=rgid, env=env_norm,
               spec_json=spec_json,
               is_prod=1 if (fields.get("is_prod")
                             or env_norm in ("prod", "production")) else 0)
    now = _now()
    with db.tx() as c:
        if existing:
            if (existing.get("body") or "") != body:      # keep the old text
                c.execute("INSERT INTO tf_revs (id, stack_id, body, at, by, note) "
                          "VALUES (?,?,?,?,?,?)",
                          (uuid.uuid4().hex, sid, existing.get("body") or "",
                           now, who, "replaced"))
            row.update(updated=now, updated_by=who)
            sets = ", ".join(f"{k} = ?" for k in row)
            c.execute(f"UPDATE tf_stacks SET {sets} WHERE id = ?",
                      (*row.values(), sid))
        else:
            sid = "ts-" + uuid.uuid4().hex[:10]
            row.update(id=sid, created=now, updated=now, created_by=who,
                       updated_by=who)
            cols = ", ".join(row)
            c.execute(f"INSERT INTO tf_stacks ({cols}) "
                      f"VALUES ({','.join('?' * len(row))})", tuple(row.values()))
    return sid


def delete_stack(sid: str) -> bool:
    with db.tx() as c:
        gone = c.execute("DELETE FROM tf_stacks WHERE id = ?", (sid,)).rowcount
    if gone:
        shutil.rmtree(_workdir(sid), ignore_errors=True)   # its state + provider cache
    return bool(gone)


def revisions(sid: str) -> list:
    return [dict(r) for r in _conn().execute(
        "SELECT id, at, by, note FROM tf_revs WHERE stack_id = ? "
        "ORDER BY at DESC", (sid,)).fetchall()]


def revision_body(rev_id: str) -> str | None:
    r = _conn().execute("SELECT body FROM tf_revs WHERE id = ?", (rev_id,)).fetchone()
    return r["body"] if r else None


# ── the persistent working directory ───────────────────────────
def _workdir(sid: str) -> str:
    """A stack's own directory, where its .tf, its state and the downloaded
    providers live. Under DATA and named by the stack id, so a name can never
    steer the path outside the data volume."""
    return os.path.join(str(STACKS), sid)


def read_outputs(sid: str) -> dict:
    """A stack's terraform outputs, read from its workdir state — no init, no
    refresh, no credential (`terraform output` just reads the state file). Used to
    hand back a Talos cluster's kubeconfig / talosconfig after apply. Empty if
    nothing has been applied yet or the binary is missing."""
    wd = _workdir(sid)
    if not os.path.exists(os.path.join(wd, "terraform.tfstate")):
        return {}
    t = tool()
    if not t.get("found"):
        return {}
    try:
        r = subprocess.run([t["path"], f"-chdir={wd}", "output", "-json"],
                           capture_output=True, text=True, timeout=30,
                           env={"PATH": env.TOOL_PATH})
    except (OSError, subprocess.SubprocessError):
        return {}
    if r.returncode != 0:
        return {}
    try:
        data = json.loads(r.stdout or "{}")
    except (ValueError, TypeError):
        return {}
    return {k: v.get("value") for k, v in data.items() if isinstance(v, dict)}


def _write_files(sid: str) -> str:
    """(Re)write the stack's .tf and .tfvars into its working directory from the
    database — the DB is the source of truth; the directory is a cache. Returns
    the directory."""
    st = _stack_raw(sid)
    if not st:
        raise Refused("that stack no longer exists")
    wd = _workdir(sid)
    os.makedirs(wd, exist_ok=True)
    os.chmod(wd, 0o700)
    with open(os.path.join(wd, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(st.get("body") or "")
    tfvars = st.get("tfvars") or ""
    tfv = os.path.join(wd, "terraform.tfvars")
    if tfvars.strip():
        with open(tfv, "w", encoding="utf-8") as fh:
            fh.write(tfvars)
    elif os.path.exists(tfv):
        os.remove(tfv)
    return wd


def _run_env(sid: str, wd: str) -> dict:
    """The environment for the run: a clean PATH/HOME/TMPDIR plus the stack's
    unsealed credential lines as variables. Terraform reads no colour so the
    page's parsing is stable."""
    st = _stack_raw(sid) or {}
    e = {"PATH": env.TOOL_PATH, "HOME": wd, "TMPDIR": wd,
         "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1",
         "TF_CLI_ARGS": "-no-color"}
    creds = secretbox.unseal(st.get("creds_sealed") or "")
    for line in (creds or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            e[k.strip()] = v
    return e


def argv_for(action: str, wd: str) -> list:
    """The command as a list, never a string — a test reads it, and nothing typed
    reaches a shell."""
    tf = tool()["path"] or env.TERRAFORM
    par = str(config()["parallelism"])
    base = [tf, f"-chdir={wd}"]
    if action == "init":
        return base + ["init", "-input=false", "-no-color"]
    if action == "plan":
        return base + ["plan", "-input=false", "-no-color", f"-parallelism={par}"]
    if action == "apply":
        return base + ["apply", "-input=false", "-no-color", "-auto-approve",
                       f"-parallelism={par}"]
    if action == "destroy":
        return base + ["destroy", "-input=false", "-no-color", "-auto-approve",
                       f"-parallelism={par}"]
    raise Refused(f"{action!r} is not a Terraform action")


# ── running ────────────────────────────────────────────────────
def start(sid: str, action: str, who: str, *, allow_apply: bool = False,
          confirm: str = "") -> str:
    """Validate everything, write the run row, spawn the worker thread, return the
    id. Every refusal happens before any write — the same order as ansible.start.
    `init`/`plan` change nothing; `apply`/`destroy` need allow_apply on and, for a
    production stack, its name typed."""
    if action not in ACTIONS:
        raise Refused(f"{action!r} is not a Terraform action")
    st = _stack_raw(sid)
    if not st:
        raise Refused("that stack is gone")
    if not (st.get("body") or "").strip():
        raise Refused("this stack has no .tf to run")
    # "Allowed to run" before "able to run": a stack whose apply is switched off,
    # or a production stack without its name typed, is refused whether or not a
    # terraform binary is even installed.
    if action in CHANGING:
        if not allow_apply:
            raise Refused("apply/destroy are switched off for this installation "
                          "— Settings → Terraform. A plan still works.")
        if st["is_prod"] and confirm.strip() != st["name"]:
            raise Refused(f"{st['name']} is marked production: type its name to "
                          f"confirm a real {action}")
    if not tool()["found"]:
        raise Refused(tool()["error"] or "terraform is not available")
    with _lock:
        n = _conn().execute("SELECT COUNT(*) AS n FROM tf_runs WHERE status = ?",
                            (STATUS_RUNNING,)).fetchone()["n"]
        if n >= MAX_CONCURRENT:
            raise Refused(f"{MAX_CONCURRENT} runs are already going — let one finish")
        if _conn().execute("SELECT 1 FROM tf_runs WHERE stack_id = ? AND status = ?",
                           (sid, STATUS_RUNNING)).fetchone():
            raise Refused("this stack already has a run going")
        run_id = "tr-" + uuid.uuid4().hex[:12]
        with db.tx() as c:
            c.execute("""INSERT INTO tf_runs (id, stack_id, stack_name, action,
                         proj_id, rgn_id, status, output, started, by)
                         VALUES (?,?,?,?,?,?,?,?,?,?)""",
                      (run_id, sid, st["name"], action, st.get("proj_id", ""),
                       st.get("rgn_id", ""), STATUS_RUNNING, "", _now(), who))
    threading.Thread(target=_execute, name=f"tf-{run_id}",
                     args=(run_id, sid, action), daemon=True).start()
    return run_id


def _execute(run_id: str, sid: str, action: str) -> None:
    proc = None
    try:
        wd = _write_files(sid)
        argv = argv_for(action, wd)
        shown = " ".join(argv)
        _set(run_id, cmd=shown)
        _append(run_id, f"$ {shown}\n\n")
        proc = subprocess.Popen(argv, cwd=wd, env=_run_env(sid, wd),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, start_new_session=True)
        _live[run_id] = proc
        _set(run_id, pid=proc.pid)
        rc = _pump(run_id, proc)
        _finish(run_id, rc, _resources(_output(run_id)))
    except Refused as e:
        _append(run_id, f"\n{e}\n")
        _finish(run_id, -1, "", why=str(e))
    except Exception as e:                                   # noqa: BLE001
        _append(run_id, f"\n{type(e).__name__}: {e}\n")
        _finish(run_id, -1, "", why=f"{type(e).__name__}: {e}")
    finally:
        _live.pop(run_id, None)
        if proc and proc.poll() is None:
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


def _pump(run_id: str, proc) -> int:
    """Read the process output and flush it to the DB in time-batched chunks
    rather than per line; enforce the run and idle ceilings."""
    began = time.time()
    buf, flushed, last = [], began, began
    while True:
        line = proc.stdout.readline() if proc.stdout else ""
        now = time.time()
        if line:
            buf.append(line); last = now
        elif proc.poll() is not None:
            break
        if buf and (now - flushed > 0.5 or sum(len(x) for x in buf) > 400):
            _append(run_id, "".join(buf)); buf.clear(); flushed = now
        if now - last > IDLE_TIMEOUT or now - began > RUN_TIMEOUT:
            _append(run_id, "\n[timed out — terminated]\n")
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            break
    if buf:
        _append(run_id, "".join(buf))
    try:
        return proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        return -1


def cancel(run_id: str, who: str) -> bool:
    proc = _live.get(run_id)
    if not proc:
        return False
    with contextlib.suppress(Exception):
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    _append(run_id, f"\n[cancelled by {who}]\n")
    return True


# ── run row helpers ────────────────────────────────────────────
def _set(run_id: str, **fields) -> None:
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    with db.tx() as c:
        c.execute(f"UPDATE tf_runs SET {sets} WHERE id = ?",
                  (*fields.values(), run_id))


def _output(run_id: str) -> str:
    r = _conn().execute("SELECT output FROM tf_runs WHERE id = ?",
                        (run_id,)).fetchone()
    return (r["output"] if r else "") or ""


def _append(run_id: str, text: str) -> None:
    with db.tx() as c:
        cur = (c.execute("SELECT output FROM tf_runs WHERE id = ?",
                         (run_id,)).fetchone() or {"output": ""})["output"] or ""
        combined = cur + text
        if len(combined) > OUTPUT_MAX:                       # keep the tail
            combined = "…[trimmed]…\n" + combined[-OUTPUT_MAX:]
        c.execute("UPDATE tf_runs SET output = ? WHERE id = ?", (combined, run_id))


def _resources(text: str) -> str:
    """Terraform's own one-line summary of the change, parsed for the pills."""
    m = _APPLY.search(text or "")
    if m:
        return json.dumps({"added": int(m[1]), "changed": int(m[2]),
                           "destroyed": int(m[3])})
    m = _PLAN.search(text or "")
    if m:
        return json.dumps({"add": int(m[1]), "change": int(m[2]),
                           "destroy": int(m[3])})
    return ""


def _finish(run_id: str, rc: int, resources: str, why: str = "") -> None:
    status = ("ok" if rc == 0 else "refused" if rc == -1 and why else "failed")
    with db.tx() as c:
        c.execute("UPDATE tf_runs SET status = ?, rc = ?, resources = ?, why = ?, "
                  "finished = ?, pid = NULL WHERE id = ? AND status = ?",
                  (status, rc, resources, why, _now(), run_id, STATUS_RUNNING))
    _trim(run_id)


def _trim(run_id: str) -> None:
    r = _conn().execute("SELECT stack_id FROM tf_runs WHERE id = ?",
                        (run_id,)).fetchone()
    if not r or not r["stack_id"]:
        return
    with db.tx() as c:
        c.execute("""DELETE FROM tf_runs WHERE stack_id = ? AND id NOT IN (
            SELECT id FROM tf_runs WHERE stack_id = ?
            ORDER BY started DESC LIMIT ?)""",
                  (r["stack_id"], r["stack_id"], RUNS_KEEP))


# ── reads ──────────────────────────────────────────────────────
def _row(r) -> dict:
    d = dict(r)
    d["pid"], d["rgid"] = d.get("proj_id", ""), d.get("rgn_id", "")
    d["ago"] = _ago(d.get("started"))
    d["took"] = _took(d.get("started"), d.get("finished"))
    try:
        d["res"] = json.loads(d.get("resources") or "{}")
    except (ValueError, TypeError):
        d["res"] = {}
    return d


def runs(limit: int = 120, stack_id: str = "") -> list:
    sql = ("SELECT id, stack_id, stack_name, action, proj_id, rgn_id, status, rc, "
           "resources, why, started, finished, by, LENGTH(output) AS len "
           "FROM tf_runs")
    args: tuple = ()
    if stack_id:
        sql += " WHERE stack_id = ?"; args = (stack_id,)
    sql += " ORDER BY started DESC LIMIT ?"
    return _placed([_row(r) for r in _conn().execute(sql, args + (limit,)).fetchall()])


def run(run_id: str, since: int = 0) -> dict | None:
    r = _conn().execute("SELECT status, output, started, finished FROM tf_runs "
                        "WHERE id = ?", (run_id,)).fetchone()
    if not r:
        return None
    out = r["output"] or ""
    return {"text": out[since:], "at": len(out), "done": r["status"] != STATUS_RUNNING,
            "status": r["status"], "took": _took(r["started"], r["finished"])}


def _last_run(sid: str) -> dict | None:
    r = _conn().execute("SELECT id, action, status, rc, resources, started, finished "
                        "FROM tf_runs WHERE stack_id = ? ORDER BY started DESC "
                        "LIMIT 1", (sid,)).fetchone()
    return _row(r) if r else None


def running() -> int:
    return _conn().execute("SELECT COUNT(*) AS n FROM tf_runs WHERE status = ?",
                          (STATUS_RUNNING,)).fetchone()["n"]


def summary(reg: str = "") -> dict:
    """The overview counts. `reg` scopes them to a region the same way the page's
    tabs are scoped: "" = every region, else that region id — so the stat tiles
    track the portal-wide region filter. Both tf_stacks and tf_runs carry rgn_id,
    so a run's region is its own column (no join)."""
    one = lambda q, a=(): (_conn().execute(q, a).fetchone() or [0])[0]   # noqa: E731
    if reg:
        rw, ra = "rgn_id = ?", (reg,)
    else:
        rw, ra = "", ()
    def cnt(table: str, cond: str = "") -> int:
        w = " AND ".join(c for c in (rw, cond) if c)
        return one(f"SELECT COUNT(*) FROM {table}" + (f" WHERE {w}" if w else ""), ra)
    return {
        "stacks": cnt("tf_stacks"),
        "runs": cnt("tf_runs"),
        "running": cnt("tf_runs", f"status = '{STATUS_RUNNING}'"),
        "applied": cnt("tf_runs", "action = 'apply' AND status = 'ok'"),
        "failed": cnt("tf_runs", "status = 'failed'"),
    }


def delete_run(run_id: str) -> bool:
    r = _conn().execute("SELECT status FROM tf_runs WHERE id = ?",
                        (run_id,)).fetchone()
    if r and r["status"] == STATUS_RUNNING:
        raise Refused("that run is still going — stop it first")
    with db.tx() as c:
        return bool(c.execute("DELETE FROM tf_runs WHERE id = ?",
                              (run_id,)).rowcount)


def clear_runs(which: str = "finished") -> int:
    where = {"finished": "status <> ?", "failed": "status = ?", "ok": "status = ?"}
    if which not in where:
        return 0
    arg = STATUS_RUNNING if which == "finished" else which
    with db.tx() as c:
        return c.execute(f"DELETE FROM tf_runs WHERE {where[which]}", (arg,)).rowcount


def adopt_orphans() -> None:
    """On startup, close any run left `running` by a portal that went down mid-run
    — its process is gone with the old worker."""
    with db.tx() as c:
        c.execute("UPDATE tf_runs SET status='failed', why='portal restarted "
                  "during the run', finished=?, pid=NULL WHERE status=?",
                  (_now(), STATUS_RUNNING))


# ── small helpers ──────────────────────────────────────────────
class contextlib_suppress:
    """Swallow the OS errors around killing a process that just exited."""
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return True


def _ago(ts: str | None) -> str:
    if not ts:
        return ""
    try:
        then = time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return ts
    secs = max(0, int(time.time() - then))
    return _dur_words(secs) + " ago"


def _took(start: str | None, end: str | None) -> str:
    if not start or not end:
        return ""
    try:
        a = time.mktime(time.strptime(start, "%Y-%m-%dT%H:%M:%S"))
        b = time.mktime(time.strptime(end, "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return ""
    return _dur_words(max(0, int(b - a)))


def _dur_words(secs: int) -> str:
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"
