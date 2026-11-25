"""The 3D view's doctor, run by the portal through Claude Code.

WHY THIS EXISTS
    The doctor could be reached two ways: an API key pasted on the account
    page (`doctor_ai`), or an AI client the person had connected over MCP and
    left running somewhere to answer calls. Somebody whose Claude is a
    subscription has no API key, and the second way meant keeping a watcher
    script alive in a terminal: "running the watcher is not practical", they
    said, and it is not. So where Claude Code is installed beside the portal,
    the portal starts it itself, one process per visit, when a listed person
    calls from the view. Nothing to keep running, and nothing to leave the game
    for.

WHOSE CLAUDE IT IS
    The machine's: whatever account Claude Code is signed in with where the
    portal runs, or the sign-in the token file names. A subscription is one
    person's, so this is off unless the installation names both the binary and
    the PEOPLE whose calls may start it (`env.DOCTOR_CLI`, `env.DOCTOR_CLI_FOR`),
    and there is no way to say "everybody".

WHAT THE PROCESS IS GIVEN, AND WHAT IT IS NOT
    * No built-in tools at all (no shell, no files, no web): only this
      portal's MCP server, and no other MCP server, plugin or project file.
    * It runs in an empty directory of its own, with a short environment
      rather than the portal's, which can hold PORTAL_* secrets.
    * It is the CALLER over MCP, with a token minted for this one visit and
      removed when it ends. So every read and every change passes the same
      roles, the same installation switch, the same production name typed and
      the same audit line as any other MCP client of theirs, and a change is
      still put to them in the view first (`doctor_permit`, and the brief).
    * The token is in a file only that process's directory holds, never on a
      command line, and the brief goes in on standard input for the same
      reason: a command line is readable by everybody on the machine.

BOUNDS
    One visit per cluster at a time, a wall clock (VISIT_LIMIT), and somebody
    watching (AWAY): a doctor nobody is looking at is stopped rather than left
    to spend the account. A process that fails says so IN THE VIEW, because the
    person is there and nowhere else.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from . import claude_code, db, doctor, doctor_brief, env, secretbox

WHO = "Claude"                   # the name the view draws the Claude figure for
TOKEN_NAME = "3D view doctor (one visit)"
VISIT_LIMIT = 30 * 60            # a visit that runs longer is stopped
AWAY = 180.0                     # no view has asked for the feed in this long: the doctor leaves
GRACE = 5.0                      # between asking the process to stop and making it
# A permission question waits a minute and a half for the person's answer, and
# the client gives a tool call less than that unless told otherwise.
TOOL_TIMEOUT_MS = "180000"
# What the process inherits. Named, not filtered: the portal's own environment
# can carry its secret key and whatever else the installation put there.
PASS_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "CLAUDE_CONFIG_DIR",
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")

log = logging.getLogger(__name__)
_guard = threading.Lock()
_visits: dict = {}               # cid -> {"thread", "stop", "uid", "at", "proc", "tid", "home"}
HOMES = "envmap-doctor-"         # what each visit's own directory is called, under the temporary directory


# ── who may have one ───────────────────────────────────────────
def _people() -> set:
    return {e.strip().lower() for e in env.DOCTOR_CLI_FOR.split(",") if e.strip()}


def _binary() -> str:
    if env.DOCTOR_CLI:
        return shutil.which(env.DOCTOR_CLI, path=env.TOOL_PATH) or ""
    return claude_code.path() if env.DOCTOR_CLI_FETCH else ""


# ── a person's own Claude subscription ─────────────────────────
# What `claude setup-token` prints: a year-long sign-in to that person's Claude
# subscription. Kept sealed, one per person, never shown again, and given only
# to the Claude Code process of a visit that person started. It lets a
# subscription be the doctor where Claude Code is not signed in to anybody (a
# cluster), and makes it that person's own account rather than the machine's.
SIGNIN = re.compile(r"sk-ant-oat\d\d-[A-Za-z0-9_\-]{40,}")


def _signin_table() -> None:
    db.run("CREATE TABLE IF NOT EXISTS doctor_signins (uid TEXT PRIMARY KEY, "
           "sealed TEXT NOT NULL, at INTEGER NOT NULL)")


def is_signin(token: str) -> bool:
    return bool(SIGNIN.fullmatch("".join((token or "").split())))


def signin_save(uid: str, token: str) -> None:
    _signin_table()
    db.run("INSERT OR REPLACE INTO doctor_signins (uid, sealed, at) VALUES (?, ?, ?)",
           (uid, secretbox.seal("".join(token.split())), int(time.time())))


def signin_forget(uid: str) -> None:
    _signin_table()
    db.run("DELETE FROM doctor_signins WHERE uid = ?", (uid,))


def signin_of(uid: str) -> str:
    _signin_table()
    row = db.one("SELECT sealed FROM doctor_signins WHERE uid = ?", (uid or "",))
    if not row:
        return ""
    try:
        return secretbox.unseal(row["sealed"])
    except Exception:                          # noqa: BLE001 - a key that cannot be read is not connected
        return ""


def offered() -> bool:
    """Whether this installation runs Claude Code for the doctor at all."""
    return bool(env.DOCTOR_CLI or env.DOCTOR_CLI_FETCH)


def signin_shown(uid: str) -> dict:
    """What the account page may say about it: whether, and when. Never the token."""
    _signin_table()
    row = db.one("SELECT at FROM doctor_signins WHERE uid = ?", (uid or "",))
    return {"connected": bool(row), "at": row["at"] if row else 0,
            "offered": offered()}


def base() -> str:
    """This portal, as a process on the same machine reaches it."""
    return (env.DOCTOR_CLI_URL or f"http://127.0.0.1:{env.PORT}").rstrip("/")


def available(user: dict | None) -> tuple[bool, str]:
    """Whether a call from this person starts Claude Code here. When it does
    not, the sentence says what is missing, but only to somebody the
    installation listed: to everybody else this way does not exist."""
    from . import mcp
    listed = bool(env.DOCTOR_CLI) and ((user or {}).get("email") or "").lower() in _people()
    own = bool(env.DOCTOR_CLI or env.DOCTOR_CLI_FETCH) and bool(signin_of((user or {}).get("id", "")))
    if not (listed or own):
        return False, ("sign Claude Code in to your Claude subscription on your account page "
                       "(Your account → Claude, the doctor)") if env.DOCTOR_CLI_FETCH else ""
    if not _binary():
        if env.DOCTOR_CLI_FETCH and not env.DOCTOR_CLI:
            return False, claude_code.waiting(claude_code.fetch())
        return False, ("whoever runs this portal has to install Claude Code where it runs "
                       f"(it is set to start “{env.DOCTOR_CLI}”, which is not there)")
    if not base().startswith(("http://", "https://")):
        return False, "whoever runs this portal has to give it its own address as http or https"
    if not mcp.enabled():
        return False, ("this portal's MCP server has to be switched on, because that is how "
                       "Claude reaches it (Settings → AI clients)")
    return True, ""


def hands(user: dict | None, sel: dict) -> dict:
    """What a visit run as this person could change, said when they call."""
    from . import mcp, rbac
    if not mcp.config()["allow_actions"]:
        return {"clients": 1, "may_change": False, "why": mcp._no_act_why(None).rstrip(".")}
    if rbac.may_area(user, "manage") or rbac.may_area(user, "config"):
        return {"clients": 1, "may_change": True, "why": ""}
    return {"clients": 1, "may_change": False,
            "why": ("your roles include neither Cluster management nor Configuration, "
                    "so it may examine but not operate")}


def busy(cid: str) -> bool:
    with _guard:
        v = _visits.get(cid)
        return bool(v and v["thread"].is_alive())


def start(user: dict, cid: str, sel: dict) -> str:
    """Send the doctor to the calls open on this cluster. "started", "here" (a
    visit is already under way, and hears whatever was just said), or
    "unavailable". Runs on its own thread: the person keeps walking."""
    ok, _why = available(user)
    if not ok:
        return "unavailable"
    with _guard:
        v = _visits.get(cid)
        if v and v["thread"].is_alive():
            return "here"
        stop = threading.Event()
        doctor.watching(cid)      # they are looking at it: they just called
        t = threading.Thread(target=_run, name=f"doctor-cli-{cid}", daemon=True,
                             args=(user, cid, {**sel, "id": cid}, _binary(), stop))
        _visits[cid] = {"thread": t, "stop": stop, "uid": user.get("id", ""),
                        "at": time.time(), "proc": None, "tid": "", "home": ""}
        t.start()
    return "started"


def stop(cid: str) -> None:
    with _guard:
        v = _visits.get(cid)
    if v:
        v["stop"].set()


# ── one visit ──────────────────────────────────────────────────
def _env(user: dict | None = None, home: str = "") -> dict:
    out = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
    out["PATH"] = env.TOOL_PATH
    out["MCP_TOOL_TIMEOUT"] = TOOL_TIMEOUT_MS
    own = signin_of((user or {}).get("id", ""))
    if own:
        # The person's own subscription. Its process lives in the visit's own
        # directory: in a pod HOME is on a read-only filesystem, and Claude Code
        # writes its state there. It is not updated in place either: the copy
        # the portal fetched and checked is the one that runs.
        out["CLAUDE_CODE_OAUTH_TOKEN"] = own
        if home:
            out["HOME"] = home
        out["DISABLE_AUTOUPDATER"] = "1"
        return out
    signin = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    if env.DOCTOR_CLI_TOKEN_FILE:
        try:
            # A token copied from a terminal often wraps onto two lines;
            # whatever whitespace came with it is not part of it.
            with open(os.path.expanduser(env.DOCTOR_CLI_TOKEN_FILE)) as f:
                signin = "".join(f.read().split()) or signin
        except OSError:
            pass                  # the process then says it is not signed in, and the view is told
    if signin:
        out["CLAUDE_CODE_OAUTH_TOKEN"] = signin
    return out


def _end(proc) -> None:
    """Stop the process and whatever it started: asked first, then made to."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except OSError:
            return
        try:
            proc.wait(GRACE)
        except subprocess.TimeoutExpired:
            continue


def _visit(user: dict, cid: str, sel: dict, call: dict, binary: str, stop) -> tuple[int, str]:
    """Run Claude Code for one call. (exit code, why it was stopped or "")."""
    from . import auth, mcp
    secret, tok = mcp.mint(user["id"], TOKEN_NAME, days=1,
                           mode="act" if mcp.config()["allow_actions"] else "read")
    home = tempfile.mkdtemp(prefix=HOMES)                 # 0700, and nobody else's
    proc = None
    with _guard:
        if cid in _visits:
            _visits[cid].update(tid=tok["id"], home=home)
    try:
        cfg = os.path.join(home, "mcp.json")
        with os.fdopen(os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            json.dump({"mcpServers": {"envmap": {
                "type": "http", "url": mcp.endpoint(base()),
                "headers": {"Authorization": f"Bearer {secret}"}}}}, f)
        may = mcp.may_act(tok)
        allowed, never = doctor_brief.tool_lists(may, [t["name"] for t in mcp.tools(user, tok)])
        brief = doctor_brief.prompt_for(
            {**call, "cluster": sel.get("name", cid), "cluster_id": cid,
             "conversation": doctor.recent(cid)},
            may, WHO, "" if may else mcp._no_act_why(tok).rstrip("."))
        cmd = [binary, "-p",
               "--tools", "",                              # none of its own: no shell, no files, no web
               "--allowedTools", ",".join(allowed),
               "--disallowedTools", ",".join(never),
               # whatever is on neither list is asked about in the 3D view
               "--permission-prompt-tool", doctor_brief.PREFIX + doctor_brief.PERMIT,
               "--mcp-config", cfg, "--strict-mcp-config",
               # no user, project or local settings: no hooks, plugins or
               # instructions that belong to whoever else uses this machine
               "--setting-sources", ""]
        auth.audit(user, "doctor_cli_visit", sel.get("name", cid),
                   f"call {call['id']} · {call.get('pod') or 'the whole cluster'}"
                   + ("" if may else " · look only"), "")
        with open(os.path.join(home, "said.txt"), "w+") as out:
            proc = subprocess.Popen(cmd, cwd=home, env=_env(user, home), stdin=subprocess.PIPE,
                                    stdout=out, stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True)
            with _guard:
                if cid in _visits:
                    _visits[cid]["proc"] = proc
            try:
                proc.stdin.write(brief)
                proc.stdin.close()
            except OSError:
                pass              # it has already gone: its exit code says why
            until, why = time.time() + VISIT_LIMIT, ""
            while proc.poll() is None:
                if stop.is_set():
                    why = "stopped"
                elif time.time() > until:
                    why = f"the visit ran past {VISIT_LIMIT // 60} minutes"
                elif time.time() - doctor.watched(cid) > AWAY:
                    why = "nobody is watching"
                if why:
                    _end(proc)
                    break
                time.sleep(0.4)
            out.seek(0)
            tail = out.read()[-2000:]
        code = proc.returncode if proc.returncode is not None else -1
        if stop.is_set() and not why:
            why = "stopped"       # ended from outside the loop: the portal is stopping
        if code and not why:
            # for whoever runs the portal; the view gets a sentence, not this
            log.warning("the doctor's Claude Code exited %s: %s", code, tail.strip()[-400:])
            if any(w in tail.lower() for w in ("authenticat", "oauth", "/login", "api key", "not logged in")):
                why = "not signed in"
        return code, why
    except OSError as e:
        log.warning("the doctor's Claude Code could not be started: %s", e)
        return -1, "could not start"
    finally:
        if proc is not None:
            _end(proc)
        mcp.forget(tok["id"])
        shutil.rmtree(home, ignore_errors=True)
        with _guard:
            if cid in _visits:
                _visits[cid].update(proc=None, tid="", home="")


SORRY = {
    "not signed in": ("I cannot come: Claude Code is not signed in where this portal runs. "
                      "Whoever runs the portal has to sign it in again."),
    "could not start": "I cannot come: Claude Code would not start where this portal runs.",
    "nobody is watching": "Nobody is watching any more, so I am leaving.",
    "stopped": "I have been called away. Press H if you need me again.",
}


def _run(user: dict, cid: str, sel: dict, binary: str, stop) -> None:
    """Answer every call open on this cluster, one process each, oldest first.

    One at a time and then look again: a visit's goodbye closes every call
    here, and a line somebody typed as it left is a new call, so the list is
    out of date the moment a visit ends. Each call gets one visit, even when it
    fails: a sign-in that is broken is not mended by trying again, and the
    next call somebody makes is told so in its turn."""
    from . import auth
    seen: set = set()
    while True:
        with _guard:
            # looked for and let go under one lock: `start` either finds this
            # visit and leaves the new call to it, or finds none and starts one
            call = None if stop.is_set() else next((c for c in doctor.calls(cid) if c["id"] not in seen), None)
            if not call:
                _visits.pop(cid, None)
                return
        seen.add(call["id"])
        mark, began = doctor.mark(), time.time()
        try:
            code, why = _visit(user, cid, sel, call, binary, stop)
        except Exception as e:                                  # noqa: BLE001
            log.exception("the doctor's visit failed")
            code, why = -1, f"error: {type(e).__name__}"
        said = doctor.spoken(cid, mark)
        auth.audit(user, "doctor_cli_left", sel.get("name", cid),
                   f"call {call['id']} · exit {code} · {int(time.time() - began)}s · {len(said)} lines"
                   + (f" · {why}" if why else ""), "")
        if why in ("nobody is watching", "stopped"):
            stop.set()                    # and no visit follows this one
        left = [c["id"] for c in doctor.calls(cid) if c["id"] in seen]
        if not left:
            continue                      # it said its goodbye: the ordinary end
        # It went without one. The calls it was answering are closed quietly,
        # and it says why only when nobody is waiting on a visit still to come:
        # a `done` line would close the call they have just made.
        waiting = [c for c in doctor.calls(cid) if c["id"] not in seen]
        doctor.close(cid, left)
        if not waiting or stop.is_set():      # stopped: no visit is coming for those either
            text = SORRY.get(why) or (
                f"I have to leave: {why}." if why and not why.startswith("error")
                else "I could not finish: Claude Code stopped with an error where this portal runs." if code
                else "I am off. Press H or T if you need me again." if said
                # it ran and ended without a word: it never reached the portal's tools
                else "I came and could not reach this portal's tools, so there is nothing I can do from here.")
            doctor.note(cid, WHO, text, "", "done")


# ── what a stopped portal leaves behind ────────────────────────
def sweep() -> int:
    """Remove what visits a killed portal never ended left behind: their
    tokens, and their directories, each of which holds one. Called once when
    the portal starts, before any visit of its own can exist.

    The directories are in the machine's temporary directory, which another
    portal on the same machine shares (a demo beside the real one), so only
    one older than any visit can be is taken: a younger one may be in use."""
    from . import db
    left = db.q("SELECT id FROM mcp_tokens WHERE name = ?", (TOKEN_NAME,))
    for r in left:
        db.run("DELETE FROM mcp_tokens WHERE id = ?", (r["id"],))
    try:
        for name in os.listdir(tempfile.gettempdir()):
            path = os.path.join(tempfile.gettempdir(), name)
            if name.startswith(HOMES) and time.time() - os.stat(path).st_mtime > VISIT_LIMIT + 120:
                shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
    return len(left)


def _shutdown() -> None:
    """The portal is stopping: its doctors stop with it, and their tokens and
    directories go. The visit threads are daemons, so their own clean-up may
    never run."""
    from . import mcp
    with _guard:
        going = list(_visits.values())
    for v in going:
        v["stop"].set()
        if v.get("proc") is not None:
            _end(v["proc"])
        if v.get("tid"):
            try:
                mcp.forget(v["tid"])
            except Exception:                                   # noqa: BLE001
                pass
        if v.get("home"):
            shutil.rmtree(v["home"], ignore_errors=True)


atexit.register(_shutdown)
