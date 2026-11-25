#!/usr/bin/env python3
"""The 3D view's doctor, started by the portal through Claude Code.

WHY THIS EXISTS
    Reported on 21 November 2026: "I still need a better way to connect my
    Claude CLI into the game. Running the watcher is not practical, and I do
    not want to use the API, I do not have it in my subscription." So the
    portal starts Claude Code itself when a listed person calls from the view.
    That is a process started by a web request, holding a credential, on the
    machine that holds every kubeconfig, so what it is given is the test:

      1. It does not exist unless the installation names the binary AND the
         person. To anybody else it is not even mentioned.
      2. The process gets no tools of its own, this portal's MCP server and no
         other, an empty directory, and a short environment: not the portal's.
      3. Its token is the caller's, lives for the visit, is never on a command
         line (nor is what was said in the view), and is gone when it ends,
         however it ends.
      4. One visit per cluster; a call made as a visit leaves gets its own.
      5. A visit that cannot happen says so IN THE VIEW and closes its call:
         the person is in the game and nowhere else.
      6. Nobody watching, or the portal stopping, stops the process.

    Claude Code itself is not run here: a stand-in binary records what it was
    given and waits to be told how to end.

    ./.venv/bin/python tests/test_doctor_cli.py
"""
from __future__ import annotations

import json
import os
import pathlib
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("doctor-cli-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
os.environ["PORTAL_NOT_FOR_CLAUDE"] = "the-portals-own-secret"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, doctor, doctor_brief, doctor_cli, env, main, mcp, rbac, scene, store  # noqa: E402

bad = 0
HOME = pathlib.Path(tempfile.mkdtemp(prefix="doctor-cli-home-"))
os.environ["HOME"] = str(HOME)          # the stand-in finds its orders here: HOME is one of the few things it is given

# `env`, not this interpreter: a shebang cannot hold a path with a space in it,
# and a checkout can live under one
FAKE = '''#!/usr/bin/env python3
import json, os, pathlib, sys, time
home = pathlib.Path(os.environ["HOME"])
argv = sys.argv[1:]
cfg = argv[argv.index("--mcp-config") + 1]
runs = sorted(home.glob("run-*.json"))
me = home / f"run-{len(runs) + 1}.json"
me.write_text(json.dumps({
    "argv": argv, "env": dict(os.environ), "cwd": os.getcwd(), "here": sorted(os.listdir(".")), "pid": os.getpid(),
    "stdin": sys.stdin.read(), "cfg": json.loads(open(cfg).read()),
    "cfg_mode": oct(os.stat(cfg).st_mode & 0o777), "dir_mode": oct(os.stat(".").st_mode & 0o777)}))
order = (home / "order").read_text().strip() if (home / "order").exists() else "wait"
if order == "auth":
    print("Error: OAuth authentication failed. Run /login."); sys.exit(1)
if order == "crash":
    print("something else went wrong"); sys.exit(3)
while not (home / f"go-{len(runs) + 1}").exists():
    time.sleep(0.05)
sys.exit(0)
'''


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def until(cond, secs: float = 6.0) -> bool:
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return bool(cond())


def runs() -> list:
    return [json.loads(p.read_text()) for p in sorted(HOME.glob("run-*.json"), key=lambda p: int(p.stem[4:]))]


def main_test() -> int:
    fake = HOME / "claude-stand-in"
    fake.write_text(FAKE)
    fake.chmod(0o755)

    def person(mail, name, areas):
        uid = auth.create_user(mail, name, "Passw0rd!xY-doctor", role="user")
        db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
        rbac.set_for_user(uid, [rbac.save("", name, "", areas, [], [])])
        return auth.by_id(uid)

    me = person("walker@test.invalid", "Walker", ["clusters", "manage", "config", "gitops"])
    other = person("guest@test.invalid", "Guest", ["clusters"])
    pid = store.add_project("Game", icon="x")
    cid = store.add_cluster(pid, "game", "apiVersion: v1\nkind: Config\n", "game")
    scene.collect = lambda c: {"pods": [], "error": ""}       # no cluster is asked anything here

    def browser(who):
        c = TestClient(main.app, raise_server_exceptions=False)
        c.__enter__()
        c.post("/login", data={"email": who["email"], "password": "Passw0rd!xY-doctor"}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
        return c

    c, guest = browser(me), browser(other)

    def press_h(who=None, pod=""):
        return (who or c).post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid, "pod": pod}).json()

    def say(text):
        return c.post("/clusters/3d/doctor.json", data={"project": pid, "cluster": cid, "say": text}).json()

    def note(text, state="examining", secret=""):
        got = mcp.resolve(secret) if secret else {}
        return mcp.call(got.get("user") or me, "doctor_note",
                        {"cluster": cid, "text": text, "state": state, "who": doctor_cli.WHO},
                        tok=got.get("token"))

    def watching():
        doctor.watching(cid)

    def idle():
        return until(lambda: not doctor_cli.busy(cid))

    print("an installation that never asked for it")
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50, token_days=1)
    got = press_h()
    check("with nothing set there is no such doctor, and the call waits for an AI client as before",
          doctor_cli.available(me) == (False, "") and got["doctor"] == "mcp" and "arrival" not in got and not runs())
    env.DOCTOR_CLI, env.DOCTOR_CLI_FOR = str(fake), ""
    check("naming the binary alone starts nothing for anybody: there is no 'everybody'",
          doctor_cli.available(me) == (False, "") and press_h()["doctor"] == "mcp" and not runs())
    env.DOCTOR_CLI_FOR = f" Walker@Test.invalid , somebody@else.invalid"
    got = press_h(guest)
    check("somebody the installation did not list is not offered it, and is told nothing about it",
          doctor_cli.available(other) == (False, "") and got["doctor"] == "mcp" and "Claude Code" not in got["how"] and not runs())
    note("Nothing to do.", "done")          # closes the calls made above

    print("listed, but something is missing")
    env.DOCTOR_CLI = str(HOME / "not-installed")
    ok, why = doctor_cli.available(me)
    got = press_h()
    check("a binary that is not there is said, to the listed person, in the answer to their call",
          not ok and "install Claude Code" in why and got["doctor"] == "mcp" and got["how"] == why and not runs())
    env.DOCTOR_CLI = str(fake)
    mcp.save_config(enabled=False, allow_actions=True, row_limit=50, token_days=1)
    ok, why = doctor_cli.available(me)
    check("so is a portal whose MCP server is off: that is how the process reaches it", not ok and "MCP server" in why)
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50, token_days=1)
    note("Nothing to do.", "done")

    print("a call from the view")
    env.DOCTOR_CLI_URL = "http://127.0.0.1:1"
    doctor.tell(cid, me["email"], "said before the call, in the view")
    got = press_h(pod="shop/api-1")
    check("the answer says Claude is on the way, and what it may do",
          got["ok"] and got["doctor"] == "portal" and got["arrival"] == "started" and got["hands"]["may_change"]
          and got["how"] == "")
    check("the process starts", until(lambda: len(runs()) == 1))
    r = runs()[0]
    argv, secret = r["argv"], r["cfg"]["mcpServers"]["envmap"]["headers"]["Authorization"].split(" ", 1)[1]

    def after(flag):
        return argv[argv.index(flag) + 1] if flag in argv else None

    check("headless, with none of its own tools: no shell, no files, no web",
          argv[0] == "-p" and after("--tools") == "")
    check("this portal's MCP server and no other, and nobody's settings, hooks or plugins",
          "--strict-mcp-config" in argv and list(r["cfg"]["mcpServers"]) == ["envmap"]
          and r["cfg"]["mcpServers"]["envmap"]["url"] == "http://127.0.0.1:1/mcp" and after("--setting-sources") == "")
    check("what it was not given outright is asked for in the view",
          after("--permission-prompt-tool") == "mcp__envmap__doctor_permit")
    allowed = (after("--allowedTools") or "").split(",")
    check("it may look with everything the portal offers this person, and cure with the doctor's own tools only",
          "mcp__envmap__kubectl_read" in allowed and "mcp__envmap__doctor_note" in allowed
          and "mcp__envmap__gitops_sync" in allowed and "mcp__envmap__cluster_action" in allowed
          and "mcp__envmap__cluster_delete" not in allowed and "mcp__envmap__terraform_run" not in allowed
          and all(t.startswith("mcp__envmap__") for t in allowed))
    check("the token is on no command line, and neither is anything said in the view",
          secret.startswith(mcp.TOKEN_PREFIX) and not any(secret in a for a in argv)
          and not any("said before the call" in a or "EnvMap doctor" in a for a in argv))
    check("the brief arrives on standard input: the call, the cluster, the talk so far, and that goodbye means go",
          "about pod shop/api-1" in r["stdin"] and f"cluster id {cid}" in r["stdin"]
          and "said before the call, in the view" in r["stdin"] and "GOODBYE MEANS GO" in r["stdin"]
          and 'Sign every\nnote as "Claude"' in r["stdin"] and "You MAY change things" in r["stdin"])
    check("the token's file is the process's alone, in a directory that is its alone and holds nothing else",
          r["cfg_mode"] == "0o600" and r["dir_mode"] == "0o700" and r["here"] == ["mcp.json", "said.txt"]
          and pathlib.Path(r["cwd"]).resolve() != pathlib.Path.cwd().resolve())
    check("it is given a short environment, not the portal's",
          "PORTAL_NOT_FOR_CLAUDE" not in r["env"] and "PORTAL_DATA_DIR" not in r["env"]
          and r["env"].get("MCP_TOOL_TIMEOUT") == "180000" and r["env"].get("HOME") == str(HOME))
    who = mcp.resolve(secret)
    check("the token is the caller's own, may change because the installation allows it, and is named for what it is",
          who.get("user", {}).get("id") == me["id"] and who["token"]["mode"] == "act"
          and who["token"]["name"] == doctor_cli.TOKEN_NAME)
    trail = [(a["action"], a["detail"]) for a in auth.read_audit(limit=20)]
    check("the visit is in the audit log", any(a == "doctor_cli_visit" and "shop/api-1" in d for a, d in trail))

    mine_tok, mine_row = mcp.mint(me["id"], "my laptop's client", days=1)
    asked = mcp.call(me, "doctor_calls", {}, tok=mine_row)["structuredContent"]
    own = mcp.call(me, "doctor_calls", {}, tok=who["token"])["structuredContent"]
    theirs = mcp.call(other, "doctor_calls", {})["structuredContent"]
    check("another client of theirs is told the portal answers these calls itself, so it does not send a second doctor",
          asked.get("portal_answers") is True and asked["waiting"])
    check("the portal's own doctor is not told to stand aside, and nobody the installation did not list is told anything",
          "portal_answers" not in own and "portal_answers" not in theirs)
    mcp.forget(mine_row["id"])

    print("while it is here")
    watching()
    again = press_h(pod="shop/api-1")
    spoke = say("and what about the database?")
    check("calling or speaking again starts no second process: the one here hears it",
          again["arrival"] == "here" and spoke["arrival"] == "here" and len(runs()) == 1 and doctor_cli.busy(cid))
    heard = note("Looking at api-1.", "examining", secret)
    check("what was said reaches it with its next note, through the token it was given",
          [h["text"] for h in heard["structuredContent"]["said_to_you"]][-1:] == ["and what about the database?"])

    print("a line said as it leaves")
    note("All healthy. Call me any time.", "done", secret)
    check("its goodbye closes the call", doctor.calls(cid) == [])
    late = say("wait, restart the worker too")
    check("a request said after the goodbye is a new call, and the visit still here is left to see to it",
          late["arrival"] == "here" and len(doctor.calls(cid)) == 1 and len(runs()) == 1)
    (HOME / "go-1").write_text("")
    check("when the first process ends, the call made meanwhile gets a process of its own",
          until(lambda: len(runs()) == 2))
    r2 = runs()[1]
    secret2 = r2["cfg"]["mcpServers"]["envmap"]["headers"]["Authorization"].split(" ", 1)[1]
    check("and that one is sent to answer the line that made it",
          'SAYING this in the view' in r2["stdin"] and "wait, restart the worker too" in r2["stdin"])
    check("the first visit's token is gone and so is its directory, and the second has its own",
          mcp.resolve(secret) == {} and not pathlib.Path(r["cwd"]).exists() and secret2 != secret
          and mcp.resolve(secret2).get("user", {}).get("id") == me["id"])
    watching()
    note("Restarted. Bye!", "done", secret2)
    (HOME / "go-2").write_text("")
    check("with every call answered the visit is over: nothing runs and no token is left",
          idle() and mcp.resolve(secret2) == {} and len(runs()) == 2
          and not [t for t in mcp.tokens(me["id"]) if t["name"] == doctor_cli.TOKEN_NAME])

    print("a goodbye answered to a doctor that has left")
    bye = say("okay bye i will call you")
    check("it is kept, and it calls nobody back",
          bye["ok"] and bye.get("parting") is True and "arrival" not in bye and doctor.calls(cid) == []
          and not doctor_cli.busy(cid) and len(runs()) == 2)
    real = say("okay now check the nodes")
    check("anything that asks for something still brings the doctor", real["arrival"] == "started" and until(lambda: len(runs()) == 3))

    print("a visit that ends without a goodbye")
    mark = doctor.mark()
    watching()
    (HOME / "go-3").write_text("")
    check("the process went quietly: its call is closed and the view is told it has gone",
          idle() and doctor.calls(cid) == []
          and [(n["state"], n["who"]) for n in doctor.spoken(cid, mark)] == [("done", "Claude")])

    print("a visit that cannot happen")
    (HOME / "order").write_text("auth")
    mark = doctor.mark()
    press_h()
    check("Claude Code that is not signed in is said in the view, and the call is closed",
          idle() and doctor.calls(cid) == []
          and any("not signed in" in n["text"] and n["state"] == "done" for n in doctor.spoken(cid, mark)))
    mark, before = doctor.mark(), len(runs())
    press_h()
    check("the next call tries once more, and is told the same: each call gets one visit",
          idle() and len(runs()) == before + 1 and any("not signed in" in n["text"] for n in doctor.spoken(cid, mark)))
    (HOME / "order").write_text("crash")
    mark = doctor.mark()
    press_h()
    check("any other failure is said too, without the process's own words",
          idle() and doctor.calls(cid) == []
          and [n["text"] for n in doctor.spoken(cid, mark)] ==
          ["I could not finish: Claude Code stopped with an error where this portal runs."])
    trail = [(a["action"], a["detail"]) for a in auth.read_audit(limit=30)]
    check("how each visit ended is in the audit log",
          any(a == "doctor_cli_left" and "exit 1" in d and "not signed in" in d for a, d in trail)
          and any(a == "doctor_cli_left" and "exit 0" in d for a, d in trail))
    (HOME / "order").write_text("wait")

    print("nobody watching")
    doctor_cli.AWAY, before, mark = 0.6, len(runs()), doctor.mark()
    press_h()
    check("a process starts", until(lambda: len(runs()) == before + 1))
    gone = until(lambda: not doctor_cli.busy(cid), 12)
    check("with no view asking for the feed it is stopped, says so, and leaves no token",
          gone and doctor.calls(cid) == [] and any("Nobody is watching" in n["text"] for n in doctor.spoken(cid, mark))
          and not [t for t in mcp.tokens(me["id"]) if t["name"] == doctor_cli.TOKEN_NAME])
    doctor_cli.AWAY = 180.0

    print("a look-only installation")
    mcp.save_config(enabled=True, allow_actions=False, row_limit=50, token_days=1)
    before = len(runs())
    got = press_h()
    check("the answer says it may examine but not operate, and which gate is shut",
          got["arrival"] == "started" and not got["hands"]["may_change"] and "switched off" in got["hands"]["why"])
    check("it starts", until(lambda: len(runs()) == before + 1))
    r = runs()[-1]
    argv = r["argv"]
    secret = r["cfg"]["mcpServers"]["envmap"]["headers"]["Authorization"].split(" ", 1)[1]
    check("its token cannot change anything, the changing tools are refused outright, and it is told it may only look",
          mcp.resolve(secret)["token"]["mode"] == "read"
          and "mcp__envmap__cluster_action" in (after("--disallowedTools") or "").split(",")
          and "mcp__envmap__cluster_action" not in (after("--allowedTools") or "").split(",")
          and "You may NOT change anything" in r["stdin"])

    print("the portal stops")
    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    was = alive(r["pid"])
    doctor_cli._shutdown()
    # Looked at the moment it returns, not a little later: the visit's own
    # thread would tidy up too if it were given the time, and a stopping
    # interpreter does not give a daemon thread any.
    now_alive, tok_left, dir_left = alive(r["pid"]), mcp.resolve(secret), pathlib.Path(r["cwd"]).exists()
    check("its doctor is stopped with it, and the visit's token and directory are gone, before the portal has finished stopping",
          was and not now_alive and tok_left == {} and not dir_left)
    check("and nothing is left running", until(lambda: not doctor_cli.busy(cid)))
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50, token_days=1)
    note("Gone.", "done")

    print("what a killed portal left behind")
    left, _row = mcp.mint(me["id"], doctor_cli.TOKEN_NAME, days=1, mode="act")
    mine, _row = mcp.mint(me["id"], "my laptop", days=1)
    old_dir, new_dir = (pathlib.Path(tempfile.mkdtemp(prefix=doctor_cli.HOMES)) for _ in range(2))
    (old_dir / "mcp.json").write_text("{}")
    long_ago = time.time() - doctor_cli.VISIT_LIMIT - 600
    os.utime(old_dir, (long_ago, long_ago))
    swept = doctor_cli.sweep()
    check("a visit's leftover token is removed at the next start, and nobody's own token is touched",
          swept == 1 and mcp.resolve(left) == {} and mcp.resolve(mine).get("user", {}).get("id") == me["id"])
    check("so is its directory, but not one young enough to be another portal's visit under way",
          not old_dir.exists() and new_dir.exists())
    new_dir.rmdir()

    print("the words")
    look = doctor_brief.prompt_for({"id": 1, "by": "a@b", "cluster": "c", "cluster_id": "c1", "pod": ""}, False,
                                   why_not="actions are off")
    check("a doctor that may only look is told why, so it can say which gate is shut",
          "The reason: actions are off." in look and "You MAY change" not in look)
    check("the closing listen is a minute, not two", doctor_brief.LISTENS == 3 and "3 listens in a row" in look)
    allowed, never = doctor_brief.tool_lists(True, ["kubectl_read", "brand_new_reader", "cluster_delete", "gitops_sync"])
    check("a read tool the portal gains later is allowed without a list being edited; a changing one never is",
          "mcp__envmap__brand_new_reader" in allowed and "mcp__envmap__cluster_delete" not in allowed
          and "mcp__envmap__gitops_sync" in allowed and "mcp__envmap__config_set" not in allowed and "Bash" in never)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
