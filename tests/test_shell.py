#!/usr/bin/env python3
"""Running things inside a container: framing, streaming, and the audit line.

WHY THIS EXISTS
    Two different things share this file because they share a shell.

    THE ONE-COMMAND PATH holds an `sh` open and writes commands to its stdin,
    so "where does this command's output end" is not a question the operating
    system answers. A random marker is echoed after each command and the reader
    watches for it. What can go wrong is invisible until someone types the
    wrong command at the wrong moment: the marker lands on the SAME line when
    output has no trailing newline (`printf ok`); a flush must never cut
    through a marker that has only half arrived, or the reader waits for one it
    has already thrown away; and stdout to a pipe is block-buffered while
    stdout to a terminal is line-buffered, which is why `ping` said nothing for
    thirteen seconds and the fix was a pty rather than anything in the reader.

    THE INTERACTIVE TERMINAL has no command boundary at all — it is a stream of
    keystrokes — so the audit line is rebuilt from them. That rebuild is the
    part with something to lose: it decides what gets written into a permanent
    log, and the first version of it wrote a password down in full. Every case
    below was measured against a real session first.

    None of it needs a cluster: the session is `sh` on a pipe or on a pty
    either way, so these run a real shell locally through the same code.

    It also checks that no module defines the same top-level name twice. That
    is not a style rule — `complete()` for the kubectl console was silently
    replaced by `complete()` for the pod shell, and the console's TAB answered
    500 for every keystroke until someone tried it.

    ./.venv/bin/python tests/test_shell.py
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys
import termios
import threading
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("shell-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import kmanage                                        # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def sh(tty: bool = False) -> kmanage._Session:
    s = kmanage._Session(["sh"], want_tty=tty)
    if tty:
        # In production there are TWO terminals: the portal's, which kubectl
        # reads and which is raw on purpose so that ^C is forwarded rather than
        # acted on locally, and the container's, which kubelet creates with the
        # ordinary defaults and which is where ^C becomes a signal. With no
        # kubectl in between, this one pty has to stand in for both, so put
        # back the signal handling the far end would have.
        mode = termios.tcgetattr(s.fd)
        mode[3] |= termios.ISIG
        termios.tcsetattr(s.fd, termios.TCSANOW, mode)
        s.run("PS1=''; stty -echo 2>/dev/null; printf ok", 8)   # as _start_session
        s.echoes = "printf" in s.run("printf ok", 8)["out"]
    return s


def collect(sess, command, timeout=8.0):
    """(text, code, kinds) from one command, the way `run` sees it."""
    out, code, kinds = [], None, []
    for kind, val in sess.frames(command, timeout):
        kinds.append(kind)
        if kind == "out":
            out.append(val)
        elif kind == "exit":
            code = val
    return "".join(out), code, kinds


def main() -> int:
    print("what the marker separates from the output")
    s = sh()
    text, code, _k = collect(s, "printf ok")
    # The bug this prevents: `printf` writes no newline, so the marker lands on
    # the same line. Discarding that line lost the output AND made the probe in
    # session_for fail, which sent every terminal down the slow one-shot path.
    check(f"output with no trailing newline survives ({text!r})", text == "ok")
    check("and its exit status is read", code == 0)

    text, code, _k = collect(s, "echo one; echo two")
    check(f"two lines come back whole ({text!r})", text == "one\ntwo\n")
    _t, code, _k = collect(s, "false")
    check(f"a non-zero status is reported ({code})", code == 1)
    _t, code, _k = collect(s, "sh -c 'exit 7'")
    check(f"and it is the real number, not just 1 ({code})", code == 7)
    text, _c, _k = collect(s, "echo to-err >&2")
    check(f"stderr is interleaved, not dropped ({text!r})", text == "to-err\n")
    check("the session is still usable after all of that", s.alive())
    s.close()

    print("output appears while the command is still running")
    s = sh()
    started, first, seen = time.time(), None, []
    for kind, val in s.frames("echo a; sleep 1.2; echo b", 8):
        if kind == "out":
            if first is None:
                first = time.time() - started
            seen.append(val)
    # The whole point of streaming: a terminal is judged on when the first
    # character appears, not on when the command ends.
    check(f"the first line arrives long before the command ends "
          f"({first:.2f}s of 1.2s)", first is not None and first < 0.6)
    check(f"and both lines arrive ({''.join(seen)!r})",
          "".join(seen) == "a\nb\n")

    print("a line with no newline does not wait for one")
    started, at = time.time(), None
    for kind, val in s.frames("printf 'password: '; sleep 1.2; echo ok", 8):
        if kind == "out" and "password" in val and at is None:
            at = time.time() - started
    # A prompt is the case that matters: holding it until the newline means the
    # user stares at a blank terminal wondering what it wants.
    check(f"a prompt shows before the command finishes "
          f"({'never' if at is None else format(at, '.2f') + 's'})",
          at is not None and at < 0.6)
    s.close()

    print("a flush must never cut a half-arrived marker in two")
    tok = "__done_abcdef012345__"
    check("a tail that could start the marker is held back",
          kmanage._overlap("output so far__do", tok) == 4)
    check("the whole marker minus one character is held back",
          kmanage._overlap("x" + tok[:-1], tok) == len(tok) - 1)
    # Never more than that: holding the whole marker back would mean holding
    # back the marker itself, and the reader would wait for ever. (A COMPLETE
    # marker in the buffer is not this function's business — find() reaches it
    # first, which the end-to-end case below covers.)
    check("nothing is ever held back beyond one character short of the marker",
          all(kmanage._overlap(b, tok) <= len(tok) - 1
              for b in ("x" + tok, tok, tok + tok, "__", "_")))
    check("ordinary text is not held back at all",
          kmanage._overlap("nothing like it", tok) == 0)
    check("nor is an empty buffer", kmanage._overlap("", tok) == 0)
    # And end to end: output that looks like the beginning of a marker is still
    # delivered, and the command still terminates.
    s = sh()
    text, code, _k = collect(s, "printf '__done_'; sleep 0.4; echo x")
    check(f"output resembling a marker is kept, not eaten ({text!r})",
          text == "__done_x\n")
    check("and the real marker is still found", code == 0)
    s.close()

    print("a command that does not come back")
    s = sh()
    started = time.time()
    got = s.run("sleep 30", 1.0)
    check(f"the deadline is honoured ({time.time() - started:.2f}s)",
          time.time() - started < 3)
    check("it is reported as a timeout", got["timeout"] and got["code"] == 124)
    # The stream is now out of step with the marker protocol — the sleep is
    # still running and will print nothing — so the session cannot be reused.
    check("and the session is closed rather than left out of step",
          not s.alive())

    print("walking away from a stream stops the command")
    s = sh()
    frames = s.frames("echo started; sleep 30", 60)
    started_at = time.time()
    first = next(frames, None)  # a generator does nothing until it is pulled
    check(f"the command is under way ({first})",
          first == ("out", "started\n") and time.time() - started_at < 2)
    frames.close()              # what an abandoned SSE response does
    check("closing the reader kills the shell, which kills the command",
          not s.alive())

    print("a terminal, so the C library does not hold the output back")
    # The measured case: `ping -c 4` in a real pod sent its header and then
    # nothing for thirteen seconds, delivering every reply at once on exit.
    # Nothing was wrong with the reader — stdout to a PIPE is block-buffered
    # and stdout to a TERMINAL is line-buffered, and that is a property of the
    # program being run, not of anything the portal can do from outside.
    # Python behaves exactly the same way, which is what makes it testable here.
    drip = ('python3 -c "import time' + chr(10)
            + 'for i in range(3): print(i); time.sleep(0.4)"')
    when = {}
    for mode in (False, True):
        s = sh(mode)
        began, marks = time.time(), []
        for kind, val in s.frames(drip, 12):
            if kind == "out" and val.strip():
                marks.append(round(time.time() - began, 2))
        when[mode] = marks
        s.close()
    check(f"through a pipe the output arrives in one lump at the end "
          f"({when[False]})", len(when[False]) == 1)
    check(f"through a terminal it arrives as it is printed ({when[True]})",
          len(when[True]) >= 3 and when[True][0] < 0.3)

    print("Ctrl+C goes where there is a terminal to take it")
    # Only half of this is testable here. Writing 0x03 is the portal's part;
    # turning it into SIGINT is the far pty's line discipline, and the far pty
    # is the one kubelet creates for the container — with a session and a
    # controlling terminal, which a bare local `sh` on a pty pair has not got.
    # So this checks what the portal decides, and the signal itself was checked
    # against a real pod: `sleep 30` stopped in 0.4s, the shell survived it,
    # and the next command ran on the same session.
    s = sh()
    check("a plain pipe has nowhere to deliver an interrupt, and says so",
          s.interrupt() is False)
    s.close()
    s = sh(True)
    check("a terminal takes it", s.interrupt() is True)
    check("and the shell is still there afterwards", s.alive())
    _t, code, _k = collect(s, "sh -c 'exit 130'")
    check(f"an interrupted command's status is passed through ({code})",
          code == 130)
    s.close()
    check("a session that has been closed refuses rather than pretends",
          s.interrupt() is False)

    print("what a terminal echoes back is not output")
    s = sh(True)
    s.echoes = True          # as if `stty -echo` were not in the image
    text, code, _k = collect(s, "echo mine")
    # The echoed line contains the printf that builds the marker. If the marker
    # were written out whole it would come back in the echo and be read as the
    # command finishing before it had begun.
    check(f"the command is not repeated back as though the pod said it "
          f"({text!r})", "printf" not in text and "__dne" not in text)
    s.close()

    print("a shell that is not there")
    s = kmanage._Session(["sh", "-c", "exit 0"])
    time.sleep(0.2)
    got = s.run("echo hello", 5)
    # A distroless image has no /bin/sh. That is not an error, it is the signal
    # to fall back to one kubectl exec per command — but only if it is noticed.
    check(f"a dead shell answers at once rather than at the deadline "
          f"({got})", got["out"] == "" and got["code"] == 124)

    print("what the audit log keeps of an interactive terminal")
    # There is no command boundary in a terminal, so the log is rebuilt from
    # keystrokes. Every case here was measured against a real session first,
    # and two earlier versions of the rule got caught by exactly these.
    #
    # The echo is the whole point and it is SLOW: it is a round trip to the
    # cluster, so it lands well after the person has pressed Enter. Each step
    # below is (what the container said, keystrokes, does it echo them), and
    # the echo is delivered AFTER the whole burst — which is what the network
    # actually does, and what broke the first two attempts.
    def session(steps, wait=True):
        a, out = kmanage.pty_audit_line(), []
        for said, keys, echo in steps:
            if said:
                a.saw_output(said)
            out += a.typed(keys)
            if echo:
                a.saw_output(keys)
            out += a.due()
        # …and then the terminal is closed, settling anything still waiting.
        return out + (a.close() if wait else [])

    got = session([("$ ", "whoami\r", True)])
    check(f"an ordinary command is recorded as typed ({got})", got == ["whoami"])

    # THE ONE THAT MATTERS. `read -s -p "database password: "` prints a prompt
    # and turns echo off. An early version counted the PROMPT itself as the
    # echo and wrote the password into the audit log in full.
    got = session([('read -s -p "db password: " PW\r\n', "", False),
                   ("db password: ", "hunter2-not-real\r", False)])
    check(f"a password typed at a password prompt is not written down ({got})",
          len(got) == 1 and "hunter2" not in got[0] and "hidden" in got[0])

    # And the other way. A whole line arrives faster than its echo comes back,
    # so judging at Enter hid ordinary commands — including every paste.
    got = session([("$ ", "kubectl get pods -A\r", True)])
    check(f"a line typed faster than the network is still recorded ({got})",
          got == ["kubectl get pods -A"])
    got = session([("$ ", "set q=ns\rkubernetes.default.svc\r", True)])
    check(f"and so is a pasted pair of commands ({got})",
          got == ["set q=ns", "kubernetes.default.svc"])

    # Nothing came back at all: a secret, whatever the prompt said.
    got = session([("Enter code: ", "123456\r", False)])
    check(f"an unechoed line is hidden even when the prompt did not say why "
          f"({got})", len(got) == 1 and "123456" not in got[0])

    # A line must not be settled by the PREVIOUS line's echo still in the
    # buffer, or one echoed command would vouch for every silent one after it.
    a = kmanage.pty_audit_line()
    a.saw_output("$ ")
    a.typed("ls\r"); a.saw_output("ls\r\nfile-a  file-b\r\n$ ")
    first = a.due()
    a.typed("ls\r")                       # same text, but nothing comes back
    second = a.close()
    check(f"an identical line with no echo of its own is still hidden "
          f"({first} then {second})",
          first == ["ls"] and len(second) == 1 and "hidden" in second[0])

    # THE REAL TERMINAL. A person types one character at a time and the shell
    # echoes each one AS IT IS TYPED — so by Enter the echo is already back. The
    # reconstruction must read it there; waiting for the command to reappear in
    # LATER output hides every real command, because a shell never re-prints what
    # it just ran. (This is exactly the bug the PAM command view surfaced: every
    # interactive command came out as "<hidden>".) Feeding whole lines, as the
    # helper above does, never exercised this.
    a = kmanage.pty_audit_line()
    a.saw_output("[root@waf01 ~]# ")
    out = []
    for ch in "systemctl restart nginx":
        out += a.typed(ch)
        a.saw_output(ch)                  # the host echoes each keystroke
    out += a.typed("\r")
    a.saw_output("\r\nJob for nginx.service...\r\n[root@waf01 ~]# ")
    out += a.close()
    check(f"a command typed character by character is recorded, not hidden "
          f"({out})", out == ["systemctl restart nginx"])

    # A password typed the same way (no echo per keystroke) stays hidden, and the
    # prompt in the note is CLEAN — the last line only, no carriage returns from
    # the scrollback that once made it "\\r\\n[root@waf01 ~]# …".
    a = kmanage.pty_audit_line()
    a.saw_output("policy version: 33\r\n[sudo] password for ammar: ")
    for ch in "s3cr3t":
        a.typed(ch)                       # a password field does not echo
    a.typed("\r")
    got = a.close()
    check(f"a character-by-character password is hidden with a clean prompt "
          f"({got})",
          len(got) == 1 and "s3cr3t" not in got[0] and "hidden" in got[0]
          and "\\r" not in got[0] and "password for ammar" in got[0])

    got = session([("$ ", "rm -rf /tmp/x\x7fy\r", True)])
    check(f"backspace is applied, not recorded ({got})",
          got == ["rm -rf /tmp/y"])
    got = session([("$ ", "secret-typo\x15ls -l\r", True)])
    check(f"Ctrl+U clears the line rather than logging it ({got})",
          got == ["ls -l"])
    got = session([("$ ", "sleep 99\r", True), ("", "\x03", False)])
    check(f"an interrupt is a thing that happened, so it is logged ({got})",
          got == ["sleep 99", "^C"])
    check("and an empty line is not an audit entry",
          session([("$ ", "\r\r\r", True)]) == [])

    # The echo comes back wrapped in the escape sequences a shell paints with;
    # the line has to be recognised through them.
    a2 = kmanage.pty_audit_line()
    a2.saw_output("\x1b[?2004h$ ")
    a2.typed("uname -a\r")
    a2.saw_output("\x1b[?2004l\runame -a\r\nLinux pod 6.6\r\n")
    check(f"an echo buried in escape sequences still counts ({a2.due()})",
          a2.due() == [] and not a2.waiting)

    print("a terminal that never starts must not look like one that ended")
    # THE BUG THIS PREVENTS, measured on a customer install and not on this
    # machine: the browser closes the terminal window by itself when a shell
    # ENDS, because somebody typed exit. It used to do that on ANY close — so
    # on a cluster whose kubeconfig may not exec, the reason appeared for a
    # fraction of a second and the page navigated away from it. The person
    # reporting it could only say "some error, too fast to read".
    #
    # 4001 is what tells the two apart, so it is worth a test that a refusal
    # really arrives with it.
    from fastapi.testclient import TestClient
    from app import auth, db, main
    email, pw = "shellws@test.local", "Why-Did-It-Close-42"
    uid = (auth.by_email(email) or {}).get("id") or \
        auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    client = TestClient(main.app)
    client.__enter__()
    client.post("/login", data={"email": email, "password": pw},
                follow_redirects=False)
    client.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    from starlette.websockets import WebSocketDisconnect
    said, code = "", None
    try:
        with client.websocket_connect(
                "/clusters/pty.ws?project=nope&cluster=nope"
                "&namespace=default&pod=nope") as ws:
            said = ws.receive_text()
            ws.receive_text()          # the close arrives as the next event
    except WebSocketDisconnect as e:
        code = e.code
    check(f"a terminal that cannot open says why on screen ({said.strip()[:60]!r})",
          "no such cluster" in said)
    check(f"and closes with the code that means it never started ({code})",
          code == 4001)

    print("the cluster is asked why, rather than the reason being guessed")
    # An explanation that might be wrong is worse than none: the message is
    # read by somebody who will act on it against their own cluster.
    real_reach, real_cani = kmanage.reachable, kmanage._can_i
    kmanage.reachable = lambda c: (False, "i/o timeout")
    check("an unreachable cluster is reported as unreachable",
          "cannot reach" in kmanage.why_refused({"id": "x"}, "default"))
    kmanage.reachable = lambda c: (True, "")
    kmanage._can_i = lambda c, v, r, ns="": False
    said = kmanage.why_refused({"id": "x"}, "payments", "exec")
    check(f"a refusal names the namespace and what is missing ({said[:70]!r})",
          "payments" in said and "pods/exec" in said)
    kmanage._can_i = lambda c, v, r, ns="": None
    check("and a question the cluster will not answer produces no guess",
          kmanage.why_refused({"id": "x"}, "default") == "")
    kmanage.reachable, kmanage._can_i = real_reach, real_cani

    print("no module defines the same top-level name twice")
    for path in sorted((ROOT / "app").glob("*.py")):
        seen_at: dict = {}
        for node in ast.parse(path.read_text()).body:
            names = ([node.name] if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                else [])
            for name in names:
                if name in seen_at:
                    check(f"app/{path.name}: {name}() is defined twice — "
                          f"line {seen_at[name]} is dead, line {node.lineno} "
                          f"is what callers get", False)
                seen_at[name] = node.lineno

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
