#!/usr/bin/env python3
"""What the person says in the 3D view reaches the doctor answering over MCP.

WHY THIS EXISTS
    Reported on 20 November 2026: "Claude asks me, then I ask him something in
    the game and he does not answer me, he just carries on or moves to the next
    pod." A doctor connected over MCP heard the person only if it called
    `doctor_listen`, and a model working pod by pod did not. A line typed when
    no visit was under way opened a call that said nothing about the line, so
    the doctor sent for it examined the whole cluster instead of answering.

    What must hold:

      1. A call made by SPEAKING carries the line that made it.
      2. Whatever the person says during a visit comes back in the answer to
         the doctor's very next note, once.
      3. A line the doctor heard by listening is not handed to it again.
      4. A line nobody heard by the time the doctor says goodbye keeps the
         call open, so it is still answered.
      5. A tool the doctor was not given is asked for IN THE VIEW, and the
         person's own answer there is the permission (`doctor_permit`): the
         doctor once sent somebody to "allow it on the machine running me".

    ./.venv/bin/python tests/test_doctor_relay.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("doctor-relay-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import json                                                    # noqa: E402

from fastapi.testclient import TestClient                      # noqa: E402

from app import auth, db, doctor, main, mcp, rbac, scene, store  # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main_test() -> int:
    uid = auth.create_user("walker@test.invalid", "Walker", "Passw0rd!xY-relay", role="user")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", "walk", "", ["clusters", "manage", "config"], [], [])])
    me = auth.by_id(uid)
    pid = store.add_project("Game", icon="x")
    cid = store.add_cluster(pid, "game", "apiVersion: v1\nkind: Config\n", "game")
    scene.collect = lambda c: {"pods": [], "error": ""}       # no cluster is asked anything here

    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": me["email"], "password": "Passw0rd!xY-relay"}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    def say(text, pod=""):
        return c.post("/clusters/3d/doctor.json",
                      data={"project": pid, "cluster": cid, "say": text, "pod": pod}).json()

    def note(text, state="examining", pod=""):
        return mcp.call(me, "doctor_note", {"cluster": cid, "text": text, "state": state, "pod": pod,
                                            "who": "Claude Code (CLI)"})

    def handed(res):
        return [h["text"] for h in (res.get("structuredContent") or {}).get("said_to_you") or []]

    print("speaking with no visit under way")
    first = say("what is this pod used for?", "security/falco-sidekick-1")
    check("the line is kept", first.get("ok") and first["note"]["text"] == "what is this pod used for?")
    open_now = doctor.calls(cid)
    check("it opens a call that carries the line and the pod it was said about",
          len(open_now) == 1 and open_now[0].get("said") == {"n": first["note"]["n"], "text": "what is this pod used for?"}
          and open_now[0]["pod"] == "security/falco-sidekick-1")
    listed = mcp.call(me, "doctor_calls", {})["structuredContent"]["waiting"]
    check("doctor_calls hands that call over with the line, and the conversation so far",
          listed and listed[0]["calls"][0].get("said", {}).get("text") == "what is this pod used for?"
          and [r["text"] for r in listed[0]["conversation"]] == ["what is this pod used for?"])

    print("during the visit")
    got = note("I am here.", "arrived", "security/falco-sidekick-1")
    check("the line the call carried is not handed over a second time", handed(got) == [])
    say("and the one next to it?")
    check("speaking while a call is open opens no second call", len(doctor.calls(cid)) == 1)
    got = note("Asking the pod.", "asking", "security/falco-sidekick-1")
    text = got["content"][0]["text"]
    check("the doctor's next note brings back what was said meanwhile, and says to answer it now",
          handed(got) == ["and the one next to it?"] and "MEANWHILE" in text and "and the one next to it?" in text
          and "before your next step" in text)
    check("once", handed(note("It forwards Falco alerts.", pod="security/falco-sidekick-1")) == [])

    print("listening")
    said = say("thanks, anything else wrong?")
    heard = mcp.call(me, "doctor_listen", {"cluster": cid, "after": said["note"]["n"] - 1, "wait": 0})
    check("doctor_listen hears it", [h["text"] for h in heard["structuredContent"]["said"]] == ["thanks, anything else wrong?"])
    check("and a line heard by listening is not handed over again", handed(note("Nothing else is wrong.")) == [])

    print("saying goodbye")
    say("wait, one more question")
    bye = note("Visit over.", "done")
    check("a line nobody heard comes back with the goodbye, and the doctor is told to answer it",
          handed(bye) == ["wait, one more question"] and "say `done` again" in bye["content"][0]["text"])
    again = doctor.calls(cid)
    check("and its call stays open, carrying the line, for whoever answers next",
          len(again) == 1 and again[0].get("said", {}).get("text") == "wait, one more question")
    note("It was a good question.")
    last = note("Visit over.", "done")
    check("answered, the next goodbye closes it and hands nothing", handed(last) == [] and doctor.calls(cid) == [])

    print("a goodbye")
    # Reported on 21 November 2026: "I told him bye, but he is stuck here with
    # me." The doctor had left; "okay bye i will call you" was a line with no
    # visit under way, so it opened a call and brought the doctor back.
    check("a goodbye, a thank-you or an ok is recognised, in more than one language",
          all(doctor.farewell(t) for t in (
              "okay bye i will call you", "it okay just leave it for now", "Thanks!", "bye claude, see you later",
              "I’ll call you back when I need you", "ok", "great, thanks. that's all for now",
              "شكرا يا دكتور", "مع السلامة", "gracias, hasta luego", "asante sana")))
    check("and a line that asks for anything is not, whatever it starts or ends with",
          not any(doctor.farewell(t) for t in (
              "thanks, now restart it", "ok call claude back", "ok fix rampart", "bye?", "ok go there",
              "yes", "Yes, do it", "ok sync it", "thanks but check the database", "will call you to restart it",
              "restart rampart", "", "ok " * 20)))
    answered = say("okay bye i will call you")
    check("said to a doctor that has just left, it is kept and shown, and it calls nobody back",
          answered.get("ok") and answered.get("parting") is True and doctor.calls(cid) == []
          and doctor.feed(cid)["notes"][-1]["text"] == "okay bye i will call you")
    asking = say("thanks, now restart it")
    check("a request said the same moment still calls", not asking.get("parting") and len(doctor.calls(cid)) == 1)
    note("Restarting it.", "treating")
    say("ok thanks bye")
    bye = note("Done. Bye!", "done")
    check("a goodbye said as the doctor leaves is not a line left unanswered: the visit ends there",
          handed(bye) == [] and doctor.calls(cid) == [] and "nothing more is owed" in bye["content"][0]["text"])
    stale = [n for n in doctor._notes[cid] if n["voice"] == "doctor"][-1]
    stale["at"] -= doctor.PARTING_WINDOW + 1
    later = say("ok thanks")
    check("long after the doctor left, the same words are somebody speaking to a doctor, and bring one",
          not later.get("parting") and len(doctor.calls(cid)) == 1)
    note("You are welcome.", "done")
    told = next(t["description"] for t in mcp.tools(me) if t["name"] == "doctor_note")
    check("every MCP doctor is told that goodbye means go", "GOODBYE MEANS GO" in told and "say `done` at once" in told.replace("\n", " "))

    print("permission, asked in the view")
    mcp.save_config(enabled=True, allow_actions=True, row_limit=50, token_days=1)
    mcp.PERMIT_WAIT = 1.5

    def permit(tool, given=None, answers=()):
        """Ask for a tool while somebody says `answers` in the view, a moment later."""
        before = len(doctor.feed(cid)["notes"])
        def speak():
            time.sleep(0.3)
            for who, text in answers:
                doctor.tell(cid, who, text)
        t = threading.Thread(target=speak, daemon=True); t.start()
        got = mcp.call(me, "doctor_permit", {"tool_name": tool, "input": given or {}})
        t.join()
        shape.append(set(got) == {"content"} and len(got["content"]) == 1 and got["content"][0]["type"] == "text")
        asked = [n for n in doctor.feed(cid)["notes"][before:] if n["state"] == "asking" and n["voice"] == "doctor"]
        return json.loads(got["content"][0]["text"]), asked

    shape = []
    mcp._doctor_at.clear()
    doc, asked = permit("mcp__envmap__config_pull")
    check("with no doctor in any view there is nobody to ask, and it says so",
          doc["behavior"] == "deny" and "doctor_note first" in doc["message"] and not asked)
    note("Looking at the repository.")
    doc, asked = permit("mcp__envmap__config_pull", {"project": "Game", "env": "dev"}, [(me["email"], "Yes, allow")])
    check("a tool the doctor was not given is asked for in the view, in the doctor's own name, with what it was given",
          doc == {"behavior": "allow", "updatedInput": {"project": "Game", "env": "dev"}} and len(asked) == 1
          and asked[0]["who"] == "Claude Code (CLI)" and "May I use config_pull" in asked[0]["text"]
          and "project: Game" in asked[0]["text"] and asked[0]["choices"] == ["Yes, allow", "No"])
    doc, asked = permit("mcp__envmap__config_pull")
    check("a yes to a tool that only reads lasts the visit: it is not asked twice", doc["behavior"] == "allow" and not asked)
    doc, asked = permit("mcp__envmap__cluster_action", {"action": "restart", "cluster": cid}, [(me["email"], "Yes, allow")])
    again, asked2 = permit("mcp__envmap__cluster_action", {"action": "restart", "cluster": cid}, [(me["email"], "No")])
    check("a tool that changes something is asked about every time, and a no is a no",
          doc["behavior"] == "allow" and len(asked) == 1 and "changes something" in asked[0]["text"]
          and again["behavior"] == "deny" and len(asked2) == 1 and "not a yes" in again["message"])
    doc, asked = permit("mcp__envmap__config_set", {}, [("somebody@else.invalid", "Yes, allow")])
    check("somebody else's yes allows nothing, and silence is a no",
          doc["behavior"] == "deny" and "nobody answered" in doc["message"])
    doc, asked = permit("Bash", {"command": "rm -rf /"}, [(me["email"], "Yes, allow")])
    other, asked2 = permit("mcp__other__config_wipe", {}, [(me["email"], "Yes, allow")])
    check("only the portal's own tools can be allowed from the view: anything else is refused unasked",
          doc["behavior"] == "deny" and not asked and other["behavior"] == "deny" and not asked2)
    # Claude Code takes the answer only as ONE text block of JSON: with a
    # structured copy beside it, it called the whole answer invalid.
    check("every answer is one text block and nothing else, the only shape the client accepts", len(shape) >= 7 and all(shape))
    trail = [(a["action"], a["detail"]) for a in auth.read_audit(limit=40) if a["action"] == "doctor_permit"]
    check("every permission asked is in the audit log, allowed or not",
          any("allowed in the 3D view" in d for _a, d in trail) and any(d.startswith("refused") for _a, d in trail)
          and any(d == "no answer" for _a, d in trail))

    src = (pathlib.Path(__file__).resolve().parent.parent / "app" / "mcp.py").read_text()
    check("the doctor_note tool tells every MCP doctor that its answers carry what the person said",
          "THE PERSON CAN TALK TO YOU AT ANY MOMENT" in src)

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main_test())
