"""The 3D view's doctor: a call for help raised from inside the picture, and
what whoever answers it says while they work.

WHAT THIS IS, AND WHAT IT IS NOT
    Somebody walking through a cluster in the 3D view can call for help with
    its unhealthy pods. An MCP client (a model the person has connected to this
    portal) reads the open calls, examines and treats the pods with the tools
    it already has, and says what it is doing; the view draws that as a doctor
    standing beside the pod it is working on.

    The visit is a CONVERSATION, because that is what an examination is: the
    doctor asks the pod what is wrong (`asking`), and the pod answers. A note
    carries a voice, `doctor` or `pod`. The pod's lines are written by the same
    client, in the pod's first person, from what the pod's own status, events
    and log say: the view draws them as the pod speaking, and where the client
    sends none the view has the pod answer from its own row.

    The person can speak too (`tell`): a line typed in the view, which the
    client hears with `heard` or by waiting on `listen`. It is kept with the
    name of whoever typed it, because a view can be open to several people and
    "yes, do it" is agreement only from the person the client is working for.

    Nothing here acts on a cluster. A call is a line of text and a note is a
    line of text. Examining and treating go through the MCP server's existing
    tools, with their existing permissions, their existing "say what you are
    about to do and get the person's agreement" and their existing audit lines.
    A call for help is not agreement to a particular change, and the tool that
    hands the calls over says so.

WHY IT IS HELD IN MEMORY
    It is the state of a game somebody is playing right now: a call nobody
    answered within two hours is not a record worth a table, and a note is
    already in the audit log as the action it describes. A restart of the
    portal ends the round, which is the right size for what this is.
"""
import re
import threading
import time

KEEP = 2 * 3600          # a call nobody answered is forgotten after this
MAX_NOTES = 80            # per cluster
MAX_TEXT = 240
MAX_ASK = 600             # a question may carry the whole change it asks about
MAX_CHOICES, MAX_CHOICE = 4, 48
STATES = ("arrived", "asking", "examining", "treating", "healed", "failed", "done")
VOICES = ("doctor", "pod")          # what a client may speak as; "person" is only ever a person
LISTEN_MAX = 20                     # seconds one `listen` may hold a worker thread

_guard = threading.Lock()
_spoke = threading.Condition(_guard)      # woken when a person says something
_calls: dict = {}         # cid -> [{id, by, pod, problem, at, open}]
_notes: dict = {}         # cid -> [{n, who, pod, text, state, at}]
_watched: dict = {}       # cid -> when a view last asked for the feed
_relayed: dict = {}       # cid -> the last line of a person's already handed to a doctor
_seq = 0


def _clean(text, limit=MAX_TEXT) -> str:
    """One line a person can read: no control characters, and not a page."""
    return "".join(ch for ch in str(text or "") if ch.isprintable()).strip()[:limit]


def _next() -> int:
    global _seq
    _seq += 1
    return _seq


def call(cid: str, by: str, pod: str = "", problem: str = "", said: dict | None = None) -> dict:
    """Somebody asks for help on this cluster, about one pod or about all of it.

    `said` is the line that made the call when somebody called by SPEAKING: the
    call carries it to whoever answers, so the visit starts by answering it
    rather than by examining the cluster as if nobody had said anything."""
    with _guard:
        row = {"id": _next(), "by": _clean(by, 120), "pod": _clean(pod, 200),
               "problem": _clean(problem, 120), "at": int(time.time()), "open": True}
        if said:
            row["said"] = {"n": int(said["n"]), "text": _clean(said["text"])}
            _relayed[cid] = max(_relayed.get(cid, 0), row["said"]["n"])
        mine = [c for c in _calls.get(cid, []) if time.time() - c["at"] < KEEP]
        # asking twice about the same pod is one call, asked again
        mine = [c for c in mine if not (c["open"] and c["pod"] == row["pod"])]
        _calls[cid] = (mine + [row])[-40:]
        return dict(row)


def calls(cid: str) -> list:
    """The calls still waiting on this cluster, oldest first."""
    with _guard:
        return [dict(c) for c in _calls.get(cid, [])
                if c["open"] and time.time() - c["at"] < KEEP]


def waiting() -> list:
    """Every cluster somebody is waiting on."""
    with _guard:
        return [cid for cid, rows in _calls.items()
                if any(c["open"] and time.time() - c["at"] < KEEP for c in rows)]


def note(cid: str, who: str, text: str, pod: str = "", state: str = "",
         voice: str = "doctor", choices=None) -> dict:
    """Whoever answered says what they are doing, or says what the pod they are
    examining told them, in that pod's voice. `healed`, `failed` and `done`
    close the call about that pod; `done` with no pod closes every call here.

    A line in the pod's voice is the pod's, so it carries no state of the
    doctor's and closes nothing: a pod saying "I feel better" is not the
    cluster saying so.

    `asking` with no pod is a question put to the PERSON in the view, who
    answers it there. `choices` are answers they may pick with one key; they
    are kept only on such a question, and they are words like every other
    line: picking one is the person saying it, nothing more."""
    voice = voice if voice in VOICES else "doctor"
    if voice == "pod" and not _clean(pod, 200):
        raise ValueError("a line in a pod's voice has to name the pod speaking")
    state = "" if voice == "pod" else state if state in STATES else "examining"
    with _guard:
        row = {"n": _next(), "who": _clean(who, 60) or "The doctor", "pod": _clean(pod, 200),
               "text": _clean(text, MAX_ASK if state == "asking" else MAX_TEXT),
               "state": state, "voice": voice, "at": int(time.time())}
        if state == "asking" and not row["pod"] and isinstance(choices, (list, tuple)):
            row["choices"] = [c for c in (_clean(c, MAX_CHOICE) for c in choices[:MAX_CHOICES]) if c]
        _notes[cid] = (_notes.get(cid, []) + [row])[-MAX_NOTES:]
        if state in ("healed", "failed", "done"):
            for c in _calls.get(cid, []):
                if c["pod"] == row["pod"] or (state == "done" and not row["pod"]):
                    c["open"] = False
        return dict(row)


def close(cid: str, ids) -> None:
    """These calls are over, with nothing said. For a doctor that went without
    saying goodbye: a `done` note would close EVERY call here, the one somebody
    has just made for the next visit included."""
    with _guard:
        for c in _calls.get(cid, []):
            if c["id"] in ids:
                c["open"] = False


def tell(cid: str, by: str, text: str, pod: str = "") -> dict:
    """The person in the view says something to whoever is being the doctor."""
    text = _clean(text)
    if not text:
        raise ValueError("there is nothing to say")
    with _spoke:
        row = {"n": _next(), "who": _clean(by, 120), "pod": _clean(pod, 200),
               "text": text, "state": "", "voice": "person", "at": int(time.time())}
        _notes[cid] = (_notes.get(cid, []) + [row])[-MAX_NOTES:]
        _spoke.notify_all()
        return dict(row)


def heard(cid: str, after: int = 0) -> list:
    """What people have said to the doctor on this cluster since `after`."""
    with _guard:
        return [dict(n) for n in _notes.get(cid, [])
                if n["voice"] == "person" and n["n"] > after
                and time.time() - n["at"] < KEEP]


def listen(cid: str, after: int = 0, wait: float = LISTEN_MAX) -> list:
    """Wait, at most `wait` seconds, for somebody to say something new.

    Bounded, and short: the caller is an MCP request sitting on a worker
    thread, and a wait with no ceiling is a thread the portal never gets back."""
    until = time.time() + max(0.0, min(float(wait), LISTEN_MAX))
    with _spoke:
        while True:
            got = [dict(n) for n in _notes.get(cid, [])
                   if n["voice"] == "person" and n["n"] > after]
            left = until - time.time()
            if got or left <= 0:
                return got
            _spoke.wait(left)


def relay(cid: str) -> list:
    """The lines people have said that no doctor has been handed yet; from now
    on they have been.

    A doctor working through a cluster pod by pod does not stop to listen
    between steps, and a model told to was found not to: a person asked a
    question and the doctor walked on to the next pod. So whoever is being the
    doctor is HANDED every new line in the answer to its very next note (the
    MCP server does that with this), and a line nobody was handed by the time
    the doctor says goodbye is still waiting for an answer."""
    with _guard:
        mark = _relayed.get(cid, 0)
        got = [dict(n) for n in _notes.get(cid, [])
               if n["voice"] == "person" and n["n"] > mark and time.time() - n["at"] < KEEP]
        if got:
            _relayed[cid] = got[-1]["n"]
        return got


# ── a goodbye is not a call ────────────────────────────────────
# Reported on 21 November 2026: "I told him bye, but he is stuck here with me."
# The doctor had said goodbye and left; the person answered "okay bye i will
# call you"; speaking is calling, so that line opened a call and brought the
# doctor straight back, to stand beside them for another four minutes.
#
# A line counts as a goodbye only when EVERY word of it is one of these and at
# least one is a parting word, so "thanks, now restart it" is still a request:
# the one direction this may not be wrong in is swallowing something they
# asked for. A goodbye this misses still brings the doctor, which is told to
# answer it in one line and go.
PARTING_WINDOW = 300      # seconds after the doctor's goodbye in which an answering goodbye is just that
_PARTING = set("""bye goodbye byebye cya ciao later thanks thank thx ty cheers ok okay okey kk
    alright fine great good nice cool perfect done noted understood
    adios chao gracias vale listo hasta luego
    kwaheri asante sawa
    باي وداعا سلام السلامة شكرا شكراً تمام ماشي اوك اوكي أوكي يسلمو تسلم""".split())
_FILLER = set("""i you u ya it its it's that thats that's all for now then so and a the very
    much lot lots see talk soon again take care day night one my friend doctor doc claude
    mate man no problem np got just leave be
    muchas de nada mucho
    sana
    مع الى إلى اللقاء جزيلا يا دكتور الله يعطيك العافية خلص""".split())
_WORDS = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)?")
# "I will call you" is part of a goodbye; "call" anywhere else is somebody
# asking for the doctor, so the phrase is recognised whole (and read as "bye")
# and the word is not.
_CALL_YOU = re.compile(r"\b(?:i\s+will|i'll|ill|will)\s+(?:call|ping)\s+(?:you|u)(?:\s+back)?"
                       r"(?:\s+(?:later|again|soon))?"
                       r"(?:\s+(?:when|if)\s+i\s+need\s+(?:you|u|something|anything|help))?")


def farewell(text: str) -> bool:
    """Whether this line is a goodbye, a thank-you or an "ok" and nothing else."""
    text = str(text or "")
    words = _WORDS.findall(_CALL_YOU.sub(" bye ", text.lower().replace("’", "'")))
    return (0 < len(words) <= 12 and "?" not in text and "؟" not in text
            and any(w in _PARTING for w in words)
            and all(w in _PARTING or w in _FILLER for w in words))


def parting(cid: str, text: str) -> bool:
    """Whether `text` is only an answer to a goodbye the doctor has just said:
    its last word here was `done`, moments ago, and this line is a farewell.
    Such a line is kept and shown like any other, and calls nobody back."""
    with _guard:
        mine = [n for n in _notes.get(cid, []) if n["voice"] == "doctor"]
        gone = bool(mine) and mine[-1]["state"] == "done" and not mine[-1]["pod"] \
            and time.time() - mine[-1]["at"] < PARTING_WINDOW
    return gone and farewell(text)


def relayed(cid: str, upto: int) -> None:
    """A doctor has heard every line up to `upto` some other way (listening)."""
    with _guard:
        _relayed[cid] = max(_relayed.get(cid, 0), int(upto))


def recent(cid: str, limit: int = 16, within: int = 1800) -> list:
    """The conversation lately on this cluster, every voice, oldest first: what
    a doctor arriving now needs to carry on from it rather than start over."""
    with _guard:
        now = time.time()
        return [{k: n[k] for k in ("n", "who", "voice", "pod", "text", "state")}
                for n in _notes.get(cid, []) if now - n["at"] < within][-limit:]


def mark() -> int:
    """The number of the last line said anywhere: everything said from now on
    is after it."""
    with _guard:
        return _seq


def spoken(cid: str, after: int = 0) -> list:
    """What the doctor and the pods have said here since `after`. Unlike
    `feed`, asking this is not somebody watching."""
    with _guard:
        return [dict(n) for n in _notes.get(cid, [])
                if n["voice"] != "person" and n["n"] > after]


def feed(cid: str, since: int = 0) -> dict:
    """What the view draws: the calls still open, and every note after `since`.
    Asking is also how a doctor knows somebody is still there to watch."""
    with _guard:
        _watched[cid] = time.time()
        fresh = [dict(n) for n in _notes.get(cid, [])
                 if n["n"] > since and time.time() - n["at"] < KEEP]
        last = max([n["n"] for n in _notes.get(cid, [])] or [since])
    return {"calls": calls(cid), "notes": fresh, "last": last}


def watching(cid: str) -> None:
    """Somebody is looking at this cluster now (they just called or spoke)."""
    with _guard:
        _watched[cid] = time.time()


def watched(cid: str) -> float:
    """When a 3D view of this cluster last asked what the doctor is saying."""
    with _guard:
        return _watched.get(cid, 0.0)


def forget() -> None:
    with _guard:
        _calls.clear()
        _notes.clear()
        _watched.clear()
        _relayed.clear()
