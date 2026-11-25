"""The assistant, as something that can look twice before answering.

WHY THIS EXISTS
    The assistant could run exactly one query per question. It matched the
    question to a name in the catalogue, ran it, and narrated the rows. That is
    a lookup with prose on top, and it fails at the question people actually
    ask, which is never "list the pods" — it is "why is this thing broken".

    Answering that needs more than one look: find the unhealthy pod, then read
    the events for its namespace, then check whether the GitOps application that
    owns it is out of sync. Each step depends on what the last one said, so no
    amount of picking a better single query gets there.

    So the model is given the catalogue as a tool and allowed to call it until
    it has enough, then answer. That is the whole difference, and it is the
    difference between a search box and something worth calling an assistant.

WHAT BOUNDS IT
    A loop that calls a cluster is a loop that can cost somebody real time and
    real API-server load, so it is bounded on three axes rather than trusted:

      * STEPS — how many times it may look before it must answer
      * SECONDS — a wall clock, because six fast reads and six slow ones are
        very different things to sit through
      * ABANDONMENT — the caller may hand in a stop flag, checked before every
        model call and every read. A person who closes the rail or types a new
        question has stopped caring about the old answer, and without this the
        thread kept going: up to six more model calls and six more cluster reads
        for nobody, at the API server's expense
      * the ROLE — every read goes through aitools, which applies the same rbac
        areas the pages do. A model asking for something the person may not see
        is refused in the same sentence they would get, and the refusal is fed
        back so it can try something else rather than dying

    When a bound is hit the model is told, and asked to answer with what it has.
    A truncated answer that says so beats a loop that never ends.

WHAT IT MAY DO
    Read, and PROPOSE. Nothing here executes: `propose_action` returns the same
    validated preview the rail renders as a card, and running it stays a thing a
    person clicks. See app/aitools.py for why those are separate functions.

WHY EVERY RESULT IS SCRUBBED
    Tool results go back to the model as text, which makes them a second path
    for a credential to leave. The briefing has always gone through
    `_no_secrets`; so does everything a tool returns, for the same reason and
    with the same refusal to redact quietly — a result that has to be censored
    is a bug in the query, not a request to serve.
"""
from __future__ import annotations

import json
import time

class Abandoned(Exception):
    """Raised when the loop is stopped because nobody is listening."""


STEPS = 6              # looks before it must answer
SECONDS = 55.0         # wall clock for the whole exchange
ROWS_BACK = 40         # rows of a result handed to the model
CHARS_BACK = 6000      # and a hard cap on the text of one result


def read_tool(user) -> dict:
    """One tool with the catalogue as an enum, rather than twenty-two tools.

    A small model handed twenty-two tool definitions spends its context on the
    definitions and picks badly; handed one tool and a list of names, it picks
    well. It is also the shape that survives a new query being added — the enum
    is generated, so nothing here has to be edited.
    """
    from . import aitools
    caps = aitools.read_tools(user)
    return {
        "name": "read",
        "description": (
            "Read live state from the portal. Returns real rows from the "
            "estate, never a guess. Call it more than once when one look is "
            "not enough: find the failing thing, then read what explains it."),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "enum": [c["name"] for c in caps],
                          "description": "\n".join(
                              f"{c['name']}: {c['help']}" for c in caps)},
                "about": {"type": "string", "description":
                          "Optional. Words narrowing it — a cluster name, a "
                          "namespace, a service, or a state like unhealthy."},
            },
            "required": ["query"],
        },
    }


def action_tool() -> dict:
    return {
        "name": "propose_action",
        "description": (
            "Offer the person a cluster action to run. This does NOT run it — "
            "it returns a preview they must confirm. Propose only when asked to "
            "change something, or when a specific fault plainly calls for it."),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "project": {"type": "string", "description": "project id"},
                "cluster": {"type": "string", "description": "cluster id"},
                "kind": {"type": "string"},
                "namespace": {"type": "string"},
                "name": {"type": "string"},
                "replicas": {"type": "string"},
            },
            "required": ["action", "project", "cluster"],
        },
    }


def tools_for(user) -> list:
    from . import aitools, rbac
    out = [read_tool(user)]
    if rbac.may_area(user, "manage") and any(
            c["manageable"] for c in aitools.clusters_for(user)):
        out.append(action_tool())
    return out


def _shrink(result: dict) -> str:
    """A tool result the model can afford to read.

    Forty rows and six thousand characters: enough to reason over, small enough
    that six of them do not fill the window before the answer is written. The
    count is always the real one, so the model can say "of 300" rather than
    believing it saw everything.
    """
    rows = result.get("rows") or []
    doc = {
        "query": result.get("query", ""),
        "matched": result.get("count", len(rows)),
        "showing": min(len(rows), ROWS_BACK),
        "columns": result.get("columns") or [],
        "rows": rows[:ROWS_BACK],
    }
    if result.get("note"):
        doc["note"] = result["note"]
    text = json.dumps(doc, default=str)
    if len(text) > CHARS_BACK:
        doc["rows"] = rows[:max(1, ROWS_BACK // 4)]
        doc["truncated"] = "fewer rows shown; ask more narrowly"
        text = json.dumps(doc, default=str)[:CHARS_BACK]
    return text


def _plan(user, args: dict) -> dict:
    """The validated preview for a propose_action call."""
    from . import aitools
    return aitools.propose(
        user, str(args.get("project", "")), str(args.get("cluster", "")),
        str(args.get("action", "")),
        {k: args.get(k, "") for k in ("kind", "namespace", "name", "replicas")})


def _proposal_result(plan: dict) -> str:
    """What the model is told about a plan it offered."""
    return json.dumps({"proposed": plan["command"],
                       "destructive": plan["destructive"],
                       "needs_confirmation": bool(plan["prod"]),
                       "note": "shown to the person as a card; they decide "
                               "whether to run it"})


def call_tool(user, name: str, args: dict, watch=None) -> str:
    """Run one tool call as this person. Never raises — a refusal is an answer
    the model can act on, and killing the loop over one bad call wastes the
    work already done."""
    from . import aitools, assistant
    try:
        if name == "read":
            got = aitools.run_read(user, str(args.get("query", "")),
                                   str(args.get("about", "")))
            # Same net as the briefing: a tool result is text going to a model.
            return assistant._no_secrets(_shrink(got), user, watch)
        if name == "propose_action":
            return _proposal_result(_plan(user, args))
        return f"no such tool: {name}"
    except aitools.Denied as e:
        return f"refused: {e}"
    except Exception as e:                                     # noqa: BLE001
        return f"that read failed: {str(e)[:200]}"


def run(user, turns: list, on_step=None, stop=None) -> dict:
    """Answer, looking as many times as it needs within the bounds.

    Returns {answer, steps, proposals}. `on_step` is called with a short
    sentence per look so a UI can narrate rather than showing a spinner for
    forty seconds — waiting is tolerable when it says what it is waiting for.

    `stop` is an Event the caller sets when nobody is listening any more; the
    loop raises Abandoned at the next boundary rather than finishing work whose
    result has nowhere to go.
    """
    def quit_if_abandoned():
        if stop is not None and stop.is_set():
            raise Abandoned("nobody is waiting for this any more")

    from . import aitools, assistant
    cfg = assistant.config_for(user)
    if cfg.get("provider") != "anthropic":
        # Tool use here is written against Anthropic's protocol. Everything else
        # keeps the single-query path, which still works — this is an upgrade
        # for the provider that can take it, not a new requirement.
        raise assistant.AiError("step-by-step answering needs an Anthropic "
                                "model; other providers still answer directly")
    # Built once for the whole exchange: the briefing and every tool result
    # are checked against the same inventory, and it cannot change mid-question.
    watch = assistant.secret_watch(user)
    system = assistant._no_secrets(assistant.briefing(user), user, watch)
    tools = tools_for(user)
    msgs = [{"role": t["role"], "content": t["text"]} for t in turns]
    base = (cfg["base_url"] or "https://api.anthropic.com").rstrip("/")
    head = {"x-api-key": cfg["token"], "anthropic-version": "2023-06-01"}
    started, steps, proposals = time.monotonic(), 0, []

    while True:
        quit_if_abandoned()
        out_of_time = time.monotonic() - started > SECONDS
        last = steps >= STEPS or out_of_time
        body = {"model": cfg["model"], "max_tokens": 1600, "system": system,
                "messages": msgs}
        if not last:
            body["tools"] = tools
        else:
            # Say why it must stop. Without this the model simply loses its
            # tools mid-conversation, which reads to it as a malfunction and
            # produces an apology instead of an answer.
            body["system"] = system + (
                "\n\nYou have used your look-ups for this question"
                f"{' and the time budget' if out_of_time else ''}. Answer now "
                "with what you have, and say plainly what you could not check.")
        doc = assistant._post(f"{base}/v1/messages", head, body,
                              cfg["skip_tls"])
        blocks = doc.get("content") or []
        calls = [b for b in blocks if b.get("type") == "tool_use"]
        if not calls:
            text = "\n".join(b.get("text", "") for b in blocks
                             if b.get("type") == "text").strip()
            return {"answer": text or "(no answer returned)",
                    "steps": steps, "proposals": proposals}

        msgs.append({"role": "assistant", "content": blocks})
        results = []
        for call in calls:
            quit_if_abandoned()
            args = call.get("input") or {}
            if on_step:
                on_step(_narrate(call.get("name", ""), args))
            if call.get("name") == "propose_action":
                # Validated once, then used twice: kept in `proposals` so the
                # rail can draw the card from the same ids the model used rather
                # than parsing them back out of prose, and reported to the model
                # as the tool result. Each was built separately before, so every
                # proposal ran the four permission checks and the cluster lookup
                # twice — and left room for the card and the answer to describe
                # different commands. A refusal now reaches the model too;
                # swallowing it meant the model proposed something it was not
                # allowed to propose and was never told.
                try:
                    plan = _plan(user, args)
                    proposals.append(plan)
                    said = _proposal_result(plan)
                except aitools.Denied as e:
                    said = f"refused: {e}"
                except Exception as e:                        # noqa: BLE001
                    said = f"that proposal failed: {str(e)[:200]}"
            else:
                said = call_tool(user, call.get("name", ""), args, watch)
            results.append({"type": "tool_result",
                            "tool_use_id": call.get("id", ""),
                            "content": said})
        msgs.append({"role": "user", "content": results})
        steps += 1


def _narrate(name: str, args: dict) -> str:
    """What to show a person while they wait. Their words, not the protocol's."""
    if name == "read":
        about = str(args.get("about", "")).strip()
        return f"reading {args.get('query', 'live state')}" + (
            f" — {about}" if about else "")
    if name == "propose_action":
        return f"preparing {args.get('action', 'an action')} for review"
    return f"running {name}"
