"""The assistant: an LLM that is told, fresh on every question, what this portal knows.

HOW IT "LEARNS" WITHOUT TRAINING
    Nothing is trained, indexed or embedded — and that is the point. Every
    question assembles a briefing from the live database and the caches the
    pages already fill: projects, regions, environments, clusters and their
    reachability, services, connections of every kind, inventory totals, the
    recent audit trail. So a cluster added a minute ago is known a minute later,
    a deleted one stops being mentioned immediately, and there is no stale index
    to rebuild or explain. The portal's own state *is* the knowledge base.

    That also bounds the failure mode: the assistant can be wrong about
    reasoning, but it cannot be confidently out of date about your estate.

WHAT IT IS ALLOWED TO SEE
    The briefing is built through the same permission checks as the pages, from
    the signed-in user's roles: someone whose roles cover only Logs and Kenya
    gets a briefing describing only that. An assistant that leaks what the UI
    hides would be a hole straight through the RBAC work.

    Credentials are never included. Tokens, passwords, kubeconfigs and sealing
    keys are filtered by construction — the briefing builder reads named fields,
    never whole connection rows — and SECRET_FIELDS is a second net under that.

WHICH MODEL
    Whatever the deployment configures: Anthropic, any OpenAI-compatible
    endpoint (OpenAI, Azure OpenAI, Groq, vLLM, LiteLLM…), or a local Ollama.
    The key is entered in Settings and stored like any other credential; nothing
    is hardcoded and no default provider is assumed, because the portal must not
    quietly send an estate description to a vendor nobody chose.

WHAT IT WILL NOT DO
    It answers and explains; it does not act. No tool calls, no kubectl, no
    commits. The portal already has audited paths for changing things, and an
    LLM with a write path is a second unaudited one. If someone wants that
    later, it belongs behind the same "allow management" tick and the same audit
    line as the console — not bolted onto a chat box.
"""
import json
import ssl

from . import urlguard
import urllib.error
import urllib.request

TIMEOUT = 60
HISTORY = 8            # turns of context sent back; enough to follow up

# Never sent to a model, whatever asks for them.
SECRET_FIELDS = ("token", "secret", "password", "client_secret", "kubeconfig",
                 "kubeconfig_file", "sealing_cert", "totp_secret", "key_id")

PROVIDERS = {
    "anthropic": {
        "label": "Anthropic",
        "icon": "🅰️",
        "url_hint": "https://api.anthropic.com",
        "model_hint": "claude-sonnet-4-5",
        "needs": ["token"],
        "note": "An API key from console.anthropic.com. The portal sends the "
                "briefing as a system prompt and your question as the message.",
    },
    "openai": {
        "label": "OpenAI-compatible",
        "icon": "🤖",
        "url_hint": "https://api.openai.com  ·  or your own gateway",
        "model_hint": "gpt-4o-mini",
        "needs": ["token"],
        "note": "Anything speaking the /v1/chat/completions API: OpenAI, Azure "
                "OpenAI, Groq, Together, vLLM, LiteLLM. Point the URL at your "
                "gateway to keep traffic inside your own network.",
    },
    "ollama": {
        "label": "Ollama (local)",
        "icon": "🦙",
        "url_hint": "http://localhost:11434",
        "model_hint": "llama3.1",
        "needs": ["base_url"],
        "note": "A model running on your own hardware — nothing leaves the "
                "network, and no API key is needed. The slowest option, and the "
                "only one where the estate description never goes to a vendor.",
    },
}


class AiError(Exception):
    pass


_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def config() -> dict:
    """The effective configuration: what an administrator saved, falling back to
    what the deployment supplied.

    The chart installs an Ollama next to the portal and passes its address here,
    so the assistant works on a fresh install with nobody configuring anything.
    A saved setting always wins — including a saved *disable* — so a chart
    upgrade cannot overwrite a deliberate choice, and moving to a hosted model
    later needs no chart change.
    """
    from . import env, store
    c = store._setting("assistant")
    saved = bool(c)          # has anyone touched this in the UI at all?
    return {
        "enabled": bool(c.get("enabled")) if saved else env.ASSISTANT_ENABLED,
        "provider": (c.get("provider") or "").strip() or env.ASSISTANT_PROVIDER,
        "base_url": (c.get("base_url") or "").strip() or env.ASSISTANT_URL,
        "model": (c.get("model") or "").strip() or env.ASSISTANT_MODEL,
        "token": c.get("token") or "",
        "skip_tls": bool(c.get("skip_tls")),
        # shown on the settings page so "why is this already on?" has an answer
        "from_deployment": not saved and bool(env.ASSISTANT_PROVIDER),
    }


def config_for(user: dict | None) -> dict:
    """The configuration THIS person's questions should use.

    Their own connected account when they have one, the deployment's otherwise.
    Layered rather than replaced: somebody who connects a key but names no model
    still gets a working assistant, and an install where nobody connects
    anything behaves exactly as it did before this existed.
    """
    from . import aiuser
    base = config()
    mine = aiuser.get((user or {}).get("id", "")) if user else {}
    if not (mine and mine.get("provider") and mine.get("token")):
        return base
    return {**base, "enabled": True, "provider": mine["provider"],
            "base_url": mine.get("base_url") or base["base_url"],
            "model": mine.get("model") or base["model"],
            "token": mine["token"], "skip_tls": bool(mine.get("skip_tls")),
            "from_deployment": False, "personal": True}


def save(**fields) -> None:
    from . import store
    keep = config()
    if not (fields.get("token") or "").strip():
        fields["token"] = keep["token"]
    store._set_setting("assistant", {**keep, **fields})


def usable(c: dict) -> bool:
    """Whether this configuration can answer at all.

    Split from ready() for the callers that already hold a config: config_for()
    reads the sealed per-user account table, and asking "is it ready" straight
    after building it read and decrypted the same row twice.
    """
    if not (c["enabled"] and c["provider"] in PROVIDERS and c["model"]):
        return False
    return all(c.get(k) for k in PROVIDERS[c["provider"]]["needs"])


def ready(user: dict | None = None) -> bool:
    """Whether a question from this person can be answered at all."""
    return usable(config_for(user) if user else config())


# ── the briefing ───────────────────────────────────────────────
def briefing(user: dict | None) -> str:
    """What this portal currently knows, in the words a model can use — limited
    to what this user's roles allow them to see."""
    from . import assets, fleet, rbac, store
    lines: list[str] = []
    may = lambda a: rbac.may_area(user, a)                     # noqa: E731

    lines.append("# What this portal manages, right now")
    lines.append("")

    if may("clusters") or may("config"):
        snap = fleet.overview()
        t = snap.get("totals") or {}
        lines.append(f"## Fleet: {t.get('projects', 0)} projects, "
                     f"{t.get('clusters', 0)} clusters, "
                     f"{t.get('reachable', 0)} reachable, "
                     f"{t.get('nodes_ready', 0)}/{t.get('nodes', 0)} nodes ready, "
                     f"{t.get('pods_running', 0)}/{t.get('pods', 0)} pods healthy, "
                     f"{t.get('pods_bad', 0)} pods needing attention.")
        allowed = rbac.visible_clusters(user)
        for c in snap.get("clusters") or []:
            if allowed is not None and c["cid"] not in allowed:
                continue
            state = "reachable" if c.get("reachable") else \
                f"UNREACHABLE ({(c.get('error') or '')[:80]})"
            cpu = c.get("cpu") or {}
            lines.append(
                f"- cluster “{c.get('name')}” in project “{c.get('project')}”: "
                f"{state}, {c.get('nodes_ready', 0)}/{c.get('nodes', 0)} nodes, "
                f"{c.get('pods_bad', 0)} unhealthy pods"
                + (f", cpu {cpu.get('pct')}%" if cpu.get("pct") is not None else ""))
        lines.append("")

    if may("config"):
        vis = rbac.visible_projects(user)
        lines.append("## Projects, regions, environments and services")
        for pid, p in store.projects().items():
            if vis is not None and pid not in vis:
                continue
            lines.append(f"- project “{p.get('name')}” ({pid})")
            for rgid, rg in (p.get("regions") or {}).items():
                envs = list((rg.get("env_clusters") or {}).keys())
                # the repositories are per-environment bindings now; the
                # briefing names the distinct set, not a region-level field
                urls = sorted({(b or {}).get("url") or ""
                               for b in (rg.get("envs") or {}).values()} - {""})
                lines.append(f"  - region “{rg.get('name')}”"
                             + (f", environments: {', '.join(envs)}" if envs else "")
                             + (f", repos: {', '.join(urls)}" if urls else ""))
        lines.append("")

    def conns(kind_fn, label, area):
        if not may(area):
            return
        rows = kind_fn()
        if not rows:
            return
        lines.append(f"## {label} ({len(rows)})")
        for c in rows:
            bits = [f"“{c.get('name')}”", f"type {c.get('type')}"]
            if c.get("base_url"):
                bits.append(c["base_url"])
            if c.get("status"):
                st = c["status"]
                healthy = st.startswith("ok") or st.startswith("connected")
                bits.append(("HEALTHY" if healthy else "NOT HEALTHY")
                            + f" — last check said: {st[:90]}")
            lines.append("- " + ", ".join(bits))
        lines.append("")

    conns(store.all_ci, "CI/CD connections", "pipelines")
    conns(store.all_sec, "Security scanning platforms", "security")
    conns(store.all_log, "Log stores", "logs")
    conns(store.all_mon, "Monitoring systems", "monitoring")
    conns(store.all_cloud, "Cloud accounts", "clouds")
    conns(store.all_stor, "Storage devices", "storage")
    conns(store.all_gitops, "GitOps controllers", "gitops")
    conns(store.all_wf, "Workflow engines", "workflows")
    conns(store.all_bmc, "Server BMCs", "bmc")
    conns(store.all_virt, "Hypervisors", "virt")

    if may("assets"):
        try:
            st = assets.stats()
            # NESTED UNDER `classes`. `assets.stats()` returns
            # {total, by, classes, cpu, ram, disk, warranty_*} -- there has
            # never been a top-level `physical` or `virtual` key, so this
            # briefing has told every assistant and every MCP client
            # "0 physical, 0 virtual" since it was written, about an estate of
            # 116 machines. A `.get` with a default cannot fail, which is
            # exactly why nothing noticed.
            cls = st.get("classes") or {}
            lines.append(f"## Inventory: {st.get('total', 0)} assets "
                         f"({cls.get('physical', 0)} physical, "
                         f"{cls.get('virtual', 0)} virtual)")
            lines.append("")
        except Exception:                                     # noqa: BLE001
            pass

    # The AREA, not the account's admin flag. Two reasons: somebody holding a
    # delegated "Audit log" role should get this context too, and — the one that
    # matters — a narrowed credential (an MCP token scoped to clusters only)
    # cannot narrow a check that reads `role` directly. Every other section here
    # goes through may(); this one was the exception, and an exception in a
    # permission filter is a leak waiting for a caller.
    if may("audit"):
        from . import auth
        recent = auth.read_audit(15, "")
        if recent:
            lines.append("## Audit history — PAST ACTIONS, not current inventory")
            lines.append("These lines describe things people did. Do not treat "
                         "them as systems that exist or are connected.")
            for r in recent:
                lines.append(f"- (past action) {r.get('at')}: {r.get('user')} "
                             f"{r.get('action')} {r.get('target', '')}".rstrip())
            lines.append("")

    from . import aitools
    acts = aitools.action_briefing(user)
    if acts:
        lines.append(acts)

    lines.append("## What you are")
    lines.append(
        "You are the assistant inside this DevOps portal. Everything above was "
        "read from its live database moments ago, so it is current. Answer from "
        "it: name the actual clusters, projects and connections rather than "
        "speaking generally. If the answer is not in the briefing, say which "
        "page of the portal would show it instead of guessing. You never run "
        "anything yourself: if an Actions section appears above you may PROPOSE "
        "one and the person decides, and if it does not, explain where in the "
        "portal they can do it. Be concise and concrete; this is a working "
        "tool, not a chat toy.")
    return "\n".join(lines)


def secret_watch(user: dict | None = None) -> tuple[tuple[str, str], ...]:
    """Every stored credential worth recognising, as (field, value) pairs.

    Split out from the check because the check now runs several times per
    question — once on the briefing and once on every tool result — and building
    this is the expensive half: ten connection tables, the model config, the
    asker's own key and every cluster in every project, each one a query whose
    sealed columns are decrypted on the way out. Rebuilding it per result cost
    roughly ninety queries and a hundred and fifty decryptions to re-derive an
    answer that had not changed since the question was asked.

    Values under eight characters are dropped here rather than at the comparison:
    a short one is a substring of ordinary prose, and the check raises.
    """
    from . import store
    live = []
    for getter in (store.all_ci, store.all_sec, store.all_log, store.all_mon,
                   store.all_cloud, store.all_stor, store.all_gitops,
                   store.all_wf, store.all_bmc, store.all_virt):
        try:
            live.extend(getter())
        except Exception:                                     # noqa: BLE001
            pass
    # every place the portal keeps a secret, not only connections: its own
    # model key, and each cluster's kubeconfig path and sealing certificate
    live.append(config())
    # and the asker's own key, now that a person can connect one. Without this
    # the check covered the deployment's credential and not theirs, which is
    # the one that is newer, likelier to be pasted somewhere by mistake, and
    # belongs to a person rather than to the install.
    if user:
        from . import aiuser
        try:
            live.append(aiuser.get(user.get("id", "")))
        except Exception:                                     # noqa: BLE001
            pass
    try:
        for proj in store.projects().values():
            live.extend((proj.get("clusters") or {}).values())
    except Exception:                                         # noqa: BLE001
        pass
    return tuple((field, val)
                 for row in live for field in SECRET_FIELDS
                 if len(val := str(row.get(field) or "")) >= 8)


def _no_secrets(text: str, user: dict | None = None, watch=None) -> str:
    """Assert text on its way to a model carries no stored credential.

    The briefing builder reads named fields and never whole connection rows, so
    this should never fire — which is exactly why it is worth checking: a future
    edit that starts dumping rows would be caught here rather than at a
    provider's API. Raising beats silently redacting: text that has to be
    censored is a bug to fix, not a request to serve.

    `watch` lets a caller making several checks in a row build the inventory
    once; without it each call rebuilds it.
    """
    for field, val in (secret_watch(user) if watch is None else watch):
        if val in text:
            raise AiError("refusing to send this to the model: it contains a "
                          f"stored {field}. This is a bug in the briefing "
                          "builder — report it rather than working around it.")
    return text

def _post(url: str, headers: dict, body: dict, skip_tls: bool) -> dict:
    req = urllib.request.Request(
        urlguard.check(url), data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers})
    ctx = _INSECURE if skip_tls else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            doc = json.loads(e.read().decode())
            detail = ((doc.get("error") or {}).get("message")
                      if isinstance(doc.get("error"), dict)
                      else doc.get("error") or doc.get("message") or "")
        except Exception:                                     # noqa: BLE001
            pass
        if e.code in (401, 403):
            raise AiError("the API key was rejected") from e
        if e.code == 404:
            raise AiError(f"not found (404) — check the URL and the model name "
                          f"{detail}".strip()) from e
        if e.code == 429:
            raise AiError("rate limited by the provider — try again shortly") from e
        raise AiError(f"HTTP {e.code}: {detail[:200]}") from e
    except urllib.error.URLError as e:
        raise AiError(f"cannot reach the model: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise AiError("the endpoint answered, but not with JSON") from e


def _anthropic(c: dict, system: str, turns: list) -> str:
    base = (c["base_url"] or "https://api.anthropic.com").rstrip("/")
    doc = _post(f"{base}/v1/messages",
                {"x-api-key": c["token"], "anthropic-version": "2023-06-01"},
                {"model": c["model"], "max_tokens": 1400, "system": system,
                 "messages": [{"role": t["role"], "content": t["text"]}
                              for t in turns]},
                c["skip_tls"])
    parts = [b.get("text", "") for b in doc.get("content") or []
             if b.get("type") == "text"]
    return "\n".join(p for p in parts if p).strip() or "(no answer returned)"


def _openai(c: dict, system: str, turns: list) -> str:
    base = (c["base_url"] or "https://api.openai.com").rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    doc = _post(f"{base}/chat/completions",
                {"Authorization": f"Bearer {c['token']}"},
                {"model": c["model"], "max_tokens": 1400,
                 "messages": [{"role": "system", "content": system}]
                 + [{"role": t["role"], "content": t["text"]} for t in turns]},
                c["skip_tls"])
    choices = doc.get("choices") or []
    if not choices:
        raise AiError("the endpoint returned no choices")
    return (choices[0].get("message") or {}).get("content", "").strip() \
        or "(no answer returned)"


def _ollama(c: dict, system: str, turns: list) -> str:
    base = (c["base_url"] or "http://localhost:11434").rstrip("/")
    doc = _post(f"{base}/api/chat", {},
                {"model": c["model"], "stream": False,
                 "messages": [{"role": "system", "content": system}]
                 + [{"role": t["role"], "content": t["text"]} for t in turns]},
                c["skip_tls"])
    return ((doc.get("message") or {}).get("content", "").strip()
            or "(no answer returned)")


IMPL = {"anthropic": _anthropic, "openai": _openai, "ollama": _ollama}


def ask(user: dict | None, turns: list) -> dict:
    """turns is [{role: user|assistant, text}] oldest first. Returns
    {answer, model, briefing_lines} or raises AiError."""
    c = config_for(user)
    if not ready(user):
        raise AiError("the assistant is not configured — an administrator can "
                      "set it up in Settings → Assistant")
    fn = IMPL.get(c["provider"])
    if not fn:
        raise AiError(f"unknown provider '{c['provider']}'")
    system = _no_secrets(briefing(user), user)
    answer = fn(c, system, turns[-HISTORY:])
    return {"answer": answer, "model": c["model"],
            "briefing_lines": system.count("\n") + 1}


def test() -> tuple[bool, str]:
    """A real round trip, so “connected” means the model answered."""
    c = config()
    if not (c["provider"] in PROVIDERS and c["model"]):
        return False, "choose a provider and name a model first"
    try:
        got = IMPL[c["provider"]](
            c, "Reply with exactly: ready",
            [{"role": "user", "text": "Are you there?"}])
    except AiError as e:
        return False, str(e)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    return True, f"connected — {c['model']} answered: {got[:60]}"


# ── streaming ──────────────────────────────────────────────────
# Even a fast answer is several seconds of silence, and silence reads as broken —
# a "thinking…" bubble that sits there for ten seconds is indistinguishable from
# a hang, which is exactly how this felt before. So the answer arrives as it is
# generated. Every provider supports it; only the wire format differs, so each
# gets a small line parser and the rest is shared.
def _stream_lines(url: str, headers: dict, body: dict, skip_tls: bool):
    """Yield decoded lines from a streaming HTTP response."""
    req = urllib.request.Request(
        urlguard.check(url), data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers})
    ctx = _INSECURE if skip_tls else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    yield line
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode()[:200]
        except Exception:                                     # noqa: BLE001
            pass
        if e.code in (401, 403):
            raise AiError("the API key was rejected") from e
        raise AiError(f"HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise AiError(f"cannot reach the model: {e.reason}") from e


def _stream_ollama(c: dict, system: str, turns: list):
    base = (c["base_url"] or "http://localhost:11434").rstrip("/")
    body = {"model": c["model"], "stream": True,
            "messages": [{"role": "system", "content": system}]
            + [{"role": t["role"], "content": t["text"]} for t in turns]}
    for line in _stream_lines(f"{base}/api/chat", {}, body, c["skip_tls"]):
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if doc.get("error"):
            raise AiError(str(doc["error"])[:200])
        piece = (doc.get("message") or {}).get("content", "")
        if piece:
            yield piece
        if doc.get("done"):
            break


def _sse_payloads(lines):
    """The JSON objects out of an SSE stream, ignoring comments and [DONE]."""
    for line in lines:
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            yield json.loads(data)
        except json.JSONDecodeError:
            continue


def _stream_openai(c: dict, system: str, turns: list):
    base = (c["base_url"] or "https://api.openai.com").rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    body = {"model": c["model"], "stream": True, "max_tokens": 1400,
            "messages": [{"role": "system", "content": system}]
            + [{"role": t["role"], "content": t["text"]} for t in turns]}
    lines = _stream_lines(f"{base}/chat/completions",
                          {"Authorization": f"Bearer {c['token']}"},
                          body, c["skip_tls"])
    for doc in _sse_payloads(lines):
        for ch in doc.get("choices") or []:
            piece = (ch.get("delta") or {}).get("content") or ""
            if piece:
                yield piece


def _stream_anthropic(c: dict, system: str, turns: list):
    base = (c["base_url"] or "https://api.anthropic.com").rstrip("/")
    body = {"model": c["model"], "stream": True, "max_tokens": 1400,
            "system": system,
            "messages": [{"role": t["role"], "content": t["text"]}
                         for t in turns]}
    lines = _stream_lines(f"{base}/v1/messages",
                          {"x-api-key": c["token"],
                           "anthropic-version": "2023-06-01"},
                          body, c["skip_tls"])
    for doc in _sse_payloads(lines):
        if doc.get("type") == "content_block_delta":
            piece = (doc.get("delta") or {}).get("text") or ""
            if piece:
                yield piece
        elif doc.get("type") == "error":
            raise AiError(str((doc.get("error") or {}).get("message", ""))[:200])


STREAMS = {"ollama": _stream_ollama, "openai": _stream_openai,
           "anthropic": _stream_anthropic}


def stream(user: dict | None, turns: list):
    """Yield ("meta", {...}) once, then ("text", chunk) repeatedly.

    The briefing is built here, so the caller cannot forget the permission
    filtering or the secret check.
    """
    c = config_for(user)
    if not ready(user):
        raise AiError("the assistant is not configured — an administrator can "
                      "set it up in Settings → Assistant")
    fn = STREAMS.get(c["provider"])
    if not fn:
        raise AiError(f"'{c['provider']}' cannot stream in this build")
    system = _no_secrets(briefing(user), user)
    yield "meta", {"model": c["model"],
                   "briefing_lines": system.count("\n") + 1}
    for piece in fn(c, system, turns[-HISTORY:]):
        yield "text", piece


# ── routing a question ─────────────────────────────────────────
# The catalogue in answers.py holds the real queries. A question is routed to one
# of them by ordinary code; a model is consulted only when that code is unsure,
# and only to pick a name from a short list. This is what keeps the assistant
# usable on a CPU: the model never sees the estate, only a question and a list.
ROUTE_MIN = 0.30          # below this, ask a model to choose if one exists


# Words that make a question a continuation of the last one rather than a new
# one. "give me the one for za preprod" carries no subject of its own: the
# subject was in the previous question, and a router that ignores that answers
# something else entirely — which it did, returning 59 pods to a question about
# an IP address.
FOLLOW_ON = {"one", "ones", "same", "that", "those", "these", "it", "its",
             "them", "also", "too", "instead", "again", "other", "another",
             "next", "as", "well", "about", "and", "what", "how", "now"}


def is_follow_up(question: str, own_confidence: float) -> bool:
    """Whether this should inherit the previous question's query.

    Two signals, and it needs one of them: the question uses a referring word
    ("the one", "same", "that"), or it names no subject at all — a bare entity
    like "za preprod" or "and for tz?" is a continuation by construction. A
    question with strong vocabulary of its own is never a follow-up, so
    "which pods need attention" after an IP question still means pods.
    """
    from . import answers
    words = [w for w in answers._words(question) if w not in answers.STOP]
    if not words:
        return True

    # Does the question name a subject of its own? Either query vocabulary
    # ("pods", "ingress", "temperature") or a concrete identifier (a serial, a
    # host name, an address) counts. A cluster name does NOT: "and for tz
    # preprod?" is a scope, not a subject.
    vocabulary = {w for spec in answers.CATALOGUE.values() for w in spec["words"]}
    names_subject = any(w in vocabulary or answers.IDENTIFIER.match(w)
                        for w in words)
    refers_back = any(w in FOLLOW_ON for w in words)

    # A long question is a new question. "how many physical servers do we have
    # in uae acme prod" named nothing this catalogue knew, so it was taken as
    # a continuation of a pipelines question and answered with pipelines — two
    # unrelated answers fused into one, which is worse than admitting the
    # question was not understood. Continuations are short by nature: "the one
    # for za preprod", "same for ke", "and tz?".
    if len(words) >= 4 and not refers_back:
        return False
    if not names_subject:
        return True

    # It does name a subject — so only a referring word makes it a continuation,
    # and only when the match is weak. Confidence is judged here rather than
    # trusted from the caller because the matcher adds a bonus for a recognised
    # cluster, which would otherwise make a bare scope look decisive.
    return refers_back and own_confidence < 0.55


REFERS_TO_SAME = {"same", "that", "this", "those", "these", "it", "there",
                  "again"}


def inherited_cluster(question: str, previous: dict | None) -> str:
    """The cluster phrase to reuse when a question points back at one.

    "show me the expiry date on the same cluster" names no cluster, so without
    this it silently widened to every cluster — an answer about the wrong thing,
    which is the failure mode worth being strict about.
    """
    from . import answers
    if not previous or answers.find_cluster(question)[0]:
        return ""
    if not (set(answers._words(question)) & REFERS_TO_SAME):
        return ""
    return str(previous.get("cluster_phrase", ""))


def route(user: dict | None, question: str,
          previous: dict | None = None) -> tuple[str, float, str]:
    """(query name, confidence, how it was decided).

    `previous` is {"query": name, "question": text} from the last exchange in
    this conversation. A follow-up keeps that query and merges the two
    questions, so "give me the one for za preprod" after "traefik ip for
    ledger prod" runs the services query, scoped to za-preprod, still filtered
    to traefik. The new question comes first in the merge, so its cluster wins
    over the old one.
    """
    from . import answers
    name, conf = answers.match(user, question)
    prev_name = (previous or {}).get("query")
    if prev_name in answers.CATALOGUE and is_follow_up(question, conf):
        return prev_name, max(conf, 0.6), "continuing the previous question"
    if name and conf >= ROUTE_MIN:
        return name, conf, "matched"
    if not ready(user):
        return name, conf, "matched" if name else "unmatched"
    # a tiny prompt: the question, and the list of things that can be asked
    caps = answers.capabilities(user)
    menu = "\n".join(f"- {c['name']}: {c['help']}" for c in caps)
    c = config_for(user)
    fn = IMPL.get(c["provider"])
    if not fn:
        return name, conf, "matched" if name else "unmatched"
    try:
        pick = fn(c, "You map a question to one data query. Reply with ONLY the "
                     "query name from the list, or the single word NONE. No "
                     "explanation.\n\nQueries:\n" + menu,
                  [{"role": "user", "text": question}])
    except AiError:
        return name, conf, "matched" if name else "unmatched"
    guess = (pick or "").strip().split()[0].strip(".,:`'\"").lower() if pick else ""
    if guess in {c["name"] for c in caps}:
        return guess, 0.99, "chosen by the model"
    return name, conf, "matched" if name else "unmatched"


def summarise_stream(user: dict | None, question: str, result_text: str,
                     count: int = 0):
    """Stream a short answer *about the rows the portal just fetched*.

    The model is handed the result, not the estate — a few hundred tokens rather
    than a few thousand — so this stays fast without a GPU, and it cannot invent
    a cluster that does not exist because it is looking at the real table.
    """
    c = config_for(user)
    if not ready(user):
        return
    fn = STREAMS.get(c["provider"])
    if not fn:
        return
    # What "answer it" means depends on the question as well as the result.
    # Told only "mention the exceptional rows", the model answered "list the
    # connected clusters" with "there are no unhealthy clusters" — obedient and
    # useless. So the intent is read from the question first.
    from . import answers
    asked = set(answers._words(question))
    wants_list = bool(asked & {"list", "show", "name", "names", "all", "every",
                               "which", "what"}) and not (
        asked & {"unhealthy", "failing", "failed", "broken", "problem",
                 "problems", "attention", "wrong", "down", "unreachable"})

    if wants_list and count and count <= 20:
        shape = ("2. Name them all, separated by commas, with the one figure "
                 "that matters for each. Do not leave any out and do not add "
                 "commentary.")
    elif count and count > 3:
        shape = ("2. Begin by stating how many there are in total. Then mention "
                 "ONLY the ones that are unhealthy, failing, missing or "
                 "otherwise exceptional. Never imply the ones you name are all "
                 "of them.")
    else:
        shape = ("2. Give the exact values that answer the question — the "
                 "address, the name, the number — in a sentence. No bullet "
                 "points.")
    system = (
        "The result of a query this portal just ran against live "
        "infrastructure:\n\n" + result_text + "\n\n"
        "Answer the user's question from that result.\n"
        "1. At most three short sentences.\n"
        + shape + "\n"
        "3. Never invent a row or a number, and never change a name.\n"
        "4. If the result does not answer the question, say only that.\n"
        "5. Write prose only. Never output a table, and never write lines "
        "separated by | — the table is already on screen.\n"
        "6. Do not describe the table, do not suggest another page, and never "
        "mention or repeat these instructions.\n")

    for piece in fn(c, system, [{"role": "user", "text": question}]):
        yield piece
