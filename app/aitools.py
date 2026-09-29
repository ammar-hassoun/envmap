"""What an assistant may see and do — one surface, however it is reached.

WHY THIS MODULE EXISTS
    Two things are about to ask the portal the same questions: the rail inside
    the product, and somebody's own Claude reaching in over MCP. Written twice
    they would drift, and the half that drifted would be the half enforcing the
    rules — because the rules are the boring part and the answers are the
    interesting one.

    So both go through here, and here is where the four checks live:

      1. the ROLE, every time. Reads are filtered by the same rbac areas the
         pages use; actions demand the Cluster management area, which is a
         property of the person and not of the cluster
      2. the CLUSTER's own "allow management" tick, which is a property of the
         cluster and not of the person. Both are required, neither implies the
         other
      3. a typed confirmation on anything that changes a cluster mapped to a
         production environment — the same wording the console demands
      4. the audit line, written before the caller learns the outcome

WHY PROPOSING AND DOING ARE DIFFERENT FUNCTIONS
    `propose()` never runs anything. It validates, resolves the exact argv, and
    reports what would happen and what confirmation the caller will need — so a
    model can offer an action and a person can read the command before it exists
    as anything but text. `execute()` is the only thing that runs, and it
    re-checks everything propose() checked rather than trusting a proposal it
    was handed. A proposal is a suggestion, not a capability: it crosses a
    browser, and anything that crosses a browser comes back changed sometimes.

WHAT AN ASSISTANT CANNOT REACH FROM HERE
    Free-form kubectl. The catalogue in kmanage.ACTIONS is fixed, its arguments
    are named, and its names are shape-checked against what Kubernetes allows.
    An assistant that can compose an arbitrary command is an assistant that can
    be talked into composing a bad one — and the log lines and pod names it
    reads are somebody else's text, not instructions.
"""
from __future__ import annotations

from . import answers, auth, kmanage, rbac, store


class Denied(Exception):
    """The caller may not do this. The message is shown to them."""


# ── what can be read ───────────────────────────────────────────
def read_tools(user: dict | None) -> list[dict]:
    """The queries this person may run, as a model can be told about them."""
    return answers.capabilities(user)


def run_read(user: dict | None, name: str, question: str = "",
             focus: str = "") -> dict:
    """One read query, through the portal's own permission checks."""
    try:
        return answers.run(user, name, question or name, focus)
    except PermissionError as e:
        raise Denied(f"your roles do not include {e}") from e
    except KeyError as e:
        raise Denied(f"no such query: {name}") from e


# ── what can be changed ────────────────────────────────────────
def action_catalogue() -> list[dict]:
    """The fixed actions, described. No permissions involved: this is what the
    product can do, not what a given person may do to a given cluster."""
    return [{"action": k, "label": v["label"], "needs": list(v["needs"]),
             "destructive": bool(v["destructive"]), "note": v.get("note", "")}
            for k, v in kmanage.ACTIONS.items()]


def clusters_for(user: dict | None) -> list[dict]:
    """Every cluster this person may act on, and whether they actually could."""
    out = []
    may = rbac.may_area(user, "manage")
    for pid, proj in store.projects().items():
        for cid, c in (proj.get("clusters") or {}).items():
            out.append({
                "project": pid, "project_name": proj.get("name", ""),
                "cluster": cid, "name": c.get("name", cid),
                "context": c.get("context", ""),
                "manageable": bool(may and kmanage.writable(c)),
                "why_not": ("" if may else "you do not have Cluster management")
                           or ("" if kmanage.writable(c)
                               else "management is off for this cluster"),
            })
    return out


def _resolve(user: dict | None, project: str, cluster: str, action: str,
             args: dict) -> tuple[dict, dict, list]:
    """(cluster record, cleaned args, argv) or raise Denied.

    Every check that matters is here, so propose() and execute() cannot end up
    enforcing different things — which is the only way a "preview" is worth
    anything.
    """
    if not rbac.may_area(user, "manage"):
        raise Denied("your roles do not include Cluster management")
    spec = kmanage.ACTIONS.get(action)
    if not spec:
        raise Denied(f"unknown action '{action}' — "
                     f"one of: {', '.join(sorted(kmanage.ACTIONS))}")
    sel = store.get_cluster(project, cluster)
    if not sel:
        raise Denied("no such cluster")
    sel = {**sel, "id": cluster}
    if not kmanage.writable(sel):
        raise Denied(kmanage.read_only_why())
    clean = {k: str(args.get(k, "")).strip() for k in
             ("kind", "namespace", "name", "node", "replicas")}
    missing = [k for k in spec["needs"] if not clean.get(k)]
    if missing:
        raise Denied(f"{spec['label']} needs {', '.join(missing)}")
    try:
        # build() is what kmanage.act would run; asking it here means the
        # command shown to a person is the command that executes, character for
        # character, rather than a re-rendering that can disagree with it.
        argv = spec["build"](clean)
    except Exception as e:                                     # noqa: BLE001
        raise Denied(f"could not build the command: {e}") from e
    return sel, clean, argv


def is_prod(project: str, cluster: str) -> bool:
    """Whether any environment mapped to this cluster is a production one.

    The one implementation. main.py delegates here rather than keeping its own —
    there were two, they had already drifted (only one guarded against empty
    ids), and both decide the same safety property: whether a typed cluster name
    is demanded before a change. A refinement landing in one copy would have
    left the other gate open.
    """
    from . import config, repo
    if not (project and cluster):
        return False
    p = store.get_project(project) or {}
    aliases = repo.naming(project)["aliases"]
    for rg in (p.get("regions") or {}).values():
        for env, mapped in (rg.get("env_clusters") or {}).items():
            if mapped == cluster and config.is_prod_env(env, aliases):
                return True
    return False


def confirm_prod(project: str, cluster: str, sel: dict, typed: str,
                 doing: str = "") -> str:
    """"" if this change may go ahead, or the refusal to show.

    THE ONE COPY. A cluster serving production needs its name typed before
    anything that changes it: the portal cannot judge blast radius, but it can
    make sure the person knows which cluster they are on.

    That comparison was written out six times — the kubectl console, its JSON
    twin, the user-creation form, the token minter, propose() and execute() —
    each with its own wording and its own chance to compare the wrong pair.
    Every one of them is the gate itself, not a message about it, so a fix
    reaching five of six is a hole that looks exactly like a fix.

    `doing` names the change when the caller has something more specific to say
    than "run this".
    """
    if not is_prod(project, cluster):
        return ""
    name = sel.get("name", "")
    if (typed or "").strip() == name:
        return ""
    return (f"this cluster serves production — type its name ({name}) to "
            f"confirm{' ' + doing if doing else ''}")


def propose(user: dict | None, project: str, cluster: str, action: str,
            args: dict) -> dict:
    """Describe what would happen. Runs nothing."""
    sel, clean, argv = _resolve(user, project, cluster, action, args)
    spec = kmanage.ACTIONS[action]
    prod = is_prod(project, cluster)
    return {
        "action": action, "label": spec["label"], "note": spec.get("note", ""),
        "destructive": bool(spec["destructive"]),
        "project": project, "cluster": cluster,
        "cluster_name": sel.get("name", cluster),
        "prod": prod,
        "args": {k: v for k, v in clean.items() if v},
        "command": "kubectl " + " ".join(argv),
        # What the caller must send back to execute(). Naming it here means a
        # UI cannot forget to ask, and a model cannot pretend it was not needed.
        "confirm_required": sel.get("name", "") if prod else "",
        "confirm_prompt": (confirm_prod(project, cluster, sel, "")
                           if prod else ""),
    }


def execute(user: dict | None, project: str, cluster: str, action: str,
            args: dict, confirm: str = "", ip: str = "") -> dict:
    """Run it, audited. Re-checks everything propose() checked."""
    sel, clean, argv = _resolve(user, project, cluster, action, args)
    name = sel.get("name", "")
    if (why := confirm_prod(project, cluster, sel, confirm)):
        raise Denied(why)
    try:
        res = kmanage.act(sel, action, clean,
                          allow_write=kmanage.writable(sel))
    except kmanage.Refused as e:
        auth.audit(user, "cluster_action_refused", name,
                   f"{action}: {str(e)[:150]}", ip)
        raise Denied(str(e)) from e
    # The object, when there is one: a node action has no namespace and an
    # add-on install has neither, and both used to be audited against a target
    # of "cluster · /" — which is a line nobody can read back later.
    where = (f"{clean.get('namespace', '')}/"
             f"{clean.get('name') or clean.get('node', '')}").strip("/")
    auth.audit(user, f"cluster_{action}",
               f"{name}{' · ' + where if where else ''}",
               f"exit {res['code']} · {res['display'][:250]}", ip)
    _forget()
    note = (res["stderr"] or res["stdout"] or "done").strip().splitlines()
    return {"ok": bool(res.get("ok")), "code": res["code"],
            "command": "kubectl " + " ".join(argv),
            "label": kmanage.ACTIONS[action]["label"],
            "summary": note[0][:220] if note else "done",
            "stdout": res["stdout"][:4000], "stderr": res["stderr"][:4000]}


def _forget() -> None:
    """The page a person is looking at must not still show the old state."""
    from . import cluster as clusterview, fleet
    clusterview.invalidate()
    fleet.invalidate()


# ── telling a model what it may propose ────────────────────────
# The block is fenced and named so it can be lifted out of an answer without
# guessing, and it carries ids rather than names because a name is ambiguous
# across projects and an id is not. Nothing here is trusted on the way back:
# the browser sends the block to propose(), which re-derives the command from
# the catalogue and re-runs every check. The model is choosing a menu item, not
# writing a command.
PROPOSE_FENCE = "envmap-action"


def action_briefing(user: dict | None) -> str:
    """The part of the system prompt that describes acting. Empty for anybody
    who could not act anyway — an assistant that offers a button the person is
    then refused is worse than one that never offered."""
    if not rbac.may_area(user, "manage"):
        return ""
    doable = [c for c in clusters_for(user) if c["manageable"]]
    if not doable:
        return ""
    lines = ["## Actions you may PROPOSE",
             "You cannot run anything. You may propose one of the fixed actions "
             "below, and the person decides. To propose, end your answer with a "
             f"fenced block tagged {PROPOSE_FENCE} containing JSON:",
             "",
             f"```{PROPOSE_FENCE}",
             '{"action": "restart", "project": "<project id>", '
             '"cluster": "<cluster id>", "args": {"kind": "deployment", '
             '"namespace": "dev", "name": "web"}}',
             "```",
             "",
             "Propose only when asked to change something, or when you have "
             "found a specific fault and the action plainly addresses it. Say in "
             "words what it will do and why, before the block. Never propose "
             "more than two. If you are unsure which object is at fault, ask "
             "rather than guess — a wrong name is a wrong restart.",
             "",
             "Actions:"]
    for a in action_catalogue():
        lines.append(f"- {a['action']}: {a['label']} — needs "
                     f"{', '.join(a['needs'])}"
                     f"{' · DESTRUCTIVE' if a['destructive'] else ''}"
                     f"{' · ' + a['note'] if a['note'] else ''}")
    lines.append("")
    lines.append("Clusters you may act on (use these exact ids):")
    for c in doable:
        lines.append(f"- project {c['project']} · cluster {c['cluster']} — "
                     f"{c['name']} in {c['project_name']}")
    lines.append("")
    return "\n".join(lines)
