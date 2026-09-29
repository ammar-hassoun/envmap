"""What an assistant may CHANGE — one catalogue, the whole portal.

WHY THIS EXISTS
    `answers.CATALOGUE` is everything the portal can be ASKED. This is the other
    half: everything it can be TOLD. It was missing, and its absence showed —
    the only thing an MCP client could change was a Kubernetes object, because
    `kmanage.ACTIONS` happened to be the one catalogue that already existed.
    Adding a host to an inventory, running a playbook, generating a VM,
    requesting a certificate and syncing an application are all things the pages
    do; a client that can read the estate and change nothing in it is half a
    tool.

    So each verb here is a thin wrapper over the function the ROUTE already
    calls. That is the whole design: the module keeps its own rules — its
    installation switch, its production confirmation, its own refusals — and
    this file only says who may reach it and with what arguments. A verb that
    re-implemented a module's gate would be a second gate to keep in step, and
    the one that drifted would be the one nobody tested.

WHAT A VERB IS
    A name, the rbac areas it needs, whether it CHANGES anything, its named
    arguments, and a `run`. Nothing is free-form: an argument the catalogue does
    not declare is dropped before the module sees it, and a verb the caller's
    roles do not cover is not offered at all.

    `changes: False` matters more than it looks. Reading a pod's logs or
    describing a node is troubleshooting, not a change, so those verbs are
    available to a read-only credential — which is the difference between an
    assistant that can diagnose and one that can only recite inventory.

THE ONE THING THAT IS FREE-FORM, AND WHY IT IS SAFE
    `kubectl_read` takes a command, and `kmanage.classify` is what makes that
    acceptable: it resolves the verb, refuses anything it does not recognise
    rather than assuming it is harmless, blocks the dangerous ones outright, and
    the runner is called with `allow_write=False` so a write cannot execute even
    if one slipped through the classifier. It is the same door the portal's own
    kubectl console uses, gated on the same area — so it grants a person nothing
    they could not already type in the browser.

CONFIGURATION IS REACHABLE; PERMISSION IS NOT
    Creating projects, registering clusters, adding regions and mapping
    environments are all here, gated on the `settings` area. They were left out
    at first and that was too cautious: registering twenty-five clusters is
    exactly the kind of work a person should be able to hand to an assistant,
    and it changes what the portal KNOWS rather than who may use it.

    Users, roles and MCP tokens are the exception, and stay out. A token that
    can grant its owner another area — or mint itself a wider token — makes
    every other gate in this file decorative, including the scope on the
    credential that called it. That is not caution about blast radius; it is the
    one hole that would make the rest untestable. Changing who may do what stays
    something a person does, signed in, at a page.

WHY `cluster_add` REFUSES A DUPLICATE ITSELF
    Because "do not add the same cluster twice" must not depend on the caller
    remembering to look first. It checks the context name AND the API server URL
    of every kubeconfig the portal already stored, so a second attempt — by a
    model, a retry, or a re-run of somebody's script — is refused with the name
    of the cluster it would have duplicated. The guarantee belongs to the
    portal, not to the diligence of whatever is calling it.
"""
from __future__ import annotations

import json

from . import (aitools, ansible, auth, certs, gitops, gitrepo, kmanage, rbac,
               repo, store)
from .aitools import Denied


def _cluster(project: str, cluster: str) -> dict:
    sel = store.get_cluster(project, cluster)
    if not sel:
        raise Denied("no such cluster — call `clusters` for the ids")
    return {**sel, "id": cluster}


# ── the verbs ──────────────────────────────────────────────────
def _kubectl_read(user, a, ip):
    # Classify BEFORE resolving the cluster: "that command changes things" is
    # the useful answer to a write, and it should not depend on whether the
    # cluster id happened to be right. Same discipline as terraform.start —
    # allowed to run is decided before able to run.
    try:
        if kmanage.classify(kmanage.parse(a["command"])) == "write":
            # Not `read_only_why`, which explains a cluster's management tick:
            # this verb is read-only for EVERY cluster, however that tick is
            # set, and saying otherwise would send the reader to change a
            # setting that makes no difference here.
            raise Denied(
                "that kubectl command changes the cluster, and kubectl_read "
                "only reads. cluster_action does the fixed changes — gated, "
                "confirmed on production, and audited.")
    except kmanage.Refused as e:
        raise Denied(str(e)) from e
    sel = _cluster(a["project"], a["cluster"])
    try:
        # allow_write=False as well: the classifier above has already refused
        # anything that would need it, and the runner refuses it again. Two
        # independent noes for the same thing.
        got = kmanage.run(sel, a["command"], allow_write=False)
    except kmanage.Refused as e:
        raise Denied(str(e)) from e
    return {"summary": f"kubectl exit {got['code']}",
            "detail": (got["stdout"] or got["stderr"] or "")[:12000],
            "target": f"{sel.get('name', a['cluster'])}: {got['display'][:120]}"}


def _cluster_action(user, a, ip):
    # Straight to aitools, which owns the cluster gates: the Cluster management
    # area, the cluster's own "allow management" tick, and a typed production
    # name. It audits its own line, hence audited=True.
    got = aitools.execute(user, a["project"], a["cluster"], a["action"],
                          a.get("args") or {}, a.get("confirm", ""), ip)
    return {"summary": got.get("summary", "done"),
            "detail": (got.get("stdout") or got.get("stderr") or "")[:8000],
            "ok": bool(got.get("ok")), "audited": True,
            "target": f"{a['cluster']}: {a['action']}"}


def _ansible_add_host(user, a, ip):
    try:
        hid = ansible.add_host(a["group"], a["name"], a["address"],
                               (user or {}).get("email", ""),
                               ssh_user=a.get("ssh_user", ""),
                               ssh_port=int(a.get("ssh_port") or 0),
                               host_vars=a.get("host_vars", ""),
                               env=a.get("env", ""))
    except (ansible.Refused, ValueError) as e:
        raise Denied(str(e)) from e
    return {"summary": f"{a['name']} added to the group",
            "detail": f"host id {hid}", "target": f"{a['group']}/{a['name']}"}


def _ansible_run(user, a, ip):
    check = bool(a.get("check", True))
    try:
        rid = ansible.start(a["playbook"], a["group"],
                            (user or {}).get("email", ""), check=check,
                            limit_to=a.get("limit_to", ""),
                            tags=a.get("tags", ""),
                            extra_vars=a.get("extra_vars", ""),
                            # The installation's own switch and the production
                            # confirmation are the module's to enforce; passing
                            # them through is what keeps one copy of each rule.
                            allow_real=ansible.config()["allow_real"],
                            confirm=a.get("confirm", ""))
    except ansible.Refused as e:
        raise Denied(str(e)) from e
    return {"summary": f"{'check' if check else 'REAL'} run started",
            "detail": f"run id {rid} — read it with ansible_run_output",
            "target": f"{a['playbook']} on {a['group']}"}


def _ansible_run_output(user, a, ip):
    got = ansible.run(a["run"])
    if not got:
        raise Denied("no such run")
    return {"summary": f"{got.get('status', '?')}"
                       f" · {got.get('pb_name', '')} on {got.get('group_name', '')}",
            "detail": (got.get("output") or "")[-12000:],
            "target": a["run"]}


def _provision_vm(user, a, ip):
    from . import provision
    spec = a.get("spec")
    if not isinstance(spec, dict):
        raise Denied("spec must be an object — see the description for its keys")
    try:
        sid = provision.create(spec, (user or {}).get("email", ""))
    except (provision.Refused, provision.ProxmoxError) as e:
        raise Denied(str(e)) from e
    return {"summary": "stack generated — nothing has been created yet",
            "detail": f"stack id {sid}. Run it with terraform_run "
                      f"(plan first, then apply).",
            "target": sid}


def _terraform_run(user, a, ip):
    from . import terraform
    try:
        rid = terraform.start(a["stack"], a["action"],
                              (user or {}).get("email", ""),
                              allow_apply=terraform.config()["allow_apply"],
                              confirm=a.get("confirm", ""))
    except terraform.Refused as e:
        raise Denied(str(e)) from e
    return {"summary": f"terraform {a['action']} started",
            "detail": f"run id {rid} — read it with terraform_run_output",
            "target": f"{a['stack']}: {a['action']}"}


def _terraform_run_output(user, a, ip):
    from . import terraform
    got = terraform.run(a["run"])
    if not got:
        raise Denied("no such run")
    return {"summary": f"{got.get('status', '?')} · {got.get('action', '')} "
                       f"on {got.get('stack_name', '')}",
            "detail": (got.get("output") or "")[-12000:], "target": a["run"]}


def _cert_request(user, a, ip):
    if not a.get("agreed"):
        raise Denied("the CA's subscriber agreement has to be accepted — ask "
                     "the person, then pass agreed: true")
    try:
        oid = certs.create((user or {}).get("id", ""), a["domains"],
                           ca=a.get("ca", "le"), email=a.get("email", ""),
                           key_type=a.get("key_type", "rsa2048"), agreed=True)
    except certs.CertError as e:
        raise Denied(str(e)) from e
    return {"summary": "order opened — it now wants DNS records proved",
            "detail": f"order id {oid}. The TXT records to publish are on the "
                      f"Certificates page; the portal finishes the order once "
                      f"they resolve.",
            "target": str(a["domains"])[:120]}


def _gitops_sync(user, a, ip):
    c = _gitops_conn(a["controller"])
    try:
        note = gitops.sync_app(c, a["application"], prune=bool(a.get("prune")),
                               dry_run=bool(a.get("dry_run")),
                               revision=a.get("revision", ""))
    except gitops.GitOpsError as e:
        raise Denied(str(e)) from e
    return {"summary": note or "sync requested",
            "detail": "", "target": f"{c.get('name', '')}:{a['application']}"}


def _gitops_refresh(user, a, ip):
    c = _gitops_conn(a["controller"])
    try:
        note = gitops.refresh_app(c, a["application"], bool(a.get("hard")))
    except gitops.GitOpsError as e:
        raise Denied(str(e)) from e
    return {"summary": note or "refreshed",
            "detail": "", "target": f"{c.get('name', '')}:{a['application']}"}


# ── the values files: read, change, commit ─────────────────────
def _find_region(project: str, region: str) -> tuple[str, str, dict, dict]:
    """(pid, rgid, project, region) by id or by name, either side."""
    pid, proj = _find_project(project)
    for rgid, rg in (proj.get("regions") or {}).items():
        if region in (rgid, rg.get("name")):
            return pid, rgid, proj, rg
    raise Denied(f"no region called {region!r} in {proj.get('name')} — "
                 f"call config_files for the names")


def _find_service(pid: str, rgid: str, env: str, service: str) -> str:
    """The stored file name for a service.

    A service is addressed by the name a person reads — "bff-mobile" — and the
    file on disk may be `bff-mobile-values.yaml` or a nested path encoded into
    one segment. `repo.list_envs` is the only thing that knows which, so the
    lookup goes through it rather than guessing at a suffix.
    """
    from . import repo
    files = (repo.list_envs(pid, rgid, include_hidden=True) or {}).get(env)
    if files is None:
        raise Denied(f"no environment called {env!r} in that region — "
                     f"call config_files")
    want = (service or "").strip().casefold()
    for fname in files:
        if want in (fname.casefold(),
                    repo.display(pid, fname).casefold(),
                    repo.service_display(fname).casefold()):
            return fname
    raise Denied(f"no service called {service!r} in {env} — "
                 f"call config_files for what is there")


def _config_files(user, a, ip):
    from . import gitrepo, repo
    out = []
    for pid, proj in _projects_now().items():
        if a.get("project") and a["project"] not in (pid, proj.get("name")):
            continue
        for rgid, rg in (proj.get("regions") or {}).items():
            if a.get("region") and a["region"] not in (rgid, rg.get("name")):
                continue
            envs_here = repo.list_envs(pid, rgid, include_hidden=True)
            urls = sorted({repo.binding(pid, rgid, e)["url"]
                           for e in envs_here} - {""})
            first = next(iter(envs_here), "")
            head = gitrepo.head_info(pid, rgid, env_name=first)
            out.append({
                "project": proj.get("name"), "region": rg.get("name"),
                "repository": ", ".join(urls),
                "branch": head.get("branch"), "head": head.get("head"),
                "uncommitted": bool(head.get("dirty")),
                "cloned": head.get("cloned"),
                "environments": {
                    env: [repo.display(pid, f) for f in files]
                    for env, files in (repo.list_envs(pid, rgid,
                                                      include_hidden=True)
                                       or {}).items()},
            })
    if not out:
        raise Denied("no region matched — call portal_config for the names")
    return {"summary": f"{len(out)} region(s), "
                       f"{sum(len(r['environments']) for r in out)} environments",
            "detail": json.dumps(out, indent=2), "doc": out,
            "target": "values files"}


def _config_read(user, a, ip):
    from . import gitrepo, repo, values
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    fname = _find_service(pid, rgid, a["env"], a["service"])
    path = repo.values_path(pid, rgid, a["env"], fname)
    if not path.exists():
        raise Denied(f"{path.name} is not in the working copy — "
                     f"call config_pull first")
    from . import yamledit
    text = path.read_text()
    # Two loaders, deliberately. `repo.yaml` tolerates duplicate keys the way
    # Helm does, so a messy file can still be READ; `yamledit.parse` does not,
    # because the line-accurate editor cannot safely rewrite a document it
    # cannot model. Saying which of the two failed is the whole point — an
    # earlier version swallowed the exception and answered "0 values", which is
    # indistinguishable from an empty file and sent the reader nowhere.
    rows, why = [], ""
    try:
        data = repo.yaml.load(text)
        for r in values.rows(data)[:600]:
            if r["kind"] == "scalar":
                rows.append({"path": r["path"], "at": r["chain"],
                             "value": r["value"], "type": r["type"],
                             "editable": r["editable"]})
    except Exception as e:                                    # noqa: BLE001
        why = f"this file does not parse as YAML at all: {str(e)[:180]}"
    editable, ewhy = True, ""
    try:
        yamledit.parse(text)
    except Exception as e:                                    # noqa: BLE001
        editable = False
        first = str(e).strip().splitlines()[0] if str(e).strip() else "unknown"
        ewhy = (f"config_set cannot edit this file: {first[:140]}. Fix it in "
                f"git first — the editor rewrites single lines and will not "
                f"guess at a document it cannot model.")
    warnings = repo.lint(text)
    head = gitrepo.head_info(pid, rgid, env_name=a["env"])
    doc = {"project": proj.get("name"), "region": rg.get("name"),
           "env": a["env"], "service": repo.display(pid, fname),
           "file": repo.rel_path(pid, rgid, a["env"], fname),
           "branch": head.get("branch"), "head": head.get("head"),
           "uncommitted_in_repo": bool(head.get("dirty")),
           "editable": editable, "problem": why or ewhy,
           "warnings": warnings, "values": rows, "yaml": text[:60000]}
    bits = [f"{len(rows)} value(s) in {repo.display(pid, fname)} · "
            f"{a['env']} · {rg.get('name')} (branch {head.get('branch')})"]
    if warnings:
        bits.append("⚠ " + "; ".join(warnings))
    if doc["problem"]:
        bits.append("⚠ " + doc["problem"])
    return {"summary": " — ".join(bits),
            "detail": json.dumps(doc, indent=2), "doc": doc,
            "target": f"{rg.get('name')}/{a['env']}/{repo.display(pid, fname)}"}


def _config_pull(user, a, ip):
    from . import gitrepo
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    # one pull per DISTINCT checkout — a region can span repositories and
    # branches, and a monorepo shared by four environments is one fetch
    done, seen, errs, first = [], set(), [], ""
    for env in sorted(store.env_sources(pid, rgid)):
        b = repo.binding(pid, rgid, env)
        key = str(repo.checkout(pid, rgid, env))
        if not b["url"] or key in seen:
            continue
        seen.add(key)
        first = first or env
        try:
            done.append(f"{env}: {gitrepo.sync_env(pid, rgid, env)}")
        except gitrepo.GitError as e:
            errs.append(f"{env}: {e}")
    if errs and not done:
        raise Denied("; ".join(errs)[:300])
    if not done and not errs:
        raise Denied("no environment in this region names a repository — "
                     "declare one with env_declare first")
    head = gitrepo.head_info(pid, rgid, env_name=first)
    return {"summary": "; ".join(done)[:160] or "up to date",
            "detail": f"branch {head.get('branch')} at {head.get('head')}"
                      + (" — the working copy has uncommitted edits"
                         if head.get("dirty") else "")
                      + ("".join(f"\nFAILED {e}" for e in errs)),
            "target": f"{proj.get('name')}/{rg.get('name')}"}


def _config_set(user, a, ip):
    from . import repo
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    fname = _find_service(pid, rgid, a["env"], a["service"])
    edits = a.get("changes")
    if not isinstance(edits, list) or not edits:
        raise Denied("changes must be a non-empty list of "
                     '{"path": ["image","tag"], "value": "1.2.3"}')
    from . import values as _values
    wanted = {}
    for i, e in enumerate(edits, 1):
        if not isinstance(e, dict) or "path" not in e or "value" not in e:
            raise Denied(f"change #{i} needs a path and a value")
        raw = e["path"]
        # A path is a LIST of segments, never a dotted string: values files are
        # full of keys like `app.name`, and splitting on dots addresses a
        # different node. config_read hands back exactly this shape.
        if isinstance(raw, str):
            raise Denied(f"change #{i}: path must be a list of segments like "
                         f'["image","tag"], not a dotted string — keys here '
                         f"contain dots")
        if not isinstance(raw, list) or not raw:
            raise Denied(f"change #{i}: path must be a non-empty list")
        wanted[_values.encode(raw)] = str(e["value"])
    try:
        changed = repo.save_value_changes(pid, rgid, a["env"], fname, wanted)
    except Exception as e:                                    # noqa: BLE001
        # A ruamel traceback is not an answer. The common cause is a file the
        # line editor cannot model — a duplicate key — and the reader needs the
        # key, not the stack.
        first = str(e).strip().splitlines()[0] if str(e).strip() else str(e)
        hints = repo.lint(repo.values_path(pid, rgid, a["env"],
                                           fname).read_text())
        raise Denied(f"could not edit that file: {first[:160]}"
                     + (f" — {'; '.join(hints)}" if hints else "")
                     + ". Fix it in git first.") from e
    where = f"{rg.get('name')}/{a['env']}/{repo.display(pid, fname)}"
    if not changed:
        return {"summary": "nothing changed — every value already said that",
                "detail": "", "target": where}
    return {"summary": f"{len(changed)} value(s) changed in the working copy",
            "detail": "\n".join(changed)
                      + "\n\nNOT committed yet — config_commit pushes it.",
            "target": where}


def _config_add(user, a, ip):
    from . import repo, values as _values
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    fname = _find_service(pid, rgid, a["env"], a["service"])
    parent = a.get("parent")
    if isinstance(parent, str):
        raise Denied('parent must be a list of segments, e.g. ["resources"], '
                     "or omitted for the top level")
    try:
        note = repo.add_value(pid, rgid, a["env"], fname,
                              _values.encode(parent) if parent else "",
                              a["key"], str(a["value"]))
    except Exception as e:                                    # noqa: BLE001
        raise Denied(str(e)[:200]) from e
    return {"summary": note or "added",
            "detail": "NOT committed yet — config_commit pushes it.",
            "target": f"{rg.get('name')}/{a['env']}/{repo.display(pid, fname)}"}


def _config_commit(user, a, ip):
    from . import gitrepo, repo
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    fname = _find_service(pid, rgid, a["env"], a["service"])
    rel = repo.rel_path(pid, rgid, a["env"], fname)
    if not (a.get("message") or "").strip():
        raise Denied("a commit message is required — say what changed and why")
    try:
        conf = gitrepo.env_repo(pid, rgid, a["env"])
        got = gitrepo.commit_and_push(
            pid, rgid, conf, [rel],
            message=a["message"], new_branch=(a.get("branch") or "").strip(),
            author=auth.git_author(user or {}), env_name=a["env"])
    except gitrepo.GitError as e:
        raise Denied(str(e)[:300]) from e
    link = gitrepo.commit_url(conf.get("url", ""), got.get("sha", ""))
    return {"summary": (f"already pushed — {got.get('sha')} is on "
                        f"{got.get('branch')}" if got.get("noop") else
                        f"pushed {got.get('sha')} to {got.get('branch')}"),
            "detail": (f"{rel}\n{link}" if link else rel)
                      + "\n\nWhatever reconciles this repository will pick it "
                        "up on its own schedule; gitops_sync makes Argo CD look "
                        "now.",
            "target": f"{rg.get('name')}/{a['env']}/{repo.display(pid, fname)}"}


def _gitops_conn(which: str) -> dict:
    """A controller by id OR by name — a model reading the estate briefing has
    the name, and making it guess an id it was never shown is a wasted turn."""
    for c in store.all_gitops():
        if which in (c.get("id"), c.get("name")):
            return c
    raise Denied("no such GitOps controller — call `connections` for the names")


def _projects_now() -> dict:
    return store.projects()


def _find_project(which: str) -> tuple[str, dict]:
    """A project by id or by name — a model that just read the config has the
    name, and making it map that back to an id it was never shown is a wasted
    turn and a wrong guess waiting to happen."""
    for pid, p in _projects_now().items():
        if which in (pid, p.get("name")):
            return pid, p
    raise Denied("no such project — call portal_config for the ids and names")


def _find_cluster(pid: str, proj: dict, which: str) -> tuple[str, dict]:
    for cid, c in (proj.get("clusters") or {}).items():
        if which in (cid, c.get("name"), c.get("context")):
            return cid, c
    raise Denied(f"no such cluster in {proj.get('name')} — call portal_config")


def _servers_in_portal(skip_cid: str = "") -> dict:
    """{api server url: "project/cluster"} for everything already registered.

    Read out of the stored kubeconfigs rather than a column, because the server
    is not one: it lives in the file the portal wrote. This is the half of the
    duplicate check a name comparison cannot do — the same cluster under a
    second context name.
    """
    import pathlib

    import yaml
    out = {}
    for _pid, p in _projects_now().items():
        for _cid, c in (p.get("clusters") or {}).items():
            if _cid == skip_cid:
                continue
            kf = c.get("kubeconfig_file") or ""
            if not (kf and pathlib.Path(kf).exists()):
                continue
            try:
                doc = yaml.safe_load(pathlib.Path(kf).read_text()) or {}
            except (yaml.YAMLError, OSError):
                continue
            for k in doc.get("clusters") or []:
                srv = (k.get("cluster") or {}).get("server")
                if srv:
                    out[srv] = f"{p.get('name')}/{c.get('name')}"
    return out


def _portal_config(user, a, ip):
    import pathlib

    import yaml
    doc = []
    servers = _servers_in_portal()
    inv = {v: k for k, v in servers.items()}
    for pid, p in _projects_now().items():
        doc.append({
            "project": pid, "name": p.get("name"), "icon": p.get("icon"),
            "regions": [{"region": rgid, "name": rg.get("name"),
                         "environments": rg.get("env_clusters") or {}}
                        for rgid, rg in (p.get("regions") or {}).items()],
            "clusters": [{"cluster": cid, "name": c.get("name"),
                          "context": c.get("context"),
                          "server": inv.get(f"{p.get('name')}/{c.get('name')}",
                                            ""),
                          "manageable": bool(kmanage.writable(c))}
                         for cid, c in (p.get("clusters") or {}).items()],
        })
    return {"summary": f"{len(doc)} project(s), "
                       f"{sum(len(d['clusters']) for d in doc)} cluster(s)",
            "detail": json.dumps(doc, indent=2), "doc": doc,
            "target": "portal configuration"}


def _project_create(user, a, ip):
    name = a["name"].strip()
    for pid, p in _projects_now().items():
        if (p.get("name") or "").casefold() == name.casefold():
            raise Denied(f"a project called {p['name']!r} already exists "
                         f"({pid}) — registering into it needs no new project")
    pid = store.add_project(name, icon=a.get("icon") or "📦")
    return {"summary": f"project {name} created", "detail": f"id {pid}",
            "target": name}


def _project_delete(user, a, ip):
    pid, proj = _find_project(a["project"])
    if a.get("confirm", "").strip() != proj.get("name"):
        raise Denied(f"deleting a project takes every cluster, region and "
                     f"environment mapping in it — type its exact name "
                     f"({proj.get('name')}) to confirm")
    n = len(proj.get("clusters") or {})
    store.delete_project(pid)
    return {"summary": f"project {proj.get('name')} deleted",
            "detail": f"{n} cluster registration(s) went with it",
            "target": proj.get("name")}


def _read_kubeconfig(raw: str, want_ctx: str = "") -> tuple[str, str]:
    """(context, server) for a kubeconfig, or a refusal saying what is wrong.

    THE ONE validator, shared by registering and replacing: a file the two
    accepted differently would be a file that registers and then cannot be
    updated, or the reverse.
    """
    import yaml
    try:
        doc = yaml.safe_load(raw) or {}
    except yaml.YAMLError as e:
        raise Denied(f"that kubeconfig is not valid YAML: {str(e)[:120]}") from e
    if not isinstance(doc, dict) or not doc.get("clusters"):
        raise Denied("that kubeconfig has no clusters in it")
    ctxs = [c.get("name") for c in doc.get("contexts") or []]
    context = (want_ctx or "").strip() or (ctxs[0] if ctxs else "")
    if not context:
        raise Denied("the kubeconfig has no context, and none was named")
    if ctxs and context not in ctxs:
        raise Denied(f"context {context!r} is not in that kubeconfig — it has "
                     f"{', '.join(str(c) for c in ctxs)}")
    server = ""
    for k in doc.get("clusters") or []:
        server = (k.get("cluster") or {}).get("server") or server
    # Nothing may point at a file on this machine: the portal keeps its own copy
    # and runs somewhere else.
    for k in doc.get("clusters") or []:
        if "certificate-authority" in (k.get("cluster") or {}):
            raise Denied("that kubeconfig references a CA file on disk — "
                         "flatten it first (kubectl config view --flatten)")
    for us in doc.get("users") or []:
        holder = us.get("user") or {}
        for key in ("client-certificate", "client-key", "tokenFile"):
            if key in holder:
                raise Denied(f"that kubeconfig references {key} as a file on "
                             f"disk — flatten it first")
        if "exec" in holder:
            raise Denied("that kubeconfig authenticates with an exec plugin, "
                         "which will not be available where the portal runs")
    return context, server


def _clashes(context: str, server: str, skip_cid: str = "") -> None:
    """Refuse a context or server already spoken for by a DIFFERENT cluster.

    `skip_cid` is how a replacement avoids colliding with itself — the whole
    point of an in-place update is that the cluster keeps its identity.
    """
    for _opid, op in _projects_now().items():
        for ocid, oc in (op.get("clusters") or {}).items():
            if ocid == skip_cid:
                continue
            if oc.get("context") == context:
                raise Denied(f"context {context!r} is already registered as "
                             f"{op.get('name')}/{oc.get('name')} — not added "
                             f"again")
    if server:
        for srv, where in _servers_in_portal(skip_cid).items():
            if srv == server:
                raise Denied(f"{server} is already registered as {where}, under "
                             f"a different context name — not added again")


def _cluster_add(user, a, ip):
    pid, proj = _find_project(a["project"])
    context, server = _read_kubeconfig(a["kubeconfig"], a.get("context", ""))
    _clashes(context, server)
    name = (a.get("name") or "").strip() or context
    cid = store.add_cluster(pid, name, a["kubeconfig"], context)
    # Everything the portal's own form does, in one call: the cluster, the
    # environment it serves, and where that environment's values live. A client
    # that has to make three calls to describe one cluster is a client that
    # makes two of them and forgets the third.
    serves = ""
    if a.get("region") and a.get("env"):
        note = _env_declare(user, {**a, "gitops_repo": a.get("gitops_repo", ""),
                                   "branch": a.get("branch", ""),
                                   "path": a.get("path", "")}, ip)
        _env_map(user, {**a, "cluster": cid}, ip)
        serves = f"\nserves {a['region']}/{a['env']} — {note['summary']}"
    return {"summary": f"{name} registered in {proj.get('name')}"
                       + (f", serving {a['env']}" if serves else ""),
            "detail": f"cluster id {cid}, context {context}"
                      + (f", server {server}" if server else "")
                      + ". Management is OFF: it is read-only until somebody "
                        "ticks it." + serves,
            "target": f"{proj.get('name')}/{name}"}


def _cluster_update(user, a, ip):
    """Replace a registered cluster's kubeconfig in place.

    IN PLACE is the point. Deleting and re-adding would work, but it mints a new
    cluster id — and `delete_cluster` drops every environment mapped to the old
    one, so a stale credential would cost the region wiring as collateral. A
    kubeconfig going stale is routine; losing the environment map to fix it is
    not.
    """
    pid, proj = _find_project(a["project"])
    cid, c = _find_cluster(pid, proj, a["cluster"])
    context, server = _read_kubeconfig(a["kubeconfig"], a.get("context", ""))
    _clashes(context, server, skip_cid=cid)
    was_ctx = c.get("context") or ""
    store.write_cluster_files(pid, cid, a["kubeconfig"])
    fields = {}
    if context != was_ctx:
        fields["context"] = context
    if (a.get("name") or "").strip():
        fields["name"] = a["name"].strip()
    if fields:
        store.update_cluster(pid, cid, **fields)
    moved = (f", endpoint now {server}" if server else "")
    return {"summary": f"{c.get('name')} re-credentialled",
            "detail": (f"kubeconfig replaced; cluster id {cid} kept, so every "
                       f"environment mapped to it still points here"
                       + (f"; context {was_ctx} → {context}"
                          if context != was_ctx else "")
                       + moved),
            "target": f"{proj.get('name')}/{c.get('name')}"}


def _cluster_delete(user, a, ip):
    pid, proj = _find_project(a["project"])
    cid, c = _find_cluster(pid, proj, a["cluster"])
    if a.get("confirm", "").strip() != c.get("name"):
        raise Denied(f"type the cluster's exact name ({c.get('name')}) to "
                     f"confirm — this also drops any environment mapped to it")
    store.delete_cluster(pid, cid)
    return {"summary": f"{c.get('name')} removed from {proj.get('name')}",
            "detail": "its kubeconfig file was deleted too",
            "target": f"{proj.get('name')}/{c.get('name')}"}


def _cluster_management(user, a, ip):
    pid, proj = _find_project(a["project"])
    cid, c = _find_cluster(pid, proj, a["cluster"])
    on = bool(a.get("allow"))
    # Always a typed name, in both directions. This tick is one of the three
    # gates that stand between an assistant and a production cluster, and
    # flipping it is the one change here that widens what everything else may
    # do — so it is confirmed like the change it is.
    if a.get("confirm", "").strip() != c.get("name"):
        raise Denied(f"turning management {'on' if on else 'off'} for "
                     f"{c.get('name')} decides whether anything may change that "
                     f"cluster — type its exact name to confirm")
    store.update_cluster(pid, cid, manage="1" if on else "")
    return {"summary": f"management {'ENABLED' if on else 'disabled'} for "
                       f"{c.get('name')}",
            "detail": "Somebody still needs the Cluster management area, and a "
                      "production cluster still wants its name typed per "
                      "action." if on else "It is read-only again.",
            "target": f"{proj.get('name')}/{c.get('name')}"}


def _region_create(user, a, ip):
    pid, proj = _find_project(a["project"])
    name = a["name"].strip()
    for rgid, rg in (proj.get("regions") or {}).items():
        if (rg.get("name") or "").casefold() == name.casefold():
            raise Denied(f"{proj.get('name')} already has a region called "
                         f"{rg['name']!r} ({rgid})")
    rgid = store.add_region(pid, name, flag=a.get("flag", ""),
                            label=a.get("label", ""))
    return {"summary": f"region {name} added to {proj.get('name')}",
            "detail": f"id {rgid}", "target": f"{proj.get('name')}/{name}"}


def _env_declare(user, a, ip):
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    env = a["env"].strip()
    if not env or "/" in env:
        raise Denied("an environment name is one path segment — no slashes")
    path = (a.get("path") or "").strip().strip("/")
    if ".." in path.split("/"):
        raise Denied("that path leaves the repository")
    url = (a.get("gitops_repo") or "").strip()
    if url and not (url.startswith(("http://", "https://", "ssh://", "/"))
                    or ("@" in url and ":" in url)):
        raise Denied("that does not look like a repository address")
    bind = {"url": url, "branch": (a.get("branch") or "").strip(), "path": path,
            "protocol": (a.get("protocol") or "").strip(),
            "username": (a.get("username") or "").strip()}
    # write-only, exactly as the form is: absent means keep whatever is stored
    if a.get("secret"):
        bind["secret"] = a["secret"]
    displaced = store.set_env_source(pid, rgid, env, bind)
    b = repo.binding(pid, rgid, env)
    fetched = ""
    if gitrepo.fetch_needed(pid, rgid, env, url, bind["branch"]):
        try:
            fetched = gitrepo.sync_env(pid, rgid, env)
        except gitrepo.GitError as e:
            raise Denied(f"declared, but its repository could not be read: {e}")
    files = repo.env_files(pid, rgid, env, include_hidden=True)
    return {"summary": f"{env} declared at {b['path'] or 'the repository root'}"
                       + (f" on {b['branch']}" if b["branch"] else "")
                       + f" — {len(files)} values file(s)",
            "detail": (f"repository {gitrepo.redact(b['url'])}"
                       + (f" (branch {b['branch']})" if b["branch"] else "")
                       + "\n" if b["url"] else
                       "no repository — it copies the region's shared one only "
                       "when every other environment here agrees on one\n")
                      + ("authenticates with stored credentials\n"
                         if b["has_own_auth"] else "")
                      + (f"{fetched}\n" if fetched else "")
                      + (f"displaced {displaced}, which pointed at the same "
                         f"files\n" if displaced else "")
                      + ("\n".join(files[:20]) if files else "no values files there yet"),
            "target": f"{proj.get('name')}/{rg.get('name', rgid)}/{env}"}


def _env_undeclare(user, a, ip):
    pid, rgid, proj, rg = _find_region(a["project"], a["region"])
    env = a["env"].strip()
    if env not in store.env_sources(pid, rgid):
        raise Denied("that environment is not declared in this region — call "
                     "config_files for the names")
    store.drop_env_source(pid, rgid, env)
    return {"summary": f"{env} is no longer declared",
            "detail": "nothing in the repository was touched",
            "target": f"{proj.get('name')}/{rg.get('name', rgid)}/{env}"}


def _env_map(user, a, ip):
    pid, proj = _find_project(a["project"])
    rgid = None
    for rid, rg in (proj.get("regions") or {}).items():
        if a["region"] in (rid, rg.get("name")):
            rgid = rid
            break
    if not rgid:
        raise Denied("no such region in that project — call portal_config")
    cid = ""
    if a.get("cluster"):
        cid, _c = _find_cluster(pid, proj, a["cluster"])
    store.map_env_cluster(pid, rgid, a["env"].strip(), cid)
    return {"summary": f"{a['env']} → "
                       + (a.get("cluster") or "(unmapped)"),
            "detail": "", "target": f"{proj.get('name')}/{a['env']}"}


CATALOGUE: dict[str, dict] = {
    # ── troubleshooting: changes nothing, so a read-only token gets it ──
    "kubectl_read": {
        "label": "Read anything in a cluster with kubectl",
        "needs": ["clusters"], "changes": False,
        "help": "Run a READ-ONLY kubectl command — get, describe, logs, top, "
                "events, explain. Anything that would change the cluster is "
                "refused by the same classifier the portal's own console uses. "
                "This is the troubleshooting tool: describe a failing pod, read "
                "its logs, look at events in a namespace.",
        "args": {
            "project": {"required": True, "help": "project id, from `clusters`"},
            "cluster": {"required": True, "help": "cluster id, from `clusters`"},
            "command": {"required": True,
                        "help": "the kubectl command WITHOUT the word kubectl, "
                                "e.g. `describe pod web-7d9 -n dev` or "
                                "`logs deploy/api -n dev --tail=200`"},
        },
        "run": _kubectl_read,
    },
    "ansible_run_output": {
        "label": "Read a playbook run's output",
        "needs": ["ansible"], "changes": False,
        "help": "The status and captured output of one Ansible run.",
        "args": {"run": {"required": True, "help": "run id, e.g. ar-…"}},
        "run": _ansible_run_output,
    },
    "terraform_run_output": {
        "label": "Read a Terraform run's output",
        "needs": ["terraform"], "changes": False,
        "help": "The status and captured output of one Terraform run.",
        "args": {"run": {"required": True, "help": "run id, e.g. tr-…"}},
        "run": _terraform_run_output,
    },

    # ── changes ──
    "cluster_action": {
        "label": "Do one of the fixed things to a Kubernetes object",
        "needs": ["manage"], "changes": True, "audit": "cluster_action",
        "help": "Restart a workload, cordon or drain a node, scale a "
                "deployment, delete a pod — whatever `list_actions` reports. "
                "The command is built from the catalogue, never composed.",
        "args": {
            "project": {"required": True, "help": "project id"},
            "cluster": {"required": True, "help": "cluster id"},
            "action": {"required": True,
                       "help": "one action name from list_actions"},
            "args": {"kind": "object",
                     "help": "the named arguments that action needs — kind, "
                             "namespace, name, node, replicas"},
            "confirm": {"help": "for a production cluster, its exact name"},
        },
        "run": _cluster_action,
    },
    "ansible_add_host": {
        "label": "Add a host to an inventory group",
        "needs": ["ansible"], "changes": True,
        "help": "Put a machine in an Ansible group so playbooks can run "
                "against it. Call `ansible` first for the group ids.",
        "args": {
            "group": {"required": True, "help": "group id, from `ansible`"},
            "name": {"required": True, "help": "inventory name"},
            "address": {"required": True, "help": "IP or resolvable host name"},
            "ssh_user": {"help": "overrides the group's user"},
            "ssh_port": {"help": "overrides the group's port"},
            "host_vars": {"help": "YAML host_vars for this host alone"},
            "env": {"help": "environment label: dev, uat, prod…"},
        },
        "run": _ansible_add_host,
    },
    "ansible_run": {
        "label": "Run a playbook against a group",
        # Two areas: seeing Ansible and being allowed to run it. `ansible_run`
        # is escalating for a reason — a playbook is arbitrary code on every
        # host in the group, as whatever user it connects as.
        "needs": ["ansible", "ansible_run"], "changes": True,
        "help": "Starts a run and returns its id; read the output with "
                "ansible_run_output. A CHECK run (the default) changes nothing "
                "on the hosts. A real run needs the installation's Ansible "
                "switch on, and a production group's name typed by the person.",
        "args": {
            "playbook": {"required": True, "help": "playbook id, from `ansible`"},
            "group": {"required": True, "help": "group id"},
            "check": {"kind": "bool",
                      "help": "true (default) for a dry run; false is REAL"},
            "limit_to": {"help": "an --limit pattern"},
            "tags": {"help": "comma-separated tags"},
            "extra_vars": {"help": "a JSON object as a string"},
            "confirm": {"help": "for a production group, its exact name"},
        },
        "run": _ansible_run,
    },
    "provision_vm": {
        "label": "Generate a VM stack (Proxmox)",
        "needs": ["terraform"], "changes": True,
        "help": "Turns a VM specification into a Terraform stack — it creates "
                "NOTHING by itself; you then plan and apply it with "
                "terraform_run, which is a separate grant. Pass `spec` as the "
                "wizard sends it: {os, connection, nodes:[{hostname, node, ip, "
                "cores, memory, disk}], network:{gateway, dns[]}, "
                "stack_name, notes}. Anything missing comes back as a plain "
                "refusal naming the field.",
        "args": {"spec": {"required": True, "kind": "object",
                          "help": "the VM specification"}},
        "run": _provision_vm,
    },
    "terraform_run": {
        "label": "Run Terraform on a stack",
        "needs": ["terraform", "terraform_apply"], "changes": True,
        "help": "init, plan, apply or destroy. Even a plan runs the provider's "
                "code with the stack's credential, which is why this is its own "
                "grant. apply/destroy also need the installation's Terraform "
                "switch on and a production stack's name typed.",
        "args": {
            "stack": {"required": True, "help": "stack id, from the stacks list"},
            "action": {"required": True,
                       "help": "init | plan | apply | destroy"},
            "confirm": {"help": "for a production stack, its exact name"},
        },
        "run": _terraform_run,
    },
    "cert_request": {
        "label": "Request a TLS certificate",
        "needs": ["certs"], "changes": True,
        "help": "Opens an ACME order and works out what has to be proved. It "
                "accepts the CA's subscriber agreement on the operator's "
                "behalf, so ASK THE PERSON before passing agreed: true. The "
                "DNS records to publish appear on the Certificates page.",
        "args": {
            "domains": {"required": True,
                        "help": "one name, or several separated by space/comma"},
            "ca": {"help": "le (Let's Encrypt, default) | le-staging | custom"},
            "email": {"help": "account contact address"},
            "key_type": {"help": "rsa2048 (default) | rsa4096 | ec256 | ec384"},
            "agreed": {"kind": "bool", "required": True,
                       "help": "true only once a person has agreed"},
        },
        "run": _cert_request,
    },
    "gitops_sync": {
        "label": "Sync a GitOps application",
        "needs": ["gitops"], "changes": True,
        "help": "Applies git to the cluster through the controller. `dry_run` "
                "reports what would change without doing it; `prune` deletes "
                "objects git no longer declares.",
        "args": {
            "controller": {"required": True, "help": "controller id or name"},
            "application": {"required": True, "help": "application name"},
            "dry_run": {"kind": "bool", "help": "describe, change nothing"},
            "prune": {"kind": "bool",
                      "help": "also delete what git no longer declares"},
            "revision": {"help": "a specific revision, else the target"},
        },
        "run": _gitops_sync,
    },
    # ── the values files: the portal's actual job ──
    # Reading and editing a service's values, then committing it. This was the
    # largest gap: the portal exists to manage these files, and an assistant
    # that could read the whole estate but not change a single value could not
    # do the work the pages are for.
    "config_files": {
        "label": "List the values files",
        "needs": ["config"], "changes": False,
        "help": "Every region, its repository and branch, whether the working "
                "copy has uncommitted edits, and every environment with the "
                "services in it. Read this first — the names the other config "
                "verbs take are here.",
        "args": {"project": {"help": "narrow to one project"},
                 "region": {"help": "narrow to one region"}},
        "run": _config_files,
    },
    "config_read": {
        "label": "Read a service's values file",
        "needs": ["config"], "changes": False,
        "help": "The whole file as YAML, plus every scalar value flattened with "
                "the exact PATH to send back to config_set. Also says which "
                "branch the working copy is on and whether it already has "
                "uncommitted edits — worth knowing before adding more.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            "region": {"required": True, "help": "region id or name"},
            "env": {"required": True, "help": "dev | uat | preprod | prod…"},
            "service": {"required": True,
                        "help": "the service name as config_files reports it"},
        },
        "run": _config_read,
    },
    "config_pull": {
        "label": "Refresh a region's working copy from git",
        "needs": ["config"], "changes": False,
        "help": "Clones or fast-forwards the local copy the portal edits. "
                "Changes nothing in git and nothing in a cluster — but do it "
                "before reading if somebody else may have pushed.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "region": {"required": True, "help": "region id or name"}},
        "run": _config_pull,
    },
    "config_set": {
        "label": "Change values in a file",
        "needs": ["config"], "changes": True,
        "help": "Edits existing values in the working copy — nothing is pushed "
                "until config_commit. `changes` is a list of "
                "{path, value}, where PATH IS A LIST of segments exactly as "
                "config_read reported it: [\"image\",\"tag\"], never "
                "\"image.tag\" — keys in these files contain dots, so a "
                "dotted string addresses a different node. Comments, ordering "
                "and formatting elsewhere in the file are left alone.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            "region": {"required": True, "help": "region id or name"},
            "env": {"required": True, "help": "environment"},
            "service": {"required": True, "help": "service name"},
            "changes": {"required": True, "kind": "list",
                        "help": 'e.g. [{"path":["image","tag"],'
                                '"value":"1.4.2"}]'},
        },
        "run": _config_set,
    },
    "config_add": {
        "label": "Add a value that is not in the file yet",
        "needs": ["config"], "changes": True,
        "help": "Adds one key. `key` may be dotted — resources.limits.cpu — and "
                "any level the file lacks is created. `parent` is a list of "
                "segments, or omitted for the top level. Not pushed until "
                "config_commit.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            "region": {"required": True, "help": "region id or name"},
            "env": {"required": True, "help": "environment"},
            "service": {"required": True, "help": "service name"},
            "parent": {"kind": "list",
                       "help": 'where to put it, e.g. ["resources"]'},
            "key": {"required": True, "help": "the new key, may be dotted"},
            "value": {"required": True, "help": "its value"},
        },
        "run": _config_add,
    },
    "config_commit": {
        "label": "Commit and push a values file",
        "needs": ["config"], "changes": True,
        "help": "Stages just this file, commits it with your identity as the "
                "author, and pushes — verifying it landed on the remote. Give a "
                "message that says what changed and why; a branch name puts it "
                "on a new branch instead of the current one. This is the point "
                "of no quiet return: whatever reconciles the repository will "
                "act on it.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            "region": {"required": True, "help": "region id or name"},
            "env": {"required": True, "help": "environment"},
            "service": {"required": True, "help": "service name"},
            "message": {"required": True, "help": "the commit message"},
            "branch": {"help": "commit to a NEW branch instead of the current "
                               "one — safer on a protected main"},
        },
        "run": _config_commit,
    },

    # ── the portal's own configuration ──
    # `settings` for all of it: that area already means "may hold credentials
    # and change how this portal is wired", which is exactly what these do.
    "portal_config": {
        "label": "Read the portal's own configuration",
        "needs": ["settings"], "changes": False,
        "help": "Every project with its id, its regions and their environment "
                "mappings, and every registered cluster with its context, its "
                "API server and whether management is on. This is what to read "
                "BEFORE registering anything — the ids the other configuration "
                "verbs take are here, and so is the answer to "
                "“is it already registered?”",
        "args": {}, "run": _portal_config,
    },
    "project_create": {
        "label": "Create a project",
        "needs": ["settings"], "changes": True,
        "help": "A project is the top of the portal's structure: clusters, "
                "regions and environments hang off one. Refuses a name that "
                "already exists rather than making a second project people "
                "then have to tell apart.",
        "args": {"name": {"required": True, "help": "what to call it"},
                 "icon": {"help": "one emoji, default 📦"}},
        "run": _project_create,
    },
    "project_delete": {
        "label": "Delete a project",
        "needs": ["settings"], "changes": True, "destructive": True,
        "help": "Takes every cluster registration, region and environment "
                "mapping in it. Needs the project's exact name typed.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "confirm": {"required": True,
                             "help": "the project's exact name"}},
        "run": _project_delete,
    },
    "cluster_add": {
        "label": "Register a Kubernetes cluster",
        "needs": ["settings"], "changes": True,
        "help": "Adds a cluster to a project from a kubeconfig you pass as "
                "text. Pass ONE context's worth — split a multi-context file "
                "first (kubectl config view --minify --flatten --context=X) so "
                "a credential for one cluster is never handed to another. "
                "REFUSES A DUPLICATE by context name and by API server URL, so "
                "calling it twice cannot register the same cluster twice. "
                "Management is off on arrival: the cluster is read-only until "
                "somebody turns it on deliberately. Pass `region` and `env` "
                "(and optionally `gitops_repo`, `branch`, `path`) to declare "
                "what it serves and where that environment's values live in the "
                "SAME call — which is the whole registration in one step.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            # `secret` keeps it out of the audit line and out of anything
            # this module echoes back: it is a live credential, and the audit
            # log is append-only.
            "kubeconfig": {"required": True, "secret": True,
                           "help": "the kubeconfig YAML, self-contained — no "
                                   "file references, no exec plugins"},
            "context": {"help": "which context; defaults to the file's only one"},
            "name": {"help": "display name; defaults to the context name"},
            # the whole registration in one call — see env_declare for what
            # these mean, they are the same fields
            "region": {"help": "region id or name; with `env`, declares what "
                               "this cluster serves in the same call"},
            "env": {"help": "the environment it serves — dev, uat, prod…"},
            "path": {"help": "path to that environment's values from the "
                             "repository root"},
            "gitops_repo": {"help": "its GitOps repository; blank inherits the "
                                    "region's"},
            "branch": {"help": "its GitOps branch; blank inherits the region's"},
        },
        "run": _cluster_add,
    },
    "cluster_update": {
        "label": "Replace a cluster's kubeconfig",
        "needs": ["settings"], "changes": True,
        "help": "Swaps in a fresh kubeconfig for a cluster ALREADY registered — "
                "for expired credentials, or an endpoint that moved (a Rancher "
                "proxy replaced by the API server's own address). Keeps the "
                "cluster's id, so every environment mapped to it still points "
                "at it; delete-and-re-add would silently drop those. Validated "
                "and duplicate-checked exactly like cluster_add, except against "
                "itself.",
        "args": {
            "project": {"required": True, "help": "project id or name"},
            "cluster": {"required": True,
                        "help": "cluster id, current name or current context"},
            "kubeconfig": {"required": True, "secret": True,
                           "help": "the replacement kubeconfig YAML"},
            "context": {"help": "which context in it; defaults to its only one"},
            "name": {"help": "rename it at the same time; omit to keep"},
        },
        "run": _cluster_update,
    },
    "cluster_delete": {
        "label": "Remove a cluster registration",
        "needs": ["settings"], "changes": True, "destructive": True,
        "help": "Removes the cluster from the portal and deletes its stored "
                "kubeconfig. Nothing happens to the cluster itself. Needs its "
                "exact name typed.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "cluster": {"required": True,
                             "help": "cluster id, name or context"},
                 "confirm": {"required": True,
                             "help": "the cluster's exact name"}},
        "run": _cluster_delete,
    },
    "cluster_management": {
        "label": "Turn a cluster's management on or off",
        "needs": ["settings"], "changes": True,
        "help": "The per-cluster tick that decides whether ANYTHING may change "
                "that cluster — one of the three gates in front of every "
                "cluster action. Needs the cluster's exact name typed in both "
                "directions, because turning it on is what widens everything "
                "else.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "cluster": {"required": True, "help": "cluster id or name"},
                 "allow": {"kind": "bool", "required": True,
                           "help": "true to permit changes, false for "
                                   "read-only"},
                 "confirm": {"required": True,
                             "help": "the cluster's exact name"}},
        "run": _cluster_management,
    },
    "region_create": {
        "label": "Add a region to a project",
        "needs": ["settings"], "changes": True,
        "help": "A region holds a git repository and the environment → cluster "
                "mapping for one place. Refuses a duplicate name within the "
                "project.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "name": {"required": True, "help": "e.g. Kenya, UAE"},
                 "flag": {"help": "one emoji"},
                 "label": {"help": "a short label"}},
        "run": _region_create,
    },
    "env_declare": {
        "label": "Declare an environment and where its values live",
        "needs": ["settings"], "changes": True,
        "help": "Says that an environment EXISTS and where its GitOps values "
                "are: repository, branch, path. This is the portal's source of "
                "truth for environments — nothing is discovered by scanning a "
                "repository, so an environment nobody declared does not exist "
                "and one that is declared exists even before its first values "
                "file is committed. Leave the repository and branch out to "
                "inherit the region's, which is the usual case; fill them in "
                "for an environment on its own branch or in its own "
                "repository, which is the case one repository per region could "
                "never express. Clones it when it has its own repository, so "
                "the answer to 'where are its values' is never an empty "
                "directory. Declaring B where A already points undeclares A: "
                "the same files under two names is a list nobody can trust.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "region": {"required": True, "help": "region id or name"},
                 "env": {"required": True,
                         "help": "one path segment — dev, uat, preprod, prod"},
                 "path": {"help": "path to its values FROM THE REPOSITORY ROOT "
                                  "— e.g. deploy/ke/preprod. Blank means "
                                  "<the region's values path>/<env>."},
                 "gitops_repo": {"help": "repository URL; blank inherits the "
                                         "region's"},
                 "branch": {"help": "branch; blank inherits the region's"},
                 # Credentials for THIS environment's repository, for the case
                 # the region's cannot reach it (a different host). Blank
                 # inherits the region's, which is the ordinary answer.
                 "protocol": {"help": "https | ssh — how to authenticate to "
                                      "this environment's own repository; "
                                      "blank inherits the region's"},
                 "username": {"help": "username for that repository; blank "
                                      "inherits the region's"},
                 # `secret` so it never reaches the append-only audit log
                 "secret": {"secret": True,
                            "help": "password/token for that repository. Blank "
                                    "KEEPS whatever is stored — it never "
                                    "clears it. Inherits the region's when the "
                                    "environment has none of its own."}},
        "run": _env_declare,
    },
    "env_undeclare": {
        "label": "Forget an environment",
        "needs": ["settings"], "changes": True,
        "help": "Removes an environment's declaration. Nothing in any "
                "repository is touched and no cluster is changed — the portal "
                "stops listing it. Use it for something declared by mistake, "
                "or a folder that was never an environment.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "region": {"required": True, "help": "region id or name"},
                 "env": {"required": True, "help": "the environment name"}},
        "run": _env_undeclare,
    },
    "env_map": {
        "label": "Map an environment to a cluster",
        "needs": ["settings"], "changes": True,
        "help": "Says which cluster serves an environment in a region — dev, "
                "uat, preprod, prod. Pass no cluster to unmap one. This is "
                "what makes a production environment read as production.",
        "args": {"project": {"required": True, "help": "project id or name"},
                 "region": {"required": True, "help": "region id or name"},
                 "env": {"required": True, "help": "dev | uat | preprod | prod…"},
                 "cluster": {"help": "cluster id or name; omit to unmap"}},
        "run": _env_map,
    },
    "gitops_refresh": {
        "label": "Make a GitOps application re-read git",
        "needs": ["gitops"], "changes": False,
        "help": "Asks the controller to compare against git again. Nothing in "
                "the cluster changes, which is why it is not a write.",
        "args": {
            "controller": {"required": True, "help": "controller id or name"},
            "application": {"required": True, "help": "application name"},
            "hard": {"kind": "bool", "help": "discard the manifest cache too"},
        },
        "run": _gitops_refresh,
    },
}


# ── who may reach what ─────────────────────────────────────────
def available(user: dict | None, may_change: bool = True) -> list[dict]:
    """The verbs this person may use, as a model can be told about them.

    `may_change` is the credential's own ceiling — an MCP token scoped to read
    still gets the verbs that change nothing, because troubleshooting is not a
    change and a read-only client that cannot look at a pod's logs is missing
    the point.
    """
    out = []
    for name, spec in CATALOGUE.items():
        if spec["changes"] and not may_change:
            continue
        if not all(rbac.may_area(user, a) for a in spec["needs"]):
            continue
        out.append({"name": name, "label": spec["label"], "help": spec["help"],
                    "changes": spec["changes"], "needs": list(spec["needs"]),
                    "args": {k: dict(v) for k, v in spec["args"].items()}})
    return out


def _clean(spec: dict, args: dict) -> dict:
    """Named arguments only, required ones present. An argument the catalogue
    does not declare is DROPPED rather than passed on — this is where "no
    free-form calls" is actually enforced."""
    args = args if isinstance(args, dict) else {}
    out, missing = {}, []
    for key, meta in spec["args"].items():
        val = args.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            if meta.get("required"):
                missing.append(key)
            continue
        kind = meta.get("kind", "string")
        if kind == "bool":
            out[key] = val if isinstance(val, bool) else \
                str(val).strip().lower() in ("1", "true", "yes", "on")
        elif kind == "object":
            if not isinstance(val, dict):
                raise Denied(f"{key} has to be an object")
            out[key] = val
        elif kind == "list":
            if not isinstance(val, list):
                raise Denied(f"{key} has to be a list")
            out[key] = val
        else:
            out[key] = val if isinstance(val, str) else str(val)
    if missing:
        raise Denied(f"{spec['label']} needs {', '.join(missing)}")
    return out


def run(user: dict | None, name: str, args: dict, ip: str = "",
        may_change: bool = True) -> dict:
    """Do one thing, audited. Raises Denied with a sentence a person can read."""
    spec = CATALOGUE.get(name)
    if not spec:
        raise Denied(f"no such action: {name}")
    if spec["changes"] and not may_change:
        raise Denied(f"{name} changes things, and this credential may only read")
    short = [a for a in spec["needs"] if not rbac.may_area(user, a)]
    if short:
        raise Denied("your roles do not include "
                     + ", ".join(rbac.AREAS[a][0] for a in short))
    clean = _clean(spec, args)
    try:
        got = spec["run"](user, clean, ip)
    except Denied:
        # Audited on the way out: a refusal is the half of the trail that says
        # somebody's client tried to reach past what they hold.
        auth.audit(user, f"mcp_{name}_refused", _target(spec, clean), "", ip)
        raise
    if not got.get("audited"):
        auth.audit(user, spec.get("audit") or f"mcp_{name}",
                   got.get("target") or _target(spec, clean),
                   got.get("summary", "")[:200], ip)
    out = {"ok": got.get("ok", True), "action": name,
           "summary": got.get("summary", "done"),
           "detail": got.get("detail", "")}
    # A verb with structured data to hand back says so, and it travels as
    # `structuredContent` rather than only as text a model has to re-parse out
    # of its own detail string.
    if got.get("doc") is not None:
        out["doc"] = got["doc"]
    return out


def _target(spec: dict, clean: dict) -> str:
    """Something readable for the audit line when the verb did not say.

    It must never dump the arguments wholesale. `cluster_add` carries a whole
    kubeconfig, and a refused call was writing the head of it into the audit
    log — which is append-only and tamper-evident, so a credential that lands
    there cannot be taken back out. The 120-character cut happened to fall just
    before the key material; that is luck, not a design. So: named keys only,
    never one marked `secret`, and never a long value.
    """
    for key in ("application", "stack", "group", "cluster", "context",
                "domains", "run", "name", "project"):
        if clean.get(key):
            return str(clean[key])[:120]
    safe = {k: v for k, v in clean.items()
            if not spec["args"].get(k, {}).get("secret")
            and isinstance(v, str) and len(v) <= 60}
    return json.dumps(safe)[:120] if safe else spec.get("label", "")[:120]
