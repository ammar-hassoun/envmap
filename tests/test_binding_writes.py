#!/usr/bin/env python3
"""A blank clears a stored binding only in a form that SHOWED that value.

WHY THIS EXISTS
    Declare an environment with its repository, then add a cluster to serve
    it with the window's GitOps fields left blank — the first run, step for
    step — and the environment lost its repository, branch and path. The
    cluster form wrote a block whenever any of its fields was non-blank, and
    its protocol select ALWAYS posts `https`, so every block "said something"
    and its blanks went over what was stored. The regions panel's declare form
    and the MCP verbs had the same shape: a field they do not carry, or an
    argument left out, arrived as "" and erased the stored one.

    The rule now: a blank clears a stored value only where the value was shown
    — the cluster form's block for an environment the cluster already serves,
    which is prefilled. Everywhere else a blank means "not given".

    Every submission here is built from the REAL form the server renders, the
    way a browser builds one: defaults, hidden fields and all. Hand-written
    dicts are how this got past the tests that already existed — none of them
    posted the protocol select's default, and that default is the whole cause.

    ./.venv/bin/python tests/test_binding_writes.py
"""
from __future__ import annotations

import html.parser
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("bindwrite-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import actions, answers, auth, db, main, repo, store  # noqa: E402
from app.env import GIT                                        # noqa: E402

BAD = 0
KEEP = ("url", "branch", "path", "protocol", "username")


def check(what: str, cond: bool, detail: str = "") -> None:
    global BAD
    print(("  ok   " if cond else "  FAIL ") + what
          + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        BAD += 1


class Submission(html.parser.HTMLParser):
    """What a browser sends for ONE form: its successful controls, in order.

    <template> content is inert and never sent, an unchecked box is not sent,
    a select sends its selected option (or its first), and a control with no
    name or a disabled one is not sent."""

    def __init__(self, action: str):
        super().__init__(convert_charrefs=True)
        self.action, self.inside, self.tpl = action, False, 0
        self.pairs: list[tuple[str, str]] = []
        self._sel = None
        self._opt = None
        self._ta = None

    def _close_option(self):
        if self._opt is not None and self._sel is not None:
            value, text, chosen = self._opt
            self._sel[1].append((value if value is not None else text.strip(),
                                 chosen))
        self._opt = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("action") == self.action:
            self.inside = True
            return
        if tag == "template":
            self.tpl += 1
        if not self.inside or self.tpl:
            return
        if tag == "input":
            kind = (a.get("type") or "text").lower()
            if (not a.get("name") or "disabled" in a
                    or kind in ("submit", "button", "reset", "image", "file")):
                return
            if kind in ("checkbox", "radio"):
                if "checked" in a:
                    self.pairs.append((a["name"], a.get("value") or "on"))
                return
            self.pairs.append((a["name"], a.get("value") or ""))
        elif tag == "textarea":
            self._ta = [a.get("name"), "", "disabled" in a]
        elif tag == "select":
            self._sel = [a.get("name"), [], "disabled" in a]
        elif tag == "option" and self._sel is not None:
            self._close_option()
            self._opt = [a.get("value"), "", "selected" in a]

    def handle_endtag(self, tag):
        if tag == "template":
            self.tpl -= 1
            return
        if tag == "form" and self.inside:
            self.inside = False
            return
        if not self.inside or self.tpl:
            return
        if tag == "textarea" and self._ta:
            name, text, off = self._ta
            if name and not off:
                self.pairs.append((name, text[1:] if text.startswith("\n")
                                   else text))
            self._ta = None
        elif tag == "option":
            self._close_option()
        elif tag == "select" and self._sel is not None:
            self._close_option()
            name, opts, off = self._sel
            if name and not off and opts:
                picked = [v for v, chosen in opts if chosen]
                self.pairs.append((name, picked[0] if picked else opts[0][0]))
            self._sel = None

    def handle_data(self, data):
        if self._ta is not None:
            self._ta[1] += data
        if self._opt is not None:
            self._opt[1] += data


def form_of(c, page: str, action: str) -> list:
    s = Submission(action)
    s.feed(c.get(page).text)
    check(f"the page renders the form ({action})", bool(s.pairs))
    return s.pairs


def typed(pairs: list, name: str, value: str) -> list:
    """Type into the first control called `name`, as a person would."""
    for i, (k, _v) in enumerate(pairs):
        if k == name:
            pairs[i] = (k, value)
            return pairs
    check(f"the form has a {name!r} field to type into", False)
    return pairs


def post(c, action: str, pairs: list):
    data: dict[str, list[str]] = {}
    for k, v in pairs:
        data.setdefault(k, []).append(v)
    return c.post(action, data=data, follow_redirects=False)


def stored(pid: str, rgid: str, env: str) -> dict:
    b = store.env_sources(pid, rgid).get(env) or {}
    return {k: b.get(k, "") for k in KEEP}


def cid_named(pid: str, name: str) -> str:
    return next((cid for cid, cl in (store.get_project(pid) or {})
                 .get("clusters", {}).items() if cl.get("name") == name), "")


def kubeconfig(ctx: str, port: int) -> str:
    return (f"apiVersion: v1\nkind: Config\nclusters:\n- name: {ctx}\n"
            f"  cluster:\n    server: https://127.0.0.1:{port}\n"
            f"contexts:\n- name: {ctx}\n  context:\n    cluster: {ctx}\n"
            f"    user: {ctx}\ncurrent-context: {ctx}\nusers:\n- name: {ctx}\n"
            f"  user:\n    token: not-a-real-token\n")


def main_test() -> int:
    uid = auth.create_user("binder@t.local", "N", "Binding-Writes-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "binder@t.local",
                           "password": "Binding-Writes-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    # A real repository, so a declaration clones and its values file is found.
    # Made by cloning a seeded tree bare, never by pushing to anything.
    fx = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "fixture"
    src, origin = fx / "src", fx / "gitops.git"
    for env in ("dev", "app", "app-v2"):
        (src / "envs" / env).mkdir(parents=True, exist_ok=True)
        (src / "envs" / env / "api-values.yaml").write_text("replicas: 1\n")

    def git(*args, cwd=None):
        subprocess.run([GIT, *args], cwd=cwd, check=True, capture_output=True)
    git("init", "-q", "-b", "main", cwd=src)
    git("add", "-A", cwd=src)
    git("-c", "user.email=t@t.invalid", "-c", "user.name=t", "commit", "-q",
        "-m", "seed", cwd=src)
    git("clone", "-q", "--bare", str(src), str(origin))
    url = str(origin)

    pid = store.add_project("First Run")
    add_page = f"/settings/project/{pid}/cluster/form"
    add_action = f"/settings/project/{pid}/cluster/new"

    print("the first run: declare an environment with its repository, then add "
          "a cluster to serve it with the GitOps fields left blank")
    rg = store.add_region(pid, "KE")
    c.post(f"/settings/project/{pid}/region/{rg}/env/add",
           data={"name": "dev", "gitops_url": url, "gitops_branch": "main",
                 "gitops_path": "envs/dev"}, follow_redirects=False)
    before = stored(pid, rg, "dev")
    check("declared with its repository, branch and path",
          before["url"] == url and before["branch"] == "main"
          and before["path"] == "envs/dev", before)
    check("and its values file was found",
          repo.env_files(pid, rg, "dev", include_hidden=True)
          == ["api-values.yaml"])

    form = form_of(c, add_page, add_action)
    check("the window posts its protocol select's default, as a browser does "
          "— the default that caused this",
          ("gitops_protocol", "https") in form)
    typed(form, "name", "ke-dev")
    typed(form, "region", rg)
    typed(form, "env", "dev")
    r = post(c, add_action, form)
    msg = urllib.parse.unquote_plus(r.headers.get("location", ""))
    after = stored(pid, rg, "dev")
    check("adding the cluster keeps the environment's repository, branch, "
          "path, protocol and username exactly as declared",
          after == before, f"{before} -> {after}")
    check("its values file is still found",
          repo.env_files(pid, rg, "dev", include_hidden=True)
          == ["api-values.yaml"])
    check("the cluster serves it",
          (store.get_region(pid, rg) or {}).get("env_clusters", {}).get("dev")
          == cid_named(pid, "ke-dev"))
    check("and the message says where its values live",
          "at envs/dev" in msg, msg)

    print("typing the repository again, and nothing else")
    form = form_of(c, add_page, add_action)
    for k, v in (("name", "ke-dev-2"), ("region", rg), ("env", "dev"),
                 ("gitops_url", url)):
        typed(form, k, v)
    post(c, add_action, form)
    check("keeps the branch and path it did not ask about",
          stored(pid, rg, "dev") == before, stored(pid, rg, "dev"))

    print("a stored ssh protocol is not overwritten by the select's default")
    rg_ssh = store.add_region(pid, "SSH")
    ssh_url = str(fx / "ssh-only.git")
    store.set_env_source(pid, rg_ssh, "build", {
        "url": ssh_url, "path": "envs/build", "protocol": "ssh"})
    form = form_of(c, add_page, add_action)
    for k, v in (("name", "ssh-build"), ("region", rg_ssh), ("env", "build")):
        typed(form, k, v)
    post(c, add_action, form)
    got = stored(pid, rg_ssh, "build")
    check("the environment still authenticates over ssh, at the same "
          "repository and path",
          got["protocol"] == "ssh" and got["url"] == ssh_url
          and got["path"] == "envs/build", got)

    print("a NEW environment copies its sibling's repository — protocol "
          "included")
    rg_new = store.add_region(pid, "NEW")
    sib_url = str(fx / "sibling.git")
    store.set_env_source(pid, rg_new, "dev", {
        "url": sib_url, "path": "envs/dev", "protocol": "ssh"})
    form = form_of(c, add_page, add_action)
    for k, v in (("name", "new-uat"), ("region", rg_new), ("env", "uat")):
        typed(form, k, v)
    post(c, add_action, form)
    got = stored(pid, rg_new, "uat")
    check("a blank repository copies the sibling's, and its ssh protocol with "
          "it — the select's https used to fill that blank first, so the copy "
          "skipped it and the new environment could not use the sibling's key",
          got["url"] == sib_url and got["protocol"] == "ssh", got)

    print("the edit form SHOWS the binding, so a blank there is a decision")
    cid2 = cid_named(pid, "ke-dev-2")
    edit_page = f"/settings/project/{pid}/cluster/form?cid={cid2}"
    edit_action = f"/settings/project/{pid}/cluster/{cid2}/update"
    form = form_of(c, edit_page, edit_action)
    check("the edit form is prefilled with the binding it serves",
          ("gitops_url", url) in form and ("gitops_branch", "main") in form
          and ("gitops_path", "envs/dev") in form, form)
    post(c, edit_action, form)
    check("saving it untouched changes nothing anybody could see",
          {k: v for k, v in stored(pid, rg, "dev").items() if k != "protocol"}
          == {k: v for k, v in before.items() if k != "protocol"}
          and stored(pid, rg, "dev")["protocol"] in ("", "https"),
          stored(pid, rg, "dev"))
    form = form_of(c, edit_page, edit_action)
    typed(form, "gitops_branch", "")
    post(c, edit_action, form)
    check("a branch emptied in the form that showed it IS cleared",
          stored(pid, rg, "dev")["branch"] == ""
          and stored(pid, rg, "dev")["url"] == url
          and stored(pid, rg, "dev")["path"] == "envs/dev",
          stored(pid, rg, "dev"))

    print("the regions panel's declare form keeps what it does not ask for")
    rg_f = store.add_region(pid, "PANEL")
    store.set_env_source(pid, rg_f, "app", {
        "url": url, "branch": "main", "path": "envs/app", "protocol": "https",
        "username": "deploy-bot"})
    panel_action = f"/settings/project/{pid}/region/{rg_f}/env/add"
    form = form_of(c, "/settings/clusters", panel_action)
    typed(form, "name", "app")
    typed(form, "gitops_path", "envs/app-v2")
    post(c, panel_action, form)
    got = stored(pid, rg_f, "app")
    check("re-declaring with a new path moves the path",
          got["path"] == "envs/app-v2", got)
    check("and keeps the repository, branch, protocol and username it has no "
          "fields for",
          got["url"] == url and got["branch"] == "main"
          and got["protocol"] == "https" and got["username"] == "deploy-bot",
          got)

    print("the same rule through MCP")
    admin = auth.by_id(uid)
    rg_m = store.add_region(pid, "MCP")
    actions.run(admin, "env_declare", {
        "project": pid, "region": rg_m, "env": "svc", "gitops_repo": url,
        "branch": "main", "path": "envs/dev", "username": "mcp-bot"})
    actions.run(admin, "env_declare", {
        "project": pid, "region": rg_m, "env": "svc", "path": "envs/app"})
    got = stored(pid, rg_m, "svc")
    check("an env_declare naming only a path moves the path and keeps the "
          "repository, branch and username",
          got["path"] == "envs/app" and got["url"] == url
          and got["branch"] == "main" and got["username"] == "mcp-bot", got)
    actions.run(admin, "cluster_add", {
        "project": pid, "kubeconfig": kubeconfig("mcp-ctx", 7),
        "region": rg_m, "env": "svc"})
    check("and cluster_add for it, with no GitOps arguments, keeps all of it — "
          "the same erasure through the other door",
          stored(pid, rg_m, "svc") == got, stored(pid, rg_m, "svc"))
    check("while still mapping the cluster to it",
          (store.get_region(pid, rg_m) or {}).get("env_clusters", {})
          .get("svc") == cid_named(pid, "mcp-ctx"))

    print("'creds ✓' means credentials are stored, and nothing else")
    rg_c = store.add_region(pid, "CREDS")
    # Exactly what the old cluster form left on every environment it declared:
    # a protocol and nothing to authenticate with. Installs already hold these.
    store.set_env_source(pid, rg_c, "plain", {
        "url": url, "branch": "main", "path": "envs/dev", "protocol": "https"})
    tok_url = str(fx / "with-token.git")
    store.set_env_source(pid, rg_c, "tok", {
        "url": tok_url, "path": "envs/tok", "username": "bot",
        "secret": "tok-0123456789"})
    store.set_env_source(pid, rg_c, "keyless", {
        "url": str(fx / "keyless.git"), "path": "envs/k", "protocol": "ssh"})
    check("a protocol alone is not credentials",
          not repo.binding(pid, rg_c, "plain")["has_own_auth"])
    check("a stored token is",
          repo.binding(pid, rg_c, "tok")["has_own_auth"])
    page = c.get("/settings/clusters").text
    # one region's block: it ends where the panel's add-a-region form begins
    block = page[page.index(f'id="{rg_c}"'):]
    block = block[:block.index("add a region to")]
    rows = {m.group(1): m.group(0) for m in
            re.finditer(r"<tr>\s*<td><b>([^<]+)</b>.*?</tr>", block, re.S)}
    check("the regions panel shows no 'creds ✓' beside the protocol-only one",
          "plain" in rows and "creds ✓" not in rows["plain"], rows.keys())
    check("and shows it beside the one with a token",
          "tok" in rows and "creds ✓" in rows["tok"])
    repos = c.get("/repos").text
    cards = [m.group(0) for m in re.finditer(
        rf'<div class="rowcard" id="{rg_c}">.*?<div class="ractions">',
        repos, re.S)]
    plain_card = next((x for x in cards if url in x), "")
    tok_card = next((x for x in cards if tok_url in x), "")
    check("the GitOps repos board agrees about the protocol-only one",
          plain_card and "creds ✓" not in plain_card)
    check("and about the one with a token", tok_card and "creds ✓" in tok_card)
    said = {r["repository"]: r["own credentials"]
            for r in answers.q_repos({"id": "t", "role": "admin"}, "repos", "")
            .get("rows", []) if r.get("region") == "CREDS"}
    check(f"so does what an assistant or MCP client is told ({said})",
          said.get(url) != "yes" and said.get(tok_url) == "yes")

    cc = store.add_cluster(pid, "creds-c", "", "ctx-creds")
    for env in ("plain", "tok", "keyless"):
        store.map_env_cluster(pid, rg_c, env, cc)
    frag = c.get(f"/settings/project/{pid}/cluster/form?cid={cc}").text

    def opens(env):
        at = frag.index(f"· {env}</b>")
        tail = frag[at:]
        m = re.search(r"<details class=\"cl-ownrepo\"([^>]*)>", tail)
        return bool(m) and "open" in m.group(1)
    check("the cluster form's 'how it authenticates' stays shut for an "
          "environment with nothing stored", not opens("plain"))
    check("opens for one with a token", opens("tok"))
    check("and opens for one set to ssh with no key yet, so the protocol is "
          "never hidden behind a shut section", opens("keyless"))

    print("\nFAILED" if BAD else "\nOK")
    return 1 if BAD else 0


if __name__ == "__main__":
    raise SystemExit(main_test())
