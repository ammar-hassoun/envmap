#!/usr/bin/env python3
"""The clusters settings page: assigning an environment from the cluster itself.

WHY THIS EXISTS
    A cluster in a region whose repository is not configured could not be
    assigned to an environment at all. The environment list is scanned from the
    repo, so an unconfigured region offered an empty dropdown — and the mapping
    card skipped such a region entirely, so it read as though the region did not
    exist rather than as though its repo was missing.

    `store.map_env_cluster` never required the environment to exist on disk.
    Only the UI did. These checks hold that open.

    ./.venv/bin/python tests/test_clusters_settings.py
"""
from __future__ import annotations

import json
import os
import re
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("clset-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import (answers, auth, db, gitrepo, main, repo,      # noqa: E402
                 secretbox, store)

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main_test() -> int:
    uid = auth.create_user("boss@t.local", "N", "Set-Clusters-Please-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "boss@t.local",
                           "password": "Set-Clusters-Please-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    print("a region with no repository is visible, and says why")
    pid = store.add_project("Env Field", icon="\N{TEST TUBE}")
    rgid = store.add_region(pid, "KE", flag="")      # deliberately no repo
    cid = store.add_cluster(pid, "ke-preprod-app", "", "admin@app-ke-preprod")
    page = c.get("/settings/clusters").text
    # Whitespace-normalised: template line wrapping puts newlines inside
    # sentences, and an assertion that breaks when a paragraph is re-wrapped
    # tests the indentation rather than the words.
    flat = " ".join(page.lower().split())
    check("the region appears rather than being skipped", "KE" in page)
    check("a region with no repository is still workable — it is listed in the "
          "regions panel with somewhere to declare an environment, because an "
          "environment names its own repository now",
          f'/region/{rgid}/env/add' in page
          and "nothing declared here yet" in flat)
    # The form is FETCHED into the window now, so the list page must NOT carry
    # it — that is the whole size win — and the fragment must.
    check("the list page no longer ships every cluster's form inline",
          'name="kubeconfig"' not in page and 'name="gitops_secret"' not in page)
    check("and the rows open it through the window instead",
          "data-clform" in page and 'id="clDlg"' in page)
    form = c.get(f"/settings/project/{pid}/cluster/form?cid={cid}").text
    check("the cluster's own form offers region + environment",
          'name="region"' in form and 'name="env"' in form)
    check("the field is marked optional, because most saves do not touch it",
          "serves environment" in form)
    check("and the credentials for that environment's repo are on the SAME "
          "form — the separate GitOps repos page is gone",
          'name="gitops_secret"' in form
          and 'name="gitops_username"' in form
          and 'name="gitops_ssh_key"' in form)
    check("the same fragment serves 'add a cluster', so the two cannot drift",
          'name="kubeconfig"' in
          c.get(f"/settings/project/{pid}/cluster/form").text)
    check("a cluster that has been deleted says so rather than rendering a "
          "form that posts nowhere",
          c.get(f"/settings/project/{pid}/cluster/form?cid=c-gone")
          .status_code == 404)
    check("the retired page redirects rather than 404s, so an old bookmark "
          "still lands somewhere useful",
          c.get("/settings/repos", follow_redirects=False)
          .headers.get("location") == "/settings/clusters")

    print("assigning it from the cluster's own form")
    c.post(f"/settings/project/{pid}/cluster/{cid}/update",
           data={"name": "ke-preprod-app", "region": rgid, "env": "preprod"},
           follow_redirects=False)
    rg = store.get_region(pid, rgid) or {}
    check("the region now maps that environment to this cluster",
          (rg.get("env_clusters") or {}).get("preprod") == cid)
    page = c.get("/settings/clusters").text
    check("the cluster row shows what it serves",
          "preprod" in page and "no environment" not in page.split("preprod")[0][-400:])
    check("and marks that nothing is behind it yet, without pretending the "
          "assignment is not real",
          "no values files for preprod" in page)
    check("assigning it also DECLARED it, so it is a thing the portal knows "
          "about rather than a name on one cluster row",
          "preprod" in store.env_sources(pid, rgid))

    print("an assignment survives an unrelated save, and can be removed")
    c.post(f"/settings/project/{pid}/cluster/{cid}/update",
           data={"name": "ke-preprod-app"}, follow_redirects=False)
    rg = store.get_region(pid, rgid) or {}
    check("saving the form without an environment leaves the mapping alone",
          (rg.get("env_clusters") or {}).get("preprod") == cid)
    c.post(f"/settings/project/{pid}/cluster/{cid}/unmap",
           data={"region": rgid, "env": "preprod"}, follow_redirects=False)
    rg = store.get_region(pid, rgid) or {}
    check("and unassigning clears just that entry",
          not (rg.get("env_clusters") or {}).get("preprod"))

    print("a cluster may serve more than one environment")
    for env in ("dev", "uat"):
        c.post(f"/settings/project/{pid}/cluster/{cid}/update",
               data={"name": "ke-preprod-app", "region": rgid, "env": env},
               follow_redirects=False)
    rg = store.get_region(pid, rgid) or {}
    check("adding a second does not replace the first",
          (rg.get("env_clusters") or {}).get("dev") == cid
          and (rg.get("env_clusters") or {}).get("uat") == cid)

    print("EVERY environment a cluster serves is on its own form, and saving "
          "them is all-or-nothing")
    # The dev cluster here really does serve UAE, CR and KE, each at its own
    # path in one repository. The form carried ONE block and a note sending you
    # elsewhere for the rest, so two of the three bindings were invisible — and
    # their values turning up on the cluster page read as a bug in the portal
    # rather than as configuration the form declined to show.
    multi = store.add_cluster(pid, "multi-dev", "", "ctx-multi")
    rg_a = store.add_region(pid, "AA")
    rg_b = store.add_region(pid, "BB")
    rg_c = store.add_region(pid, "CC")
    three = ["AA", "BB", "CC"]
    ids = {"AA": rg_a, "BB": rg_b, "CC": rg_c}

    def multipost(**over):
        """The browser's shape: every block posts the same names, so the
        server reads them as the positional zip of getlist()."""
        d = {"region": [ids[n] for n in three], "env": ["dev"] * 3,
             "gitops_url": ["https://git.example/org/gitops.git"] * 3,
             "gitops_branch": ["main"] * 3,
             "gitops_path": [f"envs/{n.lower()}/dev" for n in three],
             "gitops_protocol": ["https"] * 3, "gitops_username": [""] * 3,
             "gitops_secret": [""] * 3, "gitops_ssh_key": [""] * 3,
             "name": "multi-dev", "context": "ctx-multi"}
        d.update(over)
        return c.post(f"/settings/project/{pid}/cluster/{multi}/update",
                      data=d, follow_redirects=False)

    multipost()
    paths = {n: repo.binding(pid, ids[n], "dev")["path"] for n in three}
    check(f"all three environments are declared in one save ({paths})",
          paths == {n: f"envs/{n.lower()}/dev" for n in three})
    check("and all three are mapped to the cluster",
          all((store.get_region(pid, ids[n]) or {}).get("env_clusters", {})
              .get("dev") == multi for n in three))

    # Each may differ from the others — that is the whole reason for a block
    # each rather than one shared binding.
    multipost(gitops_branch=["main", "main", "cc-own-branch"])
    check("an environment can hold its own branch alongside the others",
          repo.binding(pid, rg_c, "dev")["branch"] == "cc-own-branch"
          and repo.binding(pid, rg_a, "dev")["branch"] == "main")

    # ALL-OR-NOTHING. The first version validated and wrote in one pass, so a
    # refusal on the second block left the first already stored: the form then
    # showed three environments and the database held one and a half. With
    # several blocks that stops being a corner case.
    before = {n: repo.binding(pid, ids[n], "dev")["path"] for n in three}
    r = multipost(region=[ids["AA"], "", ids["CC"]],
                  gitops_path=["MUST-NOT-LAND", "x", "y"])
    check("a block with no region is refused", r.status_code == 303)
    check("and NOTHING was written, not even the block before it",
          {n: repo.binding(pid, ids[n], "dev")["path"] for n in three} == before)

    r = multipost(gitops_path=["ALSO-MUST-NOT-LAND", "ok/cr", "../escape"])
    check("a bad path in the LAST block also writes nothing",
          {n: repo.binding(pid, ids[n], "dev")["path"] for n in three} == before)

    r = multipost(region=[ids["AA"], ids["AA"], ids["CC"]])
    check("the same environment twice in one save is refused",
          {n: repo.binding(pid, ids[n], "dev")["path"] for n in three} == before)

    # The blank "add another" block rides along on every save.
    r = multipost(region=[ids[n] for n in three] + [""],
                  env=["dev"] * 3 + [""],
                  gitops_url=["https://git.example/org/gitops.git"] * 3 + [""],
                  gitops_branch=["main"] * 3 + [""],
                  gitops_path=[f"envs/{n.lower()}/dev" for n in three] + [""],
                  gitops_protocol=["https"] * 4, gitops_username=[""] * 4,
                  gitops_secret=[""] * 4, gitops_ssh_key=[""] * 4)
    check("an empty block declares nothing rather than an environment called ''",
          all("" not in ((store.get_region(pid, ids[n]) or {}).get("envs") or {})
              for n in three))

    # A save that does not carry the name must not blank it.
    c.post(f"/settings/project/{pid}/cluster/{multi}/update",
           data={"context": "ctx-multi"}, follow_redirects=False)
    check("a save with no name field keeps the stored name",
          (store.get_cluster(pid, multi) or {}).get("name") == "multi-dev")

    print("the list IS the house table, which is what makes it line up")
    # It was a stack of bespoke card rows, each its own CSS grid — so a track
    # sized to content was measured against THAT row and no two rows agreed:
    # the context column started at a different x on every line ("some labels
    # left, some in the middle"). A real table has one set of columns by
    # construction, and `table.jenkins` is the component every other list in
    # the portal already uses, so it also brings headers and click-to-sort
    # wired once in base.html.
    tpl = (pathlib.Path(__file__).resolve().parent.parent
           / "templates" / "set_clusters.html").read_text()
    check("the clusters render in a table.jenkins",
          'class="jenkins cl-table"' in tpl)
    check("with real column headers, so a column says what it is",
          all(f'>{h}</th>' in tpl for h in ("cluster", "context", "serves",
                                            "status")))
    # EVERY PROJECT RENDERS ITS OWN TABLE, so an auto layout sizes each one to
    # its own content and one project's context column began 200px left of
    # the next one's — the same "nothing lines up" as the card rows, moved one level
    # out. Declared widths on a fixed layout are what make four separate tables
    # agree with each other and with their own headers.
    check("the table layout is fixed, so separate tables cannot disagree",
          "table-layout:fixed" in tpl)
    check("and every column has a declared width",
          all(f".cl-table .c-{k}" in tpl
              for k in ("name", "ctx", "srv", "st", "act")))
    check("each header cell carries its width class",
          all(f'class="c-{k}"' in tpl for k in ("name", "ctx", "srv", "st")))

    print("a project is one line until it is opened")
    check("the header is a disclosure button", 'class="cl-projhead"' in tpl
          and "aria-expanded" in tpl)
    check("and the clusters live in a body that starts hidden",
          'class="cl-projbody"' in tpl and "{% if not show %} hidden{% endif %}" in tpl)
    # A tile that filters to three clusters and then shows four shut boxes has
    # failed at the one thing it is for.
    open_pg = c.get("/settings/clusters?show=manage").text
    check("arriving through a tile filter opens what it filtered to",
          'class="cl-projbody" >' in open_pg or 'class="cl-projbody">' in open_pg)
    shut_pg = c.get("/settings/clusters").text
    check("but a plain visit starts collapsed",
          'class="cl-projbody" hidden>' in shut_pg)
    check("the action column is the sticky one the sorter skips",
          'class="actcol"' in tpl)
    check("and its buttons stay on one line, per the house standard",
          'class="actrow oneline"' in tpl)
    # Sorting a column of sentences alphabetically would put "not checked"
    # between two "ok"s, so status sorts on a rank and the name sorts folded.
    check("status carries a sort rank rather than sorting by its sentence",
          "data-sort=\"{{ (2 if c.live == 'ok' else 0 if c.live == 'bad' else 1) }}\""
          in tpl)
    check("no bespoke row grid is left behind to drift from the table",
          ".cl-head" not in tpl)
    # The form must be OUT of the row for sorting to be safe at all.
    check("the form is not a detail row a sort could separate from its parent",
          'class="cl-edit" id="ed-' not in tpl)

    print("a nonsense assignment is ignored rather than stored")
    c.post(f"/settings/project/{pid}/cluster/{cid}/update",
           data={"name": "ke-preprod-app", "region": "rg-nope",
                 "env": "prod"}, follow_redirects=False)
    check("an unknown region writes nothing",
          "prod" not in (store.get_region(pid, rgid).get("env_clusters") or {}))
    r = c.post(f"/settings/project/{pid}/cluster/{cid}/unmap",
               data={"region": rgid, "env": "never-mapped"},
               follow_redirects=False)
    check("unmapping something that was not mapped says so rather than "
          "pretending", r.status_code == 303)

    print("the project is a FIELD on the cluster form, not just whichever "
          "button you pressed")
    from pathlib import Path
    other = store.add_project("Elsewhere", icon="\N{TEST TUBE}")
    page = c.get("/settings/clusters").text
    addf = c.get(f"/settings/project/{pid}/cluster/form").text
    editf = c.get(f"/settings/project/{pid}/cluster/form?cid={cid}").text
    check("both the add and the edit form carry a project select",
          'name="project"' in addf and 'name="project"' in editf)
    check("and it offers every project, not only the one whose block it is in",
          "Elsewhere" in editf and "Env Field" in editf)

    # ADD: posted to one project's URL, but naming another — the field wins,
    # because otherwise the only way to choose is to find the right button.
    c.post(f"/settings/project/{pid}/cluster/new",
           data={"name": "lands-elsewhere", "project": other},
           follow_redirects=False)
    landed = [x for x in (store.get_project(other) or {}).get("clusters", {}).values()
              if x.get("name") == "lands-elsewhere"]
    check("adding a cluster puts it in the project the FORM named, not the one "
          "in the URL", len(landed) == 1)
    check("and it is not in the project whose button was pressed",
          not any(x.get("name") == "lands-elsewhere"
                  for x in (store.get_project(pid) or {}).get("clusters", {}).values()))

    # MOVE: row, secret files and the mappings left behind, all together
    mv = store.add_cluster(pid, "to-move", "apiVersion: v1\n", "ctx-move", "CERT")
    store.map_env_cluster(pid, rgid, "dev", mv)
    kube_before = (store.get_cluster(pid, mv) or {}).get("kubeconfig_file")
    check("its kubeconfig starts under the old project's directory",
          f"/{pid}/" in kube_before and Path(kube_before).exists())
    c.post(f"/settings/project/{pid}/cluster/{mv}/update",
           data={"name": "to-move", "project": other}, follow_redirects=False)
    check("editing the project MOVES the cluster, keeping its id — a new id "
          "would be a new cluster to every reference",
          store.get_cluster(pid, mv) is None
          and store.get_cluster(other, mv) is not None)
    kube_after = (store.get_cluster(other, mv) or {}).get("kubeconfig_file")
    check("its secret files move with it, or deleting the old project would "
          "one day take this cluster's kubeconfig with it",
          f"/{other}/" in kube_after and Path(kube_after).exists()
          and not Path(kube_before).exists())
    check("and the old project's environment stops pointing at it, because an "
          "environment cannot serve from a cluster in another project",
          (store.get_region(pid, rgid).get("env_clusters") or {}).get("dev") != mv)

    # A move that FAILS must leave nothing half-done. The files are copied
    # before the row is committed and the originals deleted only after, so a
    # failure rolls the row back with the original still on disk. Done the
    # obvious way round — move the file, then commit — the transaction rolls the
    # row back and the file does not come with it, leaving the row naming a
    # kubeconfig that is not there.
    import shutil as _sh
    hurt = store.add_cluster(pid, "half-done", "apiVersion: v1\n", "ctx-hd", "C")
    kb = (store.get_cluster(pid, hurt) or {}).get("kubeconfig_file")
    real, store.shutil.copy2 = store.shutil.copy2, None      # copy2 = None → TypeError
    try:
        try:
            store.move_cluster(pid, hurt, other)
        except Exception:                                    # noqa: BLE001
            pass
    finally:
        store.shutil.copy2 = real
    check("a move that fails part-way leaves the cluster where it was",
          store.get_cluster(pid, hurt) is not None
          and store.get_cluster(other, hurt) is None)
    check("with its kubeconfig still on disk where the row says it is",
          Path(kb).exists()
          and (store.get_cluster(pid, hurt) or {}).get("kubeconfig_file") == kb)

    print("the user's own repair: re-home a cluster AND its environment in "
          "ONE save — project switched, region created in the target, env "
          "declared, all together")
    # The real-world shape this guards: a cluster sits in project A, its
    # region got created in A by mistake, the person makes project B + a
    # region + the mapping from the cluster's own form in a single submit.
    A = store.add_project("WrongHome", icon="\N{TEST TUBE}")
    B = store.add_project("RightHome", icon="\N{TEST TUBE}")
    rgA = store.add_region(A, "UK")
    cl = store.add_cluster(A, "datalake-like", "apiVersion: v1\n", "ctx-dl", "C")
    c.post(f"/settings/project/{A}/cluster/{cl}/update",
           data={"name": "datalake-like", "region": rgA, "env": "PROD"},
           follow_redirects=False)
    check("starting state mirrors the incident: cluster and mapping in the "
          "wrong project",
          (store.get_region(A, rgA).get("env_clusters") or {}).get("PROD") == cl)
    # the inline step: region created in B while the form's project says B
    r = c.post(f"/settings/project/{B}/region/new",
               data={"name": "UK", "inline": "1"})
    rgB = r.json()["id"]
    # the ONE save: move + declare + map together
    r = c.post(f"/settings/project/{A}/cluster/{cl}/update",
           data={"name": "datalake-like", "project": B,
                 "region": rgB, "env": "PROD"},
           follow_redirects=False)
    check("the cluster moved to the right project",
          store.get_cluster(A, cl) is None
          and store.get_cluster(B, cl) is not None)
    check("the environment is declared and mapped in the RIGHT project's "
          "region, in the same submit that moved the cluster",
          "PROD" in store.env_sources(B, rgB)
          and (store.get_region(B, rgB).get("env_clusters") or {}).get("PROD") == cl)
    check("and the wrong project's mapping was cleared and NAMED, not left "
          "pointing across projects",
          not (store.get_region(A, rgA).get("env_clusters") or {}).get("PROD")
          and "UK/PROD" in __import__("urllib.parse", fromlist=["parse"])
              .unquote_plus(r.headers.get("location", "")))

    print("every file-reading helper resolves through the binding, not the "
          "old region-root guess")
    # `all_files` built `env_root(pid, rgid) / env` itself — the old model's
    # "region root plus the environment's name". Once an environment could
    # name its own repository, branch and path, that guess pointed at a
    # directory which no longer existed, and it returned [] rather than
    # raising: the service list, the diagram and the Argo namespace matcher all
    # showed EMPTY for a correctly-configured environment. The GitOps repo tab
    # said "Nothing at <the right path>" while the files sat there.
    pidF = store.add_project("FileRead", icon="\N{TEST TUBE}")
    rgF = store.add_region(pidF, "KE")
    # a binding whose path is NOT "<region root>/<env>" — the shape the old
    # guess cannot reach
    coF = store.source_dir("https://example.com/deep.git", "main")
    deep = coF / "apps" / "environments" / "KE" / "preprod"
    deep.mkdir(parents=True, exist_ok=True)
    (deep / "api-values.yaml").write_text("image:\n  tag: 1\n")
    (deep / "web-values.yaml").write_text("image:\n  tag: 2\n")
    store.set_env_source(pidF, rgF, "preprod",
                         {"url": "https://example.com/deep.git", "branch": "main",
                          "path": "apps/environments/KE/preprod"})
    check("all_files finds them through the binding",
          repo.all_files(pidF, rgF, "preprod")
          == ["api-values.yaml", "web-values.yaml"])
    check("and split_services — what the GitOps repo tab counts — agrees, "
          "instead of reporting 0 services next to a correct path",
          len(repo.split_services(pidF, rgF, "preprod")["all"]) == 2)
    check("the values file still resolves to a real path on disk",
          repo.values_path(pidF, rgF, "preprod", "api-values.yaml").exists())

    print("Save stays inside its form when the cluster serves an environment")
    # The bug: the "stop serving" chips rendered a <form> INSIDE the cluster's
    # edit form. HTML has no nested forms — the parser drops the inner start
    # tag and its </form> closes the OUTER one, so every field after it,
    # including Save, fell outside any form and the button silently did
    # nothing. Only on clusters that serve an environment, which is why it
    # survived every earlier check.
    import re as _re
    srv = store.add_cluster(pid, "serves-something", "", "ctx-serves")
    c.post(f"/settings/project/{pid}/cluster/{srv}/update",
           data={"name": "serves-something", "region": rgid, "env": "chip-env"},
           follow_redirects=False)
    # The form is a fetched fragment now, so the nesting is checked THERE —
    # moving it into a window does not make nested forms legal, and a <dialog>
    # is exactly where a stray </form> would be hardest to spot.
    page = c.get("/settings/clusters").text
    check("the cluster does serve an environment, so the row shows it",
          "chip-env" in page)
    frag = c.get(f"/settings/project/{pid}/cluster/form?cid={srv}").text
    m = _re.search(r"<form[^>]*/cluster/" + _re.escape(srv) + r"/update[^>]*>", frag)
    check("the fragment carries the cluster's own update form", m is not None)
    seg = frag[m.start():]
    depth = 0
    for t in _re.finditer(r"</?form[^>]*>", seg[:seg.index("Save cluster")]):
        depth += 1 if t.group(0).startswith("<form") else -1
    check("Save cluster is still INSIDE the edit form — a submit button "
          "outside one is inert, which is exactly how this failed",
          depth == 1)
    check("the unmap forms are emitted AFTER the edit form, reached by the "
          "chips through the HTML form= attribute",
          frag.index(f'id="unmap-ed-{srv}-1"') > frag.index("Save cluster")
          and f'form="unmap-ed-{srv}-1"' in frag)
    r = c.post(f"/settings/project/{pid}/cluster/{srv}/unmap",
               data={"region": rgid, "env": "chip-env"}, follow_redirects=False)
    check("and unmapping still works, so the fix did not cost the feature",
          r.status_code == 303
          and not (store.get_region(pid, rgid).get("env_clusters") or {})
                  .get("chip-env"))

    print("the GitOps repo tab names itself, and its dead ends have a way out")
    from app import cluster as clustermod
    check("the tab is called what it is about — the values come from a GitOps "
          "repo, and 'Config' never said so",
          ("config", "GitOps repo", "git-branch") in clustermod.TABS)
    # a cluster with no environment at all: the empty state must offer THIS
    # cluster's own settings row, not a list of twenty-four to hunt through
    solo = store.add_cluster(pid, "no-env-cluster", "", "ctx-solo")
    page = c.get(f"/clusters?project={pid}&cluster={solo}&tab=config").text
    check("an unmapped cluster's GitOps tab deep-links to ITS OWN row",
          f"/settings/clusters#ed-{solo}" in page)
    # and the deep link has to land: the settings page must open the panel the
    # hash names, or the button is a link to a page that ignores it
    setpage = c.get("/settings/clusters").text
    # #ed-<cid> used to name an in-page panel; it now names the row whose edit
    # button opens the window, so the deep link still has to LAND — the button
    # for that exact cluster must exist on the page for openNamed to click.
    check("the settings page acts on a hash, so the button lands on the form "
          "rather than on the list",
          "openNamed" in setpage and "hashchange" in setpage
          and f'data-clcid="{solo}"' in setpage)
    check("and it clears the filter first — a hidden row would make the page "
          "look like it ignored the link",
          "find.value = ''" in setpage)

    print("a credential pasted INSIDE a clone URL never reaches a page, an "
          "export, or an MCP client")
    # The shape people actually paste. It is accepted (it is a valid clone
    # address) but the token must not survive in the field the portal DISPLAYS
    # and EXPORTS — the repos board, the cluster form, assistant answers and
    # the MCP config surface all print a repository address.
    TOK = "ghp_LEAKCANARY0123456789"
    INLINE = f"https://bot:{TOK}@git.example.com/org/deploy.git"
    pidL = store.add_project("Inline", icon="\N{TEST TUBE}")
    rgL = store.add_region(pidL, "KE")
    store.set_env_source(pidL, rgL, "prod",
                         {"url": INLINE, "branch": "main", "path": "envs/prod"})
    dec = store.env_sources(pidL, rgL)["prod"]
    check("the stored address has the credential stripped out of it",
          dec["url"] == "https://git.example.com/org/deploy.git"
          and TOK not in dec["url"])
    check("and the credential was moved into the sealed field, not discarded — "
          "losing it would break the clone instead of the display",
          dec["username"] == "bot"
          and secretbox.unseal(dec["secret"]) == TOK)
    bL = repo.binding(pidL, rgL, "prod")
    check("binding() — what every template reads — never carries it",
          TOK not in json.dumps(bL))
    check("but git still gets the real address, reassembled from the sealed "
          "field, so cloning a private repo keeps working",
          TOK in gitrepo._env_for(pidL, rgL,
                                  gitrepo.env_repo(pidL, rgL, "prod"))[1])

    # A row written the old way (straight into the database, or by a version
    # before the split) must not leak either — the read path sanitises too.
    store.update_region(pidL, rgL, envs={"legacy": {"url": INLINE,
                                                    "branch": "main",
                                                    "path": "envs/legacy"}})
    bLeg = repo.binding(pidL, rgL, "legacy")
    check("a legacy row with the credential still inline is sanitised on READ",
          TOK not in json.dumps(bLeg)
          and bLeg["url"] == "https://git.example.com/org/deploy.git")
    check("and it still authenticates, so sanitising cannot break an existing "
          "install's clone",
          TOK in gitrepo._env_for(pidL, rgL,
                                  gitrepo.env_repo(pidL, rgL, "legacy"))[1])

    # the surfaces the reviewer named, each checked for real
    page = c.get("/settings/clusters").text
    check("the cluster settings page never prints it", TOK not in page)
    check("the repos board never prints it", TOK not in c.get("/repos").text)
    rows = answers.q_repos({"id": "t", "role": "admin"}, "repos", "")
    check("the assistant/MCP repository answer never exports it — this one "
          "leaves the portal for somebody's AI client",
          TOK not in json.dumps(rows))

    print("a project or region is created INLINE, from the dropdown itself")
    page = c.get("/settings/clusters").text
    # The project's create-in-place row is per PANEL (one project select per
    # cluster form) and keeps its uid; the region's is per BLOCK, because a
    # cluster serving three environments has three region dropdowns and the
    # row has to open under whichever one was used.
    frag = c.get(f"/settings/project/{pid}/cluster/form").text
    check("both dropdowns carry a create-in-place entry — nobody is sent to "
          "another page to add what the list is missing",
          'value="__new__"' in frag and 'value="__newrg__"' in frag
          and "clnewproj-" in frag and 'class="cl-inlinenew clnewrg"' in frag)
    # A fetched form's selects are native copies until something enhances them,
    # and the one-off paints normally run on DOMContentLoaded — so the window
    # has to be able to re-run them on the subtree it just inserted.
    setp = c.get("/settings/clusters").text
    check("and a fetched form gets woken up — themed dropdowns, the right "
          "regions, and the protocol switch painted",
          "window.clFormWake" in setp and "enhanceSelect" in
          (pathlib.Path(__file__).resolve().parent.parent
           / "templates" / "_cluster_dialog.html").read_text())
    r = c.post("/settings/project/new", data={"name": "Born Inline",
                                              "inline": "1"})
    check("the project route answers JSON in inline mode — a redirect would "
          "cost the half-filled cluster form its pasted kubeconfig",
          r.status_code == 200
          and r.headers.get("content-type", "").startswith("application/json")
          and r.json().get("id", "").startswith("p-")
          and r.json().get("name") == "Born Inline")
    bpid = r.json()["id"]
    check("and the project genuinely exists",
          (store.get_project(bpid) or {}).get("name") == "Born Inline")
    r = c.post(f"/settings/project/{bpid}/region/new",
               data={"name": "MX", "inline": "1"})
    check("the region route answers JSON too, with the rendered label so the "
          "new option looks like the server-rendered ones",
          r.status_code == 200 and r.json().get("id", "").startswith("rg-")
          and r.json().get("label", "").endswith(" MX"))
    check("and the region genuinely exists",
          "MX" in {rg.get("name")
                   for rg in (store.get_project(bpid) or {})
                   .get("regions", {}).values()})
    r = c.post("/settings/project/new", data={"name": "", "inline": "1"})
    check("a blank name is a 400 with a JSON reason, not a redirect the fetch "
          "cannot read", r.status_code == 400 and "name" in r.json()["error"])
    r = c.post(f"/settings/project/p-nope/region/new",
               data={"name": "XX", "inline": "1"})
    check("a vanished project is a 404, said in JSON", r.status_code == 404)
    r = c.post("/settings/project/new", data={"name": "Old Way"},
               follow_redirects=False)
    check("without inline the routes redirect exactly as before — one route, "
          "two answers, zero second creation paths",
          r.status_code == 303
          and "/settings/projects" in r.headers.get("location", ""))

    print("environments are DECLARED — repo, branch and path, per environment")
    import urllib.parse
    pid2 = store.add_project("Env Scan", icon="\N{TEST TUBE}")
    rg2 = store.add_region(pid2, "KE", flag="")
    root = store.repo_dir(pid2, rg2)
    for env in ("dev", "prod", "docs", "preprod-extra"):
        d = root / "values" / env
        d.mkdir(parents=True, exist_ok=True)
        (d / "api-values.yaml").write_text("image:\n  tag: 1.0\n")
    store.set_region_repo(pid2, rg2, {"url": "https://example.com/x.git",
                                      "values_path": "values"})
    # THE MIGRATION: an installation that upgrades into declarations must not
    # lose the environments it had. The old scan runs one last time and its
    # answer is written down; from then on nothing is guessed.
    check("upgrading materialises what the scan used to find, so nothing "
          "disappears",
          sorted(repo.list_envs(pid2, rg2)) == ["dev", "docs", "preprod-extra",
                                               "prod"])
    check("and each one is now a declaration somebody can edit",
          sorted(store.env_sources(pid2, rg2)) == ["dev", "docs",
                                                   "preprod-extra", "prod"])
    check("with the path written out from the repository root, not implied",
          (store.env_sources(pid2, rg2)["dev"] or {})["path"] == "values/dev")
    check("the scan does not run twice — the declarations are the truth now",
          repo.binding(pid2, rg2, "dev")["declared"])
    # THE ABSORB: the legacy region-level repository is folded INTO the
    # bindings and blanked — it became invisible the day its settings page was
    # retired, and invisible configuration driving a live diagram is exactly
    # the bug this model exists to prevent.
    check("every environment now carries the repository EXPLICITLY — nothing "
          "inherits from a record no form can show",
          all((store.env_sources(pid2, rg2)[e] or {}).get("url")
              == "https://example.com/x.git"
              for e in ("dev", "docs", "preprod-extra", "prod")))
    check("and the legacy region-level repository is blanked, so there is no "
          "second copy left to go stale",
          not ((store.get_region(pid2, rg2) or {}).get("repo") or {}).get("url"))
    moved = store.source_dir("https://example.com/x.git", "")
    check("the working copy moved to the shared per-(repo, branch) checkout, "
          "uncommitted files and all",
          (moved / "values" / "dev" / "api-values.yaml").exists()
          and not (root / "values").exists())

    def env_post(what, **data):
        return c.post(f"/settings/project/{pid2}/region/{rg2}/env/{what}",
                      data=data, follow_redirects=False)

    env_post("hide", name="docs")
    check("a folder that is not an environment can be undeclared",
          "docs" not in repo.list_envs(pid2, rg2))
    check("and nothing on disk was touched — the file sits in the moved "
          "checkout, undeclared but intact",
          (moved / "values" / "docs" / "api-values.yaml").exists())
    check("undeclaring is not a scan away from coming back",
          "docs" not in repo.list_envs(pid2, rg2))

    env_post("add", name="preprod", gitops_path="values/preprod-extra")
    envs = repo.list_envs(pid2, rg2)
    check("an environment can be declared at a folder named differently",
          "preprod" in envs and envs["preprod"] == ["api-values.yaml"])
    check("and the folder is no longer listed under its own name too — the "
          "same files under two names is what makes a list untrustworthy",
          "preprod-extra" not in envs)
    check("its values file resolves through the normal path helper, so every "
          "page can open it",
          repo.values_path(pid2, rg2, "preprod", envs["preprod"][0]).exists())

    env_post("add", name="uat", gitops_path="values/not-created-yet")
    check("an environment declared before any values file exists is still "
          "listed, so it can be pointed at a cluster",
          "uat" in repo.list_envs(pid2, rg2)
          and repo.list_envs(pid2, rg2)["uat"] == [])

    # THE POINT OF ALL THIS: an environment on its own branch, in its own
    # repository, which one values path per region could never express. Against
    # a real repository on a real branch, cloned by the real route — a stubbed
    # checkout would not prove that any of the git plumbing follows the binding.
    import subprocess
    from app.env import GIT
    origin = store.repo_dir(pid2, rg2).parent / "origin.git"
    work = store.repo_dir(pid2, rg2).parent / "origin-work"
    (work / "envs" / "sandbox").mkdir(parents=True, exist_ok=True)
    (work / "envs" / "sandbox" / "web-values.yaml").write_text("a: 1\n")
    g = lambda *a, **k: subprocess.run([GIT, *a], cwd=k.get("cwd"), check=True,
                                       capture_output=True)
    g("init", "--bare", "-b", "release", str(origin))
    g("init", "-b", "release", cwd=work)
    g("config", "user.email", "t@t", cwd=work)
    g("config", "user.name", "t", cwd=work)
    g("add", "-A", cwd=work)
    g("commit", "-m", "seed", cwd=work)
    g("remote", "add", "origin", str(origin), cwd=work)
    g("push", "-u", "origin", "release", cwd=work)

    r = env_post("add", name="sandbox", gitops_url=str(origin),
                 gitops_branch="release", gitops_path="envs/sandbox")
    check("declaring an environment with its own repository clones it there and "
          "then — an empty checkout is not an answer to 'where do its values "
          "live'",
          "cloned" in urllib.parse.unquote_plus(r.headers.get("location", "")))
    other = store.source_dir(str(origin), "release")
    check("into a checkout keyed by (repository, branch), so environments that "
          "share one do not clone it twice",
          (other / ".git").is_dir())
    b = repo.binding(pid2, rg2, "sandbox")
    check("an environment in a different repository, on a different branch, "
          "reads from that checkout",
          b["url"] == str(origin) and b["branch"] == "release"
          and repo.list_envs(pid2, rg2).get("sandbox") == ["web-values.yaml"])
    check("and its file resolves inside ITS checkout, not the region's",
          str(repo.values_path(pid2, rg2, "sandbox", "web-values.yaml"))
          .startswith(str(other.resolve())))
    check("while the siblings on the shared repository read the shared "
          "checkout — one clone per (repository, branch), not per environment",
          str(repo.values_path(pid2, rg2, "dev", "api-values.yaml"))
          .startswith(str(moved.resolve())))
    check("a blank repository field COPIES the repo the siblings share, "
          "stored explicitly — declaring uat above needed only a name, and "
          "its row still shows the whole truth",
          repo.binding(pid2, rg2, "uat")["url"] == "https://example.com/x.git")

    r = env_post("sync", name="sandbox")
    check("and that checkout can be pulled on its own — the region's Sync only "
          "ever touched the region's working copy, which is the wrong one",
          "cloned" in urllib.parse.unquote_plus(r.headers.get("location", ""))
          or "updated" in urllib.parse.unquote_plus(r.headers.get("location", "")))

    for climb in ("../etc", "a/../../b", ".."):
        r = env_post("add", name="climb", gitops_path=climb)
        loc = urllib.parse.unquote_plus(r.headers.get("location", ""))
        if "leaves the repository" not in loc:
            check(f"a path that climbs out of the checkout is refused ({climb})",
                  False)
    r = env_post("add", name="slashname/x", gitops_path="")
    check("an environment name with a slash is refused — it is one segment",
          "no slashes" in urllib.parse.unquote_plus(
              r.headers.get("location", "")))
    r = env_post("add", name="bad", gitops_url="not-a-repo-address")
    check("something that is not a repository address is refused",
          "repository address" in urllib.parse.unquote_plus(
              r.headers.get("location", "")))

    print("an environment can authenticate on its own, and a secret is never "
          "stored or rendered in the clear")
    env_post("add", name="otherhost", gitops_url="https://other.example.com/z.git",
             gitops_branch="main", gitops_path="envs/x",
             gitops_protocol="https", gitops_username="z-bot",
             gitops_secret="tok-abc-123")
    dec = store.env_sources(pid2, rg2)["otherhost"]
    check("its token is SEALED at rest, not sitting in the JSON blob",
          secretbox.sealed(dec["secret"])
          and secretbox.unseal(dec["secret"]) == "tok-abc-123")
    b = repo.binding(pid2, rg2, "otherhost")
    check("the binding reports THAT it has credentials without carrying them — "
          "a template cannot print what it is never given",
          b["has_own_auth"] and b["has_secret"] and "secret" not in b)
    er = gitrepo.env_repo(pid2, rg2, "otherhost")
    check("and the one reader that needs the real value gets it, with this "
          "environment's own username rather than the region's",
          secretbox.unseal(er["secret"]) == "tok-abc-123"
          and er["username"] == "z-bot")
    page = c.get("/settings/clusters").text
    check("the token appears NOWHERE on the rendered page",
          "tok-abc-123" not in page)

    # Write-only, like every other credential field in the portal — and it has
    # to hold at BOTH layers. The route omits the key when the field is blank;
    # the store ALSO refuses to write an empty one. Testing only the route
    # leaves the store free to regress for every other caller of it (MCP, a
    # future form), which is exactly what a bite-test of the store guard
    # revealed: the route-level assertion below passed without it.
    env_post("add", name="otherhost", gitops_url="https://other.example.com/z.git",
             gitops_branch="main", gitops_path="envs/x",
             gitops_protocol="https", gitops_username="z-bot-2")
    dec = store.env_sources(pid2, rg2)["otherhost"]
    check("saving that environment again WITHOUT retyping the token keeps it — "
          "a browser cannot re-send a secret it was never shown, so blank has "
          "to mean unchanged",
          secretbox.unseal(dec["secret"]) == "tok-abc-123"
          and dec["username"] == "z-bot-2")
    store.set_env_source(pid2, rg2, "otherhost",
                         {"secret": "", "username": "z-bot-3"})
    dec = store.env_sources(pid2, rg2)["otherhost"]
    check("and an explicit empty secret straight into the store is refused "
          "too — blank never means 'clear it', whoever the caller is",
          secretbox.unseal(dec["secret"]) == "tok-abc-123"
          and dec["username"] == "z-bot-3")

    check("an environment whose repository never had credentials reports "
          "none — has_own_auth is a statement about what is stored, not a "
          "guess about what might work",
          not repo.binding(pid2, rg2, "dev")["has_own_auth"])

    print("a blank repository copies what the siblings share — visibly")
    pid3 = store.add_project("Adopt", icon="\N{TEST TUBE}")
    rg3 = store.add_region(pid3, "UAE", flag="")
    c.post(f"/settings/project/{pid3}/region/{rg3}/env/add",
           data={"name": "dev", "gitops_url": str(origin),
                 "gitops_branch": "release", "gitops_path": "envs/sandbox",
                 "gitops_username": "shared-bot", "gitops_secret": "tok-shared"},
           follow_redirects=False)
    c.post(f"/settings/project/{pid3}/region/{rg3}/env/add",
           data={"name": "uat", "gitops_path": "envs/uat"},
           follow_redirects=False)
    got = store.env_sources(pid3, rg3)["uat"]
    check("the second environment left the repository blank and got the "
          "sibling's — url, branch AND credentials, stored ON it where a form "
          "can show them",
          got.get("url") == str(origin) and got.get("branch") == "release"
          and got.get("username") == "shared-bot"
          and secretbox.unseal(got.get("secret", "")) == "tok-shared")
    c.post(f"/settings/project/{pid3}/region/{rg3}/env/add",
           data={"name": "prod", "gitops_url": "https://example.com/second.git",
                 "gitops_path": "envs/prod"}, follow_redirects=False)
    check("a later declaration naming a DIFFERENT repository keeps it — the "
          "copy rule fills blanks, it never overrides what was typed",
          store.env_sources(pid3, rg3)["prod"].get("url")
          == "https://example.com/second.git")
    c.post(f"/settings/project/{pid3}/region/{rg3}/env/add",
           data={"name": "stage", "gitops_path": "envs/stage"},
           follow_redirects=False)
    check("and once the siblings DISAGREE about the repository, a blank stays "
          "blank — copying either one would be a guess, and the row says so",
          not store.env_sources(pid3, rg3)["stage"].get("url"))

    print("a token rotation typed once reaches every sibling on that repo")
    c.post(f"/settings/project/{pid3}/region/{rg3}/env/add",
           data={"name": "dev", "gitops_url": str(origin),
                 "gitops_branch": "release", "gitops_path": "envs/sandbox",
                 "gitops_username": "shared-bot", "gitops_secret": "tok-rotated"},
           follow_redirects=False)
    check("rotating the token on ONE environment updated the sibling on the "
          "same repository too — the old token silently expiring on the rest "
          "is the failure this propagation exists to prevent",
          secretbox.unseal(store.env_sources(pid3, rg3)["uat"]
                           .get("secret", "")) == "tok-rotated")
    check("and did NOT touch the environment on the other repository",
          not store.env_sources(pid3, rg3)["prod"].get("secret"))

    # A declaration naming a (repository, branch) another region already
    # cloned REUSES that checkout — shared per (url, branch) across regions
    # and projects, which is the whole point of keying it that way. The
    # values must be readable with no clone having run at all.
    pid4 = store.add_project("Adopt2", icon="\N{TEST TUBE}")
    rg4 = store.add_region(pid4, "KE", flag="")
    r = c.post(f"/settings/project/{pid4}/region/{rg4}/env/add",
               data={"name": "dev", "gitops_url": str(origin),
                     "gitops_branch": "release", "gitops_path": "envs/sandbox"},
               follow_redirects=False)
    loc = urllib.parse.unquote_plus(r.headers.get("location", ""))
    check("a declaration naming an already-cloned (repo, branch) reuses the "
          "shared checkout — one clone serves every region that names it",
          "cloned" not in loc and "1 values file found" in loc)
    check("and its values are actually readable afterwards",
          repo.list_envs(pid4, rg4).get("dev") == ["web-values.yaml"])
    # …while a branch nobody has cloned yet IS fetched on declaration —
    # there is nothing on disk for it, and "0 values files" with no reason
    # given is the failure an earlier fetch-gating bug produced.
    g("branch", "second", cwd=work)
    g("push", "-q", "origin", "second", cwd=work)
    r = c.post(f"/settings/project/{pid4}/region/{rg4}/env/add",
               data={"name": "beta", "gitops_url": str(origin),
                     "gitops_branch": "second", "gitops_path": "envs/sandbox"},
               follow_redirects=False)
    loc = urllib.parse.unquote_plus(r.headers.get("location", ""))
    check("a branch with no checkout yet is cloned at declaration",
          "cloned" in loc
          and repo.list_envs(pid4, rg4).get("beta") == ["web-values.yaml"])
    pid5 = store.add_project("Adopt3", icon="\N{TEST TUBE}")
    rg5 = store.add_region(pid5, "KE", flag="")
    r = c.post(f"/settings/project/{pid5}/region/{rg5}/env/add",
               data={"name": "dev", "gitops_url": "/nonexistent/nope.git",
                     "gitops_path": "envs/dev"}, follow_redirects=False)
    check("an unreachable repository says so rather than reporting an empty "
          "environment as if that were the answer",
          "could not be read" in urllib.parse.unquote_plus(
              r.headers.get("location", "")))

    # `clone_or_pull` DELETES its destination when a clone fails. So a
    # declaration that names no repository must not trigger a fetch: an earlier
    # version fired whenever the checkout had no `.git`, and declaring a second
    # environment in a region whose remote was unreachable wiped the working
    # copy that already held every other environment's values. Its own region,
    # so the same-path fold cannot confuse what is being measured.
    pid6 = store.add_project("NoWipe", icon="\N{TEST TUBE}")
    rg6 = store.add_region(pid6, "KE", flag="")
    keep = store.repo_dir(pid6, rg6) / "values" / "dev" / "api-values.yaml"
    keep.parent.mkdir(parents=True, exist_ok=True)
    keep.write_text("image:\n  tag: 1.0\n")
    store.set_region_repo(pid6, rg6, {"url": "https://unreachable.invalid/x.git",
                                      "values_path": "values"})
    check("the working copy is there before we start", keep.exists())
    # first read materialises + absorbs: the legacy record names an
    # UNREACHABLE remote, and the files must survive that whole journey
    envs6 = repo.list_envs(pid6, rg6, include_hidden=True)
    kept_at = repo.checkout(pid6, rg6, "dev") / "values" / "dev" / "api-values.yaml"
    check("the absorb migration moved the files rather than losing them, even "
          "though their remote does not answer",
          "dev" in envs6 and kept_at.exists())
    c.post(f"/settings/project/{pid6}/region/{rg6}/env/add",
           data={"name": "dev2", "gitops_path": "values/dev2"},
           follow_redirects=False)
    check("declaring another environment must not destroy that checkout — a "
          "clone that fails may only remove a directory it created itself, "
          "never a tree that was already there",
          kept_at.exists())
    r = c.post(f"/settings/project/{pid6}/region/{rg6}/env/sync",
               data={"name": "dev"}, follow_redirects=False)
    check("and an explicit sync against the dead remote REFUSES rather than "
          "wiping the tree to make room for a clone that cannot succeed",
          kept_at.exists()
          and "not a git repository" in urllib.parse.unquote_plus(
              r.headers.get("location", "")))

    # the scan survives as a SUGGESTION: offered on request, never applied
    got = c.get(f"/settings/project/{pid2}/region/{rg2}/env/candidates").json()
    names = {x["env"]: x for x in got["candidates"]}
    check("the repository can still be scanned — on request, as candidates",
          "dev" in names and names["dev"]["path"] == "values/dev")
    check("and it says which ones are already declared, rather than offering "
          "them again",
          names["dev"]["declared"] is True)
    check("a folder somebody undeclared is offered again rather than hidden — "
          "the scan is not a second opinion the portal keeps to itself",
          "docs" in names and names["docs"]["declared"] is False)
    before = set(store.env_sources(pid2, rg2))
    c.get(f"/settings/project/{pid2}/region/{rg2}/env/candidates")
    check("and looking changes nothing — that is the whole difference between "
          "this and the scan it replaced",
          set(store.env_sources(pid2, rg2)) == before)

    # every reader goes through list_envs, which is why declarations are
    # applied there rather than in each page
    envs_seen = repo.list_envs(pid2, rg2, include_hidden=True)
    check("include_hidden reads the same declarations — one implementation",
          "docs" not in envs_seen and "preprod" in envs_seen)
    page = c.get("/settings/clusters").text
    check("the page offers the declaration editor for a region",
          "declare an environment" in page)
    check("and a button to scan for candidates, where there is a checkout to "
          "scan — offered, never run by the page itself",
          'class="abtn envscan"' in page)
    check("and it shows for a project with NO cluster too — describing your "
          "environments cannot depend on already having somewhere to run them",
          not (store.get_project(pid2) or {}).get("clusters")
          and f'/region/{rg2}/env/add' in page)
    check("the panel's add-region form NAMES the project it acts on — acting "
          "near a cluster is not acting on its project, and a region once "
          "landed in the wrong one exactly this way",
          "add a region to Env Scan" in page)
    check("and the cluster form itself carries repo, branch and path",
          'name="gitops_url"' in page and 'name="gitops_branch"' in page
          and 'name="gitops_path"' in page)

    print("\nFAILED" if bad else "\nOK")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main_test())
