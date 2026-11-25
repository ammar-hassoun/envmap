#!/usr/bin/env python3
"""One values file in a window: read it, write it, seal into it, push it.

WHY THIS EXISTS
    This replaced a page, and a window that replaces a page inherits every one
    of that page's ways to be quietly wrong. Six of them are in here because
    each one either loses somebody's work or leaks a secret:

    1. **A file too broken to model must still OPEN.** The old page rendered a
       structured view first, so a values file with a YAML fault was a page that
       showed nothing useful about the file you had come to fix. The window
       edits TEXT, so `load_error` is reported beside the exact bytes on disk
       and the editor still works. If this regresses, the one file somebody
       urgently needs is the one they cannot reach.

    2. **Broken YAML must not be SAVED.** The mirror of the above. The working
       copy is the last place a syntax error stops before Argo takes it, so
       `save_raw` parses with the loader whose answer matches Helm's and refuses
       rather than writing. A duplicate key is the deliberate exception —
       reported, not refused, or the editor could not fix the very file it is
       warning about.

    3. **Text and comments must survive a round trip.** The file is under
       version control and its comments are why values are pinned. A save that
       silently re-emitted the document would produce a diff nobody wrote, and
       the commit would be unreviewable.

    4. **A sealed value must never come back, and must be scoped right.** The
       plaintext goes to kubeseal and nowhere else: not into the response, not
       into the audit trail, not into the file. And the blob is scoped `strict`
       to one namespace and one secret name, so the scope is read off the file
       rather than guessed — a blob sealed for the wrong scope commits cleanly
       and then fails to decrypt in the cluster, which is the worst failure
       available here.

    5. **The retired page's URL must not 404.** It is linked from portal search
       (three kinds of hit), Compare's per-environment columns, the assistant's
       answers, GitOps' "Edit in git", the environment page's tiles and the
       service just created. The route survives as a redirect that carries the
       four identifiers the window opens itself from.

    6. **Commit is the only irreversible button, and it must say so.** save and
       seal touch the working copy; only commit pushes. A window where the two
       are indistinguishable is one where somebody pushes a half-finished edit
       to production.

    kubeseal is not installed here and a cluster is not reachable, so the seal
    tests replace `sealing.seal_value` with a recorder — what is under test is
    the plumbing and the scope, not the encryption.

    ./.venv/bin/python tests/test_valuesdialog.py
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("valuesdlg-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import repo, sealing, store                           # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Comments, a blank line, quoting and a sealed block — everything a save has to
# leave alone.
FILE = """# the api gateway. do not raise replicas without asking capacity.
namespace: pay-dev
name: gateway
replicaCount: 2

image:
  repository: registry.example/gateway
  tag: "1.4.2"          # pinned deliberately

config:
  API_URL: https://api.example
  TIMEOUT: "30"

secret:
  enabled: true
  secretName: gateway-secret
  SealedSecret:
    EXISTING_KEY: AgBv0xxxxx
"""

BROKEN = """namespace: pay-dev
name: gateway
config:
   API_URL: [unclosed
"""

DUPLICATE = """namespace: pay-dev
name: gateway
replicaCount: 2
replicaCount: 5
"""

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def setup() -> tuple:
    pid = store.add_project("Values Window", "🧪")
    rgid = store.add_region(pid, "one-region")
    root = store.repo_dir(pid, rgid)
    envdir = root / "dev"
    envdir.mkdir(parents=True, exist_ok=True)
    (envdir / "gateway-values.yaml").write_text(FILE)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # no url on purpose: this fixture plants files by hand, and a fake url would
    # make the absorb migration move the tree mid-test (see CLAUDE.md)
    store.set_region_repo(pid, rgid, {"protocol": "https", "values_path": ""})
    return pid, rgid, "dev", "gateway-values.yaml"


# ── read and write the text ────────────────────────────────────
def test_text_round_trip(pid, rgid, env, fname):
    print("the file reads back exactly as it sits on disk")
    text = repo.read_raw(pid, rgid, env, fname)
    check("byte-identical to what was written", text == FILE)

    print("a save preserves comments, blank lines and quoting")
    edited = text.replace("replicaCount: 2", "replicaCount: 3")
    warnings = repo.save_raw(pid, rgid, env, fname, edited)
    after = repo.read_raw(pid, rgid, env, fname)
    check("the change landed", "replicaCount: 3" in after)
    check("no warnings on a clean file", warnings == [])
    check("the header comment survived",
          after.startswith("# the api gateway."))
    check("the trailing comment survived", "# pinned deliberately" in after)
    check("the blank line survived", "\n\nimage:" in after)
    check("the quoted string is still quoted", 'tag: "1.4.2"' in after)
    check("the sealed block is untouched", "EXISTING_KEY: AgBv0xxxxx" in after)
    # Only the one line differs — a writer that re-emits the document would
    # produce a diff nobody wrote, which is unreviewable in a pull request.
    diff = [(a, b) for a, b in zip(FILE.splitlines(), after.splitlines())
            if a != b]
    check(f"exactly one line changed ({len(diff)})", len(diff) == 1)
    repo.save_raw(pid, rgid, env, fname, FILE)


def test_a_missing_trailing_newline_is_added(pid, rgid, env, fname):
    print("a file saved without a trailing newline gets one")
    # Every editor's last line. Without this, git reports "\\ No newline at end
    # of file" on a diff the person did not intend to make.
    repo.save_raw(pid, rgid, env, fname, "namespace: x\nname: y")
    check("it ends with a newline",
          repo.read_raw(pid, rgid, env, fname).endswith("\n"))
    repo.save_raw(pid, rgid, env, fname, FILE)


def test_broken_yaml_is_refused(pid, rgid, env, fname):
    print("broken YAML is refused, and nothing is written")
    before = repo.read_raw(pid, rgid, env, fname)
    try:
        repo.save_raw(pid, rgid, env, fname, BROKEN)
        check("it was refused", False)
    except ValueError as e:
        check(f"refused, and says so plainly ({str(e)[:46]}…)",
              "not valid YAML" in str(e) and "not saved" in str(e))
    check("the file on disk is untouched",
          repo.read_raw(pid, rgid, env, fname) == before)


def test_a_duplicate_key_is_reported_not_refused(pid, rgid, env, fname):
    print("a duplicate key is a warning, not a refusal")
    # Helm keeps the last one, so the file is legal and a real repository can
    # already contain it. Refusing would make this editor unable to fix it.
    warnings = repo.save_raw(pid, rgid, env, fname, DUPLICATE)
    check("it was saved", "replicaCount: 5" in repo.read_raw(pid, rgid, env, fname))
    check(f"and the duplicate is named ({warnings})",
          len(warnings) == 1 and "replicaCount" in warnings[0])
    repo.save_raw(pid, rgid, env, fname, FILE)


def test_a_file_too_broken_to_model_still_reads(pid, rgid, env, fname):
    print("a file the portal cannot model can still be opened and fixed")
    path = repo.values_path(pid, rgid, env, fname)
    path.write_text(BROKEN)                    # straight past save_raw's guard
    text = repo.read_raw(pid, rgid, env, fname)
    check("the text comes back whole", text == BROKEN)
    modelled = True
    try:
        repo.load_service(pid, rgid, env, fname)
    except Exception:                                          # noqa: BLE001
        modelled = False
    check("while the structured read genuinely fails", not modelled)
    # And the fix goes in through the same door.
    repo.save_raw(pid, rgid, env, fname, FILE)
    check("and saving a corrected file works",
          repo.load_service(pid, rgid, env, fname)["meta"]["name"] == "gateway")


# ── sealing ────────────────────────────────────────────────────
def test_sealing_scope_and_placement(pid, rgid, env, fname):
    print("a sealed value is scoped from the file and lands in its block")
    seen = {}
    real = sealing.seal_value

    def fake(p, cluster, namespace, secret_name, value):
        seen.update({"pid": p, "cluster": cluster, "ns": namespace,
                     "name": secret_name, "value": value})
        return "AgFAKEBLOB=="

    sealing.seal_value = fake
    try:
        meta = repo.load_service(pid, rgid, env, fname)["meta"]
        secret_name = meta["secret_name"] or f"{meta['name']}-secret"
        blob = sealing.seal_value(pid, {"id": "c1"}, meta["namespace"],
                                  secret_name, "s3cret-value")
        repo.save_sealed_secrets(pid, rgid, env, fname, {"NEW_KEY": blob})
    finally:
        sealing.seal_value = real

    # The scope is the whole correctness of a sealed blob: strict scoping ties
    # it to one namespace AND one secret name, and a blob sealed for the wrong
    # pair commits cleanly then fails to decrypt in the cluster.
    check(f"the namespace came from the file ({seen.get('ns')})",
          seen.get("ns") == "pay-dev")
    check(f"and so did the secret name ({seen.get('name')})",
          seen.get("name") == "gateway-secret")

    after = repo.read_raw(pid, rgid, env, fname)
    check("the blob is in the file", "AgFAKEBLOB==" in after)
    check("under the key it was given", "NEW_KEY:" in after)
    # Inside the SealedSecret block, not at the top level: a plain-looking key
    # somewhere else would be read as configuration, not as a secret.
    keys = repo.load_service(pid, rgid, env, fname)["secret_keys"]
    check(f"and the file agrees it is sealed ({keys})",
          "NEW_KEY" in keys and "EXISTING_KEY" in keys)
    check("the plaintext is nowhere in the file",
          "s3cret-value" not in after)
    repo.save_raw(pid, rgid, env, fname, FILE)


def test_rotating_an_existing_key_replaces_it(pid, rgid, env, fname):
    print("rotating a sealed key replaces the blob rather than adding a second")
    repo.save_sealed_secrets(pid, rgid, env, fname,
                             {"EXISTING_KEY": "AgROTATED=="})
    after = repo.read_raw(pid, rgid, env, fname)
    check("the new blob is there", "AgROTATED==" in after)
    check("the old one is gone", "AgBv0xxxxx" not in after)
    check("and there is still only one of that key",
          after.count("EXISTING_KEY:") == 1)
    repo.save_raw(pid, rgid, env, fname, FILE)


# ── the routes and the window they feed ────────────────────────
def test_the_routes_exist_and_are_thin():
    print("the four routes exist, under the config area's path prefix")
    src = (ROOT / "app" / "main.py").read_text()
    for verb, path in (("get", "/raw.json"), ("post", "/raw/save"),
                       ("post", "/raw/seal"), ("post", "/raw/commit"),
                       ("post", "/raw/discard")):
        want = f'@app.{verb}("/p/{{pid}}/{{rgid}}/{{env}}/s/{{fname}}{path}")'
        check(f"{verb.upper()} …{path}", want in src)
    # `/p/` is the `config` area in rbac.AREAS, so keeping the routes under that
    # prefix is what gates them — a new prefix would have been ungoverned.
    rbac = (ROOT / "app" / "rbac.py").read_text()
    check("and /p/ is still the config area's prefix",
          '"config": ("Configuration"' in rbac and '"/p/"' in rbac)

    print("each route wraps the function that already did the job")
    block = src[src.index("def _values_where("):src.index("def service_view(")]
    for call in ("repo.read_raw", "repo.save_raw", "sealing.seal_value",
                 "repo.save_sealed_secrets", "gitrepo.commit_and_push",
                 "git_ops.discard_file"):
        check(f"calls {call}", call in block)
    # A commit needs a message: an empty one produces a commit nobody can read
    # in a log, and the old page's form required it too.
    check("and a commit without a message is refused",
          "write a commit message" in block)


def test_the_retired_page_redirects_rather_than_404s():
    print("the retired page's URL redirects, carrying the identifiers")
    src = (ROOT / "app" / "main.py").read_text()
    i = src.index("def service_view(")
    view = src[i:src.index("@app.", i)]
    check("the route still exists",
          '@app.get("/p/{pid}/{rgid}/{env}/s/{fname}", response_class=HTMLResponse)'
          in src)
    check("it redirects rather than rendering", "RedirectResponse" in view
          and "TemplateResponse" not in view)
    for ident in ("vpid", "vrgid", "venv", "vfile"):
        check(f"it carries {ident}", f'"{ident}"' in view)
    check("to the serving cluster's GitOps repo tab", "tab=config" in view)
    check("or the environment's own page when nothing serves it",
          "tab=services" in view)
    check("and the page it used to render is gone",
          not (ROOT / "templates" / "service.html").exists())


def test_the_window_follows_the_house_popup_contract():
    print("the window is the house popup, not a new shape")
    page = (ROOT / "templates" / "_values_dialog.html").read_text()
    # Every pop-over in the product is one shape (CLAUDE.md). A second window
    # shape is the thing this check exists to prevent.
    check("it is a dialog.psh", 'class="psh vfwin"' in page)
    check("with the house window bar", 'class="psh-bar"' in page)
    for dot in ("close", "mini", "maxi"):
        check(f"with its {dot} dot", f'data-vfdot="{dot}"' in page)
    check("Escape is handled rather than closing on the browser's terms",
          "addEventListener('cancel'" in page)

    print("it opens from data attributes, like the other windows")
    check("delegated on [data-valuesfile]", "[data-valuesfile]" in page)
    check("and exposes openValues for code paths", "window.openValues" in page)
    # A modified click must stay a real navigation, or the row stops being a
    # link and ⌘-click quietly does nothing.
    check("modified clicks are left alone",
          "e.metaKey || e.ctrlKey || e.shiftKey || e.button" in page)

    print("the rows that open it carry the four identifiers")
    for tpl in ("clusters.html", "env.html"):
        t = (ROOT / "templates" / tpl).read_text()
        check(f"{tpl} marks its rows", "data-valuesfile" in t)
        for a in ("data-vfpid", "data-vfrgid", "data-vfenv", "data-vffile"):
            check(f"{tpl} carries {a}", a in t)
        check(f"{tpl} includes the window", '"_values_dialog.html"' in t)
        # The href stays real so the row is still a link and ⌘-click works.
        # clusters.html builds it server-side (sv.url); env.html writes it out.
        check(f"{tpl} keeps a working href",
              ('href="{{ sv.url }}"' in t) if tpl == "clusters.html"
              else ("/s/{{ f }}" in t))

    print("read-only until asked, and only commit pushes")
    check("it opens locked", "setEditing(false)" in page)
    check("save says it is the working copy only",
          "working copy" in page and "Nothing has been pushed yet" in page)
    check("and the push asks first", "confirm('Push " in page)

    print("the plaintext is treated as one")
    check("the value field is a password field",
          'id="vfSealVal"' in page and 'type="password"' in page)
    check("it is cleared once used", "valIn.value = ''" in page)
    check("and cleared again when the window closes",
          "vfSealVal').value = ''" in page)
    # Sealing rewrites the file server-side from what is on disk, so unsaved
    # text edits would be silently discarded by it.
    check("unsaved text edits block a seal rather than being lost",
          "save or revert your text edits first" in page)

    print("the seal panel names the scope it is sealing into")
    check("the scope is shown", "'into ' + doc.namespace" in page)
    check("and a missing scope is explained, not a dead button",
          "seal_why" in page)

    print("the style block stays under the cap")
    for m in re.finditer(r"<style>(.*?)</style>", page, re.S):
        check(f"style block is {len(m.group(1))} chars (cap 4000)",
              len(m.group(1)) <= 4000)


def test_nothing_still_points_at_the_deleted_code():
    print("no leftovers from the page that was removed")
    gone = ("svcview.sides", "svcview.gitops_side", "svcview.tag_rows",
            "svcview.LABELS", "svcview.ICONS", "svcview.LIVE_EDITABLE",
            "service.html")
    for d in ("app", "templates"):
        for f in (ROOT / d).rglob("*"):
            if not f.is_file() or f.suffix not in (".py", ".html"):
                continue
            text = f.read_text(errors="ignore")
            for sym in gone:
                # new_service.html is a different template that still exists
                if sym == "service.html" and "new_service.html" in text:
                    text = text.replace("new_service.html", "")
                check(f"{f.relative_to(ROOT)} does not use {sym}",
                      sym not in text)


def main() -> int:
    pid, rgid, env, fname = setup()
    test_text_round_trip(pid, rgid, env, fname)
    test_a_missing_trailing_newline_is_added(pid, rgid, env, fname)
    test_broken_yaml_is_refused(pid, rgid, env, fname)
    test_a_duplicate_key_is_reported_not_refused(pid, rgid, env, fname)
    test_a_file_too_broken_to_model_still_reads(pid, rgid, env, fname)
    test_sealing_scope_and_placement(pid, rgid, env, fname)
    test_rotating_an_existing_key_replaces_it(pid, rgid, env, fname)
    test_the_routes_exist_and_are_thin()
    test_the_retired_page_redirects_rather_than_404s()
    test_the_window_follows_the_house_popup_contract()
    test_nothing_still_points_at_the_deleted_code()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
