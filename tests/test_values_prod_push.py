#!/usr/bin/env python3
"""Pushing a production values file wants a name typed, as the README says.

WHY THIS EXISTS
    The README has long said production pushes need an extra confirmation, and
    the values window asked exactly what every push asks — "Push this file to
    main?" — whatever environment it was. The one irreversible button in the
    window had the weakest gate in the product for the environment that
    matters most.

    So the commit route is asked for a production environment with no name, the
    wrong name and the right one: the first two must stop before git is
    touched and leave an audit line, the third must push. Which environment is
    production follows its ALIAS, not its folder, and the name is the serving
    cluster's when one serves it — the gesture production asks for everywhere
    else — or the environment's own when nothing does. A non-production push
    asks for nothing. The window is asked for its half too: it names what to
    type before the push rather than after a refusal.

    ./.venv/bin/python tests/test_values_prod_push.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("valuespush-test-")
os.environ.setdefault("PORTAL_SCHEDULER", "0")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                      # noqa: E402

from app import aitools, auth, db, git_ops, gitrepo, main, repo, store  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


P = store.add_project("Pushes")
# `prd` is production by its alias, which is the case a folder-name check gets
# wrong; `kept` is production with no cluster serving it.
store.update_project(P, env_aliases={"prd": "production", "kept": "prod"})
RG = store.add_region(P, "Main")
LIVE = store.add_cluster(P, "live", "apiVersion: v1\n", "ctx-live")
STAGE = store.add_cluster(P, "stage-one", "apiVersion: v1\n", "ctx-stage")
store.map_env_cluster(P, RG, "prd", LIVE)
store.map_env_cluster(P, RG, "staging", STAGE)

PUSHED: list = []


def _push(pid, rgid, conf, rels, message="", new_branch="", author=None,
          env_name=""):
    PUSHED.append(env_name)
    return {"sha": "abc1234", "branch": "main", "noop": False}


gitrepo.commit_and_push = _push
gitrepo.env_repo = lambda pid, rgid, env: {"url": ""}
gitrepo.commit_url = lambda url, sha: ""
git_ops.diff_file = lambda pid, rgid, rel, env="": ""
git_ops.region_status = lambda pid, rgid, check_remote=True, env="": {
    "branch": "main"}
repo.rel_path = lambda pid, rgid, env, fname: f"{env}/{fname}"
repo.read_raw = lambda pid, rgid, env, fname: "image:\n  tag: v1\n"


def signed_in():
    email, pw = "pusher@test.invalid", "Push-To-Prod-Carefully-3"
    uid = auth.create_user(email, "CI", pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    c = TestClient(main.app, raise_server_exceptions=False)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def push(c, env: str, **extra) -> dict:
    r = c.post(f"/p/{P}/{RG}/{env}/s/svc-values.yaml/raw/commit",
               data={"message": "bump the tag", **extra},
               follow_redirects=False)
    return r.json()


def refused() -> int:
    return (db.one("SELECT COUNT(*) AS n FROM audit WHERE action = "
                   "'commit_refused'") or {"n": 0})["n"]


def main_test() -> int:
    c = signed_in()

    print("a production push needs the serving cluster's name")
    for typed, label in (("", "with no name"),
                         ("prd", "with the environment's folder name"),
                         ("production", "with the alias"),
                         ("LIVE", "with the name in the wrong case")):
        PUSHED.clear()
        before = refused()
        got = push(c, "prd", confirm=typed)
        check(f"{label} it is refused ({got.get('error', '')[:80]!r})",
              got.get("ok") is False
              and "this environment is production" in got.get("error", "")
              and "(live)" in got.get("error", ""))
        check(f"{label} nothing is pushed ({PUSHED})", PUSHED == [])
        check(f"{label} the refusal is audited", refused() == before + 1)
    got = push(c, "prd")
    check("and the refusal names what to type", got.get("confirm") == "live")
    PUSHED.clear()
    got = push(c, "prd", confirm=" live ")
    check(f"with the cluster's name it pushes ({PUSHED})",
          got.get("ok") is True and PUSHED == ["prd"])

    print("production follows the alias, and the name falls back to the env's")
    PUSHED.clear()
    got = push(c, "kept")
    check(f"an aliased production env nothing serves wants ITS name "
          f"({got.get('error', '')[:70]!r})",
          "type its name (kept)" in got.get("error", "") and PUSHED == [])
    push(c, "kept", confirm="kept")
    check(f"which pushes it ({PUSHED})", PUSHED == ["kept"])

    print("anything that is not production asks for nothing")
    PUSHED.clear()
    got = push(c, "staging")
    check(f"staging pushes on the ordinary confirmation ({PUSHED})",
          got.get("ok") is True and PUSHED == ["staging"])
    check("and the rule says so directly",
          aitools.confirm_push(P, RG, "staging", "") == ""
          and aitools.push_name(P, RG, "staging") == "")

    print("the window knows what to ask for before it pushes")
    for env, want in (("prd", "live"), ("kept", "kept"), ("staging", "")):
        r = c.get(f"/p/{P}/{RG}/{env}/s/svc-values.yaml/raw.json")
        check(f"{env}: raw.json names {want or 'nothing'} "
              f"({r.json().get('confirm_name')!r})",
              r.json().get("confirm_name") == want)
    win = (ROOT / "templates" / "_values_dialog.html").read_text()
    check("the commit panel carries the name field", 'id="vfConfirm"' in win)
    check("shown only when there is a name to type",
          "vfConfirmWrap').hidden = !doc.confirm_name" in win)
    check("checked before the push is sent",
          "nameIn.value.trim() !== doc.confirm_name" in win)
    check("and sent with it", "confirm: nameIn.value" in win)
    # Found in a browser: a wrong name, then the right one and a cancelled
    # "push this?", left "type live to push" beside a field reading live.
    js = re.sub(r"//[^\n]*", "", win)
    gate = js.index("nameIn.value.trim() !== doc.confirm_name")
    ask = js.index("confirm('Push '", gate)
    check("a refusal's note is cleared once the checks it reported pass",
          "note.textContent = '';" in js[js.index("return;", gate):ask])

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
