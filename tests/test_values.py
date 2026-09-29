#!/usr/bin/env python3
"""Editing every value in a values file, through the routes the page posts to.

The portal used to manage only the `config` block. These cases cover the rest of
a realistic file — a quoted image tag, an int, a bool, a nested resource limit, a
list of ingress hosts, a list item, a top-level addition — and the two rules that
keep GitOps diffs reviewable: one line changes per edit, and a scalar does not
change type because someone typed in a box.
"""
from __future__ import annotations

import difflib
import os
import pathlib
import subprocess
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("values-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import db, repo, store, values, yamledit                # noqa: E402

FILE = """# a real-shaped values file
replicaCount: 2
image:
  repository: registry.example.com/team/app
  tag: "1.20"          # pinned deliberately
  pullPolicy: IfNotPresent
resources:
  limits:
    cpu: 500m
    memory: 512Mi
ingress:
  enabled: true
  hosts:
    - host: app.example.com
      paths:
        - /
    - host: legacy.example.com
      paths:
        - /
config:
  API_URL: https://api.example.com
secret:
  secretName: app-secret
  SealedSecret:
    DB_PASSWORD: AgBv1x9kciphertext
"""

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def setup() -> tuple[str, str, str, str]:
    """A project, a region and an environment holding one values file."""
    pid = store.add_project("Values Test", "🧪")
    rgid = store.add_region(pid, "test-region")
    root = store.repo_dir(pid, rgid)
    envdir = root / "dev"
    envdir.mkdir(parents=True, exist_ok=True)
    (envdir / "app-values.yaml").write_text(FILE)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # no url on purpose: these fixtures plant files by hand, and a fake
    # url would make the absorb migration move the tree mid-test
    store.set_region_repo(pid, rgid, {"protocol": "https", "values_path": ""})
    return pid, rgid, "dev", "app-values.yaml"


def main() -> int:
    pid, rgid, env, fname = setup()
    path = repo.values_path(pid, rgid, env, fname)
    original = path.read_text()

    # ── what the page shows ────────────────────────────────────────────────
    loaded = repo.load_values(pid, rgid, env, fname)
    rows = {".".join(str(s) for s in r["path"]): r for r in loaded["rows"]}
    check("the whole tree is listed, not just config", len(rows) > 15)
    check("a nested scalar appears", "resources.limits.cpu" in rows)
    check("a list item appears", "ingress.hosts.0.host" in rows)
    check("the sealed section is marked protected",
          rows["secret.SealedSecret"]["protected"])
    check("sealed values are never offered for editing",
          not any("DB_PASSWORD" in k for k in rows))
    check("types are reported", rows["replicaCount"]["type"] == "int"
          and rows["ingress.enabled"]["type"] == "bool"
          and rows["image.tag"]["type"] == "str")

    # ── editing ───────────────────────────────────────────────────────────
    changed = repo.save_value_changes(pid, rgid, env, fname, {
        values.encode(["replicaCount"]): "4",
        values.encode(["ingress", "enabled"]): "false",
        values.encode(["resources", "limits", "cpu"]): "750m",
        values.encode(["image", "tag"]): "1.30",
        values.encode(["ingress", "hosts", 0, "host"]): "new.example.com",
    })
    check("five edits reported", len(changed) == 5)
    d = yamledit.parse(path.read_text())
    check("an int stays an int", d["replicaCount"] == 4)
    check("a bool stays a bool", d["ingress"]["enabled"] is False)
    check("a nested value is written", d["resources"]["limits"]["cpu"] == "750m")
    check("a quoted string stays a string",
          d["image"]["tag"] == "1.30" and isinstance(d["image"]["tag"], str))
    check("a list item is written",
          d["ingress"]["hosts"][0]["host"] == "new.example.com")
    check("the header comment survives",
          path.read_text().startswith("# a real-shaped values file"))
    check("a trailing comment survives", "# pinned deliberately" in path.read_text())

    # one line per edit, and nothing else
    diff = [l for l in difflib.unified_diff(original.splitlines(),
                                            path.read_text().splitlines(), n=0)
            if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    check(f"five edits produce ten diff lines, got {len(diff)}", len(diff) == 10)

    # an unchanged value is not reported as changed
    check("re-saving the same values reports nothing",
          repo.save_value_changes(pid, rgid, env, fname, {
              values.encode(["replicaCount"]): "4"}) == [])

    # ── adding ────────────────────────────────────────────────────────────
    repo.add_value(pid, rgid, env, fname, "", "priorityClassName", "high")
    repo.add_value(pid, rgid, env, fname,
                   values.encode(["resources", "limits"]), "ephemeral-storage", "1Gi")
    repo.add_value(pid, rgid, env, fname,
                   values.encode(["ingress", "hosts", 1, "paths"]), "", "/legacy")
    d = yamledit.parse(path.read_text())
    check("a top-level key is added", d["priorityClassName"] == "high")
    check("a nested key is added",
          d["resources"]["limits"]["ephemeral-storage"] == "1Gi")
    check("a list item is appended",
          list(d["ingress"]["hosts"][1]["paths"]) == ["/", "/legacy"])
    try:
        repo.add_value(pid, rgid, env, fname, "", "priorityClassName", "x")
        check("a duplicate key is refused", False)
    except ValueError as e:
        check("a duplicate key is refused with a reason", "already exists" in str(e))

    # ── deleting ──────────────────────────────────────────────────────────
    repo.delete_value(pid, rgid, env, fname, values.encode(["image", "pullPolicy"]))
    d = yamledit.parse(path.read_text())
    check("a key is deleted", "pullPolicy" not in d["image"])
    check("its siblings survive", d["image"]["tag"] == "1.30")
    repo.delete_value(pid, rgid, env, fname,
                      values.encode(["ingress", "hosts", 1, "paths", 1]))
    d = yamledit.parse(path.read_text())
    check("a list item is deleted",
          list(d["ingress"]["hosts"][1]["paths"]) == ["/"])
    try:
        repo.delete_value(pid, rgid, env, fname,
                          values.encode(["ingress", "hosts", 1, "paths", 0]))
        check("deleting the only list item is refused", False)
    except ValueError as e:
        check("deleting the only list item is refused with a reason",
              "only item" in str(e))

    # ── a path that no longer exists says so ─────────────────────────────
    try:
        repo.save_value_changes(pid, rgid, env, fname,
                                {values.encode(["image", "pullPolicy"]): "Always"})
        check("a stale path is refused", False)
    except ValueError as e:
        check("a stale path is refused in plain language",
              "no longer in this file" in str(e))

    # ── the file still parses, and a whole section can go ────────────────
    repo.delete_value(pid, rgid, env, fname, values.encode(["tolerations"])) \
        if "tolerations" in yamledit.parse(path.read_text()) else None
    repo.delete_value(pid, rgid, env, fname, values.encode(["resources"]))
    d = yamledit.parse(path.read_text())
    check("a whole section can be removed", "resources" not in d)
    check("the rest of the file is intact",
          d["replicaCount"] == 4 and d["ingress"]["hosts"][0]["host"] == "new.example.com"
          and d["secret"]["SealedSecret"]["DB_PASSWORD"] == "AgBv1x9kciphertext")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
