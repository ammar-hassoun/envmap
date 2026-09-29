#!/usr/bin/env python3
"""Repo LAYOUT is fully configurable — discovery works for ANY structure.

WHY THIS EXISTS
    Discovery used to assume exactly `<values_path>/<env>/<svc>-values*.yaml`.
    Now the layout is per-project config:
      - values_globs   : which files are services in the default env=folder layout
      - layout_pattern : a path pattern (under values_path) with {env} and {svc}
                         that covers flat / service-first / nested / anything.
    A custom-layout fname carries the file's rel path (`/`→`~`), decoded inside
    repo.py, so routes/templates/handlers are untouched. The DEFAULT stays
    byte-identical (existing repos untouched).

    ./.venv/bin/python tests/test_layout.py
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("layout-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import repo, store                                   # noqa: E402

bad = 0
VAL = "image:\n  repository: r/{s}\n  tag: t\nconfigMap:\n  data:\n    A: '1'\n"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def build(name: str, **proj):
    pid = store.add_project(name)
    if proj:
        store.update_project(pid, **proj)
    rgid = store.add_region(pid, "KE")
    # no url on purpose: layout fixtures plant files by hand, and a fake
    # url would make the absorb migration move the tree mid-test
    store.set_region_repo(pid, rgid, {"values_path": "envs"})
    return pid, rgid, store.repo_dir(pid, rgid) / "envs"


def loads_and_resolves(pid, rgid, env, fname, svc, physical):
    """Every layout must: discover the service, display it, resolve its real
    path, and load it — that's the whole read/edit chain the pages depend on."""
    check(f"  display → {svc}", repo.display(pid, fname) == svc)
    check(f"  path → {physical}", repo.values_path(pid, rgid, env, fname) == physical.resolve())
    check(f"  loads {svc}", repo.load_service(pid, rgid, env, fname)["meta"]["image_repo"] == f"r/{svc}")


def main() -> int:
    # ── 1. DEFAULT: <env>/<svc>-values.yaml (must be byte-identical) ──
    print("default: env folders + *-values*.yaml")
    pid, rgid, root = build("Default")
    for env in ("dev", "prod"):
        (root / env).mkdir(parents=True)
        for svc in ("web", "api"):
            (root / env / f"{svc}-values.yaml").write_text(VAL.format(s=svc))
    check("finds both envs & services",
          repo.list_envs(pid, rgid, include_hidden=True) ==
          {"dev": ["api-values.yaml", "web-values.yaml"], "prod": ["api-values.yaml", "web-values.yaml"]})
    loads_and_resolves(pid, rgid, "dev", "web-values.yaml", "web", root / "dev" / "web-values.yaml")

    # ── 2. CUSTOM GLOB: <env>/<svc>.yaml ──
    print("custom glob: env folders + plain <svc>.yaml")
    pid2, rgid2, root2 = build("Glob", values_globs=["*.yaml"])
    for env in ("dev", "prod"):
        (root2 / env).mkdir(parents=True)
        for svc in ("web", "api"):
            (root2 / env / f"{svc}.yaml").write_text(VAL.format(s=svc))
    check("finds <svc>.yaml",
          repo.list_envs(pid2, rgid2, include_hidden=True) ==
          {"dev": ["api.yaml", "web.yaml"], "prod": ["api.yaml", "web.yaml"]})
    loads_and_resolves(pid2, rgid2, "prod", "api.yaml", "api", root2 / "prod" / "api.yaml")

    # ── 3. FLAT: env in the filename, all in one dir ──
    print("pattern (flat): {svc}-{env}-values.yaml")
    pid3, rgid3, root3 = build("Flat", layout_pattern="{svc}-{env}-values.yaml")
    root3.mkdir(parents=True)
    for env in ("dev", "prod"):
        for svc in ("web", "api"):
            (root3 / f"{svc}-{env}-values.yaml").write_text(VAL.format(s=svc))
    (root3 / "notes.txt").write_text("ignore")
    check("groups by env-in-filename",
          repo.list_envs(pid3, rgid3, include_hidden=True) ==
          {"dev": ["api-dev-values.yaml", "web-dev-values.yaml"],
           "prod": ["api-prod-values.yaml", "web-prod-values.yaml"]})
    loads_and_resolves(pid3, rgid3, "dev", "web-dev-values.yaml", "web", root3 / "web-dev-values.yaml")

    # ── 4. SERVICE-FIRST: <svc>/<env>/values.yaml (basename collides — needs rel) ──
    print("pattern (service-first): {svc}/{env}/values.yaml")
    pid4, rgid4, root4 = build("SvcFirst", layout_pattern="{svc}/{env}/values.yaml")
    for svc in ("web", "api"):
        for env in ("dev", "prod"):
            (root4 / svc / env).mkdir(parents=True)
            (root4 / svc / env / "values.yaml").write_text(VAL.format(s=svc))
    envs4 = repo.list_envs(pid4, rgid4, include_hidden=True)
    check("groups the same-named files by env",
          envs4 == {"dev": ["api~dev~values.yaml", "web~dev~values.yaml"],
                    "prod": ["api~prod~values.yaml", "web~prod~values.yaml"]})
    # fname carries the rel path (encoded); it round-trips to the real file
    loads_and_resolves(pid4, rgid4, "dev", "web~dev~values.yaml", "web", root4 / "web" / "dev" / "values.yaml")
    check("rel_path is the real repo path",
          repo.rel_path(pid4, rgid4, "dev", "web~dev~values.yaml").endswith("envs/web/dev/values.yaml"))

    # ── 5. NESTED: <region>/<env>/<svc>-values.yaml (env is deep) ──
    print("pattern (nested): */{env}/{svc}-values.yaml")
    pid5, rgid5, root5 = build("Nested", layout_pattern="*/{env}/{svc}-values.yaml")
    for region in ("ap", "eu"):
        for env in ("dev", "prod"):
            (root5 / region / env).mkdir(parents=True)
            (root5 / region / env / "web-values.yaml").write_text(VAL.format(s="web"))
    envs5 = repo.list_envs(pid5, rgid5, include_hidden=True)
    check("env is the 2nd segment, region wildcarded + merged",
          sorted(envs5) == ["dev", "prod"] and "ap~dev~web-values.yaml" in envs5["dev"]
          and "eu~dev~web-values.yaml" in envs5["dev"])
    loads_and_resolves(pid5, rgid5, "dev", "ap~dev~web-values.yaml", "web", root5 / "ap" / "dev" / "web-values.yaml")

    # ── 6. CREATE a new service honours the pattern's placement ──
    print("create: a new service lands where the pattern says (service-first)")
    new_fname = repo.create_service(pid4, rgid4, "dev", "cache", "r/cache", "t", 8080, "ns", {"K": "v"})
    check("new file placed at <svc>/<env>/values.yaml",
          (root4 / "cache" / "dev" / "values.yaml").is_file() and new_fname == "cache~dev~values.yaml")
    check("and it is now discovered", "cache~dev~values.yaml" in repo.list_envs(pid4, rgid4, include_hidden=True)["dev"])

    # ── 7. AUTO-DETECT suggests the right layout for each structure ──
    print("auto-detect: scan the tree and suggest the layout")
    d1 = repo.detect_layout(pid, rgid)
    check("detects the default (blank config)",
          d1["kind"] == "default" and d1["pattern"] == "" and d1["globs"] == [] and d1["envs"] == ["dev", "prod"])
    d2 = repo.detect_layout(pid2, rgid2)
    check("detects a custom glob", d2["kind"] == "glob" and d2["globs"] == ["*.yaml"])
    d4 = repo.detect_layout(pid4, rgid4)
    check("service-first: env vocab settles env-vs-svc position",
          d4["pattern"] == "{svc}/{env}/values.yaml" and set(d4["envs"]) == {"dev", "prod"})
    d5 = repo.detect_layout(pid5, rgid5)
    check("nested: picks the region-wildcard pattern",
          d5["pattern"] == "*/{env}/{svc}-values.yaml" and set(d5["envs"]) == {"dev", "prod"})
    check("project-level detect finds a cloned region",
          repo.detect_layout_project(pid4)["pattern"] == "{svc}/{env}/values.yaml")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
