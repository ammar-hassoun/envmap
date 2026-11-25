#!/usr/bin/env python3
"""Which namespaces an environment deploys into.

The topology drawing needs this, and got nothing for a repository that keeps
its namespaces where Argo CD keeps them — in the Application's destination
rather than in each values file. Seven services, an empty diagram, and a
message saying no namespaces were found.

The awkward part is not finding them; it is not finding the *other*
environments' as well, because the same service is called the same thing in
dev and uat.

    PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_namespaces.py
"""
from __future__ import annotations

import os
import pathlib
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("ns-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import repo, store                                    # noqa: E402

bad = 0


def check(what: str, cond) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


APP = """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {name}
  namespace: argocd
spec:
  project: {ns}
  source:
    repoURL: git@example.com:acme/gitops.git
    path: apps/microservice
    helm:
      valueFiles:
        - environments/{env}/{values}
  destination:
    server: https://kubernetes.default.svc
    namespace: {ns}
"""


def main() -> int:
    pid = store.add_project("Topology")
    rgid = store.add_region(pid, "KSA")
    # no url on purpose: the fixture plants files by hand, and a fake url
    # would make the absorb migration move the tree mid-test
    store.set_region_repo(pid, rgid, {
        "values_path": "apps/microservice/environments"})
    root = store.repo_dir(pid, rgid)

    # the layout that broke it: one shared chart, environments separated by
    # directory, and not a single `namespace:` in any values file
    for env in ("dev", "uat"):
        d = root / "apps" / "microservice" / "environments" / env
        d.mkdir(parents=True, exist_ok=True)
        for svc in ("demo-lms-backend", "demo-lms-client"):
            (d / f"{svc}-values.yaml").write_text(
                f'fullnameOverride: "{svc}"\nimage:\n  repository: r/{svc}\n'
                f'  tag: "abc"\n')
        apps = root / "apps" / "argocd" / env
        apps.mkdir(parents=True, exist_ok=True)
        for svc in ("demo-lms-backend", "demo-lms-client"):
            (apps / f"{env}-{svc}.yaml").write_text(APP.format(
                name=f"{env}-{svc}", ns=f"{env}-deployment", env=env,
                values=f"{svc}-values.yaml"))

    check("no values file declares a namespace",
          all("namespace" not in
              (root / "apps/microservice/environments/dev" / f).read_text()
              for f in repo.all_files(pid, rgid, "dev")))

    got = repo.namespaces(pid, rgid, "dev")
    check(f"dev finds its namespace, got {got}", got == ["dev-deployment"])
    got = repo.namespaces(pid, rgid, "uat")
    check(f"uat finds its own and not dev's, got {got}",
          got == ["uat-deployment"])
    print("  a namespace declared only by the Argo CD Application is found")
    print("  and an environment does not claim another one's")

    # a values file that does say so is still read, and both sources combine
    (root / "apps/microservice/environments/dev/extra-values.yaml").write_text(
        "namespace: dev-extras\nfullnameOverride: extra\n")
    got = repo.namespaces(pid, rgid, "dev")
    check(f"both sources are used, got {got}",
          got == ["dev-deployment", "dev-extras"])
    print("  a top-level namespace: in a values file still counts")

    # an Application for an environment with no directory of its own must not
    # be handed to whichever environment happens to be asking
    apps = root / "apps" / "argocd" / "prod"
    apps.mkdir(parents=True, exist_ok=True)
    (apps / "prod-demo.yaml").write_text(APP.format(
        name="prod-demo", ns="prod-deployment", env="prod",
        values="demo-lms-backend-values.yaml"))
    got = repo.namespaces(pid, rgid, "dev")
    check(f"a prod Application does not leak into dev, got {got}",
          "prod-deployment" not in got)
    print("  an Application naming another environment stays out of this one")

    # nothing to read is not an error
    empty_rg = store.add_region(pid, "Nowhere")
    check("a region with no checkout returns nothing rather than raising",
          repo.namespaces(pid, empty_rg, "dev") == [])

    print("\nFAILED" if bad else "\nOK")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
