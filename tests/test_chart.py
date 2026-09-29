#!/usr/bin/env python3
"""Every setting the chart writes is one the pod can actually read.

WHY THIS EXISTS
    The chart rendered a Secret holding PORTAL_UPDATE_URL,
    PORTAL_UPDATE_URL and PORTAL_SECRET_KEY, hashed it into a pod annotation so
    a change would roll the Deployment — and never referenced it. envFrom was
    rendered only from portal.extraEnvFrom, so the chart's own Secret was
    orphaned and every value only it carried did nothing.

    `--set portal.secretKey=<key>` is the documented way to set the
    install. It wrote the key to that Secret. The portal never saw it, reported
    itself as an unlicensed trial, and nothing failed: not the install, not the
    lint, not the render, not the pod. It was found by asking a running pod what
    it actually had, on the first real deployment.

    So the assertion here is deliberately not "envFrom mentions the secret". It
    is the general form — for every key the chart defines anywhere, something in
    the pod spec must deliver it — because the next value added to that Secret
    would otherwise be dead in exactly the same silent way.

    ./.venv/bin/python tests/test_chart.py
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHART = ROOT / "deploy" / "helm" / "config-portal"

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def render(*sets: str) -> list:
    """The chart's objects, as dicts."""
    cmd = ["helm", "template", "t", str(CHART)]
    for s in sets:
        cmd += ["--set", s]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode:
        print(out.stderr.strip()[:600])
        raise SystemExit("helm template failed")
    import yaml
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def pod_of(objs: list) -> dict:
    dep = next(o for o in objs if o["kind"] == "Deployment")
    return dep["spec"]["template"]["spec"]


def container_of(objs: list) -> dict:
    return pod_of(objs)["containers"][0]


def delivered(objs: list) -> set:
    """Every environment variable name the container will actually receive."""
    c = container_of(objs)
    names = {e["name"] for e in c.get("env", [])}
    by_name = {o["metadata"]["name"]: o for o in objs
               if o["kind"] in ("Secret", "ConfigMap")}
    for src in c.get("envFrom", []):
        ref = src.get("secretRef") or src.get("configMapRef") or {}
        obj = by_name.get(ref.get("name"))
        if obj:
            names |= set(obj.get("stringData", {}) or {})
            names |= set(obj.get("data", {}) or {})
    return names


def defined(objs: list) -> set:
    """Every PORTAL_* the chart writes into a Secret or ConfigMap."""
    out = set()
    for o in objs:
        if o["kind"] in ("Secret", "ConfigMap"):
            for k in list(o.get("stringData", {}) or {}) + list(o.get("data", {}) or {}):
                if k.startswith("PORTAL_"):
                    out.add(k)
    return out


def main() -> int:
    if not shutil.which("helm"):
        print("helm is not installed — skipping")
        return 0
    try:
        import yaml                                            # noqa: F401
    except ImportError:
        print("pyyaml is not installed — skipping")
        return 0

    print("nothing the chart writes is dead config")
    # with everything set, so no key is absent merely because its value is empty
    objs = render(
        "updateUrl=https://example.com/index.yaml",
        "portal.secretKey=0123456789abcdef0123456789abcdef",
    )
    orphaned = defined(objs) - delivered(objs)
    check(f"every PORTAL_* the chart defines reaches the pod, orphaned: "
          f"{sorted(orphaned)}", not orphaned)

    print("and the settings that carry a secret in particular")
    got = delivered(objs)
    for key in ("PORTAL_UPDATE_URL", "PORTAL_SECRET_KEY"):
        check(f"{key} reaches the pod", key in got)

    print("the gateway the PORTAL would add matches the one the CHART deploys")
    # The settings page can add the guacd sidecar to this install's own
    # Deployment when the chart did not — a customer sent a screenshot of that
    # card telling them to set a Helm value that was already the default. The
    # portal cannot read the chart from inside a pod, so it carries its own
    # copy of that container spec, and a copy is a thing that drifts. Pin it:
    # a gateway added by the button must be the gateway Helm would have
    # rendered, or the two produce subtly different pods.
    root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from app import pam, selfupdate                            # noqa: PLC0415
    vals = yaml.safe_load(
        (root / "deploy" / "helm" / "config-portal" / "values.yaml").read_text())
    gv = vals["guacd"]
    want = f"{gv['image']['repository']}:{gv['image']['tag']}"
    check(f"the image the button uses is the chart's ({want})",
          pam.DEFAULTS["guacd_image"] == want)
    side = render("guacd.enabled=true")
    dep = next(o for o in side if o["kind"] == "Deployment")
    chart_gw = next(c for c in dep["spec"]["template"]["spec"]["containers"]
                    if c["name"] == selfupdate.GUACD_CONTAINER)
    # COMPARED FIELD BY FIELD against the container the PORTAL would add, not
    # against a literal written here. A literal only pins the chart: the first
    # version of this passed happily while the portal's own copy was edited to
    # half the memory limit, which is the drift it exists to catch.
    mount = next(m["mountPath"] for m in chart_gw["volumeMounts"]
                 if m["name"] == "data")
    mine = selfupdate.gateway_container(want, mount)
    for field in ("name", "image", "imagePullPolicy", "securityContext",
                  "ports", "resources", "volumeMounts"):
        check(f"the button's {field} is the chart's {field}",
              mine[field] == chart_gw.get(field))
    # It shares the DATA volume, which is the whole reason it is a sidecar
    # rather than a Deployment of its own: it writes the recordings the portal
    # serves, and a ReadWriteOnce PVC cannot be shared across pods.
    check("...and that is the data volume the portal serves from",
          any(m.get("name") == "data" for m in mine["volumeMounts"]))

    print("the sealing key set at install time is the one the pod gets")
    check("it is held in a Secret, not a ConfigMap",
          all(o["kind"] != "ConfigMap" or "PORTAL_SECRET_KEY" not in
              (o.get("data") or {}) for o in objs))

    print("a setting can be removed again, not only added")
    # stringData is write-only: Kubernetes folds it into data, so a manifest
    # that sets stringData is compared by Helm's three-way merge against a live
    # object that has no stringData at all. Additions are seen, removals never
    # are — the old value stays in the Secret and in the pod through every
    # upgrade. A sealing key that cannot be withdrawn is the version of this
    # that matters, and it was live in the cluster before this was found.
    sec = next(o for o in objs if o["kind"] == "Secret")
    check("the Secret uses data, not stringData",
          "data" in sec and "stringData" not in sec)
    check("and the values really are base64",
          __import__("base64").b64decode(sec["data"]["PORTAL_SECRET_KEY"]).decode()
          == "0123456789abcdef0123456789abcdef")

    print("a setting nobody gave is not written at all")
    # Absent is not the same as empty: an empty value would override whatever
    # the image or the environment already carries.
    plain = render()
    check("no PORTAL_SECRET_KEY when none is given",
          "PORTAL_SECRET_KEY" not in defined(plain))
    check("and no update URL either",
          "PORTAL_UPDATE_URL" not in defined(plain))

    print("extraEnvFrom still composes rather than replacing")
    # the orphaned secret was reachable only by a customer setting extraEnvFrom
    # by hand, so the fix must not trade one for the other
    both = render("portal.extraEnvFrom[0].secretRef.name=customer-extra")
    refs = [s.get("secretRef", {}).get("name")
            for s in container_of(both).get("envFrom", [])]
    check(f"both sources are present, got {refs}",
          "customer-extra" in refs and any(r and r.endswith("-env") for r in refs))

    print("a private registry can be pulled from")
    check("no imagePullSecrets when none are named",
          "imagePullSecrets" not in pod_of(render()))
    pull = render("imagePullSecrets[0].name=ghcr")
    check("and they are set when one is",
          pod_of(pull).get("imagePullSecrets") == [{"name": "ghcr"}])

    print("cookies are secure once it is served over TLS")
    # inline env wins over envFrom, so this has to be checked on the delivered
    # value rather than on whichever copy happens to be read first
    tls = render("ingress.enabled=true", "ingress.tls[0].secretName=portal-tls",
                 "ingress.hosts[0].host=portal.example.com")
    env = {e["name"]: e["value"] for e in container_of(tls).get("env", [])}
    check(f"PORTAL_COOKIE_SECURE is 1 behind TLS, got {env.get('PORTAL_COOKIE_SECURE')!r}",
          env.get("PORTAL_COOKIE_SECURE") == "1")
    env = {e["name"]: e["value"] for e in container_of(render()).get("env", [])}
    check("and 0 without it", env.get("PORTAL_COOKIE_SECURE") == "0")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
