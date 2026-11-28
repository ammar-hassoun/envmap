#!/usr/bin/env python3
"""The Compose file runs the portal the way the chart does.

WHY THIS EXISTS
    deploy/compose/compose.yaml is a second description of one deployment: the
    portal, with guacd beside it sharing its network and its volume. The chart
    is the one that gets looked at, so the Compose file is the one that drifts.
    Three ways it can drift, each of which would ship without an error:

    * the gateway's image. The chart's guacd went 1.5.5 -> 1.6.0 for a CVE; a
      Compose file left on the old tag keeps every Compose install on it.
    * the sidecar's shape. guacd writes recordings into the portal's volume
      and the portal dials it on 127.0.0.1. Give it its own network or its own
      user and sessions still open, and their recordings are unreadable or the
      gateway "is not reachable".
    * what is put on the network. The portal holds credentials; the default
      must publish its port on this machine only.

    ./.venv/bin/python tests/test_compose.py
"""
from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy" / "compose" / "compose.yaml"
VALUES = ROOT / "deploy" / "helm" / "config-portal" / "values.yaml"

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"FAIL  {what}")


def default_of(text: str) -> str:
    """`${NAME:-value}` -> value; anything else as it is."""
    text = str(text)
    if text.startswith("${") and ":-" in text and text.endswith("}"):
        return text[text.index(":-") + 2:-1]
    return text


def main() -> int:
    doc = yaml.safe_load(COMPOSE.read_text())
    vals = yaml.safe_load(VALUES.read_text())
    portal, guacd = doc["services"]["envmap"], doc["services"]["guacd"]

    # ── the same images as the chart ────────────────────────────────────────
    repo, _, tag = portal["image"].partition(":")
    check("the portal image is the chart's", repo == vals["image"]["repository"])
    check("the portal tag follows the newest release unless one is named", default_of(tag) == "latest")
    grepo, _, gtag = guacd["image"].partition(":")
    check("the gateway image is the chart's", grepo == vals["guacd"]["image"]["repository"])
    check("the gateway tag is the chart's (a CVE bump must reach Compose installs too)",
          default_of(gtag) == str(vals["guacd"]["image"]["tag"]))

    # ── the portal ──────────────────────────────────────────────────────────
    env = portal["environment"]
    check("the portal is told a network bind is intended", str(env.get("PORTAL_ALLOW_NETWORK")) == "1")
    check("the mode defaults to the whole product, like the chart", default_of(env.get("PORTAL_MODE")) == vals["portal"]["mode"])
    check("the sealing key can be set and defaults to empty", default_of(env.get("PORTAL_SECRET_KEY")) == "")
    ports = portal.get("ports") or []
    check("exactly one port is published", len(ports) == 1)
    host, _, rest = str(ports[0]).partition(":${ENVMAP_PORT")
    check("the port is published on this machine only by default", default_of(host) == "127.0.0.1")
    check("it is the portal's port", str(ports[0]).endswith(f":{vals['service']['port']}"))
    mount = vals["persistence"]["mountPath"]
    check("the data volume is mounted where the image keeps its state", f"data:{mount}" in portal["volumes"])

    # ── the gateway is a sidecar in everything but name ─────────────────────
    check("guacd shares the portal's network, so 127.0.0.1:4822 reaches it",
          guacd.get("network_mode") == "service:envmap")
    check("guacd publishes nothing", not guacd.get("ports"))
    check("guacd shares the volume, at the same path, so recordings land where they are served",
          f"data:{mount}" in guacd["volumes"])
    uid = str(vals["podSecurityContext"]["runAsUser"])
    check("guacd runs as the portal's user, so each can read what the other wrote",
          str(guacd.get("user")) == f"{uid}:{uid}")

    # ── the chart's hardening, on both ──────────────────────────────────────
    for name, svc in (("portal", portal), ("guacd", guacd)):
        check(f"{name}: read-only root filesystem", svc.get("read_only") is True)
        check(f"{name}: every capability dropped", svc.get("cap_drop") == ["ALL"])
        check(f"{name}: no privilege escalation", "no-new-privileges:true" in (svc.get("security_opt") or []))
        check(f"{name}: /tmp is writable", any(str(t).split(":")[0] == "/tmp" for t in svc.get("tmpfs") or []))
    check("the portal has a writable home (git and kubectl want one)",
          any(str(t).split(":")[0] == "/home/portal" for t in portal.get("tmpfs") or []))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(main())
