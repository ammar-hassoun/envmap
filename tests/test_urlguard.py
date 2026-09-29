#!/usr/bin/env python3
"""Every outbound fetch goes through one check.

A URL in this portal is configuration — somebody typed it into a settings form
— and configuration was trusted all the way to urllib, which will fetch any
scheme it is given. A VPN portal whose base URL was file:///tmp/probe returned
the file's contents through the portal's own error path.

The cases here are the ones that must stay closed, and the ones that must stay
open: the portal is *supposed* to reach 10.x and a hostname on an internal
network, so a guard that blocks private addresses would be a guard nobody could
ship.

    ./.venv/bin/python tests/test_urlguard.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("urlguard-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import urlguard                                       # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def blocked(url: str) -> bool:
    try:
        urlguard.check(url)
        return False
    except urlguard.BlockedURL:
        return True


def main() -> int:
    print("schemes that are not http")
    # the one that was actually exploitable
    check("file:// is refused", blocked("file:///etc/passwd"))
    check("and with a host on it", blocked("file://localhost/etc/passwd"))
    for scheme in ("ftp://x/y", "gopher://127.0.0.1:11211/_stats",
                   "data:text/plain,hello", "jar:file:///x!/y", "ldap://x/y"):
        check(f"{scheme.split(':')[0]} is refused", blocked(scheme))
    check("a scheme-less string is refused", blocked("/etc/passwd"))
    check("empty is refused", blocked(""))

    print("the address that hands out cloud credentials")
    check("the IPv4 metadata address", blocked("http://169.254.169.254/latest/"))
    check("its IPv6 form", blocked("http://[fd00:ec2::254]/latest/"))
    check("and the name Google uses",
          blocked("http://metadata.google.internal/computeMetadata/v1/"))
    check("link-local generally", blocked("http://169.254.1.1/"))

    print("what the portal is for must still work")
    # An Argo CD on a private address is the normal case, not an attack. A
    # guard that blocked RFC1918 would be one nobody could turn on.
    for url in ("https://sonar.example.com/api/x",
                "http://10.0.0.5:8080/api",
                "http://192.168.1.10:9090/-/healthy",
                "http://argocd.svc.cluster.local/api/v1",
                "https://127.0.0.1:8473/healthz",
                "http://[::1]:8080/x"):
        check(f"allowed: {url}", not blocked(url))
    check("and the URL comes back unchanged",
          urlguard.check("https://x.example/y?z=1") == "https://x.example/y?z=1")

    print("no fetch anywhere bypasses it")
    # The guard is only worth having if every call site uses it. Checked by
    # reading the source rather than by trusting that they all were updated:
    # one forgotten Request() is the whole hole again.
    offenders = []
    for path in sorted((ROOT / "app").glob("*.py")):
        if path.name == "urlguard.py":
            continue
        src = path.read_text()
        for m in re.finditer(r"urllib\.request\.Request\(\s*(\S)", src):
            after = src[m.start():m.start() + 120]
            if "urlguard.check" not in after:
                line = src[:m.start()].count("\n") + 1
                offenders.append(f"{path.name}:{line}")
        # urlopen given a bare string rather than a guarded Request
        for m in re.finditer(r"urlopen\(\s*(?!req|signed|urlguard)", src):
            line = src[:m.start()].count("\n") + 1
            offenders.append(f"{path.name}:{line} (urlopen with a raw url)")
    check(f"every Request goes through the guard, offenders: {offenders}",
          not offenders)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
