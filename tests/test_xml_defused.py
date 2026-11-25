#!/usr/bin/env python3
"""Cloud and VPN XML is parsed with defusedxml, so a hostile or compromised
endpoint cannot expand entities (billion laughs / quadratic blowup) against
the pod.

cloud.py (AWS, Alibaba OSS) and vpn.py (OpenVPN Access Server) parse XML that
comes straight from an external, operator-configured endpoint. stdlib
xml.etree expands internal entities; defusedxml forbids DTDs and entities and
is a drop-in for the ElementTree API these modules use.

    ./.venv/bin/python tests/test_xml_defused.py
"""
from __future__ import annotations

import os
import pathlib
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("xml-defused-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cloud                                          # noqa: E402

bad = 0
BOMB = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "AAAAAAAAAA">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
        '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
        '<Result><X>&c;</X></Result>')


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main_test() -> int:
    print("the cloud and VPN parsers use defusedxml, not stdlib xml.etree")
    for mod in ("app/cloud.py", "app/vpn.py"):
        src = pathlib.Path(mod).read_text()
        check(f"{mod} imports defusedxml.ElementTree",
              "import defusedxml.ElementTree" in src)
        check(f"{mod} no longer imports stdlib xml.etree",
              "import xml.etree" not in src)

    print("a billion-laughs entity bomb is not expanded")
    expanded = False
    try:
        tree = cloud._aws_tree(BOMB)
        if tree is not None:
            expanded = "AAAA" in "".join(e.text or "" for e in tree.iter())
    except Exception:
        expanded = False            # blocked by defusedxml -> never expanded
    check("the AWS XML parser does not expand an entity bomb", not expanded)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
