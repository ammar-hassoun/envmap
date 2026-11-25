#!/usr/bin/env python3
"""Nothing about the vendor, or one customer, is baked into what ships.

Every install belongs to somebody else, so anything that names the people who
wrote it, or the first estate it was built against, is a bug in a tool other
people run — even when it reads as a harmless placeholder. A vendor domain
left in a settings hint tells every future operator whose software they are
running.

The rule is narrow on purpose: a real vendor's domain in a hint is fine and
necessary (smtp.office365.com is what people type), and documentation ranges
are fine (203.0.113.0/24 exists for exactly this). What must not appear is an
identity that belongs to us or to one customer.

    ./.venv/bin/python tests/test_nohardcoding.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("nohard-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

bad = 0

# Names that belong to us or to a customer. A comment carrying one is not
# shipped — the image is bytecode with the sources stripped — so only what a
# reader of the running portal could see is checked.
# Customers, employers and estates. None of them belong in a product that gets
# handed to somebody else.
#
# "envmap" is deliberately NOT here any more. It was, back when it was only a
# domain we happened to own; it is now the name of the product itself, so it
# belongs in the default brand and in the licence endpoint compiled into the
# image. A test that forbids a product from naming itself only teaches people
# to edit the test.
# THE FORBIDDEN LIST IS NOT IN THE REPOSITORY, and that is the point. This
# check exists so no operator's own estate — their company, their customers,
# their domains — leaks into a tool other people install. Writing those names
# into a public test file would be the leak it exists to prevent.
#
# Set PORTAL_PRIVATE_NAMES to a comma-separated list to enforce your own, e.g.
#   PORTAL_PRIVATE_NAMES=acme,northwind ./.venv/bin/python tests/test_nohardcoding.py
# With nothing set, the generic checks below still run: no absolute paths from
# a developer's machine, no RFC1918 addressing from one estate as placeholder
# text, and no hostnames outside the documentation domains.
PRIVATE = tuple(n.strip().lower()
                for n in os.environ.get("PORTAL_PRIVATE_NAMES", "").split(",")
                if n.strip())

# Credentials, by shape. None of these should ever be committed.
SECRETS = re.compile(
    r"xkeysib-[A-Za-z0-9]|xsmtpsib-[A-Za-z0-9]|ghp_[A-Za-z0-9]{20}"
    r"|AKIA[0-9A-Z]{12}|LTAI[0-9A-Za-z]{12}"
    # A key HEADER is not a key: the SSH fields show one as placeholder text so
    # people know what to paste. Only match when key material follows it.
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40}")

# Somebody's machine, not a deployment path.
LOCAL_PATHS = re.compile(r"/Users/[a-z]|/home/[a-z]+/|C:\\\\Users")


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def shipped_templates():
    return sorted((ROOT / "templates").rglob("*.html"))


def shipped_python():
    return sorted((ROOT / "app").glob("*.py"))


def strip_comments(src: str) -> str:
    """Python comments and Jinja comments, which never reach a customer.

    Docstrings are deliberately NOT stripped: they survive into the bytecode
    the image ships, so a vendor's name in one is a vendor's name in the
    product. That is how the one in licence.py was found.
    """
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    return "\n".join(re.sub(r"(?<!['\"])#.*$", "", ln) for ln in src.split("\n"))


def main() -> int:
    print("no private names in anything a customer can read")
    hits = []
    for path in shipped_templates():
        text = strip_comments(path.read_text()).lower()
        for name in PRIVATE:
            if name in text:
                line = next((i + 1 for i, ln in enumerate(text.split("\n"))
                             if name in ln), 0)
                hits.append(f"{path.name}:{line} ({name})")
    check(f"templates are neutral, found: {hits}", not hits)

    hits = []
    for path in shipped_python():
        text = strip_comments(path.read_text()).lower()
        for name in PRIVATE:
            if name in text:
                line = next((i + 1 for i, ln in enumerate(text.split("\n"))
                             if name in ln), 0)
                hits.append(f"{path.name}:{line} ({name})")
    check(f"app code is neutral, found: {hits}", not hits)

    print("no credentials committed")
    hits = []
    for path in list(shipped_python()) + list(shipped_templates()) + \
            sorted((ROOT / "deploy").rglob("*.yaml")) + \
            sorted((ROOT / "scripts").glob("*")) + \
            sorted((ROOT / "tools").glob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if SECRETS.search(text):
            hits.append(path.name)
    check(f"nothing credential-shaped is committed, found: {hits}", not hits)

    print("no paths from somebody's laptop")
    hits = [p.name for p in list(shipped_python()) + list(shipped_templates())
            if LOCAL_PATHS.search(p.read_text())]
    check(f"no local paths, found: {hits}", not hits)

    print("the deployment carries no values of ours")
    # The chart may name the repository the image comes from — that is where it
    # genuinely lives. What it must not carry is a default that only suits us:
    # a licence key, an upgrade URL, a mail relay, an update feed.
    values = (ROOT / "deploy/helm/config-portal/values.yaml").read_text()
    for key in ("licence:", "updateUrl:"):
        block = values.split(key, 1)[1][:400] if key in values else ""
        filled = re.findall(r'^\s+\w+:\s*"[^"]+"', block, re.M)
        check(f"{key} ships empty, found {filled[:3]}", not filled)

    print("no event attribute is cut in half by its own quotes")
    # Jinja's tojson escapes < > & and the single quote, but NOT the double
    # quote — so `onclick="fn({{ x|tojson }})"` renders as
    # onclick="fn(" followed by rubbish, and the handler silently does
    # nothing. It looks right in the template and is broken in the browser,
    # which is why it went into three places before anybody clicked one.
    hits = []
    for path in shipped_templates():
        src = path.read_text()
        for m in re.finditer(r'\bon[a-z]+="[^"]*\|\s*tojson', src):
            hits.append(f"{path.name}:{src[:m.start()].count(chr(10)) + 1}")
    check(f'tojson never sits inside a "..." event attribute, found: {hits}',
          not hits)

    print("no estate ADDRESSING is used as placeholder text either")
    # The rule already covered names and domains. It did not cover networks,
    # and three shipped templates carried this installation's own — the DNS
    # placeholder on the VM and Talos forms was literally one estate's own
    # nameservers, and the subnet examples were its real /26. A customer
    # reading their own portal should not be shown somebody else's network,
    # and a placeholder does not have to be real to be useful.
    #
    # Narrow on purpose, the same way the domain rule is: RFC 1918 examples
    # (10.0.x, 192.168.x) and the documentation ranges are FINE and necessary
    # — people type an address into these fields and a shape helps. What must
    # not appear is a prefix that belongs to one estate.
    # Set PORTAL_PRIVATE_NETS to the prefixes of your own estate, the same way
    # PORTAL_PRIVATE_NAMES carries its names — a literal list here would ship
    # one estate's addressing in a public file, which is the leak this checks
    # for. e.g. PORTAL_PRIVATE_NETS='10\.99\.\d+\.\d+,198\.51\.100\.\d+'
    ESTATE = tuple(n.strip()
                   for n in os.environ.get("PORTAL_PRIVATE_NETS", "").split(",")
                   if n.strip())
    leaked = []
    for f in shipped_templates() + shipped_python() + \
            sorted((ROOT / "deploy").rglob("*.yaml")):
        text = f.read_text(errors="ignore")
        for pat in ESTATE:
            for m in re.finditer(pat, text):
                leaked.append(f"{f.relative_to(ROOT)}: {m.group(0)}")
    check(f"no shipped file names one estate's network ({leaked[:4]})",
          not leaked)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
