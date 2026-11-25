#!/usr/bin/env python3
"""Pasted SSH keys.

A key pasted through a browser textarea arrives with CRLF line endings, and
OpenSSH refuses such a file with "invalid format". Git then reports "Permission
denied (publickey)" against the remote, which sends you to check the deploy key
on the server — the one place the problem is not. Every case here is a paste that
should either be repaired silently or refused with a sentence naming the cause.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("keys-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import store                                           # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def real_key(passphrase: str = "") -> str:
    d = tempfile.mkdtemp()
    f = os.path.join(d, "id")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase,
                    "-C", "test", "-f", f], check=True)
    with open(f, encoding="utf-8") as fh:
        return fh.read()


def main() -> int:
    key = real_key()

    # ── the paste that actually broke ──────────────────────────────────────
    crlf = key.replace("\n", "\r\n")
    fixed = store.normalise_ssh_key(crlf)
    check("CRLF must be stripped", "\r" not in fixed)
    check("the repaired key must equal the original", fixed == key)
    check("a CRLF paste must be accepted", store.ssh_key_problem(crlf) == "")

    # trailing spaces, and a missing final newline
    padded = "\n".join(ln + "  " for ln in key.strip().split("\n"))
    check("trailing spaces must be tolerated", store.ssh_key_problem(padded) == "")
    check("a final newline is added",
          store.normalise_ssh_key(key.strip()).endswith("PRIVATE KEY-----\n"))

    # ── pastes that must be refused, each for its own stated reason ───────
    pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample test@host\n"
    check("the public key must be refused",
          "private" in store.ssh_key_problem(pub).lower())
    check("an empty paste must be refused", store.ssh_key_problem("  ") != "")
    truncated = "\n".join(key.split("\n")[:3])
    check("a truncated key must be refused",
          store.ssh_key_problem(truncated) != "")
    check("nonsense must be refused",
          store.ssh_key_problem("this is not a key at all") != "")

    # a passphrase cannot be unlocked by a portal running git without a terminal
    problem = store.ssh_key_problem(real_key("hunter2hunter2"))
    check("a passphrase-protected key must be refused with the reason",
          "passphrase" in problem.lower())

    # ── what is written to disk must be what ssh accepts ─────────────────
    path = store.write_ssh_key("p-test", "rg-test", crlf)
    r = subprocess.run(["ssh-keygen", "-y", "-f", path],
                       capture_output=True, text=True)
    check("ssh-keygen must read the stored key", r.returncode == 0)
    check("the stored key must be private to the portal",
          oct(os.stat(path).st_mode)[-3:] == "600")

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
