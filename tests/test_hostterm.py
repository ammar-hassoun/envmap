#!/usr/bin/env python3
"""A terminal on an inventory host: the gates, and the injection it must refuse.

WHY THIS EXISTS
    This opens an interactive ssh session on a VM using the group's stored key
    — the same door the pod terminal is, onto a host instead of a container.
    Two things carry the whole risk and neither shows by looking:

      1. **The host and user come from the inventory, but a shell is the one
         place a smuggled `-o ProxyCommand=…` in an address is a remote command
         execution, not a broken connection.** So the argv is built as a list
         and every value is shape-checked.
      2. **It is gated exactly like a run.** No permission, no key, a production
         group without its name typed, a host not in the group — each refuses
         on its own, and the socket refuses again server-side so the page's
         checks are never the only ones.

    ./.venv/bin/python tests/test_hostterm.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("hostterm-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ansible                                       # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def refused(what: str, fn, want: str = "") -> None:
    try:
        fn()
    except ansible.Refused as e:
        if want and want not in str(e):
            check(f"{what} — reason names {want!r}, got {str(e)[:60]!r}", False)
        return
    check(f"{what} — it was ALLOWED", False)


def main() -> int:
    print("the argv is a safe list, not a string")
    priv, _pub = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "boxes", "ssh_user": "root",
                                  "key": priv}, "t")
    ansible.add_host(gid, "web-1", "10.20.0.5", "t", ssh_port=2222)
    g = ansible.group(gid)
    argv = ansible.host_shell_argv(g, "web-1", "/tmp/k", "/tmp/kh")
    check("it is the ssh binary", argv[0].endswith("ssh"))
    check("with the group's key and the host's port and user",
          "/tmp/k" in argv and "2222" in argv and "root@10.20.0.5" in argv)
    check("and it never falls back to a password",
          "BatchMode=yes" in argv
          and "PreferredAuthentications=publickey" in argv)
    check("the key file is identity-only, so an agent cannot substitute one",
          "IdentitiesOnly=yes" in argv)

    print("a smuggled address is refused, not connected to")
    for evil in ("-oProxyCommand=touch /tmp/pwned", "10.0.0.1 -oFoo",
                 "$(reboot)", "a;b", "../x"):
        ansible.add_host(gid, f"h-{abs(hash(evil)) % 9999}", evil, "t")
        g = ansible.group(gid)
        host = next(h["name"] for h in g["hosts"] if h["address"] == evil)
        refused(f"the address {evil!r}",
                lambda g=g, host=host: ansible.host_shell_argv(
                    g, host, "/k", "/kh"),
                "ssh will take safely")

    print("a group with no key cannot open a terminal")
    nk = ansible.save_group("", {"name": "nokey"}, "t")
    ansible.add_host(nk, "h1", "10.0.0.9", "t")
    refused("a keyless group", lambda: ansible.host_shell(ansible.group(nk), "h1"),
            "no key")

    print("a host that is not in the group is refused")
    refused("a stray host",
            lambda: ansible.host_shell(ansible.group(gid), "not-a-host"),
            "not a host in")

    print("through the route, gated like a run")
    from fastapi.testclient import TestClient

    from app import auth, db, main

    # a reader who may NOT run playbooks
    email, pw = "reader@test.local", "Read-But-Not-Run-42"
    ruid = auth.create_user(email, "R", pw, role="viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", ruid))
    # …and an admin who may
    aemail, apw = "admin@test.local", "May-Run-Everything-42"
    auid = auth.create_user(aemail, "A", apw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", auid))

    def login(c, e, p):
        c.post("/login", data={"email": e, "password": p},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)

    boss = TestClient(main.app)
    boss.__enter__()
    login(boss, aemail, apw)
    r = boss.get(f"/ansible/groups/{gid}/terminal?host=web-1",
                 follow_redirects=False)
    check(f"an admin reaches the terminal page ({r.status_code})",
          r.status_code == 200 and "Terminal</h1>" in r.text)
    r = boss.get(f"/ansible/groups/{gid}/terminal?host=not-a-host",
                 follow_redirects=False)
    check("a host not in the group bounces back to the group",
          r.status_code == 303 and gid in r.headers.get("location", ""))

    # a production group asks for its name first
    pg = ansible.save_group("", {"name": "prodboxes", "is_prod": "1",
                                 "key": priv, "ssh_user": "root"}, "t")
    ansible.add_host(pg, "p-1", "10.30.0.1", "t")
    r = boss.get(f"/ansible/groups/{pg}/terminal?host=p-1")
    check("a production group shows the confirm gate, not the terminal",
          "Terminal</h1>" not in r.text and "type" in r.text.lower()
          and "prodboxes" in r.text)
    r = boss.get(f"/ansible/groups/{pg}/terminal?host=p-1&confirm=prodboxes")
    check("and opens once its name is typed",
          "Terminal</h1>" in r.text)

    reader = TestClient(main.app)
    reader.__enter__()
    login(reader, email, pw)
    r = reader.get(f"/ansible/groups/{gid}/terminal?host=web-1",
                   follow_redirects=False)
    # refused is refused, whether the area middleware blocks the whole /ansible
    # prefix (403) or the route's own _may_run bounces it (303) — what must
    # never happen is the terminal page rendering for someone who cannot run
    check(f"a reader who may not run never reaches the terminal ({r.status_code})",
          r.status_code in (303, 403)
          and "Terminal</h1>" not in r.text)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
