#!/usr/bin/env python3
"""The Ansible runner, driven for real, plus every gate that stands in front of it.

WHY THIS EXISTS
    This is the second thing in the product that can change a machine, and unlike
    the first it is not limited to a fixed set of verbs — a playbook is arbitrary
    code on every host in a group. So the checks that matter are not "does the
    page render":

      1. **`--check` has to really be a dry run.** If the flag were ever dropped
         from the argv, the button marked "Check (dry run)" would apply. Nothing
         about the page would look different and the output would read the same.
         So this test runs a playbook that creates a file, in check mode, against
         the machine the test is on, and asserts the file is not there.

      2. **Nothing typed becomes an argument or a shell.** A limit of
         `--extra-vars=x` would be read by ansible as a flag; a host name with a
         semicolon in it would be a host name until somebody built a command out
         of it. Both are refused before they reach argv, and the argv is built as
         a list.

      3. **The gates.** Real runs off for the installation, the `ansible_run`
         area, and a group marked production needing its name typed. Each is a
         separate answer and each has to refuse on its own.

      4. **The key is not in the database in the clear.** A group's private key is
         the most sensitive thing on these pages. The file itself is grepped,
         because "we call seal() before the insert" is what you believe right up
         until a code path skips it.

    ./.venv/bin/python tests/test_ansible.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# The ticker stays off in the sandbox: a background thread firing a planted
# schedule between two asserts is a flake nobody can reproduce.
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
DATA = _sandbox.data_dir("ansible-test-")
os.environ["PORTAL_DATA_DIR"] = DATA
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ansible, db, secretbox                         # noqa: E402

bad = 0
# A real key, generated here: a group's key is parsed on the way in now — by
# cryptography AND by ssh-keygen — so a fixture with markers around nonsense is
# refused, which is the whole point of that change. Generated rather than pasted
# in as a constant so its body is unique to this run, which is what makes the
# "not in the database in the clear" grep below mean something.
KEY, KEY_PUB = ansible.new_keypair()
KEY_BODY = [ln for ln in KEY.splitlines() if "-----" not in ln][1].encode()

# A playbook that proves the difference between a check and a run: it creates a
# file. In check mode ansible reports the change and the file must not appear.
MARKER = os.path.join(DATA, "run-happened")
TOUCHER = f"""---
- name: create a file, so a dry run can be told from a real one
  hosts: all
  gather_facts: false
  tasks:
    - name: touch the marker
      ansible.builtin.file:
        path: {MARKER}
        state: touch
        mode: "0600"
"""


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def wait(run_id: str, secs: float = 90.0) -> dict:
    """Block until a run finishes, and say what it finished as."""
    until = time.time() + secs
    while time.time() < until:
        got = ansible.run(run_id)
        if got and got["done"]:
            return got
        time.sleep(0.3)
    return ansible.run(run_id) or {}


def local_group(name: str = "local", **over) -> str:
    """A group holding the machine the test is running on, over `local`."""
    gid = ansible.save_group("", {"name": name, **over}, "tester")
    ansible.add_host(gid, "here", "127.0.0.1", "tester",
                     host_vars="ansible_connection: local")
    return gid


def main() -> int:
    have_ansible = ansible.tool()["found"]
    if not have_ansible:
        print("  note: ansible-playbook is not installed — the parts that run a "
              "playbook are skipped, the rest still runs")

    print("an inventory is a file, and the page shows the same file ansible gets")
    gid = ansible.save_group("", {
        "name": "web", "ssh_user": "ubuntu", "ssh_port": 2222,
        "become_root": "1", "group_vars": "ansible_python_interpreter: /usr/bin/python3\n"
                                          "# a comment, which must not be indented in"},
        "tester")
    ansible.add_host(gid, "web-1", "10.0.0.9", "tester")
    ansible.add_host(gid, "web-2", "", "tester", ssh_user="root", ssh_port=22,
                     host_vars="http_port: 8080")
    text = ansible.inventory_text(ansible.group(gid))
    for want in ("    web:", "        web-1:", "          ansible_host: 10.0.0.9",
                 "          ansible_user: root", "        ansible_user: ubuntu",
                 "        ansible_port: 2222", "        ansible_become: true",
                 "          http_port: 8080",
                 "        ansible_python_interpreter: /usr/bin/python3"):
        check(f"the inventory carries {want.strip()!r}", want in text)
    check("a host with no address is left to be resolved by name",
          "web-2:\n" in text and "ansible_host: web-2" not in text)
    # A comment at the wrong indentation is harmless; a BLANK line inside a
    # mapping ends the mapping, and that is how a hand-typed vars block becomes
    # two documents.
    check("comments and blank lines do not break the mapping",
          "# a comment" not in text and "\n\n" not in text)
    if have_ansible:
        # ansible's own parser is the judge of whether that file is an inventory
        got = subprocess.run([ansible.tool()["path"], "-i", "/dev/stdin",
                              "--syntax-check", "/dev/null"],
                             input=text, capture_output=True, text=True,
                             timeout=60)
        check("and ansible does not reject the inventory itself "
              f"({(got.stderr or '').strip()[:60]})",
              "inventory" not in (got.stderr or "").lower()
              or "Unable to parse" not in (got.stderr or ""))

    print("a host taken from the server inventory follows it afterwards")
    from app import assets
    aid = assets.create({"hostname": "db-1", "ip": "10.0.0.20"}, "tester")
    ginv = ansible.save_group("", {"name": "dbs"}, "tester")
    added, skipped = ansible.from_inventory(ginv, [aid], "tester")
    check(f"the host came across ({added} added, {skipped})",
          added == 1 and not skipped)
    check("with the inventory's address",
          "ansible_host: 10.0.0.20" in ansible.inventory_text(ansible.group(ginv)))
    assets.update(aid, {"hostname": "db-1", "ip": "10.0.0.99"}, "tester")
    # The point of keeping the asset id rather than copying the address: a
    # re-addressed machine must not leave a playbook pointed at whatever answers
    # on the old one.
    check("and the address follows a re-addressing rather than going stale",
          "ansible_host: 10.0.0.99"
          in ansible.inventory_text(ansible.group(ginv)))

    print("the command is a list, and --check is in it")
    pb = ansible.save_playbook("", "toucher", TOUCHER, "", "tester")
    g = ansible.group(gid)
    paths = {"inventory": "/tmp/inv.yml", "playbook": "/tmp/pb.yml",
             "key": "/tmp/k", "vars": "/tmp/v.json"}
    dry = ansible.argv_for(ansible.playbook(pb), g, paths, True, "web-1", "deploy")
    wet = ansible.argv_for(ansible.playbook(pb), g, paths, False, "", "")
    check("check mode passes --check", "--check" in dry)
    check("and a real run does not", "--check" not in wet)
    check("become is passed because the group asks for it", "--become" in wet)
    check("the key is passed as a file",
          dry[dry.index("--private-key") + 1] == "/tmp/k")
    check("the limit and tags are their own arguments",
          dry[dry.index("--limit") + 1] == "web-1"
          and dry[dry.index("--tags") + 1] == "deploy")
    check("extra variables are a file, not a command line",
          dry[dry.index("--extra-vars") + 1] == "@/tmp/v.json")
    check("and a group that does not ask for become does not get it",
          "--become" not in ansible.argv_for(
              ansible.playbook(pb), ansible.group(ginv), paths, True, "", ""))

    print("an ad-hoc run targets a raw host with a supplied key, no saved group")
    ag = ansible._adhoc_group("prov vm", [{"name": "web1", "address": "10.9.9.9",
                                           "ssh_user": "ammar"}], "PRIVATE-KEY", True, "ammar")
    inv = ansible.inventory_text(ag)
    check("the ad-hoc inventory carries the host, ip and user",
          "web1:" in inv and "ansible_host: 10.9.9.9" in inv and "ansible_user: ammar" in inv)
    check("become is set at group level for the ad-hoc run", "ansible_become: true" in inv)
    check("the supplied private key is sealed at rest, never plaintext",
          secretbox.sealed(ag["key_sealed"]) and "PRIVATE-KEY" not in ag["key_sealed"])
    check("the ad-hoc name is sanitised to a safe token", ag["name"] == "prov_vm")
    aargv = ansible.argv_for(ansible.playbook(pb), ag,
                             {"inventory": "/i", "playbook": "/p", "key": "/k"}, False, "", "")
    check("the ad-hoc run is real (no --check) with become and a key",
          "--check" not in aargv and "--become" in aargv and "--private-key" in aargv)

    print("the ssh control socket fits in a unix socket path")
    # Reported from a real run and reproduced exactly: ansible keeps its ssh
    # multiplexing socket under HOME, the runner sets HOME to the run directory,
    # and a run directory inside a data directory with a real name went past the
    # 104-byte limit. ssh refuses before it dials, so every host in the group came
    # back UNREACHABLE — indistinguishable from the hosts being down.
    #
    #   ControlPath too long ('/Users/…/config-portal/data/ansible-run-w6k6ms7y/
    #   .ansible/cp/dd896fe634' >= 104 bytes)
    deep = os.path.join(ansible.DATA, "a" * 90, "ansible-run-abcdefgh")
    cpdir = ansible.control_path_dir(deep)
    longest = len(cpdir) + 1 + 64          # %C is 64 hex characters, always
    check(f"the socket path fits whatever the data directory is called "
          f"({longest} bytes, limit {ansible.SOCK_MAX})",
          longest <= ansible.SOCK_MAX)
    check(f"and it is not inside the run directory ({cpdir})",
          not cpdir.startswith(deep))
    genv = ansible.env_for(ansible.group(gid), tempfile.mkdtemp())
    check("the run is told where to put it",
          genv.get("ANSIBLE_SSH_CONTROL_PATH_DIR", "") != "")
    # %C rather than the default name, which carries the host: one long FQDN in
    # the inventory would otherwise be enough on its own.
    check("with a fixed-length name rather than the hostname",
          genv.get("ANSIBLE_SSH_CONTROL_PATH", "").endswith("%%C"))
    check("multiplexing is still on — it is most of a playbook's speed",
          "ANSIBLE_SSH_ARGS" not in genv)
    for stale in (cpdir, genv["ANSIBLE_SSH_CONTROL_PATH_DIR"]):
        shutil.rmtree(stale, ignore_errors=True)

    print("nothing typed can become another flag")
    for nasty in ("--extra-vars=x", "-e /etc/passwd", "web; rm -rf /",
                  "$(id)", "`id`", "a" * 300):
        try:
            ansible.start(pb, gid, "tester", check=True, limit_to=nasty)
            check(f"a limit of {nasty!r} is refused", False)
        except ansible.Refused:
            pass
    for nasty in ("host name", "web;rm", "../../etc/passwd", "-flag", ""):
        try:
            ansible.add_host(gid, nasty, "", "tester")
            check(f"a host named {nasty!r} is refused", False)
        except ansible.Refused:
            pass
    for nasty in ("has space", "a/b", "-lead"):
        try:
            ansible.save_group("", {"name": nasty}, "tester")
            check(f"a group named {nasty!r} is refused", False)
        except ansible.Refused:
            pass
    try:
        ansible.start(pb, gid, "tester", check=True, extra_vars="not json")
        check("extra variables that are not JSON are refused", False)
    except ansible.Refused:
        pass
    try:
        ansible.start(pb, gid, "tester", check=True, extra_vars='["a"]')
        check("extra variables that are not an object are refused", False)
    except ansible.Refused:
        pass

    print("a group's private key is not in the database in the clear")
    keyed = ansible.save_group("", {"name": "keyed", "key": KEY}, "tester")
    row = ansible.group(keyed)
    check("it is stored sealed", row["key_sealed"].startswith("enc.v1."))
    check("and comes back out intact",
          secretbox.unseal(row["key_sealed"]).strip() == KEY.strip())
    # The file, not the API: a code path that skipped seal() would still pass
    # every check above.
    #
    # The checkpoint is not optional, and this check passed for the wrong reason
    # without it. The database runs in WAL mode, so a row written a moment ago is
    # in portal.db-wal and not yet in portal.db — grepping only the main file
    # finds nothing whether or not the key was sealed. Measured: with sealing
    # deliberately removed, the check still passed until the WAL was folded in.
    db.connect().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blob = b""
    for suffix in ("", "-wal"):
        f = pathlib.Path(DATA, "portal.db" + suffix)
        if f.exists():
            blob += f.read_bytes()
    check(f"the database file does not contain the key ({len(blob)}B read)",
          KEY_BODY not in blob)
    # Editing anything else must not throw the key away: the form cannot show it,
    # so an empty field means "unchanged" and not "remove".
    ansible.save_group(keyed, {"name": "keyed", "ssh_user": "deploy"}, "tester")
    check("editing the group keeps the stored key",
          (ansible.group(keyed)["key_sealed"] or "").startswith("enc.v1."))
    check("and the edit landed", ansible.group(keyed)["ssh_user"] == "deploy")
    ansible.save_group(keyed, {"name": "keyed", "drop_key": "1"}, "tester")
    check("and it can be dropped deliberately",
          not ansible.group(keyed)["key_sealed"])
    try:
        ansible.save_group("", {"name": "bad-key", "key": "hunter2"}, "tester")
        check("a key that is not a key is refused", False)
    except ansible.Refused:
        pass

    print("a key is checked by the parser that will actually read it")
    # Reported from a real run, and the reason this check exists: the old test was
    # `-----BEGIN` in text and `-----END` in text, which every mangled key passes.
    # The group looked configured and the RUN failed on every host at once with
    #   Load key "…/id_key": invalid format
    # naming a temporary file that no longer existed.
    good = ansible.read_key(KEY)
    check(f"a real key parses ({good['kind']})", good["ok"])
    check("and its public half comes back", good["public"].startswith("ssh-"))
    # cryptography accepts a key whose newlines were lost and ssh REFUSES it —
    # measured both ways, which is why ssh gets the last word.
    flat = ansible.read_key(KEY.replace("\n", ""))
    check(f"a key that lost its line breaks is refused ({flat['why'][:60]})",
          not flat["ok"])
    check("and the reason says what to do about it",
          "line break" in flat["why"] or "one long line" in flat["why"])
    pub = ansible.read_key(KEY_PUB)
    check("a public key pasted by mistake is named as one",
          not pub["ok"] and "PUBLIC" in pub["why"])
    for junk, label in (("", "nothing"), ("hunter2", "a password"),
                        ("apiVersion: v1\nkind: Config\n", "a kubeconfig"),
                        ("-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n"
                         "-----END OPENSSH PRIVATE KEY-----", "markers only")):
        got = ansible.read_key(junk)
        check(f"{label} is refused, with a reason ({got['why'][:44]})",
              not got["ok"] and bool(got["why"]))
    # ssh-keygen is the authority, and it is asked: the same key it accepts is the
    # one a run will load.
    sok, _why, spub = ansible._ssh_can_load(KEY)
    check("ssh itself loads the key the portal stored", sok)
    check("and agrees about its public half", spub.split()[1] in good["public"])

    print("a stored key that cannot be read is reported on the group's page")
    # The state the reporter was actually in: a bad key already saved, from before
    # the save was checked. It has to be diagnosable without a run.
    broke = ansible.save_group("", {"name": "brokenkey", "key": KEY}, "tester")
    db.run("UPDATE ansible_groups SET key_sealed = ? WHERE id = ?",
           (secretbox.seal(KEY.replace("\n", "")), broke))
    health = ansible.key_health(ansible.group(broke))
    check(f"the page can say it is broken ({health['state']})",
          health["state"] == "broken")
    check("and why", bool(health["why"]))
    fine = ansible.key_health(ansible.group(keyed_ok := ansible.save_group(
        "", {"name": "goodkey", "key": KEY}, "tester")))
    check("a good one reads as ready", fine["state"] == "ok" and fine["public"])
    check("no key at all is not an error", ansible.key_health(
        ansible.group(pasted_none := ansible.save_group(
            "", {"name": "nokey"}, "tester")))["state"] == "none")
    del keyed_ok, pasted_none

    print("installing a key with a password: the refusals, and the leak")
    kg = ansible.save_group("", {"name": "keyinstall", "ssh_user": "root",
                                 "ssh_port": 1}, "tester")
    for args, label in (
            (("root", ""), "no password"),
            (("", "pw"), "no user and no group user to fall back on")):
        try:
            ansible.install_key(kg, *args)
            check(f"{label} is refused", False)
        except ansible.Refused:
            pass
    try:
        ansible.install_key(kg, "root", "pw")
        check("a group with no hosts is refused", False)
    except ansible.Refused:
        pass
    ansible.add_host(kg, "dead", "127.0.0.1", "tester")   # port 1, nothing there
    prodkg = ansible.save_group("", {"name": "prodkeys", "ssh_user": "root",
                                     "ssh_port": 1, "is_prod": "1"}, "tester")
    ansible.add_host(prodkg, "dead", "127.0.0.1", "tester")
    try:
        ansible.install_key(prodkg, "root", "pw")
        check("a production group needs its name typed", False)
    except ansible.Refused as e:
        check("and says so", "production" in str(e))

    # The password is the thing that must not survive this. Run it for real
    # against a port nothing listens on — every host fails, which is fine; what
    # is checked is what the failure left behind.
    SECRET = "Unique-Password-For-This-Check-70714"
    out = ansible.install_key(kg, "root", SECRET, who="tester")
    check(f"it reports per host rather than one verdict ({out['total']})",
          len(out["rows"]) == 1 and out["ok"] == 0)
    check("a key was generated on the way, so the group has one now",
          out["generated"] and ansible.key_health(ansible.group(kg))["state"] == "ok")
    check("the failure names the host and what happened",
          out["rows"][0]["name"] == "dead" and bool(out["rows"][0]["note"]))
    check("the password is not in what the page is shown",
          SECRET not in json.dumps(out))

    # The plumbing itself, without an sshd: a stand-in for ssh that obtains the
    # password the way ssh does — by running $SSH_ASKPASS — and then prints it.
    # That proves two things a dead port cannot: the askpass program really hands
    # the password over, and a transcript that ends up holding it is scrubbed.
    stand_in = pathlib.Path(DATA, "fake-ssh")
    stand_in.write_text('#!/bin/sh\n"$SSH_ASKPASS"\necho " <- what it was given"\n')
    stand_in.chmod(0o755)
    was = ansible.env.SSH
    probe = tempfile.mkdtemp(prefix="askpass-probe-", dir=str(DATA))
    try:
        ansible.env.SSH = str(stand_in)
        rc, said = ansible._ssh_password("h", 22, "root", SECRET, [],
                                         os.path.join(probe, "kh"), probe)
        check(f"the askpass program hands the password to ssh (rc {rc})",
              "what it was given" in said)
        check("and the transcript is scrubbed of it", SECRET not in said)
        check("visibly, rather than silently", "********" in said)
        # And it was never an argument: `ps` is where sshpass leaks.
        check("the password is not in the command either",
              SECRET not in " ".join([ansible.env.SSH, "-p", "22"]))
    finally:
        ansible.env.SSH = was
        shutil.rmtree(probe, ignore_errors=True)
    # Nor in the audit trail, which more people read than this page.
    from app import auth as _auth
    trail = json.dumps(_auth.read_audit(50))
    check("nor in the audit trail", SECRET not in trail)
    check("but the installation itself is audited",
          "ansible_key_installed" in trail)
    # And nowhere on disk: the askpass file and the password beside it live in a
    # 0700 directory that a finally removes.
    left = [p for p in pathlib.Path(DATA).glob("ansible-keys-*")]
    check(f"and the working directory is gone ({left})", not left)

    print("a key that installs and is still refused says which of four reasons")
    # The reported failure, and the reason this exists: "the key is in
    # authorized_keys but logging in with it still fails" is not an answer. sshd
    # knows which of these it is, the password connection still works, so the
    # portal asks. Each rule is fed the facts a real host produced.
    ed = "ssh-ed25519 AAAAC3Nza envmap"
    rsa = "ssh-rsa AAAAB3Nza envmap"
    hardened = ("## sshd\npubkeyacceptedalgorithms rsa-sha2-512,rsa-sha2-256\n"
                "authorizedkeysfile .ssh/authorized_keys\nstrictmodes yes\n")
    said = ansible._why_refused(ed, hardened)
    check(f"a FIPS-style host that leaves ed25519 out is named ({said[:52]})",
          "does not accept ssh-ed25519" in said and "RSA" in said)
    # The bug this pins: an RSA KEY is `ssh-rsa`, and a modern sshd accepts it as
    # `rsa-sha2-512`. Comparing the two directly reported "this host does not
    # accept ssh-rsa keys" about a host that accepts them perfectly well.
    check("and an RSA key on that same host is not misreported",
          "does not accept" not in ansible._why_refused(rsa, hardened))
    loose = ("## home\ndrwxrwxrwx 1 root root 4096 Aug 12 21:28 /root\n"
             "drwx------ 2 root root 4096 Aug 12 21:07 /root/.ssh\n" + hardened)
    said = ansible._why_refused(rsa, loose)
    check(f"a home directory anyone can write to is named ({said[:46]})",
          "writable" in said and "StrictModes" in said and "chmod go-w" in said)
    # Read from `ls -ld`, not from a log: sshd's reason for this one is only in
    # its log, and plenty of hosts keep none this can reach.
    check("without needing the host to keep a log", "## log" not in loose)
    other = ("## sshd\nauthorizedkeysfile /etc/ssh/keys/%u\n"
             "pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512\n")
    check("a host that reads keys from somewhere else is named",
          "/etc/ssh/keys" in ansible._why_refused(ed, other))
    cmd = ("## sshd\nauthorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\n"
           "pubkeyacceptedalgorithms ssh-ed25519\n")
    check("so is a host whose keys come from a command",
          "command" in ansible._why_refused(ed, cmd))
    off = ("## sshd\npubkeyauthentication no\n"
           "pubkeyacceptedalgorithms ssh-ed25519\n")
    check("and one with public keys switched off entirely",
          "switched off" in ansible._why_refused(ed, off))
    fine = ("## home\ndrwx------ 1 root root 4096 Aug 12 /root\n"
            "## sshd\npubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512\n"
            "authorizedkeysfile .ssh/authorized_keys\nstrictmodes yes\n")
    check("a host with nothing wrong gets no invented reason",
          ansible._why_refused(ed, fine) == "")

    print("what actually runs on the host, and what it does when refused")
    cmd = ansible.authorize_command(ed)
    check("the key is appended only when it is not already there",
          "grep -qF" in cmd and ">> ~/.ssh/authorized_keys" in cmd)
    check("so pressing it twice is the same as pressing it once",
          "ALREADY" in cmd and "ADDED" in cmd)
    check("the directory and the file are locked down",
          "chmod 700 ~/.ssh" in cmd and "chmod 600" in cmd and "umask 077" in cmd)
    # Without this, a RHEL-family host with SELinux enforcing labels a fresh .ssh
    # user_home_t, sshd cannot read it, and the login is refused with the key in
    # place and the permissions perfect.
    check("and SELinux gets the label it needs", "restorecon -R -F ~/.ssh" in cmd)
    check("the key is quoted, not interpolated into a shell",
          shlex.quote(ed) in cmd)

    # The refused path, wired end to end, without a host that refuses: the verify
    # is made to fail and the host is made to answer with a real hardened config.
    was_check, was_pw = ansible._ssh_password_free_check, ansible._ssh_password
    try:
        ansible._ssh_password_free_check = lambda *a, **k: (255, "Permission denied")
        ansible._ssh_password = lambda *a, **k: (0, hardened)
        note, facts = ansible.verify_or_explain(
            {"name": "h", "address": "h", "port": 22, "user": "root"},
            "/tmp/k", "/tmp/kh", "/tmp", "/tmp/ask", "root", "pw", ed)
        check("a refused key is explained rather than shrugged at",
              "does not accept ssh-ed25519" in note)
        check("and what the host said is kept", "pubkeyacceptedalgorithms" in facts)
        ansible._ssh_password = lambda *a, **k: (0, "## sshd\ncannot read sshd config\n")
        note2, _f = ansible.verify_or_explain(
            {"name": "h", "address": "h", "port": 22, "user": "root"},
            "/tmp/k", "/tmp/kh", "/tmp", "/tmp/ask", "root", "pw", ed)
        check("a host that says nothing useful is reported as exactly that",
              "did not say why" in note2)
        ansible._ssh_password_free_check = lambda *a, **k: (0, "")
        note3, _f = ansible.verify_or_explain(
            {"name": "h", "address": "h", "port": 22, "user": "root"},
            "/tmp/k", "/tmp/kh", "/tmp", "/tmp/ask", "root", "pw", ed)
        check("and a key that works is not explained at all", note3 == "")
    finally:
        ansible._ssh_password_free_check, ansible._ssh_password = was_check, was_pw

    print("the key type can be changed, because ed25519 is not universal")
    check("both types are offered", set(ansible.KEY_KINDS) == {"ed25519", "rsa"})
    priv_r, pub_r = ansible.new_keypair("rsa")
    check("an RSA pair is generated and parses",
          ansible.read_key(priv_r)["ok"] and pub_r.startswith("ssh-rsa "))
    check("and ssh will load it", ansible._ssh_can_load(priv_r)[0])
    kt = ansible.save_group("", {"name": "kindswap", "ssh_user": "root",
                                 "ssh_port": 1}, "tester")
    ansible.add_host(kt, "dead", "127.0.0.1", "tester")
    ansible.install_key(kt, "root", "pw")
    check("the first pass leaves an ed25519 key",
          ansible.key_health(ansible.group(kt))["kind"] == "Ed25519")
    ansible.install_key(kt, "root", "pw", key_type="rsa")
    check("asking for RSA replaces it, because the point is that the other "
          "one does not work here",
          ansible.key_health(ansible.group(kt))["kind"] == "RSA")
    same = ansible.key_health(ansible.group(kt))["public"]
    ansible.install_key(kt, "root", "pw", key_type="rsa")
    check("and asking again for the same type keeps the key it made",
          ansible.key_health(ansible.group(kt))["public"] == same)
    try:
        ansible.install_key(kt, "root", "pw", key_type="dsa")
        check("a type that is not offered is refused", False)
    except ansible.Refused:
        pass

    print("every host at once, not one after another")
    # Each host is two SSH handshakes, a password exchange and a remote shell —
    # about two seconds of waiting. A group is a fleet, so the waiting has to
    # overlap: six hosts done in sequence is a page that looks hung.
    many = ansible.save_group("", {"name": "sixhosts", "ssh_user": "root",
                                   "ssh_port": 22}, "tester")
    for n in range(6):
        ansible.add_host(many, f"m{n}", f"10.9.0.{n + 1}", "tester")
    was_pw, was_free = ansible._ssh_password, ansible._ssh_password_free_check
    try:
        def slow(*a, **k):
            time.sleep(0.5)
            return 0, "ADDED"
        ansible._ssh_password = slow
        ansible._ssh_password_free_check = lambda *a, **k: (0, "")
        t0 = time.time()
        got = ansible.install_key(many, "root", "pw", who="tester")
        took = time.time() - t0
    finally:
        ansible._ssh_password, ansible._ssh_password_free_check = was_pw, was_free
    check(f"all six were installed ({got['ok']}/{got['total']})", got["ok"] == 6)
    # Six half-second hosts: about half a second together, three seconds in a row.
    check(f"and they overlapped rather than queueing ({took:.1f}s for 6 × 0.5s)",
          took < 2.0)
    check("every host is named in the report either way",
          {r["name"] for r in got["rows"]} == {f"m{n}" for n in range(6)})

    print("several hosts can be pasted into a group that already exists")
    # The row under the table takes one host with its own user and port. This
    # takes the list of twenty addresses somebody already has — which only the
    # create form used to accept, so adding a fleet meant twenty visits to a
    # one-line form.
    into = ansible.save_group("", {"name": "pasteinto"}, "tester")
    added, skipped = ansible.add_hosts_text(
        into, "10.0.9.1\n10.0.9.2\nweb-9 10.0.9.3\nnot a valid name!\n", "tester")
    check(f"the good ones land ({added})", added == 3)
    check("and the bad one is reported rather than dropped", len(skipped) == 1)

    print("hosts can be pasted in, which is where anybody starts")
    # The form that creates a group had nowhere to put an address, so the first
    # question after making one was "where do the IPs go" — the answer being a
    # second form on a card that did not exist yet.
    pasted = ansible.save_group("", {"name": "pasted"}, "tester")
    added, skipped = ansible.add_hosts_text(pasted, """
# the front end
web-1 10.20.0.11
web-2,10.20.0.12
db-1.internal
10.20.0.20
web-1 10.20.0.99
one two three
not a valid name!
""", "tester")
    check(f"the good lines land ({added})", added == 4)
    hosts = {h["name"]: h["address"] for h in ansible.hosts_of(pasted)}
    check("a name and an address", hosts.get("web-1") == "10.20.0.11")
    check("a comma separates them just as well", hosts.get("web-2") == "10.20.0.12")
    check("a name on its own is left for ansible to resolve",
          hosts.get("db-1.internal") == "")
    check("and an address on its own is its own name",
          hosts.get("10.20.0.20") == "")
    check("a comment and a blank line are not hosts",
          "#" not in " ".join(hosts) and "" not in hosts)
    # A bad line must not cost the good ones: half a pasted list rejected means
    # retyping the half that was fine.
    check(f"the bad lines are skipped and named ({len(skipped)})",
          len(skipped) == 3)
    check("a duplicate says it is one",
          any("already in this group" in x for x in skipped))
    check("and a line with too much on it says that",
          any("more than a name" in x for x in skipped))

    print("the gates in front of a real run")
    prod = local_group("prodgroup", is_prod="1")
    try:
        ansible.start(pb, prod, "tester", check=False, allow_real=False)
        check("a real run is refused when the installation says no", False)
    except ansible.Refused as e:
        check(f"and the reason names the setting ({e})", "switched off" in str(e))
    try:
        ansible.start(pb, prod, "tester", check=False, allow_real=True, confirm="")
        check("a production group is refused without its name", False)
    except ansible.Refused as e:
        check(f"and says which name to type ({e})", "prodgroup" in str(e))
    try:
        ansible.start(pb, prod, "tester", check=False, allow_real=True,
                      confirm="prodgrouq")
        check("a near-miss on the name is refused", False)
    except ansible.Refused:
        pass
    empty = ansible.save_group("", {"name": "nohosts"}, "tester")
    try:
        ansible.start(pb, empty, "tester", check=True)
        check("a group with no hosts is refused", False)
    except ansible.Refused:
        pass

    if not have_ansible:
        print("OK" if not bad else f"{bad} FAILED")
        return 1 if bad else 0

    print("a check run changes nothing on the host — the whole point of it")
    local = local_group("here-check")
    if os.path.exists(MARKER):
        os.unlink(MARKER)
    got = wait(ansible.start(pb, local, "tester@test", check=True))
    check(f"the run finished as ok ({got.get('status')} rc={got.get('rc')})",
          got.get("status") == "ok")
    check("ansible said it would change something",
          got.get("stats", {}).get("totals", {}).get("changed") == 1)
    # The assertion this whole file exists for.
    check("and the file it would have created does NOT exist",
          not os.path.exists(MARKER))
    check("the output is kept, including the command", "$ " in (got.get("text") or "")
          and "--check" in (got.get("cmd") or ""))
    check("the check is recorded as a check", got.get("check_mode") == 1)

    print("a real run does change it")
    got = wait(ansible.start(pb, local, "tester@test", check=False,
                             allow_real=True))
    check(f"it finished as ok ({got.get('status')} rc={got.get('rc')})",
          got.get("status") == "ok")
    check("the file is there now", os.path.exists(MARKER))
    check("and the recap was read back per host",
          got.get("stats", {}).get("hosts", {}).get("here", {}).get("ok") == 1)
    if os.path.exists(MARKER):
        os.unlink(MARKER)

    print("a playbook that fails is recorded as failed, with its output")
    broken = ansible.save_playbook("", "broken", """---
- name: fail on purpose
  hosts: all
  gather_facts: false
  tasks:
    - name: run something that is not there
      ansible.builtin.command: /definitely/not/a/binary
""", "", "tester")
    got = wait(ansible.start(broken, local, "tester@test", check=False,
                             allow_real=True))
    check(f"the status says failed ({got.get('status')} rc={got.get('rc')})",
          got.get("status") == "failed" and got.get("rc") == 2)
    check("and the reason is in the output that was kept",
          "fatal" in (got.get("text") or "").lower())
    check("the failure is counted",
          got.get("stats", {}).get("totals", {}).get("failed") == 1)

    print("two runs of the same thing at once are refused")
    slow = ansible.save_playbook("", "slow", """---
- name: take a moment
  hosts: all
  gather_facts: false
  tasks:
    - name: wait
      ansible.builtin.pause:
        seconds: 8
""", "", "tester")
    first = ansible.start(slow, local, "tester@test", check=True)
    try:
        ansible.start(slow, local, "tester@test", check=True)
        check("the second is refused while the first is going", False)
    except ansible.Refused as e:
        check(f"and says why ({e})", "already running" in str(e))

    print("a run can be stopped, and what it printed is kept")
    time.sleep(1.0)
    check("cancel reaches the process", ansible.cancel(first, "tester@test"))
    got = wait(first, 30)
    check(f"the run is closed ({got.get('status')})", got.get("done"))
    check("and says it was cancelled",
          "cancelled" in (got.get("text") or ""))

    print("a run whose portal restarted is not still running")
    stuck = ansible.start(slow, local, "tester@test", check=True)
    ansible._live.pop(stuck, None)            # as a fresh process would find it
    closed = ansible.adopt_orphans()
    check(f"the orphan was closed ({closed})", closed >= 1)
    got = ansible.run(stuck)
    check("its status is no longer running", got["status"] != "running")
    check("and it says what is and is not known",
          "restarted" in (got.get("text") or ""))
    check("so the playbook can be run again",
          not any(r["id"] == stuck for r in ansible.running()))

    print("the syntax check tells a broken playbook from a working one")
    check("a good playbook passes", ansible.syntax_check(TOUCHER)["ok"])
    nope = ansible.syntax_check("- this: [is not\n  a playbook")
    check(f"a broken one does not ({(nope['error'] or '')[:40]})", not nope["ok"])
    check("and the reason is passed through", bool(nope["error"]))
    # A syntax check runs against an empty inventory, so ansible opens with
    # "[WARNING]: provided hosts list is empty" — which was the first thing the
    # editor showed somebody whose playbook had a typo on line 9.
    check("the real fault leads, not ansible's preamble",
          not nope["error"].startswith("[WARNING]"))
    check("but the warnings are still there to read",
          "WARNING" in nope["error"])

    print("the task count is of tasks, not of every name in the file")
    # Both a play and a task are `- name:`. Counting all of them called the
    # two-task example "3 tasks" on the list page and in the editor's own gutter.
    check(f"the example counts 2 ({ansible._count_tasks(ansible.EXAMPLE)})",
          ansible._count_tasks(ansible.EXAMPLE) == 2)
    check("one task counts 1", ansible._count_tasks(
        "---\n- name: play\n  hosts: all\n  tasks:\n"
        "    - name: only\n      ansible.builtin.ping:\n") == 1)
    check("a playbook whose only names are plays counts none",
          ansible._count_tasks("---\n- name: play\n  hosts: all\n") == 0)
    check("and something that is not a playbook counts none",
          ansible._count_tasks("hello") == 0)

    print("every version of a playbook is kept")
    pb2 = ansible.save_playbook("", "versioned", "---\n# one\n", "", "tester")
    ansible.save_playbook(pb2, "versioned", "---\n# two\n", "", "tester")
    ansible.save_playbook(pb2, "versioned", "---\n# three\n", "", "tester")
    revs = ansible.revisions(pb2)
    check(f"two earlier versions are there ({len(revs)})", len(revs) == 2)
    check("the newest earlier version is the one just replaced",
          "# two" in ansible.revision_body(revs[0]["id"]))
    ansible.save_playbook(pb2, "versioned", "---\n# three\n", "", "tester")
    check("saving the same text again does not make a version",
          len(ansible.revisions(pb2)) == 2)
    ansible.delete_playbook(pb2)
    check("deleting a playbook takes its versions", not ansible.revisions(pb2))
    # ...but never its runs: a run is the record that something happened on real
    # hosts, and that stays true when the playbook is gone.
    check("and the runs of a deleted playbook are still recorded",
          any(r["pb_name"] == "broken" for r in ansible.runs(200)))

    http_checks(pb, local)
    image_checks()

    print("OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


def image_checks() -> None:
    """The image has to be able to FIND the runner, not merely contain it.

    This is the fault that would have shipped: pip installs `ansible-playbook`
    into `/venv/bin`, the portal looks for its tools on `PORTAL_TOOL_PATH`, and
    that variable listed `/usr/local/bin:/usr/bin:/bin`. kubectl and git are in
    those directories; ansible is not. So every install from the image would have
    reported "ansible-playbook is not available" with the binary sitting in the
    container — and nothing outside a container would ever reproduce it, because
    a source checkout runs with the developer's own PATH.
    """
    print("the container image can find the runner it ships")
    root = pathlib.Path(__file__).resolve().parent.parent
    dockerfile = (root / "Dockerfile").read_text()
    reqs = (root / "requirements.txt").read_text()
    check("the image installs a runner",
          re.search(r"^ansible-core", reqs, re.M) is not None)
    tool_path = re.search(r'PORTAL_TOOL_PATH="([^"]+)"', dockerfile)
    check("the image sets a tool path", tool_path is not None)
    if tool_path:
        dirs = tool_path.group(1).split(":")
        # wherever the venv is, that is where a pip-installed entry point lands
        venv = re.search(r"COPY --from=deps (/\S+) ", dockerfile)
        want = (venv.group(1).rstrip("/") + "/bin") if venv else "/venv/bin"
        check(f"and it includes {want}, or ansible cannot be found ({dirs})",
              want in dirs)


def http_checks(pb: str, gid: str) -> None:
    """The pages, and the one route that can change a host.

    The module-level checks above prove the runner refuses what it should. These
    prove the *route* asks — a gate that exists in ansible.py and is never called
    from main.py is not a gate, and nothing else in this file would notice.
    """
    from fastapi.testclient import TestClient
    from app import auth, db, main as appmain, rbac

    def signin(email: str, pw: str) -> TestClient:
        c = TestClient(appmain.app, raise_server_exceptions=False)
        c.__enter__()
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        u = auth.by_email(email)
        c.post("/mfa", data={"code": auth._totp_at(
            u["totp_secret"], int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        return c

    boss_mail, boss_pw = "ansboss@test.invalid", "Runs-Playbooks-42xy"
    uid = auth.create_user(boss_mail, "Boss", boss_pw, role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    # Somebody who may READ all of this and may not run any of it. The whole
    # point of ansible_run being its own area.
    read_mail, read_pw = "ansread@test.invalid", "Reads-Only-42xy"
    ruid = auth.create_user(read_mail, "Reader", read_pw, role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", ruid))
    rbac.set_for_user(ruid, [rbac.save("", "Ansible, reading", "", ["ansible"],
                                       [], [])])

    print("the pages")
    boss = signin(boss_mail, boss_pw)
    for path in ("/ansible", "/ansible?sec=inventory", "/ansible?sec=runs",
                 f"/ansible/playbooks/{pb}", "/ansible/playbooks/new",
                 "/settings/ansible"):
        r = boss.get(path, follow_redirects=False)
        check(f"{path} → HTTP {r.status_code}", r.status_code == 200)
    body = boss.get("/ansible").text
    check("the page uses the shared sub-tab strip", 'class="subtabs' in body)
    check("and the run window is on it", 'id="arDlg"' in body)
    check("a playbook that has never run says so",
          "never run" in body or "runs recorded" in body)

    print("creating a group with its hosts in one save")
    r = boss.post("/ansible/group/save",
                  data={"name": "frankfurt", "ssh_user": "ubuntu",
                        "hosts": "fe-1 10.30.0.1\nfe-2 10.30.0.2"},
                  follow_redirects=False)
    check(f"the form redirects ({r.status_code})", r.status_code == 303)
    where = r.headers.get("location", "")
    check(f"and says how many hosts arrived ({where[-60:]})",
          "2 host" in urllib.parse.unquote(where))
    made = next((g for g in ansible.groups() if g["name"] == "frankfurt"), None)
    check("the group exists with its hosts", made and len(made["hosts"]) == 2)
    check("and its inventory carries the addresses",
          "ansible_host: 10.30.0.1" in ansible.inventory_text(made))
    # The field has to be ON the page somebody lands on to make one, not only in
    # the model — and that page is now /ansible/groups/new.
    body = boss.get("/ansible/groups/new").text
    check("the create page offers a place for them",
          body.count('name="hosts"') >= 1)
    # The shape of a line, however it is worded: an address alone is enough, and
    # a name may go in front of it.
    check("and says what shape they go in",
          "one per line" in body.lower()
          and re.search(r"\d+\.\d+\.\d+\.\d+", body) is not None)

    print("a refused save hands back everything that was typed")
    # REPORTED: a thirteen-field "create group" form, one bad field, and the
    # portal answered 303 to the INVENTORY LIST -- an error about a page you
    # are no longer on, and every word gone. A redirect re-reads the row from
    # the database, so it cannot show a submission; that is precisely why a
    # recoverable validation failure must re-render instead.
    typed = {"gid": "", "name": "bad name!", "notes": "my careful notes",
             "ssh_user": "deployer", "ssh_port": "2222",
             "group_vars": "ansible_python_interpreter: /usr/bin/python3",
             "hosts": "10.0.10.53\n10.0.10.54\nweb-1 10.20.0.11",
             "become_root": "1"}
    r = boss.post("/ansible/group/save", data=typed, follow_redirects=False)
    check(f"a refused create RE-RENDERS rather than redirecting ({r.status_code})",
          r.status_code == 200)
    b = r.text
    check("the reason is on the form, not a flash on another page",
          "letters, digits" in b)
    # EVERY FIELD, because the expensive ones are the ones nobody retypes.
    for what, needle in (("the name that was rejected", 'value="bad name!"'),
                         ("the notes", "my careful notes"),
                         ("the ssh user", 'value="deployer"'),
                         ("the group vars", "ansible_python_interpreter"),
                         ("the pasted host block", "web-1 10.20.0.11")):
        check(f"...and it still holds {what}", needle in b)
    # AND IT IS STILL A CREATE. `g` is now a submission rather than a row, so
    # anything keyed on "is there a g" would offer to delete a group that does
    # not exist.
    check("it still says Create group, not Save changes",
          "Create group" in b and "Save changes" not in b)
    check("...and does not offer to delete a group that was never made",
          "Delete this group" not in b)
    check("...and nothing was written", not [
          g for g in ansible.groups() if g["name"] == "bad name!"])

    print("...and the ticks have a removal of their own, which the group delete "
          "is not")
    # REPORTED, and it cost a whole group: the page had ONE selection -- a
    # column of ticks whose only consumer was the ssh-key dialog -- and ONE
    # control labelled delete, "Delete this group", which ignored it. Somebody
    # ticked a few hosts, pressed the thing that says delete, and lost the
    # group with every host in it. The button did what it said; the page
    # implied something else, which is a trap however carefully it is worded.
    bg = ansible.save_group("", {"name": "bulk-pick", "env": "test"}, "sys")
    b1 = ansible.add_host(bg, "bp-1", "10.31.0.1", "sys")
    b2 = ansible.add_host(bg, "bp-2", "10.31.0.2", "sys")
    b3 = ansible.add_host(bg, "bp-3", "10.31.0.3", "sys")
    body = boss.get(f"/ansible/groups/{bg}").text
    check("the ticks carry the host id, so a second action can use them",
          f'data-hid="{b1}"' in body and f'data-hid="{b2}"' in body)
    check("...and there is a removal bound to them",
          'id="h_del"' in body and 'action="/ansible/hosts/delete"' in body)
    # SUBMITTED THROUGH THE TYPED CONFIRM. `form.submit()` does not fire a
    # submit event, so it would post straight past the house delete guard --
    # on this form, of all of them.
    grp_js = (pathlib.Path(__file__).resolve().parents[1]
              / "templates" / "ansible_group.html").read_text()
    # Checked against the FUNCTION BODY, with comment lines stripped: the
    # comment explaining the choice names the wrong call, and a substring test
    # over the file would fail on its own explanation. Third time today.
    body_fn = grp_js[grp_js.index("function removePicked()"):]
    body_fn = body_fn[:body_fn.index("\nfunction ")]
    code_fn = "\n".join(l for l in body_fn.split("\n")
                        if not l.strip().startswith("//"))
    check("...and it goes through the guard, not around it",
          "form.requestSubmit();" in code_fn and "form.submit()" not in code_fn)
    # REMOVES WHAT WAS TICKED, and leaves the group and the rest standing.
    r = boss.post("/ansible/hosts/delete", data={"gid": bg, "hid": [b2]},
                  follow_redirects=False)
    left = {h["name"] for h in ansible.hosts_of(bg)}
    check(f"removing one leaves the others and the group ({sorted(left)})",
          r.status_code == 303 and left == {"bp-1", "bp-3"}
          and ansible.group(bg) is not None)
    # SEVERAL AT ONCE, which is the point of a selection.
    boss.post("/ansible/hosts/delete", data={"gid": bg, "hid": [b1, b3]},
              follow_redirects=False)
    check("removing several takes all of them, and still not the group",
          ansible.hosts_of(bg) == [] and ansible.group(bg) is not None)
    # VALIDATED AGAINST THE GROUP, not trusted. Without this the route would
    # delete any host in the install by id -- a worse version of the bug it
    # exists to fix.
    og = ansible.save_group("", {"name": "bulk-other", "env": "test"}, "sys")
    o1 = ansible.add_host(og, "other-1", "10.32.0.1", "sys")
    r = boss.post("/ansible/hosts/delete", data={"gid": bg, "hid": [o1]},
                  follow_redirects=False)
    check("a host id from ANOTHER group is ignored, not deleted",
          r.status_code == 303
          and [h["name"] for h in ansible.hosts_of(og)] == ["other-1"])
    ansible.delete_group(bg); ansible.delete_group(og)

    print("the group's page is its host table, and adding one is a row in it")
    # What a person does on a group's page is look at its hosts, add one, and ask
    # whether they can be reached — so those are what the markup makes cheap.
    body = boss.get(f"/ansible/groups/{gid}").text
    check("adding a host is the last row of the table",
          'class="addrow"' in body and 'form="addh"' in body)
    # The inputs sit in a <tr>, so they cannot be wrapped in their own <form> —
    # a form inside a table row is invalid and the browser drops it, silently.
    # What has to hold is that the id each input points at IS a form on the page:
    # a dangling `form=` is a button that does nothing and says nothing.
    targets = set(re.findall(r'form="(addh|delh-[^"]+)"', body))
    forms = set(re.findall(r'<form[^>]*action="/ansible/host/(?:add|delete)"'
                           r'[^>]*id="([^"]+)"', body))
    check(f"every row points at a real form ({sorted(targets)} → {sorted(forms)})",
          bool(targets) and targets <= forms)
    # Both ways in, on purpose: the row takes one host with its own user or port,
    # the box takes the twenty addresses somebody already has in a list. The box
    # used to be on the create form only, so adding a fleet to an existing group
    # meant twenty visits to a one-line form.
    check("one host at a time, with its own user and port",
          'form="addh"' in body and 'action="/ansible/host/add"' in body)
    check("and several at once, pasted",
          'action="/ansible/host/paste"' in body and 'name="hosts"' in body)

    print("a group can be tested without writing a playbook")
    body = boss.get("/ansible?sec=inventory").text
    # The question an inventory page exists to answer. It is a built-in playbook
    # so that a run of it is a run like any other — same gates, same record.
    check("the built-in is offered on every group",
          'data-ansrun="builtin:ping"' in body)
    check("and it starts on the click rather than needing a second button",
          'data-ansauto="check"' in body)
    check("the built-in resolves like a stored playbook",
          (ansible.playbook("builtin:ping") or {}).get("name") == "connection test")
    check("it is not in the playbook list, which is the reader's own work",
          "builtin:ping" not in [p["id"] for p in ansible.playbooks()])
    for verb, fn in (("edited", lambda: ansible.save_playbook(
                          "builtin:ping", "hijack", "---\n", "", "tester")),
                     ("deleted", lambda: ansible.delete_playbook("builtin:ping"))):
        try:
            fn()
            check(f"a built-in cannot be {verb}", False)
        except ansible.Refused as e:
            check(f"and being {verb} is refused as what it is ({e})",
                  "ships with the product" in str(e))
    if ansible.tool()["found"]:
        local = local_group("pingable")
        done = wait(ansible.start("builtin:ping", local, "tester", check=True))
        check(f"and running it answers the question ({done.get('status')})",
              done.get("status") == "ok"
              and done.get("stats", {}).get("totals", {}).get("ok") == 1)
        check("recorded under its own name, not as a mystery",
              done.get("pb_name") == "connection test")

    print("every sub-tab link on the page opens")
    # `/ansible` is a bare path, so the strip has to join with `?` and not `&`.
    # It joined with `&`, and Inventory and Runs pointed at `/ansible&sec=…` —
    # a path nothing serves. Every check here previously requested a URL this
    # test built itself, which is exactly why none of them noticed.
    body = boss.get("/ansible").text
    links = [h.replace("&amp;", "&") for h in
             re.findall(r'<a class="stab[^"]*"\s+href="([^"]+)"', body)]
    check(f"the strip drew a link per section ({links})", len(links) == 5)
    for href in links:
        got = boss.get(href, follow_redirects=False)
        check(f"following {href} → HTTP {got.status_code}", got.status_code == 200)
    check("and they are query strings, not paths",
          all("?sec=" in h or h == "/ansible" for h in links))

    print("every figure at the top is a link to what it counts")
    body = boss.get("/ansible").text
    tiles = [h.replace("&amp;", "&") for h in
             re.findall(r'<a class="ex-tile[^"]*"\s+href="([^"]+)"', body)]
    check(f"every tile is a link ({len(tiles)})", len(tiles) == 6)
    # the shared component, not a private copy: two pages carrying their own
    # version of this tile is how they drift apart
    check("and the tile styling is the shared one from base.html",
          "ex-tile" not in (pathlib.Path(__file__).resolve().parent.parent
                            / "templates" / "ansible.html").read_text()
          .split("<style>")[1].split("</style>")[0]
          if "<style>" in (pathlib.Path(__file__).resolve().parent.parent
                           / "templates" / "ansible.html").read_text() else True)
    for href in tiles:
        got = boss.get(href, follow_redirects=False)
        check(f"following {href} → HTTP {got.status_code}", got.status_code == 200)
    for want in ("/ansible?sec=playbooks", "/ansible?sec=inventory",
                 "/ansible?sec=runs&state=running",
                 "/ansible?sec=runs&state=failed", "/ansible?sec=runs"):
        check(f"one of them is {want}", want in tiles)
    # The rule the expiry radar had to learn: a tile that opens a list of a
    # different size than the number on it is worse than no number at all.
    #
    # Both failure shapes are planted first, because they are counted together
    # and reported apart: a task that failed is `failed`, a host that could not be
    # reached is `unreachable`, and a filter that knows only the first agrees with
    # the tile until the day something is actually unreachable.
    for rid, status, rc in (("r-failed", "failed", 2),
                            ("r-unreach", "unreachable", 4)):
        db.run("INSERT INTO ansible_runs (id, pb_id, pb_name, group_id,"
               " group_name, hosts, check_mode, status, rc, started, finished,"
               " by, output, stats) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (rid, "", "probe", "", "somewhere", 1, 1, status, rc,
                ansible._now(), ansible._now(), "tester", "", "{}"))
    counted = ansible.summary()["failed"]
    check(f"both shapes are counted as needing attention ({counted})",
          counted >= 2)
    listed = boss.get("/ansible?sec=runs&state=failed").text
    shown = listed.count('data-ansout="')
    check(f"the failed tile opens exactly what it counts "
          f"({shown} rows vs {counted})", shown == counted)

    print("a group is a page, and the list is a list")
    # Its own group, not the ambient `gid`: that name is reassigned further up,
    # and a section that both reads and RENAMES a fixture it does not own leaves
    # the next test running against something else — which is exactly what the
    # first version of this did.
    pgid = ansible.save_group("", {"name": "pageable", "ssh_user": "deployer",
                                   "ssh_port": 2201}, "tester")
    ansible.add_host(pgid, "page-1", "10.44.0.7", "tester")
    body = boss.get("/ansible?sec=inventory").text
    check("the list links to each group's own page",
          f'href="/ansible/groups/{pgid}"' in body)
    check("and to a page for making one", 'href="/ansible/groups/new"' in body)
    # The point of the rebuild: the list was a stack of thirteen-field forms, so
    # the page that answers "which groups do I have" also asked for a private key.
    check("the list carries no settings form",
          'action="/ansible/group/save"' not in body)
    check("and no private key field", 'name="key"' not in body)

    made = boss.get("/ansible/groups/new")
    check(f"the new-group page renders → HTTP {made.status_code}",
          made.status_code == 200)
    check("with a form that creates rather than edits",
          'action="/ansible/group/save"' in made.text
          and 'name="gid" value=""' in made.text)
    check("and somewhere to paste the hosts, which is what a new group needs",
          'name="hosts"' in made.text)

    one = boss.get(f"/ansible/groups/{pgid}")
    check(f"a group's own page renders → HTTP {one.status_code}",
          one.status_code == 200)
    for want in (f'name="gid" value="{pgid}"', 'value="pageable"',
                 'value="deployer"', 'name="key"',
                 'action="/ansible/host/add"', 'action="/ansible/group/delete"'):
        check(f"it is editable: {want}", want in one.text)
    check("the hosts are on it", "page-1" in one.text)
    check("with the inventory ansible is actually given",
          "ansible_host: 10.44.0.7" in one.text)
    gone = boss.get("/ansible/groups/g-nope", follow_redirects=False)
    check(f"a group that does not exist redirects rather than 500s "
          f"({gone.status_code})", gone.status_code == 303)

    print("the region select FOLLOWS the project, and the themed control knows")
    # Reported from the running portal: a project was chosen and the region
    # select stayed dead, on a project that has three regions. Both halves of
    # the house rule (CLAUDE.md) were broken in `place_fields`, which three
    # pages share — Ansible playbooks, Ansible groups and Terraform stacks:
    #
    #   * it set `hidden` on the <option>s. The themed dropdown builds its menu
    #     from the options it FINDS and skips only `disabled` ones, so hiding
    #     changed nothing about what was offered.
    #   * it toggled `disabled` on the native select and never called
    #     ddRefresh. The visible control is a button drawn beside that select
    #     and re-reads `disabled` only when refreshed — so the button painted
    #     disabled at load (no project yet) and stayed that way for ever.
    here = pathlib.Path(__file__).resolve().parent.parent
    bits = (here / "templates" / "_bits.html").read_text()
    place = bits[bits.index("macro place_fields"):bits.index("macro donut_panel")]
    # THE BEHAVIOUR MOVED, and so did its test. These four checks used to read
    # the macro's own inline JavaScript for the right strings — which is why
    # they said nothing at all when the SECOND copy of that JavaScript, in the
    # Privileged Access target form, turned out to have the same two faults and
    # was reported months later. There is one implementation now
    # (`window.placeSync`, base.html) and tests/test_placesync_js.py RUNS it.
    # What is left here is what belongs to this macro: that it delegates, and
    # that its markup gives the shared code what it needs.
    check("the macro delegates rather than carrying its own copy",
          "window.placeSync" in place and "o.hidden" not in place)
    # Every option must say which project it belongs to, or the filter has
    # nothing to filter on.
    check("each region option carries its project",
          'data-proj="{{ po.id }}"' in place)
    # A project with no regions is a normal state, and "whole project" is the
    # right answer for it — the shared code writes the sentence, the macro has
    # to give it somewhere to write it.
    check("there is an element for the empty-list explanation",
          'id="plcRegNote"' in place)
    # Nothing about this may be baked in: the projects and their regions come
    # from the estate, so an install with different ones works unchanged.
    src = (here / "app" / "main.py").read_text()
    opts = src[src.index("def _place_options"):]
    opts = opts[:opts.index("def _region_options")]
    check("and the options come from the estate, not a list in the code",
          "store.projects()" in opts and '"regions"' in opts)

    print("making a group is four fields and one button")
    # It was eleven fields in three cards, and the first thing anybody needs — the
    # hosts — was not the thing hardest to reach. What matters is that the page
    # somebody lands on carries exactly the four, and that the rest is still
    # there, one control down, rather than gone.
    made = boss.get("/ansible/groups/new").text
    # Split on the ADVANCED section's own class, not on any `<details`: the
    # bare substring appears in prose too — a CSS comment in base.html
    # mentioning the element was enough to cut this page before the form even
    # started, and the four checks below then failed for a reason that had
    # nothing to do with the form.
    body_only = made.split('<details class="adv"', 1)[0]
    for want, label in (('name="name"', "a name"), ('name="hosts"', "the hosts"),
                        ('name="ssh_user"', "the ssh user"),
                        ('name="password"', "a password, to set up keys now")):
        check(f"the form opens with {label}", want in body_only)
    for hidden, label in (('name="ssh_port"', "the port"),
                          ('name="key"', "a key to paste"),
                          ('name="group_vars"', "group variables"),
                          ('name="is_prod"', "the production flag"),
                          ('name="become_root"', "sudo")):
        check(f"{label} is still there, under Advanced",
              hidden in made and hidden not in body_only)
    check("and Advanced says what is inside it",
          "port, keys, sudo, production, variables" in made)
    # One button, and the password makes it do the whole job.
    check("the password field does not remember itself",
          not re.search(r'name="password"[^>]*value=', made))

    print("a password given while saving sets the keys up in the same action")
    called = {}
    was_install = ansible.install_key

    def spy(gid_, user_, password_, who_="", confirm_="", key_type_="",
            only_host_="", **extra):
        called.update(gid=gid_, user=user_, password=password_, kind=key_type_,
                      only=only_host_, extra=sorted(extra))
        return {"rows": [{"name": "h", "state": "installed", "note": "ok"}],
                "public": "ssh-ed25519 AAA x", "generated": True, "ok": 1,
                "total": 1, "why": "", "facts": {}}
    try:
        ansible.install_key = spy
        r = boss.post("/ansible/group/save",
                      data={"gid": "", "name": "oneshot", "ssh_user": "root",
                            "hosts": "10.8.0.1\n10.8.0.2",
                            "password": "typed-once", "key_type": "rsa"},
                      follow_redirects=False)
    finally:
        ansible.install_key = was_install
    where = urllib.parse.unquote(r.headers.get("location", ""))
    check(f"the group is made, the hosts land and the key goes on ({where[-70:]})",
          "2 host(s) added" in where and "reachable by key" in where)
    check("the password reaches the installer, and the key type with it",
          called.get("password") == "typed-once" and called.get("kind") == "rsa")
    check(f"and nothing new is being passed unnoticed ({called.get('extra')})",
          not called.get("extra"))
    check("and the password is not in the URL it redirects to",
          "typed-once" not in where)
    oneshot = next((g for g in ansible.groups() if g["name"] == "oneshot"), None)
    check("the group really exists afterwards", oneshot and len(oneshot["hosts"]) == 2)

    print("editing a group lands back on the group, not on the list")
    saved = boss.post("/ansible/group/save",
                      data={"gid": pgid, "name": "pageable",
                            "ssh_user": "deployer"},
                      follow_redirects=False)
    check(f"saving returns to its page ({saved.headers.get('location')})",
          f"/ansible/groups/{pgid}" in (saved.headers.get("location") or ""))
    added = boss.post("/ansible/host/add",
                      data={"gid": pgid, "name": "page-2", "address": "10.44.0.8"},
                      follow_redirects=False)
    check(f"and so does adding a host ({added.headers.get('location')})",
          f"/ansible/groups/{pgid}" in (added.headers.get("location") or ""))

    print("a group's runs follow the group, not its name")
    # Recorded with the name the group had at the time, so matching on the name
    # would drop every run made before a rename. The id does not move.
    db.run("INSERT INTO ansible_runs (id, pb_id, pb_name, group_id, group_name,"
           " hosts, check_mode, status, rc, started, finished, by, output, stats)"
           " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
           ("r-rename", "", "probe", pgid, "pageable", 1, 1, "ok", 0,
            ansible._now(), ansible._now(), "tester", "", "{}"))
    ansible.save_group(pgid, {"name": "pageable-renamed",
                              "ssh_user": "deployer"}, "tester")
    mine = ansible.runs(50, group_id=pgid)
    check(f"the renamed group keeps its runs ({len(mine)})",
          any(r["id"] == "r-rename" for r in mine))
    check("and every one of them is its own",
          all(r["group_id"] == pgid for r in mine))
    check("while another group's page does not show them",
          not any(r["id"] == "r-rename" for r in ansible.runs(50, group_id=gid)))

    print("a pasted key is parsed, not pattern-matched")
    # It used to check for -----BEGIN and -----END and nothing else, which every
    # mangled key passes — and the failure then arrived at RUN time, on every host
    # at once, as ssh's own `Load key "…/id_key": invalid format` about a temporary
    # file whose name means nothing.
    priv, pub = ansible.new_keypair()
    good = ansible.read_key(priv)
    check(f"a real key parses ({good['kind']})", good["ok"])
    check("and its public half comes back with it",
          good["public"].split()[1] == pub.split()[1])
    bad_pastes = {
        "a public key": (pub, "PUBLIC key"),
        "one long line": (priv.replace("\n", ""), "line breaks"),
        "nothing at all": ("", "nothing there"),
        "prose": ("my key is in the vault", "-----BEGIN"),
    }
    for label, (text, wanted) in bad_pastes.items():
        got = ansible.read_key(text)
        check(f"{label} is refused", not got["ok"])
        check(f"…and the reason names {wanted!r}: {got['why'][:60]}",
              wanted.lower() in got["why"].lower())
    # A key with BOTH markers and a body that lost its line breaks: the shape
    # that the old `-----BEGIN in text and -----END in text` check waved through,
    # and the shape a paste through a chat window or a spreadsheet cell produces.
    # It is the exact paste that reached a run and failed there.
    mangled = priv.replace("\n", "")
    check("the shape that fooled the old check still has both markers",
          "-----BEGIN" in mangled and "-----END" in mangled)
    try:
        ansible.save_group("", {"name": "badkey", "key": mangled}, "tester")
        check("a group will not store a key that cannot be read", False)
    except ansible.Refused as e:
        check(f"a group will not store a key that cannot be read ({str(e)[:40]})",
              True)
    check("RSA is available for a host that refuses ed25519",
          ansible.new_keypair("rsa")[1].startswith("ssh-rsa"))

    print("a key already on the host is recognised, comment or not")
    # The bug this holds shut, found by pressing the button twice: the line
    # INSTALLED carries an envmap-<date> comment, the same key derived from
    # storage afterwards carries none, and a whole-line match therefore appended a
    # second copy of the same key every time. Two identical lines, measured.
    cmd = ansible.authorize_command("ssh-ed25519 AAAAC3Nzaexample envmap-2026-08-13")
    check("the test is the key material, as sshd itself compares it",
          "'ssh-ed25519 AAAAC3Nzaexample'" in cmd and "-qF " in cmd)
    check("and not the whole line, comment and all", "-qxF" not in cmd)
    check("while the line it appends keeps its comment",
          "envmap-2026-08-13" in cmd)
    check("the directory and the file are tightened before anything is written",
          "umask 077" in cmd and "chmod 700 ~/.ssh" in cmd)
    check("and SELinux is relabelled, where SELinux exists",
          "restorecon" in cmd)

    print("the popup that copies the key")
    body = boss.get(f"/ansible/groups/{pgid}").text
    check("the button sits beside the hosts it acts on",
          'data-call="keyDlg"' in body)
    check("with a dialog, not a fourth form down the page",
          '<dialog id="keyDlg"' in body)
    check("that posts to the audited route",
          'action="/ansible/group/keys"' in body)
    check("the password is a password field, and required",
          'id="k_pw"' in body and 'type="password"' in body
          and 'name="password" required' in body.replace('\n', ' ')
          or 'required' in body[body.index('id="k_pw"'):body.index('id="k_pw"') + 200])
    check("every host can also be done on its own",
          body.count('data-call="keyDlg" data-arg="')
          == len(ansible.group(pgid)["hosts"]))
    check("and the key type is offered, because a hardened host refuses ed25519",
          'name="key_type"' in body and "RSA 4096" in body)
    prodg = ansible.save_group("", {"name": "prodkeys", "ssh_user": "root",
                                    "is_prod": "1"}, "tester")
    ansible.add_host(prodg, "p-1", "10.9.9.9", "tester")
    pbody = boss.get(f"/ansible/groups/{prodg}").text
    check("a production group asks for its name inside the dialog",
          'name="confirm" required' in pbody
          and pbody.index('<dialog id="keyDlg"') < pbody.index('name="confirm"'))
    # …and the server does not take the page's word for it
    try:
        ansible.install_key(prodg, "root", "pw", confirm="")
        check("the production confirm is enforced where it matters", False)
    except ansible.Refused as e:
        check(f"the production confirm is enforced where it matters "
              f"({str(e)[:45]})", "production" in str(e))
    try:
        ansible.install_key(pgid, "root", "pw", only_hosts=["not-a-host"])
        check("a host that is not in the group is refused", False)
    except ansible.Refused as e:
        # Named, not dropped: a stale checkbox must not quietly widen the job to
        # every host in the group.
        check(f"and the stray is named ({str(e)[:40]})", "not-a-host" in str(e))
    try:
        ansible.install_key(pgid, "root", "pw",
                            only_hosts=["page-1", "gone-since"])
        check("one stray among real hosts is refused too", False)
    except ansible.Refused as e:
        check("the stray is named, not the real one",
              "gone-since" in str(e) and "page-1" not in str(e))

    print("choosing which hosts the key goes to")
    # The estate this exists for: six machines share a password, two were built by
    # somebody else. Doing them one at a time meant typing the same password once
    # per machine, which is what "add ssh key" per row was.
    many = ansible.save_group("", {"name": "manyhosts", "ssh_user": "root"},
                              "tester")
    for n in ("m-1", "m-2", "m-3"):
        ansible.add_host(many, n, f"10.55.0.{n[-1]}", "tester")
    body = boss.get(f"/ansible/groups/{many}").text
    check("every host row carries a tick",
          body.count('class="kpick"') == 3)
    check("and EVERY tick is owned by the dialog's form, not just the first",
          body.count('class="kpick" form="keyForm" name="only_hosts"') == 3)
    check("there is one that takes them all",
          'id="k_all"' in body)
    # A script that copied the ticks into a hidden field would be a second copy of
    # the truth, and the one that goes stale.
    check("no hidden field shadows the ticks",
          not re.search(r'type="hidden"[^>]*name="only_hosts"', body))
    check("and the ticks live in the table, with the hosts they name",
          body.index('class="kpick"') < body.index('<dialog id="keyDlg"'))
    check("the button counts what is chosen", "'＋ Add ssh key (' + picked.length"
          in body or "Add ssh key (" in body)

    print("the key is tried before the password is")
    # Pressing it again on a host that is already keyed used to authenticate with
    # the password all over again, so a wrong password reported `denied` about a
    # host that was working — and a host that had since switched password auth OFF,
    # which is the whole point of installing a key, could never be confirmed.
    #
    # Exercised rather than read: the two ssh calls are replaced, so the order they
    # are used in is what the test sees. Reading the source for which line comes
    # first passes against `if False:`.
    keyed = ansible.save_group("", {"name": "keyedalready", "ssh_user": "root",
                                    "key": ansible.new_keypair()[0]}, "tester")
    ansible.add_host(keyed, "k-1", "10.66.0.1", "tester")
    was_check, was_pw = ansible._ssh_password_free_check, ansible._ssh_password
    calls = []
    try:
        ansible._ssh_password_free_check = lambda *a, **k: (calls.append("key"), (0, ""))[1]
        ansible._ssh_password = lambda *a, **k: (calls.append("password"),
                                                 (0, "ADDED"))[1]
        got = ansible.install_key(keyed, "root", "not-the-right-one", who="t")
    finally:
        ansible._ssh_password_free_check, ansible._ssh_password = was_check, was_pw
    check(f"the key is tried first ({calls})", calls[:1] == ["key"])
    check("and a host it already works on is never asked for a password",
          "password" not in calls)
    check(f"which is reported as already, not as installed "
          f"({got['rows'][0]['state']})", got["rows"][0]["state"] == "already")
    check("and it counts as reachable", got["ok"] == 1)

    print("a refusal says which kind it is")
    # Two refusals that look identical to a reader and are not.
    off, off_note = ansible.refused_state(
        "root@h: Permission denied (publickey,gssapi-with-mic).", "root")
    check(f"passwords switched off entirely is its own state ({off})",
          off == "no-password")
    check("and it says to install the key by hand instead",
          "by hand" in off_note)
    wrong, wrong_note = ansible.refused_state(
        "root@h: Permission denied (publickey,gssapi-keyex,password).", "root")
    check(f"a wrong password is not that ({wrong})", wrong == "denied")
    check("and names the user it was refused for", "root" in wrong_note)

    print("the record can be cleared, one run or a class of them")
    def plant(rid, status, when=None, pbname="probe"):
        db.run("INSERT INTO ansible_runs (id, pb_id, pb_name, group_id,"
               " group_name, hosts, check_mode, status, rc, started, finished,"
               " by, output, stats) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (rid, "", pbname, "", "somewhere", 1, 0, status,
                0 if status == "ok" else 2, when or ansible._now(),
                when or ansible._now(), "tester", "PLAY RECAP\n",
                '{"totals": {"ok": 3, "changed": 1, "failed": 0, "unreachable": 0}}'))

    for rid, status in (("d-ok1", "ok"), ("d-ok2", "ok"), ("d-bad", "failed"),
                        ("d-unr", "unreachable"), ("d-live", "running")):
        plant(rid, status)
    gone = ansible.delete_run("d-ok1")
    check(f"one run can be forgotten ({gone and gone['status']})",
          gone and gone["status"] == "ok")
    check("and it is really gone", ansible.run("d-ok1") is None)
    check("a run that never existed says so", ansible.delete_run("d-nope") is None)
    try:
        ansible.delete_run("d-live")
        check("a run still going is refused, not orphaned", False)
    except ansible.Refused as e:
        # The row is where its output is written and what the live window polls,
        # so deleting one mid-flight leaves a thread writing to nothing.
        check(f"a run still going is refused, not orphaned ({str(e)[:34]})",
              "still going" in str(e))
    # Asserted as a property of the table afterwards, not as a count of what went:
    # earlier sections in this file run real playbooks, so "how many were deleted"
    # is a number that moves with the rest of the suite.
    ansible.clear_runs("ok")
    left = {r["status"] for r in ansible.runs(200)}
    check(f"clearing the ok ones leaves none of them ({sorted(left)})",
          "ok" not in left)
    check("and the failures are still there",
          ansible.run("d-bad") is not None and ansible.run("d-unr") is not None)
    ansible.clear_runs("finished")
    left = {r["status"] for r in ansible.runs(200)}
    check(f"clearing the finished ones leaves only what is still going ({sorted(left)})",
          left <= {"running"})
    check("and never the one still going", ansible.run("d-live") is not None)
    try:
        ansible.clear_runs("everything")
        check("a class nobody defined is refused", False)
    except ansible.Refused:
        pass
    db.run("DELETE FROM ansible_runs WHERE id = 'd-live'")

    print("the overview counts what it draws")
    plant("h-1", "ok")
    plant("h-2", "failed")
    plant("h-old", "ok", when="2020-01-01T00:00:00+00:00")
    h = ansible.history(14)
    check(f"a column per day ({len(h['days'])})", len(h["days"]) == 14)
    check("today is the last one, which is where the eye goes",
          h["days"][-1]["day"] == __import__("datetime").date.today().isoformat())
    check("the busiest day is the full-height bar",
          max(d["pct"] for d in h["days"]) == 100)
    check("a run older than the window is counted in the mix but not in a day",
          h["mix"]["ok"] >= 2
          and sum(d["total"] for d in h["days"]) == h["counted"] - 1)
    # The rate has to divide by runs that FINISHED. A run still going has no
    # outcome, and counting it either way makes the figure move on its own.
    plant("h-live", "running")
    h2 = ansible.history(14)
    check(f"the denominator is the runs that finished "
          f"({h2['finished']})",
          h2["finished"] == h2["mix"]["ok"] + h2["mix"]["failed"]
          + h2["mix"]["unreachable"])
    # …and the figure itself divides by that, not by every row: with a run in
    # flight the two differ, which is the whole point of the distinction.
    check(f"and the rate is ok over finished, exactly ({h2['rate']}%)",
          h2["rate"] == round(h2["mix"]["ok"] / h2["finished"] * 100))
    check("which is not what dividing by every row would give",
          h2["mix"]["running"] > 0
          and h2["rate"] != round(h2["mix"]["ok"]
                                  / (h2["finished"] + h2["mix"]["running"]) * 100))
    check("and the task totals come from the runs, not from the run count",
          h2["tasks"]["ok"] >= 9 and h2["tasks"]["changed"] >= 3)
    db.run("DELETE FROM ansible_runs WHERE id IN ('h-1','h-2','h-old','h-live')")

    print("six boxes, and the new one agrees with its filter")
    plant("t-ok1", "ok")
    plant("t-ok2", "ok")
    plant("t-bad", "failed")
    body = boss.get("/ansible").text
    tiles = [h.replace("&amp;", "&") for h in
             re.findall(r'<a class="ex-tile[^"]*"\s+href="([^"]+)"', body)]
    check(f"there are six of them now ({len(tiles)})", len(tiles) == 6)
    check("one counts the runs that worked", "/ansible?sec=runs&state=ok" in tiles)
    listed = boss.get("/ansible?sec=runs&state=ok").text
    shown = listed.count('data-ansout="')
    counted = ansible.summary()["ok"]
    check(f"and opens exactly what it counts ({shown} vs {counted})",
          shown == counted)

    print("the overview tab, and tabs that fill the measure")
    over = boss.get("/ansible?sec=overview")
    check(f"it renders → HTTP {over.status_code}", over.status_code == 200)
    check("with a column per day", 'class="arun-days"' in over.text)
    check("a ring of how runs end", 'class="chart-donut"' in over.text)
    check("which playbooks do the work", "Which playbooks do the work" in over.text)
    check("and the tasks, not just the runs", "changed something" in over.text)
    check("it is the tab a bare /ansible lands on",
          'class="stab on"' in boss.get("/ansible").text.split("Overview")[0][-120:]
          or 'aria-current="page"' in boss.get("/ansible").text)
    check("the strip spans the measure", 'class="subtabs wide"' in over.text)
    # …and the flag is opt-in, or twelve cluster tabs would stretch too. The
    # cluster DETAIL keeps its dozen main tabs in the compact custom `viewtabs`
    # strip; only the few-tab hub overview (Overview/All/Attention) opts into wide,
    # to match Ansible/Terraform/Pipelines/Workflows.
    clus = (pathlib.Path(__file__).resolve().parent.parent
            / "templates" / "clusters.html").read_text()
    check("while the cluster page's dozen main tabs keep the compact strip",
          'class="viewtabs"' in clus and clus.count("wide=true") <= 1)

    print("deleting through the route, audited")
    # The button has to be ON the page, not merely the route behind it: a row with
    # no delete is a record nobody can clear.
    rows_body = boss.get("/ansible?sec=runs").text
    check(f"every run row offers a delete "
          f"({rows_body.count(chr(34) + '/ansible/run/delete' + chr(34))} vs "
          f"{rows_body.count('data-ansout=')} rows)",
          rows_body.count('"/ansible/run/delete"')
          == rows_body.count('data-ansout='))
    check("and the whole record can be cleared in one go",
          '"/ansible/runs/clear"' in rows_body
          and 'value="finished"' in rows_body and 'value="ok"' in rows_body)
    plant("r-del", "ok")
    r = boss.post("/ansible/run/delete", data={"run_id": "r-del"},
                  follow_redirects=False)
    check(f"the delete redirects ({r.status_code})", r.status_code == 303)
    check("and the run is gone", ansible.run("r-del") is None)
    plant("r-c1", "ok")
    plant("r-c2", "failed")
    r = boss.post("/ansible/runs/clear", data={"which": "finished"},
                  follow_redirects=False)
    where = urllib.parse.unquote(r.headers.get("location", ""))
    check(f"clearing says how many went ({where[-40:]})", "run(s) deleted" in where)
    trail = [a for a in auth.read_audit(80)
             if a.get("action") in ("ansible_run_deleted", "ansible_runs_cleared")]
    check(f"both are in the audit trail ({len(trail)})", len(trail) >= 2)
    check("and the class that was cleared is recorded",
          any("finished" in (a.get("target") or "") for a in trail))

    print("a chart that says click a day opens that day")
    # The hint said "click a day" and every column linked to the whole history —
    # a promise the page could not keep. Now a column links to its own day, and a
    # day with nothing behind it is not a link at all: a link that filters to
    # nothing invites a click that answers nothing.
    today = __import__("datetime").date.today()
    other = (today - __import__("datetime").timedelta(days=3)).isoformat()
    db.run("DELETE FROM ansible_runs")
    plant("day-t1", "ok")
    plant("day-t2", "failed")
    plant("day-o1", "ok", when=f"{other}T09:00:00+00:00", pbname="old-book")
    listed = boss.get(f"/ansible?sec=runs&day={other}").text
    check(f"the day filter opens exactly that day "
          f"({listed.count('data-ansout=')} row)",
          listed.count('data-ansout="') == 1 and "old-book" in listed)
    check("and says which day is narrowing the list", f"on {other}" in listed)
    check("with the way out beside it", ">show all</a>" in listed)
    check("today's two runs are not in it", "day-t1" not in listed)
    junk = boss.get("/ansible?sec=runs&day=13-08-2026")
    check(f"a day that is not a date is ignored, not an error "
          f"({junk.status_code})", junk.status_code == 200
          and junk.text.count('data-ansout="') == 3)
    over = boss.get("/ansible?sec=overview").text
    check("a day with runs is a link to that day",
          f'href="/ansible?sec=runs&amp;day={other}"' in over
          or f'href="/ansible?sec=runs&day={other}"' in over)
    # the empty days: columns, not links
    import re as _re
    cols = _re.findall(r'<(a|span) class="col[^"]*"', over)
    check(f"quiet days are plain columns ({dict((x, cols.count(x)) for x in set(cols))})",
          cols.count("span") >= 10 and cols.count("a") == 2)

    print("an empty filtered list is not an empty record")
    # "No runs yet" over a record with rows in it sends somebody to re-run
    # something that ran fine — the filter is why the list is empty, so the
    # page has to say so and hand back the way out.
    quiet = (today - __import__("datetime").timedelta(days=9)).isoformat()
    empty = boss.get(f"/ansible?sec=runs&day={quiet}").text
    check("a filter with nothing behind it says so",
          "Nothing matches this filter" in empty)
    check("with the whole record one click away", "show all 3" in empty)
    check("and never claims the record is empty", "No runs yet" not in empty)

    print("a playbook bar opens the runs it counted")
    # By NAME, because the chart counts by name: a playbook deleted and recreated
    # keeps one bar, and the bar's link must open exactly those runs.
    ranlist = boss.get("/ansible?sec=runs&ran=old-book").text
    check(f"the filter takes the name ({ranlist.count('data-ansout=')} row)",
          ranlist.count('data-ansout="') == 1)
    check("and the header names it", "of “old-book”" in ranlist)
    check("the overview's bar carries that link",
          "ran=old-book" in over)
    db.run("DELETE FROM ansible_runs WHERE id IN ('day-t1','day-t2','day-o1')")

    print("the version reads like a version")
    # "ansible-playbook [core 2.20.1]" was shown brackets and all, which reads
    # like a placeholder nobody filled in.
    if ansible.tool()["found"]:
        v = ansible.tool()["version"]
        check(f"no brackets survive the parse ({v!r})",
              "[" not in v and "]" not in v and v)

    print("a group and a playbook live somewhere")
    from app import store as _store
    _pid = _store.add_project("Placed")
    _rg = _store.add_region(_pid, "preprod")
    placed = ansible.save_group("", {"name": "placedg", "pid": _pid,
                                     "rgid": _rg}, "tester")
    ansible.add_host(placed, "pl-1", "10.77.0.1", "tester")
    got = next(g for g in ansible.groups() if g["id"] == placed)
    check("the group knows its project and region by name",
          got["project_name"] == "Placed" and got["region_name"] == "preprod")
    ppb = ansible.save_playbook("", "placedbook", TOUCHER, "", "tester",
                                pid=_pid, rgid=_rg)
    gotp = next(x for x in ansible.playbooks() if x["id"] == ppb)
    check("and so does the playbook", gotp["project_name"] == "Placed")
    for bad, why in (({"pid": "p-ghost"}, "project does not exist"),
                     ({"pid": _pid, "rgid": "rg-ghost"}, "not part of"),
                     ({"rgid": _rg}, "needs its project")):
        try:
            ansible.save_group("", {"name": "badplace", **bad}, "tester")
            check(f"a wrong place is refused ({bad})", False)
        except ansible.Refused as e:
            check(f"a wrong place is refused, and says why ({str(e)[:38]})",
                  why in str(e))
    # the run freezes the place it happened in — reassigning the group later
    # must not rewrite history
    rid = ansible.start(ppb, placed, "tester", check=True)
    wait(rid)
    mine = [r for r in ansible.runs(200) if r["id"] == rid]
    check("a run carries the group's place", mine
          and mine[0]["pid"] == _pid and mine[0]["rgid"] == _rg)
    other_p = _store.add_project("Elsewhere")
    ansible.save_group(placed, {"name": "placedg", "pid": other_p}, "tester")
    mine = [r for r in ansible.runs(30) if r["id"] == rid]
    check("and keeps it after the group moves", mine[0]["pid"] == _pid)
    ansible.save_group(placed, {"name": "placedg", "pid": _pid, "rgid": _rg},
                       "tester")

    print("the region filter (same picker as Infrastructure Provisioning) opens exactly what it counts")
    body = boss.get(f"/ansible?sec=inventory&reg={_rg}").text
    check("the filtered inventory holds the placed group", "placedg" in body)
    check("and not the others", "pageable" not in body)
    check("the filter names itself (region note + label)",
          "preprod" in body and "show all regions" in body)
    body = boss.get("/ansible?sec=inventory&reg=rg-ghost").text
    check("an unknown region falls back to everything, not to an error",
          "pageable" in body)
    runsbody = boss.get(f"/ansible?sec=runs&reg={_rg}").text
    check("the run list filters by the recorded place",
          "placedbook" in runsbody)
    check("and the filter survives a tab switch",
          f"reg={_rg}" in runsbody.split('class="subtabs')[1][:900])

    print("a schedule from the page, end to end")
    r = boss.post("/ansible/schedule/save",
                  data={"sid": "", "name": "nightly-report", "pb_id": ppb,
                        "group_id": placed, "check_mode": "1",
                        "kind": "daily", "at": "03:30"},
                  follow_redirects=False)
    where = urllib.parse.unquote(r.headers.get("location", ""))
    check(f"saving lands on the schedules tab ({where[:44]})",
          "sec=schedules" in where and "next run" in where)
    srow = next((x for x in ansible.schedules()
                 if x["name"] == "nightly-report"), None)
    check("the schedule exists, with its words",
          srow and srow["words"] == "every day at 03:30")
    check("and inherits the group's place for the filter",
          srow["pid"] == _pid)
    # by NAME too: the Place column read a dash for every row while the
    # hostless group listing skipped the decoration
    check("with the project said as a name, not an id",
          srow["project_name"] == "Placed")
    body = boss.get("/ansible?sec=schedules").text
    check("the tab shows it", "nightly-report" in body)
    check("with a pause and a delete on the row",
          'action="/ansible/schedule/toggle"' in body
          and 'action="/ansible/schedule/delete"' in body)
    check("and the row's name opens its page",
          f'href="/ansible/schedules/{srow["id"]}"' in body)
    page = boss.get(f"/ansible/schedules/{srow['id']}").text
    check("which is editable", 'value="nightly-report"' in page
          and 'action="/ansible/schedule/save"' in page)
    r = boss.post("/ansible/schedule/toggle", data={"sid": srow["id"]},
                  follow_redirects=False)
    check("pausing works through the route",
          ansible.schedule(srow["id"])["enabled"] == 0)
    # As if it sat paused for a month: resuming must schedule from NOW, or the
    # switch flip immediately fires everything the pause skipped.
    db.run("UPDATE ansible_schedules SET next_at='2020-01-01T00:00:00+00:00' "
           "WHERE id=?", (srow["id"],))
    r = boss.post("/ansible/schedule/toggle",
                  data={"sid": srow["id"], "enabled": "1"},
                  follow_redirects=False)
    check("and resuming recomputes the clock rather than firing at once",
          ansible.schedule(srow["id"])["enabled"] == 1
          and ansible.schedule(srow["id"])["next_at"] > ansible._now())
    boss.post("/ansible/schedule/delete", data={"sid": srow["id"]},
              follow_redirects=False)
    check("deleted through the route", ansible.schedule(srow["id"]) is None)
    trail = [a for a in auth.read_audit(60) if "schedule" in a.get("action", "")]
    check(f"every schedule action is audited ({len(trail)})", len(trail) >= 3)

    print("the ticker: due fires once, is claimed once, reschedules forward")
    import datetime as _dtm
    sid = ansible.save_schedule("", {"name": "tick-probe", "pb_id": ppb,
                                     "group_id": placed, "check_mode": "1",
                                     "kind": "minutes", "every": "30"}, "t")
    past = (_dtm.datetime.now(_dtm.timezone.utc)
            - _dtm.timedelta(seconds=5)).isoformat(timespec="seconds")
    db.run("UPDATE ansible_schedules SET next_at=? WHERE id=?", (past, sid))
    was_start, calls = ansible.start, []
    try:
        ansible.start = lambda *a, **k: (calls.append(k), "ar-tick")[1]
        fired = ansible.scheduler_tick()
        again = ansible.scheduler_tick()
    finally:
        ansible.start = was_start
    check(f"one due schedule fires once ({[f.get('run_id') for f in fired]})",
          len(fired) == 1 and fired[0].get("run_id") == "ar-tick")
    check("and is recorded as the clock's doing",
          ansible.schedule(sid)["last_run_id"] == "ar-tick")
    check("a second tick finds nothing due", again == [])
    check("the next fire is in the future",
          ansible.schedule(sid)["next_at"] > ansible._now())
    check("a skippable refusal does not disable the schedule",
          ansible.schedule(sid)["enabled"] == 1)
    # …but a schedule whose playbook is gone switches itself off with the reason
    db.run("UPDATE ansible_schedules SET next_at=? WHERE id=?", (past, sid))
    db.run("DELETE FROM ansible_playbooks WHERE id=?", (ppb,))
    ansible.scheduler_tick()
    srow = ansible.schedule(sid)
    check("a gone playbook disables it, with the reason on the row",
          srow["enabled"] == 0 and "no longer exists" in srow["last_error"])
    ansible.delete_schedule(sid)

    print("two replicas over one database fire a due schedule once")
    # The race, forced: both tickers SELECT the due schedule before either
    # claims it, by parking them on a barrier inside the next_fire they each
    # compute before claiming. Exactly one UPDATE … WHERE next_at=<old> wins,
    # so exactly one runs the playbook — however the threads interleave.
    import threading as _thr
    rpb = ansible.save_playbook("", "racebook", TOUCHER, "", "tester")
    sid3 = ansible.save_schedule("", {"name": "race-probe", "pb_id": rpb,
                                      "group_id": placed, "check_mode": "1",
                                      "kind": "minutes", "every": "30"}, "t")
    db.run("UPDATE ansible_schedules SET next_at=? WHERE id=?", (past, sid3))
    barrier = _thr.Barrier(2, timeout=10)
    was_fire, was_start = ansible.next_fire, ansible.start
    started = []

    def slow_fire(*a, **k):
        try:
            barrier.wait()
        except _thr.BrokenBarrierError:
            pass       # the second round has only one ticker; let it through
        return was_fire(*a, **k)

    try:
        ansible.next_fire = slow_fire
        ansible.start = lambda *a, **k: (started.append(1), "ar-race")[1]
        t1 = _thr.Thread(target=ansible.scheduler_tick)
        t2 = _thr.Thread(target=ansible.scheduler_tick)
        t1.start(); t2.start(); t1.join(20); t2.join(20)
    finally:
        ansible.next_fire, ansible.start = was_fire, was_start
    check(f"both tickers saw it, one fired it ({len(started)})",
          len(started) == 1)
    ansible.delete_schedule(sid3)

    print("a real schedule against production needs the name at save")
    prodg2 = ansible.save_group("", {"name": "prodsched", "is_prod": "1"},
                                "tester")
    ansible.add_host(prodg2, "ps-1", "10.88.0.1", "tester")
    pb3 = ansible.save_playbook("", "prodbook", TOUCHER, "", "tester")
    try:
        ansible.save_schedule("", {"name": "prod-real", "pb_id": pb3,
                                   "group_id": prodg2, "kind": "daily",
                                   "at": "02:00"}, "t")
        check("refused without the name", False)
    except ansible.Refused as e:
        check(f"refused without the name ({str(e)[:36]})",
              "production" in str(e))
    sid2 = ansible.save_schedule("", {"name": "prod-real", "pb_id": pb3,
                                      "group_id": prodg2, "kind": "daily",
                                      "at": "02:00", "confirm": "prodsched"},
                                 "t")
    check("stored as confirmed once typed",
          ansible.schedule(sid2)["confirmed"] == 1)
    check("while a check schedule never asks",
          ansible.save_schedule("", {"name": "prod-check", "pb_id": pb3,
                                     "group_id": prodg2, "check_mode": "1",
                                     "kind": "daily", "at": "02:00"}, "t"))

    print("the cadence arithmetic")
    base = _dtm.datetime(2026, 8, 13, 10, 0, tzinfo=_dtm.timezone.utc)
    check("minutes add minutes",
          ansible.next_fire("minutes", every=30, after=base)
          == base + _dtm.timedelta(minutes=30))
    check("and never below the floor — a typo is not a load test",
          ansible.next_fire("minutes", every=1, after=base)
          == base + _dtm.timedelta(minutes=ansible.MIN_MINUTES))
    check("hours add hours",
          ansible.next_fire("hours", every=6, after=base)
          == base + _dtm.timedelta(hours=6))
    daily = ansible.next_fire("daily", at="03:30", after=base)
    check("daily lands in the future", daily > base)
    check("and a day apart thereafter",
          ansible.next_fire("daily", at="03:30", after=daily) - daily
          == _dtm.timedelta(days=1))
    weekly = ansible.next_fire("weekly", at="06:00", weekday=2, after=base)
    check(f"weekly lands on the asked-for day "
          f"({weekly.astimezone().strftime('%A')})",
          weekly.astimezone().weekday() == 2 and weekly > base)
    for bad in ({"kind": "cron"}, {"kind": "minutes", "every": "x"},
                {"kind": "daily", "at": "25:00"},
                {"kind": "weekly", "at": "06:00", "weekday": "9"}):
        try:
            ansible._cadence_of(bad)
            check(f"a bad cadence is refused ({bad})", False)
        except ansible.Refused:
            pass

    print("action buttons follow the one standard")
    # The geometry lives in base.html and the tone in a variant class — an
    # inline colour at a call site is one edit away from a different red, which
    # is exactly what five call sites had. Scanned across every template,
    # because the standard is the product's, not this page's.
    tpl = pathlib.Path(__file__).resolve().parent.parent / "templates"
    offenders = []
    for f in sorted(tpl.glob("*.html")):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if "abtn" in line and "style=" in line and "color:" in line:
                offenders.append(f"{f.name}:{i}")
    check(f"no action button carries an inline colour ({offenders})",
          not offenders)
    src = (tpl.parent / "static" / "app.css").read_text()
    check("the geometry is fixed once — height and a minimum width",
          "height:26px" in src and "min-width:54px" in src
          and src.count(".abtn {") == 1)
    check("and the destructive tone is a class",
          ".abtn.danger" in src)

    print("reading is not running")
    reader = signin(read_mail, read_pw)
    r = reader.get("/ansible", follow_redirects=False)
    check(f"a reader may open the page → HTTP {r.status_code}", r.status_code == 200)
    check("and is told they cannot run",
          "may read playbooks but not run" in r.text)
    r = reader.post("/ansible/run", data={"pb_id": pb, "gid": gid, "check": "1"},
                    follow_redirects=False)
    check(f"and the route refuses them → HTTP {r.status_code}",
          r.status_code == 403)
    check("with a reason rather than a bare 403",
          "Ansible: run playbooks" in r.text)
    before = len(ansible.runs(500))
    check("and nothing was started", len(ansible.runs(500)) == before)

    if not ansible.tool()["found"]:
        return

    print("starting a run through the route, and following it")
    r = boss.post("/ansible/run", data={"pb_id": pb, "gid": gid, "check": "1"},
                  follow_redirects=False)
    got = r.json()
    check(f"it starts ({r.status_code} {str(got)[:80]})",
          r.status_code == 200 and got.get("ok") and got.get("run_id"))
    run_id = got.get("run_id", "")
    done = wait(run_id)
    check(f"and finishes ({done.get('status')})", done.get("status") == "ok")
    # The offset is what lets the window follow without re-reading everything.
    first = boss.get(f"/ansible/run/{run_id}.json").json()
    tail = boss.get(f"/ansible/run/{run_id}.json?since={first['at']}").json()
    check("asking again from the same offset returns nothing new",
          tail["text"] == "" and tail["at"] == first["at"])
    part = boss.get(f"/ansible/run/{run_id}.json?since=10").json()
    check("and an earlier offset returns only the rest",
          part["text"] == first["text"][10:])
    check("a run that does not exist is a 404",
          boss.get("/ansible/run/ar-nope.json").status_code == 404)

    print("every run is in the audit trail")
    rows = db.q("SELECT action, target FROM audit WHERE action LIKE 'ansible%' "
                "ORDER BY at DESC LIMIT 20")
    kinds = {r["action"] for r in rows}
    check(f"the check run is recorded ({sorted(kinds)})", "ansible_check" in kinds)
    check("and it names what was run against what",
          any("→" in (r["target"] or "") for r in rows))

    print("the settings switch is audited as its own event")
    boss.post("/settings/ansible", data={"allow_real": "1", "forks": "9",
                                         "ssh_timeout": "30"},
              follow_redirects=False)
    check("the switch took", ansible.config()["allow_real"] is True)
    check("and the numbers with it",
          ansible.config()["forks"] == 9 and ansible.config()["ssh_timeout"] == 30)
    check("turning real runs on is its own audit line",
          bool(db.one("SELECT 1 FROM audit WHERE action = "
                      "'ansible_real_runs_enabled'")))
    boss.post("/settings/ansible", data={"forks": "5", "ssh_timeout": "20"},
              follow_redirects=False)
    check("and turning them off is too",
          ansible.config()["allow_real"] is False
          and bool(db.one("SELECT 1 FROM audit WHERE action = "
                          "'ansible_real_runs_disabled'")))
    # Out-of-range numbers are clamped rather than stored: a fork count of
    # 100000 is a portal that stops answering.
    boss.post("/settings/ansible", data={"forks": "100000", "ssh_timeout": "-4"},
              follow_redirects=False)
    check(f"an absurd fork count is clamped ({ansible.config()['forks']})",
          1 <= ansible.config()["forks"] <= 100)
    check(f"and a negative timeout ({ansible.config()['ssh_timeout']})",
          ansible.config()["ssh_timeout"] >= 1)


if __name__ == "__main__":
    sys.exit(main())
