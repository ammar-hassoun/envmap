"""Privileged Access hardening: every fix the end-to-end run found, pinned.

tests/e2e_pam.py drives real ssh, sftp, guacd and x11vnc/xrdp and found each
of these by watching them fail. That run needs Docker; this one needs nothing,
so the fixes stay pinned on any laptop and in CI:

  * SSH host keys are pinned at first contact and ENFORCED after -- every
    session used to accept whatever key the far end presented
  * a session's row exists from the first second, and a process that dies
    mid-session leaves it `interrupted`, never absent
  * a desktop recording is checksummed only once guacd has finished writing
    it, or every genuine one reads as tampered
  * retention and "clear" see every session, not the newest 1,000
  * guacd lengths are code points; idle means no PERSON input; the clipboard
    of a desktop session follows a policy
  * watching or taking over a live desktop is audited -- the socket handed
    the audit an email, the write raised, and the swallow made it silence
  * the gateway has a writable HOME, or FreeRDP cannot set up TLS and every
    RDP target fails as "Security negotiation failed" -- and one from an
    earlier release is recognised as outdated and repaired in place

And what a review found that the run could not see:

  * file transfer reads the pinned known_hosts FIRST
  * a pin belongs to the target however its address is spelled, and a pin
    replaced by an address change says so
  * a host-key refusal is ssh's words at the head of the session, under a
    pin, with exit 255 -- not the same words from the far end
  * a session still opening is neither abandoned nor deletable
  * input waits for a PARSED first frame; relay endings are silent; a
    malformed terminal message is dropped
  * the routes: re-trust needs the whole of Privileged Access, a download is
    an export and never prefetched, the form's lists come from the server
"""
import base64
import json
import logging
import os
import pathlib
import sys
import tempfile
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamhard-")
os.environ.setdefault("PORTAL_PAM", "1")

from app import ansible, auth, db, env, pam, selfupdate, webseat  # noqa: E402

bad = 0


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


# A real ed25519 public key, and the fingerprint `ssh-keygen -lf` prints for
# it -- the same vector OpenSSH's own documentation uses.
KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
FP = "ED25519 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"


def pinning() -> None:
    print("SSH host keys: pinned at first contact, enforced after")
    check("a known_hosts line fingerprints as ssh-keygen says",
          pam.key_fingerprint(f"[10.0.0.9]:2222 ssh-ed25519 {KEY}") == FP)
    check("hashed hosts and comments do not change the answer",
          pam.key_fingerprint(f"|1|abc=|def= ssh-ed25519 {KEY} note") == FP)
    check("a line with no key is no fingerprint",
          pam.key_fingerprint("# a comment") == ""
          and pam.key_fingerprint("host ssh-ed25519 !!!") == "")

    tid = "pt-hardening01"
    work = tempfile.mkdtemp()
    known = os.path.join(work, "known_hosts")
    mode = pam.seed_known_hosts(tid, "10.0.0.9", 2222, known)
    check("a first contact is accept-new, with an EMPTY known_hosts",
          mode == "accept-new" and open(known).read() == "")
    # what ssh writes on accept-new
    open(known, "w").write(f"[10.0.0.9]:2222 ssh-ed25519 {KEY}\n")
    got = pam.pin_after(tid, "10.0.0.9", 2222, known, "op@t")
    check("pin_after pins what ssh accepted", bool(got)
          and got["fingerprints"] == [FP] and got["pinned_by"] == "op@t",
          str(got))
    check("and a second call does nothing (it is idempotent)",
          pam.pin_after(tid, "10.0.0.9", 2222, known, "op@t") is None)
    open(known, "w").write("")
    mode = pam.seed_known_hosts(tid, "10.0.0.9", 2222, known)
    check("once pinned, the next session is STRICT and carries the pinned key",
          mode == "yes" and KEY in open(known).read())
    mode = pam.seed_known_hosts(tid, "10.0.0.10", 2222, known)
    check("a target moved to another host is a fresh first contact",
          mode == "accept-new" and open(known).read() == "")
    check("and so is another port", pam.pin_state(tid, "10.0.0.9", 22)[1]
          is False)
    changed = ("\r\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
               "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
               "Host key for [10.0.0.9]:2222 has changed and you have requested "
               "strict checking.\r\nHost key verification failed.\r\n")
    unknown = ("No ED25519 host key is known for [10.0.0.9]:2222 and you have "
               "requested strict checking.\r\nHost key verification failed.\r\n")
    check("ssh's refusal is recognised in its own words",
          pam.hostkey_refused(changed) and pam.hostkey_refused(unknown)
          and pam.hostkey_refused("Host key verification failed.\r\n")
          and not pam.hostkey_refused("Welcome to Ubuntu"))
    # THE FAR END CAN PRINT THE SAME WORDS -- an operator on a bastion whose
    # own ssh to another box fails. ssh refuses before anything remote exists,
    # so only the head of the session counts.
    check("the same words from the remote host, after a prompt, are not a "
          "refusal", not pam.hostkey_refused("Welcome to Ubuntu 24.04\r\n"
                                             "ops@bastion:~$ ssh db2\r\n" + changed))
    old = pam.forget_pin(tid)
    check("forgetting returns what was pinned, and removes it",
          old and old["fingerprints"] == [FP] and pam.host_pin(tid) is None)
    check("the catalogue reads every pin in one call",
          isinstance(pam.host_pins(), dict))

    # the ssh command line itself, for a native target
    t = {"id": tid, "address": "10.0.0.9", "port": 2222, "auth_kind": "none"}
    pam.pin_after(tid, "10.0.0.9", 2222, _write(f"[10.0.0.9]:2222 ssh-ed25519 {KEY}\n"))
    opts, _env = pam._ssh_auth(t, tempfile.mkdtemp())
    joined = " ".join(opts)
    check("a pinned native target runs ssh with StrictHostKeyChecking=yes",
          "StrictHostKeyChecking=yes" in joined
          and "GlobalKnownHostsFile=/dev/null" in joined
          and "HashKnownHosts=no" in joined, joined)
    pam.forget_pin(tid)
    opts, _env = pam._ssh_auth(t, tempfile.mkdtemp())
    check("an unpinned one runs it with accept-new",
          "StrictHostKeyChecking=accept-new" in " ".join(opts))

    # an inventory host's command line
    g = {"name": "g", "ssh_user": "root", "hosts": [
        {"name": "h1", "address": "10.0.0.20", "port": 22}]}
    argv = ansible.host_shell_argv(g, "h1", "/k", "/kh", strict=True)
    check("an inventory host under a pin is strict too",
          "StrictHostKeyChecking=yes" in argv, str(argv))
    argv = ansible.host_shell_argv(g, "h1", "/k", "/kh")
    check("and accept-new without one",
          "StrictHostKeyChecking=accept-new" in argv)
    g["host_key_checking"] = False
    argv = ansible.host_shell_argv(g, "h1", "/k", "/kh", strict=True)
    check("a group that switched checking off keeps it off, pinned or not",
          "StrictHostKeyChecking=no" in argv)


def _write(text: str) -> str:
    path = os.path.join(tempfile.mkdtemp(), "known_hosts")
    open(path, "w").write(text)
    return path


def lifecycle() -> None:
    print("a session is on the record from its first second")
    rec = pam.start_recording("op@t", "1.2.3.4", protocol="ssh",
                              target_id="pt-life", target_name="life",
                              address="10.0.0.5", rec_kind="asciinema")
    row = pam.session(rec.id) or {}
    check("the row is written when the session OPENS, as running",
          row.get("status") == "running" and row.get("owner") == pam.OWNER
          and bool(row.get("rec_rel")), str(row)[:200])
    check("a running session is not in anybody's way on the sessions page",
          any(r["id"] == rec.id for r in pam.sessions()))
    rec.output("hello from the host\r\n")
    rec.commands_typed(["uptime"])
    rec.finish("closed")
    row = pam.session(rec.id) or {}
    check("finish() completes that same row",
          row.get("status") == "closed" and row.get("cmd_count") == 1
          and row.get("sha256") and row.get("commands") == "uptime",
          str(row)[:200])
    check("and there is exactly one row for it",
          db.q("SELECT COUNT(*) AS n FROM pam_sessions WHERE id = ?",
               (rec.id,))[0]["n"] == 1)

    print("a process that dies mid-session leaves the session interrupted")
    dead = pam.start_recording("op@t", "1.2.3.4", target_id="pt-dead",
                               target_name="dead", rec_kind="asciinema")
    dead.output("the last thing before the crash\r\n")
    with db.tx() as c:                    # as if an earlier process wrote it
        c.execute("UPDATE pam_sessions SET owner = ? WHERE id = ?",
                  (f"{__import__('socket').gethostname()}#earlierboot", dead.id))
    far = pam.start_recording("op@t", "1.2.3.4", target_id="pt-far",
                              target_name="far", rec_kind="asciinema")
    with db.tx() as c:                    # another replica, still beating
        c.execute("UPDATE pam_sessions SET owner = 'other-pod#b', beat = ? "
                  "WHERE id = ?", (pam._now(), far.id))
    quiet = pam.start_recording("op@t", "1.2.3.4", target_id="pt-quiet",
                                target_name="quiet", rec_kind="asciinema")
    with db.tx() as c:                    # another replica, gone quiet
        c.execute("UPDATE pam_sessions SET owner = 'other-pod#c', beat = "
                  "'2000-01-01T00:00:00+00:00' WHERE id = ?", (quiet.id,))
    mine = pam.start_recording("op@t", "1.2.3.4", target_id="pt-mine",
                               target_name="mine", rec_kind="asciinema")
    pam.register_active(mine.id, {"target_id": "pt-mine"}, lambda: None)
    with db.tx() as c:
        c.execute("UPDATE pam_sessions SET beat = '2000-01-01T00:00:00+00:00' "
                  "WHERE id = ?", (mine.id,))
    n = pam.recover_interrupted()
    st = {r: (pam.session(r) or {}).get("status")
          for r in (dead.id, far.id, quiet.id, mine.id)}
    check("a previous process's session is filed as interrupted",
          st[dead.id] == "interrupted", str(st))
    check("with its recording indexed and checksummed",
          bool((pam.session(dead.id) or {}).get("sha256"))
          and pam.session_integrity(dead.id)["state"] == "verified")
    check("a replica that is still beating keeps its session",
          st[far.id] == "running")
    check("a replica that went quiet loses its session to the record",
          st[quiet.id] == "interrupted")
    check("a session this process is serving is never touched",
          st[mine.id] == "running")
    check(f"and the count says so ({n})", n == 2)
    pam.drop_active(mine.id)
    mine.finish("closed")


def settle() -> None:
    print("a recording is checksummed once guacd has finished writing it")
    path = pathlib.Path(tempfile.mkdtemp()) / "rec"
    path.write_bytes(b"x" * 100)

    def keep_writing():
        for _ in range(8):
            time.sleep(0.2)
            with open(path, "ab") as fh:
                fh.write(b"y" * 50)

    th = threading.Thread(target=keep_writing)
    th.start()
    t0 = time.monotonic()
    pam._settle(path, quiet=0.6, most=10)
    waited = time.monotonic() - t0
    th.join()
    check(f"_settle waits for a growing file to stop ({waited:.1f}s)",
          path.stat().st_size == 500 and waited >= 1.5)
    t0 = time.monotonic()
    pam._settle(pathlib.Path("/nonexistent/rec"), quiet=0.3, most=1)
    check("and gives up on a file that never appears",
          time.monotonic() - t0 <= 1.5)


def retention() -> None:
    print("retention and clear see every session, and never a live one")
    import datetime as dt
    old = (dt.datetime.now(dt.UTC) - dt.timedelta(days=400)).isoformat(
        timespec="seconds")
    with db.tx() as c:
        for i in range(1105):
            c.execute("INSERT INTO pam_sessions (id, target_id, who, started, "
                      "status, rec_rel, rec_kind) VALUES (?,?,?,?,?,?,?)",
                      (f"ps-bulk{i:05d}", "pt-bulk", "bulk@t",
                       old if i < 5 else pam._now(), "closed",
                       f"pam-sessions/bulk{i}.cast", "asciinema"))
        c.execute("INSERT INTO pam_sessions (id, target_id, who, started, "
                  "status, rec_rel, rec_kind) VALUES (?,?,?,?,?,?,?)",
                  ("ps-bulklive", "pt-bulk", "bulk@t", old, "running",
                   "pam-sessions/live.cast", "asciinema"))
    pam.save_config(keep_days=30)
    got = pam.trim_recordings()
    check(f"the OLDEST recordings are trimmed even past the first 1,000 "
          f"({got['by_age']})", got["by_age"] == 5)
    check("a live session's recording is never trimmed",
          (pam.session("ps-bulklive") or {}).get("rec_rel") != "")
    pam.save_config(keep_days=0)
    n = pam.clear_sessions(who="bulk@t")
    check(f"clear removes every match, not the newest 1,000 ({n})", n == 1105)
    check("and leaves the live one alone",
          (pam.session("ps-bulklive") or {}).get("status") == "running")


def guac() -> None:
    print("guacd framing, input, clipboard")
    check("a length is counted in code points, as guacd counts it",
          pam.guac_instr("5.x", "op\U0001F600") == "3.5.x,3.op\U0001F600;"
          .encode("utf-8"))
    check("an acknowledged frame is not a person",
          not pam.guac_has_input("4.sync,13.1700000000000;"))
    check("a mouse or a key is",
          pam.guac_has_input("5.mouse,3.100,3.200,1.0;")
          and pam.guac_has_input("3.key,5.65307,1.1;"))
    t = pam.save_target("", {"name": "clip", "protocol": "vnc",
                             "address": "10.0.0.30", "auth_kind": "none",
                             "clipboard": "paste-only"}, "t")
    _p, params = pam.guac_params(pam._target_raw(t))
    check("a target's clipboard rule reaches guacd",
          params.get("disable-copy") == "true"
          and "disable-paste" not in params, str(params))
    pam.save_config(clipboard="off")
    t2 = pam.save_target("", {"name": "clip2", "protocol": "rdp",
                              "address": "10.0.0.31", "auth_kind": "none"}, "t")
    _p, params = pam.guac_params(pam._target_raw(t2))
    check("with no rule of its own a target follows the installation",
          params.get("disable-copy") == "true"
          and params.get("disable-paste") == "true", str(params))
    pam.save_config(clipboard="nonsense")
    check("an unknown installation rule reads as the default",
          pam.config()["clipboard"] == "both")
    t3 = pam.save_target("", {"name": "rdpsec", "protocol": "rdp",
                              "address": "10.0.0.32", "auth_kind": "none",
                              "security": "rdp; drop"}, "t")
    check("an RDP security mode guacd does not know is not stored",
          json.loads(pam._target_raw(t3)["extra"])["security"] == "any")


def seats() -> None:
    print("recorded-browser seats")
    cfg = dict(pam.config(), web_namespace="default")
    pol = webseat.egress_policy("pam-web-aaaaaaaa", cfg,
                                "https://app.example.com/", ["10.0.0.40"])
    check("a seat admits nothing inbound",
          pol["spec"]["policyTypes"] == ["Ingress", "Egress"]
          and not pol["spec"].get("ingress"))
    idle = webseat.idle_policy("pam-web-bbbbbbbb", cfg)
    check("and neither does a spare waiting for somebody",
          idle["spec"]["policyTypes"] == ["Ingress", "Egress"]
          and not idle["spec"].get("ingress"))


def evidence() -> None:
    print("an audit write is never lost in silence")

    def actor(action):
        rows = db.q("SELECT user FROM audit WHERE action = ?", (action,))
        return rows[-1]["user"] if rows else None

    auth.audit({"email": "dict@example.test"}, "hard_audit_dict", "t")
    check("an account dict records its email",
          actor("hard_audit_dict") == "dict@example.test")
    # The shape the live-session socket used: `me.get("email")`, a string.
    auth.audit("str@example.test", "hard_audit_str", "t")
    check("an email string records too (watch/take-over used to vanish)",
          actor("hard_audit_str") == "str@example.test",
          str(actor("hard_audit_str")))

    seen = []

    class Grab(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    h = Grab()
    logging.getLogger("uvicorn.error").addHandler(h)
    real = auth._append_audit

    def boom(*a, **k):
        raise RuntimeError("disk full")
    auth._append_audit = boom
    try:
        auth.audit({"email": "x@example.test"}, "hard_audit_fails", "t")
        raised = False
    except Exception:                                           # noqa: BLE001
        raised = True
    finally:
        auth._append_audit = real
        logging.getLogger("uvicorn.error").removeHandler(h)
    check("a failed write still never breaks the action it records",
          not raised)
    check("but it is logged, naming the action that went unrecorded",
          any("hard_audit_fails" in m for m in seen), str(seen))


def gateway() -> None:
    print("the one-click gateway is the one RDP can use")
    sent = {}
    saved = (selfupdate.enabled, selfupdate._deployment, selfupdate._api,
             selfupdate.namespace, env.SELF_DEPLOYMENT)

    def api(path, method="GET", body=None, ctype=""):
        sent.update(path=path, method=method, body=json.loads(body or b"{}"))
        return {}
    try:
        selfupdate.enabled = lambda: True
        selfupdate.namespace = lambda: "ns"
        env.SELF_DEPLOYMENT = "rel-config-portal"
        selfupdate._deployment = lambda fresh=False, **kw: {"spec": {"template": {
            "spec": {"containers": [{"name": "portal", "volumeMounts": [
                {"name": "data", "mountPath": "/data"}]}]}}}}
        selfupdate._api = api
        selfupdate.add_gateway("guacamole/guacd:1.5.5")
    finally:
        (selfupdate.enabled, selfupdate._deployment, selfupdate._api,
         selfupdate.namespace, env.SELF_DEPLOYMENT) = saved
    spec = sent.get("body", {}).get("spec", {}).get("template", {}).get("spec", {})
    gw = next((c for c in spec.get("containers", []) if c["name"] == "guacd"), {})
    home = next((e["value"] for e in gw.get("env", []) if e["name"] == "HOME"), "")
    mounted = {m["mountPath"]: m["name"] for m in gw.get("volumeMounts", [])}
    vols = {v["name"]: v for v in spec.get("volumes", [])}
    check("the patch gives guacd a HOME", bool(home), str(gw.get("env")))
    check("mounted from a volume the SAME patch adds -- a mount naming a "
          "volume the pod lacks is a pod that will not start",
          home in mounted and "emptyDir" in vols.get(mounted[home], {}),
          f"mounts={mounted} volumes={list(vols)}")


def _mark() -> int:
    return int(db.q("SELECT COALESCE(MAX(id), 0) AS n FROM audit")[0]["n"])


def _audits(since: int, action: str) -> list:
    return [dict(r) for r in db.q("SELECT * FROM audit WHERE id > ? AND "
                                  "action = ? ORDER BY id", (since, action))]


def spelling() -> None:
    print("a pin belongs to the target, however its address is spelled")
    tid = pam.save_target("", {"name": "spell", "protocol": "ssh",
                               "address": "db01.example.com", "port": "22",
                               "auth_kind": "none"}, "t")
    pam.pin_after(tid, "db01.example.com", 22,
                  _write(f"db01.example.com ssh-ed25519 {KEY}\n"), who="t")
    # ssh lower-cases the name and keeps a trailing dot (`ssh -G`), and looks
    # the connection up under exactly that -- so the pin must be written so.
    lines, strict = pam.pin_state(tid, "DB01.Example.COM.", 22)
    check("case and a trailing dot are the same machine, still pinned",
          strict and lines == f"db01.example.com. ssh-ed25519 {KEY}\n", lines)
    check("and a different port is not", pam.pin_state(tid, "db01.example.com",
                                                     2222)[1] is False)
    t2 = pam.save_target("", {"name": "spell2", "protocol": "ssh",
                              "address": "db02.example.com", "port": "2222",
                              "auth_kind": "none"}, "t")
    pam.pin_after(t2, "db02.example.com", 2222,
                  _write(f"[db02.example.com]:2222 ssh-ed25519 {KEY}\n"), who="t")
    lines, strict = pam.pin_state(t2, "DB02.example.com", 2222)
    check("a port that is not 22 is bracketed, the way ssh looks it up",
          strict and lines == f"[db02.example.com]:2222 ssh-ed25519 {KEY}\n",
          lines)
    got = pam.pin_after(tid, "10.0.0.77", 22,
                        _write(f"10.0.0.77 ssh-ed25519 {KEY}\n"), who="t")
    check("a pin replaced because the address changed says what it replaced",
          bool(got) and (got.get("replaced") or {}).get("host")
          == "db01.example.com", str(got))


def transfer() -> None:
    print("file transfer carries the pin, first")
    keep = pam._ensure_master
    pam._ensure_master = lambda *a, **k: None
    try:
        tid = pam.save_target("", {"name": "xfer", "protocol": "ssh",
                                   "address": "10.0.0.50", "port": "22",
                                   "username": "ops", "auth_kind": "none"}, "t")
        pam.pin_after(tid, "10.0.0.50", 22,
                      _write(f"10.0.0.50 ssh-ed25519 {KEY}\n"), who="t")
        priv, _pub = ansible.new_keypair()
        gid = ansible.save_group("", {"name": "xfer-g", "ssh_user": "ops",
                                      "key": priv}, "t")
        ansible.add_host(gid, "xfer-h", "10.0.0.51", "t", ssh_port=22)
        itid = next(t["id"] for t in pam.targets()
                    if t.get("source") == "ansible" and t["name"] == "xfer-h")
        pam.pin_after(itid, "10.0.0.51", 22,
                      _write(f"10.0.0.51 ssh-ed25519 {KEY}\n"), who="t")
        for label, target in (("a native target", tid),
                              ("an inventory host", itid)):
            argv, _env = pam._sftp_argv(target, tempfile.mkdtemp())
            # ssh keeps the FIRST value of an option; a stable file in front
            # of the pin made every transfer that connected on its own fail.
            first = next((a.split("=", 1)[1] for a in argv
                          if a.startswith("UserKnownHostsFile=")), "")
            held = (pathlib.Path(first).read_text()
                    if first and os.path.isfile(first) else "")
            check(f"{label}: the first known_hosts sftp reads holds the pin",
                  KEY in held, str(argv))
            check(f"{label}: and the transfer is strict",
                  "StrictHostKeyChecking=yes" in argv)
    finally:
        pam._ensure_master = keep


def opening() -> None:
    print("a session still opening is not an abandoned one")
    building = pam.start_recording("op@t", "1.2.3.4", target_id="pt-build",
                                   target_name="build", rec_kind="asciinema")
    # Written at the start, live only once its seat is built: a cold browser
    # takes minutes, longer than BEAT_STALE.
    with db.tx() as c:
        c.execute("UPDATE pam_sessions SET beat = '2000-01-01T00:00:00+00:00' "
                  "WHERE id = ?", (building.id,))
    pam.recover_interrupted()
    check("this process's own row, not yet live and long unbeaten, is left "
          "running", (pam.session(building.id) or {}).get("status") == "running")
    pam._beat_once()
    check("and the heartbeat reaches it, by owner rather than by the live list",
          ((pam.session(building.id) or {}).get("beat") or "") > "2001")
    check("a running session cannot be deleted from under its recorder",
          not pam.delete_session(building.id)
          and (pam.session(building.id) or {}).get("status") == "running")
    building.finish("closed")
    check("once it has ended, it can", pam.delete_session(building.id))


def gate() -> None:
    print("input waits for the first frame")
    check("a frame's end is a PARSED sync, not the bytes of one",
          pam.guac_drew("4.sync,13.1700000000000;")
          and not pam.guac_drew("4.name,7.4.sync,;")
          and not pam.guac_drew("3.img,1.1;"))
    check("before it, input is held back and the rest passes",
          pam.guac_before_display("5.mouse,3.100,3.200,1.0;"
                                  "4.sync,13.1700000000000;3.key,5.65307,1.1;")
          == "4.sync,13.1700000000000;")
    check("and a message that was only input becomes nothing",
          pam.guac_before_display("5.mouse,3.100,3.200,1.0;") == "")


def relays() -> None:
    print("the relays: endings, messages, refusals")
    import subprocess

    import anyio
    from starlette.websockets import WebSocketDisconnect

    from app import main
    seen = []

    class Grab(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    h = Grab()
    logging.getLogger("uvicorn.error").addHandler(h)
    try:
        main._relay_ended(ExceptionGroup("g", [WebSocketDisconnect(1000),
                                               anyio.EndOfStream()]))
        main._relay_ended(RuntimeError("closed"))
        quiet = len(seen)
        main._relay_ended(ExceptionGroup("g", [WebSocketDisconnect(1000),
                                               ValueError("boom")]))
        main._relay_ended(ValueError("bare"))
    finally:
        logging.getLogger("uvicorn.error").removeHandler(h)
    check("an ordinary ending, wrapped or bare, logs nothing", quiet == 0,
          str(seen))
    check("anything else is logged once each", len(seen) == 2, str(seen))

    junk = ('{"r": "x"}', '{"r": [1]}', "[]", "5", '{"i": 7}', "not json",
            '{"i": ""}', '{"r": {"a": 1}}')
    check("a malformed terminal message is dropped, never raised",
          all(main._pty_msg(m) is None for m in junk))
    check("a resize is clamped to a terminal that can exist",
          main._pty_msg('{"r": [0, 99999]}') == ("resize", (2, 1000)))
    check("and keys are keys", main._pty_msg('{"i": "ls"}') == ("keys", "ls"))

    class Proc:
        def __init__(self, code):
            self.code = code

        def wait(self, timeout=None):
            if self.code is None:
                raise subprocess.TimeoutExpired("ssh", timeout)
            return self.code

    class Term:
        def __init__(self, strict, code):
            self.strict, self.proc = strict, Proc(code)
            self.hostkey = ("pt-watch", "10.0.0.9", 2222, "/nonexistent")

    refusal = ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
               "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
               "Host key verification failed.\r\n")

    def verdict(strict, code, text):
        w = main._HostKeyWatch(Term(strict, code), None, "w", "")
        w.saw(text)
        return w._refused()

    check("a refusal is ssh's words first, under a pin, and exit 255",
          verdict(True, 255, refusal))
    check("not without a pin -- nothing else makes ssh refuse a key",
          not verdict(False, 255, refusal))
    check("not when ssh exited any other way",
          not verdict(True, 0, refusal) and not verdict(True, None, refusal))
    check("and not when the words came from the far end",
          not verdict(True, 255, "ops@bastion:~$ ssh db2\r\n" + refusal))


def routes() -> None:
    print("through the routes")
    from fastapi.testclient import TestClient

    from app import main, rbac

    def enrol(email, pw, role):
        uid = auth.create_user(email, "N", pw, role=role)
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
               "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
        return uid

    def signed_in(email, pw):
        c = TestClient(main.app)
        c.__enter__()
        c.post("/login", data={"email": email, "password": pw},
               follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
        return c

    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    tid = pam.save_target("", {"name": "route pin", "protocol": "ssh",
                               "address": "10.0.0.60", "port": "22",
                               "auth_kind": "none"}, "t")
    pam.pin_after(tid, "10.0.0.60", 22,
                  _write(f"10.0.0.60 ssh-ed25519 {KEY}\n"), who="t")
    enrol("hard-boss@t.local", "Boss-Hardening-Pass-42", "admin")
    uid = enrol("hard-op@t.local", "Scoped-Operator-Pass-42", "viewer")
    rid = rbac.save("", "hard scoped", "", ["pam", "pam_connect"], [], [],
                    [tid])
    rbac.set_for_user(uid, [rid])
    boss = signed_in("hard-boss@t.local", "Boss-Hardening-Pass-42")
    op = signed_in("hard-op@t.local", "Scoped-Operator-Pass-42")

    since = _mark()
    r = op.post("/pam/target/hostkey/forget", data={"tid": tid},
                follow_redirects=False)
    check("somebody who may only use a target cannot re-trust its key",
          r.status_code == 303 and "err=" in r.headers.get("location", "")
          and pam.host_pin(tid) is not None and not _audits(
              since, "pam_hostkey_forgotten"))
    boss.post("/pam/target/hostkey/forget", data={"tid": tid},
              follow_redirects=False)
    check("the whole of Privileged Access can, audited with the key it forgot",
          pam.host_pin(tid) is None and any(
              FP in (a.get("detail") or "")
              for a in _audits(since, "pam_hostkey_forgotten")))

    rec = pam.start_recording("hard-boss@t.local", "1.2.3.4", protocol="ssh",
                              target_id=tid, target_name="route pin",
                              address="10.0.0.60", rec_kind="asciinema")
    rec.output("hello\r\n")
    rec.finish("closed")
    since = _mark()
    boss.get(f"/pam/sessions/{rec.id}/recording")
    boss.get(f"/pam/sessions/{rec.id}/recording?export=1")
    check("the player's fetch is a replay; the download link is an export",
          len(_audits(since, "pam_session_replayed")) == 1
          and len(_audits(since, "pam_session_export")) == 1)
    page = boss.get(f"/pam/sessions/{rec.id}").text
    check("and the download link stays out of the hover prefetch",
          '/recording?export=1" data-nopf' in page)

    live = pam.start_recording("hard-boss@t.local", "1.2.3.4", protocol="ssh",
                               target_id=tid, target_name="route pin",
                               address="10.0.0.60", rec_kind="asciinema")
    r = boss.post("/pam/session/delete", data={"sid": live.id},
                  follow_redirects=False)
    check("a running session cannot be deleted through the page either",
          (pam.session(live.id) or {}).get("status") == "running"
          and "still running" in urllib.parse.unquote(
              r.headers.get("location", "")))
    listing = boss.get("/pam?sec=sessions").text
    check("the list says it is recording, with replay and delete disabled",
          "recording now" in listing
          and 'title="still recording — the replay is ready once the session '
          'ends">replay' in listing
          and 'title="still recording — a session can be deleted once it has '
          'ended">delete' in listing)
    live.finish("closed")

    form = boss.get("/pam/targets/new").text
    check("the form's RDP security choices are the ones the server stores",
          all(f'<option value="{s}"' in form for s in pam.RDP_SECURITY))
    check("and its clipboard protocols come from the server",
          f'data-protocols="{" ".join(pam.CLIPBOARD_PROTOCOLS)}"' in form)

    # REACHABLE IS NOT WORKING: an outdated sidecar answers, so the settings
    # page must ask the Deployment even then, and offer the repair.
    keep = (pam._guacd_answers, selfupdate.gateway_state, selfupdate.enabled)
    try:
        pam._guacd_answers = lambda cfg: True
        selfupdate.gateway_state = lambda: {"how": "outdated",
                                            "why": "the gateway is outdated"}
        selfupdate.enabled = lambda: True
        page = boss.get("/settings/pam").text
    finally:
        pam._guacd_answers, selfupdate.gateway_state, selfupdate.enabled = keep
    check("a reachable but outdated gateway is reported, with its repair",
          "reachable" in page and "the gateway is outdated." in page
          and 'id="gwRepair"' in page
          and 'formaction="/settings/pam/gateway/start"' in page)


def outdated() -> None:
    print("a gateway without its home is outdated, and repaired in place")
    old = {"name": "guacd", "image": "mirror.example/guacd:1.5.5",
           "volumeMounts": [{"name": "data", "mountPath": "/data"}]}
    dep = {"spec": {"template": {"spec": {"containers": [
        {"name": "portal", "volumeMounts": [{"name": "data",
                                             "mountPath": "/data"}]}, old]}}}}
    sent = {}

    def api(path, method="GET", body=None, ctype=""):
        sent.update(body=json.loads(body or b"{}"))
        return {}
    saved = (selfupdate.in_cluster, selfupdate._deployment, selfupdate._api,
             selfupdate.enabled, selfupdate.namespace, env.SELF_DEPLOYMENT)
    try:
        selfupdate.in_cluster = lambda: True
        selfupdate._deployment = lambda fresh=False, **kw: dep
        state = selfupdate.gateway_state()
        selfupdate.enabled = lambda: True
        selfupdate.namespace = lambda: "ns"
        env.SELF_DEPLOYMENT = "rel-config-portal"
        selfupdate._api = api
        try:
            got = selfupdate.add_gateway("guacamole/guacd:1.5.5")
        except selfupdate.UpdateError as e:
            got = {"refused": str(e)}
    finally:
        (selfupdate.in_cluster, selfupdate._deployment, selfupdate._api,
         selfupdate.enabled, selfupdate.namespace, env.SELF_DEPLOYMENT) = saved
    check("present and answering is not working: it reads OUTDATED",
          state.get("how") == "outdated", str(state))
    spec = sent.get("body", {}).get("spec", {}).get("template", {}).get("spec", {})
    gw = (spec.get("containers") or [{}])[0]
    check("the button repairs it, keeping the image the container runs",
          got.get("repaired") and gw.get("image") == "mirror.example/guacd:1.5.5"
          and selfupdate.gateway_current(gw), f"{got} {str(gw)[:160]}")


if __name__ == "__main__":
    pinning()
    lifecycle()
    settle()
    retention()
    guac()
    seats()
    evidence()
    gateway()
    spelling()
    transfer()
    opening()
    gate()
    relays()
    routes()
    outdated()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
