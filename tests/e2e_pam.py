"""Privileged Access, end to end, against REAL servers.

WHY THIS IS NOT PART OF THE SUITE
    Everything else under tests/ runs on any laptop. This needs an SSH server,
    a VNC desktop, an RDP desktop and guacd, so it is named e2e_* rather than
    test_* and the suite's glob never picks it up. `scripts/pam-e2e.sh` starts
    all four in Docker and runs this against them; point the PAM_E2E_*
    variables elsewhere to run it against your own.

A RECORDED WEB SESSION needs a real cluster as well, so it runs only when
    PAM_E2E_WEB_KUBECONFIG, PAM_E2E_WEB_CONTEXT and PAM_E2E_WEB_NAMESPACE name
    one (an existing namespace it may create pods in), and
    PAM_E2E_WEB_SEAT_HOST says how guacd reaches THIS machine -- from Docker
    Desktop, host.docker.internal. It opens one seat, inspects the pod, its
    policy and the forwards while the session is live, and checks that
    nothing is left behind.

WHAT IT PROVES THAT THE UNIT TESTS CANNOT
    test_pam.py pins the portal's own logic against fakes. Every serious PAM
    bug so far lived in the gap between the portal and a real binary: ssh
    copying a raw tty's modes to the remote end, sftp spelling the port
    differently, a textarea posting CRLF, guacd's receive timeout, a
    NetworkPolicy that only confined one direction. So this drives the real
    thing through the real server: a uvicorn process, real websockets carrying
    a session cookie, the ssh and sftp binaries, guacd, and x11vnc/xrdp on the
    far side.

HOW TO READ A FAILURE
    Each check prints the evidence it looked at. The portal's own log is kept
    at the end of the data directory it prints, and the last check reads it
    for tracebacks, because a session that works while the server logs an
    exception on every disconnect is not working.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E = os.environ.get
DATA = E("PAM_E2E_DATA") or tempfile.mkdtemp(prefix="pam-e2e-")
os.makedirs(DATA, exist_ok=True)
os.environ.update(PORTAL_DATA_DIR=DATA, PORTAL_PAM="1")
sys.path.insert(0, ROOT)

import httpx  # noqa: E402
from websockets.asyncio.client import connect  # noqa: E402
from websockets.exceptions import ConnectionClosed  # noqa: E402

# The whole app, so every module has registered its tables and run its
# migrations exactly as the server does -- seeding against a half-migrated
# database is how a harness tests a schema nobody ships.
from app import main as _app  # noqa: E402,F401
from app import ansible, auth, db, pam, rbac, store  # noqa: E402

SSH_HOST = E("PAM_E2E_SSH_HOST", "127.0.0.1")
SSH_PORT = int(E("PAM_E2E_SSH_PORT", "2222"))
SSH_USER = E("PAM_E2E_SSH_USER", "pamuser")
SSH_KEY = E("PAM_E2E_SSH_KEY", "")
SSH_PASSWORD = E("PAM_E2E_SSH_PASSWORD", "")
SSH_ROTATE = E("PAM_E2E_SSH_ROTATE", "")      # gives the server a NEW host key
GUACD = E("PAM_E2E_GUACD", "127.0.0.1:4822")
VNC = E("PAM_E2E_VNC", "")                    # host:port as guacd sees it
VNC_PASSWORD = E("PAM_E2E_VNC_PASSWORD", "")
RDP = E("PAM_E2E_RDP", "")
RDP_USER = E("PAM_E2E_RDP_USER", "")
RDP_PASSWORD = E("PAM_E2E_RDP_PASSWORD", "")
WEB_KUBECONFIG = E("PAM_E2E_WEB_KUBECONFIG", "")
WEB_CONTEXT = E("PAM_E2E_WEB_CONTEXT", "")
WEB_NAMESPACE = E("PAM_E2E_WEB_NAMESPACE", "")
WEB_URL = E("PAM_E2E_WEB_URL", "https://example.com/")
WEB_SEAT_HOST = E("PAM_E2E_WEB_SEAT_HOST", "")
WEB_PROBE_IMAGE = E("PAM_E2E_WEB_PROBE_IMAGE", "busybox:1.36")
ONLY = {s for s in (E("PAM_E2E_ONLY") or "").split(",") if s}

bad = 0
results: list = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    global bad
    results.append((name, bool(ok)))
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + name
          + (f"\n          {detail}" if detail and not ok else ""))
    return bool(ok)


def section(name: str) -> bool:
    # By PREFIX, because several section names carry commas of their own.
    if ONLY and not any(name.startswith(o) for o in ONLY):
        return False
    print(f"\n{name}")
    return True


# ── the portal, as a real process ────────────────────────────────
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = int(E("PAM_E2E_PORT") or _free_port())
BASE = f"http://127.0.0.1:{PORT}"
WSBASE = f"ws://127.0.0.1:{PORT}"
LOG = os.path.join(DATA, "portal.log")
proc: subprocess.Popen | None = None


def start_portal() -> None:
    global proc
    py = os.path.join(ROOT, ".venv", "bin", "python")
    with open(LOG, "a") as log:
        proc = subprocess.Popen(
            [py, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(PORT), "--ws-ping-interval", "30",
             "--ws-ping-timeout", "300"],
            cwd=ROOT, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            if httpx.get(BASE + "/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise SystemExit(f"the portal did not start; see {LOG}")


def stop_portal(hard: bool = False) -> None:
    global proc
    if proc and proc.poll() is None:
        if hard:
            proc.send_signal(signal.SIGKILL)
        else:
            proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
    proc = None


# ── people ───────────────────────────────────────────────────────
def enrol(email: str, pw: str, role: str) -> tuple[str, str]:
    uid = auth.create_user(email, email.split("@")[0], pw, role=role)
    secret = auth.new_totp_secret()
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", (secret, uid))
    return uid, secret


def login(email: str, pw: str, secret: str) -> httpx.Client:
    # Browser-shaped: every request says it came from this origin, as a
    # browser's own navigation and fetches do.
    c = httpx.Client(base_url=BASE, follow_redirects=False, timeout=60,
                     headers={"Origin": BASE, "Sec-Fetch-Site": "same-origin"})
    c.post("/login", data={"email": email, "password": pw})
    code = auth._totp_at(secret, int(time.time() // auth.TOTP_STEP))
    r = c.post("/mfa", data={"code": code})
    if r.status_code not in (302, 303) or "portal_session" not in c.cookies:
        raise SystemExit(f"could not sign in as {email}: {r.status_code}")
    return c


def cookie_header(c: httpx.Client) -> str:
    return "; ".join(f"{k}={v}" for k, v in c.cookies.items())


# ── a terminal, driven the way the page drives it ────────────────
class Term:
    """One /pam/ssh.ws session: send keys, wait for text, see how it ended."""

    def __init__(self, ws):
        self.ws, self.text, self.closed = ws, "", None

    @classmethod
    async def open(cls, c: httpx.Client, tid: str, origin: str = BASE,
                   **q) -> "Term":
        qs = urllib.parse.urlencode({"tid": tid, "rows": 30, "cols": 100, **q})
        ws = await connect(f"{WSBASE}/pam/ssh.ws?{qs}", max_size=None,
                           additional_headers={"Cookie": cookie_header(c),
                                               "Origin": origin},
                           open_timeout=30)
        return cls(ws)

    async def until(self, needle: str, timeout: float = 25) -> bool:
        end = time.monotonic() + timeout
        while needle not in self.text:
            left = end - time.monotonic()
            if left <= 0 or self.closed:
                return needle in self.text
            try:
                self.text += await asyncio.wait_for(self.ws.recv(), left)
            except (asyncio.TimeoutError, TimeoutError):
                return needle in self.text
            except ConnectionClosed as e:
                self.closed = e
                return needle in self.text
        return True

    async def drain(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.closed and time.monotonic() < end:
            try:
                self.text += await asyncio.wait_for(
                    self.ws.recv(), end - time.monotonic())
            except (asyncio.TimeoutError, TimeoutError):
                return
            except ConnectionClosed as e:
                self.closed = e

    async def keys(self, s: str) -> None:
        # Sending into a socket the server has already ended is part of the
        # behaviour under test (a session closed by policy), not a harness
        # crash -- note it and carry on reading.
        if self.closed:
            return
        try:
            await self.ws.send(json.dumps({"i": s}))
        except ConnectionClosed as e:
            self.closed = e

    async def run(self, cmd: str, marker: str, timeout: float = 25) -> bool:
        await self.keys(cmd + "\r")
        return await self.until(marker, timeout)

    async def close(self) -> None:
        with _quiet():
            await self.ws.close()
        await self.drain(1)

    def close_code(self) -> int:
        e = self.closed
        rcvd = getattr(e, "rcvd", None) if e else None
        return getattr(rcvd, "code", 0) if rcvd else 0


class _quiet:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return True


def latest_session(tid: str) -> dict:
    rows = pam.sessions(target_id=tid)
    return rows[0] if rows else {}


def live_ids(c: httpx.Client) -> list:
    return re.findall(r'data-kill="(ps-[0-9a-f]{12})"',
                      c.get("/pam?sec=active").text)


def mark() -> int:
    return int(db.q("SELECT COALESCE(MAX(id), 0) AS n FROM audit")[0]["n"])


def audited(since: int, action: str = "") -> list:
    sql, args = "SELECT * FROM audit WHERE id > ?", [since]
    if action:
        sql += " AND action = ?"
        args.append(action)
    return [dict(r) for r in db.q(sql + " ORDER BY id", tuple(args))]


def cfg(**fields) -> None:
    pam.save_config(**fields)


# ── the estate this run works against ────────────────────────────
people: dict = {}
T: dict = {}


def seed() -> None:
    gh, gp = GUACD.rsplit(":", 1)
    cfg(enabled=True, allow_connect=True, record_sessions=True,
        guacd_host=gh, guacd_port=int(gp), require_reason="prod",
        idle_timeout=0, max_duration=0, max_concurrent=0)
    people["admin"] = ("boss@e2e.local", "Boss-Knows-Everything-42",
                       enrol("boss@e2e.local", "Boss-Knows-Everything-42",
                             "admin")[1])
    key = open(SSH_KEY).read() if SSH_KEY else ""
    if key:
        T["ssh_key"] = pam.save_target("", {
            "name": "e2e ssh key", "protocol": "ssh", "address": SSH_HOST,
            "port": str(SSH_PORT), "username": SSH_USER, "auth_kind": "key",
            "secret_key": key, "env": "dev"}, "e2e")
        T["ssh_prod"] = pam.save_target("", {
            "name": "e2e ssh prod", "protocol": "ssh", "address": SSH_HOST,
            "port": str(SSH_PORT), "username": SSH_USER, "auth_kind": "key",
            "secret_key": key, "env": "production"}, "e2e")
        # An Ansible inventory host: the second front door to the same
        # credential path, and the one host-key pinning must also cover.
        gid = ansible.save_group("", {"name": "e2e-group", "ssh_user": SSH_USER,
                                      "key": key}, "e2e")
        ansible.add_host(gid, "e2e-inv-host", SSH_HOST, "e2e",
                         ssh_port=SSH_PORT)
        T["ssh_inv"] = next(t["id"] for t in pam.targets()
                            if t.get("source") == "ansible"
                            and t["name"] == "e2e-inv-host")
    if SSH_PASSWORD:
        T["ssh_pw"] = pam.save_target("", {
            "name": "e2e ssh password", "protocol": "ssh", "address": SSH_HOST,
            "port": str(SSH_PORT), "username": SSH_USER,
            "auth_kind": "password", "secret": SSH_PASSWORD}, "e2e")
    if VNC:
        vh, vp = VNC.rsplit(":", 1)
        T["vnc"] = pam.save_target("", {
            "name": "e2e vnc", "protocol": "vnc", "address": vh, "port": vp,
            "auth_kind": "password", "secret": VNC_PASSWORD}, "e2e")
        # A name OUTSIDE the Basic Multilingual Plane rides in a guacd
        # parameter. VNC ignores the username, so the only thing this can
        # break is the framing -- which is exactly what it is here to test.
        T["vnc_astral"] = pam.save_target("", {
            "name": "e2e vnc astral", "protocol": "vnc", "address": vh,
            "port": vp, "username": "op\U0001F600", "auth_kind": "password",
            "secret": VNC_PASSWORD}, "e2e")
    if RDP:
        rh, rp = RDP.rsplit(":", 1)
        T["rdp"] = pam.save_target("", {
            "name": "e2e rdp", "protocol": "rdp", "address": rh, "port": rp,
            "username": RDP_USER, "auth_kind": "password",
            "secret": RDP_PASSWORD, "security": "any",
            "ignore_cert": "1"}, "e2e")
    if WEB_KUBECONFIG and WEB_CONTEXT and WEB_NAMESPACE:
        pid = store.add_project("e2e web")
        cid = store.add_cluster(pid, "e2e seat cluster",
                                open(WEB_KUBECONFIG).read(), WEB_CONTEXT)
        store.update_cluster(pid, cid, manage="1")
        # No spares: a warm pool is a pod left running after the run.
        cfg(web_browser=True, web_cluster=cid, web_namespace=WEB_NAMESPACE,
            web_seat_host=WEB_SEAT_HOST, web_spares=0, web_ready_timeout=600)
        T["web"] = pam.save_target("", {
            "name": "e2e web", "protocol": "https",
            "address": urllib.parse.urlsplit(WEB_URL).hostname or "",
            "url": WEB_URL, "auth_kind": "none"}, "e2e")
    # A scoped operator: may connect, but only to the password target.
    rid = rbac.save("", "e2e scoped", "", ["pam", "pam_connect"], [], [],
                    [T.get("ssh_pw") or T.get("ssh_key", "")])
    uid, sec = enrol("scoped@e2e.local", "Only-One-Machine-42", "viewer")
    rbac.set_for_user(uid, [rid])
    people["scoped"] = ("scoped@e2e.local", "Only-One-Machine-42", sec)


# ── SSH ──────────────────────────────────────────────────────────
async def ssh_basic(c: httpx.Client) -> None:
    if not section("ssh: a key target, through the real socket"):
        return
    m = mark()
    t = await Term.open(c, T["ssh_key"])
    ok = await t.run("echo E2E_$((6*7))_OK", "E2E_42_OK")
    check("a key-authenticated session opens and runs a command", ok,
          t.text[-400:])
    ok = await t.run("printf 'line\\nbreaks\\n'", "breaks")
    check("the remote shell turns \\n into \\r\\n (no marching prompt)",
          "line\r\nbreaks" in t.text, repr(t.text[-200:]))
    await t.keys("exit\r")
    await t.drain(4)
    row = latest_session(T["ssh_key"])
    check("the session is filed, closed, as an asciinema recording",
          row.get("status") == "closed" and row.get("rec_kind") == "asciinema",
          str({k: row.get(k) for k in ("status", "rec_kind", "rec_rel")}))
    integ = pam.session_integrity(row.get("id", ""))
    check("its recording verifies against the checksum taken at filing",
          integ["state"] == "verified", str(integ))
    check("the typed command is in the command transcript",
          "echo E2E_$((6*7))_OK" in (pam.session(row.get("id", "")) or {})
          .get("commands", ""))
    cast = open(pam.session_rec_path(row["id"]), encoding="utf-8").read()
    check("the recording holds the command's OUTPUT", "E2E_42_OK" in cast)
    acts = [a["detail"] for a in audited(m, "pam_ssh")]
    check("opening and closing are audited",
          any("session opened" in d for d in acts)
          and any("session closed" in d for d in acts), str(acts[:4]))
    r = c.get(f"/pam/sessions/{row['id']}")
    check(f"the recording page renders ({r.status_code})",
          r.status_code == 200 and "verified" in r.text.lower())


async def ssh_password(c: httpx.Client) -> None:
    if "ssh_pw" not in T or not section("ssh: a password target (askpass)"):
        return
    t = await Term.open(c, T["ssh_pw"])
    ok = await t.run("echo PW_$((2+3))_OK", "PW_5_OK")
    check("a password-authenticated session opens without a prompt", ok,
          t.text[-400:])
    check("the password never appears on the terminal",
          SSH_PASSWORD not in t.text)
    await t.close()
    await asyncio.sleep(1)
    cast = open(pam.session_rec_path(latest_session(T["ssh_pw"])["id"]),
                encoding="utf-8").read()
    check("and never in the recording", SSH_PASSWORD not in cast)


async def ssh_gates(c: httpx.Client) -> None:
    if not section("ssh: production, reasons and limits"):
        return
    t = await Term.open(c, T["ssh_prod"])
    await t.until("__never__", 8)
    check("a production target refuses without its name typed",
          t.closed is not None and "production" in t.text, t.text[-300:])
    t = await Term.open(c, T["ssh_prod"], confirm="e2e ssh prod")
    await t.until("__never__", 8)
    check("and then refuses without a justification (reason = prod)",
          t.closed is not None and "ticket" in t.text, t.text[-300:])
    t = await Term.open(c, T["ssh_prod"], confirm="e2e ssh prod",
                        ticket="https://tickets.example.com/CHG-1",
                        stime="15 minutes", summary="e2e check")
    ok = await t.run("echo PROD_OK", "PROD_OK")
    check("with name and justification it opens", ok, t.text[-300:])
    await t.close()
    await asyncio.sleep(1)
    row = latest_session(T["ssh_prod"])
    check("the justification is stored on the session",
          row.get("ticket") == "https://tickets.example.com/CHG-1"
          and row.get("reason") == "e2e check"
          and row.get("session_time") == "15 minutes", str(row)[:300])

    cfg(max_concurrent=1)
    try:
        first = await Term.open(c, T["ssh_key"])
        await first.run("echo ONE", "ONE")
        second = await Term.open(c, T["ssh_key"])
        await second.until("__never__", 8)
        check("the concurrent-session cap refuses the second session",
              second.closed is not None and "concurrent" in second.text,
              second.text[-300:])
        await first.close()
    finally:
        cfg(max_concurrent=0)

    cfg(idle_timeout=8)
    try:
        t = await Term.open(c, T["ssh_key"])
        await t.run("echo IDLE_START", "IDLE_START")
        await t.until("__never__", 20)
        check("an idle session is closed by policy",
              t.closed is not None and "inactivity" in t.text,
              t.text[-300:])
    finally:
        cfg(idle_timeout=0)

    cfg(max_duration=8)
    try:
        t = await Term.open(c, T["ssh_key"])
        await t.run("echo LONG_START", "LONG_START")
        for _ in range(6):           # keep typing: this is duration, not idle
            await t.keys(" ")
            await t.until("__never__", 2.5)
        check("a session past the maximum duration is closed",
              t.closed is not None and "maximum duration" in t.text,
              t.text[-300:])
    finally:
        cfg(max_duration=0)


async def ssh_live(c: httpx.Client) -> None:
    if not section("ssh: live watch and kill"):
        return
    t = await Term.open(c, T["ssh_key"])
    await t.run("echo WATCH_ME_$((3*3))", "WATCH_ME_9")
    ids = live_ids(c)
    check("the live session is listed on the Active tab", len(ids) == 1,
          str(ids))
    sid = ids[0] if ids else ""
    got = c.get(f"/pam/session/{sid}/live.json", params={"frm": 0}).json()
    check("a supervisor can watch it while it runs (the cast tail)",
          got.get("live") and "WATCH_ME_9" in got.get("text", ""),
          str(got)[:300])
    # A multi-byte character must survive the tail's chunk boundaries: the
    # watcher resumes at `next`, and a character cut in half there is lost.
    # The marker is COMPUTED, like WATCH_ME_$((3*3)): a literal one is in the
    # echo of the typed command, which arrives before the output does.
    await t.run("printf '\\342\\202\\254%.0s' $(seq 1 3000); "
                "echo EUROS_$((2*3))_DONE", "EUROS_6_DONE", 30)
    frm, seen, end = 0, "", time.monotonic() + 15
    while "EUROS_6_DONE" not in seen and time.monotonic() < end:
        j = c.get(f"/pam/session/{sid}/live.json", params={"frm": frm}).json()
        seen += j.get("text", "")
        if j.get("next", frm) == frm:
            await asyncio.sleep(0.3)
        frm = j.get("next", frm)
    # The cast is JSON lines, so a euro sign arrives as its six-character
    # escape unless the writer keeps UTF-8 -- count both spellings.
    euros = seen.count("\\u20ac") + seen.count("€")
    check("the watch tail never loses a character at a chunk boundary",
          euros >= 3000, f"{euros} of 3000 euro signs arrived")
    m = mark()
    r = c.post(f"/pam/session/{sid}/kill")
    await t.until("__never__", 8)
    check("the kill switch ends it", r.json().get("ok") and t.closed is not None,
          f"{r.status_code} {r.text[:200]}")
    check("and the kill is audited", bool(audited(m, "pam_session_killed")))


async def ssh_files(c: httpx.Client) -> None:
    if not section("ssh: file transfer inside a live session"):
        return
    r = c.get(f"/pam/targets/{T['ssh_key']}/sftp/list", params={"path": "."})
    check("a transfer is refused without a live session",
          r.status_code == 403 and "open a session" in r.text, r.text[:200])
    t = await Term.open(c, T["ssh_key"])
    await t.run("echo FILES", "FILES")
    m = mark()
    body = b"e2e upload \xe2\x82\xac " + os.urandom(64 * 1024)
    r = c.post(f"/pam/targets/{T['ssh_key']}/sftp/put",
               data={"path": "."}, files={"file": ("e2e-up.bin", body)})
    check(f"an upload lands ({r.status_code})",
          r.status_code == 200 and r.json().get("ok"), r.text[:200])
    r = c.get(f"/pam/targets/{T['ssh_key']}/sftp/list", params={"path": "."})
    names = [e.get("name") for e in r.json().get("rows", [])]
    check("the listing shows it", "e2e-up.bin" in names, str(names)[:200])
    r = c.get(f"/pam/targets/{T['ssh_key']}/sftp/get",
              params={"path": "e2e-up.bin"})
    check("the download is byte-identical", r.content == body,
          f"{len(r.content)} bytes vs {len(body)}")
    r = c.get(f"/pam/targets/{T['ssh_key']}/sftp/get",
              params={"path": "/nonexistent/e2e-missing"})
    check("a download that cannot be served is refused", r.status_code != 200,
          f"{r.status_code}")
    ups = audited(m, "pam_sftp_upload")
    downs = audited(m, "pam_sftp_download")
    check("every transfer, refusals included, is audited",
          len(ups) == 1 and len(downs) == 2
          and any("refused" in d["detail"] for d in downs),
          str([d["detail"] for d in ups + downs]))
    # `sftp -b` reads one command per LINE, so a newline in the destination is
    # a second command running with the target's credential.
    r = c.post(f"/pam/targets/{T['ssh_key']}/sftp/put",
               data={"path": "./x\nmkdir e2e-injected"},
               files={"file": ("inj.txt", b"x")})
    r2 = c.get(f"/pam/targets/{T['ssh_key']}/sftp/list", params={"path": "."})
    listed = [e.get("name") for e in r2.json().get("rows", [])]
    check("a newline in the destination cannot become a second sftp command",
          not r.json().get("ok") and "e2e-injected" not in listed,
          f"{r.text[:160]} listing={listed}")
    await t.run("rm -f e2e-up.bin; echo CLEAN", "CLEAN")
    await t.close()


# ── the doors: who may open a socket at all ──────────────────────
async def refused_ws(coro) -> tuple[bool, str]:
    """(refused, evidence) for a socket that must not open a session."""
    from websockets.exceptions import InvalidStatus
    try:
        t = await coro
    except InvalidStatus as e:
        return True, f"handshake refused: {e.response.status_code}"
    except Exception as e:                                      # noqa: BLE001
        return True, f"{type(e).__name__}: {e}"
    await t.until("__never__", 6)
    ok = t.closed is not None and "E2E" not in t.text
    return ok, f"closed={t.closed is not None} text={t.text[-200:]!r}"


async def doors(c: httpx.Client) -> None:
    if not section("security: origin, switch, scope, malformed input"):
        return
    ok, why = await refused_ws(Term.open(c, T["ssh_key"],
                                         origin="https://evil.example"))
    check("a socket opened from another origin is refused (no hijacking)",
          ok, why)
    r = c.post("/pam/target/save",
               headers={"Origin": "https://evil.example",
                        "Sec-Fetch-Site": "cross-site"},
               data={"name": "csrf planted", "protocol": "ssh",
                     "address": "10.9.9.9", "auth_kind": "none"})
    check("a cross-origin form post is refused (no CSRF)",
          r.status_code == 403 and not any(
              t["name"] == "csrf planted" for t in pam.targets()),
          f"{r.status_code} {r.headers.get('location', '')}")
    r = c.post("/pam/target/save",
               headers={"Origin": "https://sibling.example",
                        "Sec-Fetch-Site": "same-site"},
               data={"name": "csrf sibling", "protocol": "ssh",
                     "address": "10.9.9.8", "auth_kind": "none"})
    check("and so is one from a sibling subdomain (same-site, not same-origin)",
          r.status_code == 403, f"{r.status_code}")
    r = c.post("/pam/target/save", data={"name": "honest save",
               "protocol": "ssh", "address": "10.9.9.7", "auth_kind": "none"})
    check("while the portal's own form post still works",
          r.status_code == 303 and any(t["name"] == "honest save"
                                       for t in pam.targets()),
          f"{r.status_code}")

    # A PAM-only installation (PORTAL_MODE=pam) has no off switch: the stored
    # one is ignored, so what is proved there is that it STAYS on.
    if os.environ.get("PORTAL_MODE", "").strip().lower() == "pam":
        cfg(enabled=False)
        try:
            t = await Term.open(c, T["ssh_key"])
            ok = await t.run("echo STILL_$((40+2))_ON", "STILL_42_ON")
            await t.close()
            check("PAM-only: a stored 'off' does not switch the PAM off", ok,
                  t.text[-200:])
        finally:
            cfg(enabled=True)
    else:
        cfg(enabled=False)
        try:
            ok, why = await refused_ws(Term.open(c, T["ssh_key"]))
            check("with Privileged Access switched off the SSH socket refuses",
                  ok, why)
            if "vnc" in T:
                ok, why = await refused_guac(c, T["vnc"])
                check("and so does the desktop socket", ok, why)
        finally:
            cfg(enabled=True)

    sc = login(*people["scoped"])
    ok, why = await refused_ws(Term.open(sc, T["ssh_key"]))
    check("a scoped operator cannot open a target outside their scope",
          ok, why)
    ids = [t["id"] for t in sc.get("/pam/targets.json").json()]
    check("and does not see it in their picker", T["ssh_key"] not in ids,
          str(ids))

    t = await Term.open(c, T["ssh_key"])
    await t.run("echo BEFORE", "BEFORE")
    for junk in ('{"r": "x"}', '{"r": [1]}', "[]", "5", '{"i": 7}', "not json"):
        await t.ws.send(junk)
    ok = await t.run("echo AFTER_$((1+1))", "AFTER_2")
    check("malformed messages do not kill the session", ok, t.text[-300:])
    await t.close()


async def refused_guac(c: httpx.Client, tid: str) -> tuple[bool, str]:
    from websockets.exceptions import InvalidStatus
    try:
        g = await Guac.open(c, tid)
    except InvalidStatus as e:
        return True, f"handshake refused: {e.response.status_code}"
    await g.pump(6)
    ok = g.closed is not None and not g.ready
    await g.close()
    return ok, f"ready={g.ready}"


async def pinning(c: httpx.Client) -> None:
    if not SSH_ROTATE or not section("ssh: host keys are pinned, not re-trusted"):
        return
    pin = getattr(pam, "host_pin", lambda _t: None)
    first = pin(T["ssh_key"])
    check("the first session pinned the server's host key",
          bool(first and first.get("fingerprints")), str(first))
    inv_first = pin(T["ssh_inv"]) if "ssh_inv" in T else None
    if "ssh_inv" in T:
        t = await Term.open(c, T["ssh_inv"])
        await t.run("echo INV_OK", "INV_OK")
        await t.close()
        await asyncio.sleep(1)
        inv_first = pin(T["ssh_inv"])
        check("an inventory host is pinned the same way",
              bool(inv_first and inv_first.get("fingerprints")),
              str(inv_first))
    subprocess.run(SSH_ROTATE, shell=True, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex((SSH_HOST, SSH_PORT)) == 0:
                break
        time.sleep(1)
    time.sleep(3)
    m = mark()
    t = await Term.open(c, T["ssh_key"])
    await t.until("__never__", 12)
    check("a CHANGED host key is refused, not silently accepted",
          t.closed is not None and "E2E" not in t.text
          and "host key" in t.text.lower(), t.text[-400:])
    check("and the mismatch is audited",
          bool(audited(m, "pam_hostkey_mismatch")))
    if "ssh_inv" in T:
        t = await Term.open(c, T["ssh_inv"])
        await t.until("__never__", 12)
        check("the inventory host refuses the changed key too",
              t.closed is not None and "host key" in t.text.lower(),
              t.text[-300:])
    r = c.post("/pam/target/hostkey/forget", data={"tid": T["ssh_key"]})
    check(f"an administrator can re-trust it ({r.status_code})",
          r.status_code == 303 and pin(T["ssh_key"]) is None)
    t = await Term.open(c, T["ssh_key"])
    ok = await t.run("echo RETRUSTED", "RETRUSTED")
    await t.close()
    await asyncio.sleep(1)
    now = pin(T["ssh_key"])
    check("the next session connects and pins the NEW key", ok and bool(now)
          and now.get("fingerprints") != (first or {}).get("fingerprints"),
          str(now))

    # A RE-SPELLED ADDRESS IS THE SAME MACHINE. ssh looks a host up under the
    # spelling it is given -- lower-cased, a trailing dot kept -- so the pin
    # is written under the connection's own spelling. Without that, editing
    # `localhost` to `LOCALHOST.` is either refused or quietly pinned afresh.
    fields = {"name": "e2e ssh named", "protocol": "ssh", "address": "localhost",
              "port": str(SSH_PORT), "username": SSH_USER, "auth_kind": "key",
              "secret_key": open(SSH_KEY).read(), "env": "dev"}
    named = pam.save_target("", fields, "e2e")
    t = await Term.open(c, named)
    ok1 = await t.run("echo NAMED_$((4*4))", "NAMED_16")
    await t.close()
    await asyncio.sleep(1)
    before = pam.host_pin(named) or {}
    pam.save_target(named, dict(fields, address="LOCALHOST.", secret_key=""),
                    "e2e")
    m = mark()
    t = await Term.open(c, named)
    ok2 = await t.run("echo SPELT_$((5*5))", "SPELT_25")
    await t.close()
    await asyncio.sleep(1)
    after = pam.host_pin(named) or {}
    check("a re-spelled address (localhost → LOCALHOST.) keeps its pin",
          ok1 and ok2 and bool(before.get("fingerprints"))
          and after.get("pinned") == before.get("pinned")
          and not audited(m, "pam_hostkey_pinned")
          and not audited(m, "pam_hostkey_mismatch"),
          f"ok1={ok1} ok2={ok2} before={before.get('pinned')} "
          f"after={after.get('pinned')} tail={t.text[-200:]!r}")
    for k in ("ssh_inv", "ssh_pw", "ssh_prod"):
        if k in T:
            c.post("/pam/target/hostkey/forget", data={"tid": T[k]})


async def crash(c: httpx.Client) -> None:
    if not section("evidence survives the portal dying mid-session"):
        return
    t = await Term.open(c, T["ssh_key"])
    await t.run("echo BEFORE_THE_CRASH", "BEFORE_THE_CRASH")
    ids = live_ids(c)
    sid = ids[0] if ids else ""
    row = pam.session(sid) or {}
    check("a live session already has its row (status running)",
          row.get("status") == "running", str(row)[:200])
    stop_portal(hard=True)
    start_portal()
    row = pam.session(sid) or {}
    check("after a hard kill and restart the session is on record",
          row.get("status") == "interrupted", str(row)[:300])
    check("with its recording indexed and checksummed",
          bool(row.get("rec_rel")) and bool(row.get("sha256"))
          and pam.session_integrity(sid)["state"] == "verified",
          str({k: row.get(k) for k in ("rec_rel", "sha256")}))
    path = pam.session_rec_path(sid) or ""
    check("and the recording still holds what happened",
          bool(path) and "BEFORE_THE_CRASH" in open(path, encoding="utf-8").read())


# ── RDP / VNC through guacd ──────────────────────────────────────
def guac_parse(text: str) -> list:
    out, i, n = [], 0, len(text)
    while i < n:
        elems = []
        while i < n:
            dot = text.find(".", i)
            if dot < 0:
                return out
            ln = int(text[i:dot])
            elems.append(text[dot + 1:dot + 1 + ln])
            i = dot + 1 + ln + 1
            if text[dot + 1 + ln] == ";":
                break
        out.append(elems)
    return out


def ginstr(*elems: str) -> str:
    return ",".join(f"{len(e)}.{e}" for e in elems) + ";"


class Guac:
    """A minimal guacamole-common-js: acknowledges syncs, counts what arrives."""

    def __init__(self, ws):
        self.ws, self.ready, self.bytes, self.ops = ws, "", 0, {}
        self.errors, self.closed, self.names = [], None, []

    @classmethod
    async def open(cls, c: httpx.Client, tid: str = "", path: str = "",
                   origin: str = BASE) -> "Guac":
        path = path or f"/pam/guac.ws?tid={tid}&w=1024&h=768"
        ws = await connect(WSBASE + path, subprotocols=["guacamole"],
                           max_size=None, open_timeout=30,
                           additional_headers={"Cookie": cookie_header(c),
                                               "Origin": origin})
        return cls(ws)

    async def pump(self, seconds: float, mouse: bool = False) -> None:
        end, x = time.monotonic() + seconds, 10
        while not self.closed and time.monotonic() < end:
            try:
                msg = await asyncio.wait_for(self.ws.recv(),
                                             max(0.05, end - time.monotonic()))
            except (asyncio.TimeoutError, TimeoutError):
                continue
            except ConnectionClosed as e:
                self.closed = e
                break
            self.bytes += len(msg)
            for el in guac_parse(msg):
                op = el[0] if el else ""
                self.ops[op] = self.ops.get(op, 0) + 1
                if op == "ready":
                    self.ready = el[1] if len(el) > 1 else "?"
                elif op == "sync":
                    await self._send(ginstr("sync", el[1]))
                elif op == "error":
                    self.errors.append(el[1:])
                elif op == "name" and len(el) > 1:
                    self.names.append(el[1])
            if mouse:
                x = (x + 7) % 600 + 10
                await self._send(ginstr("mouse", str(x), "100", "0"))

    async def _send(self, text: str) -> None:
        if self.closed:
            return
        try:
            await self.ws.send(text)
        except ConnectionClosed as e:
            self.closed = e

    async def close(self) -> None:
        with _quiet():
            await self.ws.send(ginstr("disconnect"))
        with _quiet():
            await self.ws.close()


async def desktop(c: httpx.Client, key: str, label: str) -> None:
    if key not in T or not section(f"{label}: a desktop through guacd"):
        return
    g = await Guac.open(c, T[key])
    await g.pump(12, mouse=True)
    # PROTOCOL evidence, not a byte count: a quiet test desktop is a few kB a
    # second and a busy one megabytes, so no threshold means "it streams".
    # What does: a display size, images, and frames still being acknowledged
    # after the first -- the broken relay stopped at `ready` (49 bytes).
    ops = g.ops
    check(f"{label}: guacd completes the handshake and the display streams",
          bool(g.ready) and ops.get("size", 0) >= 1 and ops.get("img", 0) >= 2
          and ops.get("sync", 0) >= 2 and not g.errors,
          f"ready={g.ready!r} bytes={g.bytes} ops={ops} errors={g.errors}")
    await g.close()
    # Filing now waits for guacd to finish writing the recording (see
    # pam._settle), so the row may still say running for a few seconds.
    for _ in range(40):
        row = latest_session(T[key])
        if row.get("status") != "running":
            break
        await asyncio.sleep(0.5)
    check(f"{label}: the session is filed as a guacd recording",
          row.get("rec_kind") == "guac" and bool(row.get("rec_rel"))
          and int(row.get("out_bytes") or 0) > 1000,
          str({k: row.get(k) for k in ("status", "rec_kind", "rec_rel",
                                        "out_bytes")}))
    check(f"{label}: and it verifies",
          pam.session_integrity(row.get("id", ""))["state"] == "verified")
    m = mark()
    r = c.get(f"/pam/sessions/{row.get('id')}/recording")
    check(f"{label}: the recording downloads, and that access is audited",
          r.status_code == 200 and len(r.content) > 1000
          and bool(audited(m)), f"{r.status_code} {len(r.content)}")


async def desktop_more(c: httpx.Client) -> None:
    if "vnc" not in T or not section("vnc: idle, watch, take-over, framing"):
        return
    cfg(idle_timeout=8)
    try:
        g = await Guac.open(c, T["vnc"])
        # Only syncs go back -- no mouse, no keys. The screen has a clock on
        # it, so guacd keeps sending frames and the client keeps acking them:
        # that traffic is not a person, and the idle timer must not think so.
        await g.pump(25)
        check("an idle desktop (clock ticking, nobody typing) is closed",
              g.closed is not None or any("inactivity" in " ".join(e)
                                          for e in g.errors),
              f"closed={g.closed is not None} errors={g.errors} "
              f"bytes={g.bytes}")
        await g.close()
    finally:
        cfg(idle_timeout=0)

    prim = await Guac.open(c, T["vnc"])
    await prim.pump(5, mouse=True)
    sid = (live_ids(c) or [""])[0]
    m = mark()
    watch = await Guac.open(c, path=f"/pam/session/{sid}/shadow.ws?mode=watch")
    await asyncio.gather(watch.pump(8), prim.pump(8, mouse=True))
    check("a supervisor joins the live desktop and sees it",
          bool(watch.ready) and watch.bytes > 5000,
          f"ready={watch.ready!r} bytes={watch.bytes} errors={watch.errors}")
    check("watching is audited", bool(audited(m, "pam_session_watch")))
    await watch.close()
    m = mark()
    ctl = await Guac.open(c, path=f"/pam/session/{sid}/shadow.ws?mode=control")
    await asyncio.gather(ctl.pump(6, mouse=True), prim.pump(6))
    check("and can take the keyboard", bool(ctl.ready) and ctl.bytes > 1000,
          f"ready={ctl.ready!r} bytes={ctl.bytes}")
    check("taking the keyboard is audited as its own event",
          bool(audited(m, "pam_session_control")))
    await ctl.close()
    await prim.close()

    g = await Guac.open(c, T["vnc_astral"])
    await g.pump(8)
    check("a parameter outside the BMP does not break guacd's framing",
          bool(g.ready) and not g.errors,
          f"ready={g.ready!r} errors={g.errors} closed={g.closed}")
    await g.close()

    ok, why = await refused_guac_origin(c, T["vnc"])
    check("the desktop socket refuses another origin too", ok, why)


async def refused_guac_origin(c, tid) -> tuple[bool, str]:
    from websockets.exceptions import InvalidStatus
    try:
        g = await Guac.open(c, tid, origin="https://evil.example")
    except InvalidStatus as e:
        return True, f"handshake refused: {e.response.status_code}"
    await g.pump(5)
    ok = not g.ready
    await g.close()
    return ok, f"ready={g.ready!r}"


# ── a recorded browser, in a real cluster ────────────────────────
def kube(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", "--kubeconfig", WEB_KUBECONFIG,
                           "--context", WEB_CONTEXT, "-n", WEB_NAMESPACE,
                           *args], capture_output=True, text=True,
                          timeout=timeout)


def kube_json(*args: str) -> dict:
    r = kube(*args, "-o", "json")
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout else {}


def listening(pod: str) -> dict:
    """{remote port: [local listen addresses]} for this machine's port-forwards
    to `pod` -- read off the OS, not off what the portal says it asked for."""
    out: dict = {}
    ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                        text=True).stdout
    for line in ps.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        if "port-forward" not in cmd or f"pod/{pod}" not in cmd:
            continue
        ports = re.findall(r" :(\d+)", cmd)
        ls = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP",
                             "-sTCP:LISTEN", "-Fn"], capture_output=True,
                            text=True).stdout
        addrs = [ln[1:] for ln in ls.splitlines() if ln.startswith("n")]
        for p in ports:
            out.setdefault(int(p), []).extend(addrs)
    return out


def probe_from_a_pod(ip: str) -> str:
    """What ANOTHER pod in the namespace can reach on the seat: the ingress
    side of the policy, which nothing on this machine can see."""
    name = f"pam-e2e-probe-{os.urandom(3).hex()}"
    script = (f"for p in 4444 5900; do if nc -z -w 3 {ip} $p; then echo OPEN-$p; "
              f"else echo SHUT-$p; fi; done; "
              "if nc -z -w 3 kube-dns.kube-system.svc.cluster.local 53; "
              "then echo DNS-OK; else echo DNS-FAIL; fi")
    kube("run", name, f"--image={WEB_PROBE_IMAGE}", "--restart=Never",
         "--command", "--", "sh", "-c", script)
    try:
        for _ in range(60):
            ph = kube("get", "pod", name, "-o",
                      "jsonpath={.status.phase}").stdout.strip()
            if ph in ("Succeeded", "Failed"):
                break
            time.sleep(2)
        return kube("logs", name).stdout
    finally:
        kube("delete", "pod", name, "--wait=false")


async def web_seat(c: httpx.Client) -> None:
    if "web" not in T or not section("web: a recorded browser in a cluster"):
        return
    m = mark()
    g = await Guac.open(c, T["web"])
    # Building the seat -- create, pull, Ready, forward, WebDriver, navigate --
    # takes seconds warm and minutes cold; the relay keeps the tunnel alive
    # with `nop` and narrates with `name` meanwhile.
    end = time.monotonic() + 600
    while not g.ready and not g.closed and time.monotonic() < end:
        await g.pump(3)
    await g.pump(8, mouse=True)
    ops = g.ops
    check("a web target opens a browser in the cluster and the display streams",
          bool(g.ready) and ops.get("size", 0) >= 1 and ops.get("img", 0) >= 2
          and ops.get("sync", 0) >= 2 and not g.errors,
          f"ready={g.ready!r} ops={ops} errors={g.errors} said={g.names[-3:]} "
          f"closed={getattr(getattr(g.closed, 'rcvd', None), 'reason', '')}")
    sid = (pam.sessions(target_id=T["web"]) or [{}])[0].get("id", "")
    pods = kube_json("get", "pods", "-l", f"envmap.tech/session={sid}")
    pod = (pods.get("items") or [{}])[0]
    name = (pod.get("metadata") or {}).get("name", "")
    ready = next((x.get("status") for x in
                  (pod.get("status") or {}).get("conditions") or []
                  if x.get("type") == "Ready"), "")
    check("the seat is Ready under a policy that denies it all inbound -- "
          "the readiness probe still reaches it",
          bool(name) and ready == "True", f"pod={name!r} ready={ready!r}")
    pol = kube_json("get", "networkpolicy", name) if name else {}
    spec = pol.get("spec") or {}
    check("its policy admits nothing in and confines what goes out",
          spec.get("policyTypes") == ["Ingress", "Egress"]
          and not spec.get("ingress") and bool(spec.get("egress")),
          json.dumps(spec)[:300])
    lst = listening(name) if name else {}
    drv, vnc = lst.get(4444, []), lst.get(5900, [])
    check("WebDriver is forwarded on loopback only (SEC-1)",
          bool(drv) and all(a.startswith(("127.0.0.1:", "[::1]:")) for a in drv),
          str(lst))
    check("and VNC listens where guacd can reach it",
          any(a.startswith("*:") for a in vnc), str(lst))
    ip = (pod.get("status") or {}).get("podIP", "")
    said = probe_from_a_pod(ip) if ip else ""
    check("another pod cannot reach the seat's WebDriver or VNC, while it "
          "can reach DNS (so the refusal is the policy, not a dead network)",
          "SHUT-4444" in said and "SHUT-5900" in said and "DNS-OK" in said,
          said.strip().replace("\n", " ") or "no probe output")
    await g.close()
    gone = False
    for _ in range(45):
        left = kube_json("get", "pods", "-l", f"envmap.tech/session={sid}")
        if not left.get("items") and name and kube(
                "get", "networkpolicy", name).returncode != 0:
            gone = True
            break
        await asyncio.sleep(2)
    check("closing the session deletes the seat and its policy", gone)
    for _ in range(40):
        row = pam.session(sid) or {}
        if row.get("status") != "running":
            break
        await asyncio.sleep(0.5)
    check("the web session is filed as a guacd recording, and it verifies",
          row.get("rec_kind") == "guac" and int(row.get("out_bytes") or 0) > 1000
          and pam.session_integrity(sid)["state"] == "verified",
          str({k: row.get(k) for k in ("status", "rec_kind", "out_bytes")}))
    check("the session is audited", bool(audited(m, "pam_console")))


# ── the whole run ────────────────────────────────────────────────
def server_log_faults() -> list:
    try:
        text = open(LOG, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    return [ln for ln in text.splitlines()
            if "Traceback" in ln or ln.startswith("ERROR")
            or "Exception in ASGI" in ln]


async def guarded(fn, *args) -> None:
    """One section, isolated: a section that crashes is a failure to report,
    not a reason to skip every section after it."""
    try:
        await fn(*args)
    except Exception as e:                                      # noqa: BLE001
        check(f"{fn.__name__} ran to the end", False,
              f"{type(e).__name__}: {e}")


async def main() -> None:
    seed()
    start_portal()
    try:
        admin = login(*people["admin"])
        if "ssh_key" in T:
            for fn in (ssh_basic, ssh_password, ssh_gates, ssh_live, ssh_files,
                       doors, pinning):
                await guarded(fn, admin)
        await guarded(desktop, admin, "vnc", "vnc")
        await guarded(desktop, admin, "rdp", "rdp")
        await guarded(desktop_more, admin)
        await guarded(web_seat, admin)
        if "ssh_key" in T:
            await guarded(crash, admin)
            admin = login(*people["admin"])
        if section("the server stayed healthy"):
            faults = server_log_faults()
            check("no tracebacks or ASGI errors in the portal's own log",
                  not faults, "\n          ".join(faults[:6]))
    finally:
        stop_portal()
    print(f"\ndata: {DATA}\nlog:  {LOG}")
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    asyncio.run(main())
