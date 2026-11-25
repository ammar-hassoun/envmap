"""A session that is not recorded is still a live session.

WHY THIS EXISTS
    The live list -- the Active tab, the End button, the concurrent-session
    cap -- is keyed by a session id, and the id came from the recording. With
    recording switched off `start_recording` returns None, the id was "", and
    every relay skipped `register_active`: the session ran on no list. Nobody
    could see it, nobody could end it, and its owner could open as many as
    they liked past the cap. A web seat is labelled with the same id, so the
    warmer would also have reaped a live, unrecorded browser as a pod nobody
    owned.

    This drives the REAL socket handlers -- the PAM SSH terminal, the desktop
    relay and the Ansible host terminal -- with the transport faked: a
    terminal that prints a prompt and waits, and a guacd that completes the
    handshake and holds the connection. Calling `register_active` from a test
    would prove nothing about the handlers, which is where the gap was.
"""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamunrec-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from app import ansible, auth, db, main, pam, rbac  # noqa: E402

bad = 0


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


def enrol(email: str, pw: str, areas) -> dict:
    uid = auth.create_user(email, "N", pw, role="viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], [], [])])
    return auth.by_id(uid)


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


class Proc:
    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class Term:
    """What `pam.open_ssh` hands the relay: a prompt, then nothing until it
    is closed -- which is what ending a session does to a real one."""

    def __init__(self):
        self.closed = threading.Event()
        self.prompted = False
        self.opened = time.time()
        self.proc = Proc()
        self.workdir = ""

    def read(self, timeout):
        if self.closed.wait(timeout):
            raise EOFError
        if not self.prompted:
            self.prompted = True
            return b"fake$ "
        return b""

    def write(self, data):
        pass

    def resize(self, rows, cols):
        pass

    def close(self):
        self.closed.set()


OPENED: list = []


def fake_open(*_a, **_k):
    t = Term()
    OPENED.append(t)
    return t


def live_row(tid: str, wait: float = 3.0) -> dict:
    """The Active row for a target. The relay registers just AFTER it sends
    its first frame, so a reader that looks at once can beat it."""
    end = time.time() + wait
    while time.time() < end:
        got = [a for a in pam.active_sessions() if a.get("target_id") == tid]
        if got:
            return got[0]
        time.sleep(0.05)
    return {}


def gone(tid: str, wait: float = 10.0) -> bool:
    end = time.time() + wait
    while time.time() < end:
        if not any(a.get("target_id") == tid for a in pam.active_sessions()):
            return True
        time.sleep(0.05)
    return False


def recordings_of(tid: str) -> int:
    return int(db.q("SELECT COUNT(*) AS n FROM pam_sessions WHERE "
                    "target_id = ?", (tid,))[0]["n"])


def recv(ws, wait: float = 8.0) -> tuple:
    """("text", str), ("closed", (code, reason)) or ("timeout", None).

    BOUNDED, because the regression this file exists to catch is a session on
    no list -- which is exactly the session nothing will ever close. The first
    version waited on `receive_text()` and, with the fix reverted, hung the
    suite instead of failing it."""
    out: dict = {}

    def go():
        try:
            out["text"] = ws.receive_text()
        except WebSocketDisconnect as e:
            out["closed"] = (e.code, e.reason or "")
        except Exception as e:                                  # noqa: BLE001
            out["closed"] = (None, f"{type(e).__name__}: {e}")

    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(wait)
    if th.is_alive():
        return "timeout", None
    return ("text", out["text"]) if "text" in out else ("closed", out["closed"])


def refusal(c: TestClient, url: str, **kw) -> tuple:
    """(what the terminal printed, the close code, the close reason) for a
    socket the handler should refuse. The SSH relay prints its reason; the
    desktop relay only closes with it. A socket that is NOT refused is left by
    closing it from this side, which ends the session it opened."""
    said, code, reason = "", None, ""
    try:
        with c.websocket_connect(url, **kw) as ws:
            for _ in range(2):
                kind, val = recv(ws, 3.0)
                if kind == "text":
                    said = said or val
                    continue
                if kind == "closed":
                    code, reason = val
                break
    except WebSocketDisconnect as e:
        code, reason = e.code, e.reason or ""
    return said, code, reason


def ended(ws) -> bool:
    """Whether the server closed this socket, within a bound."""
    for _ in range(20):
        kind, _ = recv(ws)
        if kind != "text":
            return kind == "closed"
    return False


def first_text(ws) -> str:
    kind, val = recv(ws)
    return val if kind == "text" else ""


def ssh(recorded: bool, c: TestClient, who: str) -> None:
    label = "recorded" if recorded else "NOT recorded"
    print(f"an SSH session that is {label} is live: listed, capped, ended")
    pam.save_config(enabled=True, allow_connect=True,
                    record_sessions=recorded, require_reason="off",
                    max_concurrent=1)
    tid = pam.save_target("", {"name": f"box {label}", "protocol": "ssh",
                               "address": "10.0.0.5", "port": "22",
                               "auth_kind": "none"}, "t")
    OPENED.clear()
    with c.websocket_connect(f"/pam/ssh.ws?tid={tid}") as ws:
        first = first_text(ws)
        row = live_row(tid)
        check("the session opened", "fake$" in first, first)
        check("it is on the live list", bool(row) and row.get("who") == who,
              str(row))
        check(f"and the row says whether it is recorded ({row.get('recorded')})",
              row.get("recorded") is recorded)
        sid = row.get("id", "")
        check("it has an id of its own", sid.startswith("ps-"), sid)
        # File transfer hangs off holding a live session, so it was refused
        # on every unrecorded one: "open a session on this target first".
        check("and file transfer's gate sees the session it is in",
              bool(sid) and pam.live_session_of(who, tid) == sid)
        page = c.get("/pam?sec=active").text
        check("the Active tab lists it",
              f'data-kill="{sid}"' in page and who in page)
        check("and says 'not recorded' exactly when it is not",
              ("not\n            recorded</div>" in page) is (not recorded))

        # THE CAP COUNTS IT: a second session by the same person is refused
        # before anything is opened.
        said, code, _ = refusal(c, f"/pam/ssh.ws?tid={tid}")
        check("a second session is refused by the concurrent-session cap",
              "concurrent-session limit" in said and code == 4001, said)
        check("  without a second terminal being opened", len(OPENED) == 1)

        # END WORKS ON IT.
        r = c.post(f"/pam/session/{sid or 'none'}/kill")
        check("ending it from the Active tab succeeds",
              r.status_code == 200 and r.json().get("ok"), r.text)
        check("the operator's socket is closed", ended(ws))
    check("its terminal was closed",
          bool(OPENED) and OPENED[0].closed.is_set())
    check("and it left the live list", gone(tid))
    check(f"a recording row exists only when recording is on "
          f"({recordings_of(tid)})", (recordings_of(tid) == 1) is recorded)


class Guacd:
    """Enough of guacd to be relayed to: args for a select, ready for a
    connect, and then the connection held open until the portal lets go."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.eof = threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(conn,), daemon=True).start()

    def one(self, conn):
        buf = ""
        with conn:
            while "6.select," not in buf or not buf.endswith(";"):
                got = conn.recv(65536)
                if not got:
                    return
                buf += got.decode()
            conn.sendall(pam.guac_instr("args", "VERSION_1_5_0", "hostname",
                                        "port", "password"))
            buf = ""
            while "7.connect," not in buf or not buf.endswith(";"):
                got = conn.recv(65536)
                if not got:
                    return
                buf += got.decode()
            conn.sendall(pam.guac_instr("ready", "$fake-connection"))
            while conn.recv(65536):
                pass
            self.eof.set()


def desktop(c: TestClient, who: str) -> None:
    print("a desktop session that is NOT recorded is live, joinable, ended")
    fake = Guacd()
    pam.save_config(enabled=True, allow_connect=True, record_sessions=False,
                    require_reason="off", max_concurrent=1,
                    guacd_host="127.0.0.1", guacd_port=fake.port)
    tid = pam.save_target("", {"name": "desk", "protocol": "rdp",
                               "address": "10.0.0.6", "port": "3389",
                               "auth_kind": "none"}, "t")
    with c.websocket_connect(f"/pam/guac.ws?tid={tid}&w=1280&h=800",
                             subprotocols=["guacamole"]) as ws:
        hello = first_text(ws)
        row = live_row(tid)
        check("guacd's ready reached the browser", "5.ready," in hello, hello)
        check("it is on the live list, not recorded",
              bool(row) and row.get("recorded") is False
              and row.get("who") == who, str(row))
        check("and a supervisor can still join it -- watching a desktop "
              "needs guacd's connection, not a recording",
              row.get("shadowable") is True)
        _, code, reason = refusal(c, f"/pam/guac.ws?tid={tid}&w=1280&h=800",
                                  subprotocols=["guacamole"])
        check("the cap counts it",
              code == 4001 and "concurrent-session limit" in reason,
              f"{code} {reason!r}")
        r = c.post(f"/pam/session/{row.get('id') or 'none'}/kill")
        check("ending it succeeds", r.status_code == 200 and r.json().get("ok"),
              r.text)
        check("and the gateway connection is let go", fake.eof.wait(10))
        check("and the operator's socket is closed", ended(ws))
    check("it left the live list", gone(tid))
    check("and no recording row was written", recordings_of(tid) == 0)


def ansible_terminal(c: TestClient, who: str) -> None:
    print("an Ansible host terminal that is NOT recorded is live too")
    pam.save_config(enabled=True, allow_connect=True, record_sessions=False,
                    require_reason="off", max_concurrent=0)
    priv, _ = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "unrec", "ssh_user": "root",
                                  "key": priv}, "t")
    ansible.add_host(gid, "web01", "10.0.0.7", "t")
    hid = next(t["id"] for t in pam.targets() if t.get("source") == "ansible"
               and t["name"] == "web01")
    OPENED.clear()
    with c.websocket_connect(f"/ansible/host.ws?gid={gid}&host=web01") as ws:
        first = first_text(ws)
        row = live_row(hid)
        check("the terminal opened", "fake$" in first, first)
        check("it is on Privileged Access's live list, not recorded",
              bool(row) and row.get("recorded") is False
              and row.get("source") == "ansible", str(row))
        r = c.post(f"/pam/session/{row.get('id') or 'none'}/kill")
        check("and it can be ended from there",
              r.status_code == 200 and r.json().get("ok"), r.text)
        check("which closes the operator's socket", ended(ws))
    check("it left the live list", gone(hid))


if __name__ == "__main__":
    keep = (pam.open_ssh, pam.inventory_shell)
    pam.open_ssh = fake_open
    pam.inventory_shell = fake_open
    try:
        email = "live@pamunrec.test"
        enrol(email, "Live-Unrecorded-42",
              ["pam", "pam_connect", "ansible", "ansible_run"])
        client = signed_in(email, "Live-Unrecorded-42")
        ssh(False, client, email)
        ssh(True, client, email)
        desktop(client, email)
        ansible_terminal(client, email)
    finally:
        pam.open_ssh, pam.inventory_shell = keep
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
