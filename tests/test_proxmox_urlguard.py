#!/usr/bin/env python3
"""The Proxmox client goes through urlguard, and nothing built on httpx skips it.

Every outbound fetch in this portal passes `urlguard.check`, which refuses any
scheme but http(s) and the cloud metadata address — the one address nobody
configures on purpose and that hands out credentials for the asking. The
read-only Proxmox client behind the provisioning wizard was the exception: it
builds its own httpx client, and the guard's own sweep (tests/test_urlguard.py)
looks for urllib only, so it went past unnoticed. A connection whose endpoint
was the metadata address had this process fetch it — carrying the API token
in a header, or posting the username and password to it.

So: the metadata address is refused at every door a Proxmox endpoint arrives
by — the client itself, the wizard's Test button, a stored connection — and
refused BEFORE any request is attempted; the private addresses the product
exists to reach still are reached; and a sweep makes the next httpx client
answer to the guard too.

    ./.venv/bin/python tests/test_proxmox_urlguard.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pxguard-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx                                                   # noqa: E402

from app import auth, db, main, provision                      # noqa: E402
from app import terraform as tf                                # noqa: E402

bad = 0
attempts: list[str] = []


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _no_network(self, request):
    """Every request httpx would send, recorded and then failed — so a test
    can tell "refused before asking" from "asked and got no answer"."""
    attempts.append(str(request.url))
    raise httpx.ConnectError("no network in this test", request=request)


httpx.HTTPTransport.handle_request = _no_network


def refusal(fn) -> str:
    try:
        fn()
    except provision.ProxmoxError as e:
        return str(e)
    return ""


def main_test() -> int:
    print("the client refuses the metadata address before asking it anything")
    for url in ("https://169.254.169.254:8006", "http://169.254.169.254",
                "https://[fd00:ec2::254]:8006",
                "https://metadata.google.internal:8006",
                "https://169.254.1.1:8006", "file:///etc/passwd"):
        del attempts[:]
        why = refusal(lambda: provision.Proxmox(url, token="root@pam!t=SEK"))
        check(f"{url} is refused, got {why!r}", "refused" in why)
        check(f"{url}: and nothing was sent", not attempts)
    why = refusal(lambda: provision.Proxmox("https://169.254.169.254:8006",
                                            token="root@pam!t=SEK"))
    check(f"the refusal says why in words, got {why!r}", "metadata" in why)

    print("the wizard's Test button, through the real route")
    from fastapi.testclient import TestClient
    uid = auth.create_user("px-admin@test.local", "CI", "Proxmox-Guard-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.post("/login", data={"email": "px-admin@test.local",
                           "password": "Proxmox-Guard-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    del attempts[:]
    r = c.post("/provision/host/test",
               json={"endpoint": "169.254.169.254", "api_token": "root@pam!t=SEK"})
    got = r.json()
    check(f"a typed metadata endpoint is refused, got {got}",
          got.get("ok") is False and "metadata" in got.get("error", ""))
    check("and the token went nowhere", not attempts)

    print("a stored connection pointed at it")
    sid = tf.save_stack("", {
        "name": "pve-meta", "provider": "proxmox", "env": "prod",
        "body": 'provider "proxmox" {}',
        "creds": "PROXMOX_VE_ENDPOINT=https://169.254.169.254:8006/\n"
                 "PROXMOX_VE_USERNAME=root@pam\nPROXMOX_VE_PASSWORD=SEKRIT"},
        "adm")
    del attempts[:]
    why = refusal(lambda: provision.client_for(sid))
    check(f"opening a client from it is refused, got {why!r}", "metadata" in why)
    why = refusal(lambda: provision.console_open(sid, "pve1", 100))
    check(f"so is the console, whose websocket follows the same endpoint, got "
          f"{why!r}", "metadata" in why)
    check("and the password was posted nowhere", not attempts)

    print("what the client is for must still work")
    del attempts[:]
    px = provision.Proxmox("https://10.0.10.11:8006", token="root@pam!t=SEK")
    why = refusal(px.version)
    px.close()
    check(f"a private address is asked, got {attempts}",
          attempts == ["https://10.0.10.11:8006/api2/json/version"])
    check(f"and its silence reported as such, got {why!r}",
          "could not connect" in why)

    print("the image download is guarded, and a refusal ends its job in words")
    # A staging job runs on its own thread, so an exception it does not name
    # kills the thread and leaves the job reading "downloading…" for ever.
    key = "almalinux-10"
    saved = dict(provision.CATALOG[key])
    provision.CATALOG[key] = {**saved, "url": "http://169.254.169.254/latest/"}
    job = "stg-guardtest"
    with provision._STAGE_LOCK:
        provision._STAGE[job] = {"status": "running", "pct": 0, "msg": "",
                                 "volid": "", "by": "test"}
    del attempts[:]
    escaped = None
    try:
        provision._stage_run(job, sid, ["pve1"], key, "", "local")
    except Exception as e:                                     # noqa: BLE001
        escaped = e
    finally:
        provision.CATALOG[key] = saved
    st = provision.stage_status(job) or {}
    check(f"nothing escaped the job's thread, got {escaped!r}", escaped is None)
    check(f"the job failed and says why, got {st}",
          st.get("status") == "failed" and "metadata" in st.get("msg", ""))
    check("and nothing was fetched", not attempts)
    # the catalogue's real address is still asked, and a mirror that does not
    # answer ends the job the same way rather than leaving it downloading
    job = "stg-guardtest-2"
    with provision._STAGE_LOCK:
        provision._STAGE[job] = {"status": "running", "pct": 0, "msg": "",
                                 "volid": "", "by": "test"}
    del attempts[:]
    escaped = None
    try:
        provision._stage_run(job, sid, ["pve1"], key, "", "local")
    except Exception as e:                                     # noqa: BLE001
        escaped = e
    st = provision.stage_status(job) or {}
    check(f"the real catalogue address is asked, got {attempts}",
          len(attempts) == 1
          and attempts[0].startswith("https://repo.almalinux.org/"))
    check(f"and an unreachable mirror fails the job in words, got {st}, "
          f"{escaped!r}", escaped is None and st.get("status") == "failed"
          and st.get("msg"))

    print("nothing built on httpx skips the guard")
    # The sweep tests/test_urlguard.py runs reads urllib calls only, which is
    # exactly how this client went unseen. Read the source for the httpx
    # shapes too, so the next one cannot.
    offenders = []
    for path in sorted((ROOT / "app").glob("*.py")):
        src = path.read_text()
        for m in re.finditer(r"httpx\.(?:Async)?Client\(", src):
            call = src[m.end():m.end() + 400]
            call = call[:call.find(")\n") + 1 or len(call)]
            if "base_url=" in call and "base_url=urlguard.check(" not in call:
                offenders.append(f"{path.name}:{src[:m.start()].count(chr(10)) + 1}")
        for m in re.finditer(r"httpx\.(?:get|post|put|patch|delete|head|"
                             r"options|request|stream)\(", src):
            if "urlguard.check(" not in src[m.end():m.end() + 120]:
                offenders.append(f"{path.name}:"
                                 f"{src[:m.start()].count(chr(10)) + 1} (bare)")
    check(f"every httpx client with a base is built from the guard, and no "
          f"bare httpx call bypasses it — offenders: {offenders}", not offenders)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
