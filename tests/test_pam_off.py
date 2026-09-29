#!/usr/bin/env python3
"""Privileged Access is a SWITCH IN SETTINGS, and OFF by default.

WHY THIS EXISTS
    The PAM was removed from the product but kept in the tree, behind a flag.
    That flag was `PORTAL_PAM`, an environment variable, and it moved into the
    portal's own Settings on request — an installation switch that needs a
    redeploy to flip is not one the person running the portal owns.

    This proves the OFF state is complete AND escapable, which are in tension:

      1. /pam does not resolve — it redirects away.
      2. The sidebar has no Privileged Access link.
      3. The Ansible host rows have no shell button (it routed into PAM).
      4. **/settings/pam DOES resolve, and carries the switch.** It is the one
         part of the feature that must survive being switched off, or off is a
         one-way door — this is the assertion that was inverted when the flag
         moved, and the one that matters most.
      5. The Settings hub still shows its card, saying "off", because a card
         that vanishes leaves nothing to press.
      6. Turning it on from that page WORKS end to end — /pam resolves
         afterwards. A switch nobody can prove flips is not a switch.

    The rest of the portal is unaffected — the audit log still renders.

    ./.venv/bin/python tests/test_pam_off.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
os.environ.pop("PORTAL_PAM", None)   # nothing seeds it on: off, as a fresh install is
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pamoff-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ansible, auth, db, pam            # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    print("Privileged Access is off by default, and completely gone when off")
    check("a fresh installation reads off", pam.enabled() is False)
    # BEHAVIOUR, not a source grep. The first version of this check read
    # pam.enabled's source for "os.environ", and a bite that renamed the import
    # to `_o` sailed straight through it — a test a rename can satisfy is not a
    # test. Writing the setting must move the answer.
    from app import store
    store._set_setting("pam", {**pam.config(), "enabled": True})
    check("writing the stored setting is what decides it", pam.enabled() is True)
    store._set_setting("pam", {**pam.config(), "enabled": False})
    check("both ways", pam.enabled() is False)

    from fastapi.testclient import TestClient
    from app import main

    uid = auth.create_user("boss@t.local", "N", "Admin-Pass-Word-42", role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0 WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app); c.__enter__()
    c.post("/login", data={"email": "boss@t.local", "password": "Admin-Pass-Word-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    r = c.get("/pam", follow_redirects=False)
    check(f"/pam does not resolve — it redirects ({r.status_code})",
          r.status_code == 303 and r.headers.get("location") == "/")
    r = c.get("/pam/targets/new", follow_redirects=False)
    check("even a deep PAM URL is gone", r.status_code == 303)

    # THE ONE THAT MUST NOT REDIRECT. Everything above is the feature being
    # absent; this is the way back, and it was blocked by the same middleware
    # line until the switch moved onto it.
    r = c.get("/settings/pam", follow_redirects=False)
    check(f"/settings/pam still resolves while off ({r.status_code})",
          r.status_code == 200)
    check("and it carries the switch that turns the feature on",
          'name="enabled"' in r.text)

    r = c.get("/")
    # The LINK, not the phrase. This matched any occurrence of the words
    # anywhere in the page — including a JavaScript comment in base.html, which
    # ships on every page — so an unrelated edit failed it. What it means is
    # that there is no way to navigate to the feature.
    check("the sidebar has no Privileged Access link",
          r.status_code == 200 and 'href="/pam"' not in r.text)
    r = c.get("/settings")
    check("the Settings hub still offers the card, so there is something to "
          "press", r.status_code == 200 and "/settings/pam" in r.text)
    check("and the card says the feature is off",
          "Privileged Access" in r.text and ">off<" in r.text)

    # an Ansible group with a key would show a shell button when PAM is on
    priv, _ = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "grp", "ssh_user": "root",
                                  "key": priv}, "boss")
    ansible.add_host(gid, "h1", "10.0.0.1", "boss")
    r = c.get(f"/ansible/groups/{gid}")
    check("the Ansible host rows have no shell button",
          r.status_code == 200 and "/pam/targets/" not in r.text
          and ">shell</a>" not in r.text and ">shell</button>" not in r.text)

    # the rest of the portal is untouched
    r = c.get("/admin/audit")
    check("the audit log still renders (PAM off does not break other pages)",
          r.status_code == 200 and "Audit log" in r.text)

    print("and the switch actually flips, from the page, without a redeploy")
    r = c.post("/settings/pam", data={"enabled": "1", "record_sessions": "1",
                                      "guacd_host": "127.0.0.1",
                                      "guacd_port": "4822",
                                      "rdp_width": "1280", "rdp_height": "800",
                                      "require_reason": "prod",
                                      "idle_timeout": "1800",
                                      "max_duration": "0",
                                      "max_concurrent": "0"},
               follow_redirects=False)
    check(f"the form saves ({r.status_code})", r.status_code == 303)
    check("the feature reads on", pam.enabled() is True)
    check("/pam resolves now", c.get("/pam", follow_redirects=False
                                     ).status_code == 200)
    check("the sidebar has the link", 'href="/pam"' in c.get("/").text)
    check("and it is audited as the installation-level change it is",
          any(r["action"] == "pam_enabled" for r in auth.read_audit(50)))

    # THE TRAP save_config used to carry: filling an unsupplied field from
    # DEFAULTS meant any partial write turned the feature off, because off is
    # the default. A caller saving only the governance fields must not disarm
    # the whole feature as a side effect.
    pam.save_config(**{"require_reason": "always"})
    check("a partial save leaves the feature on", pam.enabled() is True)
    check("and still writes what it was given",
          pam.config()["require_reason"] == "always")

    # switched off again from the same page, and the way back is still there
    c.post("/settings/pam", data={"guacd_host": "127.0.0.1",
                                  "guacd_port": "4822",
                                  "rdp_width": "1280", "rdp_height": "800",
                                  "require_reason": "prod",
                                  "idle_timeout": "1800", "max_duration": "0",
                                  "max_concurrent": "0"},
           follow_redirects=False)
    check("unchecking it switches the feature back off", pam.enabled() is False)
    check("/pam is gone again",
          c.get("/pam", follow_redirects=False).status_code == 303)
    check("and /settings/pam is STILL reachable, so it is not a one-way door",
          c.get("/settings/pam", follow_redirects=False).status_code == 200)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
