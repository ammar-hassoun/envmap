#!/usr/bin/env python3
"""Privileged Access: the catalogue, the brokered credential, the recording, the
guacd framing, and who may touch each.

WHY THIS EXISTS
    This is the PAM: it holds credentials for other machines and opens live root
    shells and desktops on them. The load-bearing facts:

      1. **The credential is brokered, never shown.** A target's secret is sealed
         at rest and appears in no page context. It reaches ssh or guacd and
         nowhere else.
      2. **The guacd framing is length-computed, not concatenated.** A password
         with any character cannot break the instruction stream — the same
         discipline as an argv list.
      3. **The recording is output only, redaction intact**, and a stored
         recording path can never walk out of the data directory.
      4. **Connecting is gated apart from reading.** A viewer may read the
         catalogue and replay recordings; opening a live session, deleting a
         recording, or killing a session needs `pam_connect`.
      5. **The SSH recordings inherited from Ansible are carried forward.**

    ./.venv/bin/python tests/test_pam.py
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
os.environ["PORTAL_PAM"] = "1"          # PAM is archived off by default; on for its tests
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("pam-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import ansible, db, kmanage, pam, secretbox, webseat  # noqa: E402
from app.paths import DATA                                     # noqa: E402

bad = 0


# The repo root, once and at module level. Two functions each held a local
# `root` and `main` held none, which is the same reused-name trap that had
# these checks looking for `class _Sftp` inside one function's source.
ROOT = pathlib.Path(__file__).resolve().parent.parent


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def refused(what, fn):
    try:
        fn()
    except pam.Refused:
        return
    check(f"{what} — it was ALLOWED", False)


def main() -> int:
    print("the catalogue seals the credential and never shows it")
    tid = pam.save_target("", {"name": "EU WAF", "protocol": "ssh",
        "address": "10.0.10.11", "port": "22", "username": "root",
        "auth_kind": "password", "secret": "S3cr3t", "is_prod": "1"}, "ammar")
    t = pam.target(tid)
    check("the view carries no sealed secret", "secret_sealed" not in t)
    check("it knows the protocol and prod flag",
          t["proto_label"] == "SSH" and t["is_prod"] == 1)
    raw = db.q("SELECT secret_sealed FROM pam_targets WHERE id=?", (tid,))[0]["secret_sealed"]
    check("the secret is sealed at rest, no plaintext in the row",
          secretbox.sealed(raw) and "S3cr3t" not in raw)
    check("brokered back only on demand", pam.target_secret(tid) == "S3cr3t")
    pam.save_target(tid, {"name": "EU WAF", "protocol": "ssh",
        "address": "10.0.10.11", "port": "2222", "username": "root",
        "auth_kind": "password", "secret": ""}, "ammar")
    check("editing without a secret keeps the stored one and changes the port",
          pam.target_secret(tid) == "S3cr3t" and pam.target(tid)["port"] == 2222)
    refused("a flag-injecting address",
            lambda: pam.save_target("", {"name": "x", "protocol": "ssh",
                "address": "-oProxyCommand=touch /tmp/x", "auth_kind": "none"}, "x"))

    print("an SSH key is put to ssh AT THE FORM, not at connect time")
    # REPORTED BY A CUSTOMER: the terminal failed with ssh's own
    # `error in libcrypto` and `Permission denied (publickey)` while the same
    # key worked from their shell. This form stored whatever it was handed —
    # the Ansible group form has asked ssh about a key since a mangled paste
    # took out a whole run, and a target's key was getting no such check.
    from app import ansible as _ans                            # noqa: PLC0415
    good, _pub = _ans.new_keypair()

    def save_key(name, key):
        # `secret_key`, which is the field the form actually posts: the key
        # box is a textarea and the password box is a separate input. They
        # used to be conflated on submit, which is what destroyed the
        # newlines — see "the key REACHES the server" below.
        return pam.save_target("", {"name": name, "protocol": "ssh",
                                    "address": "10.0.0.9", "port": "22",
                                    "username": "root", "auth_kind": "key",
                                    "secret": "", "secret_key": key}, "ammar")
    kid = save_key("keygood", good)
    check("a good key is stored", pam.target_secret(kid) == good)
    # AN HTML TEXTAREA POSTS CRLF — that is the specification, not a quirk —
    # and measured both ways: cryptography loads such a key and ssh-keygen
    # refuses it with `invalid format`. So it is NORMALISED, not refused: the
    # mangling is the browser's, and telling somebody their correct key is
    # invalid because of how a form posts it would blame them for our
    # plumbing.
    def stored(name, key):
        """The key as it would be written, or the refusal, never a crash."""
        try:
            return pam.target_secret(save_key(name, key))
        except (pam.Refused, _ans.Refused) as e:
            return f"REFUSED: {e}"
    got = stored("keycrlf", good.replace("\n", "\r\n"))
    check(f"a CRLF paste is repaired, byte for byte ({got[:34]!r}…)",
          got == good)
    check("...so nothing carries a CR into the key file", "\r" not in got)
    check("a key with no trailing newline gains exactly one",
          stored("keynonl", good.rstrip("\n")) == good)
    # ANYTHING BEFORE -----BEGIN BREAKS AN OPENSSH-FORMAT KEY AND NOTHING ELSE
    # DOES. Measured in the portal's own image: a UTF-8 BOM (what a Windows
    # editor writes), a leading blank line, or a line of notes above the key
    # all load in `cryptography` and make ssh answer `error in libcrypto` —
    # the one combination that gets PAST a validator and fails at connect
    # time, which is exactly what a customer hit while the same key worked
    # from their own shell. A PEM key tolerates the same bytes, which is why
    # it looks arbitrary from outside.
    for label, mangled in (("a UTF-8 BOM", "\ufeff" + good),
                           ("a leading blank line", "\n" + good),
                           ("notes above the key", "vpn server key\n" + good),
                           ("a BOM and CRLF together",
                            "\ufeff" + good.replace("\n", "\r\n"))):
        check(f"{label} is repaired, not refused",
              stored("k" + label.replace(" ", "")[:9], mangled) == good)
    # The repair must not eat a key: trimming starts at the header, so what is
    # stored is the file byte for byte.
    check("and nothing is trimmed from the key itself",
          _ans.key_text("\ufeff" + good) == good)
    # THE SHAPE A REAL CUSTOMER'S KEY ARRIVED IN, and the one this could not
    # repair for two releases. Their file separated lines with LF-THEN-CR —
    # reversed CRLF, which nothing here produces on purpose but files in the
    # world do. A textarea's value sanitisation turns CRLF into LF and then a
    # LONE CR into LF as well, so every separator became two newlines and the
    # body reached the server with a blank line between every line of base64.
    # ssh answers `error in libcrypto`; reproduced end to end in the portal's
    # own image, before and after.
    lfcr = good.replace("\n", "\n\r")
    dom = lfcr.replace("\r\n", "\n").replace("\r", "\n")   # what the DOM stores
    posted = dom.replace("\n", "\r\n")                      # what the form posts
    check(f"a body full of blank lines is repaired ({posted.count(chr(10))} newlines in)",
          _ans.key_text(posted) == good)
    check("...and the target accepts it", stored("keylfcr", posted) == good)
    # A BLANK LINE IS STRUCTURAL IN AN OLD ENCRYPTED PEM (Proc-Type/DEK-Info),
    # so they are dropped only where there are no such headers — otherwise a
    # passphrase-protected key would be mangled into a worse error than the
    # accurate one it already gets.
    headered = ("-----BEGIN RSA PRIVATE KEY-----\n"
                "Proc-Type: 4,ENCRYPTED\n"
                "DEK-Info: AES-128-CBC,0123456789ABCDEF\n"
                "\nQUJD\n-----END RSA PRIVATE KEY-----\n")
    out = _ans.key_text(headered)
    check("an encrypted PEM keeps the blank line after its headers",
          "DEK-Info" in out
          and any(not ln.strip() for ln in out.split("\n")[1:-1]))
    # And what ssh cannot load is refused HERE, with ssh's own reason, rather
    # than at connect time in a terminal window.
    # NOT named `bad`: that is this file's own failure counter, and assigning
    # it here made it a local of main(), so the summary printed a loop value
    # instead of a count. Nothing had actually failed.
    for label, wrong in (("a public key", _pub),
                         ("a key with a lost line",
                          "\n".join(l for i, l in enumerate(good.strip().split("\n"))
                                    if i != 2) + "\n"),
                         ("nonsense", "not a key at all")):
        try:
            save_key("keybad", wrong)
            check(f"{label} is refused at the form", False)
        except (pam.Refused, _ans.Refused) as e:
            check(f"{label} is refused at the form ({str(e)[:40]}…)", True)
    # A PASSWORD IS NOT A KEY and must not be put through a key parser.
    pid2 = pam.save_target("", {"name": "keypw", "protocol": "ssh",
                                "address": "10.0.0.9", "port": "22",
                                "username": "root", "auth_kind": "password",
                                "secret": "  hunter2\r\n  "}, "ammar")
    check("a password is stored verbatim, never normalised as a key",
          pam.target_secret(pid2) == "  hunter2\r\n  ")

    # ONE definition: the same field is filled on two forms, and a normaliser
    # written twice is one of them drifting.
    check("pam defers to ansible's normaliser rather than keeping its own",
          "ansible.key_text(raw)" in (ROOT / "app" / "pam.py").read_text())
    check("...and read_key normalises before it parses, so both forms benefit",
          "raw = key_text(text)" in (ROOT / "app" / "ansible.py").read_text())

    print("...and the key REACHES the server with its line breaks")
    # THE ROOT CAUSE OF THE WHOLE KEY SAGA, found last and present all along.
    # The form copied the textarea into the PASSWORD input on submit, and an
    # `<input>` runs a value sanitisation that STRIPS every CR and LF — so the
    # key left the browser as one unbroken line and no repair on this side
    # could put the breaks back. Every newline fix that came before was
    # mending damage that had already happened upstream of the request.
    # Verified in a real browser through the real form: secret_key arrives
    # with its newlines, secret arrives empty.
    tf0 = (ROOT / "templates" / "pam_target.html").read_text()
    check("nothing copies the key into a single-line input",
          "pw.value = key.value" not in tf0)
    check("the key field is a textarea, which keeps newlines",
          '<textarea id="key" name="secret_key"' in tf0)
    check("and the server reads THAT field for key auth",
          'fields.get("secret_key") if auth_kind == "key"'
          in (ROOT / "app" / "pam.py").read_text())
    # Driven, not read: a key posted under its own field survives whole.
    real, _ = _ans.new_keypair()
    kid2 = pam.save_target("", {"name": "viaform", "protocol": "ssh",
                                "address": "10.0.1.250", "port": "22",
                                "username": "root", "auth_kind": "key",
                                "secret": "", "secret_key": real}, "ammar")
    check("a key posted in its own field is stored intact",
          pam.target_secret(kid2) == real)
    # A password must still come from the password box, not the key box.
    pid3 = pam.save_target("", {"name": "viapw", "protocol": "ssh",
                                "address": "10.0.1.250", "port": "22",
                                "username": "root", "auth_kind": "password",
                                "secret": "hunter2", "secret_key": ""}, "ammar")
    check("and a password still comes from the password field",
          pam.target_secret(pid3) == "hunter2")
    # The one-line shape is what the old form produced, so it stays refused —
    # and says the useful thing whichever words ssh chose for it.
    try:
        pam.save_target("", {"name": "flatkey", "protocol": "ssh",
                             "address": "10.0.1.250", "port": "22",
                             "username": "root", "auth_kind": "key",
                             "secret": "", "secret_key": real.replace("\n", "")},
                        "ammar")
        check("a one-line key is still refused", False)
    except (pam.Refused, _ans.Refused) as e:
        check(f"a one-line key is refused, and named ({str(e)[:38]}…)",
              "one long line" in str(e))

    print("...and the console says what the CLUSTER said, not a guess")
    wsrc2 = (ROOT / "app" / "webseat.py").read_text()
    check("the pod's own trouble is read rather than inferred",
          "def trouble(" in wsrc2 and "ImagePullBackOff" in wsrc2)
    check("waiting polls, so the reason arrives when the cluster knows it",
          "def wait_ready" in wsrc2 and "READY_POLL" in wsrc2)
    check("a backing-off pull is not waited out to the full budget",
          "BackOff" in wsrc2 and "Unschedulable" in wsrc2)
    msrc2 = (ROOT / "app" / "main.py").read_text()
    check("and the relay forwards it to the waiting pane",
          "webseat.progress(sid)" in msrc2)
    con2 = (ROOT / "templates" / "pam_console.html").read_text()
    check("...which the console displays",
          "client.onname" in con2)

    print("...and a stuck seat is explained in the CLUSTER'S words")
    # A CUSTOMER WAITED THE WHOLE BUDGET and was told "the cluster reported
    # nothing wrong with the pod", which was true of the two places that were
    # being looked at and useless to them. A pod that RUNS and never passes
    # its readiness probe has its reason in none of them: it is in the events,
    # in `lastState`, and in what the container itself said. Verified against
    # real pods on a real cluster — a pull that cannot resolve, and a
    # container that runs and never listens — before this was written.
    import json as _json                                       # noqa: PLC0415

    class _Fake:
        def __init__(self, out): self.stdout, self.stderr, self.returncode = out, "", 0

    def _seat_saying(pod, events="", logs=""):
        seat = webseat.Seat({"name": "c"}, dict(pam.config(),
                                                web_namespace="browsers"),
                            "pam-web-aaaaaaaa")
        def fake(argv, timeout, stdin=""):
            if "events" in argv:
                return _Fake(events)
            if "logs" in argv:
                return _Fake(logs)
            return _Fake(_json.dumps(pod))
        # `_base` wants a real kubeconfig; the argv it builds is not what is
        # under test here — the parsing of what comes back is.
        keep, webseat._run = webseat._run, fake
        keep_base, seat._base = seat._base, lambda: ["kubectl"]
        try:
            return seat.trouble()
        finally:
            webseat._run = keep
            seat._base = keep_base

    pull = _seat_saying({"status": {"containerStatuses": [
        {"name": "browser", "ready": False, "state": {"waiting": {
            "reason": "ImagePullBackOff",
            "message": "Back-off pulling image \"x/y:1\""}}}]}})
    check(f"an image it cannot pull is named ({pull[:34]}…)",
          "ImagePullBackOff" in pull and "Back-off pulling" in pull)
    sched = _seat_saying({"status": {"conditions": [
        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
         "message": "0/3 nodes are available"}]}})
    check(f"a pod nothing will schedule is named ({sched[:30]}…)",
          "Unschedulable" in sched and "0/3 nodes" in sched)
    died = _seat_saying({"status": {"containerStatuses": [
        {"name": "browser", "ready": False, "restartCount": 4,
         "state": {"waiting": {"reason": "CrashLoopBackOff"}},
         "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}]}})
    # BOTH halves: that it is crashing, and what killed it. CrashLoopBackOff
    # alone does not distinguish "give it more memory" from "read the logs".
    check(f"a container that keeps dying is named ({died[:44]}…)",
          "CrashLoopBackOff" in died)
    check("...and so is what killed it, which is the actionable half",
          "OOMKilled" in died and "restarted 4 times" in died)
    # THE ONE THAT WAS MISSING: running, not ready, nothing in the status.
    probe = _seat_saying(
        {"status": {"phase": "Running", "containerStatuses": [
            {"name": "browser", "ready": False, "state": {"running": {}}}]}},
        events="Unhealthy|Readiness probe failed: connection refused\n",
        logs="cannot start the browser: not enough memory\n")
    check(f"a probe that never passes is named ({probe[:34]}…)",
          "Readiness probe failed" in probe)
    # ...and the container's own last words, which say WHY it is not
    # listening. "connection refused" alone is the symptom, not the cause.
    check("...along with what the container itself said",
          "not enough memory" in probe and "it last said" in probe)
    # Nothing wrong at all must stay silent, or every healthy start would
    # carry a scary sentence.
    fine = _seat_saying({"status": {"phase": "Running", "containerStatuses": [
        {"name": "browser", "ready": True, "state": {"running": {}}}]}})
    check("a healthy pod says nothing", fine == "")

    # "I COULD NOT ASK" IS NOT "NOTHING IS WRONG". Conflating them produced
    # the worst message this feature has sent: a customer watched a pod that
    # was up and serving — Selenium bound four seconds in, by its own logs —
    # while the console said the browser never became ready AND that the
    # cluster reported nothing wrong with it. Both halves were false; the read
    # itself had failed. Silence about a failed question is worse than no
    # question.
    class _Broke:
        stdout, stderr, returncode = "", "namespaces \"x\" not found", 1

    seat_b = webseat.Seat({"name": "c"}, dict(pam.config(), web_namespace="x",
                                              web_ready_timeout=5),
                          "pam-web-aaaaaaaa")
    keep_run, keep_base = webseat._run, seat_b._base
    webseat._run = lambda argv, timeout, stdin="": _Broke()
    seat_b._base = lambda: ["kubectl"]
    try:
        blind = seat_b.trouble()
        check(f"a pod it cannot READ is named as such ({blind[:38]}…)",
              "cannot read" in blind and "not found" in blind)
        # AND IT MUST NOT BE WAITED OUT. Polling on through a failed read is
        # what turned this into ten minutes of silence.
        import time as _t                                      # noqa: PLC0415
        t0 = _t.monotonic()
        try:
            seat_b.wait_ready()
            check("an unreadable pod is refused, not waited out", False)
        except webseat.Refused as e:
            took = _t.monotonic() - t0
            check(f"an unreadable pod is refused at once ({took:.1f}s, "
                  f"budget was 5s)", took < 3 and "cannot read" in str(e))
    finally:
        webseat._run, seat_b._base = keep_run, keep_base

    print("...and the key can be CHOSEN as a file, not only pasted")
    tf = (ROOT / "templates" / "pam_target.html").read_text()
    check("there is a file picker beside the box", 'id="keyFile"' in tf)
    # READ IN THE BROWSER, into the field the form already posts: a private key
    # is the one thing worth keeping off any path that does not already carry
    # it, so no upload endpoint exists for this.
    check("it is read in the browser, not uploaded to a new endpoint",
          "FileReader" in tf and 'type="file"' in tf
          and "/upload" not in tf)
    check("...and it fills the field the form already submits",
          "key.value = text" in tf)
    check("the picker appears only for key auth",
          "key-pick" in tf and "k === 'key' ? 'flex' : 'none'" in tf)
    # Picking the .pub half is the common mistake and its failure would
    # otherwise be a parse error a save later.
    check("choosing the public half is named as such, before saving",
          "PUBLIC half" in tf)

    print("a WEB target is opened, never proxied — and the open is EVIDENCE")
    # Reported as "I added a web application but I cannot see a live session or
    # a recording for it". Correct, and the product had been claiming the
    # opposite in two places, which is what created the expectation.
    web = pam.save_target("", {"name": "AML", "protocol": "https",
        "address": "aml.example.internal", "port": "8443",
        "url": "https://aml.example.internal:8443/app",
        "auth_kind": "none", "is_prod": "1"}, "ammar")
    wt = pam.target(web)
    check("a web target is not a live protocol, so it counts as neither",
          wt["is_live"] is False and wt["needs_guac"] is False)
    check("the form stops promising a brokered launch",
          "not\n          proxied</b>" in
          (ROOT / "templates" / "pam_target.html").read_text()
          and "launched with the brokered credential" not in
          (ROOT / "templates" / "pam_target.html").read_text())

    # STORED XSS, found by storing the payload and reading the rendered row —
    # the same way the 3 September scan DISPROVED the identical shape on the
    # BMC page. That one has a `urlguard` fetch standing in front of the
    # render; this page had nothing, and there is no CSP in this product, so
    # the href executed. The boundary crossed is "may add a target" to "runs
    # script in a reader's session".
    refused("a javascript: URL on a web target",
            lambda: pam.save_target("", {"name": "evil", "protocol": "https",
                "address": "a.example.net", "url": "javascript:alert(1)",
                "auth_kind": "none"}, "x"))
    refused("a data: URL either",
            lambda: pam.save_target("", {"name": "evil2", "protocol": "https",
                "address": "a.example.net",
                "url": "data:text/html,<script>alert(1)</script>",
                "auth_kind": "none"}, "x"))
    # Rows stored BEFORE the scheme was validated are still in the database,
    # so the read side refuses them too rather than trusting the write side.
    check("a legacy javascript: row is neutralised on the way out",
          pam.web_url({"protocol": "https", "address": "h", "port": 443,
                       "extra_d": {"url": "javascript:alert(1)"}}) == "")
    check("and a target with no URL derives one from its own address",
          pam.web_url(wt).startswith("https://aml.example.internal:8443")
          or pam.web_url(pam.target(pam.save_target("", {"name": "AML2",
              "protocol": "https", "address": "aml2.example.net", "port": "8443",
              "auth_kind": "none"}, "x"))) == "https://aml2.example.net:8443")

    print("...and the seat is CONFINED, not just chrome-less")
    # REPORTED: "from the browser I can see the URL tab where I can open
    # google.com and it works fine". A seat is meant to be a controlled path
    # to ONE application; a browser with an omnibox and no egress policy is an
    # unrestricted browser inside somebody's cluster — able to reach every
    # internal service, the node's metadata endpoint and the internet — handed
    # to anybody holding pam_connect on one harmless target.
    seat_src = (ROOT / "app" / "webseat.py").read_text()
    # The WINDOW TYPE and the confinement flags are asserted against what the
    # driver is actually SENT, in `seat_navigation()` below — reading them out
    # of the source proves only that a string is present in a file.
    # Deliberately NOT asserting the comment that says kiosk mode is cosmetic:
    # a check on prose wraps at a line break and proves nothing anyway. What
    # the honesty is worth is the NetworkPolicy below, and that is asserted.

    # THE ACTUAL CONTROL.
    cfg = dict(pam.config(), web_namespace="browsers")
    pol = webseat.egress_policy("pam-web-aaaaaaaa", cfg,
                                "https://app.example.net:8443/x",
                                ["10.1.2.3", "10.1.2.4"])
    check("a per-seat NetworkPolicy is built, selecting only that seat",
          pol["kind"] == "NetworkPolicy"
          and pol["spec"]["podSelector"]["matchLabels"]["envmap.tech/seat"]
              == "pam-web-aaaaaaaa")
    check("it restricts EGRESS", pol["spec"]["policyTypes"] == ["Egress"])
    rules = pol["spec"]["egress"]
    cidrs = [t["ipBlock"]["cidr"] for r in rules for t in r.get("to", [])
             if "ipBlock" in t]
    check(f"to the target's own addresses only ({cidrs})",
          set(cidrs) == {"10.1.2.3/32", "10.1.2.4/32"})
    check("on the target's own port, not everything",
          any(pt.get("port") == 8443 for r in rules for pt in r.get("ports", [])))
    # EVERY address, because a policy naming one of a round-robin set is a
    # session that works four times in five.
    check("all resolved addresses are named, not just the first",
          len(cidrs) == 2)
    check("DNS is allowed, or the browser cannot resolve what it was given",
          any(pt.get("port") == 53 for r in rules for pt in r.get("ports", [])))
    # AND TO ANY RESOLVER, which is the whole point. Naming `kube-system` is
    # wrong on a great many real clusters: NodeLocal DNSCache intercepts DNS
    # to the kube-dns ClusterIP with iptables and answers from a LINK-LOCAL
    # address on the NODE, which is not a pod in any namespace, so a
    # namespace selector cannot match it and every lookup is dropped. Found
    # on a customer's cluster — the seat became Ready, because the grid binds
    # locally and needs no DNS, and then sat on a blank page unable to
    # resolve the one host it was allowed to visit.
    dns = [r for r in rules
           if any(pt.get("port") == 53 for pt in r.get("ports", []))]
    check(f"...to ANY resolver, not only pods in one namespace ({dns[0]})",
          all(not r.get("to") for r in dns))
    # It does not widen what the browser can FETCH: TCP egress is still the
    # single address list, and asking a resolver a question is not reaching a
    # service.
    tcp = [r for r in rules
           if any(pt.get("port") != 53 for pt in r.get("ports", []))]
    check("and TCP still goes only to the target's own addresses",
          all(r.get("to") and all("ipBlock" in t for t in r["to"]) for r in tcp))
    # AN ipBlock CANNOT MATCH THIS CLUSTER'S OWN INGRESS, and that cost a
    # customer a working console. Their target resolved to the external
    # address of `traefik/traefik-public`, the LoadBalancer of the very
    # cluster the seat runs in -- the most ordinary arrangement there is. The
    # load balancer hairpins the packet straight back in, so the policy engine
    # sees a POD as the destination, not the CIDR that was allowed, and under
    # a default deny that is a silent DROP. Hence ERR_CONNECTION_TIMED_OUT
    # with every layer underneath healthy: pod running, policy applied as
    # written, DNS resolving, application answering from anywhere else.
    svcs = {"items": [
        {"metadata": {"namespace": "traefik"},
         "spec": {"selector": {"app.kubernetes.io/name": "traefik"},
                  "clusterIP": "172.16.0.9",
                  "ports": [{"port": 443, "targetPort": "websecure"},
                            {"port": 80, "targetPort": 8000},
                            {"port": 53, "protocol": "UDP"}]},
         "status": {"loadBalancer": {"ingress": [{"ip": "8.213.33.124"}]}}},
        {"metadata": {"namespace": "other"},              # a different address
         "spec": {"selector": {"app": "nope"}, "clusterIP": "172.16.9.9"}},
        {"metadata": {"namespace": "manual"},             # no pods to name
         "spec": {"clusterIP": "8.213.33.124"}},
    ]}
    saved_kc = webseat._kubectl
    try:
        webseat._kubectl = lambda cl, argv, to: type("R", (), {
            "returncode": 0, "stdout": json.dumps(svcs)})()
        found = webseat.serving_pods({"name": "c"}, ["8.213.33.124"])
        webseat._kubectl = lambda cl, argv, to: type("R", (), {
            "returncode": 1, "stdout": ""})()
        soft = webseat.serving_pods({"name": "c"}, ["8.213.33.124"])
    finally:
        webseat._kubectl = saved_kc
    check(f"the cluster's own Service answering on that address is found "
          f"({[f['namespace'] for f in found]})",
          [f["namespace"] for f in found] == ["traefik"])
    check("...named by ITS OWN selector, not by namespace alone",
          found[0]["selector"] == {"app.kubernetes.io/name": "traefik"})
    # A NetworkPolicy peer is the POD, so it is the pod's port that matters --
    # which is not always the port the Service is published on.
    check(f"...on the port the POD listens on ({found[0]['ports']})",
          found[0]["ports"] == ["websecure", 8000])
    check("...and a Service with no selector is skipped, having no pods",
          all(f["namespace"] != "manual" for f in found))
    check("...and a Service on other addresses is not allowed",
          all(f["namespace"] != "other" for f in found))
    # SOFT: a cluster this portal cannot list Services in gets exactly the
    # policy it got before, rather than no seat at all.
    check(f"a cluster that cannot be read simply adds nothing ({soft})",
          soft == [])

    hair = webseat.egress_policy("pam-web-aaaaaaaa", cfg,
                                 "https://app.example.net:8443/x",
                                 ["10.1.2.3"], tuple(found))
    peers = [t for r in hair["spec"]["egress"] for t in r.get("to", [])
             if "podSelector" in t]
    check(f"the seat may also reach that Service's pods ({len(peers)})",
          len(peers) == 1
          and peers[0]["podSelector"]["matchLabels"]
              == {"app.kubernetes.io/name": "traefik"}
          and peers[0]["namespaceSelector"]["matchLabels"][
              "kubernetes.io/metadata.name"] == "traefik")
    # NOT THE WHOLE CLUSTER, and not the whole namespace either: one element
    # carrying both selectors is an AND, so it is those pods in that namespace.
    check("...scoped to those pods IN that namespace, not either alone",
          all("podSelector" in t and "namespaceSelector" in t for t in peers))
    check("...and the target's own addresses are still named",
          any("ipBlock" in t for r in hair["spec"]["egress"]
              for t in r.get("to", [])))
    # REGRESSION GUARD: a target that is NOT served by this cluster must get
    # byte-for-byte the policy it got before this existed.
    check("a target outside the cluster gets exactly the old policy",
          webseat.egress_policy("pam-web-aaaaaaaa", cfg,
                                "https://app.example.net:8443/x",
                                ["10.1.2.3", "10.1.2.4"]
                                )["spec"]["egress"] == rules)

    print("a console opens as its own WINDOW")
    # ASKED FOR DIRECTLY: "when I click on a console the web page should open in
    # a pop up page where I can maximise, minimise and do whatever I can do in
    # the browser". Inside the portal a session sits under a sidebar and
    # breadcrumbs that take pixels from the application and offer nowhere to
    # navigate to, and it cannot be put beside the thing it is used to check.
    hub = (ROOT / "templates" / "pam.html").read_text()
    # EVERY console link, not just the first: the hub has one for a web target
    # and one for RDP/VNC, and a "connect" that still opens in the page is the
    # same complaint reported against a different row.
    console_links = re.findall(r"<a\b[^>]*?/console\b[^>]*?>", hub, re.S)
    check(f"every console link asks for a window ({len(console_links)} links)",
          len(console_links) >= 2
          and all("data-console-window" in a for a in console_links)
          and "window.open(" in hub)
    check("...and tells the page to drop the portal frame",
          "'win=1'" in hub or "+ 'win=1'" in hub or "win=1" in hub)
    # NAMED PER TARGET: clicking console twice for the same target focuses the
    # window already open instead of starting a SECOND seat -- two pods, two
    # recordings and two audit trails for one intent.
    check("...named per target, so a second click focuses rather than duplicates",
          "'envmap-console-' + a.getAttribute('href')" in hub
          and "win.focus()" in hub)
    # A BLOCKED POP-UP MUST NOT LOSE THE CLICK: `open` returns null and the
    # link is followed exactly as it was before this existed.
    # Scoped to THIS handler: the file has other click handlers with their own
    # preventDefault, and the first one in the file is not this one.
    opener = hub[hub.index("a[data-console-window]"):]
    opener = opener[:opener.index("</script>")]
    check("...and a blocked pop-up simply follows the link",
          "if (!win) return;" in opener
          and opener.index("if (!win) return;")
              < opener.index("ev.preventDefault()"))
    # Modified clicks belong to the browser: ctrl/cmd/shift-click and
    # middle-click open tabs and windows the way the person asked for.
    check("...and a modified click is left to the browser",
          "ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.button" in hub)
    # THE FRAME IS DROPPED IN THE TEMPLATE, not guessed from window.opener, so
    # a window that is reopened or bookmarked behaves as it did the first time.
    basehtml = (ROOT / "templates" / "base.html").read_text()
    check("base.html can render a page with no portal frame",
          "{% if not bare %}" in basehtml
          and "{{ self.content() }}" in basehtml
          and 'class="bare"' in basehtml)
    # And that layout lives in the CACHED sheet: every byte inline in base.html
    # is a byte on every page of every navigation, which the page-size budget
    # in test_speed.py exists to protect.
    appcss = (ROOT / "static" / "app.css").read_text()
    check("...and its layout is in the cached stylesheet, not on every page",
          "body.bare" in appcss and "body.bare" not in basehtml)

    print("...and the desktop asked for is the pane it will be shown in")
    # REPORTED against a console opened in its own window: "there is black bar
    # on top and bottom instead of having the full screen". Three numbers
    # described the same box -- the request took innerHeight*0.72, the fitter
    # took 0.78, and full screen measured the pane -- so the desktop that came
    # back was shorter than the pane and got centred in it. Letterboxing by
    # arithmetic.
    con = (ROOT / "templates" / "pam_console.html").read_text()
    # Checked against the CODE, not the file: the comment above the fix names
    # the old fraction, and a substring test over the whole file would pass on
    # its own explanation.
    code = "\n".join(l for l in con.split("\n")
                     if not l.strip().startswith(("//", "*", "/*")))
    check("the request no longer guesses a fraction of the window",
          "innerHeight * 0.72" not in code)
    check(f"...one function answers how tall the pane is, for both "
          f"({code.count('paneH()')} callers)",
          con.count("const paneH = ()") == 1 and code.count("paneH()") >= 2)
    # MEASURED WHEREVER THE HEIGHT IS REAL: its own window and full screen both
    # give the wrapper a resolved height. Inside the page it is a card with no
    # intrinsic height, so the viewport fraction is still all there is.
    check("...measured in its own window and in full screen",
          "if (isFull() || windowed)" in con and "wrap.clientHeight" in con)
    check("...and still a fraction of the window inside the page",
          "window.innerHeight * 0.78" in con)
    # A pane that short is not a pane -- layout may not be resolved on the
    # first call, and asking for a 480px desktop because of it is worse than
    # falling back.
    check("...with a floor, so an unresolved layout does not shrink the seat",
          "if (got > 300) return got;" in con)
    # FILL THE SURFACE WHERE THE PANE IS THE SURFACE. Capping the scale at 1 in
    # a window leaves the same black rectangle by another route.
    check("filling is what covers a screen the desktop does not fit",
          "fill ? Math.max(wrap.clientWidth / dw, paneH() / dh)" in con)
    # A `const` READ BEFORE ITS INITIALISER IS A ReferenceError, not undefined.
    # `paneH` runs while the connection parameters are built, which is long
    # before the fitter that used to be `isFull`'s only caller.
    check("...and isFull is declared before the code that calls it",
          con.index("const isFull =") < con.index("const paneH =")
          < con.index("function autoFit"))

    print("...and the seat's desktop carries THIS product's mark, not the vendor's")
    # REPORTED, twice: the Selenium Grid logo on the desktop. The browser image
    # paints it -- `start-vnc.sh` runs `fbsetbg -u Esetroot -c
    # /usr/share/images/fluxbox/ubuntu-light.png`, verified on a live seat --
    # and it shows for the second before the browser covers it, and again if a
    # session drops. Somebody else's branding on the inside of this product.
    wcfg = dict(cfg, web_image="selenium/standalone-chromium:latest")
    png = webseat.wallpaper_png(True)
    check("a background is produced without any imaging dependency",
          png[:8] == b"\x89PNG\r\n\x1a\n")
    import struct as _st                                      # noqa: PLC0415
    pw, ph, depth, ctype = _st.unpack(">IIBB", png[16:26])
    check(f"...a real PNG the browser image can read ({pw}x{ph}, type {ctype})",
          (pw, ph, depth, ctype) == (webseat.WALL_PX, webseat.WALL_PX, 8, 2))
    # Small enough to travel in the pod spec: a ConfigMap would be a second
    # object to create, update and delete with every seat, and one more thing
    # to leak when a pod dies unseen -- which has already happened once, to the
    # NetworkPolicies.
    check(f"...small enough to carry in the pod itself ({len(png)} bytes)",
          len(png) < 60_000)
    mf = webseat.manifest("pam-web-aaaaaaaa", wcfg, "", size=(1600, 900))
    mounts = {m["mountPath"]: m
              for m in mf["spec"]["containers"][0]["volumeMounts"]}
    check(f"it is mounted over the file the image actually uses",
          webseat.WALL_PATH in mounts
          and mounts[webseat.WALL_PATH].get("subPath") == "wall.png")
    # `subPath` replaces ONE file and leaves the rest of the image alone; such
    # a mount is read-only always, which is all that is wanted.
    check("...one file, read only, not the directory around it",
          mounts[webseat.WALL_PATH].get("readOnly") is True)
    init = mf["spec"]["initContainers"]
    check("...written by an init container, so nothing outlives the pod",
          len(init) == 1 and init[0]["name"] == "brand")
    check("...on the same image as the browser, so there is nothing to pull",
          init[0]["image"] == mf["spec"]["containers"][0]["image"])
    check("...and it drops every capability, like the browser beside it",
          init[0]["securityContext"]["capabilities"]["drop"] == ["ALL"])

    print("...and a desktop is never an ODD number of pixels")
    # Observed on a customer's session: a desktop of 1728x829 whose VNC link
    # died with guacd reporting "Error handling message from VNC server". Odd
    # dimensions are a long-standing sore point in the encoders underneath,
    # several of which work in 2x2 blocks. Not proof of the cause, and not
    # offered as one -- one pixel of height against a class of failure that is
    # expensive to diagnose and free to avoid.
    check(f"an odd pane height becomes an even framebuffer "
          f"({webseat.screen_of(wcfg, (1728, 829))})",
          webseat.screen_of(wcfg, (1728, 829)) == (1728, 828))
    check("...and an odd configured default too",
          webseat.screen_of({"rdp_width": 1281, "rdp_height": 801}) == (1280, 800))
    check("...never below the floor",
          all(v >= webseat.MIN_SCREEN
              for v in webseat.screen_of(wcfg, (321, 481))))
    # guacd must be told the size the framebuffer ACTUALLY has, or the two
    # disagree by a pixel and something scales that nobody asked for.
    _, gparams = pam.guac_web_params(
        type("S", (), {"vnc_host": "127.0.0.1", "vnc_port": 5900,
                       "vnc_password": ""})(), 1728, 829)
    check(f"...and guacd is told the same even size ({gparams['width']}x"
          f"{gparams['height']})",
          (gparams["width"], gparams["height"]) == ("1728", "828"))
    check("...asked for as an even number in the first place",
          "const even = v => Math.max(2, v - (v % 2));" in con)

    print("...and the picture is not encoded with only the two oldest formats")
    # The 166 KiB measured for one full-surface scroll was an encoder choosing
    # between PNG and JPEG, because the handshake declared nothing else. This
    # instruction is a CLIENT capability list -- what the browser can decode --
    # and every browser that runs guacamole-common-js decodes WebP, which is
    # materially smaller than JPEG at the same quality.
    mainsrc = (ROOT / "app" / "main.py").read_text()
    check("the browser's decodable formats include webp",
          mainsrc.count('pam.guac_instr("image", "image/webp",') == 2)
    # BOTH SOCKETS. A supervisor watching a session goes through the other one,
    # and declaring it on only the console would have left them the old volume.
    check("...on the watch socket as well as the console",
          mainsrc.count('"image/png", "image/jpeg"))') == 2)

    print("...and colour depth is a choice, not a silent downgrade")
    # Colour is the one dimension of that 166 KiB that can be traded
    # deliberately: 16 bits halves the pixel data and bands photographs. So it
    # is settable and ABSENT by default -- an absent parameter leaves guacd
    # doing exactly what every existing install already does.
    seatlike = type("S", (), {"vnc_host": "127.0.0.1", "vnc_port": 5900,
                              "vnc_password": ""})()
    pam.save_config(guac_color_depth="")
    _, d0 = pam.guac_web_params(seatlike, 1600, 900)
    check("by default no colour depth is sent at all",
          "color-depth" not in d0)
    pam.save_config(guac_color_depth="16")
    _, d16 = pam.guac_web_params(seatlike, 1600, 900)
    check(f"...set, it reaches guacd ({d16.get('color-depth')})",
          d16.get("color-depth") == "16")
    # The same trade on the same terms for a real desktop, or an operator on a
    # slow link fixes the browser seat and not the RDP session beside it.
    rdpt = pam.save_target("", {"name": "Depth RDP", "protocol": "rdp",
        "address": "10.9.9.9", "auth_kind": "none"}, "sys")
    _, dr = pam.guac_params(pam.target(rdpt), 1600, 900)
    check(f"...and an RDP target honours it too ({dr.get('color-depth')})",
          dr.get("color-depth") == "16")
    pam.save_config(guac_color_depth="")
    _, dr0 = pam.guac_params(pam.target(rdpt), 1600, 900)
    check("...and clearing it goes back to guacd's own default",
          "color-depth" not in dr0)
    # RDP got the even-dimension rounding as well, for the same reason.
    _, dodd = pam.guac_params(pam.target(rdpt), 1601, 829)
    check(f"...and an RDP desktop is even too ({dodd['width']}x{dodd['height']})",
          (dodd["width"], dodd["height"]) == ("1600", "828"))
    pam.delete_target(rdpt)

    print("...and a failure says what happened, not '[object Object]'")
    # REPORTED verbatim. A Guacamole failure is a `Guacamole.Status` with a
    # numeric code and often no message, and both handlers fell back to the
    # value itself -- so the header read "[object Object]" while the real fault
    # sat in guacd's log. A status nobody can read is a status nobody reports.
    check("a status object is never rendered as itself",
          "String(why)" not in con and "|| e, true)" not in con)
    check("...its code is turned into a sentence",
          "const REASON = {" in con and "typeof e.code === 'number'" in con)
    # The one that was actually happening, so the next person sees it.
    check("...including the upstream failure this hid",
          "0x0203:" in con and "0x0202:" in con)
    check("...and the code is still shown, for anyone matching it to a log",
          "' (code 0x' + e.code.toString(16) + ')'" in con)

    print("...and the desktop is cut to the SCREEN's shape, so full screen is exact")
    # A seat's screen is created with the pod and can never be resized, so the
    # ONE geometry it will ever have must suit both the window it is opened in
    # and the screen it is later put full screen on. A 1600x815 pane is 1.96
    # and a 16:9 screen is 1.78: fitting left 102px bands, filling cropped
    # 200px off the sides -- and on a right-to-left page that cuts the side the
    # content starts on. Reported twice. Neither had to happen: the shape of
    # the window is ours to choose.
    # Checked against the CODE: the comment above the change explains the
    # chrome allowance by name, and a substring test over the file would pass
    # on the explanation alone.
    hubcode = "\n".join(l for l in hub.split("\n")
                        if not l.strip().startswith(("//", "*", "/*", "{#", "#}")))
    check("the window is asked for in the screen's shape",
          "screen.width / screen.height" in hubcode
          and "Math.round(w / aspect) + CHROME" in hubcode)
    check("...and the console corrects that shape before asking for a desktop",
          "const screenAspect =" in con and "window.resizeBy(0, by)" in con)
    # A REQUEST, NOT A GUARANTEE: a window manager may refuse it, the screen may
    # have no room, and it may not have applied by the time the pane is read.
    check("...bounded by the screen, and never small enough to stop being one",
          "screen.availHeight - window.outerHeight" in con
          and "Math.max(240 - window.outerHeight" in con)
    # AND THE DESKTOP IS THE PANE, EXACTLY. It was briefly inscribed into the
    # screen's shape instead, so that full screen was exact even when the
    # reshape was refused -- and that was the wrong trade, reported at once: on
    # a real install it made a 1282x828 desktop inside a 1600-wide pane, so
    # every frame was stretched 1.25x. Bigger text, softer edges, and a
    # full-surface resample per frame on the path already complained about for
    # lag. It degraded the case somebody uses constantly to improve the one
    # they use occasionally.
    check("the desktop is the pane exactly, never a shape fitted inside it",
          "const dw = wrap.clientWidth, dh = paneH();" in con
          and "dw = dh * screenAspect" not in con)
    # Which means the scale in a window is 1, and is not allowed to be
    # anything else -- stretching a fixed framebuffer to cover a difference is
    # what made the page look nothing like the same page in the same browser.
    check("...so a window never scales past native",
          "if (!full) scale = Math.min(scale, 1);" in con)
    # Reshaping the WINDOW is still attempted, because when it works both
    # surfaces are exact; it is just no longer paid for by the window.
    insc = con[con.index("const screenAspect ="):con.index("const even = v =>")]
    check("...while the window's own shape is still corrected where allowed",
          insc.count("windowed && screenAspect > 0") == 1
          and "window.resizeBy(0, by)" in insc)

    print("...and full screen offers FILL, because the desktop cannot be resized")
    # A seat's Xvfb screen is created with the pod and cannot grow afterwards.
    # Measured on a real seat: "minimum 1 x 1, current 1600x815, maximum
    # 1600x815", and x11vnc is not started with resize support either. So a
    # 1600x815 desktop (1.96) on a 16:9 screen (1.78) either keeps its shape
    # and leaves bands top and bottom -- reported as "i can still see black
    # blank on top and bottom when i click on full screen" -- or fills the
    # screen and loses a strip off the edges. Neither is right for everybody,
    # so it is offered rather than chosen.
    check("there is a fill control beside fit",
          'id="conFill"' in con)
    # COVER, NOT CONTAIN: the LARGER ratio is what leaves no band.
    check("...filling covers the surface instead of fitting inside it",
          "fill ? Math.max(wrap.clientWidth / dw, paneH() / dh)" in con
          and ": Math.min(wrap.clientWidth / dw, paneH() / dh)" in con)
    # The overflow must stay reachable, which is why the wrapper centres with
    # `safe center` -- plain centring puts overflow on both sides and
    # scrollLeft cannot go negative, so half of it becomes unreachable.
    check("...and the overflow it creates can still be scrolled to",
          "align-items:safe center" in con.replace(" ", "").replace(
              "align-items:safecenter", "align-items:safe center"))
    check("the choice is remembered, and a refusal to store it is survivable",
          "localStorage.setItem('envmap.console.fill'" in con
          and con.count("catch (e) {}") >= 2)
    # THE LABEL IS THE STATE: `.on` is not styled for `.btn`, so a class would
    # say nothing to anybody.
    check("...and the button says what it will do next",
          "'⤡ Fit to window' : '⤢ Fill'" in con
          and "classList.toggle('on'" not in con)

    print("a page is rarely ONE host, and the confinement follows the page")
    # Measured on a customer's application: the page pulls its API from a
    # SECOND name on the same server -- already allowed by the egress policy,
    # since it resolves to the same address -- and its images from an object
    # store. Only `--host-resolver-rules` refused the API, because it excluded
    # exactly one NAME. So the landing page rendered, signing in could not
    # work, and nothing in the seat could say why.
    check("hosts are cleaned to bare names, folded and de-duplicated",
          webseat.also_hosts(["API.app.internal.", "api.app.internal",
                              "assets.app.internal"])
          == ["api.app.internal", "assets.app.internal"])
    # These become resolver-rule exclusions and are resolved for the policy, so
    # anything carrying a scheme, port, path or space is a rule that would not
    # mean what it looks like.
    for bad in ("https://api.app.internal/", "api.app.internal:443",
                "api.app.internal/x", "two words", "a@b", ""):
        check(f"...and {bad!r} is not accepted as a host",
              webseat.also_hosts([bad]) == [])
    check("...and the list is bounded",
          len(webseat.also_hosts([f"h{i}.example" for i in range(50)])) == 20)

    # AND THEIR ADDRESSES JOIN THE POLICY, or the browser could resolve a name
    # it still cannot reach -- which is the same blank page by another route.
    import socket as _sock                                  # noqa: PLC0415
    _saved_gai = _sock.getaddrinfo

    def _fake(h, *a, **k):
        known = {"app.example.net": "10.0.0.1", "api.example.net": "10.0.0.2"}
        if h not in known:
            raise OSError("no such host")
        return [(_sock.AF_INET, 0, 0, "", (known[h], 0))]
    try:
        _sock.getaddrinfo = _fake
        both = webseat.target_ips("https://app.example.net/", ["api.example.net"])
        alone = webseat.target_ips("https://app.example.net/")
    finally:
        _sock.getaddrinfo = _saved_gai
    check(f"an extra host's addresses are named in the policy too ({both})",
          both == ["10.0.0.1", "10.0.0.2"])
    check(f"...and a target without them names only its own ({alone})",
          alone == ["10.0.0.1"])

    # THE TARGET'S OWN failure to resolve is still fatal -- that is the
    # fail-closed path -- but an extra host that does not resolve is one asset
    # the page will do without, not a reason to refuse the seat.
    check("an extra host that does not resolve does not sink the seat",
          webseat.target_ips("https://localhost/",
                             ["does-not-resolve.invalid"]) != [])
    check("...but the target's own does",
          webseat.target_ips("https://does-not-resolve.invalid/",
                             ["localhost"]) == [])

    # A SPARE HAS NO TARGET YET, and must not be unrestricted while it waits.
    idle = webseat.idle_policy("pam-web-bbbbbbbb", cfg)
    check("a waiting spare gets DNS and nothing else",
          len(idle["spec"]["egress"]) == 1
          and all("ipBlock" not in t
                  for t in idle["spec"]["egress"][0].get("to", [])))
    # FAIL CLOSED. A target that cannot be resolved cannot be confined, and an
    # unconfined browser is the bug — so it is refused, not opened.
    why = webseat.lock_egress({"name": "c"}, cfg, "pam-web-aaaaaaaa",
                              "https://does-not-resolve.invalid/")
    check("an unresolvable target is REFUSED rather than left unconfined",
          "unrestricted browser" in why)
    # And the policy is applied before the browser can go anywhere.
    for path in ("claim_spare", "open_seat"):
        body = seat_src[seat_src.index(f"def {path}("):]
        body = body[:body.index("\ndef ", 10)]
        check(f"{path} locks egress before it opens the URL",
              "lock_egress(" in body
              and body.index("lock_egress(") < body.index("open_url("))
    check("and the policy is removed with the seat",
          "drop_policy(" in seat_src)

    print("...and a warm seat, because 36.9s cold is not a click")
    # MEASURED, not guessed: on a real cluster a cold seat was 36.9s to Ready
    # and a warm one 4.3s. Reported as "very very very slow". A spare is
    # already Running with the image, so a click is a label flip plus a
    # port-forward.
    seat_src = (ROOT / "app" / "webseat.py").read_text()
    check("open_seat claims a warm spare BEFORE creating anything",
          seat_src.index("claim_spare(cfg, url, sid")
          < seat_src.index('f"pam-web-{secrets.token_hex(4)}", sid'))
    # A SPARE IS NEVER A POD THAT SERVED BEFORE. The claim flips it out of the
    # pool, and the pool only ever contains pods that have served nobody — so
    # one-pod-per-session, the property the whole design rests on, is intact.
    check("claiming flips the label out of the pool rather than reusing",
          f'{"SPARE_LABEL"}=taken' in seat_src.replace('f"{SPARE_LABEL}=taken"',
                                                        'SPARE_LABEL=taken')
          or '=taken' in seat_src)
    # THE RACE THAT WOULD BREAK IT: two sessions listing the same spare and
    # both taking it would put two people in one browser. The claim is
    # optimistic concurrency on resourceVersion, so the loser is refused by
    # the API server and moves to the next candidate.
    check("the claim is a compare-and-set on resourceVersion",
          "--resource-version=" in seat_src
          and "somebody else won it" in seat_src)
    # READ AS JSON, NOT AS COLUMNS, and asserted by behaviour rather than by
    # a string in the file. A space-separated jsonpath drops an empty field and
    # every column after it shifts left; on the reaping path that once lined a
    # LIVE session up to be deleted. A spare built before the screen label
    # existed is exactly the row that would have shifted.
    scfg = dict(pam.config(), web_cluster="c-x", web_namespace="default")
    pods = {"items": [
        {"metadata": {"name": "pam-web-aaaaaaaa", "resourceVersion": "7",
                      "labels": {webseat.SCREEN_LABEL: "1410x679"}},
         "status": {"phase": "Running",
                    "containerStatuses": [{"ready": True}]}},
        {"metadata": {"name": "pam-web-bbbbbbbb", "resourceVersion": "8"},
         "status": {"phase": "Running",
                    "containerStatuses": [{"ready": False}]}},
        {"metadata": {"name": "pam-web-cccccccc", "resourceVersion": "9"},
         "status": {"phase": "Failed", "containerStatuses": [{}]}},
        {"metadata": {"name": "not-a-seat", "resourceVersion": "1"},
         "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}},
    ]}
    _keepsp = (webseat._clusters, webseat._kubectl, webseat.kube.base_args)
    try:
        webseat._clusters = lambda: {"c-x": {"name": "c"}}
        webseat.kube.base_args = lambda cl: ["kubectl"]
        webseat._kubectl = lambda cl, argv, to: type("R", (), {
            "returncode": 0, "stdout": json.dumps(pods)})()
        pool_read = webseat.spares(scfg)
    finally:
        (webseat._clusters, webseat._kubectl,
         webseat.kube.base_args) = _keepsp
    by = {sp["name"]: sp for sp in pool_read}
    check(f"only seats are read as spares ({sorted(by)})",
          "not-a-seat" not in by and len(by) == 3)
    check("and only a READY spare is offered, not one still pulling",
          by["pam-web-aaaaaaaa"]["ready"]
          and not by["pam-web-bbbbbbbb"]["ready"])
    check("a stopped spare is a corpse, not a spare",
          by["pam-web-cccccccc"]["dead"])
    # THE FIELD THAT WOULD HAVE SHIFTED: present on one, absent on the others,
    # and every other field still lands where it belongs.
    check(f"each spare carries the screen it was built with "
          f"({by['pam-web-aaaaaaaa']['screen']!r})",
          by["pam-web-aaaaaaaa"]["screen"] == "1410x679"
          and by["pam-web-bbbbbbbb"]["screen"] == ""
          and by["pam-web-aaaaaaaa"]["rv"] == "7"
          and by["pam-web-bbbbbbbb"]["rv"] == "8")
    # NOBODY GETS AN IDLE BROWSER BY UPGRADING — the pool touches nothing at
    # all while the feature itself is off.
    check("the pool does nothing while the feature is unavailable",
          'if why_unavailable(cfg):' in seat_src)
    cfg0 = dict(pam.config(), web_spares=0)
    check("and asking for zero spares creates none",
          webseat.ensure_spares(cfg0)["made"] == 0)
    # ZERO NO LONGER MEANS "IGNORE THE POOL", though: it means drain it. The
    # old rule returned before reaping, so turning the pool off stranded every
    # spare already running until its deadline — which is the opposite of what
    # somebody turning it off on a full cluster is asking for. See the drain
    # test below.
    check("...but zero is a DRAIN, not an early return",
          "for extra in have[want:]" in seat_src)
    check("the size is clamped to something sane",
          (pam.save_config(web_spares="99") or pam.config()["web_spares"]) <= 8)
    pam.save_config(web_spares=1)
    # The spare is replaced BEHIND the session, or the second click is slow
    # again.
    mn = (ROOT / "app" / "main.py").read_text()
    check("a claimed spare is replaced without the session waiting for it",
          "webseat.ensure_spares" in mn and "run_in_executor" in mn)
    warm = (ROOT / "app" / "warmer.py").read_text()
    check("and the pool is topped up on the periodic pass too",
          "webseat.ensure_spares(cfg)" in warm)
    # THE WAIT IS NARRATED. A blank pane and the word "waiting" for forty
    # seconds is what made this read as broken rather than slow.
    con = (ROOT / "templates" / "pam_console.html").read_text()
    check("the console page says what it is waiting for",
          "starting a browser in the cluster" in con)
    # AND DOES NOT INVENT A CAUSE, OR OUTLIVE THE SESSION. The first version
    # asserted "the image is being pulled onto the node" after 8s and counted
    # for ever, so a session that FAILED at 75s displayed "still starting
    # (268s)" with a made-up reason, having overwritten the real one two
    # seconds after it arrived.
    check("an error wins and stops the clock, rather than being talked over",
          "settled" in con and "stopWaiting()" in con
          and "if (settled && !final) return;" in con)
    # Checked as the CODE, not the words: the comment explaining this change
    # contains the phrase "tunnel error", so `"tunnel error" not in con`
    # matched my own prose — the third time that trap bit in this session.
    check("and the ws close REASON is shown verbatim, not a generic label",
          "e.reason" in con and "'tunnel error: '" not in con)
    # A failure has to be diagnosable from the server too: a close reason
    # lives only in the browser that received it.
    mn2 = (ROOT / "app" / "main.py").read_text()
    check("a failed seat is audited with its reason",
          "pam_console_failed" in mn2)
    check("and the refusal names which step it failed at",
          "(while {step})" in seat_src or "while {step}" in seat_src)

    print("...and a guac recording PAINTS on arrival, not only on play")
    # REPORTED AS "the record is blank". It was not: the recording was 1.77MB,
    # integrity verified, 177 frames over 4kB each, and 99% lit from 0 to 85%.
    # A Guacamole display is 0x0 until a frame is APPLIED, so the page opened
    # as an empty box and stayed one until somebody pressed play. Measured in a
    # browser against that real recording.
    rep = (ROOT / "templates" / "pam_session.html").read_text()
    check("the player paints a poster frame without being asked",
          "rec.onload" in rep and "rec.seek(" in rep)
    # ON `onload`, NOT `onprogress`: a seek issued while the recording is still
    # downloading is dropped, which is how the first attempt at this fix
    # changed nothing at all.
    prog = rep[rep.index("rec.onprogress ="):]
    prog = prog[:prog.index("rec.onload")]
    check("and it hangs off onload, because a seek mid-download is dropped",
          "rec.seek(" not in prog)
    # NOT to zero: at 0ms that recording's framebuffer was 0% lit and at 500ms
    # it was 100% lit, so zero would poster the very blank frame this avoids.
    check("seeking slightly in, since frame zero is the blank one",
          "Math.min(1500" in rep)
    # A seat records at its own size (1280x800), which overflowed a narrower
    # card until the display was scaled to it.
    check("the display is scaled to the card it sits in",
          "display.scale(" in rep and "clientWidth" in rep)

    print("the guacd stream is re-framed on instruction boundaries, whatever "
          "the chunking")
    # guacamole-common-js parses each WebSocket MESSAGE on its own and errors
    # ("Invalid array length") if one ends mid-instruction -- it keeps no buffer
    # across messages. guacd's TCP stream splits wherever the read landed, so
    # this is the piece that must never be wrong. It had no test at all.
    def _mk(*parts):
        return ",".join("%d.%s" % (len(str(x)), x) for x in parts) + ";"
    stream = (_mk("size", 0, 1024, 768)
              + _mk("img", 1, 14, "data;with;semis")   # ';' INSIDE a value
              + _mk("blob", 1, "x" * 5000)             # bigger than a read
              + _mk("sync", 123456)
              + _mk("nop"))
    for chunk in (1, 2, 7, 64, 997, 4096, len(stream)):
        fr = pam.GuacFramer()
        got, ends = "", []
        for i in range(0, len(stream), chunk):
            out = fr.feed(stream[i:i + chunk])
            if out:
                got += out
                ends.append(out)
        check(f"every byte comes out in order at chunk={chunk}",
              got == stream and fr.buf == "")
        # THE WHOLE POINT: a message may never end inside an instruction.
        check(f"...and no message ends mid-instruction at chunk={chunk}",
              all(m.endswith(";") for m in ends)
              and all(pam.GuacFramer().feed(m) == m for m in ends))
    # A ';' inside a value is NOT a boundary -- the length prefix is.
    fr = pam.GuacFramer()
    one = fr.feed(_mk("img", 1, 14, "data;with;semis"))
    check(f"a semicolon inside a value does not end an instruction ({one!r})",
          one == _mk("img", 1, 14, "data;with;semis"))
    # An incomplete tail is HELD, not forwarded.
    fr = pam.GuacFramer()
    check("a partial instruction is held back until it completes",
          fr.feed("4.sync,3.12") == "" and fr.feed("3;") == "4.sync,3.123;")

    print("...and re-framing stays linear on the frames that matter")
    # KEPT AS A GUARD, NOT AS A FIX. Chased as a suspect for a laggy console --
    # `feed` restarts at index 0 each call and `buf += text` looks like a copy
    # per read -- and then MEASURED: 0.2ms for a 400kB instruction, 0.5ms for a
    # megabyte, because the scan jumps by length prefixes and CPython appends
    # in place when it holds the only reference. It is not the bottleneck and
    # was not optimised. This is here so a future change that IS quadratic is
    # caught, and because a component whose failure shows as "Invalid array
    # length" in somebody's console had no test at all.
    big = _mk("blob", 1, "y" * 400000) + _mk("sync", 1)
    fr = pam.GuacFramer()
    t0 = time.monotonic()
    for i in range(0, len(big), 16384):
        fr.feed(big[i:i + 16384])
    slow = time.monotonic() - t0
    # A REAL NUMBER, not a loose bound. The first version of this asserted
    # only "under 0.25s", which would have passed at 200ms per frame -- and
    # 200ms per frame would have been the whole lag complaint, hidden behind a
    # test that said the code was fine. Measured: 0.07ms for a 195 KiB frame.
    check(f"a 400kB instruction in 16kB reads is not quadratic ({slow*1000:.2f}ms)",
          slow < 0.02)
    # AND THE RELAY READS IN BIG CHUNKS, so one frame becomes one websocket
    # message rather than five, each of which costs a header here and a parse
    # in the browser's tunnel.
    check("the relay reads far more than one instruction at a time",
          "GUAC_READ = 262144" in (ROOT / "app" / "main.py").read_text()
          and (ROOT / "app" / "main.py").read_text().count(
              "await reader.read(GUAC_READ)") == 2)

    print("...and the 'preparing' caption is on the pane, not beside it")
    # REPORTED with a screenshot: in full screen the message sat down the
    # LEFT-HAND EDGE, next to a recording that was visibly playing. `.rec-wrap`
    # becomes a flex ROW in full screen, so a block in flow becomes a column
    # beside the picture. A caption about the pane belongs ON the pane.
    check("it is taken out of the flow and centred over the pane",
          ".rec-prep { position:absolute; inset:0;" in rep
          and "pointer-events:none" in rep)
    check("...and the pane it covers is the positioning context",
          ".rec-wrap {" in rep and "position:relative; }" in rep)
    # AND IT GOES AS SOON AS THERE IS SOMETHING TO SEE. A Guacamole display is
    # 0x0 until a frame is applied, so that is the moment the pane stops being
    # empty -- long before the last byte arrives. Saying "preparing" over a
    # recording that is already playing is simply wrong.
    check("it goes when the first frame lands, not when the file finishes",
          "if (ready || display.getWidth() > 0) { prepEl.remove();" in rep)

    print("...and the seek bar does not DANCE while the file is parsing")
    # REPORTED: "when I open the record for the first time it is jumping to the
    # middle and start dancing, after maybe 30 second it will become stable".
    # It was: `onprogress` reports the duration parsed SO FAR and it grows, and
    # the bar was scaled to it -- so `value/max` moved because MAX moved. The
    # session in the report was 81s and 15.7MB; a few seconds in the player
    # called it 20s, which put the playhead at 10/20, halfway, and then walked
    # it backwards for the half-minute the file took to parse.
    prog2 = rep[rep.index("rec.onprogress ="):]
    prog2 = prog2[:prog2.index("rec.onload")]
    check("parsing progress no longer sets the duration from what it parsed",
          "dur = d;" not in prog2)
    check("...and the bar's scale only moves for a row that has no length",
          "if (total <= 0) { dur = Math.max(dur, d); seek.max = dur; }" in prog2)
    # The row has known the true length all along.
    check("the total comes from the session row, so it is right at once",
          'max="{{ (s.seconds or 0) * 1000 }}"' in rep
          and 'data-total="{{ (s.seconds or 0) * 1000 }}"' in rep)
    # An older row with no recorded length keeps the previous behaviour, but
    # monotonically -- it may still grow, it may not jump about.
    check("...and a row with no length still only ever grows",
          "dur = Math.max(dur, d)" in rep)
    # WHAT IT SHOWS INSTEAD: how much is actually seekable. Until the file is
    # parsed a seek past the parsed point is dropped, so dragging there does
    # nothing -- which is why the control says so rather than letting somebody
    # discover it.
    check("how much is seekable is shown, not discovered by dragging",
          "--buf" in rep and "rec-buf" in rep)
    # AND EVERYTHING THAT SEEKS AIMS AT WHAT IS READ. Past the parsed point a
    # seek is silently dropped and its callback never arrives -- which stopped
    # the chain that drives every rate above 1x, reported as "when I click
    # pause and replay or play again it is stuck". Disabling the control until
    # the whole file was parsed was worse than the problem: half a minute of
    # not being able to move at all, in a player that was already playing.
    check("the bar stays usable while loading, within what is ready",
          "seek.disabled = true" not in rep and "const seekable = ()" in rep)
    check("...the fast-forward stepper aims at what is read, not the total",
          "const end = seekable();" in rep
          and "target = Math.min(end, target + STEP * rate);" in rep)
    check("...and the slider cannot ask for a position that would be dropped",
          "Math.min(+seek.value, seekable())" in rep)
    # Once parsed, the PLAYER's duration is the authority: the row is whole
    # seconds and the file ends where it ends. Trusting the row past that point
    # meant `atEnd` never became true, so a finished recording would not
    # replay, and the stepper aimed past the last frame and stopped dead.
    check("once loaded, the player's own duration takes over",
          "if (real > 0) dur = real;" in rep)
    # AND THE PANE SAYS WHAT IT IS DOING. A Guacamole display is 0x0 until a
    # frame is applied and the first frame cannot be painted until the file is
    # parsed, so the box was blank for that whole half-minute.
    check("the empty pane says it is preparing, with how far along",
          "preparing recording" in rep)
    # ONE PLACE PAINTS IT. The label and the thumb were written from four
    # handlers and drifted apart; a clock and a thumb that disagree read as
    # broken even when both are nearly right.
    # Counted within the DESKTOP player only: the SSH replay further down the
    # same file has a clock of its own and is not what this is about.
    gjs = rep[rep.index("const play = document.getElementById('gPlay')"):
              rep.index('id="recSeek"')]
    check(f"the clock and the thumb are painted together, not separately "
          f"({gjs.count('timeEl.textContent')} writes)",
          gjs.count("timeEl.textContent") == 1)

    print("...and a FINISHED recording plays again")
    # REPORTED: "when I finish watching the record and I try to click play
    # again it is not working". Both paths were silently no-ops at the end and
    # for different reasons — `rec.play()` has nothing left to play, and the
    # stepper's first target is already the duration, so it seeked to the end
    # and set itself back to stopped. Reproduced in a browser against a real
    # 1:24 recording: at 1:24/1:24 the click moved nothing at all.
    check("pressing play at the end rewinds first",
          "if (atEnd()) { rec.seek(0, beginPlay); return; }" in rep)
    check("...to the START, not to the poster offset",
          "rec.seek(0, beginPlay)" in rep)
    # `const` is NOT hoisted, and `onpause` can fire while the recording is
    # still loading — so a handler calling atEnd before its declaration would
    # have thrown a ReferenceError instead of setting a label.
    check("atEnd is declared before every handler that calls it",
          rep.index("const atEnd =") < rep.index("rec.onpause =")
          and rep.index("const atEnd =") < rep.index("rec.onseek ="))
    # The tolerance matters: a recording rarely stops on a round number, so an
    # exact `>= dur` test leaves a player that is visibly finished and still
    # refuses to start.
    check("the end test has slack for a last frame that lands short",
          "END_SLACK" in rep and "dur - END_SLACK" in rep)
    # AND THE BUTTON SAYS WHICH STATE IT IS IN. A finished player offering
    # "play" is the control that did nothing; it reads replay now, and the
    # stepper's own end branch has to agree or 8x ends in a lying button.
    check("a finished player offers replay rather than play",
          rep.count("'\u21bb replay'") >= 3)
    # The slider's handler calls stopPlay() before the seek lands, so it reads
    # the OLD position — the label is settled in onseek, once it is real.
    seekh = rep[rep.index("rec.onseek ="):]
    seekh = seekh[:seekh.index("rec.onplay =")]
    check("and dragging to the end relabels too, after the seek lands",
          "atEnd()" in seekh)

    print("a setting left out of a save KEEPS its value, never the floor")
    # FOUND ON A CUSTOMER INSTALL where every numeric web setting sat exactly
    # on its minimum — ports at 1, spares at 0, every timeout at its floor.
    # Nobody types that. The route reads the form with `f.get(...)`, so a
    # control missing from the POST arrives as None with its KEY PRESENT,
    # which slipped past "absent keeps its value" and was then normalised to
    # 0 and clamped UP to the minimum. The visible result was a readiness
    # probe against port 1, which nothing answers, so every browser they
    # opened "never became ready" — and nothing on the page looked wrong.
    # NON-DEFAULT values on purpose: with the defaults, "kept its value" and
    # "fell back to the default" look identical and the test proves neither.
    # Both bites passed against the broken code until this was changed.
    pam.save_config(web_vnc_port=5901, web_driver_port=4445, web_ttl=1801,
                    web_spares=2, web_ready_timeout=601, web_page_timeout=21)
    before = pam.config()
    check("the fixture really is off the defaults",
          before["web_vnc_port"] != pam.DEFAULTS["web_vnc_port"]
          and before["web_ttl"] != pam.DEFAULTS["web_ttl"])
    pam.save_config(enabled=True, allow_connect=True, web_vnc_port=None,
                    web_driver_port=None, web_ttl=None, web_spares=None,
                    web_ready_timeout=None, web_page_timeout=None)
    after = pam.config()
    for k in ("web_vnc_port", "web_driver_port", "web_ttl", "web_spares",
              "web_ready_timeout", "web_page_timeout"):
        check(f"{k} survives a save that omits it ({after[k]})",
              after[k] == before[k])
    # A number box submitted EMPTY is the same thing: it cannot mean "the
    # smallest legal value", which is what it used to mean.
    pam.save_config(web_vnc_port="", web_driver_port="   ")
    blank = pam.config()
    check(f"a blank number box keeps the value too ({blank['web_vnc_port']})",
          blank["web_vnc_port"] == 5901 and blank["web_driver_port"] == 4445)
    # ...while a real edit must still take effect, or this trades one silent
    # failure for another.
    pam.save_config(web_vnc_port=6000)
    check("but a real change still applies", pam.config()["web_vnc_port"] == 6000)
    # Text and booleans keep their own rules: a cleared text field is a
    # deliberate clear, and an unchecked box is passed as False on purpose.
    pam.save_config(web_seat_host="somewhere:1234")
    pam.save_config(web_seat_host="")
    check("a cleared TEXT field still clears",
          pam.config()["web_seat_host"] == "")
    pam.save_config(web_browser=False)
    check("and an unchecked box still switches off",
          pam.config()["web_browser"] is False)
    pam.save_config(web_vnc_port=5900, web_driver_port=4444, web_browser=True)
    # A STORE THAT ALREADY HOLDS A BLANK — from a version that wrote one
    # before the rule above existed — must read as the DEFAULT, never as the
    # floor. This is the half that repairs an install rather than preventing
    # one, so it is exercised at the store, which is the only way to reach it
    # now that save_config filters blanks out.
    from app import store as _store                            # noqa: PLC0415
    raw = dict(_store._setting("pam"))
    raw["web_vnc_port"] = ""
    raw["web_ttl"] = None
    _store._set_setting("pam", raw)
    healed = pam.config()
    check(f"a blank already in the store reads as the default, not the floor "
          f"({healed['web_vnc_port']}, {healed['web_ttl']})",
          healed["web_vnc_port"] == pam.DEFAULTS["web_vnc_port"]
          and healed["web_ttl"] == pam.DEFAULTS["web_ttl"])

    print("...and a seat that COULD NOT work is refused before it is built")
    # A customer ran for days with both browser ports set to 1 — collapsed
    # there by the settings save above, not typed — so every seat was probed
    # on port 1, every browser "never became ready", and nothing in the
    # product said a word. The pod's own describe made it obvious in one
    # line: `Readiness: http-get http://:1/status`. The portal could have
    # known before it built the pod.
    setp = (ROOT / "templates" / "set_pam.html").read_text()
    from app import kmanage as _km, kube as _kube               # noqa: PLC0415
    keep = (webseat._clusters, _kube.base_args, _km.writable)
    webseat._clusters = lambda: {"c-x": {"id": "c-x", "name": "theirs"}}
    _kube.base_args = lambda c: ["kubectl"]
    _km.writable = lambda c: True
    try:
        base = dict(pam.config(), web_browser=True, web_cluster="c-x",
                    web_namespace="default", guacd_host="127.0.0.1",
                    web_seat_host="")
        # NOT named `bad`: that is this file's failure counter, and assigning
        # it inside main() makes it a local — the summary then prints a
        # message instead of a count. Documented once already this session
        # and repeated anyway, which is what a trap is.
        nope = webseat.why_unavailable(dict(base, web_driver_port=1,
                                            web_vnc_port=1))
        check(f"an impossible WebDriver port is refused ({nope[:40]}…)",
              "WebDriver port" in nope and "1" in nope)
        check("...and the message names the value to put back",
              "4444" in nope)
        vnc = webseat.why_unavailable(dict(base, web_driver_port=4444,
                                           web_vnc_port=80))
        check("a privileged VNC port is refused too, naming 5900",
              "VNC port" in vnc and "5900" in vnc)
        ok = webseat.why_unavailable(dict(base, web_driver_port=4444,
                                          web_vnc_port=5900))
        check(f"and correct ports raise no objection ({ok[:30]!r})", ok == "")
        # A DIRECTION IS ONLY USEFUL FROM WHERE THE READER IS STANDING. The
        # first version sent somebody to "Settings → Privileged Access" while
        # they were already on that page looking straight at the box, and
        # they had to ask where the option was. Name the ROW.
        check("the message names the row, not the page they are already on",
              "ports & password" in nope
              and "Settings → Privileged Access" not in nope)
    finally:
        webseat._clusters, _kube.base_args, _km.writable = keep

    # And the row itself puts each label BEFORE its input. Trailing labels
    # read as "[1] VNC [1] WebDriver", where the eye cannot tell whether a box
    # is the thing named after it or before it.
    ports = setp[setp.index("ports &amp; password"):]
    ports = ports[:ports.index("</div></div>")]
    check("each port label comes before its own input",
          ports.index("VNC</span>") < ports.index('name="web_vnc_port"')
          and ports.index("WebDriver</span>") < ports.index('name="web_driver_port"'))
    check("...and the boxes carry the right defaults as placeholders",
          'placeholder="5900"' in ports and 'placeholder="4444"' in ports)

    print("the seat is built for the screen it will be READ on")
    # Reported: "the dimension looks so bad for the page, it is not the same as
    # when I connect directly using my device browser". It was not the same:
    # the seat rendered at a configured size shared with RDP and the console
    # then scaled that picture into whatever pane the person had -- so the
    # image was resampled AND the application laid itself out for a viewport
    # nobody was looking at. A 1280x800 page shown at 85% in a 1410x679 pane.
    webseat._screen_seen = ()
    base_cfg = dict(pam.config(), web_namespace="browsers")
    dflt = (int(base_cfg["rdp_width"]), int(base_cfg["rdp_height"]))
    check(f"with no client size the configured screen is used ({dflt})",
          webseat.screen_of(base_cfg) == dflt)
    # An EVEN size, so this tests the match and not the rounding -- an odd
    # pane height is rounded down, and that has its own tests above.
    check("with a client size, the seat is built at exactly that size",
          webseat.screen_of(base_cfg, (1410, 680)) == (1410, 680))
    # It arrives from a browser, so it is bounded: a seat asked for 30000
    # pixels of framebuffer is a way to spend a node's memory, not to see a
    # page.
    for absurd in ((99999, 600), (10, 10), (0, 0), ("x", None), (1410, 99999)):
        check(f"...and {absurd} falls back to the configured screen",
              webseat.screen_of(base_cfg, absurd) == dflt)
    env = {e["name"]: e["value"] for e in
           webseat.manifest("pam-web-aaaaaaaa", base_cfg, "",
                            size=(1410, 680))["spec"]["containers"][0]["env"]}
    check(f"the pod's screen is the client's ({env['SE_SCREEN_WIDTH']}x"
          f"{env['SE_SCREEN_HEIGHT']})",
          (env["SE_SCREEN_WIDTH"], env["SE_SCREEN_HEIGHT"]) == ("1410", "680"))
    lbl = webseat.manifest("pam-web-aaaaaaaa", base_cfg, "",
                           size=(1410, 680))["metadata"]["labels"]
    check("...and the pod says which screen it has, so a claim can tell",
          lbl.get(webseat.SCREEN_LABEL) == "1410x680")
    # A SPARE OF THE WRONG SHAPE IS NOT A SAVING: claiming it puts the person
    # back where they started. The pool learns the size actually in use.
    check("a spare is built for the screen this install is really read at",
          webseat.wanted_screen(base_cfg) == dflt)
    webseat.remember_screen(1410, 680)
    check("...which the last real console teaches it",
          webseat.wanted_screen(base_cfg) == (1410, 680))
    webseat.remember_screen(0, 0)
    check("...and junk does not un-teach it",
          webseat.wanted_screen(base_cfg) == (1410, 680))
    webseat._screen_seen = ()

    print("...and turning the spare pool OFF drains it")
    # Found on a cluster that was FULL. Setting the pool to zero used to
    # return before reaping, so every spare already running was stranded until
    # its own deadline killed it — each holding a memory request and a pod
    # slot the whole time. Turning the pool off to free room did the opposite,
    # and the fresh seat that replaced the claim could not be scheduled:
    # "0/2 nodes are available: 1 Insufficient memory, 1 Too many pods". Off
    # has to mean off NOW, or the setting cannot be used to recover from the
    # situation it is most needed in.
    killed2: list = []
    webseat._screen_seen = ()
    _scr = "%dx%d" % webseat.wanted_screen(pam.config())
    pool = [{"name": "pam-web-11111111", "rv": "1", "phase": "Running",
             "ready": True, "dead": False, "screen": _scr},
            {"name": "pam-web-22222222", "rv": "2", "phase": "Running",
             "ready": True, "dead": False, "screen": _scr}]
    keep2 = (webseat.spares, webseat._clusters, webseat.delete,
             webseat.drop_policy, webseat.why_unavailable)
    try:
        webseat.spares = lambda cfg: list(pool)
        webseat._clusters = lambda: {"c-x": {"name": "c"}}
        webseat.delete = lambda cl, ns, n: killed2.append(n)
        webseat.drop_policy = lambda cl, ns, n: None
        webseat.why_unavailable = lambda cfg: ""
        got2 = webseat.ensure_spares(dict(pam.config(), web_spares=0,
                                          web_cluster="c-x",
                                          web_namespace="default"))
        check(f"a pool set to zero deletes the spares it left behind "
              f"({sorted(killed2)})", len(killed2) == 2)
        check("...and reports having none", got2["have"] == 0)
        # And a pool of one keeps one and drops the surplus, or reducing the
        # size would leave the extras stranded in the same way.
        killed2.clear()
        webseat._run = webseat._run
        got1 = webseat.ensure_spares(dict(pam.config(), web_spares=1,
                                          web_cluster="c-x",
                                          web_namespace="default"))
        check(f"a smaller pool drops only the surplus ({killed2})",
              len(killed2) == 1)
    finally:
        (webseat.spares, webseat._clusters, webseat.delete,
         webseat.drop_policy, webseat.why_unavailable) = keep2

    print("...and a seat can be SIZED to the cluster it runs in")
    # These were fixed in code, so an install whose nodes cannot spare 768Mi
    # and a pod slot had no way to make a seat fit — and the failure it got
    # was the scheduler's, after the click, rather than a number it could
    # change.
    setp2 = (ROOT / "templates" / "set_pam.html").read_text()
    for f in ("web_cpu_req", "web_mem_req", "web_cpu_lim", "web_mem_lim"):
        check(f"{f} can be edited on the settings page",
              f'name="{f}"' in setp2)
        check(f"...and {f} is read back by the save handler",
              f'{f}=f.get("{f}")' in (ROOT / "app" / "main.py").read_text())

    print("a silent gateway is DIAGNOSED, not guessed at")
    # A customer sent a screenshot of this card telling them to set
    # `guacd.enabled: true` — a value that has been the default since 0.7.3.
    # The message asserted one cause whenever the socket was silent; the
    # Deployment knows which of three it actually is, so it is asked.
    from app import selfupdate                                 # noqa: PLC0415
    keep_state, keep_reach = selfupdate.gateway_state, pam.guacd_reachable
    try:
        pam.guacd_reachable = lambda: False
        selfupdate.gateway_state = lambda: {"how": "absent", "why": "x"}
        why = pam.guacd_why()
        check(f"absent says the container is not there ({why[-60:]})",
              "no gateway container" in why)
        check("...and does not repeat the stale advice about a default value",
              "set `guacd.enabled: true`" not in why)
        selfupdate.gateway_state = lambda: {"how": "present", "why": "x"}
        why = pam.guacd_why()
        check(f"present sends them to the logs instead ({why[-52:]})",
              "logs" in why and "no gateway container" not in why)
        selfupdate.gateway_state = lambda: {"how": "unknown", "why": "no rbac"}
        why = pam.guacd_why()
        check("unknown falls back to the general advice",
              "guacd.enabled" in why)
        # SSH IS UNAFFECTED and every branch has to keep saying so — it is the
        # difference between "one protocol is unavailable" and "the feature is
        # broken", which is how this was read the first time.
        for how in ("absent", "present", "unknown"):
            selfupdate.gateway_state = lambda h=how: {"how": h, "why": "x"}
            check(f"...and {how} still says SSH does not need it",
                  "SSH" in pam.guacd_why())
    finally:
        selfupdate.gateway_state, pam.guacd_reachable = keep_state, keep_reach

    print("no template nests a <form>, because the browser drops the inner one")
    # HTML DOES NOT NEST FORMS. The inner one is discarded and its button
    # becomes an ordinary submit for the OUTER form — so it looks like it
    # worked (the page comes back saying "saved") while the route it named was
    # never called. Reported exactly that way, on the gateway button, in a
    # page that already did it correctly with `formaction` two hundred lines
    # further down. Swept over every template, because the next one to do this
    # will not be this one.
    import re as _re
    for tpl in sorted((ROOT / "templates").glob("*.html")):
        body = _re.sub(r"\{#.*?#\}", "", tpl.read_text(), flags=_re.S)
        depth = worst = 0
        for tok in _re.findall(r"</?form\b", body):
            depth += 1 if tok == "<form" else -1
            worst = max(worst, depth)
        check(f"{tpl.name} never opens a form inside a form (depth {worst})",
              worst <= 1)

    print("...and the page offers to FIX it, where it can")
    setp = (ROOT / "templates" / "set_pam.html").read_text()
    check("there is a button, not only an instruction",
          '/settings/pam/gateway/start' in setp)
    # It reaches that route the way this page already reaches its other one.
    check("...which it reaches by formaction, not a form inside a form",
          'formaction="/settings/pam/gateway/start"' in setp)
    # OFFERED ONLY WHERE IT WOULD WORK: the container is genuinely missing AND
    # this install granted the portal permission over its own Deployment.
    check("...shown only when the container is absent and the grant exists",
          "{% if gw.how == 'absent' and gw_grant %}" in setp)
    check("...and without the grant it names THAT, not the Helm value alone",
          "rbac.selfUpdate=true" in setp)
    check("...and when it cannot look, it says so rather than guessing",
          "{% elif gw.how == 'unknown' and gw.why %}" in setp)
    # "I cannot tell" on its own leaves somebody where they started — and this
    # is the branch a default install lands in, because the portal is granted
    # nothing over its own namespace. A CUSTOMER ON THE LATEST RELEASE hit
    # exactly this, so it hands over the one command that answers it, with
    # their own namespace and deployment already in it.
    check("...and hands over the command that answers it",
          "gw.check" in setp)
    from app import selfupdate as _su                          # noqa: PLC0415
    cmd = _su._check_command()
    check(f"which names the container list, not a shape to fill in ({cmd[-44:]})",
          "get deploy" in cmd and "containers[*].name" in cmd)
    # A DIAGNOSIS MUST NOT BE ABLE TO BREAK THE PAGE IT IS DRAWN ON.
    keep_dep = _su._deployment
    try:
        _su._deployment = lambda fresh=False: (_ for _ in ()).throw(
            RuntimeError("boom"))
        _su.in_cluster = lambda: True
        got = _su.gateway_state()
        check(f"a failing diagnosis degrades to unknown ({got.get('how')})",
              got.get("how") == "unknown" and "boom" in got.get("why", ""))
    finally:
        _su._deployment = keep_dep
    # THE TWO COSTS, on the button rather than discovered afterwards.
    check("the confirm warns that the portal restarts",
          "RESTARTS" in setp)
    check("...and that a pull it cannot satisfy stops the whole pod",
          "whole pod stops" in setp)
    check("...and that Helm will undo it",
          "guacd.enabled=true" in setp and "helm upgrade" in setp)
    # A SIDECAR THAT CANNOT BE PULLED TAKES THE PORTAL DOWN, so a mirrored or
    # air-gapped install must be able to point this somewhere else first.
    check("the gateway image is configuration, not a constant",
          'name="guacd_image"' in setp
          and pam.DEFAULTS["guacd_image"].startswith("guacamole/guacd:"))
    msrc = (ROOT / "app" / "main.py").read_text()
    check("and the form's value is actually saved",
          'guacd_image=f.get("guacd_image")' in msrc)
    # FOUND WHILE WIRING THAT: the page has had a `web_page_timeout` field
    # since 0.7.4 and the handler never read it, so editing it did nothing.
    check("...as is web_page_timeout, which had a field and no reader",
          'web_page_timeout=f.get("web_page_timeout")' in msrc)
    # It must refuse rather than half-act when the grant is absent.
    keep_en = selfupdate.enabled
    try:
        selfupdate.enabled = lambda: False
        try:
            selfupdate.add_gateway("guacamole/guacd:1.5.5")
            check("adding the gateway without permission is refused", False)
        except selfupdate.UpdateError as e:
            check(f"adding the gateway without permission is refused ({e!s:.44})",
                  "rbac.selfUpdate" in str(e))
    finally:
        selfupdate.enabled = keep_en

    print("...and a missing gateway says what to DO about it")
    # THE WHOLE POINT. "the gateway is not reachable" is true and useless: the
    # default arrangement is a sidecar in this very pod, so the only way it is
    # absent is that the chart did not deploy it — a Helm value nobody can find
    # from inside the portal. An evening went into concluding the feature was
    # broken when the fix was one line.
    was_h, was_p = pam.config()["guacd_host"], pam.config()["guacd_port"]
    pam.save_config(guacd_host="127.0.0.1", guacd_port=4823)
    why = pam.guacd_why()
    check("a loopback gateway that is absent names the Helm value",
          "guacd.enabled" in why and "upgrade" in why)
    check("and says SSH is unaffected, so the reader knows the scope",
          "SSH" in why)
    check("and it names the address it actually tried",
          "127.0.0.1:4823" in why)
    # A DIFFERENT SENTENCE when somebody pointed it elsewhere: telling them to
    # set a chart value would be wrong, and wrong advice is worse than none.
    pam.save_config(guacd_host="10.0.0.9", guacd_port=4822)
    remote = pam.guacd_why()
    check("a remote gateway is not told to change the chart",
          "guacd.enabled" not in remote
          and "Settings → Privileged Access" in remote
          and "10.0.0.9:4822" in remote)
    pam.save_config(guacd_host=was_h, guacd_port=was_p)
    # ONE definition, used by every surface — a reason written twice is one of
    # them going stale.
    page = (ROOT / "templates" / "pam.html").read_text()
    setp = (ROOT / "templates" / "set_pam.html").read_text()
    check("the catalogue row uses it rather than its own wording",
          "guacd_why" in page
          and "the RDP/VNC gateway (guacd) is not reachable" not in page
          and "the gateway (guacd) is not reachable" not in page)
    check("and so does the settings page", "guacd_why" in setp)
    # THE DEFAULT. A feature that renders a row and a tile and cannot work is
    # worse than one that is absent.
    vals = (ROOT / "deploy" / "helm" / "config-portal" / "values.yaml").read_text()
    gblock = vals[vals.index("\nguacd:"):]
    gblock = gblock[:gblock.index("\nollama:")] if "\nollama:" in gblock else gblock
    check("guacd ships ON by default",
          "\n  enabled: true" in gblock)
    # And the reason it might have to be turned off is written down, because a
    # sidecar that cannot pull stops the WHOLE pod.
    check("with the mirrored/air-gapped caveat recorded beside it",
          "SIDECAR" in gblock and "whole pod" in gblock.lower()
          and "enabled: false" in gblock)

    print("...and a recording does not grow for ever — retention")
    # WHY THIS MATTERS AT ALL: an asciinema cast is ~6 bytes/second and a guac
    # recording about 9,000, so the volume that also holds the git checkouts
    # and the Terraform state is what fills up once RDP/VNC/web sessions are
    # actually used. Nothing trimmed them.
    import datetime as _d
    pam.save_config(keep_days=0, keep_mb=0)

    def _seed(sid, when, size):
        f = pam.SESSIONS / f"{sid}.cast"
        pam.SESSIONS.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x" * size)
        db.run("INSERT OR REPLACE INTO pam_sessions (id, protocol, who, "
               "target_name, started, rec_kind, rec_rel, sha256, seconds) "
               "VALUES (?,?,?,?,?,?,?,?,?)",
               (sid, "ssh", "a@t.local", "old box", when, "asciinema",
                f"pam-sessions/{sid}.cast", "deadbeef", 10))
        return f

    # The format the module itself writes — offset included. A naive stamp
    # here made `ansible.ago()` raise on the sessions page, which is a fair
    # warning that a hand-seeded row must look like a real one.
    # NO POLICY DELETES NOTHING, checked on a FILE rather than on the returned
    # counters: the early return is only a fast path — skip it and the two `if`
    # blocks still decline to run — so a bite that removed it changed no
    # counter and the first version of this check passed regardless.
    _anc = None

    old_day = (_d.datetime.now(_d.UTC)
               - _d.timedelta(days=40)).isoformat(timespec="seconds")
    new_day = _d.datetime.now(_d.UTC).isoformat(timespec="seconds")
    f_old, f_new = _seed("ps-retold", old_day, 2000), _seed("ps-retnew", new_day, 2000)

    check("with no policy, even a 40-day-old recording is left alone",
          pam.trim_recordings()["by_age"] == 0 and f_old.exists())

    pam.save_config(keep_days=30, keep_mb=0)
    got = pam.trim_recordings()
    check(f"a recording past the age limit loses its FILE ({got['by_age']})",
          got["by_age"] == 1 and not f_old.exists() and f_new.exists())
    # THE ROW IS THE AUDIT RECORD and costs a few hundred bytes; the file is
    # the screen and is what grows. Deleting the row would throw away the
    # evidence and keep the expensive half.
    row = pam.session("ps-retold")
    check("but KEEPS its row — who reached what, when, is the evidence",
          bool(row) and row["target_name"] == "old box" and not row["rec_rel"])
    # A POLICY DOING ITS JOB MUST NOT LOOK LIKE AN INCIDENT. 'missing' in this
    # product means the evidence went astray.
    st = pam.session_integrity("ps-retold")
    check(f"and reads as EXPIRED, not missing ({st['state']})",
          st["state"] == "expired" and st.get("when"))
    check("while an untouched one still verifies or reads as tampered, not expired",
          pam.session_integrity("ps-retnew")["state"] in ("verified", "tampered"))

    # The size cap takes the OLDEST first — the newest recording is the one
    # somebody is most likely to want.
    pam.save_config(keep_days=0, keep_mb=0)
    for f in list(pam.SESSIONS.iterdir()):
        if f.is_file() and f.name.startswith("ps-ret"):
            f.unlink()
    db.run("DELETE FROM pam_sessions WHERE id LIKE 'ps-ret%'")
    # Sized so the cap is genuinely BELOW what is on disk. The first version
    # rounded the cap UP past the seeded total, so nothing needed trimming and
    # the check passed on a policy that had done nothing.
    MB = 1024 * 1024
    a = _seed("ps-retA", "2026-01-01T00:00:00+00:00", 3 * MB)
    b = _seed("ps-retB", "2026-06-01T00:00:00+00:00", 3 * MB)
    before = pam.store_bytes()
    cap = 4                                     # MB, against ~6MB on disk
    check(f"the store really is over the cap first ({before // MB}MB > {cap}MB)",
          before > cap * MB)
    pam.save_config(keep_days=0, keep_mb=cap)
    got = pam.trim_recordings()
    check(f"the size cap trims oldest-first ({got['by_size']} removed)",
          got["by_size"] >= 1 and not a.exists())
    check(f"and stops once under the cap, keeping the newest "
          f"({pam.store_bytes() // MB}MB left)",
          pam.store_bytes() <= cap * MB and b.exists())
    pam.save_config(keep_days=0, keep_mb=0)
    for sid in ("ps-retA", "ps-retB"):
        f = pam.SESSIONS / f"{sid}.cast"
        if f.exists():
            f.unlink()
    db.run("DELETE FROM pam_sessions WHERE id LIKE 'ps-ret%'")

    # It has to actually RUN. A retention setting nothing applies is a setting
    # that lies, and the warmer is where the other periodic work already is.
    warm = (ROOT / "app" / "warmer.py").read_text()
    check("the periodic pass applies it",
          "_trim_recordings" in warm
          and "steps += [_trim_recordings]" in warm
          and "pam.trim_recordings()" in warm)
    # The GUARD, not its exact line: it legitimately gained a third condition
    # when the warm-seat pool started sharing this pass, and pinning the whole
    # expression failed for a change that was correct.
    check("and it does nothing at all when nothing is configured",
          'not cfg["keep_days"]' in warm and 'not cfg["keep_mb"]' in warm
          and warm[warm.index('not cfg["keep_days"]'):]
                  .split("\n", 2)[1].strip() == "return")
    check("a trim is audited, so the deletion is on the record too",
          "pam_recordings_trimmed" in warm)
    setp = (ROOT / "templates" / "set_pam.html").read_text()
    check("and the page offers both limits with the usage beside them",
          'name="keep_days"' in setp and 'name="keep_mb"' in setp
          and "rec_mb" in setp)

    print("...and a web target CAN be recorded — a browser in the cluster")
    # THE ANSWER TO THE REPORT. Off, a web target is a bookmark with an audit
    # line; on, it is a browser this portal starts, rendered and recorded by
    # the same guacd the RDP targets use.
    pam.save_config(web_browser=False)
    off = pam.target(web)
    check("with the gateway off, a web target is not live-capable",
          off["is_live"] is False and off["needs_guac"] is False
          and off["web"] is True)
    pam.save_config(web_browser=True)
    on = pam.target(web)
    check("switched on, the SAME target becomes live and guac-rendered",
          on["is_live"] is True and on["needs_guac"] is True)
    # The switch decides capability; a cluster that cannot take the pod is a
    # reason the BUTTON is disabled, said in words. Keeping those apart is what
    # stops the tile and the row from disagreeing.
    check("and it says which switch is missing rather than failing on click",
          "no cluster is chosen" in webseat.why_unavailable(pam.config()))
    pam.save_config(web_browser=False)
    check("off, the reason names the setting that turns it on",
          "Settings → Privileged Access" in webseat.why_unavailable(pam.config()))
    pam.save_config(web_browser=True)

    # THE TOPOLOGY HAS TO ADD UP, and this was a real hole. `guacd_host` is
    # configurable, so guacd need not be this pod's sidecar — and a guacd
    # anywhere else cannot reach a seat at 127.0.0.1, because that is ITS
    # loopback and the seat lives on the portal's. It would have failed as
    # "the browser did not answer", naming the wrong thing entirely.
    # A USABLE CLUSTER, so the checks after it are actually reached: they run
    # in order and "no cluster is chosen" short-circuited the topology guard,
    # which is how the first version of this passed while testing nothing.
    from app import store
    wpid = store.add_project("seatproj")
    kcf = pathlib.Path(os.environ["PORTAL_DATA_DIR"]) / "seat-kubeconfig"
    kcf.write_text("apiVersion: v1\nkind: Config\ncontexts: []\n")
    wcid = store.add_cluster(wpid, "seatcluster", str(kcf), "ctx")
    store.update_cluster(wpid, wcid, manage=1)
    live = dict(pam.config(), web_cluster=wcid, web_browser=True,
                web_namespace="default")
    check("with a managed cluster and the sidecar, a seat can be opened",
          webseat.why_unavailable(live) == "")
    # A cluster the portal may not write to cannot host a seat — a seat is a
    # pod, and the reason says where the tick lives.
    store.update_cluster(wpid, wcid, manage=0)
    check("a read-only cluster is refused, saying where to enable it",
          "management" in webseat.why_unavailable(live).lower())
    store.update_cluster(wpid, wcid, manage=1)
    check("a remote guacd with no reachable address for the portal is refused",
          "not as this portal's sidecar" in
          webseat.why_unavailable(dict(live, guacd_host="10.0.0.9",
                                       web_seat_host="")))
    check("and naming that address clears it",
          "sidecar" not in webseat.why_unavailable(
              dict(live, guacd_host="10.0.0.9", web_seat_host="portal.local")))
    # ASKED ABOUT THE CONFIG IT WAS HANDED. The first version read config()
    # regardless, so `why_unavailable(cfg)` was not a function of its own
    # argument and the settings page could disagree with the socket about the
    # very thing it was rendering.
    check("the check reads the guacd host it was given, not the stored one",
          pam.guacd_is_local("10.0.0.9") is False
          and pam.guacd_is_local("127.0.0.1") is True
          and pam.guacd_is_local("") is True)
    # Blank MEANS the sidecar, so it must survive being saved as blank rather
    # than being filled in from the defaults like the other text fields.
    pam.save_config(web_seat_host="")
    check("blank stays blank, because blank is the sidecar",
          pam.config()["web_seat_host"] == "")
    pam.save_config(web_seat_host="  host.docker.internal  ")
    check("and a named address is trimmed and kept",
          pam.config()["web_seat_host"] == "host.docker.internal")
    # AND THE SEAT ACTUALLY USES IT. The guard and the `--address` check both
    # passed with `vnc_host` hardcoded back to 127.0.0.1 — the two halves that
    # surround a value say nothing about the value.
    class _Cfg:
        def __init__(self, cfg): self.cfg = cfg
    host_of = webseat.Seat.vnc_host.fget
    check("a seat is dialled at the configured address",
          host_of(_Cfg({"web_seat_host": "host.docker.internal"}))
          == "host.docker.internal")
    check("and at loopback when nothing is set, which is the sidecar",
          host_of(_Cfg({"web_seat_host": ""})) == "127.0.0.1"
          and host_of(_Cfg({})) == "127.0.0.1")
    seat_src = (ROOT / "app" / "webseat.py").read_text()
    # THREE BLOCKERS FOUND BY AUDIT, all on the path this feature was built
    # for, none reachable by the tests that existed.
    #
    # 1. The forward parser only matched a LOOPBACK bind line — while
    #    forward() itself passes `--address 0.0.0.0` whenever the seat is
    #    dialled elsewhere, which makes kubectl print `0.0.0.0:<port>`. The
    #    ports were never learned. The default path prints four lines, two of
    #    them loopback, which is exactly why the sidecar arrangement worked
    #    and this stayed invisible until the escape hatch was used.
    fwd = re.search(r"_FWD_LINE = re\.compile\((.+)\)", seat_src).group(1)
    check(f"the forward parser accepts any bind address ({fwd})",
          "127" not in fwd)
    import re as _re
    pat = _re.compile(r"Forwarding from \S+:(\d+) -> (\d+)")
    check("and really parses loopback, all-interfaces and IPv6 alike",
          all(pat.search(f"Forwarding from {a}:54321 -> 5900")
              for a in ("127.0.0.1", "0.0.0.0", "[::1]")))
    # 2. …and it read with a BLOCKING readline, so when the lines did not
    #    parse the deadline was never re-evaluated and FORWARD_TIMEOUT could
    #    not fire. That did not merely hang one click: it held an anyio worker
    #    thread for ever, and enough clicks would stall every threadpool call
    #    in the portal.
    fwd_body = seat_src[seat_src.index("    def forward("):]
    fwd_body = fwd_body[:fwd_body.index("\n    def ")]
    check("the forward output is pumped, so its timeout can actually fire",
          "queue.Queue" in fwd_body and "lines.get(timeout=" in fwd_body
          and ".readline()" not in fwd_body)
    # 3. `kubectl wait --for=condition=Ready` returns when the CONTAINER is
    #    running; Selenium binds its port seconds later, and a port-forward to
    #    a port nothing listens on is refused instantly — so the single POST
    #    failed fast and deleted the pod. It read as flakiness.
    check("the seat waits for the browser to actually listen before using it",
          "def wait_driver(" in seat_src
          and "self.wait_driver()" in seat_src
          and '"/status"' in seat_src or "/status" in seat_src)
    # 4. The BROWSER gives up first: guacamole-common-js defaults
    #    receiveTimeout to 15s and only an incoming instruction resets it. An
    #    RDP target answers in under a second; a seat cannot. The symptom was
    #    "tunnel error: Server timeout" plus a 0-second session — which is
    #    exactly the "Active shows 0" that was reported.
    console = (ROOT / "templates" / "pam_console.html").read_text()
    check("the console page waits longer than a seat takes to build",
          "tunnel.receiveTimeout" in console
          and int(re.search(r"tunnel\.receiveTimeout = (\d+)", console).group(1))
              >= 120000)
    main_src = (ROOT / "app" / "main.py").read_text()
    check("and the relay sends nop while the seat is built, so it is not silent",
          '_hold_open' in main_src and 'guac_instr("nop")' in main_src)

    # A listener on 127.0.0.1 is unreachable from anywhere but this pod, so
    # naming a different address has to move the listener too — otherwise the
    # seat opens and guacd still cannot reach it.
    check("a non-loopback seat host also widens the forward's listener",
          'if self.vnc_host != "127.0.0.1":' in seat_src
          and '"--address", "0.0.0.0"' in seat_src)
    pam.save_config(web_seat_host="")

    # ONE POD PER SESSION is a security property, not tidiness: two people on
    # one browser share its cookies, so the second inherits the first's
    # authenticated session.
    cfg = dict(pam.config(), web_namespace="browsers")
    m1 = webseat.manifest("pam-web-aaaaaaaa", cfg)
    m2 = webseat.manifest("pam-web-bbbbbbbb", cfg)
    check("each seat is its own pod", m1["metadata"]["name"] != m2["metadata"]["name"]
          and m1["kind"] == "Pod")
    check("in the configured namespace",
          m1["metadata"]["namespace"] == "browsers")
    # THE BACKSTOP. Without it, a portal killed mid-session leaves a browser
    # logged in to a production application until somebody notices.
    # `.get`, not `[...]`: a missing key CRASHED the file, which is a failing
    # test but a worse one — it takes every check after it with it instead of
    # naming the one thing that is wrong.
    check("the pod carries its own deadline, so a lost session is not a lost "
          "browser",
          m1["spec"].get("activeDeadlineSeconds") == cfg["web_ttl"]
          and m1["spec"].get("restartPolicy") == "Never")
    check("and there is deliberately no unlimited lifetime",
          pam.config()["web_ttl"] >= 300
          and (pam.save_config(web_ttl="0") or pam.config()["web_ttl"] >= 300))
    pam.save_config(web_ttl="3600")
    check("it mounts no service account token",
          m1["spec"].get("automountServiceAccountToken") is False)
    check("and drops every capability",
          (m1["spec"]["containers"][0].get("securityContext") or {})
          .get("capabilities", {}).get("drop") == ["ALL"])
    # A seat is watched, not shared — nothing else may queue a browser on it.
    envs = {e["name"]: e["value"] for e in m1["spec"]["containers"][0]["env"]}
    check("the browser takes one session at a time",
          envs.get("SE_NODE_MAX_SESSIONS") == "1")
    check("and the screen is the configured desktop size",
          envs.get("SE_SCREEN_WIDTH") == str(cfg["rdp_width"]))

    # DELETE ONLY WHAT THIS MODULE NAMED, the guard netshoot_stop applies for
    # the same reason.
    refused_ws = False
    try:
        webseat.delete({"kubeconfig_file": "/x", "context": "y"}, "browsers",
                       "kube-apiserver-node1")
    except webseat.Refused:
        refused_ws = True
    check("it refuses to delete a pod it did not create", refused_ws)
    check("and its name shape is what decides",
          bool(webseat.POD_RE.match("pam-web-0123abcd"))
          and not webseat.POD_RE.match("pam-web-0123abcd-x")
          and not webseat.POD_RE.match("browser-0123abcd"))

    # guacd is pointed at the SEAT, never at the application: it renders a
    # browser, and the browser is what visits the app. Which is also why a web
    # target's stored credential is still brokered nowhere.
    class _FakeSeat:
        vnc_host, vnc_port, vnc_password = "127.0.0.1", 54321, "secret"
    proto, gp = pam.guac_web_params(_FakeSeat(), 1280, 800)
    check("guacd is told VNC on the seat, not the target's own address",
          proto == "vnc" and gp["hostname"] == "127.0.0.1"
          and gp["port"] == "54321"
          and "aml.example.internal" not in json.dumps(gp))
    check("and the seat's VNC password reaches guacd and nowhere else",
          gp["password"] == "secret")

    print("...and the catalogue can be SEARCHED, and says what it searched")
    page = (ROOT / "templates" / "pam.html").read_text()
    form = (ROOT / "templates" / "pam_target.html").read_text()
    check("the catalogue carries a host name and a label column",
          ">Hostname<" in page and ">Label<" in page)
    check("and both are on the form that creates a target",
          'name="hostname"' in form and 'name="label"' in form)
    check("there is a search box over the catalogue",
          'id="tgtQ"' in page and 'type="search"' in page)
    # CLIENT-SIDE: finding a row is typing three letters, and a round trip per
    # letter is the wrong shape. The protocol and environment filters stay
    # server-side because they are state somebody links to.
    check("it filters in the browser rather than round-tripping",
          "q.addEventListener('input', paint)" in page)
    # The haystack is built server-side from what the row RENDERS, chips
    # included — searching for the thing you can see is the first thing
    # anybody tries, and it is what did not work on the settings pages this
    # pattern came from.
    check("the haystack is the row as rendered, including its chips",
          "data-find=" in page and "t.hostname" in page and "t.label" in page
          and "t.project_name ~ ' · ' ~ t.region_name" in page)
    # `hidden` on a <tr> loses to the table's own display rule in some engines.
    check("a filtered row is hidden AND display:none, not one of the two",
          "r.hidden = !hit" in page and "r.style.display = hit ? '' : 'none'" in page)
    check("the count and a no-match row keep the filter honest",
          'id="tgtCount"' in page and 'id="tgtNone"' in page)
    # A filter left in the box is a page quietly showing a subset.
    check("Escape clears it", "ev.key === 'Escape' && q.value" in page)
    # The no-match row spans the table, so the column count has to follow the
    # two new columns — a short colspan leaves a cell hanging off the row.
    cols = page.count('<th ', page.index("Target catalogue"),
                      page.index("</thead>", page.index("Target catalogue")))
    check(f"the no-match row spans every column ({cols})",
          f'colspan="{cols}"' in page)

    print("...and a row says WHICH machine it is: a host name and a label")
    # An address is often an IP, and an IP identifies nothing — the reason both
    # columns were asked for. Two fields, deliberately different in kind: a
    # host name is something a resolver may be handed, a label is prose.
    named = pam.save_target("", {"name": "EU WAF 02", "protocol": "ssh",
        "address": "10.0.10.12", "hostname": "eu-preprod-waf02",
        "label": "EU preprod WAF, rack 4", "auth_kind": "none"}, "ammar")
    nt = pam.target(named)
    check("a target stores its host name and its label",
          nt["hostname"] == "eu-preprod-waf02"
          and nt["label"] == "EU preprod WAF, rack 4")
    # The host name is held to the address shape because that is what it is.
    refused("a host name with a space in it",
            lambda: pam.save_target("", {"name": "y", "protocol": "ssh",
                "address": "10.0.0.2", "hostname": "not a hostname",
                "auth_kind": "none"}, "x"))
    # The label is free text — that is the point of having it beside a name
    # that is not — but it is still rendered in tables and written into
    # inventory files, so a control character is not free text.
    check("a label keeps its spaces and loses its control characters",
          pam._label("EU  preprod\tWAF\n") == "EU preprod WAF"
          and pam._label("bell\x07here") == "bellhere")
    # ONE definition, shared with the inventory: the same field is typed on two
    # pages and two definitions is one of them drifting.
    check("and it is the inventory's definition, not a second copy",
          pam._label is not ansible._label
          and pam._label("  x  ") == ansible._label("  x  ")
          and "ansible._label" in (ROOT / "app" / "pam.py").read_text())

    # AN INVENTORY HOST gets both too, or the columns are decorative for
    # exactly the rows somebody is looking at — every row on the reported page
    # was inventory-derived.
    lpriv, _ = ansible.new_keypair()
    lg = ansible.save_group("", {"name": "labelgrp", "ssh_user": "root",
                                 "key": lpriv}, "adm")
    ansible.add_host(lg, "10.0.10.21", "10.0.10.21", "adm",
                     label="EU preprod DNS 01")
    lh = next(t for t in pam.targets()
              if t.get("source") == "ansible" and t["name"] == "10.0.10.21")
    check("an inventory host carries the label typed on it in Ansible",
          lh["label"] == "EU preprod DNS 01")
    # A host pasted in as a bare IP has NO host name anywhere, and the honest
    # answer is an empty column — printing the address again under a second
    # heading would be the page inventing information.
    check("and no host name is invented from the address",
          lh["hostname"] == "")
    ansible.add_host(lg, "eu-preprod-dns02", "10.0.10.22", "adm")
    lh2 = next(t for t in pam.targets()
               if t.get("source") == "ansible" and t["name"] == "eu-preprod-dns02")
    check("a host whose inventory name is not its address supplies one",
          lh2["hostname"] == "eu-preprod-dns02")
    # The asset inventory is where a machine's name is actually recorded, so it
    # wins over the inventory name.
    from app import assets
    aid = assets.create({"hostname": "eu-preprod-dns03.example.net",
                         "ip": "10.0.10.23"}, "adm")
    ansible.add_host(lg, "dns03", "10.0.10.23", "adm", asset_id=aid)
    lh3 = next(t for t in pam.targets()
               if t.get("source") == "ansible" and t["name"] == "dns03")
    check("the asset inventory's host name wins over the inventory name",
          lh3["hostname"] == "eu-preprod-dns03.example.net")
    # One read for the whole inventory, not a `get()` per host: this runs on
    # every page load of the catalogue.
    check("resolving a whole inventory's assets is one query",
          "def many(" in (ROOT / "app" / "assets.py").read_text()
          and "assets.many(" in (ROOT / "app" / "ansible.py").read_text())

    print("the SSH shell refuses an address ssh would not take safely")
    evil = pam.save_target("", {"name": "evil", "protocol": "ssh",
        "address": "10.0.0.1", "auth_kind": "none"}, "x")
    row = pam._target_raw(evil)
    row["address"] = "$(reboot)"                # a value the form would never store
    refused("a smuggled address at the shell", lambda: pam.ssh_shell(row))

    print("the guacd framing is length-computed, not concatenated")
    check("an instruction is LEN.VALUE,…;",
          pam.guac_instr("select", "rdp") == b"6.select,3.rdp;")
    check("length is UTF-16 code units, not bytes",
          pam.guac_instr("é") == b"1.\xc3\xa9;")           # é: 1 unit, 2 bytes
    args = ["VERSION_1_5_0", "hostname", "port", "password", "unset-knob"]
    vals = pam.guac_connect_values(args, {"hostname": "h", "port": "3389",
                                          "password": "p@,;.ss"})
    check("connect values echo the version and match by name, unknowns empty",
          vals == ["VERSION_1_5_0", "h", "3389", "p@,;.ss", ""])
    check("a value with the protocol's own delimiters survives framing",
          pam.guac_instr("password", "p@,;.ss") == b"8.password,7.p@,;.ss;")

    print("guac_params fills from the target + the brokered secret, RDP only")
    rid = pam.save_target("", {"name": "WIN", "protocol": "rdp",
        "address": "10.0.0.5", "port": "3389", "username": "admin",
        "auth_kind": "password", "secret": "hunter2", "domain": "CORP",
        "security": "nla", "ignore_cert": "1"}, "x")
    proto, params = pam.guac_params(pam._target_raw(rid), 1024, 768)
    check("protocol + host + creds are present",
          proto == "rdp" and params["hostname"] == "10.0.0.5"
          and params["username"] == "admin" and params["password"] == "hunter2")
    check("RDP knobs come from extra",
          params["domain"] == "CORP" and params["security"] == "nla"
          and params["ignore-cert"] == "true")
    check("an SSH target is refused by guac_params",
          _raises(lambda: pam.guac_params(pam._target_raw(tid))))
    recp = pam.guac_recording_params("ps-xyz")
    check("recording params name the file in our store",
          recp["recording-name"] == "ps-xyz"
          and recp["recording-path"] == str(pam.SESSIONS)
          and recp["recording-include-keys"] == "false")

    print("recording: asciinema is output only and keeps the redaction")
    cast = kmanage.SessionCast(str(DATA / "p.cast"), 24, 100)
    cast.output("hi"); cast.close()
    kinds = {json.loads(l)[1] for l in open(DATA / "p.cast").read().splitlines()[1:] if l}
    check("no input events in a cast", kinds <= {"o", "r"})
    rec = pam.start_recording("ops@x.com", "1.2.3.4", protocol="ssh",
        target_id=tid, target_name="EU WAF", address="10.0.10.11",
        rec_kind="asciinema", rows=24, cols=100)
    rec.output("uptime\r\n")
    rec.commands_typed(["uptime", "<hidden — 8 characters typed after 'Password:'>"])
    rec.finish("closed")
    s = pam.sessions()[0]
    check("the session is filed with its command count and protocol",
          s["cmd_count"] == 2 and s["protocol"] == "ssh")
    txt = pam.session_commands_text(s["id"])
    check("the transcript keeps the redaction and leaks no secret material",
          "uptime" in txt and "<hidden" in txt and "\x1b" not in txt)

    print("a guac recording is indexed from the file guacd wrote")
    grec = pam.start_recording("ops@x.com", "1.2.3.4", protocol="rdp",
        target_id=rid, target_name="WIN", address="10.0.0.5", rec_kind="guac")
    (pam.SESSIONS / grec.id).write_bytes(b"5.guac fake recording bytes")  # stand in for guacd
    grec.finish("closed")
    gs = pam.session(grec.id)
    check("the guac session points at the file, kind 'guac'",
          gs["rec_kind"] == "guac" and gs["out_bytes"] > 0
          and bool(pam.session_rec_path(grec.id)))
    check("an RDP session has no command transcript",
          "graphical session" in pam.session_commands_text(grec.id))

    print("the session transcript is the whole screen, ANSI stripped")
    trec = pam.start_recording("ops@x.com", "1.2.3.4", protocol="ssh",
        target_id=tid, target_name="EU WAF", address="10.0.10.11",
        rec_kind="asciinema", rows=24, cols=100)
    trec.output("\x1b[1;32m[root@waf01 ~]#\x1b[0m uptime\r\n up 3 days\r\n")
    trec.output("\x1b[1;32m[root@waf01 ~]#\x1b[0m exit\r\nlogout\r\n")
    trec.commands_typed(["uptime", "exit"])
    trec.finish("closed")
    tx = pam.session_transcript_text(trec.id)
    check("it holds the prompt, the command AND its output",
          tx is not None and "[root@waf01 ~]# uptime" in tx
          and "up 3 days" in tx and "logout" in tx)
    check("and the ANSI colour codes are gone", "\x1b" not in tx)
    check("a graphical (guac) session has no text transcript",
          pam.session_transcript_text(grec.id) is None)

    print("a stored recording path can never leave the data directory")
    db.run("INSERT INTO pam_sessions (id, rec_kind, rec_rel) VALUES (?,?,?)",
           ("ps-evil", "guac", "../../../../etc/passwd"))
    check("a traversing rec_rel resolves to nothing",
          pam.session_rec_path("ps-evil") is None)

    print("delete and clear remove the row and the file")
    p = pam.session_rec_path(grec.id)
    check("delete reports one gone", pam.delete_session(grec.id) is True)
    check("the row and file are gone",
          pam.session(grec.id) is None and not os.path.isfile(p))

    print("recording can be switched off")
    from app import store
    store._set_setting("pam", {**pam.config(), "record_sessions": False})
    check("start_recording is None when off",
          pam.start_recording("x", "", protocol="ssh") is None)
    store._set_setting("pam", {**pam.config(), "record_sessions": True})

    inventory()
    per_device_rbac()
    environments()
    integrity()
    governance()
    migration()
    routes()
    watching_live()
    file_transfer()
    seat_navigation()
    orphan_reaping()
    print("OK" if not bad else f"{bad} FAILED")


def environments() -> None:
    print("targets carry an environment: coloured, filterable, prod-deriving")
    a = pam.save_target("", {"name": "Env A", "protocol": "ssh",
        "address": "10.2.0.1", "auth_kind": "none", "env": "staging"}, "adm")
    b = pam.save_target("", {"name": "Env B", "protocol": "ssh",
        "address": "10.2.0.2", "auth_kind": "none", "env": "production"}, "adm")
    ta, tb = pam.target(a), pam.target(b)
    check("a staging target is stored and is not production",
          ta["env"] == "staging" and ta["is_prod"] == 0
          and ta["env_label"] == "Staging" and ta["env_tone"] == "warn")
    check("a production environment switches the prod safeguard on by itself",
          tb["env"] == "production" and tb["is_prod"] == 1)
    check("an unknown environment shows as typed, in a neutral tone",
          pam.env_label("bluezone") == "bluezone"
          and pam.env_tone("bluezone") == "muted")
    check("the catalogue filters by environment",
          any(t["id"] == a for t in pam.targets(env="staging"))
          and all(t["env"] == "staging" for t in pam.targets(env="staging"))
          and not any(t["id"] == a for t in pam.targets(env="production")))
    check("the environment facet lists what is present",
          "staging" in pam.target_facets()["envs"]
          and "production" in pam.target_facets()["envs"])
    # an Ansible group's environment reaches its inventory hosts in PAM
    priv, _ = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "envgrp", "ssh_user": "root",
                                  "key": priv, "env": "preprod"}, "adm")
    ansible.add_host(gid, "eh1", "10.2.9.9", "adm")
    host = next(t for t in pam.targets()
                if t.get("source") == "ansible" and t["name"] == "eh1")
    check("an inventory host inherits its group's environment",
          host["env"] == "preprod" and host["env_label"] == "Pre-prod")
    gp = ansible.save_group("", {"name": "envgrp2", "ssh_user": "root",
                                 "key": priv, "env": "production"}, "adm")
    check("a production Ansible group is marked prod from its environment",
          ansible.group(gp)["is_prod"] == 1)
    # a host's own environment overrides the group's, and a production host env
    # switches on the typed-name safeguard even when the group is not prod
    ansible.add_host(gid, "eh2", "10.2.9.10", "adm", env="production")
    eh2 = next(t for t in pam.targets()
               if t.get("source") == "ansible" and t["name"] == "eh2")
    check("a host's own env overrides the group's, and prod derives is_prod",
          eh2["env"] == "production" and eh2["is_prod"] == 1
          and eh2["env_label"] == "Production")
    # editing an existing host changes the environment it shows in PAM
    hid = next(h["id"] for h in ansible.group(gid)["hosts"] if h["name"] == "eh1")
    ansible.update_host(hid, {"name": "eh1", "address": "10.2.9.9",
                              "env": "staging"}, "adm")
    eh1b = next(t for t in pam.targets()
                if t.get("source") == "ansible" and t["name"] == "eh1")
    check("editing a host changes the environment it shows in PAM",
          eh1b["env"] == "staging")
    # a playbook carries an environment on its place
    pbid = ansible.save_playbook("", "Env PB", "body", "", "adm", env="uat")
    check("a playbook stores its place environment",
          ansible.playbook(pbid)["env"] == "uat")


def integrity() -> None:
    print("a recording carries a checksum, and a change to it is provable")
    from app import store
    store._set_setting("pam", {**pam.config(), "record_sessions": True})
    rec = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id="ti",
                              target_name="Box", address="10.0.0.9")
    rec.output("uptime\r\n 10:00  up 3 days\r\n")
    rec.finish()
    row = pam.session(rec.id)
    check("a SHA-256 was stored when the session was filed",
          bool(row.get("sha256")) and len(row["sha256"]) == 64)
    v = pam.session_integrity(rec.id)
    check("the untouched recording verifies", v["state"] == "verified"
          and v["current"] == row["sha256"])
    path = pam.session_rec_path(rec.id)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('\n[0.1,"o","tampered"]\n')      # forge an extra output event
    v2 = pam.session_integrity(rec.id)
    check("a change to the file on disk is caught", v2["state"] == "tampered"
          and v2["current"] != v2["stored"])
    os.remove(path)
    check("a missing recording reads as missing, not verified",
          pam.session_integrity(rec.id)["state"] == "missing")
    # a session with no checksum (an older row) reads 'none', never a false pass
    db.run("UPDATE pam_sessions SET sha256='' WHERE id=?", (rec.id,))
    check("no checksum stored reads as none",
          pam.session_integrity(rec.id)["state"] == "none")


def governance() -> None:
    print("session governance: a reason may be required, sessions are capped")
    from app import store
    base = pam.config()
    # reason modes
    store._set_setting("pam", {**base, "require_reason": "off"})
    check("'off' never requires a reason",
          not pam.reason_required(True) and not pam.reason_required(False))
    store._set_setting("pam", {**base, "require_reason": "prod"})
    check("'prod' requires it on production only",
          pam.reason_required(True) and not pam.reason_required(False))
    store._set_setting("pam", {**base, "require_reason": "always"})
    check("'always' requires it everywhere",
          pam.reason_required(True) and pam.reason_required(False))
    # the justification is three mandatory parts, and the ticket must be a URL
    OK_T = "30 minutes"          # an OFFERED length; see below on typed ones
    check("all three parts are required",
          pam.justification("https://jira/INC-1", OK_T, "patch") is not None
          and pam.justification("", OK_T, "patch") is None
          and pam.justification("https://jira/INC-1", "", "patch") is None
          and pam.justification("https://jira/INC-1", OK_T, "no") is None)
    check("the ticket must be an http(s) URL, not free text",
          pam.justification("INC-1234", OK_T, "patch it") is None
          and pam.justification("https://jira/INC-1234", OK_T, "patch it"))
    # AND THE LENGTH MUST BE ONE OF THE OFFERED ONES. It was free text, so it
    # took "30m", "asap" and "half an hour" -- and prose cannot bound a
    # session, which is why the field did not do what its name said.
    check("a session length that was typed rather than chosen is not accepted",
          pam.justification("https://jira/INC-1", "30m", "patch it") is None
          and pam.justification("https://jira/INC-1", "asap", "patch it") is None
          and pam.justification("https://jira/INC-1", "half an hour",
                                "patch it") is None)
    check("...and every offered length IS accepted, so the list and the check "
          "cannot drift apart",
          all(pam.justification("https://jira/INC-1", label, "patch it")
              is not None for _, label in pam.SESSION_TIMES))
    # the three parts are stored on the recording and shown back
    store._set_setting("pam", {**base, "require_reason": "always",
                               "record_sessions": True})
    rec = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id="tg",
                              target_name="Box", address="10.0.0.1",
                              reason="patch the WAF", ticket="https://jira/INC-4821",
                              session_time="30 minutes")
    rec.output("id\r\n")
    rec.finish()
    row = pam.session(rec.id)
    check("the three-part justification is filed with the session",
          row.get("reason") == "patch the WAF"
          and row.get("ticket") == "https://jira/INC-4821"
          and row.get("session_time") == "30 minutes")
    # guardrails clamp to sane values
    store._set_setting("pam", {**base, "idle_timeout": "999999",
                               "max_concurrent": "-5"})
    cfg = pam.config()
    check("idle timeout is clamped, a negative cap becomes zero",
          cfg["idle_timeout"] == 86400 and cfg["max_concurrent"] == 0)
    # concurrent count reflects the live registry
    pam.register_active("g-1", {"who": "cap@t", "target_id": "t"}, lambda: None)
    pam.register_active("g-2", {"who": "cap@t", "target_id": "t"}, lambda: None)
    check("concurrent_for counts a person's live sessions",
          pam.concurrent_for("cap@t") == 2 and pam.concurrent_for("nobody@t") == 0)
    pam.drop_active("g-1"); pam.drop_active("g-2")
    store._set_setting("pam", base)


def inventory() -> None:
    print("Ansible inventory hosts appear as PAM targets, without re-entry")
    priv, _ = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "grp", "ssh_user": "root",
                                  "key": priv, "is_prod": "1"}, "adm")
    ansible.add_host(gid, "waf01", "10.9.0.1", "adm")
    ts = pam.targets()
    host = next((t for t in ts if t.get("source") == "ansible"), None)
    check("the inventory host is in the catalogue", host is not None)
    check("it is read-only in PAM (edited in Ansible)",
          host and host["editable"] is False and host["id"].startswith("ah-"))
    check("it carries the group's prod flag and key",
          host and host["is_prod"] == 1 and host["has_secret"] is True)
    check("the terminal resolves it via the inventory",
          pam.ssh_meta(host["id"]) is not None
          and pam.ssh_meta(host["id"])["source"] == "ansible"
          and pam.inventory_of(host["id"]) is not None)
    check("an SSH filter keeps it; an RDP filter drops it",
          any(t.get("source") == "ansible" for t in pam.targets(protocol="ssh"))
          and not any(t.get("source") == "ansible"
                      for t in pam.targets(protocol="rdp")))


def per_device_rbac() -> None:
    print("per-device access: a role scoped to targets shows only those")
    from app import auth, rbac
    a = pam.save_target("", {"name": "Dev A", "protocol": "ssh",
                             "address": "10.1.1.1", "auth_kind": "none"}, "adm")
    b = pam.save_target("", {"name": "Dev B", "protocol": "ssh",
                             "address": "10.1.1.2", "auth_kind": "none"}, "adm")
    rid = rbac.save("", "only A", "", ["pam", "pam_connect"], [], [], [a])
    uid = auth.create_user("scoped@t.local", "S", "Pass-Word-12345", role="viewer")
    db.run("UPDATE users SET disabled=0 WHERE id=?", (uid,))
    rbac.set_for_user(uid, [rid])
    u = auth.by_email("scoped@t.local")
    check("the scope names only A", rbac.visible_targets(u, "pam") == {a})
    check("may see + connect A", rbac.may_target(u, a, "pam")
          and rbac.may_target(u, a, "pam_connect"))
    check("may NOT see or connect B", not rbac.may_target(u, b, "pam")
          and not rbac.may_target(u, b, "pam_connect"))
    check("an unscoped grant is every target",
          rbac.visible_targets({"role": "admin"}, "pam") is None)
    check("the role reads as N PAM targets",
          "1 PAM target" in rbac.describe(rbac.get(rid), {}, {}))

    # The load-bearing half of "grant App A → see only App A's records": a
    # recording is scoped to the target it was of. A session of A is the scoped
    # user's to see; a session of B is not, though an admin sees both.
    ra = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id=a,
                             target_name="Dev A", address="10.1.1.1")
    ra.finish()
    rb = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id=b,
                             target_name="Dev B", address="10.1.1.2")
    rb.finish()
    vis = rbac.visible_targets(u, "pam")
    seen = {s["id"] for s in pam.sessions(visible=vis)}
    check("the scoped user sees A's recording, not B's",
          ra.id in seen and rb.id not in seen)
    check("an admin (unscoped) sees both recordings",
          {ra.id, rb.id} <= {s["id"] for s in pam.sessions(visible=None)})
    check("the scoped session stats count only A",
          pam.sessions_stats(visible=vis)["count"]
          < pam.sessions_stats(visible=None)["count"])
    check("the scoped command report holds A's session, not B's",
          ra.id in pam.commands_for(visible=vis)
          and rb.id not in pam.commands_for(visible=vis))

    # Live sessions carry their target too, so the operator watches (and can
    # kill) only the ones on their own targets.
    pam.register_active("live-a", {"target_id": a, "protocol": "ssh"}, lambda: None)
    pam.register_active("live-b", {"target_id": b, "protocol": "ssh"}, lambda: None)
    live = {s["id"] for s in pam.active_sessions(visible=vis)}
    check("a live session on A is visible; on B is not",
          "live-a" in live and "live-b" not in live)
    check("active_target resolves a live session's target",
          pam.active_target("live-b") == b)
    pam.drop_active("live-a"); pam.drop_active("live-b")
    return bad


def _raises(fn) -> bool:
    try:
        fn(); return False
    except pam.Refused:
        return True


def migration() -> None:
    print("the SSH recordings inherited from Ansible are carried forward")
    # ansible_sessions may not exist in this sandbox until the ansible migration
    # ran; it did (pam imports ansible). Seed a legacy row and re-migrate.
    db.run("""INSERT OR IGNORE INTO ansible_sessions
        (id, group_name, host, who, proj_id, rgn_id, started, ended, seconds,
         out_bytes, cmd_count, status, ip, cast_rel, commands)
        VALUES ('as-legacy','Old WAF','10.9.9.9','sre','','','2026-08-01T10:00:00+00:00',
        '2026-08-01T10:03:00+00:00',180,90,1,'closed','1.1.1.1',
        'ansible-sessions/as-legacy.cast','uptime')""")
    db._migrated = False
    db.connect()                                    # re-runs pam._migrate
    row = pam.session("as-legacy")
    check("the legacy SSH recording appears under Privileged Access",
          bool(row) and row["source"] == "ansible" and row["protocol"] == "ssh"
          and row["rec_kind"] == "asciinema")


def routes() -> None:
    print("through the routes: reading vs connecting are separate grants")
    from fastapi.testclient import TestClient

    from app import auth, main, rbac

    def enrol(email, pw, role):
        uid = auth.create_user(email, "N", pw, role=role)
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
               "email_verified=1 WHERE id=?", ("TESTSECRET", uid))

    aemail, apw = "boss@t.local", "May-Connect-Everything-42"
    remail, rpw = "eyes@t.local", "Read-Only-Please-42"
    enrol(aemail, apw, "admin")
    enrol(remail, rpw, "viewer")

    def login(c, e, p):
        c.post("/login", data={"email": e, "password": p}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    pam.save_config(allow_connect=True, record_sessions=True,
                    guacd_host="127.0.0.1", guacd_port=4822,
                    rdp_width=1280, rdp_height=800)
    tid = pam.save_target("", {"name": "RT SSH", "protocol": "ssh",
        "address": "10.1.2.3", "username": "root", "auth_kind": "none"}, "sys")

    boss = TestClient(main.app); boss.__enter__(); login(boss, aemail, apw)
    r = boss.get("/pam")
    check(f"the PAM page renders ({r.status_code})",
          r.status_code == 200 and "Privileged Access" in r.text
          and "RT SSH" in r.text and "10.1.2.3" in r.text)
    check("no secret is anywhere on the page", "TESTSECRET" not in r.text)
    # THE RENDERED PAGE, not the template's source: a column header in a file
    # says nothing about whether the row beneath it carries anything, and the
    # haystack is the half that has to be right for the search to work at all.
    srch = pam.save_target("", {"name": "RT SEARCH", "protocol": "ssh",
        "address": "10.1.2.9", "hostname": "rt-search-01",
        "label": "the row you are looking for", "auth_kind": "none"}, "sys")
    r = boss.get("/pam?sec=targets")
    row = r.text[r.text.index(f'id="t-{srch}"'):][:900]
    check(f"the catalogue renders its search box and both columns ({r.status_code})",
          r.status_code == 200 and 'id="tgtQ"' in r.text
          and ">Hostname<" in r.text and ">Label<" in r.text)
    # With the haystack stripped OUT. A bite that emptied both cells sailed
    # through the first version of this: the values were still in `data-find`,
    # so "the row contains them" was true of a row that displayed neither.
    seen = re.sub(r'data-find="[^"]*"', "", row)
    check("a rendered row DISPLAYS the host name and the label",
          "rt-search-01" in seen and "the row you are looking for" in seen)
    check("and a haystack that has them lowercased for searching",
          'data-find="' in row
          and "rt-search-01" in row.split('data-find="')[1].split('"')[0]
          and "the row you are looking for"
              in row.split('data-find="')[1].split('"')[0])
    pam.delete_target(srch)
    # A WEB TARGET'S OPEN: through the portal, audited, and the stored URL
    # never reaches the page as markup.
    # NOT production, deliberately: this block tests the audited open, and a
    # production web target no longer has one -- it is reached through the
    # recorded console only, which is asserted where that rule lives.
    wtid = pam.save_target("", {"name": "RT WEB", "protocol": "https",
        "address": "rt.example.internal", "port": "8443",
        "url": "https://rt.example.internal:8443/app", "auth_kind": "none",
        "env": "test"}, "sys")
    # STATED, not inherited: this asserts the gateway-off row, and another
    # section of this file leaves the switch on. A check that passes because of
    # what a different function did last is a check that moves on its own.
    pam.save_config(web_browser=False)
    r = boss.get("/pam?sec=targets")
    check("the row links to the portal's launch, not to the app directly",
          f'href="/pam/targets/{wtid}/launch"' in r.text
          and "rt.example.internal:8443/app" not in r.text)
    # SAID ON THE ROW, and checked where it is RENDERED — the first version of
    # this read the sentence out of the template file, which `{% if false %}`
    # left sitting there untouched.
    # Sliced to the row's END, not to a character count: the cells carry
    # inline SVG glyphs, so a row is ~2.2kB and a fixed 1600 or 2200 cut it off
    # before the action column — which made these checks pass and fail on the
    # length of an icon.
    def _row(html, ident):
        cut = html[html.index(f'id="t-{ident}"'):]
        return cut[:cut.index("</tr>")]
    wrow, srow = _row(r.text, wtid), _row(r.text, tid)
    # BOTH STATES, from the outside. The row's sentence has to follow the
    # gateway switch, and asserting only one of them is how a page ends up
    # still saying "not recorded" about a session it is recording.
    check("with the gateway OFF the web row says it is not recorded",
          "not recorded" in wrow and "in\n            a browser" not in wrow)
    check("and an SSH row says neither, because it is always recorded",
          "not recorded" not in srow)
    pam.save_config(web_browser=True)
    wrow_on = _row(boss.get("/pam?sec=targets").text, wtid)
    check("switched ON the same row says it IS recorded, in a browser",
          "recorded" in wrow_on and "not recorded" not in wrow_on)
    check("and a console control appears, with the audited open kept beside it",
          ">console<" in wrow_on and f'/pam/targets/{wtid}/launch' in wrow_on)
    # DISABLED WITH THE REASON, not hidden and not a dead link: no cluster is
    # chosen in this fixture, which is the house rule for an inapplicable
    # action and the difference between a button that explains itself and one
    # that fails after the click.
    check("which is disabled, saying which setting is missing",
          "disabled" in wrow_on and "no cluster is chosen" in wrow_on)
    # The web branch must be REACHED: `needs_guac` is true for a web target
    # now, so the generic RDP/VNC branch swallowed it and this row rendered an
    # RDP connect button with no `open` beside it at all.
    check("the web row is not mistaken for an RDP one",
          "the RDP/VNC gateway (guacd) is not reachable" not in wrow_on
          and ">connect<" not in wrow_on)
    pam.save_config(web_browser=False)
    r = boss.get(f"/pam/targets/{wtid}/launch", follow_redirects=False)
    check(f"the launch redirects to the application ({r.status_code})",
          r.status_code == 303
          and r.headers.get("location") == "https://rt.example.internal:8443/app")
    # THE POINT OF THE ROUTE. A web target is not proxied, so the audit line
    # is the only evidence the portal can produce that an application was
    # opened out of the privileged-access catalogue — and before this it
    # produced none, because the button was a plain link.
    trail = db.q("SELECT action, target, detail FROM audit "
                 "WHERE action = 'pam_web_opened' ORDER BY rowid DESC LIMIT 1")
    check("and the open is audited, by name and address",
          bool(trail) and trail[0]["target"] == "RT WEB"
          and "rt.example.internal" in trail[0]["detail"])
    check("the audit line says it was NOT recorded, so the gap is on the record",
          bool(trail) and "not proxied or recorded" in trail[0]["detail"])
    r = boss.get(f"/pam/targets/{tid}/launch", follow_redirects=False)
    # Unquoted: `_pam_back` percent-encodes the reason, so the literal
    # sentence is not in the header — checking the raw Location for it passed
    # nothing and failed for the wrong reason.
    where = urllib.parse.unquote(r.headers.get("location", ""))
    check(f"launching a non-web target is refused rather than redirected ({where})",
          r.status_code == 303 and where.startswith("/pam")
          and "not a web target" in where)
    pam.delete_target(wtid)

    r = boss.get(f"/pam/targets/{tid}/terminal", follow_redirects=False)
    check("an admin reaches the SSH terminal page",
          r.status_code == 200 and "Terminal</h1>" in r.text)
    # The switch has to be reachable and say what it will do — turning it on
    # starts creating pods in somebody's cluster and pulling a browser image.
    rw = boss.get("/settings/pam")
    check("settings offers the recorded-web switch and its cluster",
          rw.status_code == 200 and 'name="web_browser"' in rw.text
          and 'name="web_cluster"' in rw.text and 'name="web_image"' in rw.text)
    check("and says plainly that it is one pod per session",
          "One pod per session" in rw.text or "one pod per session" in rw.text)
    check("with no unlimited seat lifetime offered",
          'name="web_ttl"' in rw.text and 'min="300"' in rw.text)
    # Flipping it is a third switch and a third audit line.
    boss.post("/settings/pam", data={
        "enabled": "1", "allow_connect": "1", "record_sessions": "1",
        "guacd_host": "127.0.0.1", "guacd_port": "4822",
        "rdp_width": "1280", "rdp_height": "800", "require_reason": "prod",
        "idle_timeout": "1800", "max_duration": "0", "max_concurrent": "0",
        "web_browser": "1", "web_image": "selenium/standalone-chromium:latest",
        "web_cluster": "", "web_namespace": "browsers",
        "web_vnc_port": "5900", "web_driver_port": "4444",
        "web_vnc_password": "secret", "web_ttl": "3600"},
        follow_redirects=False)
    check("the web switch is stored from the page",
          pam.config()["web_browser"] is True
          and pam.config()["web_namespace"] == "browsers")
    trail = db.q("SELECT action, detail FROM audit "
                 "WHERE action LIKE 'pam_web_%' ORDER BY rowid DESC LIMIT 1")
    check("and turning it on is audited on its own line",
          bool(trail) and trail[0]["action"] == "pam_web_enabled")
    # A leftover browser must be removable without reaching for kubectl.
    rs = boss.post("/settings/pam/web/sweep", follow_redirects=False)
    check(f"there is a control to clear leftover browsers ({rs.status_code})",
          rs.status_code == 303)
    boss.post("/settings/pam", data={
        "enabled": "1", "allow_connect": "1", "record_sessions": "1",
        "guacd_host": "127.0.0.1", "guacd_port": "4822",
        "rdp_width": "1280", "rdp_height": "800", "require_reason": "prod",
        "idle_timeout": "1800", "max_duration": "0", "max_concurrent": "0",
        "web_namespace": "default", "web_ttl": "3600"},
        follow_redirects=False)
    check("and unticking it turns it off again — not a one-way door",
          pam.config()["web_browser"] is False)

    r = boss.get("/settings/pam")
    check("settings renders with governance + the gateway state",
          r.status_code == 200 and "guacd" in r.text
          and "reason for access" in r.text and "concurrent sessions" in r.text)
    r = boss.get("/admin/roles")
    check("the role editor groups access-targets by environment",
          r.status_code == 200 and "envtag" in r.text
          and ("Staging" in r.text or "Production" in r.text))

    # The Ansible shell button gates on Privileged Access: a user with full
    # Ansible but no PAM gets the popup button, not a link into /pam (which the
    # middleware would 403). An admin gets the real link.
    priv, _ = ansible.new_keypair()
    ag = ansible.save_group("", {"name": "shellgrp", "ssh_user": "root",
                                 "key": priv, "env": "staging"}, "sys")
    ansible.add_host(ag, "sh1", "10.4.4.4", "sys")
    enrol("ansonly@t.local", "Ansible-Only-Please-42", "viewer")
    au = auth.by_email("ansonly@t.local")
    arid = rbac.save("", "ansible only", "", ["ansible", "ansible_run"], [], [], [])
    rbac.set_for_user(au["id"], [arid])
    anscli = TestClient(main.app); anscli.__enter__()
    login(anscli, "ansonly@t.local", "Ansible-Only-Please-42")
    r = anscli.get(f"/ansible/groups/{ag}")
    check("an Ansible-only user gets the PAM popup button, not a shell link",
          r.status_code == 200
          and "opening a shell needs Privileged Access" in r.text
          and "/pam/targets/" not in r.text)
    r = boss.get(f"/ansible/groups/{ag}")
    check("an admin gets the real shell link into Privileged Access",
          r.status_code == 200 and "/pam/targets/" in r.text
          and "opening a shell needs Privileged Access" not in r.text)

    reader = TestClient(main.app); reader.__enter__(); login(reader, remail, rpw)
    r = reader.get(f"/pam/targets/{tid}/terminal", follow_redirects=False)
    check(f"a viewer cannot reach the terminal ({r.status_code})",
          r.status_code in (303, 403) and "Terminal</h1>" not in r.text)
    r = reader.post("/pam/target/delete", data={"tid": tid}, follow_redirects=False)
    # a viewer has no `pam` write area either
    check("a viewer cannot delete a target",
          r.status_code in (303, 403) and pam.target(tid) is not None)

    # a guac target cannot be consoled without a gateway. Point guacd at a port
    # nothing answers on, so the check holds whether or not a real guacd happens
    # to be running on this machine.
    pam.save_config(allow_connect=True, record_sessions=True,
                    guacd_host="127.0.0.1", guacd_port=9, rdp_width=1280,
                    rdp_height=800)
    gid = pam.save_target("", {"name": "RT RDP", "protocol": "rdp",
        "address": "10.1.2.9", "auth_kind": "none"}, "sys")
    r = boss.get(f"/pam/targets/{gid}/console", follow_redirects=False)
    check("the console redirects when guacd is unreachable",
          r.status_code == 303 and "guacd" in r.headers.get("location", "").lower())

    # Reason-to-connect gate on the terminal page (the socket enforces it too):
    # with 'always', even a non-prod target asks for a reason first.
    pam.save_config(**{**pam.config(), "allow_connect": True,
                       "require_reason": "always"})
    rt = pam.save_target("", {"name": "Reason SSH", "protocol": "ssh",
        "address": "10.7.7.7", "auth_kind": "none"}, "sys")
    r = boss.get(f"/pam/targets/{rt}/terminal", follow_redirects=False)
    check("a target needing a justification shows the gate, not the terminal",
          r.status_code == 200 and "ticket URL" in r.text and "summary" in r.text
          and "Terminal</h1>" not in r.text)
    r = boss.get(f"/pam/targets/{rt}/terminal?ticket=https%3A%2F%2Fjira%2FINC-9"
                 "&stime=30+minutes&summary=patch+it", follow_redirects=False)
    check("with all three parts supplied, the terminal page opens",
          r.status_code == 200 and "Terminal</h1>" in r.text)
    # A TIME THAT WAS TYPED rather than chosen is not a time: it was free text,
    # so it took "30m", "asap" and "half an hour", and nothing can be bounded
    # by prose -- which is why the field never did what its name said.
    r = boss.get(f"/pam/targets/{rt}/terminal?ticket=https%3A%2F%2Fjira%2FINC-9"
                 "&stime=30m&summary=patch+it", follow_redirects=False)
    check("...and a made-up length keeps the gate up",
          r.status_code == 200 and "Terminal</h1>" not in r.text)
    # It is offered as a LIST, so there is nothing to mistype.
    check("...the gate offers lengths to choose from",
          "<select name=\"stime\"" in r.text and ">30 minutes<" in r.text)
    # AND IT IS A LIMIT. Both relays take the shorter of the declared length
    # and the install's own maximum.
    mainsrc = (ROOT / "app" / "main.py").read_text()
    check("...which both relays enforce, taking whichever is shorter",
          mainsrc.count("pam.session_cap_seconds(") == 2
          and mainsrc.count("min(maxd, cap) if maxd else cap") == 1
          and mainsrc.count("min(maxd, _cap) if maxd else _cap") == 1)
    check("...and the length reads back as seconds",
          pam.session_cap_seconds("30 minutes") == 1800
          and pam.session_cap_seconds("2 hours") == 7200)
    # An older row with somebody's typed prose yields nothing, so the
    # install-wide limit applies -- which is what that row was created under.
    check("...while a legacy typed value bounds nothing, rather than guessing",
          pam.session_cap_seconds("half an hour") == 0)
    # a partial justification (no ticket) is still refused at the page
    r = boss.get(f"/pam/targets/{rt}/terminal?stime=30+minutes&summary=patch+it",
                 follow_redirects=False)
    check("a missing ticket keeps the gate up",
          r.status_code == 200 and "ticket URL" in r.text
          and "Terminal</h1>" not in r.text)
    pam.save_config(**{**pam.config(), "require_reason": "prod"})

    # Per-target scoping, through the HTTP routes: a user granted App A reaches
    # App A's recording and nothing of App B's — the sessions tab, the replay
    # page and the transcript download all agree. This is the exact request:
    # "grant App A → see only App A's records."
    ta = pam.save_target("", {"name": "Scoped-A", "protocol": "ssh",
        "address": "10.5.0.1", "auth_kind": "none"}, "sys")
    tb = pam.save_target("", {"name": "Scoped-B", "protocol": "ssh",
        "address": "10.5.0.2", "auth_kind": "none"}, "sys")
    sa = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id=ta,
                             target_name="Scoped-A", address="10.5.0.1")
    sa.output("id\r\nuid=0(root)\r\n"); sa.finish()
    sb = pam.start_recording("op", "1.1.1.1", protocol="ssh", target_id=tb,
                             target_name="Scoped-B", address="10.5.0.2")
    sb.output("id\r\nuid=0(root)\r\n"); sb.finish()
    semail, spw = "scoped-routes@t.local", "Only-App-A-Please-42"
    enrol(semail, spw, "viewer")
    su = auth.by_email(semail)
    srid = rbac.save("", "only Scoped-A", "", ["pam"], [], [], [ta])
    rbac.set_for_user(su["id"], [srid])
    scoped = TestClient(main.app); scoped.__enter__(); login(scoped, semail, spw)
    r = scoped.get("/pam?sec=sessions")
    check("the scoped sessions tab shows App A, not App B",
          r.status_code == 200 and "Scoped-A" in r.text and "Scoped-B" not in r.text)
    r = scoped.get(f"/pam/sessions/{sa.id}/transcript.txt")
    check("the scoped user downloads App A's transcript",
          r.status_code == 200 and "uid=0(root)" in r.text)
    r = scoped.get(f"/pam/sessions/{sb.id}/transcript.txt")
    check(f"the scoped user is refused App B's transcript ({r.status_code})",
          r.status_code == 404)
    r = scoped.get(f"/pam/sessions/{sb.id}", follow_redirects=False)
    check("the scoped user cannot open App B's replay page",
          r.status_code == 303 and "sec=sessions" in
          r.headers.get("location", ""))
    r = boss.get(f"/pam/sessions/{sb.id}/transcript.txt")
    check("an admin still reads either transcript", r.status_code == 200)

    print("...and REMOVING a recording needs the whole area, unconfined")
    # A recording is the EVIDENCE that a session happened, and the person with
    # the strongest reason to remove one is the person who did something in it.
    # So deletion cannot be part of the same grant as the ability to open the
    # session: it used to be `pam_connect`, which every operator of a target
    # holds, scoped to exactly the targets whose recordings they would want
    # gone.
    # THE USER THIS GATE EXISTS FOR: holds BOTH halves, so the ordinary
    # connect check lets them through, and is confined to one target -- the
    # operator of App A, whose own recording of App A this is. A first version
    # of this test used the read-only scoped user instead and passed for the
    # wrong reason: that user has no `pam_connect` at all, so they were already
    # refused before the new check was ever reached, and removing the check
    # broke nothing. A bite test is what found that.
    cemail, cpw = "connect-confined@t.local", "Holds-Both-But-Scoped-42"
    enrol(cemail, cpw, "viewer")
    cu = auth.by_email(cemail)
    crid = rbac.save("", "both halves, one target", "",
                     ["pam", "pam_connect"], [], [], [ta])
    rbac.set_for_user(cu["id"], [crid])
    check("holding BOTH halves is not enough while confined to targets",
          not rbac.may_pam_full(auth.by_email(cemail)))
    confined = TestClient(main.app); confined.__enter__()
    login(confined, cemail, cpw)
    # They may READ their own target's recording -- the scoping works.
    r = confined.get(f"/pam/sessions/{sa.id}/transcript.txt")
    check(f"...and they can still read that recording ({r.status_code})",
          r.status_code == 200)
    r = confined.post("/pam/session/delete", data={"sid": sa.id},
                      follow_redirects=False)
    loc = r.headers.get("location", "").replace("%20", "+")
    check(f"...but deleting it is refused ({r.status_code})",
          r.status_code == 303 and "Privileged+Access" in loc)
    check("...and the recording is still there afterwards",
          pam.session(sa.id) is not None)
    r = confined.post("/pam/sessions/clear", data={}, follow_redirects=False)
    loc = r.headers.get("location", "").replace("%20", "+")
    check(f"...a bulk clear is refused too ({r.status_code})",
          r.status_code == 303 and "Privileged+Access" in loc
          and pam.session(sa.id) is not None)
    # And the read-only scoped user is refused as well, by the older check --
    # asserted so the two reasons stay distinguishable.
    check("a read-only scoped operator is not full either",
          not rbac.may_pam_full(su))
    # ...and the same role with nothing named is the unconfined one an install
    # gives to whoever is accountable for the trail.
    frid = rbac.save("", "both halves, unconfined", "",
                     ["pam", "pam_connect"], [], [], [])
    rbac.set_for_user(cu["id"], [frid])
    check("the same two halves, confined to nothing, IS full",
          rbac.may_pam_full(auth.by_email(cemail)))
    check("...and an admin qualifies without a role at all",
          rbac.may_pam_full(auth.by_email(aemail)))
    # THE BUTTON FOLLOWS THE HANDLER, or the page offers something that is
    # refused on submit.
    r = scoped.get("/pam?sec=sessions")
    check("the page hides delete from somebody who may not delete",
          r.status_code == 200 and "/pam/session/delete" not in r.text
          and "/pam/sessions/clear" not in r.text)
    r = boss.get("/pam?sec=sessions")
    check("...and offers it to somebody who may",
          r.status_code == 200 and "/pam/session/delete" in r.text)
    # And an admin really can, so this did not just lock everybody out.
    r = boss.post("/pam/session/delete", data={"sid": sb.id},
                  follow_redirects=False)
    check(f"an admin deletes a recording ({r.status_code})",
          r.status_code == 303 and pam.session(sb.id) is None)

    print("an Ansible host can be named and labelled FROM the catalogue")
    # Asked for: the catalogue lists inventory hosts as bare IP addresses with
    # an empty hostname and label, and those are the two columns somebody needs
    # to tell one from another. An inventory host stays read-only for
    # everything that decides how it is REACHED -- address, port, user,
    # credential are its Ansible group's, and changing them here would move
    # what a playbook runs against -- but a name and a label change none of
    # that.
    dgid = ansible.save_group("", {"name": "cat-desc", "env": "test"}, "sys")
    dhid = ansible.add_host(dgid, "10.0.10.21", "10.0.10.21", "sys")
    t0 = pam.target(dhid)
    check("an inventory host arrives with neither, and is not editable here",
          t0["source"] == "ansible" and not t0["editable"]
          and not t0["hostname"] and not t0["label"])
    r = boss.post("/pam/target/describe", data={
        "tid": dhid, "hostname": "eu-preprod-ns01.internal",
        "label": "EU preprod DNS"}, follow_redirects=False)
    check(f"describing it from the catalogue works ({r.status_code})",
          r.status_code == 303)
    t1 = pam.target(dhid)
    check("...and the catalogue shows both",
          t1["hostname"] == "eu-preprod-ns01.internal"
          and t1["label"] == "EU preprod DNS")
    # ONE ROW, so the two pages cannot disagree. A copy kept beside the
    # inventory would drift the first time somebody edited the other page.
    inv = ansible.host(dhid)
    check("...written to the INVENTORY row, so Ansible shows them too",
          inv["hostname"] == "eu-preprod-ns01.internal"
          and inv["label"] == "EU preprod DNS")
    # WHAT SOMEBODY TYPED WINS over anything derived. This key appeared TWICE
    # in the same dict literal and the derived one silently won, so a typed
    # hostname vanished with no error anywhere -- found by testing the route,
    # not by reading it.
    check("...and the typed hostname beats the one derived from the name",
          pam.target(dhid)["hostname"] != "10.0.10.21")
    # STILL ONLY THOSE TWO. Everything that decides how it is reached is the
    # group's.
    r = boss.post("/pam/target/describe", data={
        "tid": dhid, "hostname": "bad name!", "label": "x"},
        follow_redirects=False)
    check(f"a hostname that is not a name is refused ({r.status_code})",
          r.status_code == 303
          and ansible.host(dhid)["hostname"] == "eu-preprod-ns01.internal")
    # ...and a fully qualified one IS a name: the inventory-name check caps at
    # 63 characters, which is one label's limit, not a hostname's.
    r = boss.post("/pam/target/describe", data={
        "tid": dhid, "hostname": "a.very.long.host.name.inside.some.company.example.internal",
        "label": "EU preprod DNS"}, follow_redirects=False)
    check("...while a fully qualified name is accepted",
          ansible.host(dhid)["hostname"].endswith("example.internal"))
    # A TARGET ENTERED HERE is edited on its own page, and this route says so
    # rather than half-working.
    npt = pam.save_target("", {"name": "Native-Desc", "protocol": "ssh",
        "address": "10.0.0.9", "auth_kind": "none"}, "sys")
    r = boss.post("/pam/target/describe", data={"tid": npt, "hostname": "x.y"},
                  follow_redirects=False)
    check("a target entered here is refused, with where to go instead",
          "not+an+inventory+host" in r.headers.get("location", "").replace(
              "%20", "+"))
    # And the row offers it, on the cells that were dashes and beside "in Ansible".
    body = boss.get("/pam?sec=targets").text
    check("the row offers the action rather than a dash and a tooltip",
          body.count("data-describe") >= 2 and 'id="dsxDlg"' in body)
    pam.delete_target(npt)
    ansible.delete_group(dgid)

    print("...and a PRODUCTION web target is reached through the console only")
    # `open` goes straight from somebody's own browser to the application: the
    # portal is not in the path, so there is no session to watch, nothing is
    # recorded, and the credential is not brokered. Reasonable on a test
    # system; the wrong trade on production, where the recorded console is the
    # whole reason this exists.
    tprod = pam.save_target("", {"name": "Prod-Web", "protocol": "https",
        "address": "app.prod.example", "url": "https://app.prod.example/",
        "env": "production", "auth_kind": "none"}, "sys")
    ttest = pam.save_target("", {"name": "Test-Web", "protocol": "https",
        "address": "app.test.example", "url": "https://app.test.example/",
        "env": "test", "auth_kind": "none"}, "sys")
    check("naming the env production marks the target production",
          bool(pam.target(tprod).get("is_prod"))
          and not pam.target(ttest).get("is_prod"))
    r = boss.get(f"/pam/targets/{tprod}/launch", follow_redirects=False)
    check(f"opening a production web target directly is REFUSED ({r.status_code})",
          r.status_code == 303
          and "sec=targets" in r.headers.get("location", "")
          and "app.prod.example" not in r.headers.get("location", ""))
    # ENFORCED IN THE ROUTE, not only in the row: this address is guessable
    # from any other target's, and a hidden button is not a control.
    r = boss.get(f"/pam/targets/{ttest}/launch", follow_redirects=False)
    check(f"...while a non-production one still opens ({r.status_code})",
          r.status_code == 303
          and "app.test.example" in r.headers.get("location", ""))
    # And the refusal is on the record: somebody TRIED, and that is worth as
    # much as the opens that succeed.
    trail = db.q("SELECT action, target, detail FROM audit "
                 "WHERE action = 'pam_web_open_refused' "
                 "ORDER BY rowid DESC LIMIT 1")
    check("...and the refusal itself is audited",
          bool(trail) and trail[0]["target"] == "Prod-Web"
          and "refused" in trail[0]["detail"])
    # THE ROW FOLLOWS. Stated rather than inherited -- another section of this
    # file leaves the gateway switch in whatever state it needed.
    pam.save_config(web_browser=True)
    body = boss.get("/pam?sec=targets").text
    def _prow(html, ident):
        cut = html[html.index(f'id="t-{ident}"'):]
        return cut[:cut.index("</tr>")]
    prow, trow = _prow(body, tprod), _prow(body, ttest)
    check("the production row offers no open at all",
          f"/pam/targets/{tprod}/launch" not in prow)
    check("...and says why, rather than dropping a button silently",
          "production" in prow and "recorded console" in prow)
    check("...and the non-production row still has its open",
          f"/pam/targets/{ttest}/launch" in trow)
    # The console is still the way in on production -- offered when the
    # gateway can serve it, and explained when it cannot, never absent.
    check("...and production still points at the console, one way or the other",
          (f"/pam/targets/{tprod}/console" in prow) or (">console<" in prow))


def seat_navigation() -> None:
    """What the browser is actually TOLD, and what makes a seat acceptable.

    Driven against a fake WebDriver rather than read out of the source,
    because every bug this section exists for was in the REQUEST or in what
    was done with the reply, and a source scan cannot see either. Measured
    against a real target first: the shipped code refused a working seat with
    "the browser did not answer: ReadTimeout" for 70 seconds while the browser
    sat on the page, rendered and titled.
    """
    import http.server
    import threading

    seen: dict = {}

    class _Driver(http.server.BaseHTTPRequestHandler):
        # What a real ChromeDriver does with a page that never finishes: the
        # navigation answers with a timeout error, and every read afterwards
        # is instant because nothing is pending any more.
        at = ""
        navigate_code = 200
        stall = 0.0          # seconds `GET /url` blocks, as a busy renderer does
        commit = True        # whether navigating makes the address readable

        def _say(self, obj: dict, code: int = 200) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:                              # noqa: N802
            if self.path.endswith("/status"):
                self._say({"value": {"ready": True}})
            elif self.path.endswith("/url"):
                # `GET /url` IS ITSELF A WEBDRIVER COMMAND, so while the
                # renderer is loading it QUEUES rather than answering "still
                # loading". Measured on a customer's target: four consecutive
                # reads each blocked the full client timeout.
                if _Driver.stall:
                    time.sleep(_Driver.stall)
                self._say({"value": _Driver.at})
            else:
                self._say({"value": None})

        def do_POST(self) -> None:                             # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.loads(raw or b"{}")
            if self.path.endswith("/session"):
                seen["caps"] = body["capabilities"]["alwaysMatch"]
                self._say({"value": {"sessionId": "s1", "capabilities": {}}})
            elif self.path.endswith("/url"):
                seen["went"] = body.get("url")
                seen["navigations"] = seen.get("navigations", 0) + 1
                if _Driver.at == "" and _Driver.commit:
                    _Driver.at = body.get("url") or ""
                self._say({"value": None}, _Driver.navigate_code)
            else:
                self._say({"value": None})

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Driver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    cfg = dict(pam.config(), web_namespace="browsers", web_driver_port=4444,
               web_page_timeout=7)
    url = "https://app.example.net:8443/x"

    def fresh() -> webseat.Seat:
        _Driver.at, _Driver.navigate_code = "", 200
        _Driver.stall, _Driver.commit = 0.0, True
        seen.clear()
        st = webseat.Seat({"name": "c"}, cfg, "pam-web-aaaaaaaa")
        st.ports = {4444: port, 5900: port}
        return st

    # AND THE BROWSER IS TOLD. A name allowed by the policy that the browser
    # may not RESOLVE is a name the page cannot use.
    _Driver.at, _Driver.navigate_code = "", 200
    _Driver.stall, _Driver.commit = 0.0, True
    seen.clear()
    st = webseat.Seat({"name": "c"}, cfg, "pam-web-alsoalso", "",
                      ("api.app.example", "assets.app.example"))
    st.ports = {4444: port, 5900: port}
    st.open_url(url)
    rule = [a for a in seen["caps"]["goog:chromeOptions"]["args"]
            if a.startswith("--host-resolver-rules")][0]
    check(f"the seat may resolve the target and the page's other hosts "
          f"({rule[-46:]})",
          "EXCLUDE app.example.net" in rule
          and "EXCLUDE api.app.example" in rule
          and "EXCLUDE assets.app.example" in rule)
    check("...and every other name is still unresolvable",
          rule.startswith("--host-resolver-rules=MAP * ~NOTFOUND"))
    # A target with no extra hosts is untouched.
    seen.clear()
    st = webseat.Seat({"name": "c"}, cfg, "pam-web-plainone")
    st.ports = {4444: port, 5900: port}
    _Driver.at = ""
    st.open_url(url)
    plain = [a for a in seen["caps"]["goog:chromeOptions"]["args"]
             if a.startswith("--host-resolver-rules")][0]
    check(f"a target with no extra hosts excludes only its own ({plain[-34:]})",
          plain == "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE app.example.net")

    print("a slow target does not spend the budget ANSWERING, and is not refused")
    # THE CUSTOMER'S FAILURE, reproduced. `GET /url` blocks while the renderer
    # is busy; with a per-read timeout of DRIVER_TIMEOUT (60s) against a budget
    # of `web_page_timeout`, ONE blocked read spent the whole budget and the
    # deadline -- checked only after it returned -- was already gone. The seat
    # was refused after a single look, and the refusal blamed the settle time
    # or the seat's network. Measured on the real target: the browser had
    # arrived; nobody had managed to ask it.
    slow = dict(cfg, web_page_timeout=2)
    _Driver.at, _Driver.navigate_code = "", 200
    _Driver.stall, _Driver.commit = 5.0, False
    seen.clear()
    st = webseat.Seat({"name": "c"}, slow, "pam-web-slowslow", "sid-slow")
    st.ports = {4444: port, 5900: port}
    t0 = time.monotonic()
    try:
        st.open_url(url)
        refused = ""
    except webseat.Refused as e:
        refused = str(e)
    took = time.monotonic() - t0
    # A read that cannot outlive the budget is the whole point: unbounded, this
    # waits for the stall (5s) instead of the budget (2s).
    check(f"no single read outlives the budget ({took:.1f}s for a 2s budget)",
          took < 4.0)
    check(f"and a browser that has not YET answered is not refused ({refused!r})",
          refused == "")
    check("the person is told it is still opening, rather than told nothing",
          "still opening" in webseat.progress("sid-slow"))
    webseat.forget("sid-slow")

    print("...but a browser that went ELSEWHERE is still refused")
    # The one arrival fact that IS a verdict. Confinement is the egress policy
    # and the resolver rule, not this check -- but a seat demonstrably on
    # another host is a different session from the one that was authorised.
    _Driver.at, _Driver.navigate_code = "https://evil.example.org/", 200
    _Driver.stall, _Driver.commit = 0.0, False
    seen.clear()
    st = webseat.Seat({"name": "c"}, dict(cfg, web_page_timeout=1),
                      "pam-web-elsewher")
    st.ports = {4444: port, 5900: port}
    try:
        st.open_url(url)
        wrong = ""
    except webseat.Refused as e:
        wrong = str(e)
    check(f"going to another host is still a refusal ({wrong!r})",
          "evil.example.org" in wrong and "instead of" in wrong)
    _Driver.stall, _Driver.commit = 0.0, True

    print("what the browser is TOLD, and when the seat is handed over")
    seat = fresh()
    seat.open_url(url)
    caps = seen["caps"]
    args = caps["goog:chromeOptions"]["args"]
    check("a session is created and the target is navigated to separately",
          seen.get("went") == url)
    # THE FIX. `--app=<target>` made the target's page load part of session
    # creation, and with the default strategy that POST does not return until
    # the page fires `load` — which a PWA with a live connection never does.
    check("the session opens on about:blank, not on the target",
          "--app=about:blank" in args
          and not any(a.startswith("--app=http") for a in args))
    check("and it does not wait for the page to report it finished",
          caps["pageLoadStrategy"] == "none")
    # `eager` was tried and cost the WHOLE timeout, because the measured
    # target fires neither `load` nor DOMContentLoaded inside it.
    check("...specifically not eager, which was measured and rejected",
          caps["pageLoadStrategy"] != "eager")
    check("the window still has no address bar or tab strip",
          "--kiosk" in args)
    # The page bound comes from CONFIG. Hard-coded, a slow application is a
    # guaranteed failure on somebody else's estate.
    check("the page bound is the configured one, not a constant",
          caps["timeouts"]["pageLoad"] == 7000)
    # EVERY OTHER HOST FAILS TO RESOLVE, INSTANTLY. Measured: the target's own
    # login page sat on its spinner for ever behind a third-party tag manager,
    # because a DROPPED packet is not a refusal — the browser waits out a TCP
    # timeout. Nine seconds in, the DOM had not moved.
    rule = next((a for a in args if a.startswith("--host-resolver-rules=")), "")
    check("every other host is made unresolvable, so denial is instant",
          "MAP * ~NOTFOUND" in rule)
    check("...except the target's own host",
          "EXCLUDE app.example.net" in rule)
    check("and the rule names the HOST, never the whole address",
          "8443" not in rule and "/x" not in rule)
    # NO "Chrome is being controlled by automated test software". Reported from
    # a real session, and measured on a real cluster: the bar cost 56px of an
    # 800px seat (viewport 1280x744 with it, 1280x800 without) — which is the
    # same 57px offset the reported session's own recording shows on its page
    # frame. `--disable-infobars` is the flag people reach for and has done
    # nothing for years; the bar hangs off the `enable-automation` switch.
    check("the automation bar is not part of the seat",
          caps["goog:chromeOptions"].get("excludeSwitches")
          == ["enable-automation"])
    check("...and it is not attempted with the flag that no longer works",
          not any("disable-infobars" in a for a in args))

    print("...and the console pane can BE the screen")
    con = (ROOT / "templates" / "pam_console.html").read_text()
    check("there is a full-screen control",
          'id="conFull"' in con)
    # THE PANE, not the page: what somebody wants filled is the desktop they
    # are working in, not the portal's sidebar and breadcrumbs with it.
    check("it puts the DESKTOP full screen, not the document",
          "wrap.requestFullscreen" in con
          and "document.body.requestFullscreen" not in con)
    check("and it toggles back out rather than trapping the reader",
          "exitFullscreen" in con)
    # A scale computed from the pane is the WRONG scale on a screen, so the
    # fit has to run again on the change — without it the desktop stays
    # pane-sized in the middle of a full screen.
    # BOTH listeners, matched exactly. `webkitfullscreenchange` CONTAINS
    # `fullscreenchange`, so a loose substring check passed with the standard
    # listener deleted — the same boundary-not-substring trap the `.pf-note`
    # rule hit.
    check("the fit runs again when the screen changes under it",
          "const refit = () => setTimeout(autoFit, 60);" in con
          and "addEventListener('fullscreenchange', refit)" in con
          and "addEventListener('webkitfullscreenchange', refit)" in con)
    # Scaling ABOVE 1 ONLY in full screen, which is the one place the surface
    # is genuinely a different size from the desktop. In a window the desktop
    # IS the pane, so any scale but 1 means stretching a fixed framebuffer --
    # and inside the page, growing past native would blow the card apart.
    check("it may scale past native ONLY in full screen",
          "if (!full) scale = Math.min(scale, 1);" in con)

    print("...and a navigation that never completes is not a failed seat")
    # THE BUG, exactly: ChromeDriver answers the navigation with an error when
    # its own pageLoad timeout fires, and the old code turned that into a
    # refusal — throwing away a session whose browser was on the page.
    seat = fresh()
    _Driver.at = url                  # the browser IS there
    _Driver.navigate_code = 500       # ...and the navigation "failed"
    try:
        seat.open_url(url)
        got = seat.driver_session
    except webseat.Refused as e:
        got = f"refused: {e}"
    check(f"a timed-out navigation still yields a seat ({got})",
          got == "s1")

    print("...and a navigation that never commits is RETRIED")
    # A CLAIMED SPARE is a running pod whose egress policy was just changed
    # underneath it — from the DNS-only rule a spare waits on to one naming
    # the target — and a CNI does not necessarily program that before the
    # browser's first packet. A dropped packet is not a refused one: Chrome
    # shows an error page for a refusal and hangs for ever on a drop, which
    # is why the symptom is a blank page rather than an error, and Chrome
    # never retries a hung navigation. A fresh seat never had this problem
    # because it is created with the right policy already on it — exactly the
    # kind of difference that only shows up on somebody else's cluster.
    seat = fresh()
    _Driver.at = "about:blank"          # never commits
    try:
        seat.open_url(url)
    except webseat.Refused:
        pass
    tries = seen.get("navigations", 0)
    check(f"the navigation is re-issued while it has not committed ({tries}x "
          f"in {cfg['web_page_timeout']}s)", tries >= 2)
    # ...and NOT re-issued once it has arrived, or every session would order
    # the page again on top of itself.
    seat = fresh()
    seen["navigations"] = 0
    _Driver.at = ""                     # commits on the first navigate
    seat.open_url(url)
    check(f"but not once it has arrived ({seen.get('navigations')}x)",
          seen.get("navigations") == 1)

    print("...and a browser still on a blank page says what to DO")
    # Reported from a customer install: "the browser is on nothing, not
    # <host>". True, and it leaves the reader nowhere. Still on about:blank
    # means the page had not begun to arrive, which is either too short a
    # settle time — theirs had collapsed to the 5s minimum — or a target the
    # SEAT cannot reach. The seat's network is not the portal's, and that is
    # the part nobody thinks of.
    seat = fresh()
    seat.sid = "sid-blank"
    _Driver.at = "about:blank"
    # IT IS SAID, NOT RULED. The advice below was written for a refusal, and
    # refusing is what threw away working seats -- the browser had arrived and
    # simply had not answered yet. So the seat is handed over and the same
    # guidance arrives as the progress line, to somebody who can now also see
    # the screen it is about.
    seat.open_url(url)
    msg = webseat.progress("sid-blank")
    check(f"a browser still on a blank page is NOT refused ({msg[:40]}…)",
          bool(msg))
    check("it does not just say 'on nothing'", "on nothing" not in msg)
    check("...it names the setting to raise, with the value in force",
          "settle" in msg and str(cfg["web_page_timeout"]) in msg)
    check("...and that the SEAT is what must reach the target",
          "reach" in msg and "not through" in msg)
    webseat.forget("sid-blank")
    # A browser that went somewhere ELSE is a different fault and keeps its
    # own sentence — that one is a confinement problem, not a slow page.
    seat = fresh()
    _Driver.at = "https://www.google.com/"
    try:
        seat.open_url(url)
        check("...and going elsewhere still reads differently", False)
    except webseat.Refused as e:
        check(f"...and going elsewhere still reads differently ({str(e)[:40]}…)",
              "google.com" in str(e) and "settle" not in str(e))

    print("...and a browser that went somewhere else is refused")
    # The other direction, which must NOT be waved through: a seat that ends
    # up off the target is not confined to the application it was opened for.
    seat = fresh()
    _Driver.at = "https://www.google.com/"
    try:
        seat.open_url(url)
        check("a seat that left the target is refused", False)
    except webseat.Refused as e:
        check(f"a seat that left the target is refused ({e})",
              "google.com" in str(e) and "app.example.net" in str(e))
    # A REDIRECT INSIDE THE APPLICATION IS THE APPLICATION WORKING. /login
    # sending somebody to /dashboard must not read as an escape, so only the
    # host is compared.
    seat = fresh()
    _Driver.at = "https://app.example.net:8443/dashboard?next=1"
    seat.open_url(url)
    check("but a redirect to another PATH on the target is fine",
          seat.driver_session == "s1")
    check("_host_of folds case and survives junk",
          webseat._host_of("https://APP.Example.NET/x") == "app.example.net"
          and webseat._host_of("") == "")
    srv.shutdown()


def orphan_reaping() -> None:
    """A finished seat is collected; a LIVE one is not.

    The first version of this read the labels out of a `jsonpath` template
    separated by spaces. jsonpath emits an absent label as an EMPTY field and
    `.split()` collapses whitespace, so a seat created directly — a session
    and no spare label — came back as two fields with its session id sitting
    in the spare column. It then looked like a pod naming no session at all,
    which is this function's definition of rubbish, and it would have deleted
    the browser somebody was using. That is what this test is for, so it is
    driven with a pod whose spare label is ABSENT.
    """
    print("orphaned seats are reaped, and live ones are not")
    cfg = dict(pam.config(), web_cluster="c-x", web_namespace="browsers")
    pods = {"items": [
        # a seat serving a live session, with NO spare label at all
        {"metadata": {"name": "pam-web-aaaaaa01",
                      "labels": {"envmap.tech/session": "live-1"}}},
        # a seat whose session has ended
        {"metadata": {"name": "pam-web-bbbbbb02",
                      "labels": {"envmap.tech/session": "done-2"}}},
        # an unclaimed spare, waiting for somebody
        {"metadata": {"name": "pam-web-cccccc03",
                      "labels": {"envmap.tech/spare": "yes"}}},
        # something else entirely, which must never be touched
        {"metadata": {"name": "some-other-pod",
                      "labels": {"envmap.tech/session": "done-9"}}},
    ]}
    killed: list = []
    saved = (webseat._clusters, webseat._kubectl, webseat.delete,
             webseat.drop_policy, webseat.kube.base_args)
    try:
        webseat.kube.base_args = lambda cl: ["kubectl"]
        webseat._clusters = lambda: {"c-x": {"name": "c"}}
        webseat._kubectl = lambda *a, **k: type(
            "R", (), {"stdout": json.dumps(pods), "returncode": 0})()
        webseat.delete = lambda cl, ns, n: killed.append(n)
        webseat.drop_policy = lambda cl, ns, n: None
        gone = webseat.reap_orphans(cfg, {"live-1"})
    finally:
        (webseat._clusters, webseat._kubectl, webseat.delete,
         webseat.drop_policy, webseat.kube.base_args) = saved
    check(f"the finished seat is collected ({gone})",
          "pam-web-bbbbbb02" in gone)
    # THE ONE THAT MATTERS. A live seat with no spare label is the shape the
    # broken parse mangled.
    check("the LIVE seat is left alone, spare label absent and all",
          "pam-web-aaaaaa01" not in gone)
    check("the unclaimed spare stays in the pool",
          "pam-web-cccccc03" not in gone)
    check("and a pod that is not a seat is never touched",
          "some-other-pod" not in gone and "some-other-pod" not in killed)
    check("what it reports is what it deleted",
          sorted(killed) == sorted(gone))

    print("...and a policy whose pod is gone is collected too")
    # `drop_policy` runs when the PORTAL deletes a seat — but a pod that dies
    # of its own activeDeadlineSeconds is never deleted by us, so its
    # NetworkPolicy stayed for ever. Found on a customer's cluster holding one
    # from twenty hours earlier; they accumulate one per seat that ever timed
    # out. Harmless individually and unbounded in aggregate, which is the
    # worst shape for a leak — nothing ever fails because of it.
    dropped: list = []
    saved2 = (webseat._clusters, webseat._kubectl, webseat.delete,
              webseat.drop_policy, webseat.kube.base_args)
    try:
        webseat.kube.base_args = lambda cl: ["kubectl"]
        webseat._clusters = lambda: {"c-x": {"name": "c"}}

        def two_calls(cl, argv, timeout):
            if "networkpolicy" in argv:
                # one policy for a live pod, one orphan, one not ours
                return type("R", (), {"returncode": 0, "stdout":
                    "pam-web-aaaaaa01\npam-web-deadbeef\nsomebody-elses\n"})()
            return type("R", (), {"returncode": 0, "stdout": json.dumps(
                {"items": [{"metadata": {"name": "pam-web-aaaaaa01",
                                         "labels": {"envmap.tech/session": "live-1"}}}]})})()
        webseat._kubectl = two_calls
        webseat.delete = lambda cl, ns, n: killed.append(n)
        webseat.drop_policy = lambda cl, ns, n: dropped.append(n)
        out2 = webseat.reap_orphans(cfg, {"live-1"})
    finally:
        (webseat._clusters, webseat._kubectl, webseat.delete,
         webseat.drop_policy, webseat.kube.base_args) = saved2
    check(f"the orphaned policy is dropped ({dropped})",
          "pam-web-deadbeef" in dropped)
    check("the policy of a LIVE seat is left alone",
          "pam-web-aaaaaa01" not in dropped)
    # It only ever touches names this module creates, so nothing of anybody
    # else's is collected by a sweep of a shared namespace.
    check("and a policy that is not ours is never touched",
          "somebody-elses" not in dropped and "somebody-elses" not in out2)


def watching_live() -> None:
    """A live session can be WATCHED, not only ended.

    Asked for directly: the Active tab offered one action, `end`, while the page
    already promised watching in two places ("open sessions you can watch or
    end"). A page that claims a capability it does not have is worse than one
    that never mentioned it.

    Watching is a TAIL of the asciinema cast the session is already writing,
    which is what makes it read-only by construction: there is no path from the
    window back to the terminal.
    """
    import json as _json
    from fastapi.testclient import TestClient

    from app import auth, db, main, pam, rbac

    print("a live session can be watched as it runs")
    uid = auth.create_user("watch@t.local", "W", "Watch-Pass-Word-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "watch@t.local",
                           "password": "Watch-Pass-Word-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)

    rec = pam.start_recording("someone@t.local", "10.0.0.9", protocol="ssh",
                              target_id="t-live", target_name="db01",
                              address="10.0.0.9", pid="", rgid="",
                              source="pam", rec_kind="asciinema",
                              rows=24, cols=100)
    pam.register_active(rec.id, {"who": "someone@t.local", "target": "db01",
                                 "target_id": "t-live", "address": "10.0.0.9",
                                 "protocol": "ssh", "ip": "10.0.0.9",
                                 "cast": rec.cast.path}, lambda: None)
    rows = [r for r in pam.active_sessions() if r["id"] == rec.id]
    check("the live row says it is watchable", rows and rows[0]["watchable"])
    check(f"and says WHO is on it ({rows[0]['who'] if rows else '?'})",
          rows and rows[0]["who"] == "someone@t.local")
    # A filesystem path on a page is a filesystem path in somebody's browser.
    check("but never carries the recording's path",
          rows and "cast" not in rows[0])

    rec.output("hello from the host\r\n")
    j = c.get(f"/pam/session/{rec.id}/live.json?frm=0").json()
    seen = [_json.loads(l)[2] for l in j.get("text", "").split("\n")
            if l.strip().startswith("[")]
    check(f"the first poll shows what the host printed ({seen})",
          j.get("ok") and j.get("live") and "hello from the host\r\n" in seen)

    # INCREMENTAL, or every poll replays the whole session from the top.
    rec.output("second line\r\n")
    j2 = c.get(f"/pam/session/{rec.id}/live.json?frm={j['next']}").json()
    seen2 = [_json.loads(l)[2] for l in j2.get("text", "").split("\n")
             if l.strip().startswith("[")]
    check(f"the next poll returns ONLY what is new ({seen2})",
          seen2 == ["second line\r\n"])

    print("...and watching is a READ, gated apart from ending")
    # The same recording this reader may open the moment the session closes, so
    # requiring pam_connect to watch would be stricter than the thing it
    # protects. Ending is the escalating one.
    reader = auth.create_user("look@t.local", "L", "Look-Pass-Word-42",
                              role="user")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", reader))
    # The read area and nothing else — no pam_connect, so this account can
    # watch and must not be able to end.
    rid = rbac.save("", "watcher", "", ["pam"], [], [], [])
    db.run("UPDATE users SET disabled=0 WHERE id=?", (reader,))
    rbac.set_for_user(reader, [rid])
    rc = TestClient(main.app)
    rc.__enter__()
    rc.post("/login", data={"email": "look@t.local",
                            "password": "Look-Pass-Word-42"},
            follow_redirects=False)
    rc.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    r = rc.get(f"/pam/session/{rec.id}/live.json?frm=0")
    check(f"somebody with the read area may watch ({r.status_code})",
          r.status_code == 200 and r.json().get("ok"))
    k = rc.post(f"/pam/session/{rec.id}/kill")
    check(f"but may NOT end it ({k.status_code})", k.status_code == 403)

    print("...and it stops when the session does")
    rec.finish()
    pam.drop_active(rec.id)
    j3 = c.get(f"/pam/session/{rec.id}/live.json?frm=0").json()
    check(f"a closed session reports done, so the watcher stops polling "
          f"(live={j3.get('live')}, done={j3.get('done')})",
          j3.get("ok") and not j3.get("live") and j3.get("done"))

    print("...and a recording outside the data directory is refused")
    # Same containment rule the replay path applies: this reads a file named by
    # a session record, and a record is not a reason to read anything on disk.
    pam.register_active("s-escape", {"who": "x", "target": "t", "target_id": "",
                                     "address": "", "protocol": "ssh",
                                     "ip": "", "cast": "/etc/passwd"},
                        lambda: None)
    check("a cast path outside DATA resolves to nothing",
          pam.live_cast("s-escape") == "")
    out = c.get("/pam/session/s-escape/live.json?frm=0").json()
    check("so the route hands back no content for it",
          out.get("ok") and not out.get("text"))
    pam.drop_active("s-escape")

    print("...and EVERY tab reports the live count, not only the Active one")
    # Reported: "in the main page for pam I can see 0 running even though there
    # is running sessions". `active` was built only when cur == "active", and
    # BOTH the tab badge and the "live now" tile render `active|length` — so
    # every other tab said zero while sessions were running. That is the
    # clickable-tiles rule broken in the way that matters most: a tile claiming
    # nothing is happening.
    live2 = pam.start_recording("someone@t.local", "10.0.0.9", protocol="ssh",
                                target_id="t-count", target_name="db02",
                                address="10.0.0.9", pid="", rgid="",
                                source="pam", rec_kind="asciinema",
                                rows=24, cols=100)
    pam.register_active(live2.id, {"who": "someone@t.local", "target": "db02",
                                   "target_id": "t-count",
                                   "address": "10.0.0.9", "protocol": "ssh",
                                   "ip": "10.0.0.9",
                                   "cast": live2.cast.path}, lambda: None)
    for tab, name in (("", "Targets"), ("sessions", "Recordings"),
                      ("active", "Active")):
        page = c.get("/pam" + (f"?sec={tab}" if tab else "")).text
        # The tile is the number above the words "live now"; finding it by that
        # anchor rather than by a count of digits is what makes this readable
        # when it fails.
        chunk = page.split("live now")[0][-260:] if "live now" in page else ""
        check(f"the {name} tab shows the live session on its tile "
              f"(...{chunk[-70:].strip()[-40:]})",
              ">1<" in chunk or ">1 <" in chunk)
    live2.finish()
    pam.drop_active(live2.id)

    print("...and the page offers the control, disabled where it cannot work")
    page = (pathlib.Path(__file__).resolve().parent.parent / "templates"
            / "pam.html").read_text()
    check("the Active row carries a watch control",
          'data-pamwatch="{{ a.id }}"' in page)
    # WATCHING IS TWO MECHANISMS and the row picks by session. An SSH cast is
    # line-buffered, so watching it is tailing the file it already writes; a
    # desktop has no such tail, but guacd will let a second viewer JOIN the
    # connection it is running — the same screen, live.
    root = pathlib.Path(__file__).resolve().parent.parent
    act = page[page.index("Live sessions"):]
    check("a desktop session is watched by joining the gateway",
          "/pam/session/{{ a.id }}/shadow?mode=watch" in act)
    check("and taking the keyboard is its own action",
          "/pam/session/{{ a.id }}/shadow?mode=control" in act)
    # An inapplicable action is DISABLED with a reason, never removed, so the
    # row's controls do not jump between rows.
    check("which is DISABLED rather than hidden when it cannot work",
          act.count('class="abtn" disabled') >= 2)
    # TAKING CONTROL ENDS IN A KEYBOARD ON SOMEBODY'S MACHINE, so it is gated
    # like opening a session rather than like reading a recording.
    check("taking control is gated on the connect permission",
          "{% if a.shadowable and may_connect %}" in act)
    check("...while watching is not, being the same thing as the recording",
          "{% if a.shadowable %}" in act
          and act.index("{% if a.shadowable %}")
              < act.index("{% if a.shadowable and may_connect %}"))

    print("...and the recording ends on THIS install's name")
    # Reported after watching a recording back: the last thing on it was the
    # browser image's own desktop, which is this product's plumbing captioning
    # somebody's audit evidence — the same objection as the automation bar.
    import urllib.parse as _u
    page_url = webseat.brand_page("DevOps EnvMap")
    doc = _u.unquote(page_url.split(",", 1)[1])
    check("it is a data: URL, so a confined seat needs no egress for it",
          page_url.startswith("data:text/html"))
    check("the install's name is on it", "DevOps EnvMap" in doc)
    # NO ORGANISATION NAME. It used to print the brand's SUBTITLE under the
    # name, which on the install it was written against read as a company —
    # a company name on the last frame of somebody's audit evidence. Reported
    # on sight. A recording is a record of what an operator did, not a place
    # to sign the work.
    check("and NOT the brand's subtitle, whatever it says",
          "environments, mapped" not in
          _u.unquote(webseat.brand_page("DevOps EnvMap").split(",", 1)[1]))
    msrc0 = (ROOT / "app" / "main.py").read_text()
    tail0 = msrc0[msrc0.index("async def pam_guac_socket"):]
    tail0 = tail0[:tail0.index("\n@app.")]
    check("...and the relay does not pass one",
          'seat.farewell, b["name"], ""' in tail0
          and 'b.get("org")' not in tail0)
    # The slot survives for the product's own ADDRESS, which is a fact about
    # the software rather than a name about a company.
    check("a site line renders when there is one to render",
          "envmap.example" in _u.unquote(
              webseat.brand_page("X", "envmap.example").split(",", 1)[1]))
    check("...with the mark above the name",
          "<svg" in doc and doc.index("<svg") < doc.index('class="n"'))
    # THE MARK FOLLOWS THE HOUSE RULE: it appears only when the install is not
    # wearing somebody else's name. Our logo over a customer's name would be
    # worse than no logo at all.
    theirs = _u.unquote(webseat.brand_page("Acme Ops", "", mark=False)
                        .split(",", 1)[1])
    check("a rebranded install gets its own name and NOT our mark",
          "Acme Ops" in theirs and "<svg" not in theirs)
    check("and a brand name cannot inject markup into it",
          "<script>" not in _u.unquote(
              webseat.brand_page("<script>x</script>", "").split(",", 1)[1]))
    # THE ORDERING IS THE WHOLE TRICK. guacd stops writing the recording the
    # moment its socket closes, so a farewell drawn after `writer.close()`
    # would be shown to nobody and recorded onto nothing.
    msrc = (root / "app" / "main.py").read_text()
    tail = msrc[msrc.index("async def pam_guac_socket"):]
    tail = tail[:tail.index("\n@app.")]
    # Read inside the FINALLY, because `writer.close()` also appears far
    # earlier as the session's kill switch (`register_active`'s closer) — and
    # comparing against that occurrence made this pass while proving nothing.
    fin = tail[tail.rindex("    finally:"):]
    # COMMENTS STRIPPED FIRST. The comment explaining this ordering names
    # `writer.close()` and sits above the call, so the un-stripped block put
    # the words in the wrong order and failed a correct implementation — the
    # mirror image of a test its own documentation can satisfy.
    fin = "\n".join(ln for ln in fin.split("\n")
                    if not ln.strip().startswith("#"))
    check("the sign-off is shown BEFORE the gateway socket is closed",
          "seat.farewell" in fin
          and fin.index("seat.farewell") < fin.index("writer.close()"))
    # And it must never hold a teardown open: a session that has finished is
    # finished, and failing to draw a logo is not a reason to leave a browser
    # logged in to a production application.
    wsrc = (root / "app" / "webseat.py").read_text()
    farewell_body = wsrc[wsrc.index("def farewell("):wsrc.index("def close(")]
    check("it is bounded and cannot fail a teardown",
          "FAREWELL_TIMEOUT" in wsrc
          and "contextlib.suppress" in farewell_body)

    print("...and a watcher has no way back to the keyboard")
    # THE READ-ONLY GUARANTEE IS A FILTER, not a property of joining: guacd
    # accepts mouse and key from any user on a shared connection, sharing being
    # a first-class feature of the protocol. Driven, not read: `sync` has to
    # pass (it is flow control and dropping it stalls the stream) and input
    # must not.
    msg = (pam.guac_instr("sync", "9").decode()
           + pam.guac_instr("mouse", "5", "6", "1").decode()
           + pam.guac_instr("key", "65", "1").decode()
           + pam.guac_instr("clipboard", "0", "text/plain").decode())
    watcher = [op for op, _ in pam.guac_ops(pam.guac_upstream(msg, False))]
    driver = [op for op, _ in pam.guac_ops(pam.guac_upstream(msg, True))]
    check(f"a watcher sends flow control and nothing else ({watcher})",
          watcher == ["sync"])
    check(f"somebody with control sends input too ({driver})",
          "mouse" in driver and "key" in driver and "sync" in driver)
    # A viewer must not be able to end the session it is only looking at, and
    # `disconnect` is how you would try. Dropped in BOTH directions.
    bye = pam.guac_instr("sync", "1").decode() + pam.guac_instr("disconnect").decode()
    check("neither can hang up on the operator",
          "disconnect" not in pam.guac_upstream(bye, False)
          and "disconnect" not in pam.guac_upstream(bye, True))
    # Length-prefixed framing: a ';' inside a value is not a boundary, or a
    # crafted clipboard would let an instruction be smuggled past the filter.
    tricky = pam.guac_instr("key", "a;b", "1").decode()
    check("a delimiter inside a value cannot smuggle an instruction",
          [op for op, _ in pam.guac_ops(tricky)] == ["key"]
          and pam.guac_upstream(tricky, False) == "")
    # And the WINDOW binds nothing when it is only watching — the other half
    # of the same promise, so a wrong filter still could not reach a keyboard.
    con = (root / "templates" / "pam_console.html").read_text()
    check("the watch window binds no keyboard or mouse",
          "{% if join and join.mode != 'control' %}" in con
          and con.index("{% if join and join.mode != 'control' %}")
              < con.index("new Guacamole.Keyboard(document)"))
    root = pathlib.Path(__file__).resolve().parent.parent
    win = (root / "templates" / "_pam_watch_dialog.html").read_text()
    check("and the window is the house .psh shape",
          '<dialog id="pwDlg" class="psh">' in win)
    # A MODAL WITH NO EXIT IS A TRAP, and the first version was one: it invented
    # `.psh-dot` (singular, no <b> inside), so no rule in app.css matched and
    # there was nothing on screen to close the window with. Check the class the
    # stylesheet actually defines, not merely that some attribute is present.
    css = (root / "static" / "app.css").read_text()
    check("the bar uses the dots class the stylesheet defines",
          ".psh-dots b" in css and '<span class="psh-dots"><b' in win)
    check("and there is a close button as well as the dot",
          'id="pwClose"' in win and 'class="psh-x"' in win)
    check("all three exits are wired (dot, button, Escape)",
          "data-pwdot" in win and "pwClose').addEventListener" in win
          and "'cancel'" in win)
    # EVERY class the window uses has to be one the stylesheet defines — the
    # whole fault was a class that looked right and matched nothing. Checked as
    # a set rather than one by one, so a future invented class is caught too.
    used = set(re.findall(r'class="([^"]*psh[^"]*)"', win))
    names = {n for c in used for n in c.split() if n.startswith("psh")}
    missing = sorted(n for n in names if f".{n}" not in css)
    check(f"every psh- class it uses exists in app.css (missing: {missing})",
          not missing)

def file_transfer() -> None:
    """Upload and download inside a live session, over its own credential.

    VERIFIED AGAINST A REAL sshd, not only here. The whole flow — list, a text
    download, a 64kB binary download, an upload whose name carries a space AND
    a double quote — was run against an Alpine `openssh-server` container on
    :2222 with a real key, the way CLAUDE.md's PAM verification section
    describes. Three faults came out of doing that and none of them was visible
    by reading:

      * `sftp` spells the port `-P`; `ssh` spells it `-p`. The shared option
        list carried ssh's, and sftp answered with a usage error naming neither
        ("[-X sftp_option] destination").
      * the routes passed `pam.target()`, which strips the credential for
        pages, so a target with a perfectly good stored key answered
        "Permission denied (publickey)". The transfer functions take an ID now
        and resolve the row themselves.
      * ssh's own "Permanently added '[host]:port' to the list of known hosts"
        notice was merged into the parsed output and came back as a FILE called
        "Warning: Permanently added…" — on every first connection to a host.

    What is checked HERE is what can be checked without a host to reach: the
    argv (both credential paths), the quoting, the gates, and the audit line.
    A test needing docker would not run on a fresh checkout.
    """
    import inspect

    from fastapi.testclient import TestClient

    from app import ansible, auth, db, main, pam

    print("file transfer: the command, for both credential paths")
    # A REAL key, because the form validates one now: a target's key is put to
    # ssh at save time, the same as an Ansible group's has been since a mangled
    # paste took out a whole run. The placeholder this used to carry would be
    # refused today, which is the point.
    real_key, _ = ansible.new_keypair()
    tid = pam.save_target("", {"name": "filebox", "protocol": "ssh",
                               "address": "10.9.9.9", "port": 2222,
                               "username": "root", "auth_kind": "key",
                               "secret": "", "secret_key": real_key},
                          "ammar")
    work = pam.term_scratch()
    try:
        argv, penv = pam._sftp_argv(tid, work)
    finally:
        pam.drop_session_dir(work)
    # THE FLAG. -p is "preserve times" to sftp; the port must be -P, and the
    # usage error it answers with names neither the port nor the flag.
    check(f"the port is -P for sftp, never ssh's -p ({argv})",
          "-P" in argv and argv[argv.index("-P") + 1] == "2222"
          and "-p" not in argv)
    check("the batch is read from stdin, so no file holds the paths",
          "-b" in argv and argv[argv.index("-b") + 1] == "-")
    check("it runs the configured sftp binary, not a hardcoded one",
          argv[0] == pam.env.SFTP)
    check("the destination is last, and is user@address",
          argv[-1] == "root@10.9.9.9")
    check("the key never reaches argv — it is a file in the scratch dir",
          not any("PRIVATE KEY" in a for a in argv)
          and "-i" in argv)

    print("...and an inventory host uses its GROUP's key, via one shape-check")
    priv, _pub = ansible.new_keypair()
    gid = ansible.save_group("", {"name": "fleet", "ssh_user": "root",
                                  "key": priv}, "ammar")
    ansible.add_host(gid, "box1", "10.9.9.8", "ammar")
    ah = next((t["id"] for t in ansible.inventory_targets()
               if t["name"] == "box1"), "")
    check(f"the inventory host is reachable as a target ({ah})", bool(ah))
    work = pam.term_scratch()
    try:
        iargv, _p = pam._sftp_argv(ah, work)
    finally:
        pam.drop_session_dir(work)
    check(f"its command is sftp, not ssh, and has no -tt ({iargv[:2]})",
          iargv[0] == pam.env.SFTP and "-tt" not in iargv)
    check("with the port translated to -P as well",
          "-P" in iargv and "-p" not in iargv)
    check("and the destination the inventory gave", iargv[-1] == "root@10.9.9.8")
    # The shape-checking that stops a smuggled -o ProxyCommand= lives in
    # ansible.host_shell_argv; translating it means there is ONE copy of that
    # check, not two that can drift.
    src = inspect.getsource(pam._sftp_argv)
    check("built by translating host_shell_argv rather than rebuilding it",
          "host_shell_argv" in src)

    print("...and a path cannot smuggle a second sftp command")
    # THE INJECTION THAT MATTERS: `sftp -b` reads one command per LINE, so a
    # newline in a path is a second command running with the target's
    # credential. Refused outright rather than escaped.
    for bad in ("/tmp/x\nrm -rf /", "/tmp/x\rls /", "/tmp/x\x00y", ""):
        try:
            pam._sftp_quote(bad)
            check(f"a path containing {bad!r} is refused", False)
        except pam.Refused:
            pass
    check("a newline in a path is refused", True)
    # And the ordinary awkward names still work, because refusing those would
    # make the feature useless on a real box.
    check('a space survives quoting',
          pam._sftp_quote("/tmp/a b.txt") == '"/tmp/a b.txt"')
    check('a double quote is escaped, not refused',
          pam._sftp_quote('/tmp/say "hi"') == '"/tmp/say \\"hi\\""')

    print("...and a transfer needs a live session THIS person holds")
    uid = auth.create_user("mover@t.local", "M", "Move-Pass-Word-42",
                           role="admin")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
           ("TESTSECRET", uid))
    pam.save_config(enabled=True, allow_connect=True)
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": "mover@t.local",
                           "password": "Move-Pass-Word-42"},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    r = c.get(f"/pam/targets/{tid}/sftp/list?path=/root")
    check(f"with no session open, listing is refused ({r.status_code})",
          r.status_code == 403 and "open a session" in r.json()["error"])
    check("nothing was even attempted — no credential was unsealed",
          not pam.live_session_of("mover@t.local", tid))

    # Somebody ELSE's session is not a door either.
    pam.register_active("s-other", {"who": "someone.else@t.local",
                                    "target": "filebox", "target_id": tid,
                                    "address": "10.9.9.9", "protocol": "ssh",
                                    "ip": "10.0.0.1", "cast": ""},
                        lambda: None)
    r = c.get(f"/pam/targets/{tid}/sftp/list?path=/root")
    check(f"and another person's session does not count ({r.status_code})",
          r.status_code == 403)
    pam.drop_active("s-other")

    print("...and the transfer is AUDITED, because the recording cannot see it")
    pam.register_active("s-mine", {"who": "mover@t.local", "target": "filebox",
                                   "target_id": tid, "address": "10.9.9.9",
                                   "protocol": "ssh", "ip": "10.0.0.1",
                                   "cast": ""}, lambda: None)
    # 10.9.9.9 does not exist, so this fails at the connection — which is the
    # point: a REFUSED transfer must be in the log too, or the log only holds
    # the ones that worked.
    c.get(f"/pam/targets/{tid}/sftp/get?path=/etc/shadow")
    rows = auth.read_audit(30)
    hit = [r for r in rows if r["action"] == "pam_sftp_download"]
    check(f"a download attempt is audited ({len(hit)})", bool(hit))
    check(f"naming the target and the path ({hit[0]['target'] if hit else ''})",
          hit and "filebox" in hit[0]["target"] and "/etc/shadow" in hit[0]["target"])
    pam.drop_active("s-mine")

    print("...and the page offers it where a session lives")
    root = pathlib.Path(__file__).resolve().parent.parent
    term = (root / "templates" / "pam_terminal.html").read_text()
    check("the terminal has a Files control", 'id="wsxFiles"' in term)
    check("which opens the window for the FOCUSED tab, not the first",
          "S[active]" in term and "window.pamFiles(s.tid" in term)
    win = (root / "templates" / "_pam_files_dialog.html").read_text()
    check("the window is the house .psh shape",
          '<dialog id="pfDlg" class="psh">' in win)
    css = (root / "static" / "app.css").read_text()
    names = {n for c in re.findall(r'class="([^"]*psh[^"]*)"', win)
             for n in c.split() if n.startswith("psh")}
    missing = sorted(n for n in names if f".{n}" not in css)
    check(f"every psh- class it uses exists in app.css (missing: {missing})",
          not missing)
    check("a directory's download button is disabled, not dropped",
          "disabled title=" in win and "cannot be " in win)

    print("...and a transfer SHOWS ITS PROGRESS, in both directions")
    # Reported: "for upload and download there is no progress line or circle".
    # Uploads must go through XHR — `upload.onprogress` is the only way a
    # browser reports how much of a request BODY has gone, and fetch has no
    # equivalent, so a fetch upload can only ever show 0% then 100%.
    check("uploads use XHR for real body progress, not fetch",
          "new XMLHttpRequest()" in win and "upload.onprogress" in win)
    # Downloads are read as a stream and counted against Content-Length, so the
    # bar moves inside the window rather than only in the browser's own shelf.
    check("downloads are streamed and counted",
          "getReader" in win and "content-length" in win)
    check("and both land in one tray with a bar",
          'id="pfTrayRows"' in win and ".pf-bar i" in win
          and "paintJob" in win)
    check("a failed transfer says so on its row rather than vanishing",
          "'bad'" in win and "pf-why" in win)
    # A FINISHED ROW LOSES ITS BAR. A green stripe pinned at 100% is a
    # picture of nothing — reported as "this progress line looks so bad".
    check("a finished or failed row shows a word, not a full bar",
          ".pf-row.done .pf-bar, .pf-row.bad .pf-bar { display:none; }" in win
          and "job.state === 'done' ? 'done'" in win)
    # The bar was its own grid column with the name on a `1fr` beside it, so on
    # a wide window it floated in the middle of the row attached to nothing.
    check("bar, percentage and size are one right-aligned group",
          'class="pf-rail"' in win and ".pf-rail { display:flex" in win
          and "justify-self:end" in win)
    # THE DEAD SPACE, and it was inherited. `.psh-body` is `white-space:
    # pre-wrap` in app.css for the LOG window's preformatted text; this window
    # reuses that chrome, so every newline in its own markup became a real
    # line break. Measured: the tray was 286px tall for 168px of rows, three
    # whitespace text nodes accounting for 119 of them, and it was every gap in
    # the window rather than only the tray. 286 -> 170 after this one line.
    css = (root / "static" / "app.css").read_text()
    assert "white-space:pre-wrap" in css.replace(" ", "")
    check("the window opts out of the log chrome's pre-wrap",
          "white-space:normal" in win.replace(" ", ""))
    # EVERY pf- class the window uses must be one it DEFINES. The same fault as
    # the watch window's invented `.psh-dot`, and it happened again here: the
    # tray's clear button kept `class="pf-icon"` after that rule was deleted
    # with the pencil, so it fell back to the default filled button. Checked as
    # a set, so the next dangling class is caught rather than shipped.
    style = "\n".join(win.split("<style>")[i].split("</style>")[0]
                      for i in range(1, len(win.split("<style>"))))
    # Names are lifted from the markup AND from the strings the script builds
    # rows out of, then trimmed of the quote/concat punctuation that ends a
    # JavaScript fragment — `'<div class="pf-node' + (on ? ' on' : '')` yields
    # `pf-node'` otherwise, which is a false alarm rather than a finding.
    used = {n.strip("'\"+ ")
            for c in re.findall(r'class="([^"<>]*pf-[^"<>]*)', win)
            for n in c.split()}
    used |= {n.strip("'\"+ ")
             for c in re.findall(r"className = '([^']*)'", win)
             for n in c.split()}
    used = {n for n in used if n.startswith("pf-")}
    # The lookup needs a BOUNDARY, not a substring: `.pf-note` is a substring
    # of `.pf-noteX`, so a plain `in` check passed with the rule renamed out
    # from under it.
    dangling = sorted(n for n in used
                      if not re.search(r"\." + re.escape(n) + r"(?![\w-])",
                                       style))
    check(f"every pf- class it uses is one it defines (dangling: {dangling})",
          not dangling)
    # And the note's TWO STATES are two looks. `tell(text, bad)` toggles the
    # class either way; with only one rule defined, "some entries here could
    # not be read" and "this directory could not be read at all" rendered
    # identically, so the flag was doing nothing anybody could see.
    check("a failed listing reads differently from a remark about one",
          "note.classList.toggle('bad'" in win
          and re.search(r"\.pf-note\.bad\s*\{[^}]*danger", win))

    print("...and you can BROWSE it, not only type a path at it")
    # Asked for by name: "similar to when I open from FileZilla". Typing an
    # absolute path is what you do when you already know it; it is not a way to
    # look around, and it was the only way.
    check("there is a directory tree beside the listing",
          'id="pfTree"' in win and ".pf-split" in win)
    # Lazily, one directory per expand: a tree that walked the filesystem up
    # front would be a thousand sftp calls to draw a sidebar.
    check("loaded one directory at a time, not all at once",
          "function fetchKids" in win and "r.dir" in win)
    check("the twisty expands and the name navigates — two gestures, one row",
          "closest('.pf-twist')" in win and "load(pth)" in win)
    # A sidebar that does not follow the table is two views of one place that
    # disagree.
    check("the tree follows the listing and scrolls to where you are",
          "function reveal(" in win
          and "scrollIntoView({block: 'nearest'})" in win)
    # AND IT FETCHES NOTHING. `reveal` used to await fetchKids for every
    # ancestor, so one click into a four-deep path was five sequential round
    # trips — reported as "moving between the folders is so so so slow". The
    # spine is drawn from what is already known; siblings wait for a twisty.
    body = win[win.index("function reveal("):]
    body = body[:body.index("\n  function ")]
    # THE SLOWNESS WAS THE AWAIT, not the fetching. reveal used to `await
    # fetchKids` for every ancestor in turn, so a four-deep click was five
    # sequential round trips and nothing appeared until the last landed.
    check("reveal never AWAITS an ancestor — that was the slowness",
          "await fetchKids" not in body and "await " not in body)
    check("a listing already read is reused rather than asked for again",
          "if (!force && seen[at])" in win)
    # A cache nobody can escape is a cache that lies.
    check("and ↻ bypasses that cache", "load(at, true)" in win
          and "delete seen[at]" in win)
    # Unknown ancestors are asked for AT ONCE and unawaited, so the listing is
    # on screen after one round trip while the tree thickens behind it — the
    # same "draw now, fill in behind" rule the fleet pages follow. Fetching
    # nothing at all was the over-correction: it left a tree with no siblings
    # to click, which is most of what a tree is for.
    # Checked as the CALL, not as the absence of a word: the comment above it
    # says "unawaited", and a `"await" not in body` test matched that prose
    # rather than the code.
    check("unknown levels are asked for at once instead",
          "want.forEach(fetchKids)" in body)
    # Clicking a tree NAME must not fetch the directory twice: `load` takes the
    # children out of the listing it already asked for. Measured at 2 requests
    # per click before this, 1 after.
    click = win[win.index("treeEl.addEventListener"):]
    click = click[:click.index("\n  rowsEl.addEventListener")]
    check("and a tree click reads the directory ONCE",
          "load(pth)" in click and "if (!n.kids) fetchKids(pth)" not in click)

    print("...and ONE sftp session is kept open, because setup was half the cost")
    # The WHOLE module, not the one function `src` held at this point — a
    # local name reused for two different things is how these checks came to
    # look for `class _Sftp` inside `_sftp_argv`.
    mod = (pathlib.Path(__file__).resolve().parent.parent
           / "app" / "pam.py").read_text()
    # Measured against a host with 40ms each way, which is what localhost could
    # never show and the reason this was "fixed" twice while still being slow.
    # Per listing: 1.04s with no shared connection, 0.62s riding one, and 0.29s
    # of that 0.62 was opening a NEW sftp session — channel plus SFTP protocol
    # INIT — before a single command was sent. A kept-open session is 0.27s.
    check("there is a kept-open session per target",
          "class _Sftp" in mod and "_sessions" in mod)
    # Without this the FIRST bad path kills the session and every later click
    # reconnects. Found by trying it: the pipe broke on call two.
    check("every command is `-` prefixed so an error cannot end the batch",
          'f"-{c}\\n"' in mod)
    # A marker that cost a round trip would give back a third of the saving.
    check("the terminator is sftp's LOCAL version command",
          '_SFTP_END = "SFTP protocol version"' in mod
          and '"version\\n"' in mod)
    # A blocking readline on a process that has gone quiet is a held worker.
    check("output is pumped by a thread so a silent session can be given up on",
          "def pump(" in mod and "queue.Queue" in mod)
    check("and a session that stops answering is dropped, not reused",
          "drop_sftp_session(tid)" in mod)
    # The session OWNS its key: Popen returns as soon as the process exists,
    # not once sftp has authenticated, so dropping the scratch immediately gave
    # "Identity file … not accessible" on every session.
    check("the session holds its scratch for as long as it lives",
          "self.work = work" in mod and "drop_session_dir(self.work)" in mod)
    # `-` prefixed commands mean the exit code says nothing, so failure has to
    # be read out of the OUTPUT — and `_sftp_why` ends with "or else the last
    # line", which made every successful listing report its last file as an
    # error. Strict matching, no fallback.
    check("failure is detected strictly, with no last-line fallback",
          "def _sftp_fail(" in mod and "_FAILED = (" in mod)
    fail = mod[mod.index("def _sftp_fail("):]
    fail = fail[:fail.index("\ndef ")]
    check("and _sftp_fail really has no fallback",
          "lines[-1]" not in fail and 'return ""' in fail)
    # AND THE CALLER USES IT. Checking only _sftp_fail's own body could not see
    # `_sftp_talk` switching back to `_sftp_why`, which is the regression that
    # matters — the strict matcher existing is no use if nothing calls it.
    talk = mod[mod.index("def _sftp_talk("):]
    talk = talk[:talk.index("\ndef ")]
    check("and _sftp_talk decides with the strict matcher, not the fallback",
          "_sftp_fail(out)" in talk and "_sftp_why(" not in talk)
    # An exit code that says nothing also means an upload cannot be inferred.
    check("an upload is confirmed by reading the destination back",
          'f"ls -l {_sftp_quote(dest)}"' in mod and "did not appear" in mod)
    # Dropping the `cd` saves two round trips and changes the ANSWER: `ls -l
    # <path>` prints full paths where `cd` + `ls -l` prints bare names.
    check("an absolute path skips cd and pwd", 'if path.startswith("/")' in mod)
    check("and the full path is stripped back off the name",
          "if name.startswith(head)" in mod)

    print("...and the download button says what it does")
    # "get" was terse to the point of unclear; asked for directly.
    check("the action is labelled download, not get",
          "download</button>" in win and ">get</button>" not in win)
    # The universal idiom for going back, which having only a bar button hid.
    check("the listing carries a `..` row at the top",
          "pf-up pf-into" in win and 'pf-label">..</span>' in win)
    check("and a whole directory row enters it, not just its name",
          'class="pf-into" data-pfcd=' in win)
    # THE PATH BAR READS AND ACCEPTS, with no gesture in front of either.
    # It was a breadcrumb plus a pencil, and both halves were reported: at "/"
    # the breadcrumb said nothing about where you were, and reaching a known
    # path cost a click first.
    check("the path field is always visible, never behind a pencil",
          'id="pfPath"' in win and 'id="pfEdit"' not in win
          and "hidden" not in win[win.index('id="pfPathRow"'):
                                  win.index('id="pfFile"')])
    # Asserted as the ASSIGNMENT, not as the presence of a `drawPath` name: a
    # field that is never written to is a field that says "." for ever, which
    # is exactly what made the breadcrumb useless.
    # Both call sites, named. A COUNT of `drawPath()` calls passed with the
    # resolved-path one deleted, because the submit and Escape handlers call it
    # too — and it is the resolved one that carries the whole point: the server
    # turns "." into /root, so without it the box says "." while the listing
    # shows /root.
    check("and every arrival writes the resolved path into it",
          "function drawPath() { pathEl.value = at; }" in win
          and "at = j.path || at; drawPath();" in win
          and "at = path || '.';\n    drawPath();" in win)
    # Enter is handled on the FIELD, not left to the form's implicit
    # submission — that default is the browser's, keyed off the Enter keyCode,
    # and it is the one gesture that was asked for by name. `go` goes through
    # submit; both end in the same function.
    check("typing one and pressing Enter opens it",
          "if (ev.key === 'Enter') {" in win and "function go() {" in win
          and "load(want)" in win)
    check("and the go button ends in the same place",
          "pathRow.addEventListener('submit', ev => { ev.preventDefault(); "
          "go(); });" in win)
    # A dialog turns Escape into `cancel`, so without this, correcting a typo
    # and pressing Escape shut the whole window.
    check("Escape in the field undoes the typing instead of shutting the window",
          "if (pathEl.value === at) return;" in win
          and "ev.stopPropagation();" in win)

    print("...and the listing rides ONE ssh connection, not one per click")
    # Reported as "loading the files is too slow": every navigation opened a
    # fresh connection, which on a VPN is about six round trips of handshake.
    src = (root / "app" / "pam.py").read_text()
    check("a background master is opened explicitly",
          '"-M", "-f", "-N"' in src and "ControlPersist" in src)
    # sftp must USE a master, never try to be one: measured by hand, `sftp -o
    # ControlMaster=auto -o ControlPersist=90` leaves no socket behind at all.
    # The OPTION as it is passed, not the words. The first version matched
    # `ControlMaster=no` anywhere in the file and the docstring explaining the
    # choice satisfied it — so flipping the code to `auto` sailed through.
    check("and sftp only rides it, never becomes it",
          '"-o", "ControlMaster=no",' in src
          and '"-o", "ControlMaster=auto",' not in src)
    check("known_hosts is kept, so the host key is accepted once",
          "_sftp_home" in src and "known_hosts" in src)
    check("and the shared connection closes with the last session on a target",
          "drop_sftp_home" in src and "still" in src)

if __name__ == "__main__":
    sys.exit(1 if main() else 0)
