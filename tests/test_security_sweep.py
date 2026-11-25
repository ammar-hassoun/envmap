"""The real findings of the security sweeps, pinned so they cannot come back.

  * SEC-1: a recorded browser's WebDriver port never leaves the portal pod's
    loopback, and no seat is given the image's published VNC password -- the
    VNC forward DOES listen on the pod's address when guacd is not the sidecar
  * SEC-3: the HTML sanitiser behind Grafana text panels and SOPs judges a
    style or a link by what the BROWSER will read: a CSS escape or comment
    cannot smuggle `position:fixed` past it, and `/\\host` or `/<TAB>/host`
    (both `//host` to a browser) is not a same-site link

Each was found by `security/scan.sh` plus triage; the reports are in
`security/reports/`.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("secsweep-")
os.environ.setdefault("PORTAL_PAM", "1")

from app import grafview, pam, webseat  # noqa: E402

bad = 0


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


class FakeProc:
    def __init__(self, argv):
        self.argv = argv
        self.stdout = iter([])


def forwards() -> None:
    """SEC-1, part one: the argv of every port-forward a seat opens."""
    print("SEC-1 · WebDriver stays on loopback")
    for host in ("", "10.0.0.5"):
        cfg = {**pam.DEFAULTS, "web_seat_host": host}
        seat = webseat.Seat({"id": "c"}, cfg, "pam-web-aaaaaaaa")
        calls = []

        def fake(ports, address, calls=calls):
            calls.append((list(ports), address))
            return FakeProc([]), {p: 40000 + i for i, p in enumerate(ports)}

        seat._forward = fake
        seat.forward()
        drv, vnc = int(cfg["web_driver_port"]), int(cfg["web_vnc_port"])
        wide = [p for ports, addr in calls if addr for p in ports]
        check(f"guacd at {host or 'the sidecar'}: the driver port is never "
              f"forwarded on a non-loopback address ({calls})", drv not in wide)
        check(f"guacd at {host or 'the sidecar'}: both ports are forwarded",
              {drv, vnc} <= {p for ports, _ in calls for p in ports})
        if host:
            check("guacd elsewhere: only VNC is widened", wide == [vnc])
        else:
            check("guacd as the sidecar: nothing is widened", wide == [])


def passwords() -> None:
    """SEC-1, part two: what guards the VNC port when it is widened."""
    print("SEC-1 · every seat has its own VNC password")
    check("the shipped default is blank, not the image's own password",
          pam.DEFAULTS["web_vnc_password"] == "")
    for stored in ("", "secret", "  "):
        cfg = {**pam.DEFAULTS, "web_vnc_password": stored}
        a = webseat.vnc_password_for(cfg, "pam-web-aaaaaaaa")
        b = webseat.vnc_password_for(cfg, "pam-web-bbbbbbbb")
        check(f"stored {stored!r}: a seat never gets `secret` ({a})",
              a != "secret" and b != "secret")
        check(f"stored {stored!r}: two seats get different passwords",
              a != b)
        check(f"stored {stored!r}: 8 alphanumerics, all RFB reads ({a})",
              bool(re.fullmatch(r"[A-Za-z0-9]{8}", a)))
        check(f"stored {stored!r}: stable for a pod, so a spare claimed later "
              "still matches", a == webseat.vnc_password_for(cfg, "pam-web-aaaaaaaa"))
    cfg = {**pam.DEFAULTS}
    mf = webseat.manifest("pam-web-aaaaaaaa", cfg, "")
    env = {e["name"]: e["value"] for e in mf["spec"]["containers"][0]["env"]}
    seat = webseat.Seat({"id": "c"}, cfg, "pam-web-aaaaaaaa")
    check("the pod is given the password guacd is handed",
          env["SE_VNC_PASSWORD"] == seat.vnc_password != "secret")
    lbl = mf["metadata"]["labels"]
    check("the pod is labelled with WHICH password it was built with",
          lbl.get(webseat.VNC_LABEL) == webseat.vnc_tag(cfg, "pam-web-aaaaaaaa"))
    check("...as a keyed tag, not the password or a plain hash of it",
          seat.vnc_password not in lbl.get(webseat.VNC_LABEL, "")
          and len(lbl.get(webseat.VNC_LABEL, "")) == 12)
    spares_pool()
    own = {**pam.DEFAULTS, "web_vnc_password": "typed-by-op"}
    check("a password the operator typed is used as typed (their image)",
          webseat.vnc_password_for(own, "pam-web-aaaaaaaa") == "typed-by-op")
    page = open(os.path.join(os.path.dirname(__file__), "..", "templates",
                             "set_pam.html")).read()
    check("the settings page no longer says the VNC port is never exposed",
          "never exposed" not in page)


def spares_pool() -> None:
    """A spare built with another password -- by a release before per-seat
    passwords (`secret`, no label) or before a settings change -- would
    connect to nothing once claimed: it is retired, never handed out."""
    cfg = {**pam.DEFAULTS, "web_spares": 2, "web_cluster": "c-x",
           "web_namespace": "default"}
    scr = "%dx%d" % webseat.wanted_screen(cfg)
    good = "pam-web-11111111"
    pool = [{"name": good, "rv": "1", "phase": "Running", "ready": True,
             "dead": False, "screen": scr, "vnc": webseat.vnc_tag(cfg, good)},
            {"name": "pam-web-22222222", "rv": "2", "phase": "Running",
             "ready": True, "dead": False, "screen": scr, "vnc": ""}]
    killed, labelled = [], []
    keep = (webseat.spares, webseat._clusters, webseat.delete,
            webseat.drop_policy, webseat.why_unavailable, webseat._kubectl,
            webseat._run, webseat.kube.base_args)
    try:
        webseat.kube.base_args = lambda cl: ["kubectl"]
        webseat.spares = lambda c: [dict(p) for p in pool]
        webseat._clusters = lambda: {"c-x": {"name": "c"}}
        webseat.delete = lambda cl, ns, n: killed.append(n)
        webseat.drop_policy = lambda cl, ns, n: None
        webseat.why_unavailable = lambda c: ""
        webseat._run = lambda *a, **k: type("R", (), {"returncode": 1,
                                                      "stdout": "", "stderr": ""})()
        webseat.ensure_spares(cfg)
        check(f"a pre-upgrade spare is retired ({killed})",
              killed == ["pam-web-22222222"])

        def kubectl(cl, argv, to):
            labelled.append(argv[2])
            return type("R", (), {"returncode": 1, "stdout": ""})()
        webseat._kubectl = kubectl
        webseat.claim_spare(cfg, "https://example.com", "s1")
        check(f"...and never claimed ({labelled})",
              "pam-web-22222222" not in labelled and good in labelled)
    finally:
        (webseat.spares, webseat._clusters, webseat.delete,
         webseat.drop_policy, webseat.why_unavailable, webseat._kubectl,
         webseat._run, webseat.kube.base_args) = keep


def sanitiser() -> None:
    print("SEC-3 · the text-panel sanitiser reads what the browser reads")
    s = lambda h: str(grafview.sanitize(h))  # noqa: E731
    for payload in ("posit\\69on:fixed", "position/**/:fixed",
                    "position :fixed", "POSITION:fixed", "z-ind\\65x:99",
                    "z-index/**/:99", "background:u\\72l(https://x/y)"):
        out = s(f'<div style="{payload};color:red">x</div>')
        check(f"{payload!r} is dropped and the rest kept ({out})",
              "position" not in out.lower() and "z-ind" not in out.lower()
              and "\\" not in out and "color:red" in out)
    for href in ("/\\evil.example", "/&#9;/evil.example", "/&#10;/evil.example",
                 "\\\\evil.example", "//evil.example", "jav&#x61;script:alert(1)",
                 " javascript:alert(1)"):
        out = s(f'<a href="{href}">a</a>')
        check(f"href {href!r} is not kept ({out})", "href" not in out)
    for href in ("/d/abc?orgId=1", "https://grafana.example/d/x", "#top",
                 "mailto:noc@example.com"):
        out = s(f'<a href="{href}">a</a>')
        check(f"a real link {href!r} survives", f'href="{href}"' in out)
    out = s('<span style="color:#f00;font-weight:bold;'
            'background-color:rgba(0,0,0,.2)">ok</span>')
    check("ordinary presentation survives",
          "color:#f00" in out and "font-weight:bold" in out
          and "background-color:rgba(0,0,0,.2)" in out)
    css = open(os.path.join(os.path.dirname(__file__), "..", "static",
                            "grafdash.css")).read()
    rule = re.search(r"\.gp-body \{[^}]*\}", css).group(0)
    check("a panel body is a paint container, so nothing can leave its box",
          "contain:paint" in rule.replace(" ", ""))


if __name__ == "__main__":
    forwards()
    passwords()
    sanitiser()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
