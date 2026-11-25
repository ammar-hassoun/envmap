#!/usr/bin/env python3
"""What is firing, everywhere, and which systems could not say.

WHY THIS EXISTS
    Three faults, each invisible until a particular kind of system answered:

      * The Overview's "Firing alerts" panel called merge_counts with two
        arguments. The moment ANY monitoring system answered, the roll raised
        TypeError and the landing page itself returned a 500. Nothing caught
        it: the panel is not on the default layout, and the catalogue check in
        test_panels.py builds it with no system registered, which returns
        before the call.
      * A system that did not answer vanished. Its read raised inside _pmap,
        which turns an exception into None, and the None was skipped, so a
        panel of systems nobody could reach said "nothing firing".
      * The Monitoring page counted every alert whose state was not "active"
        as suppressed. Prometheus says "firing", so every firing Prometheus
        alert was "suppressed" while the tiles counted it as firing. Grafana,
        the other way round, had its silenced alerts counted as firing.

    The fakes answer at monitoring._req, the seam the docs demo uses, so the
    real overview code, routes and templates all run. Synthetic data only.

    ./.venv/bin/python tests/test_monitoring.py
"""
from __future__ import annotations

import copy
import os
import pathlib
import re
import sys
import time
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("monitoring-test-")
os.environ["PORTAL_SCHEDULER"] = "0"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth, db, layout, monitoring, store            # noqa: E402
from app import main as portal                                 # noqa: E402

bad = 0
DOWN = "cannot reach the server: [Errno 61] Connection refused"


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _am(name, sev, state="active"):
    return {"labels": {"alertname": name, "severity": sev, "namespace": "shop"},
            "annotations": {"summary": f"{name} summary"},
            "startsAt": "2026-10-01T08:00:00Z", "status": {"state": state}}


def _prom(name, sev, state):
    return {"labels": {"alertname": name, "severity": sev, "job": "node"},
            "annotations": {"summary": f"{name} summary"}, "state": state,
            "activeAt": "2026-10-01T08:00:00Z"}


# host -> path (or Zabbix method) -> what that system answers
ANSWERS = {
    "am.example.com": {
        "/api/v2/alerts": [_am("CheckoutErrors", "critical"),
                           _am("QueueLag", "warning"),
                           # not yet run through silences: still firing
                           _am("JustArrived", "warning", "unprocessed")],
        "/api/v2/silences": []},
    "prom.example.com": {
        "/api/v1/alerts": {"status": "success", "data": {"alerts": [
            _prom("HostCpuHigh", "warning", "firing"),
            _prom("DiskFillingUp", "critical", "pending")]}},
        "/api/v1/targets": {"status": "success", "data": {"activeTargets": []}}},
    "grafana.example.com": {
        "/api/search": [],
        "/api/alertmanager/grafana/api/v2/alerts": [
            _am("LatencyHigh", "warning"),
            _am("SilencedDiskFull", "critical", "suppressed")]},
    "zabbix.example.com": {
        "problem.get": [
            {"eventid": "3", "name": "Database down", "severity": "4", "clock": "1759305600",
             "acknowledged": "0", "suppressed": "0"},
            {"eventid": "2", "name": "Backup late", "severity": "3", "clock": "1759305600",
             "acknowledged": "1", "suppressed": "0"},
            {"eventid": "1", "name": "Disk in maintenance", "severity": "5",
             "clock": "1759305600", "acknowledged": "0", "suppressed": "1"}],
        "host.get": []},
    "quiet.example.com": {"/api/v2/alerts": [], "/api/v2/silences": []},
    # six warnings listed BEFORE its one critical
    "noisy.example.com": {
        "/api/v2/alerts": [_am(f"Noise{i}", "warning") for i in range(6)]
                          + [_am("ListedLast", "critical")],
        "/api/v2/silences": []},
}


def fake_req(url, headers, verify=True, body=None):
    u = urllib.parse.urlsplit(url)
    host, path = u.hostname or "", u.path.rstrip("/")
    if host == "down.example.com":
        raise monitoring.MonError(DOWN)
    if path.endswith("/api_jsonrpc.php"):
        return {"jsonrpc": "2.0", "id": 1,
                "result": copy.deepcopy(ANSWERS[host].get(body["method"], []))}
    if path in ANSWERS.get(host, {}):
        return copy.deepcopy(ANSWERS[host][path])
    raise monitoring.MonError("not found (404)")


SYSTEMS = {
    "am": ("Alertmanager eu", "alertmanager", "https://am.example.com", "eu-1"),
    "prom": ("Prometheus us", "prometheus", "https://prom.example.com", "us-1"),
    "grafana": ("Grafana", "grafana", "https://grafana.example.com", ""),
    "zabbix": ("Zabbix", "zabbix", "https://zabbix.example.com/api_jsonrpc.php", ""),
    "noisy": ("Noisy", "alertmanager", "https://noisy.example.com", ""),
    "quiet": ("Quiet", "alertmanager", "https://quiet.example.com", ""),
    "down": ("Prometheus down", "prometheus", "https://down.example.com", ""),
}


def only(*keys) -> dict:
    """Exactly these systems registered, nothing cached from the last case."""
    for c in store.all_mon():
        store.delete_mon(c.get("pid") or "", c["id"])
    monitoring.invalidate()
    out = {}
    for k in keys:
        name, kind, base, cluster = SYSTEMS[k]
        cid = store.add_mon("", {"type": kind, "name": name, "cluster": cluster,
                                 "base_url": base, "username": "", "token": "",
                                 "skip_tls": False})
        out[k] = store.get_mon("", cid)
    return out


_CLIENT = None


def client():
    global _CLIENT
    from fastapi.testclient import TestClient
    if _CLIENT is None:
        email, pw = "monitoring@test.local", "Firing-Everywhere-And-Why-42"
        uid = auth.create_user(email, "CI", pw, role="admin")
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=? WHERE id=?",
               ("TESTSECRET", uid))
        # a 500 must come back as a status to count, not as an exception that
        # ends the run at the first broken page
        _CLIENT = TestClient(portal.app, raise_server_exceptions=False)
        _CLIENT.__enter__()
        _CLIENT.post("/login", data={"email": email, "password": pw},
                     follow_redirects=False)
        _CLIENT.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
            follow_redirects=False)
    return _CLIENT


def page(path: str) -> str:
    r = client().get(path)
    return re.sub(r"\s+", " ", r.text) if r.status_code == 200 else f"HTTP {r.status_code}"


def tile(html: str, cap: str):
    m = re.search(r'<span class="big">(\d+)</span> <span class="cap">' + cap + "</span>",
                  html)
    return int(m.group(1)) if m else None


def kv(html: str, label: str):
    m = re.search(r'<span class="v">' + label + r'</span><span class="n">(\d+)</span>',
                  html)
    return int(m.group(1)) if m else None


def rows(html: str) -> int:
    """Alert rows in the Firing tab's table."""
    return html.count('<td class="jname">')


def roll_now() -> dict:
    """The Overview's roll, or an empty one after recording why it raised: one
    crash must not hide every check after it."""
    try:
        return portal._alerts_roll()
    except Exception as e:                                     # noqa: BLE001
        check(f"the roll must not raise ({type(e).__name__}: {e})", False)
        return {"conns": 0, "answered": 0, "counts": {}, "total": 0,
                "broken": [], "alerts": []}


def panel(roll: dict) -> str:
    out = portal.templates.env.get_template("panels/alerts.html").render(
        d={"alerts": roll})
    return re.sub(r"\s+", " ", out)


def main() -> int:
    monitoring._req = fake_req

    print("a state means one thing, whatever the platform called it")
    for raw in ("firing", "active", "unprocessed", "Active", " FIRING ", "", None):
        check(f"{raw!r} is firing", monitoring._norm_state(raw) == monitoring.FIRING)
    for raw in ("suppressed", "silenced", "inhibited", "Suppressed"):
        check(f"{raw!r} is suppressed",
              monitoring._norm_state(raw) == monitoring.SUPPRESSED)
    check("a word it does not know is kept, not mapped onto one it does",
          monitoring._norm_state("acknowledged") == "acknowledged")

    print("each platform counts what is firing and sets the muted apart")
    s = only("am", "prom", "grafana", "zabbix")
    o = monitoring.overview(s["prom"])
    check(f"Prometheus: a FIRING alert is counted as firing ({o['counts']})",
          o["counts"] == {"critical": 0, "warning": 1, "info": 0})
    check("...listed as firing", [a["name"] for a in o["alerts"]] == ["HostCpuHigh"])
    check("...and not set apart as suppressed", o["suppressed"] == [])
    check("...in the one vocabulary", o["alerts"][0]["state"] == monitoring.FIRING)
    o = monitoring.overview(s["am"])
    check(f"Alertmanager: active and unprocessed are both firing ({o['counts']})",
          o["counts"] == {"critical": 1, "warning": 2, "info": 0}
          and o["suppressed"] == [])
    o = monitoring.overview(s["grafana"])
    check(f"Grafana: a silenced alert is not counted as firing ({o['counts']})",
          o["counts"] == {"critical": 0, "warning": 1, "info": 0})
    check("...nor listed as firing", [a["name"] for a in o["alerts"]] == ["LatencyHigh"])
    check("...but carried, so a page can say how many",
          [a["name"] for a in o["suppressed"]] == ["SilencedDiskFull"])
    ok, said = monitoring.test(s["grafana"])
    check(f"the connection test says so too ({said})",
          ok and "1 alert(s) firing" in said and "1 suppressed" in said)
    o = monitoring.overview(s["zabbix"])
    check("Zabbix: a problem in maintenance is suppressed",
          [a["name"] for a in o["suppressed"]] == ["Disk in maintenance"])
    check(f"...and an acknowledged one is still firing ({o['counts']})",
          o["counts"] == {"critical": 1, "warning": 1, "info": 0})
    check("...keeping its word for the Firing tab",
          {a["name"]: a["state"] for a in o["alerts"]}
          == {"Database down": monitoring.FIRING, "Backup late": "acknowledged"})

    print("merge_counts adds up overview ANSWERS")
    check("a list of answers, one missing its counts",
          monitoring.merge_counts([{"counts": {"critical": 1, "warning": 2}},
                                   {"counts": {"warning": 1, "info": 4}}, {}])
          == {"critical": 1, "warning": 3, "info": 4})

    print("the Overview's alerts roll: one system answering, one not")
    only("prom", "down")
    roll = roll_now()
    check("both systems are registered", roll.get("conns") == 2)
    check("one of them answered", roll.get("answered") == 1)
    check(f"what it said is counted ({roll.get('counts')})",
          roll.get("counts") == {"critical": 0, "warning": 1, "info": 0}
          and roll.get("total") == 1)
    check(f"the one that did not answer is NAMED, with its error ({roll.get('broken')})",
          roll.get("broken") == [{"name": "Prometheus down", "error": DOWN}])
    check("each alert says which system and cluster it came from",
          [(a.get("name"), a.get("conn"), a.get("cluster")) for a in roll.get("alerts", [])]
          == [("HostCpuHigh", "Prometheus us", "us-1")])
    html = panel(roll)
    check("the panel draws what answered",
          "HostCpuHigh" in html and "1<i>warning</i>" in html)
    check("...and its cluster beside each alert",
          '<span class="hint">us-1</span>' in html)
    check("...and names the system that did not, with the reason",
          "Prometheus down" in html and DOWN in html)
    check("...and counts it in the header, linked to the systems it counts",
          '<a class="badge" style="color:var(--warn-ink);" href="/monitoring?sec=systems"> '
          '1 unreachable</a>' in html)

    print("none answering reads as unknown, never as zero")
    only("down")
    roll = roll_now()
    check(f"nothing answered and it is named ({roll})",
          roll.get("conns") == 1 and roll.get("answered") == 0
          and roll.get("broken") == [{"name": "Prometheus down", "error": DOWN}])
    html = panel(roll)
    check("no zero counts are drawn", "<i>critical</i>" not in html)
    check("nor 'nothing firing'", "nothing firing" not in html)
    check("it says the answer is not known", "what is firing is not known" in html)
    check("and names the system with its error", "Prometheus down" in html and DOWN in html)

    print("'nothing firing' says whose silence it is")
    only("quiet", "down")
    html = panel(roll_now())
    check("with one system unreachable it is the ones that answered",
          "nothing firing on the 1 answering" in html)
    only("quiet")
    html = panel(roll_now())
    check("with every system answering it is plain",
          "nothing firing</span>" in html and "answering" not in html)

    print("worst first, BEFORE each system's own cap")
    only("noisy")
    roll = roll_now()
    check(f"a critical its system listed seventh still leads the panel "
          f"({[a.get('name') for a in roll.get('alerts', [])]})",
          [a.get("name") for a in roll.get("alerts", [])][:1] == ["ListedLast"])

    print("the panel on the Overview, added the way Arrange adds it")
    only("prom", "down")
    # without a project the Overview is "Nothing connected yet" and no panel
    # renders at all, which would pass every check below for the wrong reason
    store.add_project("Shop")
    c = client()
    r = c.post("/overview/layout", json={"panels": [
        {"id": p["id"], "w": p["w"]} for p in layout.DEFAULT] + [{"id": "alerts", "w": 0}]})
    check(f"the arrangement saves ({r.status_code})",
          r.status_code == 200 and "alerts" in [p["id"] for p in r.json()["panels"]])
    for path in ("/?arrange=1", "/", "/overview/panel/alerts"):
        html = page(path)
        check(f"{path} renders ({html[:12]})", not html.startswith("HTTP "))
        check(f"{path} draws the firing alert", "HostCpuHigh" in html)
        check(f"{path} names the unreachable system with its error",
              "Prometheus down" in html and DOWN in html)
    check("the board carries the panel", 'data-id="alerts"' in page("/"))

    print("Monitoring: a firing Prometheus alert is firing, not suppressed")
    only("prom")
    over = page("/monitoring?sec=overview")
    check(f"the firing tile counts it ({tile(over, 'firing')})", tile(over, "firing") == 1)
    check("so does the warning tile", tile(over, "warning") == 1)
    check(f"and 'suppressed alerts' is 0 ({kv(over, 'suppressed alerts')})",
          kv(over, "suppressed alerts") == 0)
    fire = page("/monitoring?sec=firing")
    check(f"the Firing tab lists it ({rows(fire)} rows)",
          "HostCpuHigh" in fire and rows(fire) == 1)
    check("and does not call anything suppressed", "suppressed, not listed" not in fire)
    check("its state is not drawn as a note", '<span class="jbranch">' not in fire)

    print("...and a silenced Grafana alert is suppressed, not firing")
    only("grafana")
    over = page("/monitoring?sec=overview")
    check(f"the firing tile counts only the active one ({tile(over, 'firing')})",
          tile(over, "firing") == 1)
    check("the critical tile leaves the silenced critical out",
          tile(over, "critical") == 0)
    check(f"'suppressed alerts' counts it ({kv(over, 'suppressed alerts')})",
          kv(over, "suppressed alerts") == 1)
    fire = page("/monitoring?sec=firing")
    check("it is not a row of the Firing list", "SilencedDiskFull" not in fire)
    check("and the list says one is suppressed and not listed",
          "1 suppressed, not listed" in fire)
    check("a severity filter narrows that count with the list",
          "suppressed, not listed" not in page("/monitoring?sec=firing&sev=warning"))
    only("zabbix")
    check("an acknowledged Zabbix problem keeps its note on the row",
          '<span class="jbranch">acknowledged</span>' in page("/monitoring?sec=firing"))

    print("every tile equals the rows its link opens, whatever answered")
    only("am", "prom", "grafana", "zabbix", "down")
    over = page("/monitoring?sec=overview")
    check(f"the firing tile is the Firing tab ({tile(over, 'firing')})",
          tile(over, "firing") == rows(page("/monitoring?sec=firing")))
    for sev in monitoring.SEVERITIES:
        check(f"the {sev} tile is the {sev} list",
              tile(over, sev) == rows(page(f"/monitoring?sec=firing&sev={sev}")))
    check(f"suppressed counts the silenced Grafana alert and the Zabbix "
          f"maintenance ({kv(over, 'suppressed alerts')})",
          kv(over, "suppressed alerts") == 2)
    check("the unreachable system is still reported", kv(over, "unreachable") == 1)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
