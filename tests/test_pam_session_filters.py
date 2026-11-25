"""The recordings tab filters by user, target and a date range -- and the same
filter drives the list, the stats readout, the dropdown facets, the route, and
the bulk clear.

Each filter is proved to NARROW: the filtered set is exactly the expected rows,
which fails the moment a filter is ignored. The bulk clear is shown to honour
the SAME filter, so it can never remove more than the view showed.

    ./.venv/bin/python tests/test_pam_session_filters.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamfilt-")
os.environ.setdefault("PORTAL_PAM", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, main, pam, rbac  # noqa: E402

bad = 0


def check(what: str, ok: bool) -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok   " if ok else "  FAIL ") + what)


def enrol(email: str, pw: str, areas: list) -> None:
    uid = auth.create_user(email, "N", pw, role="viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    rid = rbac.save("", email.split("@")[0], "", areas, [], [], [])
    rbac.set_for_user(uid, [rid])


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw}, follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)
    return c


def mk_target(name: str, addr: str) -> str:
    return pam.save_target("", {"name": name, "protocol": "ssh",
                                "address": addr, "port": "22",
                                "auth_kind": "none"}, "setup")


def mk_session(who: str, tid: str, tname: str, addr: str, date: str) -> str:
    rec = pam.start_recording(who, addr, protocol="ssh", target_id=tid,
                              target_name=tname, address=addr,
                              rec_kind="asciinema")
    rec.finish("closed")
    # Controlled date: the filter reads the YYYY-MM-DD prefix of `started`,
    # which is stored as an ISO instant.
    db.run("UPDATE pam_sessions SET started = ? WHERE id = ?",
           (date + "T10:00:00+00:00", rec.id))
    return rec.id


def ids(rows) -> set:
    return {r["id"] for r in rows}


def main_test() -> int:
    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    ta = mk_target("web-a", "10.0.0.1")
    tb = mk_target("web-b", "10.0.0.2")
    s1 = mk_session("alice@t", ta, "web-a", "10.0.0.1", "2026-09-01")
    s2 = mk_session("bob@t",   ta, "web-a", "10.0.0.1", "2026-10-05")
    s3 = mk_session("alice@t", tb, "web-b", "10.0.0.2", "2026-10-05")
    allids = {s1, s2, s3}

    print("the unfiltered list has all three")
    check("all three listed", ids(pam.sessions()) >= allids)

    print("the TARGET filter narrows to that target's recordings")
    check("target A -> s1,s2", ids(pam.sessions(target_id=ta)) & allids == {s1, s2})
    check("target B -> s3", ids(pam.sessions(target_id=tb)) & allids == {s3})

    print("the USER filter narrows to that user")
    check("alice -> s1,s3", ids(pam.sessions(who="alice@t")) & allids == {s1, s3})

    print("the DATE range narrows by the started date, inclusive both ends")
    check("from 2026-10-01 -> s2,s3",
          ids(pam.sessions(d_from="2026-10-01")) & allids == {s2, s3})
    check("to 2026-09-30 -> s1",
          ids(pam.sessions(d_to="2026-09-30")) & allids == {s1})
    check("the 5th, inclusive on both ends -> s2,s3",
          ids(pam.sessions(d_from="2026-10-05", d_to="2026-10-05")) & allids == {s2, s3})

    print("filters COMBINE (AND)")
    check("target A + from Oct -> s2",
          ids(pam.sessions(target_id=ta, d_from="2026-10-01")) & allids == {s2})
    check("alice + target A -> s1",
          ids(pam.sessions(who="alice@t", target_id=ta)) & allids == {s1})

    print("the stats readout counts the SAME filtered set")
    check("stats target A == 2", pam.sessions_stats(target_id=ta)["count"] == 2)
    check("stats alice + target A == 1",
          pam.sessions_stats(who="alice@t", target_id=ta)["count"] == 1)
    check("stats from Oct == 2", pam.sessions_stats(d_from="2026-10-01")["count"] == 2)

    print("facets offer both targets, by id and label")
    facs = pam.session_facets()
    check("both target labels present",
          {"web-a", "web-b"} <= {t["label"] for t in facs["targets"]})
    check("both target ids present",
          {ta, tb} <= {t["id"] for t in facs["targets"]})

    print("the route wires the params through to the rendered rows")
    enrol("reader@t", "Reader-Pass-4242", ["pam", "pam_connect"])
    c = signed_in("reader@t", "Reader-Pass-4242")
    body_all = c.get("/pam?sec=sessions").text
    body_b = c.get(f"/pam?sec=sessions&sess_target={tb}").text
    body_sep = c.get("/pam?sec=sessions&sess_from=2026-10-01").text
    # The replay link carries the session id, so it is present exactly when the
    # row is -- unlike a target name, which also sits in the dropdown options.
    check("unfiltered page has all three rows",
          all(f"/pam/sessions/{s}" in body_all for s in allids))
    check("target=B page keeps s3, drops s1 and s2",
          f"/pam/sessions/{s3}" in body_b
          and f"/pam/sessions/{s1}" not in body_b
          and f"/pam/sessions/{s2}" not in body_b)
    check("from=Oct page keeps s2,s3, drops the September s1",
          f"/pam/sessions/{s2}" in body_sep and f"/pam/sessions/{s3}" in body_sep
          and f"/pam/sessions/{s1}" not in body_sep)
    check("the target dropdown renders both options",
          f'value="{ta}"' in body_all and f'value="{tb}"' in body_all)

    print("CLEAR honours the filter -- it removes only the subset shown")
    gone = pam.clear_sessions(target_id=tb)
    check("clearing target B removed exactly 1", gone == 1)
    check("s3 is gone", pam.session(s3) is None)
    check("s1 and s2 survive", bool(pam.session(s1)) and bool(pam.session(s2)))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
