#!/usr/bin/env python3
"""Database servers and VPN portals, through the real HTTP stack.

The claims worth a test are the ones a customer is relying on:

  * a registered database server holds no credential — not in the row, not
    anywhere the database file can be read
  * credentials given at the console are bound to one person and one server,
    and a ticket lifted into another session is worthless
  * the console is read-only until somebody deliberately says otherwise, and
    the switch needs a typed word
  * removing a server closes every console open against it

The parts that need a live database are skipped unless one is running. Start
them with:

    docker run -d --name portal-pg -e POSTGRES_PASSWORD=devpass \\
      -e POSTGRES_USER=devuser -e POSTGRES_DB=shop \\
      -p 127.0.0.1:55432:5432 postgres:17-alpine

Run:  PORTAL_DATA_DIR=$(mktemp -d) ./.venv/bin/python tests/test_dbvpn.py
"""
from __future__ import annotations

import os
import pathlib
import socket
import sys
import urllib.parse

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("dbvpn-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient                       # noqa: E402

from app import auth, db, dbconn, main, store                   # noqa: E402

PASSWORD = "Tests-Are-Cheap-42"
EMAIL = "dbtester@example.com"
PG = ("127.0.0.1", 55432)
bad = 0


def fail(what: str) -> None:
    global bad
    bad += 1
    print(f"  FAIL {what}")


def check(what: str, cond) -> None:
    if not cond:
        fail(what)


def up(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), 1):
            return True
    except OSError:
        return False


def sign_in(client: TestClient, email: str) -> str:
    """Sign in for real, including the TOTP step — the code is generated from
    the stored secret. Forging the session cookie would test the forgery."""
    import time
    u = auth.by_email(email)
    uid = u["id"] if u else auth.create_user(email, "Tester", PASSWORD, role="admin")
    db.run("UPDATE users SET mfa_enrolled = 1, totp_secret = ? WHERE id = ?",
           ("TESTSECRET", uid))
    client.post("/login", data={"email": email, "password": PASSWORD},
                follow_redirects=False)
    code = auth._totp_at("TESTSECRET", int(time.time() // auth.TOTP_STEP))
    r = client.post("/mfa", data={"code": code}, follow_redirects=False)
    if r.status_code not in (302, 303):
        raise SystemExit(f"MFA step failed: {r.status_code} {r.text[:200]}")
    return uid


def main_test() -> int:
    client = TestClient(main.app)
    with client:
        uid = sign_in(client, EMAIL)

        # ── 1. registering a server stores no credential ──────────────────
        r = client.post("/settings/conns/db/new", follow_redirects=False, data={
            "type": "postgres", "name": "Shop DB", "host": PG[0],
            "port": str(PG[1]), "database": "shop", "pid": ""})
        check(f"registering a server redirects, got {r.status_code}",
              r.status_code in (302, 303))
        servers = store.all_db()
        check(f"one server is registered, got {len(servers)}", len(servers) == 1)
        srv = servers[0]
        cid = srv["id"]

        # the row itself, straight out of the database — not the dict the
        # store hands back, which could be filtering
        row = db.one("SELECT data FROM conns WHERE id = ?", (cid,))
        raw = (row["data"] or "").lower()
        for secret in ("password", "devpass", "secret"):
            check(f"the stored row must not contain {secret!r}", secret not in raw)
        print("  a registered server carries no credential of any kind")

        # ── 2. the console is shut until somebody signs in ────────────────
        r = client.get(f"/db/{cid}", follow_redirects=False)
        check("an unopened console redirects to the sign-in",
              r.status_code == 303 and f"open={cid}" in r.headers.get("location", ""))
        r = client.post(f"/db/{cid}/query", data={"sql": "SELECT 1"},
                        follow_redirects=False)
        # 409 rather than a redirect: the query panel is fetched, and swapping
        # a redirected sign-in page into it would look like the query answered
        check(f"and a query posted at it is refused, got {r.status_code}",
              r.status_code == 409)
        print("  no console until somebody has signed in to the database")

        print("taking a backup out")
        # A dump nobody can restore is worse than no dump, so the cases here
        # are the ones that decide whether it restores: a table written before
        # the table it points at, a serial column whose sequence has to exist
        # first, and a name that has to survive quoting.
        MY = ("127.0.0.1", 53306)
        for kind, where, user, pw, dbname in (
                ("postgres", PG, "devuser", "devpass", "shop"),
                ("mysql", MY, "root", "devpass", "shop")):
            if not up(*where):
                print(f"  SKIP  no {kind} on {where[0]}:{where[1]}")
                continue
            server = {"type": kind, "name": f"t-{kind}", "host": where[0],
                      "port": str(where[1]), "database": dbname, "id": f"x-{kind}"}
            con = dbconn.Console(f"x-{kind}", "u", user, pw, server)
            try:
                targets = con.export_targets(dbname)
                check(f"{kind}: the dialog has something to offer", bool(targets))

                dump = "".join(con.export(dbname, data=True))
                check(f"{kind}: the header says what this is not",
                      "not a physical backup" in dump)
                check(f"{kind}: tables are created", "CREATE TABLE" in dump)
                check(f"{kind}: rows come out", "INSERT INTO" in dump)

                # structure only must contain no data at all — somebody picks
                # it precisely because the rows are sensitive or enormous
                bare = "".join(con.export(dbname, data=False))
                check(f"{kind}: structure only has no rows",
                      "INSERT INTO" not in bare)
                check(f"{kind}: but still has the tables", "CREATE TABLE" in bare)

                first = sorted(targets)[0]
                one = sorted(targets[first])[0]
                part = "".join(con.export(dbname, schema=first,
                                          tables=[f"{first}.{one}"]))
                check(f"{kind}: one table means one table",
                      part.count("CREATE TABLE") == 1)

                if kind == "postgres":
                    # a serial default is nextval() on a sequence, so the
                    # sequence has to be created before the table that uses it
                    if "nextval(" in dump:
                        check("postgres: the sequences are created too",
                              "CREATE SEQUENCE" in dump)
                        check("and before the table that needs them",
                              dump.index("CREATE SEQUENCE") < dump.index("nextval("))
                        check("and moved past the rows just inserted",
                              "setval(" in dump)
                    check("postgres: names needing quotes keep them",
                          '"Admins"' in dump or "Admins" not in dump)
                else:
                    # mysqldump writes unqualified names so a restore lands
                    # where you point it; qualified ones sent the rows back
                    # into the database being backed up
                    check("mysql: the table names are unqualified",
                          f"INSERT INTO {dbname}." not in dump)
                    check("mysql: foreign key checks are turned off first",
                          dump.index("FOREIGN_KEY_CHECKS=0")
                          < dump.index("CREATE TABLE"))
                # every database at once, one file each. A combined .sql
                # would mean editing SQL by hand to restore one of them, and
                # on a server where a database is 290 MB, a file nobody opens.
                files = dict((n, "".join(c)) for n, c in
                             con.export_all(data=False))
                check(f"{kind}: every database comes out as its own file, "
                      f"got {sorted(files)}", len(files) >= 1)
                check(f"{kind}: named after the database",
                      all(n.endswith(".sql") for n in files))
                check(f"{kind}: and each one is a dump in its own right",
                      all("logical export" in body for body in files.values()))
                if kind == "postgres":
                    # backing up a template is never what anybody meant
                    check("postgres: templates are left out",
                          not {"template0.sql", "template1.sql"} & set(files))

            finally:
                con.close()

        live = up(*PG)
        if not live:
            print(f"  SKIP  nothing on {PG[0]}:{PG[1]} — the live-database "
                  f"sections did not run")
        else:
            # ── 3. a wrong password is refused, and nothing is kept ───────
            r = client.post(f"/db/{cid}/open", follow_redirects=False, data={
                "user": "devuser", "password": "wrong-on-purpose"})
            check("a bad password comes back to the sign-in",
                  f"open={cid}" in r.headers.get("location", ""))
            check("and nothing was put in the vault", dbconn.open_count(cid) == 0)

            # ── 4. signing in properly ────────────────────────────────────
            r = client.post(f"/db/{cid}/open", follow_redirects=False, data={
                "user": "devuser", "password": "devpass"})
            check(f"a good password opens the console, got {r.headers.get('location')}",
                  r.headers.get("location", "") == f"/db/{cid}")
            check("the vault holds exactly one", dbconn.open_count(cid) == 1)
            page = client.get(f"/db/{cid}").text
            # The backup dialog reads the current database out of this page. It
            # looked for select[name=database]; the picker is #dbpick, so it
            # always sent an empty name — invisible on a server that has a
            # default database to fall back on, and "0 schemas, 0 tables" on
            # one that does not.
            check("the console renders the database picker the dialog reads",
                  'id="dbpick"' in page)
            check("and the dialog reads that exact id",
                  "getElementById('dbpick')" in page)
            check("a database with nothing in it says so, rather than "
                  "showing a silent zero", "Nothing to export from" in page)
            check("the console names the account", "devuser" in page)
            check("and says it is read-only", "read-only" in page)
            check("the overview counted the tables", "tables" in page)
            print("  signing in opens a console, and it opens read-only")

            # ── 5. read-only is the server's decision, not a text check ───
            r = client.post(f"/db/{cid}/query", data={
                "sql": "DELETE FROM customers", "database": "shop"})
            check("a plain DELETE is refused before it is sent",
                  "read-only mode" in r.text)
            # this passes the keyword check — only the server can stop it
            r = client.post(f"/db/{cid}/query", data={
                "sql": "WITH gone AS (DELETE FROM customers WHERE id = 999999 "
                       "RETURNING *) SELECT * FROM gone", "database": "shop"})
            check("a write hidden inside a SELECT is refused by the server",
                  "read-only transaction" in r.text)
            print("  a write disguised as a read is stopped by the server itself")

            # ── 6. a working query ────────────────────────────────────────
            r = client.post(f"/db/{cid}/query", data={
                "sql": "SELECT 42 AS answer", "database": "shop"})
            check("a select renders its result", "answer" in r.text and "42" in r.text)

            # ── 7. write mode needs the word typed ────────────────────────
            r = client.post(f"/db/{cid}/write", data={"on": "1"},
                            follow_redirects=True)
            check("write mode without the word is refused", "Type write" in r.text)
            held = dbconn.session(_ticket(client, cid), cid, uid)
            check("the ticket is readable out of the cookie at all", held is not None)
            check("and the console is still read-only", held and not held["write"])
            client.post(f"/db/{cid}/write", data={"on": "1", "confirm": "write"},
                        follow_redirects=True)
            held = dbconn.session(_ticket(client, cid), cid, uid)
            check("with the word, write mode is on", held and held["write"])
            print("  write mode needs the word typed, exactly like every other "
                  "consequential action")

            # ── 8. every statement is in the audit log ────────────────────
            log = db.q("SELECT action, detail FROM audit ORDER BY id DESC LIMIT 40")
            actions = [a["action"] for a in log]
            for want in ("db_console_opened", "db_query", "db_write_enabled",
                         "db_signin_failed"):
                check(f"{want} is recorded", want in actions)
            check("the statement text is recorded, not just that one ran",
                  any("SELECT 42" in (a["detail"] or "") for a in log))
            print("  the audit log has who signed in, what they ran and when "
                  "write mode went on")

            # ── 8b. the console holds its connection open ─────────────────
            con = dbconn.console(_ticket(client, cid), cid, uid)
            before = con.open_connections()
            for t in ("tables", "roles", "activity", "locks", "overview"):
                r = client.get(f"/db/{cid}/tab/{t}?database=shop")
                check(f"the {t} fragment renders, got {r.status_code}",
                      r.status_code == 200)
                check(f"the {t} fragment is a fragment, not a page",
                      "<html" not in r.text.lower())
            check(f"and no extra connections were opened ({before} -> "
                  f"{con.open_connections()})", con.open_connections() == before)
            print("  every tab is a fragment on one already-open connection")

            # ── 8c. the overview really is one statement ──────────────────
            con.forget()
            fell_back = []
            real = con._overview_piecemeal
            con._overview_piecemeal = lambda d: (fell_back.append(1), real(d))[1]
            con.overview("shop", force=True)
            con._overview_piecemeal = real
            check("the one-statement overview works and is not falling back "
                  "to thirteen", not fell_back)

            # ── 8d. the editor's schema map ───────────────────────────────
            r = client.get(f"/db/{cid}/schema.json?database=shop")
            got = r.json()
            names = [t["qualified"] for t in got["tables"]]
            check(f"the schema map lists the tables, got {names}",
                  "public.customers" in names)
            cols = [c["name"] for t in got["tables"]
                    if t["qualified"] == "public.customers" for c in t["columns"]]
            check(f"with their columns, got {cols}", "city" in cols)
            check("and keywords to complete", "SELECT" in got["keywords"])
            print("  the editor is given this database's tables and columns")

            # ── 8e. one table, in full ────────────────────────────────────
            r = client.get(f"/db/{cid}/table?database=shop&schema=public"
                           f"&name=customers")
            for want in ("city", "CREATE TABLE", "Indexes", "Constraints"):
                check(f"the table page shows {want!r}", want in r.text)
            check("and a page of its rows", "Nairobi" in r.text or "Dubai" in r.text)
            # sorting only accepts a real column: anything else is dropped
            data = con.rows("shop", "public", "customers", 1, "city; DROP TABLE x", False)
            check("an invented sort column is ignored rather than injected",
                  data["order"] == "city; DROP TABLE x" and data["rows"])
            print("  a table shows its columns, keys, indexes, DDL and rows")

            # ── 8e2. a name that needs quoting ────────────────────────────
            # PostgreSQL folds an unquoted identifier to lower case, so a table
            # created as "Admins" cannot be reached by typing public.Admins.
            # The completion used to offer exactly that, and the query it gave
            # you could not run.
            import psycopg
            with psycopg.connect(host=PG[0], port=PG[1], user="devuser",
                                 password="devpass", dbname="shop",
                                 autocommit=True) as raw:
                raw.execute('CREATE TABLE IF NOT EXISTS "MixedCase" '
                            '(id int, "colOne" text)')
            con.forget()
            sm = con.schema_map("shop", force=True)
            mixed = next((t for t in sm["tables"] if t["name"] == "MixedCase"), None)
            check("the mixed-case table is offered", mixed is not None)
            check(f'and inserted quoted, got {mixed and mixed["insert"]!r}',
                  mixed and mixed["insert"] == 'public."MixedCase"')
            col = next(c for c in mixed["columns"] if c["name"] == "colOne")
            check(f'its mixed-case column too, got {col["insert"]!r}',
                  col["insert"] == '"colOne"')
            plain = next(t for t in sm["tables"] if t["name"] == "customers")
            check(f'an ordinary name is left alone, got {plain["insert"]!r}',
                  plain["insert"] == "public.customers")
            # what the completion inserts must actually run
            out = con.run(f'SELECT * FROM {mixed["insert"]}', "shop")
            check("and what it inserts runs", out["columns"] == ["id", "colOne"])
            # the unquoted form still fails, but now says why
            try:
                con.run("SELECT * FROM public.MixedCase", "shop")
                fail("the unquoted form should still fail")
            except dbconn.DBError as e:
                check(f"the error names the real table, got {e}",
                      "MixedCase" in str(e) and 'public."MixedCase"' in str(e))
            r = client.get(f"/db/{cid}/tab/tables?database=shop")
            check("the Query button builds a runnable statement",
                  'FROM public.&#34;MixedCase&#34; LIMIT 100' in r.text
                  or 'FROM public."MixedCase" LIMIT 100' in r.text)
            print("  a name that needs quoting is offered, inserted and "
                  "generated quoted")

            # ── 8f. CSV ───────────────────────────────────────────────────
            r = client.post(f"/db/{cid}/export", data={
                "sql": "SELECT city FROM customers ORDER BY city LIMIT 3",
                "database": "shop"})
            check(f"the export answers CSV, got {r.headers.get('content-type')}",
                  "text/csv" in r.headers.get("content-type", ""))
            check("with a header row", r.text.splitlines()[0].strip() == "city")
            check("and the rows", len(r.text.strip().splitlines()) == 4)
            print("  a result downloads as CSV, re-run rather than held in memory")

            # ── 8g. losing the console says why, and comes back here ──────
            # The credentials only live in memory, so a restart drops every
            # console. Being dropped onto an unexplained sign-in box — having
            # lost which tab and which database you were on — is the same
            # experience as a bug, and was reported as one.
            was_boot = dbconn.BOOT
            here = f"/db/{cid}?tab=query&database=shop"
            # what a restart actually is: the vault is empty and the process
            # is a different one, while the browser still holds its ticket
            dbconn._VAULT.clear()
            dbconn.BOOT = "a-different-process"
            r = client.get(here, follow_redirects=False)
            loc = r.headers.get("location", "")
            check(f"a dropped console redirects to the sign-in, got {loc}",
                  f"open={cid}" in loc)
            check("carrying where you were", "back=" in loc)
            page = client.get(loc).text
            check("and the dialog says the portal restarted",
                  "portal restarted" in page)

            # signing out is a different sentence from a restart: same process,
            # ticket simply no longer in the vault
            dbconn.BOOT = was_boot
            client.get(here, follow_redirects=False)   # re-stamp nothing; boot matches
            page = client.get(f"/db?open={cid}").text
            check("a console closed some other way says so instead",
                  "portal restarted" not in page and "was closed" in page)

            # and coming back lands where you left
            r = client.post(
                f"/db/{cid}/open?back={urllib.parse.quote(here, safe='')}",
                data={"user": "devuser", "password": "devpass"},
                follow_redirects=False)
            check(f"signing in returns you to where you were, got "
                  f"{r.headers.get('location')}",
                  r.headers.get("location") == here)

            # a redirect target is not somewhere a query string gets to choose
            r = client.post(f"/db/{cid}/open?back=https://elsewhere.example/x",
                            data={"user": "devuser", "password": "devpass"},
                            follow_redirects=False)
            check(f"an off-site back is ignored, got {r.headers.get('location')}",
                  r.headers.get("location") == f"/db/{cid}")
            print("  a dropped console says why it went and puts you back")

            # ── 9. a ticket is bound to its person ────────────────────────
            ticket = _ticket(client, cid)
            check("the ticket works for the person who made it",
                  dbconn.session(ticket, cid, uid) is not None)
            check("and for nobody else",
                  dbconn.session(ticket, cid, "u-someone-else") is None)
            check("and not for another server",
                  dbconn.session(ticket, "db-other", uid) is None)
            print("  a ticket is worthless in anyone else's session")

        # ── 10. removing the server closes the consoles ───────────────────
        client.post(f"/settings/conns/db/{cid}/delete", data={"pid": ""},
                    follow_redirects=False)
        check("removing the server empties its vault", dbconn.open_count(cid) == 0)
        check("and the server is gone", not store.all_db())
        print("  removing a server takes every open console with it")

        # ── 11. VPN: the settings page, and a portal that is not there ────
        r = client.get("/settings/conns/vpn")
        check(f"the VPN settings page renders, got {r.status_code}",
              r.status_code == 200)
        for label in ("Pritunl", "OpenVPN Access Server", "wg-easy", "Netmaker"):
            check(f"{label} is offered", label in r.text)
        client.post("/settings/conns/vpn/new", follow_redirects=False, data={
            "type": "pritunl", "name": "Nowhere VPN",
            "base_url": "https://127.0.0.1:59998", "username": "tok",
            "token": "sec", "pid": ""})
        r = client.get("/vpn")
        check(f"the VPN page renders with an unreachable portal, got {r.status_code}",
              r.status_code == 200)
        check("and says which one it cannot read", "Nowhere VPN" in r.text)
        check("with a reason rather than a stack trace",
              "Cannot read this portal" in r.text)
        print("  an unreachable VPN portal is a row with a reason, not an error page")

        # ── 12. the fields a provider declares are the fields it gets ─────
        r = client.get("/settings/conns/db")
        check("the database settings page renders", r.status_code == 200)
        check("and asks for a host", "Host or address" in r.text)
        # the words "no password is kept" appear on the page, and should;
        # what must not appear is a field to type one into
        check("and offers no password field at all",
              'type="password"' not in r.text)

        print("  a Pritunl portal says which credential is wrong")
        # A console username and password in the API boxes is the easy mistake: the
        # fields ask for a "token" and a "secret", and a login has two boxes too.
        # Pritunl's own answer is "401 Missing token", which explains nothing to
        # somebody who believes they typed a token.
        from app import vpn as _vpn
        why = _vpn._pritunl_credentials_problem(
            {"username": "admin", "token": "hunter2hunter"})
        check(f"a short token is named as the problem, got {why[:44]!r}",
              "32 characters" in why and "5 and 13" in why)
        check("and it says where the real ones come from",
              "Administrators" in why)
        # the reason that box is often empty rather than wrong: Pritunl's
        # admin API is an Enterprise feature, so on the free edition there is
        # no token in that console to copy
        check("and that the free edition has none to give",
              "Enterprise" in why)
        check("both missing is its own message",
              "needs both" in _vpn._pritunl_credentials_problem(
                  {"username": "", "token": ""}))
        check("correctly shaped credentials raise no objection",
              _vpn._pritunl_credentials_problem(
                  {"username": "a" * 32, "token": "b" * 32}) == "")
        print("  the settings page for a database asks for a host, never a password")

    print("\nFAILED" if bad else "\nOK")
    return 1 if bad else 0


def _ticket(client: TestClient, cid: str) -> str:
    """The ticket the browser is carrying, read out of the signed cookie the
    same way the app does."""
    from itsdangerous import TimestampSigner
    import base64
    import json
    raw = client.cookies.get("portal_session")
    if not raw:
        return ""
    signer = TimestampSigner(auth.session_secret())
    data = json.loads(base64.urlsafe_b64decode(signer.unsign(raw, max_age=None)))
    return (data.get("db_tickets") or {}).get(cid, "")


if __name__ == "__main__":
    raise SystemExit(main_test())
