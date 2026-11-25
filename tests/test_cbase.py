#!/usr/bin/env python3
"""Couchbase management, against stubs of both API generations.

WHY TWO GENERATIONS AND NOT ONE
    The cluster this was written against is 4.6, and the current documentation
    describes 7.x. Three differences bite:

      * a bucket create on 4.x is rejected without authType; sending it to 7.x
        is dead weight
      * /settings/rbac/users does not exist before 5.0
      * scopes and collections do not exist before 7.0

    A stub is used rather than a live cluster because the dangerous outcomes are
    all silent: an empty users table, an empty scope list, a create that fails
    with a message nobody reads. Against a healthy 7.x server every one of them
    looks fine.

    ./.venv/bin/python tests/test_cbase.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("cbase-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cbase, dbconn                                  # noqa: E402

bad = 0
VERSION = "4.6.4-4590-enterprise"      # flipped to 7.x mid-run
POOLS_CODE = 200        # flipped to 401/403 to stand in for a secured cluster
POOLS_BODY = ""         # set to stand in for a port that is not Couchbase
REBALANCING = False     # flipped to stand in for one in flight
MEMBERSHIP = "active"   # "inactiveAdded" = a node that holds nothing yet
NODE_OTP = "ns_1@10.0.0.1"
POSTED: list[tuple[str, dict]] = []
XDCR_CODE = 200

NODE = {"hostname": "cb01.example.com:8091", "status": "healthy",
        "otpNode": "ns_1@10.0.0.1",
        "clusterMembership": "active", "version": "4.6.4-4590-enterprise",
        "services": ["kv", "index", "n1ql"], "uptime": "90061",
        "memoryTotal": 16 * 2**30, "memoryFree": 8 * 2**30,
        "systemStats": {"cpu_utilization_rate": 12.5},
        "interestingStats": {"curr_items": 4200, "vb_replica_curr_items": 4200,
                             "ops": 31, "couch_docs_actual_disk_size": 2**30}}
BUCKET = {"name": "orders", "bucketType": "membase", "authType": "sasl",
          "saslPassword": "", "replicaNumber": 1, "evictionPolicy": "valueOnly",
          "threadsNumber": 3, "quota": {"ram": 1536 * 2**20},
          "nodes": [NODE], "controllers": {"doFlush": "/x"},
          "basicStats": {"itemCount": 4200, "opsPerSec": 31.0,
                         "diskUsed": 2**30, "dataUsed": 2**29,
                         "memUsed": 2**28, "diskFetches": 7,
                         "quotaPercentUsed": 41.5}}


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                                          # noqa: N802
        p = self.path
        if p == "/pools":
            if POOLS_CODE != 200:
                return self._send({"message": "Unauthorized"}, POOLS_CODE)
            if POOLS_BODY:
                body = POOLS_BODY.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            return self._send({"implementationVersion": VERSION,
                               "isEnterprise": True,
                               "pools": [{"name": "default"}]})
        if p.startswith("/pools/default/buckets/orders/scopes"):
            return self._send({"scopes": [
                {"name": "_default", "collections": [{"name": "_default"}]},
                {"name": "sales", "collections": [{"name": "invoices"},
                                                  {"name": "credits"}]}]})
        if p.startswith("/pools/default/buckets/"):
            # one bucket is an object; the collection is a list. Answering a
            # list to both is what a stub does and a real server never does.
            return self._send(BUCKET)
        if p.startswith("/pools/default/buckets"):
            return self._send([BUCKET])
        if p.startswith("/pools/default/remoteClusters"):
            if XDCR_CODE != 200:
                return self._send({"message": "Forbidden"}, XDCR_CODE)
            return self._send([{"name": "dr-site", "hostname": "cb-dr:8091",
                                "username": "repl", "uuid": "abc123",
                                "demandEncryption": True},
                               {"name": "gone", "hostname": "x", "uuid": "z",
                                "deleted": True}])
        if p.startswith("/pools/default/tasks"):
            if REBALANCING:
                return self._send([{"type": "rebalance", "status": "running",
                                    "progress": 42.5,
                                    "perNode": {NODE_OTP: {"progress": 42.5}}}])
            return self._send([
                {"type": "rebalance", "status": "notRunning"},
                {"type": "xdcr", "id": "abc123/orders/orders_dr",
                 "source": "orders", "target": "/remoteClusters/abc123/buckets/orders_dr",
                 "status": "running", "continuous": True,
                 "changesLeft": 12345, "docsWritten": 900, "errors": []}])
        if p.startswith("/pools/default"):
            node = dict(NODE, clusterMembership=MEMBERSHIP)
            return self._send({"clusterName": "stub", "nodes": [node],
                               "rebalanceStatus": "running" if REBALANCING else "none",
                               "memoryQuota": 9530, "indexMemoryQuota": 512,
                               "maxBucketCount": 10,
                               "alerts": [],
                               "storageTotals": {
                                   "ram": {"total": 16 * 2**30, "used": 5 * 2**30,
                                           "quotaTotal": 9530 * 2**20,
                                           "quotaUsed": 7168 * 2**20,
                                           "usedByData": 2**30},
                                   "hdd": {"total": 64 * 2**30, "used": 3 * 2**30,
                                           "free": 61 * 2**30, "usedByData": 2**25}}})
        if p == "/indexStatus":
            return self._send({"indexes": [
                {"index": "idx_status", "bucket": "orders", "status": "Ready",
                 "hosts": ["cb01.example.com:8091"],
                 "definition": "CREATE INDEX idx_status ON `orders`(`status`)"}]})
        if p == "/settings/rbac/users":
            if VERSION.startswith("4."):
                return self._send({"message": "not found"}, 404)
            return self._send([{"id": "svc_orders", "name": "Orders service",
                                "domain": "local",
                                "roles": [{"role": "bucket_full_access",
                                           "bucket_name": "orders"}]}])
        if p == "/settings/rbac/roles":
            return self._send([
                {"role": "admin", "name": "Full Admin", "desc": "everything"},
                {"role": "data_reader", "name": "Data Reader",
                 "bucket_name": "orders", "desc": "read documents"},
                {"role": "data_reader", "name": "Data Reader",
                 "bucket_name": "other", "desc": "read documents"},
            ])
        return self._send({"message": "unknown"}, 404)

    def do_PUT(self):                                          # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(self.rfile.read(n).decode(),
                                      keep_blank_values=True).items()}
        POSTED.append(("PUT " + self.path, form))
        return self._send({}, 200)

    def do_POST(self):                                         # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode()
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        POSTED.append((self.path, form))
        if self.path == "/pools/default/buckets":
            if VERSION.startswith("4.") and "authType" not in form:
                # what the real 4.x server does, and the reason this is tested
                return self._send({"errors": {"authType": "is missing"}}, 400)
            return self._send({}, 202)
        if self.path in ("/controller/rebalance", "/controller/stopRebalance"):
            return self._send({}, 200)
        if self.path == "/query/service":
            if "DROP" in form.get("statement", "").upper() \
                    and form.get("readonly") == "true":
                return self._send({"errors": [{"code": 1000,
                                               "msg": "readonly violation"}]}, 403)
            return self._send({"status": "success",
                               "results": [{"id": "o-1", "total": 9},
                                           {"id": "o-2", "extra": True}],
                               "metrics": {"resultCount": 2,
                                           "elapsedTime": "4.1ms"}})
        return self._send({"message": "unknown"}, 404)


def main() -> int:
    global VERSION, XDCR_CODE, POOLS_CODE, POOLS_BODY
    global MEMBERSHIP, REBALANCING, NODE_OTP
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    conn = {"type": "couchbase", "host": "127.0.0.1", "port": str(port),
            "query_port": str(port)}

    def fresh(write=False):
        c = cbase.Console("cb1", "u1", "admin", "pw", conn)
        c.write = write
        return c

    print("it is registered where an operator looks for a database")
    check("couchbase is a db provider", "couchbase" in dbconn.PROVIDERS)
    check("and is marked as its own engine",
          dbconn.PROVIDERS["couchbase"].get("engine") == "couchbase")
    check("the admin port is the default",
          dbconn.PROVIDERS["couchbase"]["default_port"] == 8091)
    ok, note = dbconn.test(conn)
    check(f"the test button delegates and succeeds, got {note[:60]!r}",
          ok and "Couchbase" in note and "4.6.4" in note)
    # This stub answers /pools anonymously, which is not something to pass over
    # in silence: everything in that note was read with no account.
    check(f"an anonymous answer is remarked on, got {note[-90:]!r}",
          "WITHOUT any credentials" in note)

    print("a properly secured cluster PASSES the reachability test")
    # It failed. A production cluster that refuses to describe itself without an
    # account was reported as "failed", with advice from the console's error
    # path telling the operator to open a console the button never opens — while
    # a cluster that answers anonymously passed. The test was rewarding the
    # misconfiguration. There are no credentials to offer here by design, so the
    # only question is whether the port answered as Couchbase, and a 401 does.
    for POOLS_CODE in (401, 403):
        ok, note = dbconn.test(conn)
        check(f"{POOLS_CODE} on /pools is reachable, not failed — got "
              f"{ok} {note[:48]!r}", ok is True)
        check(f"{POOLS_CODE}: it says an account is needed",
              "requires an account" in note)
        check(f"{POOLS_CODE}: and does not talk about reopening a console",
              "Open it again" not in note and "open it again" not in note)
        check(f"{POOLS_CODE}: nor claims anonymous readability",
              "WITHOUT any credentials" not in note)
    POOLS_CODE = 200

    print("something that is not Couchbase still fails")
    POOLS_BODY = '{"nginx":"hello"}'
    ok, note = dbconn.test(conn)
    check(f"a JSON answer without pools is refused, got {ok} {note[:40]!r}",
          ok is False and "not as Couchbase" in note)
    POOLS_BODY = ""

    print("a 4.6 cluster: what it cannot answer, it says so")
    con = fresh()
    v = con.version()
    check(f"version parsed, got {v['tuple']}", v["tuple"] == (4, 6))
    check("no cluster-wide users on this generation", v["has_rbac"] is False)
    check("no scopes either", v["has_collections"] is False)
    u = con.users()
    check("users reports unsupported rather than an empty list",
          u["supported"] is False and u["rows"] == [] and "5.0" in u["why"])
    col = con.collections("orders")
    check("collections likewise", col["supported"] is False and "7.0" in col["why"])

    print("the overview")
    o = con.overview()
    check(f"quota totals carried, got {o['ram']['quota_used']}",
          o["ram"]["quota_used"] == 7168 * 2**20)
    check("services are the union across nodes",
          o["services"] == ["index", "kv", "n1ql"])
    check(f"uptime is human, got {o['nodes'][0]['uptime']!r}",
          o["nodes"][0]["uptime"] == "1d 1h")
    check("a healthy cluster raises no alert", o["alerts"] == [])

    print("no key may shadow a dict method — the Jinja trap")
    # `{{ node.items }}` in a template resolves to the dict's own .items method,
    # not to the value. It rendered as a TypeError a long way from the cause,
    # so every row this module hands a template is checked for the whole family.
    rows = [o["nodes"][0], con.buckets()[0], con.indexes()["rows"][0]]
    for row in rows:
        clash = sorted(k for k in row if hasattr({}, k))
        check(f"a row uses reserved key(s) {clash}", not clash)

    print("buckets")
    b = con.buckets()[0]
    check(f"documents counted, got {b['docs']}", b["docs"] == 4200)
    check("a bucket with no SASL password is flagged as such",
          b["auth"] == "sasl" and b["sasl_set"] is False)
    check("flush availability is read from the controllers", b["can_flush"] is True)

    print("creating a bucket is refused until the console says otherwise")
    try:
        con.bucket_create("new", 256)
        check("a read-only console created a bucket", False)
    except dbconn.DBError as e:
        check(f"it says what to do, got {str(e)[:40]!r}", "write mode" in str(e))
    check("and nothing was sent", not POSTED)

    print("creating one on 4.x sends authType, or the server rejects it")
    w = fresh(write=True)
    msg = w.bucket_create("new", 256, replicas=2)
    path, form = POSTED[-1]
    check(f"posted to the buckets endpoint, got {path}",
          path == "/pools/default/buckets")
    check("authType is present for this generation", form.get("authType") == "sasl")
    check(f"quota and replicas carried, got {form}",
          form.get("ramQuotaMB") == "256" and form.get("replicaNumber") == "2")
    check("flush is off unless asked", form.get("flushEnabled") == "0")
    check(f"the confirmation names the bucket, got {msg[:40]!r}", "new" in msg)
    try:
        w.bucket_create("tiny", 8)
        check("an impossible quota was accepted", False)
    except dbconn.DBError as e:
        check("a too-small quota is caught before the round trip",
              "100 MB" in str(e))

    print("rebalance: running, needed, and neither are three states")
    con.forget()
    rb = con.rebalance()
    check(f"a balanced cluster is not running one, got {rb}",
          rb["running"] is False and rb["needed"] is False)
    check("the node's own identifier is carried, not its hostname",
          rb["known"] == ["ns_1@10.0.0.1"])

    MEMBERSHIP = "inactiveAdded"
    con.forget()
    rb = con.rebalance()
    # This is the state that is easy to miss: the node count says 1, and that
    # node holds nothing until a rebalance runs.
    check("a node added but not rebalanced in marks one as needed",
          rb["needed"] is True and rb["running"] is False)
    check(f"and it is named with why, got {rb['pending']}",
          rb["pending"] == [{"host": "cb01.example.com:8091",
                             "why": "inactiveAdded"}])
    MEMBERSHIP = "active"

    print("starting one can never eject a node")
    # The same endpoint removes nodes when ejectedNodes is populated, and a node
    # missing from knownNodes is treated as one to eject. Both are how a cluster
    # loses a node by accident, so both are asserted rather than trusted.
    w = fresh(write=True)
    msg = w.rebalance_start()
    path, form = POSTED[-1]
    check(f"posted to the rebalance controller, got {path}",
          path == "/controller/rebalance")
    check(f"ejectedNodes is present and EMPTY, got {form.get('ejectedNodes')!r}",
          form.get("ejectedNodes") == "")
    check(f"every node is named as one to keep, got {form.get('knownNodes')!r}",
          form.get("knownNodes") == "ns_1@10.0.0.1")
    check(f"the confirmation says nothing was ejected, got {msg[:60]!r}",
          "ejecting none" in msg)

    print("and it refuses rather than guess when the node list is incomplete")
    NODE_OTP = ""           # a cluster that did not report an identifier
    saved, NODE["otpNode"] = NODE["otpNode"], ""
    w2 = fresh(write=True)
    before = len(POSTED)
    try:
        w2.rebalance_start()
        check("it rebalanced with an incomplete node list", False)
    except dbconn.DBError as e:
        check(f"it explains why it refused, got {str(e)[:44]!r}",
              "eject" in str(e))
    check("and sent nothing at all", len(POSTED) == before)
    NODE["otpNode"], NODE_OTP = saved, saved

    print("a rebalance already running is not started twice")
    REBALANCING = True
    w3 = fresh(write=True)
    rb = w3.rebalance()
    check(f"it is seen as running at {rb['progress']}%",
          rb["running"] is True and rb["progress"] == 42.5)
    check(f"per-node progress is carried, got {rb['per_node']}",
          rb["per_node"] == {"ns_1@10.0.0.1": 42.5})
    before = len(POSTED)
    try:
        w3.rebalance_start()
        check("a second rebalance was started on top of one", False)
    except dbconn.DBError as e:
        check("it says one is already running", "already running" in str(e))
    check("and sent nothing", len(POSTED) == before)
    msg = w3.rebalance_stop()
    check(f"stopping posts to stopRebalance, got {POSTED[-1][0]}",
          POSTED[-1][0] == "/controller/stopRebalance")
    check("and says the cluster is left consistent", "consistent" in msg)
    REBALANCING = False

    print("neither rebalance action is available read-only")
    ro = fresh()
    for fn, what in ((ro.rebalance_start, "start"), (ro.rebalance_stop, "stop")):
        try:
            fn()
            check(f"a read-only console could {what} a rebalance", False)
        except dbconn.DBError as e:
            check(f"{what} needs write mode", "write mode" in str(e))

    print("XDCR: a deleted remote is not a remote, and a lag is a number")
    x = con.xdcr()
    check(f"one live remote, got {len(x['remotes'])}", len(x["remotes"]) == 1)
    check("the deleted one is dropped", x["remotes"][0]["name"] == "dr-site")
    check("encryption is read", x["remotes"][0]["secure"] is True)
    check(f"one replication, got {len(x['replications'])}",
          len(x["replications"]) == 1)
    r = x["replications"][0]
    check(f"the remote is named, not a uuid, got {r['remote']!r}",
          r["remote"] == "dr-site")
    check(f"target bucket unwrapped from the uri, got {r['target']!r}",
          r["target"] == "orders_dr")
    check(f"lag carried, got {r['changes_left']}", r["changes_left"] == 12345)
    check("the rebalance task is not mistaken for a replication",
          all(t["source"] == "orders" for t in x["replications"]))

    print("XDCR refused is not XDCR absent")
    XDCR_CODE = 403
    con.forget()
    x = con.xdcr()
    check("no replications are invented", x["replications"] == [])
    check(f"and the reason is carried, got {x['note'][:48]!r}",
          "permitted" in x["note"] and "admin" in x["note"])
    XDCR_CODE = 200

    print("SQL++")
    con.forget()
    out = con.query("SELECT id, total FROM orders")
    check("it succeeded", out["ok"] is True)
    check(f"columns are the union over rows, got {out['columns']}",
          out["columns"] == ["id", "total", "extra"])
    check("readonly is asserted for a read-only console",
          POSTED[-1][1].get("readonly") == "true")
    check("elapsed time is carried from the metrics", out["elapsed"] == "4.1ms")
    out = con.query("DROP INDEX orders.idx_status")
    check("a mutating statement is refused with the reason",
          out["ok"] is False and "write mode" in out["error"])
    w2 = fresh(write=True)
    w2.query("SELECT 1")
    check("a write console does not assert readonly",
          "readonly" not in POSTED[-1][1])
    check("history records both outcomes",
          len(con.history) == 2 and [h["ok"] for h in con.history] == [False, True])

    print("indexes")
    ix = con.indexes()
    check("one index, named and attributed to its bucket",
          len(ix["rows"]) == 1 and ix["rows"][0]["bucket"] == "orders")

    print("a 7.x cluster: the same code, the newer shapes")
    VERSION = "7.2.4-1234-enterprise"
    con = fresh()
    v = con.version()
    check(f"version parsed, got {v['tuple']}", v["tuple"] == (7, 2))
    check("users are supported now", v["has_rbac"] is True)
    u = con.users()
    check(f"and are listed, got {len(u['rows'])}",
          u["supported"] is True and len(u["rows"]) == 1)
    check("a role carrying a bucket is shown with it",
          u["rows"][0]["roles"] == ["bucket_full_access[orders]"])
    col = con.collections("orders")
    check(f"scopes are listed, got {[s['name'] for s in col['scopes']]}",
          col["supported"] is True and len(col["scopes"]) == 2)
    named = [c["name"] for c in col["scopes"][0]["collections"]]
    check(f"collections come with them, got {named}",
          named == ["credits", "invoices"])
    check("and the _default scope sorts last rather than being hidden",
          [s["name"] for s in col["scopes"]] == ["sales", "_default"])
    check(f"the total is carried, got {col.get('total')}", col.get("total") == 3)

    print("one bucket in detail")
    d = con.bucket_detail("orders")
    check(f"settings are carried, got quota {d['quota']}",
          d["quota"] == 1536 * 2**20 and d["eviction"] == "valueOnly")
    check("its collections come with it, not as a second call the page must make",
          d["collections"]["supported"] is True)
    check("no key in the detail shadows a dict attribute",
          not [k for k in d if hasattr({}, k)])

    print("the role catalogue, so roles are picked and not guessed")
    r = con.roles()
    check(f"roles are listed, got {[x['role'] for x in r['rows']]}",
          r["supported"] is True and len(r["rows"]) == 2)
    check("a role repeated once per bucket appears once",
          [x["role"] for x in r["rows"]] == ["admin", "data_reader"])
    check("a bucket-scoped role is marked as needing a bucket",
          [x["scoped"] for x in r["rows"]] == [False, True])

    print("creating and editing an account")
    w = fresh(write=True)
    try:
        w.user_save("svc", "S", "")
        check("an account with no roles was accepted", False)
    except dbconn.DBError as e:
        check(f"roles are required, got {str(e)[:30]!r}", "role" in str(e))
    try:
        w.user_save("svc", "S", "admin", new=True)
        check("a new account with no password was accepted", False)
    except dbconn.DBError as e:
        check("a new local account needs a password", "password" in str(e))
    msg = w.user_save("svc", "Svc", " admin , data_reader[orders] ",
                      password="s3cret", new=True)
    path, form = POSTED[-1]
    check(f"it PUTs to the local domain, got {path}",
          path == "PUT /settings/rbac/users/local/svc")
    check(f"roles are trimmed and rejoined, got {form.get('roles')!r}",
          form.get("roles") == "admin,data_reader[orders]")
    check("the password is sent", form.get("password") == "s3cret")
    # It ends up in an audit line, so it must not contain the password.
    check(f"the confirmation never contains the password, got {msg!r}",
          "s3cret" not in msg)
    w.user_save("svc", "Svc", "admin")
    check("an edit with no password does not send one",
          "password" not in POSTED[-1][1])
    con2 = fresh()
    try:
        con2.user_save("svc", "S", "admin")
        check("a read-only console changed an account", False)
    except dbconn.DBError as e:
        check("write mode is required", "write mode" in str(e))
    w = fresh(write=True)
    w.bucket_create("modern", 512)
    check("authType is NOT sent to a cluster that has RBAC",
          "authType" not in POSTED[-1][1])

    print("an unparsable version assumes nothing newer works")
    VERSION = "not-a-version"
    con = fresh()
    v = con.version()
    check(f"degrades to zero, got {v['tuple']}", v["tuple"] == (0, 0))
    check("so the newer endpoints are not attempted",
          con.users()["supported"] is False)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
