#!/usr/bin/env python3
"""Reading one Temporal execution: filters, history, and why it failed.

WHY A STUB
    The interesting cases are all ones a healthy server will not show you. A
    cluster with nothing failed in its retention window cannot demonstrate a
    failure chain; a 2.42 UI server cannot demonstrate the newer URL shape; and
    a rejected visibility query is the one thing an operator will hit on day one.

WHAT KEEPS BREAKING
    Two things, both found by running this against a real server first:

      * the UI server changed how it addresses one execution. 2.42 wants
        /workflows/{id}?runId={run} and newer builds want
        /workflows/{id}/runs/{run}. The wrong one is a flat 404, which reads as
        "no such workflow" rather than "this server spells it differently".
      * a failure chain ends with cause == {}, and an empty dict is still a
        dict. Walking it as truthy appended four blank links to every failure.

    ./.venv/bin/python tests/test_temporal.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("temporal-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import workflows as W                                 # noqa: E402

bad = 0
SHAPE = "query"          # which URL form this stub answers: query | path
COUNT_SHAPE = "hyphen"   # workflow-count (2.42) | workflows/count | absent
SEEN: list[str] = []     # every path asked for


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def payload(obj) -> dict:
    return {"metadata": {"encoding": b64("json/plain")},
            "data": b64(json.dumps(obj))}


# An activity failure wrapping an application failure. The inner one is the
# answer; the outer one is what a shallow reader reports instead.
FAILURE = {
    "message": "Activity task failed",
    "activityFailureInfo": {"scheduledEventId": 5},
    "stackTrace": "outer.frame(Outer.java:1)",
    "cause": {
        "message": "gateway said no",
        "applicationFailureInfo": {"type": "GatewayRejected",
                                   "nonRetryable": True},
        "stackTrace": "com.example.Activity.call(Activity.java:42)",
        "cause": {},          # the end of the chain, and still a dict
    },
}

EVENTS = [
    {"eventId": 1, "eventTime": "2026-08-03T10:00:00Z",
     "eventType": "EVENT_TYPE_WORKFLOW_EXECUTION_STARTED",
     "workflowExecutionStartedEventAttributes": {
         "workflowType": {"name": "PayoutWorkflow"},
         "taskQueue": {"name": "payout-tq"},
         "input": {"payloads": [payload({"msisdn": "255700000000"})]}}},
    {"eventId": 2, "eventTime": "2026-08-03T10:00:01Z",
     "eventType": "EVENT_TYPE_ACTIVITY_TASK_SCHEDULED",
     "activityTaskScheduledEventAttributes": {
         "activityType": {"name": "CallGateway"}, "activityId": "1",
         "taskQueue": {"name": "payout-tq"}}},
    {"eventId": 3, "eventTime": "2026-08-03T10:00:02Z",
     "eventType": "EVENT_TYPE_ACTIVITY_TASK_FAILED",
     "activityTaskFailedEventAttributes": {
         "identity": "1@worker-abc", "scheduledEventId": 2,
         "retryState": "RETRY_STATE_NON_RETRYABLE_FAILURE",
         "failure": FAILURE}},
    {"eventId": 4, "eventTime": "2026-08-03T10:00:03Z",
     "eventType": "EVENT_TYPE_TIMER_STARTED",
     "timerStartedEventAttributes": {"timerId": "5"}},
    {"eventId": 5, "eventTime": "2026-08-03T10:00:03Z",
     "eventType": "EVENT_TYPE_TIMER_FIRED",
     "timerFiredEventAttributes": {"timerId": "5", "startedEventId": 4}},
    {"eventId": 6, "eventTime": "2026-08-03T10:00:04Z",
     "eventType": "EVENT_TYPE_WORKFLOW_EXECUTION_FAILED",
     "workflowExecutionFailedEventAttributes": {"failure": FAILURE}},
]

DESCRIBE = {
    "workflowExecutionInfo": {
        "execution": {"workflowId": "pay-1", "runId": "run-1"},
        "type": {"name": "PayoutWorkflow"},
        "status": "WORKFLOW_EXECUTION_STATUS_TIMED_OUT",
        "startTime": "2026-08-03T10:00:00Z",
        "executionDuration": "125s",
        "historyLength": "5", "historySizeBytes": "2048",
        "stateTransitionCount": "4",
        "searchAttributes": {"indexedFields": {"CustomKey": payload("abc")}},
        "memo": {"fields": {"note": payload("hello")}},
    },
    "executionConfig": {"taskQueue": {"name": "payout-tq"},
                        "workflowRunTimeout": "600s",
                        "defaultWorkflowTaskTimeout": "30s"},
    "pendingActivities": [
        {"activityId": "1", "activityType": {"name": "CallGateway"},
         "state": "PENDING_ACTIVITY_STATE_SCHEDULED", "attempt": "7",
         "maximumAttempts": 10, "lastWorkerIdentity": "1@worker-abc",
         "lastFailure": FAILURE}],
}


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
        SEEN.append(self.path)
        p, _, qs = self.path.partition("?")
        q = urllib.parse.parse_qs(qs)
        if p == "/api/v1/namespaces":
            return self._send({"namespaces": [
                {"namespaceInfo": {"name": "default", "description": "main"},
                 "config": {"workflowExecutionRetentionTtl": "259200s"}},
                {"namespaceInfo": {"name": "temporal-system"},
                 "config": {"workflowExecutionRetentionTtl": "604800s"}}]})
        if p.endswith("/search-attributes"):
            return self._send({
                "customAttributes": {"partnerId": "INDEXED_VALUE_TYPE_KEYWORD",
                                     "phoneNumber": "INDEXED_VALUE_TYPE_KEYWORD"},
                "systemAttributes": {
                    "ExecutionStatus": "INDEXED_VALUE_TYPE_KEYWORD",
                    "HistoryLength": "INDEXED_VALUE_TYPE_INT",
                    "CloseTime": "INDEXED_VALUE_TYPE_DATETIME"}})
        if "/task-queues/" in p:
            if p.endswith("/nobody-here"):
                return self._send({"pollers": []})
            return self._send({
                "effectiveRateLimit": {"requestsPerSecond": 4000},
                "pollers": [{"identity": "1@worker-abc",
                             "lastAccessTime": "2026-08-03T10:00:00Z",
                             "ratePerSecond": "100000"}]})
        if p.endswith("/workflow-count") or p.endswith("/workflows/count"):
            mine = ("/workflow-count" if COUNT_SHAPE == "hyphen"
                    else "/workflows/count")
            if COUNT_SHAPE == "absent" or not p.endswith(mine):
                return self._send({"message": "not found"}, 404)
            return self._send({"count": "4342", "groups": [
                {"groupValues": [{"metadata": {"encoding": b64("json/plain")},
                                  "data": b64('"Completed"')}], "count": "4339"},
                {"groupValues": [{"metadata": {"encoding": b64("json/plain")},
                                  "data": b64('"Failed"')}], "count": "3"}]})
        if p.endswith("/workflows"):
            if "NoSuchField" in (q.get("query") or [""])[0]:
                return self._send(
                    {"message": "invalid query: column name 'NoSuchField' is "
                                "not a valid search attribute"}, 400)
            return self._send({"executions": [{
                "execution": {"workflowId": "pay-1", "runId": "run-1"},
                "type": {"name": "PayoutWorkflow"},
                "status": "WORKFLOW_EXECUTION_STATUS_FAILED",
                "startTime": "2026-08-03T10:00:00Z",
                "executionDuration": "0.42s",
                "taskQueue": "payout-tq", "historyLength": 5}],
                "nextPageToken": "TOKEN123"})
        # the two spellings; this stub answers only the configured one
        wants_query = "runId=" in qs
        wants_path = "/runs/" in p
        if (SHAPE == "query" and not wants_query) or \
           (SHAPE == "path" and not wants_path):
            return self._send({"message": "not found"}, 404)
        if p.endswith("/history") or p.endswith("/history-reverse"):
            ev = list(EVENTS)
            if p.endswith("-reverse"):
                ev.reverse()
            return self._send({"history": {"events": ev}})
        return self._send(DESCRIBE)


def main() -> int:
    global SHAPE, COUNT_SHAPE
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conn = {"id": "wf-test", "type": "temporal",
            "base_url": f"http://127.0.0.1:{srv.server_address[1]}"}

    print("filters become a visibility query, and a value cannot escape it")
    check("one status is an equality",
          W.build_query({"status": ["Failed"]}) == 'ExecutionStatus = "Failed"')
    check("several become IN",
          W.build_query({"status": ["Failed", "Running"]})
          == 'ExecutionStatus IN ("Failed", "Running")')
    check("fields are ANDed",
          W.build_query({"type": "P", "queue": "q"})
          == 'WorkflowType = "P" AND TaskQueue = "q"')
    # A quote in a value would otherwise close the clause and change the query.
    check(f'a quote is escaped, got {W.build_query({"wid": 'a"b'})}',
          W.build_query({"wid": 'a"b'}) == 'WorkflowId = "a\\"b"')
    check("a raw query wins over the fields",
          W.build_query({"raw": "X = 1", "type": "P"}) == "X = 1")
    check("an unknown status is not smuggled through",
          W.build_query({"status": ["Nonsense"]}) == "")

    print("namespaces, with the system one sorted last")
    ns = W.namespaces(conn)
    check(f"got {[n['name'] for n in ns]}",
          [n["name"] for n in ns] == ["default", "temporal-system"])
    check("retention is carried, because it explains an empty result",
          ns[0]["retention"] == "259200s")

    print("the list")
    r = W.search(conn, "default", {"status": ["Failed"]})
    check("one row", len(r["rows"]) == 1)
    row = r["rows"][0]
    check(f"status is shortened, got {row['status']!r}", row["status"] == "Failed")
    check(f"a sub-second duration reads as ms, got {row['took']!r}",
          row["took"] == "420ms")
    check("the page token is carried", r["token"] == "TOKEN123")

    print("a rejected query is handed back with the server's own words")
    r = W.search(conn, "default", {"raw": "NoSuchField = 'x'"})
    check("it did not raise past the page", r["rows"] == [])
    check(f"and says which attribute, got {r['error'][:60]!r}",
          "NoSuchField" in r["error"] and "not a valid search attribute" in r["error"])

    print("both URL shapes, because the UI server changed its routes")
    for shape in ("query", "path"):
        SHAPE = shape
        W._shape.clear()
        d = W.describe(conn, "default", "pay-1", "run-1")
        check(f"{shape}: describe worked", d["type"] == "PayoutWorkflow")
        check(f"{shape}: the shape is remembered so the next call costs one hit",
              W._shape.get("wf-test") == shape)
        before = len(SEEN)
        W.describe(conn, "default", "pay-1", "run-1")
        check(f"{shape}: second call made exactly one request, made "
              f"{len(SEEN) - before}", len(SEEN) - before == 1)
    SHAPE = "query"
    W._shape.clear()

    print("describe")
    d = W.describe(conn, "default", "pay-1", "run-1")
    check(f"status shortened, got {d['status']!r}", d["status"] == "TimedOut")
    check(f"duration humanised, got {d['took']!r}", d["took"] == "2m 5s")
    check("the task queue comes from the config", d["queue"] == "payout-tq")
    check("search attributes are decoded, not left as base64",
          d["search_attrs"].get("CustomKey") == '"abc"')
    check("so is the memo", d["memo"].get("note") == '"hello"')
    check("a pending activity carries its attempt count",
          len(d["pending"]) == 1 and d["pending"][0]["attempt"] == 7
          and d["pending"][0]["max"] == 10)
    check("and the failure that keeps it retrying",
          d["pending"][0]["failure"][-1]["message"] == "gateway said no")

    print("the failure chain ends where the causes end")
    # It did not. cause == {} is falsy but IS a dict, so the walk appended four
    # empty links and the page showed "?:" rows under every real failure.
    chain = W._failure(FAILURE)
    check(f"two links, got {len(chain)}", len(chain) == 2)
    check("no link is blank", all(c["message"] for c in chain))
    check(f"the root cause is last, got {chain[-1]['message']!r}",
          chain[-1]["message"] == "gateway said no")
    check("and is typed by the application",
          chain[-1]["type"] == "GatewayRejected")
    check("the outer link is typed from its *FailureInfo key",
          chain[0]["type"].lower().startswith("activity"))
    check("stack traces are carried", "Activity.java:42" in chain[-1]["stack"])

    print("history")
    h = W.history(conn, "default", "pay-1", "run-1")
    check(f"all events, got {h['shown']}", h["shown"] == 6)
    check("not truncated", h["truncated"] is False)
    cats = [e["cat"] for e in h["events"]]
    check(f"each is categorised for skimming, got {cats}",
          cats == ["workflow", "activity", "activity", "timer", "timer",
                   "workflow"])
    check("the type is readable",
          h["events"][0]["kind"] == "Workflow Execution Started")
    # Both the activity failure and the workflow failure carry one.
    check(f"failure points are collected, got {len(h['failures'])}",
          len(h["failures"]) == 2)
    check("each failure point names its event",
          [f["event"] for f in h["failures"]] == [3, 6])
    started = h["events"][0]
    check(f"input is decoded and pretty-printed, got {started['payloads']}",
          started["payloads"] and "msisdn" in started["payloads"][0][1])
    detail = dict(started["detail"])
    check(f"the workflow type is pulled out, got {detail}",
          detail.get("workflow") == "PayoutWorkflow")
    failed = h["events"][2]
    check("a retry state is shortened rather than shouted",
          dict(failed["detail"]).get("retry state") == "Non Retryable Failure")

    print("newest first asks the other endpoint")
    h2 = W.history(conn, "default", "pay-1", "run-1", newest_first=True)
    check("the order is reversed", [e["id"] for e in h2["events"]]
          == [6, 5, 4, 3, 2, 1])
    check("via history-reverse", any("history-reverse" in s for s in SEEN))

    print("payloads that are not text are described, not mangled")
    check("binary is named with its size",
          "not decoded here" in W._payload(
              {"metadata": {"encoding": b64("binary/protobuf")}, "data": b64("xx")}))
    # This one was written `... or True`, which is not a test at all.
    junk = W._payload({"data": "!!! not base64 !!!"})
    check(f"undecodable data is described, got {junk[:40]!r}",
          junk.startswith("<") and junk.endswith(">"))
    check("a missing payload says so", "no data" in W._payload({}))
    big = W._payload(payload("x" * (W.PAYLOAD_CAP + 500)))
    check(f"a huge payload is capped, got {len(big)}",
          len(big) <= W.PAYLOAD_CAP + 20 and "truncated" in big)

    print("int64 arrives as a JSON string, and must not stay one")
    # historySizeBytes comes back as "2048". Left as a string, formatting it with
    # thousands separators raises ValueError deep inside a template render, which
    # is a long way from the cause.
    d = W.describe(conn, "default", "pay-1", "run-1")
    for key in ("events", "bytes", "transitions"):
        check(f"{key} is an int, got {type(d[key]).__name__}",
              isinstance(d[key], int))
    check(f"and keeps its value, got {d['bytes']}", d["bytes"] == 2048)
    check("a pending activity's attempt too",
          isinstance(d["pending"][0]["attempt"], int))
    check("junk does not raise", W._int("not a number") == 0)

    print("input, result and parent come out of the history, not a second call")
    h = W.history(conn, "default", "pay-1", "run-1")
    check(f"input decoded, got {h['input']}",
          h["input"] and "msisdn" in h["input"][0])
    # The workflow failed, so its "result" is the reason — which is what Temporal
    # puts in the Result box for a failed execution.
    check(f"a failed execution's result is the root cause, got {h['result']}",
          h["result"] == ["gateway said no"])
    check(f"closed_by names the closing event, got {h['closed_by']!r}",
          h["closed_by"] == "Failed")

    print("counts, for the status pills")
    global COUNT_SHAPE
    for shape in ("hyphen", "count"):
        COUNT_SHAPE = shape
        W._count_shape.clear()
        t = W.counts(conn, "default")
        check(f"{shape}: counts came back", t["available"] is True)
        check(f"{shape}: total, got {t['total']}", t["total"] == 4342)
        check(f"{shape}: split by status, got {t['by_status']}",
              t["by_status"] == {"Completed": 4339, "Failed": 3})
        check(f"{shape}: the spelling is remembered",
              W._count_shape.get("wf-test") == shape)
    # A server without the endpoint at all must degrade, not break the page.
    COUNT_SHAPE = "absent"
    W._count_shape.clear()
    t = W.counts(conn, "default")
    check("an absent endpoint is reported as unavailable",
          t["available"] is False and t["total"] == 0)
    check(f"with a reason, got {t['why'][:40]!r}", "does not report counts" in t["why"])
    COUNT_SHAPE = "hyphen"
    check("the base filters narrow the counts",
          'ExecutionStatus' not in W.build_query({"status": [], "type": "P"}))

    print("saved views are queries a database-backed store will accept")
    for v in W.views("2026-08-03T09:00:00Z"):
        q = v["query"]
        check(f"{v['label']}: no ORDER BY", "ORDER BY" not in q.upper())
        check(f"{v['label']}: no STARTS_WITH", "STARTS_WITH" not in q.upper())
    labels = [v["key"] for v in W.views("2026-08-03T09:00:00Z")]
    check(f"the first is unfiltered, got {labels}", labels[0] == "")

    print("the attributes a namespace can be filtered by")
    sa = W.search_attributes(conn, "default")
    check(f"custom ones are separated, got {[a['name'] for a in sa['custom']]}",
          [a["name"] for a in sa["custom"]] == ["partnerId", "phoneNumber"])
    check("and typed", sa["custom"][0]["type"] == "KEYWORD")
    check("the INDEXED_VALUE_TYPE_ prefix is stripped",
          all("INDEXED" not in a["type"] for a in sa["custom"] + sa["system"]))
    ints = [a for a in sa["system"] if a["name"] == "HistoryLength"]
    check(f"an int attribute offers comparisons, got {ints and ints[0]['ops']}",
          ints and ">" in ints[0]["ops"])
    kw = [a for a in sa["custom"] if a["name"] == "phoneNumber"][0]
    check(f"a keyword does not offer them, got {kw['ops']}", ">" not in kw["ops"])

    print("a clause is quoted by the attribute's type, not by guesswork")
    # Both failure modes are silent: a quoted int is a type error, and an
    # unquoted keyword matches nothing at all rather than erroring.
    check("an int is bare", W.attr_clause("HistoryLength", ">", "5", "INT")
          == "HistoryLength > 5")
    check("a keyword is quoted",
          W.attr_clause("phoneNumber", "=", "2557", "KEYWORD")
          == 'phoneNumber = "2557"')
    check("IN splits and quotes each value",
          W.attr_clause("providerId", "IN", "a, b", "KEYWORD")
          == 'providerId IN ("a", "b")')
    check("IN on an int does not quote",
          W.attr_clause("HistoryLength", "IN", "1, 2", "INT")
          == "HistoryLength IN (1, 2)")
    check("a bool becomes a literal",
          W.attr_clause("x", "=", "yes", "BOOL") == "x = true")
    check("IS NULL takes no value",
          W.attr_clause("x", "IS NULL", "", "KEYWORD") == "x IS NULL")
    check("an empty value is dropped rather than sent as an empty match",
          W.attr_clause("x", "=", "", "KEYWORD") == "")
    check("and a quote in the value cannot end the clause",
          W.attr_clause("x", "=", 'a"b', "KEYWORD") == 'x = "a\\"b"')
    check("attribute filters join the rest of the query",
          W.build_query({"status": ["Failed"],
                         "attrs": [{"name": "providerId", "op": "=",
                                    "value": "m", "type": "KEYWORD"}]})
          == 'ExecutionStatus = "Failed" AND providerId = "m"')

    print("who is polling a task queue — the reason a workflow sits at Scheduled")
    pl = W.pollers(conn, "default", "payout-tq")
    check(f"pollers are listed, got {len(pl['rows'])}", len(pl["rows"]) == 1)
    check("with an identity and a rate",
          pl["rows"][0]["identity"] == "1@worker-abc"
          and pl["rows"][0]["rate"] == 100000)
    check("and the queue's rate limit", pl["rate"] == 4000)
    empty = W.pollers(conn, "default", "nobody-here")
    check(f"an unpolled queue says so, got {empty['why']!r}",
          empty["rows"] == [] and "no worker" in empty["why"])
    check("no queue asks nothing", W.pollers(conn, "default", "")["rows"] == [])

    print("the timeline, stitched by the ids events use to refer to each other")
    h = W.history(conn, "default", "pay-1", "run-1")
    rows = sorted(h["events"], key=lambda e: W._int(e["id"]))
    lanes = W.timeline(rows)
    kinds = [(l["kind"], l["outcome"]) for l in lanes]
    check(f"one lane per activity and timer, got {kinds}",
          kinds == [("activity", "failed"), ("timer", "completed")])
    act = lanes[0]
    # The three events belong to one bar only because STARTED and FAILED both
    # carry scheduledEventId = 2. Grouping by anything else scatters them.
    check(f"scheduled, started and failed are one lane, got {act['events']}",
          act["events"] == [2, 3])
    check(f"named from the scheduled event, got {act['name']!r}",
          act["name"] == "CallGateway")
    check("and it carries the failure chain for the panel",
          act["detail"] and act["detail"][-1]["message"] == "gateway said no")
    check("a timer that fired reads as completed",
          lanes[1]["outcome"] == "completed")
    a, b = W.span(rows)
    check(f"the window is first to last, got {a[11:19]}–{b[11:19]}",
          a.endswith("10:00:00Z") and b.endswith("10:00:04Z"))
    check("epoch parses for positioning", W.epoch(b) - W.epoch(a) == 4.0)
    check("an unparsable time does not raise", W.epoch("not a time") == 0.0)

    print("every event carries its own JSON, capped")
    check("JSON is present", h["events"][0]["json"].startswith("{"))
    check(f"and capped at {W.EVENT_JSON_CAP}",
          all(len(e["json"]) <= W.EVENT_JSON_CAP for e in h["events"]))

    print("durations")
    for raw, want in (("0.42s", "420ms"), ("45s", "45s"), ("125s", "2m 5s"),
                      ("7200s", "2h 0m"), ("", "")):
        got = W._duration(raw)
        check(f"{raw!r} -> {got!r}, wanted {want!r}", got == want)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
