"""The questions this assistant must understand, as a test.

Every case here is one somebody actually asked and got a wrong answer to. They
are kept as a suite because each fix was undone at least once by the next one:
adding "failing" to the pods vocabulary broke "any failing pipelines?", and
removing "clusters" from the stopwords broke "traefik ip for ledger prod
cluster". A list of sentences is the only honest regression test for a router.

    ./.venv/bin/python tests/test_routing.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ADMIN = {"id": "test", "role": "admin"}

# question, expected query
COLD = [
    ("what is the traefik ip for ledger prod cluster", "services"),
    ("what is the traefik ip for ledger dev cluster", "services"),
    ("give me the traefik ip on eu preprod cluster", "services"),
    ("show me the loadbalancer addresses", "services"),
    ("list the connected clusters", "clusters"),
    ("list the connected k8s cluster", "clusters"),
    ("which clusters are unreachable", "clusters"),
    ("which clusters are unhealthy", "clusters"),
    ("which integrations are connected", "connections"),
    ("which integrations are unhealthy", "connections"),
    ("give me the ingress hosts on us-preprod", "ingress"),
    ("which dns names does eu preprod serve", "ingress"),
    ("i have server SN C7KG414 give me the ip", "assets"),
    ("what is the idrac ip for esx01", "assets"),
    ("what is 10.4.9.50", "assets"),
    ("how many physical server we have in uae acme prod ?", "assets"),
    ("how many physical servers do we have", "assets"),
    ("what is in the inventory", "assets"),
    ("which pods need attention", "pods"),
    ("pods on eu preprod cluster", "pods"),
    ("which pods are crashing", "pods"),
    ("what is the running pod on eu preprod cluster", "pods"),
    ("show me nodes that are not ready", "nodes"),
    ("any failing pipelines?", "pipelines"),
    ("which pipelines are failing", "pipelines"),
    ("argocd apps out of sync", "gitops"),
    ("temporal workflows that failed", "workflows"),
    ("temperature of the servers", "servers"),
    ("is anything overheating", "servers"),
    ("what vms are stopped", "vms"),
    ("why did that pod get killed", "events"),
    ("how many deployments are there", "workloads"),
    # shapes the dynamic layer has to handle: superlatives, counts, states
    ("what is the last pipeline that ran", "pipelines"),
    ("what is the last running pipeline", "pipelines"),
    ("which was the last failed pipeline", "pipelines"),
    ("show me the last 3 pipelines that ran", "pipelines"),
    ("how many pipelines are failing", "pipelines"),
    ("what is the build number and duration of the last pipeline", "pipelines"),
    ("how many clusters do we have", "clusters"),
    ("how many pods on eu preprod", "pods"),
    # the datasets that were missing entirely, each from a real question
    ("give me the list of connected repo", "repos"),
    ("give me the list of connected repositories", "repos"),
    ("give me the list of connected clouds", "cloud_accounts"),
    ("give me list of connected gitops tools", "gitops_tools"),
    ("list the connected log stores", "log_stores"),
    ("which monitoring systems are connected", "monitoring_systems"),
    ("list the connected hypervisors", "hypervisors"),
    ("what storage devices do we have", "storage_devices"),
    ("give me a direct link to edit the config for checkout in us preprod", "config"),
    ("where is the values file for pesalink in ke dev", "config"),
    ("give me the list of connected ciluster", "clusters"),
]

# the same questions, typed the way people actually type
MISSPELLED = [
    ("what is the traefic ip for ledgr dev", "services"),
    ("wich pdos need atention", "pods"),
    ("lst the conected clsuters", "clusters"),
    ("ingres hosts on ke-prprod", "ingress"),
    ("temperture of the servrs", "servers"),
    ("wich integrations are unhealty", "connections"),
    ("nods not redy", "nodes"),
    ("failng pipelins", "pipelines"),
    ("certifcate on eu preprod", "certificates"),
    ("ssl certs expirng soon", "certificates"),
]

# question, previous query, expected — continuations inherit, real questions do not
FOLLOW_UP = [
    ("the one for eu preprod", "services", "services"),
    ("and for ap preprod?", "services", "services"),
    ("same for us-preprod", "ingress", "ingress"),
    ("what about tz", "pods", "pods"),
    ("eu preprod", "nodes", "nodes"),
    ("which pods need attention", "services", "pods"),
    ("which clusters are unreachable", "services", "clusters"),
    ("what is 10.4.9.50", "services", "assets"),
    ("how many physical server we have in uae acme prod ?", "pipelines", "assets"),
]


def names_a_cluster(question: str) -> bool:
    """A question mentioning a place can only route correctly if that place is
    registered — the router resolves it through the cluster index."""
    q = question.lower()
    return any(w in q for w in ("preprod", "prod", "cluster", "dev"))


def estate() -> dict:
    """The clusters this installation knows, or {} — the whole difference
    between a failing case and an unanswerable one.

    Most of this file asks the router a question that NAMES a cluster, and the
    estate-dependent half asks what the ANSWER says. Against an empty database
    every one of those fails, and not one of the failures says anything about
    the router — which is how this file earned its reputation as "the test that
    does not pass". It reports them as skipped instead, so a real routing
    regression is the only thing that can turn it red.

    The proper fix is a fixture estate (P2), and this is not it: with no
    database these cases are NOT being tested, and the count says so out loud
    rather than printing a reassuring OK.
    """
    from app import answers
    return answers.cluster_index()


def main() -> int:
    from app import assistant
    known = estate()
    bad = skipped = 0
    for label, cases in (("cold", COLD), ("misspelled", MISSPELLED)):
        # counted per label: sharing one counter made the second group report
        # the first group's failures, which is worse than no number at all
        failed = 0
        for question, want in cases:
            if not known and names_a_cluster(question):
                skipped += 1
                continue
            got = assistant.route(ADMIN, question)[0]
            if got != want:
                failed += 1
                print(f"FAIL [{label}] {question!r} -> {got or '(none)'} "
                      f"(expected {want})")
        bad += failed
        print(f"  {label}: {len(cases) - failed} of {len(cases)}"
              if failed else f"  {label}: all {len(cases)} pass")
    for question, previous, want in FOLLOW_UP:
        got = assistant.route(
            ADMIN, question,
            {"query": previous, "question": "x", "focus": ""})[0]
        if got != want:
            bad += 1
            print(f"FAIL [follow-up after {previous}] {question!r} -> {got} "
                  f"(expected {want})")
    if not bad:
        print(f"  follow-up: all {len(FOLLOW_UP)} pass")
    bad += check_shapes(known)
    bad += check_inherited_cluster(known)
    if skipped:
        print(f"  {skipped} cases skipped: they name a cluster and this "
              f"database has none (see estate() — P2 is to give this fixtures)")
    print("FAILED" if bad else "OK")
    return 1 if bad else 0




# ── the dynamic layer, checked by outcome rather than by route ──
# These assert what the answer must *say*, because routing alone would have
# passed while the answer was still wrong: "the last running pipeline" once
# returned the most recent successful one.
SHAPES = [
    # question, must appear in the note or headline
    ("what is the last pipeline that ran", "most recent"),
    ("what is the last running pipeline", "running"),
    ("how many pipelines are failing", "pipelines"),
    # a question naming a thing that exists must find it, and one naming a thing
    # that does not must say so rather than answering about something else
    ("give me a direct link to edit the config for checkout in us preprod",
     "checkout"),
    ("give me the list of connected gitops tools", "no gitops"),
    # certificates: asking for them used to answer with ingress host names, and
    # "the expiry DATE" used to be read as a search for a thing called "date"
    ("list for me the certificate on eu preprod cluster", "expires"),
    ("show me the expiry date for the used certificate on eu preprod", "expires"),
    ("which certificates expire in the next 30 days", "within 30 days"),
]


def check_inherited_cluster(known: dict) -> int:
    """"…on the same cluster" must keep the scope even when the subject changes:
    widening to every cluster answers a different question."""
    from app import answers, assistant
    if not known:
        print("  inherited-cluster: SKIPPED — no estate")
        return 0
    bad = 0
    prev = {"query": "ingress", "question": "host names on eu preprod",
            "focus": "", "cluster_phrase": "eu preprod"}
    q = "show me the expiry date for the used certificate on the same cluster"
    inherit = assistant.inherited_cluster(q, prev)
    if inherit != "eu preprod":
        print(f"  FAIL inherit: {q!r} -> {inherit!r}")
        bad += 1
    else:
        got = answers.run(ADMIN, "certificates", f"{q} {inherit}")
        # the phrase is what a person types; the cluster's own name may
        # punctuate it differently, so compare loosely
        if not got["rows"] or any(
                r["cluster"].replace("-", " ").lower() != "eu preprod"
                for r in got["rows"]):
            print(f"  FAIL scope: {[r['cluster'] for r in got['rows']]}")
            bad += 1
    # and a question that names no cluster and points at nothing must not inherit
    if assistant.inherited_cluster("list all certificates", prev):
        print("  FAIL: inherited a cluster with nothing pointing back")
        bad += 1
    print(f"  inherited-cluster: {'ok' if not bad else str(bad) + ' failed'}")
    return bad


def check_shapes(known: dict) -> int:
    from app import answers, assistant
    if not known:
        print(f"  shapes: {len(SHAPES)} SKIPPED — these assert what an answer "
              f"says, and there is no estate to answer about")
        return 0
    bad = 0
    for question, expect in SHAPES:
        name = assistant.route(ADMIN, question)[0]
        got = answers.run(ADMIN, name, question)
        blob = (got.get("note", "") + " " + (answers.headline(got) or "")).lower()
        if expect.lower() not in blob:
            bad += 1
            print(f"FAIL [shape] {question!r} -> {blob[:100]!r} "
                  f"(expected {expect!r})")
    if not bad:
        print(f"  shapes: all {len(SHAPES)} pass")
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
