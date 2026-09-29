#!/usr/bin/env python3
"""Resolving a cloud region from what somebody actually typed.

Alibaba refuses its central endpoint for most regions — "The specified endpoint
cant operate this region" — so each region has to be called at its own endpoint,
and the endpoint comes from the API rather than a table that goes stale. That
also means the region has to be resolved before anything can be asked, and the
value in the settings box is often a name rather than an id: Alibaba's own name
for Riyadh is "SAU (Riyadh)".

The names here are the real ones this account sees, including the collision that
made the first attempt ambiguous: São Paulo is spelled "Sau Paulo".
"""
from __future__ import annotations

import os
import pathlib
import time
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("cloud-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cloud                                           # noqa: E402

REGIONS = [
    {"id": "cn-hangzhou", "name": "China (Hangzhou)",
     "endpoint": "ecs-cn-hangzhou.aliyuncs.com"},
    {"id": "cn-beijing", "name": "China (Beijing)",
     "endpoint": "ecs.aliyuncs.com"},
    {"id": "me-central-1", "name": "SAU (Riyadh)",
     "endpoint": "ecs.me-central-1.aliyuncs.com"},
    {"id": "me-east-1", "name": "UAE (Dubai)",
     "endpoint": "ecs.me-east-1.aliyuncs.com"},
    {"id": "sa-east-1", "name": "Brazil (Sau Paulo)",
     "endpoint": "ecs.sa-east-1.aliyuncs.com"},
    {"id": "ap-southeast-1", "name": "Singapore",
     "endpoint": "ecs.ap-southeast-1.aliyuncs.com"},
]

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def resolves(want: str) -> tuple[str, str]:
    r, note = cloud.alibaba_resolve_region(want, REGIONS)
    return r["id"], note


def refuses(want: str) -> str:
    try:
        cloud.alibaba_resolve_region(want, REGIONS)
        return ""
    except cloud.CloudError as e:
        return str(e)


def main() -> int:
    # ── an id is used as given, and says nothing ──────────────────────────
    rid, note = resolves("me-central-1")
    check("an exact id resolves to itself", rid == "me-central-1" and note == "")
    rid, _ = resolves("ME-Central-1")
    check("an id is not case sensitive", rid == "me-central-1")

    # ── the case that started this: a name, not an id ─────────────────────
    rid, note = resolves("SAU")
    check("SAU resolves to Riyadh, not to Sau Paulo", rid == "me-central-1")
    check("the substitution is stated, not silent",
          "not a region id" in note and "me-central-1" in note)
    check("lower case works too", resolves("sau")[0] == "me-central-1")
    check("UAE resolves to Dubai", resolves("UAE")[0] == "me-east-1")
    check("a city name resolves", resolves("riyadh")[0] == "me-central-1")
    check("a country name resolves", resolves("brazil")[0] == "sa-east-1")
    check("a name that is one word resolves",
          resolves("singapore")[0] == "ap-southeast-1")

    # ── ambiguity is refused, not guessed ────────────────────────────────
    why = refuses("sa")
    check("an ambiguous prefix is refused", why != "")
    check("the refusal names the candidates and asks for an id",
          "sa-east-1" in why and "me-central-1" in why and "region id" in why)
    why = refuses("china")
    check("two regions in the same country are refused rather than guessed",
          "cn-hangzhou" in why and "cn-beijing" in why)

    # ── nonsense, and nothing at all ─────────────────────────────────────
    why = refuses("atlantis")
    check("an unknown region is refused with the count and some options",
          "6 regions" in why and "Closest" in why)
    rid, note = resolves("")
    check("an empty region falls back and says so",
          rid == REGIONS[0]["id"] and "no region set" in note)

    # with no region list at all — the account could not be read — whatever was
    # typed is used rather than the call being blocked on a lookup that failed
    r, note = cloud.alibaba_resolve_region("me-central-1", [])
    check("no region list does not block the call", r["id"] == "me-central-1")

    # ── the endpoint must come from the region, never the central default ──
    r, _ = cloud.alibaba_resolve_region("SAU", REGIONS)
    check("the region's own endpoint is carried",
          r["endpoint"] == "ecs.me-central-1.aliyuncs.com")

    # ── the sweep: nothing may fail silently ─────────────────────────────
    import app.cloud as cl

    def stub(c, action, version, host, region, extra=None):
        if action == "DescribeRegions":
            return 200, {"Regions": {"Region": [
                {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                 "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
        if action == "DescribeInstances" and host.startswith("ecs"):
            return 200, {"Instances": {"Instance": [
                {"InstanceId": "i-1", "InstanceName": "web", "Status": "Running",
                 "InstanceType": "ecs.c6.large", "ZoneId": "me-central-1a",
                 "VpcAttributes": {"PrivateIpAddress": {"IpAddress": ["10.0.0.5"]}}}]}}
        if action == "DescribeVSwitches":
            return 200, {"VSwitches": {"VSwitch": [
                {"VSwitchId": "vsw-1", "VSwitchName": "private-a",
                 "CidrBlock": "10.0.1.0/24", "Status": "Available",
                 "AvailableIpAddressCount": 252, "VpcId": "vpc-1",
                 "ZoneId": "me-central-1a"}]}}
        if action == "ListUsers":
            raise TimeoutError("The handshake operation timed out")
        if action == "ListRoles":
            return 403, {"Code": "Forbidden", "Message": "not authorized"}
        if action == "QueryAccountBalance":
            if host == "business.aliyuncs.com":
                return 400, {"Code": "InvalidSite", "Message": "auth site failed."}
            return 200, {"Data": {"AvailableAmount": "12.34", "Currency": "USD"}}
        if action == "QueryBillOverview":
            return 200, {"Data": {"Items": {"Item": [
                {"ProductName": "Elastic Compute Service", "ProductCode": "ecs",
                 "PretaxAmount": "336.69", "Currency": "USD",
                 "SubscriptionType": "PayAsYouGo"}]}}}
        return 200, {}

    real = cl._alibaba_rpc
    cl._alibaba_rpc = stub
    cl._ALI_REGIONS.clear()
    try:
        inv = cl._alibaba_inventory({"id": "a1", "key_id": "k", "secret": "s",
                                     "region": "SAU"})
    finally:
        cl._alibaba_rpc = real

    keys = {g["key"]: g for g in inv["groups"]}
    check("subnets are listed, which was the point of asking", "subnets" in keys)
    check("a subnet row carries its CIDR and free addresses",
          keys["subnets"]["rows"][0]["kind"] == "10.0.1.0/24"
          and "252 free IPs" in keys["subnets"]["rows"][0]["extra"])
    notes = " | ".join(inv["notes"])
    check("a product that timed out says so instead of vanishing",
          "RAM users" in notes and "timed out" in notes)
    check("a product refused for permissions says which and why",
          "RAM roles" in notes and "not authorized" in notes
          and "lacks read permission" in notes)
    check("billing falls back to the international host rather than concluding",
          inv["billing"]["host"] == "business.ap-southeast-1.aliyuncs.com")
    check("the balance and the month's total are read",
          inv["billing"]["balance"] == "12.34"
          and inv["billing"]["total"] == "USD 336.69")
    check("spend is a group with its own column labels",
          "billing" in keys and keys["billing"]["columns"][0] == "product")
    check("the region list is offered for switching", len(inv["regions"]) == 1)

    # ── OSS, which signs like S3 rather than speaking RPC ────────────────
    import app.cloud as c2
    seen: list = []

    BUCKETS = """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://doc.oss-cn-hangzhou.aliyuncs.com">
  <Buckets>
    <Bucket><Name>uat-bucket</Name><Location>oss-me-central-1</Location>
      <StorageClass>Standard</StorageClass>
      <ExtranetEndpoint>oss-me-central-1.aliyuncs.com</ExtranetEndpoint></Bucket>
    <Bucket><Name>archive</Name><Location>oss-me-east-1</Location>
      <StorageClass>Archive</StorageClass></Bucket>
  </Buckets>
</ListAllMyBucketsResult>"""

    def oss_stub(url, headers=None, *a, **kw):
        seen.append((url, (headers or {}).get("Authorization", "")))
        if "?stat" in url:
            return 200, ('<BucketStat><Storage>134217728</Storage>'
                         '<ObjectCount>463</ObjectCount>'
                         '<MultipartUploadCount>0</MultipartUploadCount>'
                         '<StandardStorage>134217728</StandardStorage></BucketStat>')
        if "?bucketInfo" in url:
            return 200, ('<BucketInfo><Bucket><CreationDate>2025-12-16T16:53:31.000Z'
                         '</CreationDate><StorageClass>Standard</StorageClass>'
                         '<Versioning>Enabled</Versioning>'
                         '<AccessControlList><Grant>private</Grant>'
                         '</AccessControlList></Bucket></BucketInfo>')
        if "?location" in url:
            return 200, '<LocationConstraint>oss-me-central-1</LocationConstraint>'
        return 200, BUCKETS

    real_get = c2._get
    c2._get = oss_stub
    try:
        rows, why = c2.alibaba_buckets({"key_id": "k", "secret": "s"},
                                       "me-central-1")
        check("buckets are listed", [r["name"] for r in rows] == ["archive", "uat-bucket"])
        check("a bucket in another region is still shown, with its region",
              next(r for r in rows if r["name"] == "archive")["zone"] == "me-east-1")
        check("the storage class comes through",
              next(r for r in rows if r["name"] == "archive")["kind"] == "Archive")
        check("the request is signed the OSS way, not with a Bearer token",
              seen and seen[0][1].startswith("OSS k:"))

        det = c2.alibaba_bucket_detail({"key_id": "k", "secret": "s"},
                                       "uat-bucket", "me-central-1")
        fields = dict(det["fields"])
        check("the size is converted to something readable",
              fields["size (GiB)"] == 0.12)
        check("the object count is read", fields["objects"] == "463")
        check("versioning and the ACL are read",
              fields.get("versioning") == "Enabled" and fields.get("ACL") == "private")
        # the trap that cost a 403: path is "/", the signature covers "/bucket/"
        stat_url = next(u for u, _ in seen if "?stat" in u)
        check("the bucket is addressed in the host, not repeated in the path",
              stat_url.startswith("https://uat-bucket.")
              and "/uat-bucket/?stat" not in stat_url)

        # a refusal explains itself rather than showing an empty bucket list
        def denied(url, headers=None, *a, **kw):
            return 403, ('<Error><Code>AccessDenied</Code>'
                         '<Message>Access denied by bucket policy.</Message></Error>')
        c2._get = denied
        rows, why = c2.alibaba_buckets({"key_id": "k", "secret": "s"}, "me-central-1")
        check("a denied bucket list says so, with the remedy",
              rows == [] and "Access denied" in why and "AliyunOSSReadOnlyAccess" in why)
    finally:
        c2._get = real_get

    # ── a transient failure is retried, not reported as an answer ─────────
    import app.cloud as c3
    # the retry lives inside _get, so urlopen is what has to misbehave
    import urllib.request as _ur
    opened = {"n": 0}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getcode(self):
            return 200

        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout=None):
        opened["n"] += 1
        if opened["n"] == 1:
            raise OSError("[Errno 54] Connection reset by peer")
        return _Resp()

    real_open = _ur.urlopen
    _ur.urlopen = fake_urlopen
    try:
        code, text = c3._get("https://example.invalid/x")
        check("a connection reset is retried and then succeeds",
              code == 200 and opened["n"] == 2)
        # an HTTP error is an answer: it must NOT be retried
        opened["n"] = 0

        def http_error(req, timeout=None):
            opened["n"] += 1
            import urllib.error
            raise urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
        _ur.urlopen = http_error
        try:
            c3._get("https://example.invalid/x")
        except Exception:
            pass
        check("an HTTP error is not retried", opened["n"] == 1)
    finally:
        _ur.urlopen = real_open

    # ── the cache key: peek() and inventory() must agree ─────────────────
    check("the cache key includes the region",
          c3._inv_key({"id": "a"}, "me-central-1") != c3._inv_key({"id": "a"}, ""))
    c3._inv.clear()
    c3._inv[c3._inv_key({"id": "a"}, "")] = (time.time(), {"groups": [], "total": 0})
    check("peek finds what inventory stored — it did not, once",
          c3.peek({"id": "a"}) is not None)

    # ── a product that is switched off is not a permission problem ───────
    why = c3._ali_why({"Message": "Your account does not open Nas Service yet."},
                      400)
    check("a disabled product says so, not 'lacks permission'",
          "not enabled on the account" in why and "lacks read" not in why)

    # ── exposure, the one security number worth a tile ───────────────────
    def sg_stub(conn, action, version, host, region, extra=None):
        if action == "DescribeSecurityGroupAttribute":
            sg = (extra or {}).get("SecurityGroupId")
            rules = {
                "sg-open": [{"Direction": "ingress", "SourceCidrIp": "0.0.0.0/0",
                             "IpProtocol": "TCP", "PortRange": "22/22",
                             "Policy": "Accept"},
                            {"Direction": "ingress", "SourceCidrIp": "10.0.0.0/8",
                             "IpProtocol": "TCP", "PortRange": "443/443",
                             "Policy": "Accept"}],
                "sg-shut": [{"Direction": "ingress", "SourceCidrIp": "10.0.0.0/8",
                             "IpProtocol": "TCP", "PortRange": "443/443",
                             "Policy": "Accept"}],
                # a drop rule to 0.0.0.0/0 is not an opening, and an egress rule
                # to the world is normal
                "sg-drop": [{"Direction": "ingress", "SourceCidrIp": "0.0.0.0/0",
                             "IpProtocol": "TCP", "PortRange": "22/22",
                             "Policy": "Drop"},
                            {"Direction": "egress", "SourceCidrIp": "0.0.0.0/0",
                             "IpProtocol": "ALL", "PortRange": "-1/-1",
                             "Policy": "Accept"}],
            }.get(sg, [])
            return 200, {"Permissions": {"Permission": rules}}
        return 200, {}

    real2 = c3._alibaba_rpc
    c3._alibaba_rpc = sg_stub
    try:
        notes = []
        groups = [{"key": "secgroups", "rows": [
            {"id": "sg-open", "name": "vpn"}, {"id": "sg-shut", "name": "internal"},
            {"id": "sg-drop", "name": "denied"}]}]
        sec = c3._alibaba_exposure({"key_id": "k", "secret": "s"}, groups,
                                   "me-central-1", notes)
        check("a rule open to the world is counted", sec["open_rules"] == 1)
        check("only the group that has one is counted", sec["open_groups"] == 1)
        check("the rule is named so it can be found",
              sec["worst"] and "vpn" in sec["worst"][0] and "22/22" in sec["worst"][0])
        check("a drop rule to 0.0.0.0/0 is not an opening",
              not any("denied" in w for w in sec["worst"]))
        check("an egress rule to the world is not an opening",
              sec["open_rules"] == 1)
        check("how many groups were looked at is reported",
              sec["checked"] == 3 and sec["total"] == 3 and not sec["capped"])

        # a big estate is capped, and says so rather than pretending to be whole
        many = [{"key": "secgroups",
                 "rows": [{"id": f"sg-{i}", "name": f"g{i}"} for i in range(30)]}]
        notes = []
        sec = c3._alibaba_exposure({"key_id": "k", "secret": "s"}, many,
                                   "me-central-1", notes)
        check("a large estate is capped", sec["capped"]
              and sec["checked"] == c3.EXPOSURE_CAP)
        check("the cap is stated in the notes, not hidden",
              any("of 30 security groups" in n for n in notes))
    finally:
        c3._alibaba_rpc = real2

    # ── a checker must not add the verdict prefix its caller adds ────────
    import inspect
    for mod_name in ("cloud", "stordev"):
        mod = __import__(f"app.{mod_name}", fromlist=["x"])
        src = inspect.getsource(mod)
        check(f"app/{mod_name}.py does not return its own 'ok:' prefix",
              'return True, "ok: ' not in src and "return True, f\"ok: " not in src)

    # ── the search index: the words people actually type ─────────────────
    from app import main as app_main
    inv = {"region": "me-central-1", "groups": [
        {"key": "compute", "label": "ECS instances", "icon": "🖥", "rows": [
            {"id": "i-1", "name": "vpn-server", "kind": "ecs.t6",
             "extra": "10.0.1.250", "state": "Running"}]},
        {"key": "ram_users", "label": "RAM users", "icon": "👤", "rows": [
            {"id": "211", "name": "devops-portal", "kind": "", "extra": ""}]},
        {"key": "oss", "label": "OSS buckets", "icon": "🪣", "rows": [
            {"id": "uat-bucket", "name": "uat-bucket", "kind": "Standard",
             "extra": ""}]},
        {"key": "billing", "label": "Spend", "icon": "💳", "rows": [{"name": "ECS"}]},
    ]}
    idx = app_main._cloud_search({"id": "acc-1"}, inv)
    by_label = {e["label"]: e for e in idx}
    check("the bills page is reachable from search", "Bills" in by_label)
    check("every service is in the index",
          {"ECS instances", "RAM users", "OSS buckets"} <= set(by_label))
    check("the billing group is not offered twice — Bills covers it",
          "Spend" not in by_label)
    check("console words are attached, not just the portal's labels",
          "ecs" in by_label["ECS instances"]["words"]
          and "iam" in by_label["RAM users"]["words"]
          and "s3" in by_label["OSS buckets"]["words"])
    check("a resource is reachable directly", "vpn-server" in by_label)
    check("a resource's address is searchable through its subtitle",
          "10.0.1.250" in by_label["vpn-server"]["sub"])
    check("an instance links to its own page",
          by_label["vpn-server"]["url"]
          == "/clouds/r/acc-1/compute/i-1?region=me-central-1")
    check("a RAM user is keyed by name, which is what its API takes",
          by_label["devops-portal"]["url"].endswith("/ram_users/devops-portal"
                                                    "?region=me-central-1"))
    check("a bucket is keyed by name too",
          by_label["uat-bucket"]["url"].endswith("/oss/uat-bucket"
                                                 "?region=me-central-1"))
    check("a service entry says how many are in it",
          by_label["ECS instances"]["sub"] == "1 in me-central-1")
    check("every entry can be jumped to",
          all(e["url"].startswith("/clouds/") for e in idx))

    # ── the container registry: two steps, not one ───────────────────────
    def reg_stub(c, action, version, host, region, extra=None):
        if action == "DescribeRegions":
            return 200, {"Regions": {"Region": [
                {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                 "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
        if action == "ListInstance":
            return 200, {"TotalCount": 1, "Instances": [
                {"InstanceId": "cri-1", "InstanceName": "prod-registry"}]}
        if action == "ListRepository":
            if not (extra or {}).get("InstanceId"):
                return 400, {"Code": "MissingInstanceId",
                             "Message": "InstanceId is mandatory for this action."}
            return 200, {"TotalCount": 2, "Repositories": [
                {"RepoNamespaceName": "uat", "RepoName": "api",
                 "RepoType": "PRIVATE", "RepoStatus": "NORMAL",
                 "InstanceId": "cri-1", "ModifiedTime": 1770000000000},
                {"RepoNamespaceName": "uat", "RepoName": "web",
                 "RepoType": "PRIVATE", "RepoStatus": "NORMAL",
                 "InstanceId": "cri-1", "ModifiedTime": 1770000000000}]}
        if action == "QueryAccountBalance":
            return 200, {"Data": {"AvailableAmount": "12.00", "Currency": "USD",
                                  "CreditAmount": "500.00"}}
        if action == "QuerySettleBill":
            return 200, {"Data": {"Items": {"Item": [
                {"ProductName": "Elastic Compute Service", "Status": "PayUnsettle",
                 "PaymentAmount": 0.0, "OutstandingAmount": 338.09,
                 "Currency": "USD", "PaymentTime": ""},
                {"ProductName": "Object Storage Service", "Status": "PayFinish",
                 "PaymentAmount": 4.20, "OutstandingAmount": 0.0,
                 "Currency": "USD", "PaymentTime": "2026-07-02 08:11:00"},
                {"ProductName": "Nothing At All", "Status": "PayFinish",
                 "PaymentAmount": 0.0, "OutstandingAmount": 0.0,
                 "Currency": "USD", "PaymentTime": ""}]}}}
        return 200, {}

    real3 = c3._alibaba_rpc
    c3._alibaba_rpc = reg_stub
    c3._ALI_REGIONS.clear()
    try:
        rows, why = c3.alibaba_registry({"key_id": "K", "secret": "S"},
                                        "me-central-1")
        check("repositories are read from under their instance",
              [r["name"] for r in rows] == ["uat/api", "uat/web"] and not why)
        check("a namespace and a name are joined the way the registry joins them",
              rows[0]["name"] == "uat/api")

        # an account with no registry says where to look instead of nothing
        def no_instances(c, action, version, host, region, extra=None):
            if action == "ListInstance":
                return 200, {"TotalCount": 0, "Instances": []}
            return reg_stub(c, action, version, host, region, extra)
        c3._alibaba_rpc = no_instances
        rows, why = c3.alibaba_registry({"key_id": "K", "secret": "S"},
                                        "me-central-1")
        check("no registry in this region is explained, not left blank",
              rows == [] and "per region" in why)

        # ── payments ────────────────────────────────────────────────────
        c3._alibaba_rpc = reg_stub
        c3._ALI_REGIONS.clear()
        pay = c3.payments({"id": "a", "type": "alibaba", "key_id": "K",
                           "secret": "S"})
        check("the balance and credit limit are read",
              pay["balance"] == "12.00" and pay["credit"] == "500.00")
        check("what is outstanding is added up", pay["outstanding"] == 338.09)
        check("what has settled is added up too", pay["settled"] == 4.2)
        check("a line with no money either way is left out",
              all(r["product"] != "Nothing At All" for r in pay["rows"]))
        check("the unsettled line comes first", pay["rows"][0]["outstanding"] > 0)
        check("a paid line carries when it was paid",
              any(r["when"].startswith("2026-07-02") for r in pay["rows"]))
        check("payment methods are not claimed to be editable",
              pay["manageable"] is False)
        check("one link is offered, to the billing console",
              [l for l, _u, _w in pay["consoles"]] == ["Billing overview"]
              and pay["consoles"][0][1] == "https://billing.console.aliyun.com/")
    finally:
        c3._alibaba_rpc = real3
        c3._ALI_REGIONS.clear()

    # ── a script must come after the elements it looks for ───────────────
    # The search box did nothing because its script had been appended to the
    # first {% endblock %} in the file — the crumbs block — so it ran before the
    # input existed, found nothing, and returned silently. No error anywhere.
    #
    # Only a lookup in a script's prologue is checked: one at the top level runs
    # immediately, while a lookup inside a function or an inline onchange= runs
    # when something happens, by which time the page is built.
    import re as _re
    for tpl in sorted(pathlib.Path("templates").glob("*.html")):
        text = tpl.read_text()
        for block in _re.finditer(r"<script>(.*?)</script>", text, _re.S):
            body, at = block.group(1), block.start(1)
            # an immediately-invoked wrapper is not "inside a function" for this
            # purpose — its body runs at once, which is the whole point of it.
            # Missing that made the check pass while the bug was still there.
            head = _re.match(r"\s*\(\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{",
                             body)
            offset = head.end() if head else 0
            rest = body[offset:]
            cut = min([m.start() for m in
                       _re.finditer(r"\bfunction\b|addEventListener|=>", rest)]
                      or [len(rest)])
            body, at = rest, at + offset
            for m in _re.finditer(
                    r"getElementById\(['\"]([A-Za-z0-9_-]+)['\"]\)",
                    body[:cut]):
                ident = m.group(1)
                decl = text.find(f'id="{ident}"')
                if decl == -1:
                    continue              # declared in base.html, not here
                check(f"{tpl.name}: #{ident} exists before the script that reads it",
                      decl < at + m.start())

    # ── the network going away must not read as an empty account ─────────
    # "0 resources" next to a raw URLError says the account is empty. It was one
    # failed call: the region list, which everything else depends on.
    import urllib.error as _ue
    import urllib.request as _ur

    ACCT = {"id": "net-1", "type": "alibaba", "key_id": "K", "secret": "S",
            "region": "SAU", "name": "Net Test"}

    def no_dns(req, timeout=None):
        raise _ue.URLError("<urlopen error [Errno 8] nodename nor servname "
                           "provided, or not known>")

    real_open = _ur.urlopen
    try:
        # nothing known, and the region is written as a name: one clear sentence
        c3.invalidate(); c3._ALI_REGIONS.clear(); c3._LAST_REGION.clear()
        _ur.urlopen = no_dns
        got = c3.inventory(ACCT)
        _ur.urlopen = real_open
        check("a failed region list does not raise to the page",
              not got.get("error"))
        check("it is explained in one note, not twenty-two",
              len(got["notes"]) == 1)
        check("the note says what to check and what the region should look like",
              "region list could not be read" in got["notes"][0]
              and "me-central-1" in got["notes"][0])

        # a region that worked before is used rather than guessed at
        c3.invalidate(); c3._ALI_REGIONS.clear()
        c3._LAST_REGION["K"] = "me-central-1"
        _ur.urlopen = no_dns
        got = c3.inventory(ACCT)
        _ur.urlopen = real_open
        check("a remembered region is reused", got["region"] == "me-central-1")
        check("reusing it is stated", any("worked last time" in n
                                         for n in got["notes"]))
        check("products failing the same way are folded into one note",
              any("products could not be read" in n for n in got["notes"]))
        check("the raw exception spelling is not shown",
              not any("URLError" in n for n in got["notes"]
                      if "products could not be read" in n))

        # a good result must not be replaced by an empty one
        c3.invalidate(); c3._ALI_REGIONS.clear(); c3._LAST_REGION.clear()
        c3._inv[c3._inv_key(ACCT, "")] = (time.time() - 5, {
            "groups": [{"key": "compute", "label": "ECS instances", "icon": "🖥",
                        "rows": [{"id": "i-1", "name": "web"}]}],
            "notes": [], "region": "me-central-1", "total": 1, "billing": {},
            "security": {}})
        c3._LAST_REGION["K"] = "me-central-1"
        _ur.urlopen = no_dns
        got = c3.inventory(ACCT, refresh=True)
        _ur.urlopen = real_open
        check("what was known is kept rather than blanked", got["total"] == 1)
        check("and it is marked as old", got.get("stale_for", 0) >= 5)
        check("with the failure carried alongside it",
              any("could not be read" in n for n in got["notes"]))
    finally:
        _ur.urlopen = real_open
        c3.invalidate(); c3._ALI_REGIONS.clear(); c3._LAST_REGION.clear()

    # ── a resolved region is kept, so a restart cannot lose it ───────────
    # It was remembered in memory only, and the dev server restarts on every
    # save — so the next page load had no region list, no memory, and a name
    # rather than an id, and reported an account with nothing in it.
    saved: dict = {}

    def fake_update(kind, pid, cid, **fields):
        saved[cid] = fields

    def region_only(c, action, version, host, region, extra=None):
        if action == "DescribeRegions":
            return 200, {"Regions": {"Region": [
                {"RegionId": "me-central-1", "LocalName": "SAU (Riyadh)",
                 "RegionEndpoint": "ecs.me-central-1.aliyuncs.com"}]}}
        return 403, {"Code": "Forbidden", "Message": "not authorized"}

    from app import store as real_store_mod
    real_rpc = c3._alibaba_rpc
    real_update = real_store_mod.update_conn
    c3._alibaba_rpc = region_only
    real_store_mod.update_conn = fake_update
    try:
        c3.invalidate(); c3._ALI_REGIONS.clear(); c3._LAST_REGION.clear()
        got = c3._alibaba_inventory({"id": "acct-9", "pid": "", "key_id": "K",
                                     "secret": "S", "region": "SAU",
                                     "type": "alibaba"})
        check("a name is resolved to an id", got["region"] == "me-central-1")
        check("and written back, so it is worked out once ever",
              saved.get("acct-9", {}).get("region") == "me-central-1")
        check("the page says it was saved",
              any("saved" in n for n in got["notes"]))
    finally:
        c3._alibaba_rpc = real_rpc
        real_store_mod.update_conn = real_update
        c3.invalidate(); c3._ALI_REGIONS.clear(); c3._LAST_REGION.clear()

    check("a DNS failure counts as transient and is retried",
          any("nodename" in t or "getaddrinfo" in t for t in c3.TRANSIENT))
    check("a readable failure names the cause, not the exception class",
          "would not resolve" in c3._readable_failure(
              _ue.URLError("[Errno 8] nodename nor servname provided")))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
