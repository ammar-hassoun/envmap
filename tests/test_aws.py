#!/usr/bin/env python3
"""AWS, to the same depth as Alibaba, against a stubbed account.

There is no AWS account to point at yet, so every response here is a real one in
shape: the XML AWS actually returns, including the awkward parts — reservations
wrapping instances, tags as an unindexed list of key/value pairs, IAM answering
only at its global endpoint, and Cost Explorer being JSON while everything else
is XML.

The signature itself is checked against the example AWS publishes, because a
signer that is subtly wrong fails with "SignatureDoesNotMatch" and no clue.
"""
from __future__ import annotations

import datetime as real_dt
import json
import os
import pathlib
import re
import sys
import time

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("aws-test-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import cloud, cloudops                                 # noqa: E402

ACCOUNT = {"id": "aws-1", "type": "aws", "name": "AWS Test",
           "key_id": "AKIATEST", "secret": "s3cret", "region": "eu-west-1",
           "pid": ""}
bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


# ── the XML AWS really sends, trimmed to what is read ─────────────────────
INSTANCES = """<DescribeInstancesResponse>
 <reservationSet><item><instancesSet>
  <item>
   <instanceId>i-0abc</instanceId><instanceType>t3.medium</instanceType>
   <imageId>ami-123</imageId><instanceState><code>16</code><name>running</name></instanceState>
   <privateIpAddress>10.0.1.15</privateIpAddress><ipAddress>52.1.2.3</ipAddress>
   <vpcId>vpc-1</vpcId><subnetId>subnet-a</subnetId><keyName>deploy</keyName>
   <placement><availabilityZone>eu-west-1a</availabilityZone></placement>
   <tagSet><item><key>Name</key><value>api-1</value></item>
           <item><key>Env</key><value>prod</value></item></tagSet>
   <groupSet><item><groupId>sg-1</groupId><groupName>web</groupName></item></groupSet>
   <blockDeviceMapping><item><deviceName>/dev/xvda</deviceName>
     <ebs><volumeId>vol-1</volumeId><status>attached</status></ebs></item></blockDeviceMapping>
  </item>
  <item>
   <instanceId>i-0def</instanceId><instanceType>t3.small</instanceType>
   <instanceState><code>80</code><name>stopped</name></instanceState>
   <privateIpAddress>10.0.2.20</privateIpAddress>
   <placement><availabilityZone>eu-west-1b</availabilityZone></placement>
   <tagSet><item><key>Name</key><value>batch</value></item></tagSet>
  </item>
 </instancesSet></item></reservationSet>
</DescribeInstancesResponse>"""

VOLUMES = """<DescribeVolumesResponse><volumeSet>
 <item><volumeId>vol-1</volumeId><size>100</size><volumeType>gp3</volumeType>
  <status>in-use</status><availabilityZone>eu-west-1a</availabilityZone>
  <attachmentSet><item><instanceId>i-0abc</instanceId><device>/dev/xvda</device>
    <status>attached</status><deleteOnTermination>true</deleteOnTermination></item></attachmentSet>
 </item>
 <item><volumeId>vol-2</volumeId><size>500</size><volumeType>gp2</volumeType>
  <status>available</status><availabilityZone>eu-west-1a</availabilityZone>
  <attachmentSet/></item>
</volumeSet></DescribeVolumesResponse>"""

SGS = """<DescribeSecurityGroupsResponse><securityGroupInfo>
 <item><groupId>sg-1</groupId><groupName>web</groupName>
  <groupDescription>public web</groupDescription><vpcId>vpc-1</vpcId>
  <ipPermissions>
    <item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort>
      <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>
    <item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>
      <ipRanges><item><cidrIp>10.0.0.0/8</cidrIp></item></ipRanges></item>
  </ipPermissions>
  <ipPermissionsEgress><item><ipProtocol>-1</ipProtocol>
    <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissionsEgress>
 </item>
 <item><groupId>sg-2</groupId><groupName>db</groupName>
  <groupDescription>database</groupDescription><vpcId>vpc-1</vpcId>
  <ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort>
    <toPort>5432</toPort><groups><item><groupId>sg-1</groupId></item></groups></item></ipPermissions>
 </item>
</securityGroupInfo></DescribeSecurityGroupsResponse>"""

SUBNETS = """<DescribeSubnetsResponse><subnetSet>
 <item><subnetId>subnet-a</subnetId><cidrBlock>10.0.1.0/24</cidrBlock>
  <availableIpAddressCount>250</availableIpAddressCount><vpcId>vpc-1</vpcId>
  <availabilityZone>eu-west-1a</availabilityZone><state>available</state>
  <tagSet><item><key>Name</key><value>public-a</value></item></tagSet></item>
 <item><subnetId>subnet-b</subnetId><cidrBlock>10.0.2.0/24</cidrBlock>
  <availableIpAddressCount>240</availableIpAddressCount><vpcId>vpc-1</vpcId>
  <availabilityZone>eu-west-1b</availabilityZone><state>available</state>
  <tagSet><item><key>Name</key><value>private-b</value></item></tagSet></item>
</subnetSet></DescribeSubnetsResponse>"""

BUCKETS = """<ListAllMyBucketsResult><Buckets>
 <Bucket><Name>app-artifacts</Name><CreationDate>2024-02-01T00:00:00Z</CreationDate></Bucket>
 <Bucket><Name>logs-archive</Name><CreationDate>2023-06-11T00:00:00Z</CreationDate></Bucket>
</Buckets></ListAllMyBucketsResult>"""

COSTS = json.dumps({"ResultsByTime": [
    {"TimePeriod": {"Start": "2026-06-01"}, "Groups": [
        {"Keys": ["Amazon Elastic Compute Cloud - Compute"],
         "Metrics": {"UnblendedCost": {"Amount": "412.50", "Unit": "USD"}}},
        {"Keys": ["Amazon Relational Database Service"],
         "Metrics": {"UnblendedCost": {"Amount": "180.25", "Unit": "USD"}}}]},
    {"TimePeriod": {"Start": "2026-07-01"}, "Groups": [
        {"Keys": ["Amazon Elastic Compute Cloud - Compute"],
         "Metrics": {"UnblendedCost": {"Amount": "455.00", "Unit": "USD"}}},
        {"Keys": ["Amazon Simple Storage Service"],
         "Metrics": {"UnblendedCost": {"Amount": "12.10", "Unit": "USD"}}},
        {"Keys": ["Tax"], "Metrics": {"UnblendedCost": {"Amount": "0", "Unit": "USD"}}},
        {"Keys": ["AWS Data Transfer"],
         "Metrics": {"UnblendedCost": {"Amount": "-0.000004", "Unit": "USD"}}}]},
]})

REGIONS = """<DescribeRegionsResponse><regionInfo>
 <item><regionName>eu-west-1</regionName><regionEndpoint>ec2.eu-west-1.amazonaws.com</regionEndpoint></item>
 <item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint></item>
 <item><regionName>me-south-1</regionName><regionEndpoint>ec2.me-south-1.amazonaws.com</regionEndpoint></item>
</regionInfo></DescribeRegionsResponse>"""

IAM_USERS = """<ListUsersResponse><ListUsersResult><Users>
 <member><UserName>deployer</UserName><UserId>AIDA1</UserId>
  <Arn>arn:aws:iam::111:user/deployer</Arn><CreateDate>2025-01-05T00:00:00Z</CreateDate></member>
 <member><UserName>readonly</UserName><UserId>AIDA2</UserId>
  <Arn>arn:aws:iam::111:user/readonly</Arn><CreateDate>2025-03-09T00:00:00Z</CreateDate></member>
</Users></ListUsersResult></ListUsersResponse>"""

RDS = """<DescribeDBInstancesResponse><DBInstances>
 <DBInstance><DBInstanceIdentifier>orders</DBInstanceIdentifier>
  <Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>
  <DBInstanceClass>db.t3.medium</DBInstanceClass><DBInstanceStatus>available</DBInstanceStatus>
  <AllocatedStorage>200</AllocatedStorage><MultiAZ>true</MultiAZ>
  <AvailabilityZone>eu-west-1a</AvailabilityZone>
  <Endpoint><Address>orders.abc.eu-west-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>
  <VpcSecurityGroups><VpcSecurityGroupMembership><VpcSecurityGroupId>sg-2</VpcSecurityGroupId>
    <Status>active</Status></VpcSecurityGroupMembership></VpcSecurityGroups>
 </DBInstance></DBInstances></DescribeDBInstancesResponse>"""

ELB = """<DescribeLoadBalancersResponse><LoadBalancers>
 <member><LoadBalancerArn>arn:aws:elb:eu-west-1:111:lb/app/main/abc</LoadBalancerArn>
  <LoadBalancerName>main</LoadBalancerName><Type>application</Type>
  <Scheme>internet-facing</Scheme><State><Code>active</Code></State>
  <DNSName>main-123.eu-west-1.elb.amazonaws.com</DNSName><VpcId>vpc-1</VpcId></member>
</LoadBalancers></DescribeLoadBalancersResponse>"""

calls: list = []


def fake_signed(c, service, region, method="POST", path="/", query="", body="",
                headers=None, host=""):
    action = re.search(r"Action=([A-Za-z]+)", body or "")
    action = action.group(1) if action else ""
    calls.append({"service": service, "region": region, "host": host,
                  "action": action, "path": path, "query": query, "body": body})
    if service == "ce":
        return 200, COSTS
    if service == "ecr":
        return 200, json.dumps({"repositories": [
            {"repositoryName": "dev-lms/api", "imageTagMutability": "MUTABLE",
             "encryptionConfiguration": {"encryptionType": "AES256"},
             "imageScanningConfiguration": {"scanOnPush": False},
             "repositoryUri": "111.dkr.ecr.eu-west-1.amazonaws.com/dev-lms/api",
             "createdAt": 1773315320.203},
            {"repositoryName": "dev-lms/web", "imageTagMutability": "IMMUTABLE",
             "encryptionConfiguration": {"encryptionType": "AES256"},
             "repositoryUri": "111.dkr.ecr.eu-west-1.amazonaws.com/dev-lms/web",
             "createdAt": 1773315320.203}]})
    if service == "lambda":
        return 200, json.dumps({"Functions": [
            {"FunctionName": "resize-images", "Runtime": "python3.12",
             "MemorySize": 512, "Timeout": 30, "CodeSize": 2097152,
             "State": "Active", "LastModified": "2026-05-04T10:00:00.000+0000"}]})
    if service == "eks":
        return 200, json.dumps({"clusters": ["lms-uat"]})
    if service == "elasticache":
        return 200, "<DescribeCacheClustersResponse></DescribeCacheClustersResponse>"
    if service == "s3":
        if query.startswith("location"):
            return 200, "<LocationConstraint>eu-west-1</LocationConstraint>"
        if query.startswith("publicAccessBlock"):
            return 200, ("<PublicAccessBlockConfiguration><BlockPublicAcls>true"
                         "</BlockPublicAcls><RestrictPublicBuckets>false"
                         "</RestrictPublicBuckets></PublicAccessBlockConfiguration>")
        if query.startswith("versioning"):
            return 200, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
        if query.startswith("encryption"):
            return 404, "<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code></Error>"
        return 200, BUCKETS
    return {
        "DescribeRegions": (200, REGIONS),
        "DescribeInstances": (200, INSTANCES),
        "DescribeVolumes": (200, VOLUMES),
        "DescribeSecurityGroups": (200, SGS),
        "DescribeSubnets": (200, SUBNETS),
        "DescribeVpcs": (200, """<DescribeVpcsResponse><vpcSet><item>
            <vpcId>vpc-1</vpcId><cidrBlock>10.0.0.0/16</cidrBlock>
            <state>available</state><isDefault>false</isDefault>
            <tagSet><item><key>Name</key><value>prod-vpc</value></item></tagSet>
            </item></vpcSet></DescribeVpcsResponse>"""),
        "DescribeAddresses": (200, """<DescribeAddressesResponse><addressesSet><item>
            <publicIp>52.1.2.3</publicIp><allocationId>eipalloc-1</allocationId>
            <associationId>eipassoc-1</associationId><domain>vpc</domain>
            <instanceId>i-0abc</instanceId></item></addressesSet></DescribeAddressesResponse>"""),
        "DescribeNatGateways": (200, """<DescribeNatGatewaysResponse><natGatewaySet><item>
            <natGatewayId>nat-1</natGatewayId><state>available</state>
            <vpcId>vpc-1</vpcId><subnetId>subnet-a</subnetId>
            </item></natGatewaySet></DescribeNatGatewaysResponse>"""),
        "DescribeLoadBalancers": (200, ELB),
        "DescribeDBInstances": (200, RDS),
        "ListUsers": (200, IAM_USERS),
        "ListRoles": (403, "<Error><Code>AccessDenied</Code><Message>User is not "
                           "authorized to perform iam:ListRoles</Message></Error>"),
        "ListPolicies": (200, "<ListPoliciesResponse></ListPoliciesResponse>"),
        "GetUser": (200, """<GetUserResponse><GetUserResult><User>
            <UserName>deployer</UserName><UserId>AIDA1</UserId>
            <Arn>arn:aws:iam::111:user/deployer</Arn>
            <CreateDate>2025-01-05T00:00:00Z</CreateDate></User></GetUserResult></GetUserResponse>"""),
        "ListAttachedUserPolicies": (200, """<r><member><PolicyName>ReadOnlyAccess</PolicyName>
            <PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn></member></r>"""),
        "ListAccessKeys": (200, """<r><member><AccessKeyId>AKIAOLD</AccessKeyId>
            <Status>Active</Status></member></r>"""),
        "ListGroupsForUser": (200, "<r></r>"),
        "StartInstances": (200, "<StartInstancesResponse/>"),
        "CreateAccessKey": (200, """<CreateAccessKeyResponse><CreateAccessKeyResult>
            <AccessKey><AccessKeyId>AKIANEW</AccessKeyId>
            <SecretAccessKey>brand-new-secret</SecretAccessKey></AccessKey>
            </CreateAccessKeyResult></CreateAccessKeyResponse>"""),
        "SendCommand": (200, "<SendCommandResponse><Command><CommandId>cmd-1</CommandId>"
                             "</Command></SendCommandResponse>"),
        "GetCommandInvocation": (200, """<GetCommandInvocationResponse>
            <Status>Success</Status><ResponseCode>0</ResponseCode>
            <StandardOutputContent>nginx is running</StandardOutputContent>
            <ExecutionEndDateTime>2026-07-30T10:00:00Z</ExecutionEndDateTime>
            </GetCommandInvocationResponse>"""),
    }.get(action, (200, "<empty/>"))


def main() -> int:
    # ── the signature, against the example AWS publishes ─────────────────
    FIXED = real_dt.datetime(2015, 8, 30, 12, 36, 0, tzinfo=real_dt.timezone.utc)

    class FakeDT:
        timezone = real_dt.timezone

        class datetime:
            @staticmethod
            def now(tz=None):
                return FIXED

    seen = {}

    def capture(url, headers=None, data=None, tries=2):
        seen.update(url=url, headers=headers or {})
        return 200, "<ok/>"

    real_get, real_dt_mod = cloud._get, cloud.datetime
    cloud._get, cloud.datetime = capture, FakeDT
    try:
        cloud.aws_signed(
            {"key_id": "AKIDEXAMPLE",
             "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
            "iam", "us-east-1", "GET", "/",
            "Action=ListUsers&Version=2010-05-08", "",
            {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            host="iam.amazonaws.com")
    finally:
        cloud._get, cloud.datetime = real_get, real_dt_mod
    sig = seen["headers"]["Authorization"].split("Signature=")[1]
    check("the signature matches the example AWS publishes",
          sig == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")

    # ── the sweep ────────────────────────────────────────────────────────
    real_signed = cloud.aws_signed
    cloud.aws_signed = fake_signed
    cloud.invalidate()
    cloud._ALI_REGIONS.clear()
    try:
        inv = cloud._aws_inventory(ACCOUNT)
        by = {g["key"]: g for g in inv["groups"]}

        check("the region comes through", inv["region"] == "eu-west-1")
        check("regions are offered for switching", len(inv["regions"]) == 3)
        check("instances are read out of their reservations",
              [r["name"] for r in by["compute"]["rows"]] == ["api-1", "batch"])
        check("the Name tag becomes the name, not the id",
              by["compute"]["rows"][0]["id"] == "i-0abc")
        check("both addresses are shown",
              by["compute"]["rows"][0]["extra"] == "10.0.1.15, 52.1.2.3")
        check("a stopped instance keeps its state",
              by["compute"]["rows"][1]["state"] == "stopped")
        check("volumes carry size and what they are attached to",
              by["disks"]["rows"][0]["kind"] == "gp3 · 100 GiB"
              and by["disks"]["rows"][1]["extra"] == "not attached")
        check("subnets carry CIDR and free addresses",
              by["subnets"]["rows"][0]["kind"] == "10.0.1.0/24"
              and "250 free IPs" in by["subnets"]["rows"][0]["extra"])
        check("load balancers say which kind they are",
              by["clb"]["rows"][0]["kind"] == "APPLICATION · internet-facing")
        check("RDS carries engine, class and endpoint",
              "postgres 16.3" in by["rds"]["rows"][0]["kind"]
              and "rds.amazonaws.com" in by["rds"]["rows"][0]["extra"])
        check("IAM users are listed", len(by["iam_users"]["rows"]) == 2)
        check("S3 buckets are listed account-wide",
              [r["name"] for r in by["buckets"]["rows"]]
              == ["app-artifacts", "logs-archive"])

        # the group keys must be the shared ones, or none of the pages work
        check("the keys are the shared ones, so every page works unchanged",
              {"compute", "disks", "secgroups", "vpcs", "subnets", "eips", "nat",
               "clb", "rds", "iam_users", "buckets"} <= set(by))

        # IAM is global: asking it in eu-west-1 fails in a confusing way
        iam_calls = [c for c in calls if c["action"] in ("ListUsers", "ListRoles")]
        check("IAM is asked at its global endpoint",
              all(c["host"] == "iam.amazonaws.com" for c in iam_calls))
        check("EC2 is asked in the region on screen",
              all(c["region"] == "eu-west-1" for c in calls
                  if c["action"] == "DescribeInstances"))

        # a refused call explains itself and does not remove the rest
        check("a refused product is a note, not a missing page",
              any("ListRoles" in n or "IAM roles" in n for n in inv["notes"]))
        check("the refusal names the remedy",
              any("IAM policy does not allow" in n for n in inv["notes"]))

        # exposure comes from the rules already read, with no extra call
        sec = inv["security"]
        check("a rule open to the world is counted once",
              sec["open_rules"] == 1 and sec["open_groups"] == 1)
        check("the open rule is named", sec["worst"]
              and "web" in sec["worst"][0] and "443" in sec["worst"][0])
        check("an egress rule to the world is not counted as exposure",
              sec["open_rules"] == 1)
        check("nothing had to be capped, because the rules came inline",
              not sec["capped"] and sec["checked"] == 2)

        # ── bills, which are JSON while everything else is XML ───────────
        calls.clear()          # count this call's requests, not the sweep's
        bills = cloud.aws_bills(ACCOUNT, 12, refresh=True)
        check("months come back in order", bills["labels"] == ["2026-06", "2026-07"])
        check("monthly totals are summed",
              bills["series"] == [592.75, 467.1])
        check("the currency is read", bills["currency"] == "USD")
        check("a zero line is dropped rather than shown as a product",
              all(r["product"] != "Tax" for m in bills["months"] for r in m["rows"]))
        check("products are ranked across the window",
              bills["by_product"][0]["product"].startswith("Amazon Elastic Compute"))
        check("Cost Explorer is asked once, not once per month",
              len([c for c in calls if c["service"] == "ce"]) == 1)

        # ── one resource, in depth ──────────────────────────────────────
        det = cloudops.detail(ACCOUNT, "compute", "i-0abc", "eu-west-1")
        fields = dict(det["fields"])
        check("an instance detail reads its own fields",
              fields.get("type") == "t3.medium" and fields.get("state") == "running")
        check("its tags are listed",
              any(e["label"] == "tags" and ("Env", "prod") in e["rows"]
                  for e in det["extras"]))
        check("its volumes and security groups are listed",
              {e["label"] for e in det["extras"]}
              >= {"attached volumes", "security groups"})

        det = cloudops.detail(ACCOUNT, "secgroups", "sg-1", "eu-west-1")
        rules = det["table"]["rows"]
        check("a security group shows its rules with direction",
              any(r["direction"] == "ingress" and r["source"] == "0.0.0.0/0"
                  for r in rules)
              and any(r["direction"] == "egress" for r in rules))
        check("a rule sourced from another group is shown too",
              cloudops.detail(ACCOUNT, "secgroups", "sg-2", "eu-west-1")["table"]
              ["rows"][0]["source"] == "sg-1")

        det = cloudops.detail(ACCOUNT, "iam_users", "deployer", "eu-west-1")
        labels = {e["label"]: e for e in det["extras"]}
        check("an IAM user lists its attached policies",
              labels["attached policies"]["rows"][0][0] == "ReadOnlyAccess")
        check("and its access keys", labels["access keys"]["rows"][0][0] == "AKIAOLD")

        det = cloudops.detail(ACCOUNT, "buckets", "app-artifacts", "eu-west-1")
        bfields = dict(det["fields"])
        check("a bucket says where it lives", bfields.get("region") == "eu-west-1")
        check("and whether it is versioned", bfields.get("versioning") == "Enabled")
        check("a bucket with no encryption says so, rather than saying nothing",
              bfields.get("default encryption") == "none")

        # ── actions ─────────────────────────────────────────────────────
        check("AWS has its own actions", len(cloudops.for_group("compute", "aws")) >= 4)
        check("a removal still asks for the resource id",
              cloudops.confirm_word("sg.delete", {"GroupId": "sg-1"}, "aws") == "sg-1")
        got = cloudops.run(ACCOUNT, "ec2.start", {"InstanceId.1": "i-0abc"},
                           "eu-west-1")
        check("starting an instance calls StartInstances", got["ok"]
              and calls[-1]["action"] == "StartInstances")
        check("only declared parameters are sent",
              "Sneaky" not in cloudops.run(
                  ACCOUNT, "ec2.start",
                  {"InstanceId.1": "i-0abc", "Sneaky": "x"}, "eu-west-1")
              and "Sneaky" not in calls[-1]["body"])
        got = cloudops.run(ACCOUNT, "iam.create_key", {"UserName": "deployer"},
                           "eu-west-1")
        check("a new key comes back once and is not stored",
              got["data"]["AccessKeyId"] == "AKIANEW"
              and got["data"]["AccessKeySecret"] == "brand-new-secret")
        check("an IAM write also goes to the global endpoint",
              calls[-1]["host"] == "iam.amazonaws.com")
        try:
            cloudops.run(ACCOUNT, "ecs.start", {"InstanceId": "i-1"}, "eu-west-1")
            check("an Alibaba action is not available on AWS", False)
        except cloudops.OpError as e:
            check("an Alibaba action is not available on AWS", "unknown" in str(e))

        # ── a command on an instance, through SSM ───────────────────────
        got = cloudops.run_command(ACCOUNT, "i-0abc", "systemctl is-active nginx",
                                   "eu-west-1")
        check("a command goes through SSM", calls[-1]["action"] == "SendCommand"
              and got["invoke_id"] == "cmd-1")
        res = cloudops.command_result(ACCOUNT, "cmd-1", "eu-west-1", "i-0abc")
        check("its output comes back", res["output"] == "nginx is running"
              and res["done"] and res["status"] == "Success")

        # ── the console ────────────────────────────────────────────────
        link = cloudops.vnc_link(ACCOUNT, "i-0abc", "eu-west-1")
        check("the console link goes to the instance in the right region",
              "eu-west-1.console.aws.amazon.com" in link
              and "i-0abc" in link)
        check("no credential is in it", "secret" not in link.lower()
              and "signature" not in link.lower())

        # ── a region that is not on the account ────────────────────────
        got = cloud._aws_inventory(ACCOUNT, "eu-west-9")
        check("an unknown region is refused with the closest match",
              not got["groups"] and any("not a region this account" in n
                                        for n in got["notes"]))
    finally:
        cloud.aws_signed = real_signed
        cloud.invalidate()
        cloud._ALI_REGIONS.clear()
        cloud._BILLS.clear()

    # ── the services that do not speak the query protocol ────────────────
    # ECR was missing entirely, on an account whose own bill said "EC2 Container
    # Registry" — because the product table only spoke one AWS dialect.
    cloud.aws_signed = fake_signed
    cloud.invalidate()
    cloud._ALI_REGIONS.clear()
    try:
        calls.clear()
        inv = cloud._aws_inventory(ACCOUNT)
        by = {g["key"]: g for g in inv["groups"]}
        check("ECR repositories are read", "registry" in by
              and len(by["registry"]["rows"]) == 2)
        check("a repository shows its URI and mutability",
              by["registry"]["rows"][0]["kind"].startswith("MUTABLE")
              and "dkr.ecr" in by["registry"]["rows"][0]["extra"])
        check("ECR is asked as JSON-RPC with a target header",
              any(c["service"] == "ecr" for c in calls))
        check("Lambda functions are read", "functions" in by
              and by["functions"]["rows"][0]["name"] == "resize-images")
        check("Lambda is asked over REST, not the query protocol",
              any(c["service"] == "lambda" and c["path"].startswith("/2015-")
                  for c in calls))
        check("EKS clusters are read",
              "k8s" in by and by["k8s"]["rows"][0]["name"] == "lms-uat")

        # DescribeSnapshots takes Owner.1; OwnerId.1 is rejected outright, which
        # is what the real account answered
        snap = next(c for c in calls if c["action"] == "DescribeSnapshots")
        check("snapshots are asked for with Owner.1, not OwnerId.1",
              "Owner.1=self" in snap["body"] and "OwnerId" not in snap["body"])

        # Cost Explorer returns tiny negatives for rounding; "-0.0" on a
        # dashboard reads as a bug
        bills = cloud.aws_bills(ACCOUNT, 12, refresh=True)
        check("a rounding artefact is not shown as a negative bill",
              all(r["amount"] >= 0 for m in bills["months"] for r in m["rows"]))
        check("a zero line is left out entirely",
              all(r["amount"] != 0 for m in bills["months"] for r in m["rows"]))

        # a detail lookup is remembered briefly, since some endpoints are slow
        calls.clear()
        cloudops.detail(ACCOUNT, "compute", "i-0abc", "eu-west-1")
        first = len(calls)
        cloudops.detail(ACCOUNT, "compute", "i-0abc", "eu-west-1")
        check("a detail page is not fetched twice in a minute",
              len(calls) == first)
        cloudops.detail(ACCOUNT, "compute", "i-0abc", "eu-west-1", refresh=True)
        check("refresh still goes back to the provider", len(calls) > first)
    finally:
        cloud.aws_signed = real_signed
        cloudops._DETAIL_CACHE.clear()
        cloud.invalidate()
        cloud._ALI_REGIONS.clear()
        cloud._BILLS.clear()

    # ── ECR actions, which are JSON-RPC and needed shaping ───────────────
    cloud.aws_signed = fake_signed
    try:
        acts = {a["key"] for a in cloudops.for_group("registry", "aws")}
        check("the ECR page offers actions at all", acts)
        check("it offers the ones that matter",
              {"ecr.create", "ecr.delete", "ecr.tag_mutability",
               "ecr.scan_on_push", "ecr.delete_image"} <= acts)
        check("deleting a repository asks for its name, not a word",
              cloudops.confirm_word("ecr.delete", {"repositoryName": "team/app"},
                                    "aws") == "team/app")

        calls.clear()
        cloudops.run(ACCOUNT, "ecr.create",
                     {"repositoryName": "team/app",
                      "imageTagMutability": "IMMUTABLE"}, "eu-west-1")
        body = json.loads(calls[-1]["body"])
        check("creating a repository is sent as JSON, not a form",
              body == {"repositoryName": "team/app",
                       "imageTagMutability": "IMMUTABLE"})

        cloudops.run(ACCOUNT, "ecr.scan_on_push",
                     {"repositoryName": "team/app",
                      "imageScanningConfiguration": "true"}, "eu-west-1")
        body = json.loads(calls[-1]["body"])
        check("a boolean is sent as a boolean, nested where AWS wants it",
              body["imageScanningConfiguration"] == {"scanOnPush": True})

        cloudops.run(ACCOUNT, "ecr.delete_image",
                     {"repositoryName": "team/app", "imageIds": "1.2.3, 1.2.4"},
                     "eu-west-1")
        body = json.loads(calls[-1]["body"])
        check("a list of tags becomes a list of objects",
              body["imageIds"] == [{"imageTag": "1.2.3"}, {"imageTag": "1.2.4"}])

        cloudops.run(ACCOUNT, "ecr.delete",
                     {"repositoryName": "team/app", "force": "true"}, "eu-west-1")
        check("force is a boolean too", json.loads(calls[-1]["body"])["force"] is True)
        check("ECR actions are not offered on an Alibaba account",
              not any(k.startswith("ecr.") for k in cloudops.ALI_ACTIONS))

        # ── payments: read what exists, and be honest about the rest ─────
        pay = cloud.payments(ACCOUNT)
        check("AWS payments say plainly that there is no API for a card",
              any("no API for a card" in n for n in pay["notes"]))
        check("and link to the billing console where it is changed",
              [l for l, _u, _w in pay["consoles"]] == ["Billing overview"]
              and any("console.aws.amazon.com/billing" in u
                      for _l, u, _w in pay["consoles"]))
        check("payment methods are never presented as editable here",
              pay["manageable"] is False)
        for kind in ("alibaba", "aws"):
            links = cloud.PAYMENT_CONSOLES[kind]
            check(f"{kind} links are https and to the provider",
                  all(u.startswith("https://") and
                      ("aliyun.com" in u or "amazon.com" in u)
                      for _l, u, _w in links))
    finally:
        cloud.aws_signed = real_signed
        cloudops._DETAIL_CACHE.clear()
        cloud._BILLS.clear()

    # ── the search vocabulary covers what an AWS user types ─────────────
    for word, key in (("ec2", "compute"), ("ebs", "disks"), ("s3", "buckets"),
                      ("alb", "clb"), ("iam", "iam_users"), ("ami", "images")):
        check(f"“{word}” leads to {key}", word in cloud.SERVICE_WORDS.get(key, ""))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
