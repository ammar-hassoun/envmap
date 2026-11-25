"""Actions against a cloud account, and the detail behind one resource.

WHY THIS IS A TABLE AND NOT A HUNDRED FUNCTIONS
    Every action is the same three things: a call to make, the parameters it
    needs, and how badly it goes if it is wrong. Declaring them means the form,
    the confirmation, the audit entry and the test all read from one place, and
    adding an action is a row rather than a route.

THE SAFETY MODEL, WHICH IS NOT NEGOTIABLE
    * nothing here runs without a typed confirmation — the word is per action,
      and a destructive one asks for the resource's own id
    * every attempt is audited before it is made, including the parameters, so a
      failed attempt is on the record too
    * a read never goes through here; this module is only for change
    * the portal shows the exact call it is about to make. An operator should be
      able to see "AuthorizeSecurityGroup on sg-x, tcp/22 from 0.0.0.0/0" and
      stop it

    Deleting a database, a VPC or a subnet is deliberately absent. Those are
    once-only mistakes with no undo, the console asks for more than a typed
    word, and nobody needs to do them from a dashboard at 2am.
"""
from __future__ import annotations

import base64
import time

from . import cloud

# Danger ladder, which decides what the confirmation asks for:
#   safe      a state change that reverts (start, tag)
#   care      a change that something may depend on (stop, new rule, new user)
#   removal   an irreversible removal of a thing the portal created
DANGER = ("safe", "care", "removal")


def _p(name: str, label: str, required: bool = True, hint: str = "",
       kind: str = "text", options=None) -> dict:
    return {"name": name, "label": label, "required": required, "hint": hint,
            "kind": kind, "options": options or []}


# (product prefix or full host, API version)
ECS = ("ecs", "2014-05-26")
VPC = ("vpc", "2016-04-28")
RAM = ("ram.aliyuncs.com", "2015-05-01")

ALI_ACTIONS: dict = {
    # ── ECS lifecycle ─────────────────────────────────────────────────────
    "ecs.start": {
        "label": "Start instance", "group": "compute", "icon": "▶",
        "danger": "safe", "product": ECS, "action": "StartInstance",
        "params": [_p("InstanceId", "instance id")],
        "note": "Boots a stopped instance. Billing resumes.",
    },
    "ecs.stop": {
        "label": "Stop instance", "group": "compute", "icon": "⏸",
        "danger": "care", "product": ECS, "action": "StopInstance",
        "params": [_p("InstanceId", "instance id"),
                   _p("ForceStop", "force (skip clean shutdown)", False,
                      "false unless the guest is unresponsive", "select",
                      ["false", "true"])],
        "note": "Stops the guest. Anything running on it goes down.",
    },
    "ecs.reboot": {
        "label": "Reboot instance", "group": "compute", "icon": "↻",
        "danger": "care", "product": ECS, "action": "RebootInstance",
        "params": [_p("InstanceId", "instance id")],
        "note": "Restarts the guest.",
    },
    "ecs.vnc_password": {
        "label": "Set the console (VNC) password", "group": "compute",
        "icon": "🔑", "danger": "care", "product": ECS,
        "action": "ModifyInstanceVncPasswd",
        "params": [_p("InstanceId", "instance id"),
                   _p("VncPassword", "new password", True,
                      "exactly 6 characters, letters and digits only")],
        "note": "The VNC console asks for this password, and it is not the "
                "operating system's. The portal does not keep it — set it, then "
                "type it into the console when it asks.",
    },
    "ecs.tag": {
        "label": "Tag a resource", "group": "compute", "icon": "🏷",
        "danger": "safe", "product": ECS, "action": "TagResources",
        "params": [_p("ResourceType", "resource type", True,
                      "instance, disk, snapshot, securitygroup, eni", "select",
                      ["instance", "disk", "securitygroup", "eni", "snapshot"]),
                   _p("ResourceId.1", "resource id"),
                   _p("Tag.1.Key", "tag key"),
                   _p("Tag.1.Value", "tag value", False)],
        "note": "Tags are how anything larger than a handful of resources stays "
                "findable, and they cost nothing.",
    },

    # ── security groups ───────────────────────────────────────────────────
    "sg.create": {
        "label": "Create security group", "group": "secgroups", "icon": "＋",
        "danger": "care", "product": ECS, "action": "CreateSecurityGroup",
        "params": [_p("SecurityGroupName", "name"),
                   _p("VpcId", "VPC id"),
                   _p("Description", "description", False),
                   _p("SecurityGroupType", "type", False, "normal or enterprise",
                      "select", ["normal", "enterprise"])],
        "note": "A new group starts with no inbound rules, which denies "
                "everything until a rule is added.",
    },
    "sg.authorize": {
        "label": "Add an inbound rule", "group": "secgroups", "icon": "🔓",
        "danger": "care", "product": ECS, "action": "AuthorizeSecurityGroup",
        "params": [_p("SecurityGroupId", "security group id"),
                   _p("IpProtocol", "protocol", True, "", "select",
                      ["tcp", "udp", "icmp", "gre", "all"]),
                   _p("PortRange", "port range", True, "e.g. 443/443 or -1/-1"),
                   _p("SourceCidrIp", "source CIDR", True,
                      "0.0.0.0/0 opens it to the internet — say so out loud"),
                   _p("Policy", "policy", False, "", "select", ["accept", "drop"]),
                   _p("Description", "why", False,
                      "future you will want to know why this rule exists")],
        "note": "Opening a port to 0.0.0.0/0 is the single most common way an "
                "estate gets compromised. The portal will not stop you, but it "
                "will record it.",
    },
    "sg.revoke": {
        "label": "Remove an inbound rule", "group": "secgroups", "icon": "🔒",
        "danger": "care", "product": ECS, "action": "RevokeSecurityGroup",
        "params": [_p("SecurityGroupId", "security group id"),
                   _p("IpProtocol", "protocol", True, "", "select",
                      ["tcp", "udp", "icmp", "gre", "all"]),
                   _p("PortRange", "port range"),
                   _p("SourceCidrIp", "source CIDR")],
        "note": "Removes one rule. Anything relying on that port loses access "
                "immediately.",
    },
    "sg.delete": {
        "label": "Delete security group", "group": "secgroups", "icon": "🗑",
        "danger": "removal", "product": ECS, "action": "DeleteSecurityGroup",
        "params": [_p("SecurityGroupId", "security group id")],
        "note": "Only possible when nothing is in the group.",
    },

    # ── RAM ───────────────────────────────────────────────────────────────
    "ram.create_user": {
        "label": "Create RAM user", "group": "ram_users", "icon": "＋",
        "danger": "care", "product": RAM, "action": "CreateUser",
        "params": [_p("UserName", "user name", True, "no spaces"),
                   _p("DisplayName", "display name", False),
                   _p("Email", "email", False),
                   _p("Comments", "what this user is for", False)],
        "note": "A new user has no permissions and no credentials until you "
                "attach a policy and create a key.",
    },
    "ram.attach_policy": {
        "label": "Attach policy to user", "group": "ram_users", "icon": "📜",
        "danger": "care", "product": RAM, "action": "AttachPolicyToUser",
        "params": [_p("UserName", "user name"),
                   _p("PolicyName", "policy name", True,
                      "e.g. AliyunECSReadOnlyAccess"),
                   _p("PolicyType", "policy type", True, "", "select",
                      ["System", "Custom"])],
        "note": "Grants everything the policy allows, immediately.",
    },
    "ram.detach_policy": {
        "label": "Detach policy from user", "group": "ram_users", "icon": "⛔",
        "danger": "care", "product": RAM, "action": "DetachPolicyFromUser",
        "params": [_p("UserName", "user name"),
                   _p("PolicyName", "policy name"),
                   _p("PolicyType", "policy type", True, "", "select",
                      ["System", "Custom"])],
        "note": "Whatever was using this permission stops working at once.",
    },
    "ram.create_key": {
        "label": "Create access key", "group": "ram_users", "icon": "🔑",
        "danger": "care", "product": RAM, "action": "CreateAccessKey",
        "params": [_p("UserName", "user name")],
        "note": "The secret is shown once and never stored by the portal. If you "
                "lose it, delete the key and make another.",
        "secret_result": True,
    },
    "ram.disable_key": {
        "label": "Disable access key", "group": "ram_users", "icon": "🚫",
        "danger": "care", "product": RAM, "action": "UpdateAccessKey",
        "params": [_p("UserName", "user name"),
                   _p("UserAccessKeyId", "access key id"),
                   _p("Status", "status", True, "", "select",
                      ["Inactive", "Active"])],
        "note": "Anything signing requests with this key stops working. This is "
                "the right first move on a leaked key.",
    },
    "ram.delete_key": {
        "label": "Delete access key", "group": "ram_users", "icon": "🗑",
        "danger": "removal", "product": RAM, "action": "DeleteAccessKey",
        "params": [_p("UserName", "user name"),
                   _p("UserAccessKeyId", "access key id")],
        "note": "Irreversible. Disable it first and wait, unless it is leaked.",
    },
    "ram.delete_user": {
        "label": "Delete RAM user", "group": "ram_users", "icon": "🗑",
        "danger": "removal", "product": RAM, "action": "DeleteUser",
        "params": [_p("UserName", "user name")],
        "note": "Only possible once the user has no keys, no policies and no "
                "console login.",
    },

    # ── network ───────────────────────────────────────────────────────────
    "vpc.create_vswitch": {
        "label": "Create subnet (VSwitch)", "group": "subnets", "icon": "＋",
        "danger": "care", "product": VPC, "action": "CreateVSwitch",
        "params": [_p("VpcId", "VPC id"),
                   _p("CidrBlock", "CIDR", True, "inside the VPC's range, "
                      "not overlapping an existing subnet"),
                   _p("ZoneId", "zone", True, "e.g. me-central-1a"),
                   _p("VSwitchName", "name", False),
                   _p("Description", "description", False)],
        "note": "A subnet cannot be resized afterwards, and its CIDR cannot "
                "overlap another in the same VPC.",
    },
    "eip.associate": {
        "label": "Attach an elastic IP", "group": "eips", "icon": "🔗",
        "danger": "care", "product": VPC, "action": "AssociateEipAddress",
        "params": [_p("AllocationId", "EIP allocation id"),
                   _p("InstanceId", "target instance id"),
                   _p("InstanceType", "target type", False, "", "select",
                      ["EcsInstance", "SlbInstance", "Nat", "NetworkInterface"])],
        "note": "Puts a public address on the target.",
    },
    "eip.unassociate": {
        "label": "Detach an elastic IP", "group": "eips", "icon": "⛓",
        "danger": "care", "product": VPC, "action": "UnassociateEipAddress",
        "params": [_p("AllocationId", "EIP allocation id"),
                   _p("InstanceId", "instance id")],
        "note": "Whatever was reachable on that address stops being reachable.",
    },
}


# ── AWS: the same declarations, its own calls ──────────────────────────────
EC2 = ("ec2", "2016-11-15")
ELB = ("elasticloadbalancing", "2015-12-01")
IAM = ("iam", "2010-05-08")
AWS_RDS = ("rds", "2014-10-31")

AWS_ACTIONS: dict = {
    "ec2.start": {
        "label": "Start instance", "group": "compute", "icon": "▶",
        "danger": "safe", "product": EC2, "action": "StartInstances",
        "params": [_p("InstanceId.1", "instance id")],
        "note": "Boots a stopped instance. Charging resumes.",
    },
    "ec2.stop": {
        "label": "Stop instance", "group": "compute", "icon": "⏸",
        "danger": "care", "product": EC2, "action": "StopInstances",
        "params": [_p("InstanceId.1", "instance id"),
                   _p("Force", "force (skip clean shutdown)", False,
                      "true only when the guest is unresponsive", "select",
                      ["false", "true"])],
        "note": "Stops the guest. An instance-store volume loses its contents; "
                "EBS survives and is still charged for.",
    },
    "ec2.reboot": {
        "label": "Reboot instance", "group": "compute", "icon": "↻",
        "danger": "care", "product": EC2, "action": "RebootInstances",
        "params": [_p("InstanceId.1", "instance id")],
        "note": "Restarts the guest in place.",
    },
    "ec2.tag": {
        "label": "Tag a resource", "group": "compute", "icon": "🏷",
        "danger": "safe", "product": EC2, "action": "CreateTags",
        "params": [_p("ResourceId.1", "resource id", True,
                      "an instance, volume, snapshot, security group…"),
                   _p("Tag.1.Key", "tag key"),
                   _p("Tag.1.Value", "tag value", False)],
        "note": "Tags are what cost allocation and every search rely on.",
    },
    "sg.create": {
        "label": "Create security group", "group": "secgroups", "icon": "＋",
        "danger": "care", "product": EC2, "action": "CreateSecurityGroup",
        "params": [_p("GroupName", "name"),
                   _p("GroupDescription", "description", True,
                      "AWS requires one and will not let you change it"),
                   _p("VpcId", "VPC id")],
        "note": "A new group allows nothing inbound until a rule is added, and "
                "allows all outbound.",
    },
    "sg.authorize": {
        "label": "Add an inbound rule", "group": "secgroups", "icon": "🔓",
        "danger": "care", "product": EC2, "action": "AuthorizeSecurityGroupIngress",
        "params": [_p("GroupId", "security group id"),
                   _p("IpPermissions.1.IpProtocol", "protocol", True, "", "select",
                      ["tcp", "udp", "icmp", "-1"]),
                   _p("IpPermissions.1.FromPort", "from port", True, "e.g. 443"),
                   _p("IpPermissions.1.ToPort", "to port", True, "e.g. 443"),
                   _p("IpPermissions.1.IpRanges.1.CidrIp", "source CIDR", True,
                      "0.0.0.0/0 opens it to the internet"),
                   _p("IpPermissions.1.IpRanges.1.Description", "why", False,
                      "future you will want to know why this exists")],
        "note": "Opening a port to 0.0.0.0/0 is how most estates get "
                "compromised. The portal will not stop you; it will record it.",
    },
    "sg.revoke": {
        "label": "Remove an inbound rule", "group": "secgroups", "icon": "🔒",
        "danger": "care", "product": EC2, "action": "RevokeSecurityGroupIngress",
        "params": [_p("GroupId", "security group id"),
                   _p("IpPermissions.1.IpProtocol", "protocol", True, "", "select",
                      ["tcp", "udp", "icmp", "-1"]),
                   _p("IpPermissions.1.FromPort", "from port"),
                   _p("IpPermissions.1.ToPort", "to port"),
                   _p("IpPermissions.1.IpRanges.1.CidrIp", "source CIDR")],
        "note": "Anything relying on that port loses access at once.",
    },
    "sg.delete": {
        "label": "Delete security group", "group": "secgroups", "icon": "🗑",
        "danger": "removal", "product": EC2, "action": "DeleteSecurityGroup",
        "params": [_p("GroupId", "security group id")],
        "note": "Only possible when nothing refers to the group.",
    },
    "iam.create_user": {
        "label": "Create IAM user", "group": "iam_users", "icon": "＋",
        "danger": "care", "product": IAM, "action": "CreateUser",
        "params": [_p("UserName", "user name"),
                   _p("Path", "path", False, "e.g. /service/")],
        "note": "A new user has no permissions and no credentials until a policy "
                "is attached and a key created.",
    },
    "iam.attach_policy": {
        "label": "Attach policy to user", "group": "iam_users", "icon": "📜",
        "danger": "care", "product": IAM, "action": "AttachUserPolicy",
        "params": [_p("UserName", "user name"),
                   _p("PolicyArn", "policy ARN", True,
                      "e.g. arn:aws:iam::aws:policy/ReadOnlyAccess")],
        "note": "Grants everything the policy allows, immediately.",
    },
    "iam.detach_policy": {
        "label": "Detach policy from user", "group": "iam_users", "icon": "⛔",
        "danger": "care", "product": IAM, "action": "DetachUserPolicy",
        "params": [_p("UserName", "user name"),
                   _p("PolicyArn", "policy ARN")],
        "note": "Whatever used that permission stops working at once.",
    },
    "iam.create_key": {
        "label": "Create access key", "group": "iam_users", "icon": "🔑",
        "danger": "care", "product": IAM, "action": "CreateAccessKey",
        "params": [_p("UserName", "user name")],
        "note": "The secret is shown once and is never stored by the portal. "
                "AWS allows two keys per user, which is what makes rotation "
                "possible without downtime.",
        "secret_result": True,
    },
    "iam.disable_key": {
        "label": "Deactivate access key", "group": "iam_users", "icon": "🚫",
        "danger": "care", "product": IAM, "action": "UpdateAccessKey",
        "params": [_p("UserName", "user name"),
                   _p("AccessKeyId", "access key id"),
                   _p("Status", "status", True, "", "select",
                      ["Inactive", "Active"])],
        "note": "The right first move on a leaked key: reversible, and it stops "
                "the key working immediately.",
    },
    "iam.delete_key": {
        "label": "Delete access key", "group": "iam_users", "icon": "🗑",
        "danger": "removal", "product": IAM, "action": "DeleteAccessKey",
        "params": [_p("UserName", "user name"),
                   _p("AccessKeyId", "access key id")],
        "note": "Irreversible. Deactivate it and wait, unless it is leaked.",
    },
    "iam.delete_user": {
        "label": "Delete IAM user", "group": "iam_users", "icon": "🗑",
        "danger": "removal", "product": IAM, "action": "DeleteUser",
        "params": [_p("UserName", "user name")],
        "note": "Only possible once the user has no keys, no policies, no groups "
                "and no console password.",
    },
    "ecr.create": {
        "label": "Create repository", "group": "registry", "icon": "＋",
        "danger": "care", "product": ("ecr", "2015-09-21"),
        "action": "CreateRepository", "target": "AmazonEC2ContainerRegistry_V20150921.CreateRepository",
        "params": [_p("repositoryName", "repository name", True,
                      "lower case, and a namespace is just a prefix: team/app"),
                   _p("imageTagMutability", "tags", False,
                      "IMMUTABLE stops a tag being moved, which is what you want "
                      "for releases", "select", ["MUTABLE", "IMMUTABLE"])],
        "note": "A new repository is empty and costs nothing until images are "
                "pushed. Storage is charged per GB-month afterwards.",
    },
    "ecr.tag_mutability": {
        "label": "Set tag mutability", "group": "registry", "icon": "🔖",
        "danger": "care", "product": ("ecr", "2015-09-21"),
        "action": "PutImageTagMutability",
        "target": "AmazonEC2ContainerRegistry_V20150921.PutImageTagMutability",
        "params": [_p("repositoryName", "repository name"),
                   _p("imageTagMutability", "tags", True, "", "select",
                      ["IMMUTABLE", "MUTABLE"])],
        "note": "IMMUTABLE means a tag can never be repointed at a different "
                "image — the difference between a deploy you can reproduce and "
                "one you cannot.",
    },
    "ecr.scan_on_push": {
        "label": "Scan images on push", "group": "registry", "icon": "🔍",
        "danger": "safe", "product": ("ecr", "2015-09-21"),
        "action": "PutImageScanningConfiguration",
        "target": "AmazonEC2ContainerRegistry_V20150921.PutImageScanningConfiguration",
        "params": [_p("repositoryName", "repository name"),
                   _p("imageScanningConfiguration", "scan on push", True,
                      "", "select", ["true", "false"])],
        "note": "Basic scanning runs on every push and costs nothing.",
        "wrap": {"imageScanningConfiguration": "scanOnPush"},
    },
    "ecr.delete_image": {
        "label": "Delete image tags", "group": "registry", "icon": "🗑",
        "danger": "removal", "product": ("ecr", "2015-09-21"),
        "action": "BatchDeleteImage", "target": "AmazonEC2ContainerRegistry_V20150921.BatchDeleteImage",
        "params": [_p("repositoryName", "repository name"),
                   _p("imageIds", "tags to delete", True,
                      "comma separated, e.g. 1.2.3, 1.2.4")],
        "note": "Deletes those tags. An untagged image that nothing else "
                "references is removed by ECR afterwards.",
        "tags": "imageIds",
    },
    "ecr.delete": {
        "label": "Delete repository", "group": "registry", "icon": "🗑",
        "danger": "removal", "product": ("ecr", "2015-09-21"),
        "action": "DeleteRepository", "target": "AmazonEC2ContainerRegistry_V20150921.DeleteRepository",
        "params": [_p("repositoryName", "repository name"),
                   _p("force", "delete even if it holds images", False, "",
                      "select", ["false", "true"])],
        "note": "Irreversible, and with force it takes every image with it.",
    },
    "eip.associate": {
        "label": "Attach an elastic IP", "group": "eips", "icon": "🔗",
        "danger": "care", "product": EC2, "action": "AssociateAddress",
        "params": [_p("AllocationId", "allocation id"),
                   _p("InstanceId", "instance id")],
        "note": "Puts a public address on the instance.",
    },
    "eip.unassociate": {
        "label": "Detach an elastic IP", "group": "eips", "icon": "⛓",
        "danger": "care", "product": EC2, "action": "DisassociateAddress",
        "params": [_p("AssociationId", "association id", True,
                      "not the allocation id — AWS wants the association")],
        "note": "Whatever was reachable on that address stops being reachable.",
    },
    "ec2.snapshot": {
        "label": "Snapshot a volume", "group": "disks", "icon": "📸",
        "danger": "safe", "product": EC2, "action": "CreateSnapshot",
        "params": [_p("VolumeId", "volume id"),
                   _p("Description", "why", False)],
        "note": "A point-in-time copy. Safe to take at any time, and charged for "
                "until deleted.",
    },
}

AWS_DETAILS: dict = {
    "compute": {"product": EC2, "action": "DescribeInstances",
                "id_param": "InstanceId.1", "reader": "instance"},
    "secgroups": {"product": EC2, "action": "DescribeSecurityGroups",
                  "id_param": "GroupId.1", "reader": "secgroup"},
    "vpcs": {"product": EC2, "action": "DescribeVpcs", "id_param": "VpcId.1",
             "reader": "vpc"},
    "subnets": {"product": EC2, "action": "DescribeSubnets",
                "id_param": "SubnetId.1", "reader": "subnet"},
    "disks": {"product": EC2, "action": "DescribeVolumes",
              "id_param": "VolumeId.1", "reader": "volume"},
    "rds": {"product": AWS_RDS, "action": "DescribeDBInstances",
            "id_param": "DBInstanceIdentifier", "reader": "rds"},
    "iam_users": {"product": IAM, "action": "GetUser", "id_param": "UserName",
                  "reader": "iam_user"},
}


def _provider_actions(provider: str) -> dict:
    return AWS_ACTIONS if provider == "aws" else ALI_ACTIONS


def for_group(key: str, provider: str = "alibaba") -> list[dict]:
    """The actions offered on a resource list, in declaration order."""
    return [{**spec, "key": k}
            for k, spec in _provider_actions(provider).items()
            if spec["group"] == key]


def confirm_word(key: str, params: dict, provider: str = "alibaba") -> str:
    """What the person has to type. A removal asks for the thing's own id, so
    muscle memory cannot carry someone through it."""
    spec = _provider_actions(provider).get(key) or {}
    if spec.get("danger") != "removal":
        return "CONFIRM"
    for p in spec.get("params", []):
        if p["name"].endswith(("Id", "Name")) and params.get(p["name"]):
            return str(params[p["name"]])
    return "DELETE"


def preview(key: str, params: dict, provider: str = "alibaba") -> str:
    """The call in one line, for the confirmation and the audit entry."""
    spec = _provider_actions(provider).get(key)
    if not spec:
        return ""
    given = ", ".join(f"{k}={v}" for k, v in params.items() if v != "")
    return f"{spec['action']}({given})"


class OpError(Exception):
    pass


def run(conn: dict, key: str, params: dict, region: str) -> dict:
    """Make the call. Confirmation and audit are the caller's job — this only
    talks to the provider, so the tests can drive it directly."""
    provider = conn.get("type", "")
    if provider not in ("alibaba", "aws"):
        raise OpError(f"actions are implemented for Alibaba Cloud and AWS, not "
                      f"{provider or 'this provider'}")
    spec = _provider_actions(provider).get(key)
    if not spec:
        raise OpError(f"unknown action '{key}'")
    missing = [p["label"] for p in spec["params"]
               if p["required"] and not str(params.get(p["name"], "")).strip()]
    if missing:
        raise OpError("missing: " + ", ".join(missing))
    send = {k: v for k, v in params.items()
            if v != "" and any(p["name"] == k for p in spec["params"])}

    if provider == "aws":
        return _run_aws(conn, spec, send, region)

    host_prefix, version = spec["product"]
    host = (host_prefix if "." in host_prefix
            else f"{host_prefix}.{region}.aliyuncs.com")
    code, doc = cloud._alibaba_rpc(conn, spec["action"], version, host, region,
                                   send)
    if code != 200:
        raise OpError(cloud._ali_why(doc, code))
    out = {"ok": True, "message": f"{spec['label']} done", "data": {}}
    if spec.get("secret_result"):
        ak = (doc.get("AccessKey") or {})
        out["data"] = {"AccessKeyId": ak.get("AccessKeyId", ""),
                       "AccessKeySecret": ak.get("AccessKeySecret", "")}
        out["message"] = ("Access key created. The secret is shown once and is "
                          "not stored here.")
    return out


def _run_aws(conn: dict, spec: dict, send: dict, region: str) -> dict:
    """One AWS write, in whichever dialect the service speaks.

    IAM answers only at its global endpoint, so an IAM action asked for in
    eu-west-1 fails in a way that reads like a permissions problem. And ECR is
    JSON-RPC rather than the query protocol — the same reason it was missing from
    the reads is the reason its actions need this branch.
    """
    import json as _json
    import urllib.parse
    service, version = spec["product"]
    host = cloud.AWS_GLOBAL.get(service, "")
    where = "us-east-1" if host else region
    target = spec.get("target")
    if target:
        # A form gives text; a JSON API wants types and sometimes structure.
        # Both shapes are declared on the action rather than guessed at: "tags"
        # names a field that is a list of image tags, "wrap" names one that has
        # to be nested in an object of its own.
        payload = {}
        for k, v in send.items():
            value = v
            if k == spec.get("tags"):
                value = [{"imageTag": x.strip()} for x in v.split(",") if x.strip()]
            elif v in ("true", "false"):
                value = v == "true"
            wrap = (spec.get("wrap") or {}).get(k)
            payload[k] = {wrap: value} if wrap else value
        code, text = cloud.aws_signed(
            conn, service, where, "POST", "/", "", _json.dumps(payload),
            {"Content-Type": "application/x-amz-json-1.1",
             "X-Amz-Target": target}, host=host)
    else:
        params = {"Action": spec["action"], "Version": version, **send}
        body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                        for k, v in params.items())
        code, text = cloud.aws_signed(
            conn, service, where, "POST", "/", "", body,
            {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            host=host)
    if code != 200:
        raise OpError(cloud._aws_why(text, code))
    out = {"ok": True, "message": f"{spec['label']} done", "data": {}}
    if spec.get("secret_result"):
        out["data"] = {
            "AccessKeyId": cloud._xml_one(text, "AccessKeyId"),
            "AccessKeySecret": cloud._xml_one(text, "SecretAccessKey")}
        out["message"] = ("Access key created. The secret is shown once and is "
                          "not stored here.")
    return out


# ── the console ────────────────────────────────────────────────────────────
def vnc_link(conn: dict, instance: str, region: str,
             windows: bool = False) -> str:
    if conn.get("type") == "aws":
        return aws_console_link(conn, instance, region)
    """A link that opens Alibaba's own VNC console for this instance.

    The password is deliberately NOT passed. Alibaba's console page asks for the
    VNC password itself, which keeps a credential out of a URL, out of the
    portal's logs and out of the browser's history. Setting that password is a
    separate, audited action for when nobody remembers it.
    """
    code, doc = cloud._alibaba_rpc(conn, "DescribeInstanceVncUrl",
                                   "2014-05-26",
                                   f"ecs.{region}.aliyuncs.com", region,
                                   {"InstanceId": instance})
    if code != 200:
        why = cloud._ali_why(doc, code)
        if "IncorrectInstanceStatus" in str(doc.get("Code", "")):
            why += " — the instance has to be running for a console session"
        raise OpError(why)
    url = doc.get("VncUrl", "")
    if not url:
        raise OpError("Alibaba returned no console URL for that instance")
    import urllib.parse as up
    return ("https://ecs.console.aliyun.com/vnc/index.htm?"
            + up.urlencode({"vncUrl": url, "instanceId": instance,
                            "regionId": region,
                            "isWindows": "true" if windows else "false"}))


def aws_console_link(conn: dict, instance: str, region: str) -> str:
    """A link into the AWS console for this instance.

    There is no VNC here. AWS offers the serial console (needs it enabled per
    account and an IAM permission) and EC2 Instance Connect; neither can be
    handed over as a plain URL with a session in it. So this opens the console at
    the instance, and the command runner below is the part that actually does
    work without leaving the portal.
    """
    return (f"https://{region}.console.aws.amazon.com/ec2/home?region={region}"
            f"#InstanceDetails:instanceId={instance}")


def aws_run_command(conn: dict, instance: str, script: str, region: str,
                    timeout: int = 60) -> dict:
    """Run a shell command through SSM, which is the AWS equivalent of Cloud
    Assistant: the instance needs the SSM agent and an instance profile allowing
    it, and the command is recorded here before it runs."""
    import urllib.parse
    if not instance.strip() or not script.strip():
        raise OpError("an instance and a command are both required")
    body = "&".join([
        "Action=SendCommand", "Version=2014-11-06",
        "DocumentName=AWS-RunShellScript",
        f"InstanceIds.member.1={urllib.parse.quote(instance, safe='')}",
        f"Parameters.entry.1.key=commands",
        f"Parameters.entry.1.value.member.1={urllib.parse.quote(script, safe='')}",
        f"TimeoutSeconds={timeout}"])
    code, text = cloud.aws_signed(
        conn, "ssm", region, "POST", "/", "", body,
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
    if code != 200:
        why = cloud._aws_why(text, code)
        low = why.lower()
        if "invalidinstanceid" in low or "not in a valid state" in low:
            why += (" — the instance needs the SSM agent running and an instance "
                    "profile granting AmazonSSMManagedInstanceCore")
        raise OpError(why)
    return {"invoke_id": cloud._xml_one(text, "CommandId"), "instance": instance}


def aws_command_result(conn: dict, invoke_id: str, instance: str,
                       region: str) -> dict:
    import urllib.parse
    body = "&".join([
        "Action=GetCommandInvocation", "Version=2014-11-06",
        f"CommandId={urllib.parse.quote(invoke_id, safe='')}",
        f"InstanceId={urllib.parse.quote(instance, safe='')}"])
    code, text = cloud.aws_signed(
        conn, "ssm", region, "POST", "/", "", body,
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
    if code != 200:
        raise OpError(cloud._aws_why(text, code))
    status = cloud._xml_one(text, "Status")
    out = cloud._xml_one(text, "StandardOutputContent")
    err = cloud._xml_one(text, "StandardErrorContent")
    return {"done": status in ("Success", "Failed", "TimedOut", "Cancelled"),
            "status": status,
            "exit": cloud._xml_one(text, "ResponseCode") or None,
            "output": (out + ("\n" + err if err else "")).strip(),
            "finished": cloud._xml_one(text, "ExecutionEndDateTime")}


# ── running a command on an instance ───────────────────────────────────────
# Alibaba's Cloud Assistant, which is how a shell works here: there is no
# interactive session over the API, so a command is submitted and its output
# collected. That suits an audited portal better than a terminal would — every
# command run through here is on the record with who ran it.
def run_command(conn: dict, instance: str, script: str, region: str,
                timeout: int = 60) -> dict:
    if conn.get("type") == "aws":
        return aws_run_command(conn, instance, script, region, timeout)
    if not instance.strip() or not script.strip():
        raise OpError("an instance and a command are both required")
    body = base64.b64encode(script.encode()).decode()
    code, doc = cloud._alibaba_rpc(
        conn, "RunCommand", "2014-05-26", f"ecs.{region}.aliyuncs.com", region,
        {"Type": "RunShellScript", "CommandContent": body,
         "ContentEncoding": "Base64", "InstanceId.1": instance,
         "Timeout": str(timeout)})
    if code != 200:
        why = cloud._ali_why(doc, code)
        if "cloudassistant" in why.lower() or "NotFound" in str(doc.get("Code", "")):
            why += (" — the instance needs the Cloud Assistant agent, which is "
                    "preinstalled on recent images and installable on older ones")
        raise OpError(why)
    return {"invoke_id": doc.get("InvokeId", ""), "instance": instance}


def command_result(conn: dict, invoke_id: str, region: str,
                   instance: str = "") -> dict:
    """Output of a submitted command, or that it is still running."""
    if conn.get("type") == "aws":
        return aws_command_result(conn, invoke_id, instance, region)
    code, doc = cloud._alibaba_rpc(
        conn, "DescribeInvocationResults", "2014-05-26",
        f"ecs.{region}.aliyuncs.com", region, {"InvokeId": invoke_id})
    if code != 200:
        raise OpError(cloud._ali_why(doc, code))
    rows = ((doc.get("Invocation") or {}).get("InvocationResults") or {}) \
        .get("InvocationResult", []) or []
    if not rows:
        return {"done": False, "output": "", "status": "pending", "exit": None}
    r = rows[0]
    raw = r.get("Output") or ""
    try:
        out = base64.b64decode(raw).decode(errors="replace") if raw else ""
    except Exception:                                          # noqa: BLE001
        out = raw
    status = r.get("InvocationStatus") or r.get("InvokeRecordStatus") or ""
    return {"done": status in ("Success", "Failed", "Timeout", "Cancelled",
                               "Error"),
            "status": status, "exit": r.get("ExitCode"),
            "output": out, "finished": r.get("FinishedTime", "")}


def wait_for(conn: dict, invoke_id: str, region: str, seconds: int = 25,
             instance: str = "") -> dict:
    """Poll until the command finishes or the wait runs out.

    A short wait rather than a websocket: most administrative commands answer in
    a second or two, and a page that returns "still running, refresh" is honest
    about the ones that do not.
    """
    deadline = time.time() + seconds
    got = {"done": False, "output": "", "status": "pending", "exit": None}
    while time.time() < deadline:
        got = command_result(conn, invoke_id, region, instance)
        if got["done"]:
            return got
        time.sleep(1.5)
    return got


# ── detail behind one resource ─────────────────────────────────────────────
# What a deep page asks for, per group. Each entry is a call plus a reader that
# turns the answer into (label, value) pairs, so the page is the same code for
# every resource type and a new one is a row here.
def _kv(doc: dict, mapping: list[tuple[str, str]], root=None) -> list[tuple]:
    node = doc
    if root:
        for step in root:
            node = (node or {}).get(step) or {}
            if isinstance(node, list):
                node = node[0] if node else {}
    return [(label, node.get(field, "")) for label, field in mapping
            if node.get(field, "") not in ("", None, [], {})]


ALI_DETAILS: dict = {
    "compute": {
        "id_param": "InstanceIds", "quote": True,
        "product": ECS, "action": "DescribeInstances",
        "fields": lambda d: _kv(d, [
            ("instance id", "InstanceId"), ("name", "InstanceName"),
            ("status", "Status"), ("type", "InstanceType"),
            ("CPU", "Cpu"), ("memory (MiB)", "Memory"),
            ("image", "ImageId"), ("OS", "OSName"),
            ("zone", "ZoneId"), ("charge", "InstanceChargeType"),
            ("created", "CreationTime"), ("expires", "ExpiredTime"),
            ("host name", "HostName"), ("key pair", "KeyPairName"),
            ("region", "RegionId")],
            root=["Instances", "Instance"]),
        "extras": [
            ("networking", ECS, "DescribeInstanceAttribute", "InstanceId",
             lambda d: _kv(d, [("private IP", "PrivateIpAddress"),
                               ("VPC", "VpcId"), ("subnet", "VSwitchId"),
                               ("internet out (Mbps)", "InternetMaxBandwidthOut")])),
        ],
    },
    "secgroups": {
        "id_param": "SecurityGroupId", "product": ECS,
        "action": "DescribeSecurityGroupAttribute",
        "fields": lambda d: _kv(d, [
            ("group id", "SecurityGroupId"), ("name", "SecurityGroupName"),
            ("description", "Description"), ("VPC", "VpcId"),
            ("region", "RegionId")]),
        "table": ("rules", lambda d: [
            {"protocol": p.get("IpProtocol", ""), "ports": p.get("PortRange", ""),
             "source": p.get("SourceCidrIp") or p.get("SourceGroupId", ""),
             "direction": p.get("Direction", ""), "policy": p.get("Policy", ""),
             "why": p.get("Description", "")}
            for p in ((d.get("Permissions") or {}).get("Permission", []) or [])]),
    },
    "vpcs": {
        "id_param": "VpcId", "product": VPC, "action": "DescribeVpcAttribute",
        "fields": lambda d: _kv(d, [
            ("VPC id", "VpcId"), ("name", "VpcName"), ("CIDR", "CidrBlock"),
            ("IPv6 CIDR", "Ipv6CidrBlock"), ("status", "Status"),
            ("router", "VRouterId"), ("created", "CreationTime"),
            ("region", "RegionId")]),
    },
    "subnets": {
        "id_param": "VSwitchId", "product": VPC,
        "action": "DescribeVSwitchAttributes",
        "fields": lambda d: _kv(d, [
            ("subnet id", "VSwitchId"), ("name", "VSwitchName"),
            ("CIDR", "CidrBlock"), ("free addresses", "AvailableIpAddressCount"),
            ("zone", "ZoneId"), ("VPC", "VpcId"), ("status", "Status"),
            ("created", "CreationTime")]),
    },
    "rds": {
        "id_param": "DBInstanceId", "product": ("rds", "2014-08-15"),
        "action": "DescribeDBInstanceAttribute",
        "fields": lambda d: _kv(d, [
            ("instance", "DBInstanceId"), ("description", "DBInstanceDescription"),
            ("engine", "Engine"), ("version", "EngineVersion"),
            ("class", "DBInstanceClass"), ("status", "DBInstanceStatus"),
            ("storage (GB)", "DBInstanceStorage"), ("type", "DBInstanceType"),
            ("network", "DBInstanceNetType"), ("VPC", "VpcId"),
            ("zone", "ZoneId"), ("created", "CreationTime"),
            ("maintenance", "MaintainTime"), ("connection", "ConnectionString")],
            root=["Items", "DBInstanceAttribute"]),
        # the databases inside the instance, which is the question people
        # actually have about an RDS box
        "extras": [
            ("databases", ("rds", "2014-08-15"), "DescribeDatabases",
             "DBInstanceId",
             lambda d: [(db.get("DBName", ""),
                         f"{db.get('DBStatus', '')} · "
                         f"{db.get('CharacterSetName', '')}"
                         + (f" · {db.get('DBDescription')}"
                            if db.get("DBDescription") else ""))
                        for db in ((d.get("Databases") or {}).get("Database", [])
                                   or [])]),
            ("accounts", ("rds", "2014-08-15"), "DescribeAccounts",
             "DBInstanceId",
             lambda d: [(a.get("AccountName", ""),
                         f"{a.get('AccountType', '')} · "
                         f"{a.get('AccountStatus', '')}")
                        for a in ((d.get("Accounts") or {}).get("DBInstanceAccount",
                                                                []) or [])]),
        ],
    },
    "ram_users": {
        "id_param": "UserName", "product": RAM, "action": "GetUser",
        "fields": lambda d: _kv(d, [
            ("user", "UserName"), ("display name", "DisplayName"),
            ("id", "UserId"), ("email", "Email"), ("phone", "MobilePhone"),
            ("comments", "Comments"), ("created", "CreateDate"),
            ("last login", "LastLoginDate")], root=["User"]),
        "extras": [
            ("attached policies", RAM, "ListPoliciesForUser", "UserName",
             lambda d: [(p.get("PolicyName", ""),
                         f"{p.get('PolicyType', '')} · attached "
                         f"{(p.get('AttachDate') or '')[:10]}")
                        for p in ((d.get("Policies") or {}).get("Policy", []) or [])]),
            ("access keys", RAM, "ListAccessKeys", "UserName",
             lambda d: [(k.get("AccessKeyId", ""),
                         f"{k.get('Status', '')} · created "
                         f"{(k.get('CreateDate') or '')[:10]}")
                        for k in ((d.get("AccessKeys") or {}).get("AccessKey", [])
                                  or [])]),
        ],
    },
    "clb": {
        "id_param": "LoadBalancerId", "product": ("slb", "2014-05-15"),
        "action": "DescribeLoadBalancerAttribute",
        "fields": lambda d: _kv(d, [
            ("load balancer", "LoadBalancerId"), ("name", "LoadBalancerName"),
            ("status", "LoadBalancerStatus"), ("address", "Address"),
            ("address type", "AddressType"), ("spec", "LoadBalancerSpec"),
            ("VPC", "VpcId"), ("subnet", "VSwitchId"),
            ("bandwidth", "Bandwidth"), ("created", "CreateTime")]),
        "table": ("listeners", lambda d: [
            {"port": p.get("ListenerPort", ""), "protocol": p.get("ListenerProtocol", ""),
             "forward": p.get("ForwardPort", "")}
            for p in ((d.get("ListenerPortsAndProtocol") or {})
                      .get("ListenerPortAndProtocol", []) or [])]),
    },
    "disks": {
        "id_param": "DiskIds", "quote": True, "product": ECS,
        "action": "DescribeDisks",
        "fields": lambda d: _kv(d, [
            ("disk", "DiskId"), ("name", "DiskName"), ("size (GiB)", "Size"),
            ("category", "Category"), ("status", "Status"),
            ("type", "Type"), ("attached to", "InstanceId"),
            ("device", "Device"), ("zone", "ZoneId"),
            ("encrypted", "Encrypted"), ("created", "CreationTime"),
            ("delete with instance", "DeleteWithInstance")],
            root=["Disks", "Disk"]),
    },
    "eips": {
        "id_param": "AllocationId", "product": VPC,
        "action": "DescribeEipAddresses",
        "fields": lambda d: _kv(d, [
            ("allocation", "AllocationId"), ("address", "IpAddress"),
            ("name", "Name"), ("status", "Status"),
            ("bandwidth (Mbps)", "Bandwidth"), ("charge", "InternetChargeType"),
            ("bound to", "InstanceId"), ("bound type", "InstanceType"),
            ("created", "AllocationTime")],
            root=["EipAddresses", "EipAddress"]),
    },
}


# What an action form should already know when it is opened from a resource:
# retyping the id you just clicked is how the wrong id gets pasted into a delete.
PREFILL = {
    "compute": lambda i: {"InstanceId": i, "ResourceId.1": i,
                          "ResourceType": "instance"},
    "disks": lambda i: {"ResourceId.1": i, "ResourceType": "disk"},
    "secgroups": lambda i: {"SecurityGroupId": i, "ResourceId.1": i,
                            "ResourceType": "securitygroup"},
    "ram_users": lambda i: {"UserName": i},
    "vpcs": lambda i: {"VpcId": i},
    "subnets": lambda i: {"VSwitchId": i},
    "eips": lambda i: {"AllocationId": i},
}


def prefill_for(group: str, ident: str, provider: str = "alibaba") -> dict:
    if provider == "aws":
        fn = AWS_PREFILL.get(group)
        return fn(ident) if fn else {}
    fn = PREFILL.get(group)
    return fn(ident) if fn else {}


AWS_PREFILL = {
    "compute": lambda i: {"InstanceId.1": i, "InstanceId": i, "ResourceId.1": i},
    "disks": lambda i: {"VolumeId": i, "ResourceId.1": i},
    "secgroups": lambda i: {"GroupId": i, "ResourceId.1": i},
    "iam_users": lambda i: {"UserName": i},
    "eips": lambda i: {"AllocationId": i},
}


def has_detail(group: str, provider: str = "alibaba") -> bool:
    """Whether this resource type opens into a page of its own."""
    if provider == "aws":
        return group in AWS_DETAILS or group in cloud.BUCKET_KEYS
    return group in ALI_DETAILS or group in cloud.BUCKET_KEYS


def _aws_detail(conn: dict, group: str, ident: str, region: str) -> dict:
    """One AWS resource, as deeply as its own API describes it."""
    import urllib.parse
    tree, n, kids, direct = cloud._aws_tree, cloud._n, cloud._kids, cloud._direct

    if group in cloud.BUCKET_KEYS:
        return _aws_bucket_detail(conn, ident, region)

    spec = AWS_DETAILS.get(group)
    if not spec:
        return {"error": f"no detail view for {group}", "fields": [],
                "extras": [], "table": None}
    service, version = spec["product"]
    host = cloud.AWS_GLOBAL.get(service, "")
    body = "&".join([f"Action={spec['action']}", f"Version={version}",
                     f"{spec['id_param']}={urllib.parse.quote(ident, safe='')}"])
    try:
        code, text = cloud.aws_signed(
            conn, service, "us-east-1" if host else region, "POST", "/", "", body,
            {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            host=host)
    except Exception as e:                                    # noqa: BLE001
        why = "timed out" if "timed out" in str(e).lower() else str(e)
        return {"error": f"{spec['action']}: {why}", "fields": [], "extras": [],
                "table": None}
    if code != 200:
        return {"error": cloud._aws_why(text, code), "fields": [], "extras": [],
                "table": None}

    root = tree(text)
    out = {"error": "", "fields": [], "extras": [], "table": None}
    kind = spec["reader"]

    def pairs(node, wanted):
        return [(label, n(node, tag)) for label, tag in wanted if n(node, tag)]

    def find(items, tag, value):
        return next((it for it in items if n(it, tag) == value), None)

    if kind == "instance":
        items = [it for iset in kids(root, "instancesSet")
                 for it in direct(iset, "item")]
        item = find(items, "instanceId", ident)
        if item is None:
            return {"error": f"{ident} was not found in {region}", "fields": [],
                    "extras": [], "table": None}
        out["fields"] = pairs(item, [
            ("instance id", "instanceId"), ("type", "instanceType"),
            ("image", "imageId"), ("architecture", "architecture"),
            ("platform", "platformDetails"), ("private IP", "privateIpAddress"),
            ("public IP", "ipAddress"), ("private DNS", "privateDnsName"),
            ("public DNS", "dnsName"), ("VPC", "vpcId"), ("subnet", "subnetId"),
            ("key pair", "keyName"), ("launched", "launchTime"),
            ("root device", "rootDeviceName"),
            ("virtualisation", "virtualizationType")])
        state = item.find("instanceState")
        if state is not None and n(state, "name"):
            out["fields"].insert(1, ("state", n(state, "name")))
        place = item.find("placement")
        if place is not None and n(place, "availabilityZone"):
            out["fields"].append(("zone", n(place, "availabilityZone")))
        tags = [(n(t, "key"), n(t, "value")) for ts in kids(item, "tagSet")
                for t in direct(ts, "item") if n(t, "key")]
        if tags:
            out["extras"].append({"label": "tags", "rows": tags, "note": ""})
        vols = []
        for bdm in kids(item, "blockDeviceMapping"):
            for v in direct(bdm, "item"):
                ebs = v.find("ebs")
                vols.append((n(v, "deviceName"),
                             f"{n(ebs, 'volumeId') if ebs is not None else ''} · "
                             f"{n(ebs, 'status') if ebs is not None else ''}"))
        if vols:
            out["extras"].append({"label": "attached volumes", "rows": vols,
                                  "note": ""})
        sgs = [(n(g, "groupId"), n(g, "groupName"))
               for gs in kids(item, "groupSet") for g in direct(gs, "item")
               if n(g, "groupId")]
        if sgs:
            out["extras"].append({"label": "security groups", "rows": sgs,
                                  "note": ""})

    elif kind == "secgroup":
        items = [it for info in (kids(root, "securityGroupInfo") or [root])
                 for it in direct(info, "item")]
        item = find(items, "groupId", ident)
        if item is None:
            return {"error": f"{ident} was not found in {region}", "fields": [],
                    "extras": [], "table": None}
        out["fields"] = pairs(item, [
            ("group id", "groupId"), ("name", "groupName"),
            ("description", "groupDescription"), ("VPC", "vpcId"),
            ("owner", "ownerId")])
        rules = []
        for direction, tag in (("ingress", "ipPermissions"),
                               ("egress", "ipPermissionsEgress")):
            for perms in direct(item, tag):
                for perm in direct(perms, "item"):
                    proto = n(perm, "ipProtocol")
                    frm, to = n(perm, "fromPort"), n(perm, "toPort")
                    sources = [n(r, "cidrIp") for rs in direct(perm, "ipRanges")
                               for r in direct(rs, "item") if n(r, "cidrIp")]
                    sources += [n(g, "groupId") for gs in direct(perm, "groups")
                                for g in direct(gs, "item") if n(g, "groupId")]
                    for src in sources or [""]:
                        rules.append({
                            "direction": direction,
                            "protocol": "all" if proto == "-1" else proto,
                            "ports": f"{frm}-{to}" if frm else "all",
                            "source": src, "why": n(perm, "description")})
        out["table"] = {"label": "rules", "rows": rules}

    elif kind == "vpc":
        items = [it for vs in (kids(root, "vpcSet") or [root])
                 for it in direct(vs, "item")]
        item = find(items, "vpcId", ident)
        out["fields"] = pairs(item, [
            ("VPC id", "vpcId"), ("CIDR", "cidrBlock"), ("state", "state"),
            ("tenancy", "instanceTenancy"), ("default", "isDefault"),
            ("DHCP options", "dhcpOptionsId"), ("owner", "ownerId")]) \
            if item is not None else []

    elif kind == "subnet":
        items = [it for ss in (kids(root, "subnetSet") or [root])
                 for it in direct(ss, "item")]
        item = find(items, "subnetId", ident)
        out["fields"] = pairs(item, [
            ("subnet id", "subnetId"), ("CIDR", "cidrBlock"),
            ("free addresses", "availableIpAddressCount"),
            ("zone", "availabilityZone"), ("VPC", "vpcId"), ("state", "state"),
            ("public IP on launch", "mapPublicIpOnLaunch"),
            ("owner", "ownerId")]) if item is not None else []

    elif kind == "volume":
        items = [it for vs in (kids(root, "volumeSet") or [root])
                 for it in direct(vs, "item")]
        item = find(items, "volumeId", ident)
        if item is None:
            return {"error": f"{ident} was not found in {region}", "fields": [],
                    "extras": [], "table": None}
        out["fields"] = pairs(item, [
            ("volume id", "volumeId"), ("size (GiB)", "size"),
            ("type", "volumeType"), ("IOPS", "iops"),
            ("throughput", "throughput"), ("state", "status"),
            ("encrypted", "encrypted"), ("zone", "availabilityZone"),
            ("created", "createTime"), ("from snapshot", "snapshotId")])
        att = []
        for aset in direct(item, "attachmentSet"):
            for a in direct(aset, "item"):
                att.append((n(a, "instanceId"),
                            f"{n(a, 'device')} · {n(a, 'status')}"
                            + (" · deletes with the instance"
                               if n(a, "deleteOnTermination") == "true" else "")))
        if att:
            out["extras"].append({"label": "attached to", "rows": att, "note": ""})

    elif kind == "rds":
        item = find(kids(root, "DBInstance"), "DBInstanceIdentifier", ident)
        if item is None:
            return {"error": f"{ident} was not found in {region}", "fields": [],
                    "extras": [], "table": None}
        out["fields"] = pairs(item, [
            ("instance", "DBInstanceIdentifier"), ("engine", "Engine"),
            ("version", "EngineVersion"), ("class", "DBInstanceClass"),
            ("status", "DBInstanceStatus"), ("storage (GiB)", "AllocatedStorage"),
            ("storage type", "StorageType"), ("multi-AZ", "MultiAZ"),
            ("public", "PubliclyAccessible"), ("zone", "AvailabilityZone"),
            ("created", "InstanceCreateTime"),
            ("backup retention (days)", "BackupRetentionPeriod"),
            ("maintenance window", "PreferredMaintenanceWindow"),
            ("master user", "MasterUsername")])
        endpoint = item.find("Endpoint")
        if endpoint is not None and n(endpoint, "Address"):
            out["fields"].append(("endpoint", f"{n(endpoint, 'Address')}:"
                                              f"{n(endpoint, 'Port')}"))
        sgs = [(n(g, "VpcSecurityGroupId"), n(g, "Status"))
               for g in kids(item, "VpcSecurityGroupMembership")
               if n(g, "VpcSecurityGroupId")]
        if sgs:
            out["extras"].append({"label": "security groups", "rows": sgs,
                                  "note": ""})

    elif kind == "iam_user":
        item = root.find(".//User") if root is not None else None
        out["fields"] = pairs(item, [
            ("user", "UserName"), ("id", "UserId"), ("ARN", "Arn"),
            ("path", "Path"), ("created", "CreateDate"),
            ("password last used", "PasswordLastUsed")]) \
            if item is not None else []
        # three independent lookups: in series they are three round trips to a
        # global endpoint, which is most of the time this page took
        from .fleet import _pmap

        def ask(job):
            label, action, cols = job
            try:
                c2, t2 = cloud.aws_signed(
                    conn, "iam", "us-east-1", "POST", "/", "",
                    f"Action={action}&Version=2010-05-08&UserName="
                    + urllib.parse.quote(ident, safe=""),
                    {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                    host=cloud.AWS_GLOBAL["iam"])
            except Exception as e:                            # noqa: BLE001
                return {"label": label, "rows": [],
                        "note": ("timed out" if "timed out" in str(e).lower()
                                 else str(e))}
            if c2 != 200:
                return {"label": label, "rows": [],
                        "note": cloud._aws_why(t2, c2)}
            sub = tree(t2)
            return {"label": label, "rows": [(n(m, cols[0]), n(m, cols[1]))
                                             for m in kids(sub, "member")
                                             if n(m, cols[0])], "note": ""}

        jobs = [("attached policies", "ListAttachedUserPolicies",
                 ("PolicyName", "PolicyArn")),
                ("access keys", "ListAccessKeys", ("AccessKeyId", "Status")),
                ("groups", "ListGroupsForUser", ("GroupName", "Arn"))]
        out["extras"] += [got for got in (_pmap(ask, jobs, workers=3) or [])
                          if got]
    return out


def _aws_bucket_detail(conn: dict, bucket: str, region: str) -> dict:
    """Where a bucket lives, and whether it is public.

    Two calls, and the second one matters: "is this bucket public" is the
    question worth answering on sight.
    """
    n, tree = cloud._n, cloud._aws_tree
    fields, notes = [], []
    loc = "us-east-1"
    try:
        code, text = cloud.aws_signed(conn, "s3", "us-east-1", "GET",
                                      f"/{bucket}", "location=", "",
                                      host=cloud.AWS_GLOBAL["s3"])
        if code == 200:
            got = n(tree(text), "LocationConstraint")
            loc = got or "us-east-1"
            fields.append(("region", loc))
    except Exception as e:                                    # noqa: BLE001
        notes.append(str(e))

    host = f"s3.{loc}.amazonaws.com"
    for label, query, tags in (
            ("public access", "publicAccessBlock=",
             [("block public ACLs", "BlockPublicAcls"),
              ("ignore public ACLs", "IgnorePublicAcls"),
              ("block public policy", "BlockPublicPolicy"),
              ("restrict public buckets", "RestrictPublicBuckets")]),
            ("versioning", "versioning=", [("versioning", "Status"),
                                           ("MFA delete", "MfaDelete")]),
            ("encryption", "encryption=",
             [("default encryption", "SSEAlgorithm"),
              ("KMS key", "KMSMasterKeyID")])):
        try:
            code, text = cloud.aws_signed(conn, "s3", loc, "GET", f"/{bucket}",
                                          query, "", host=host)
        except Exception as e:                                # noqa: BLE001
            notes.append(f"{label}: {e}")
            continue
        if code != 200:
            if code == 404 and "encryption" in query:
                fields.append(("default encryption", "none"))
            continue
        parsed = tree(text)
        for name, tag in tags:
            val = n(parsed, tag)
            if val:
                fields.append((name, val))
    return {"error": "", "fields": fields, "table": None,
            "extras": ([{"label": "not readable", "rows": [],
                         "note": "; ".join(notes)}] if notes else [])}


# A resource's own attributes change slowly, and some endpoints are slow to ask:
# ram.aliyuncs.com takes seconds from some networks. A minute of cache makes
# going back to a page you just left instant, which is most of the navigating
# anyone does.
_DETAIL_CACHE: dict = {}
_DETAIL_TTL = 60.0


def detail(conn: dict, group: str, ident: str, region: str,
           refresh: bool = False) -> dict:
    """{fields, extras, table, actions} for one resource, or an error."""
    key = (conn.get("id"), group, ident, region)
    hit = _DETAIL_CACHE.get(key)
    if hit and not refresh and time.time() - hit[0] < _DETAIL_TTL:
        return hit[1]
    got = _detail(conn, group, ident, region)
    # a failed lookup is not worth remembering; the next visit should retry
    if not got.get("error"):
        _DETAIL_CACHE[key] = (time.time(), got)
    return got


def _detail(conn: dict, group: str, ident: str, region: str) -> dict:
    if conn.get("type") == "aws":
        return _aws_detail(conn, group, ident, region)
    if group == "oss":
        # OSS signs like S3 rather than speaking RPC, so it cannot be a row in
        # ALI_DETAILS — it has its own reader in cloud.py
        got = cloud.alibaba_bucket_detail(conn, ident, region)
        return {"error": "", "fields": got["fields"], "table": None,
                "extras": ([{"label": "not readable", "rows": [],
                             "note": "; ".join(got["notes"])}]
                           if got["notes"] else [])}
    spec = ALI_DETAILS.get(group)
    if not spec:
        return {"error": f"no detail view for {group}", "fields": [],
                "extras": [], "table": None}
    host_prefix, version = spec["product"]
    host = (host_prefix if "." in host_prefix
            else f"{host_prefix}.{region}.aliyuncs.com")
    value = f'["{ident}"]' if spec.get("quote") else ident
    # a slow endpoint must produce a message, not a traceback: ram.aliyuncs.com
    # times out often enough that an unwrapped call took the whole page down
    try:
        code, doc = cloud._alibaba_rpc(conn, spec["action"], version, host,
                                       region, {spec["id_param"]: value})
    except Exception as e:                                    # noqa: BLE001
        why = "timed out" if "timed out" in str(e).lower() else str(e)
        return {"error": f"{spec['action']}: {why}", "fields": [], "extras": [],
                "table": None}
    if code != 200:
        return {"error": cloud._ali_why(doc, code), "fields": [], "extras": [],
                "table": None}
    out = {"error": "", "fields": spec["fields"](doc), "extras": [],
           "table": None}
    if spec.get("table"):
        label, reader = spec["table"]
        out["table"] = {"label": label, "rows": reader(doc)}
    extras = spec.get("extras", [])
    if extras:
        from .fleet import _pmap

        def ask(job):
            label, (prefix, ver), action, id_param, reader = job
            h = prefix if "." in prefix else f"{prefix}.{region}.aliyuncs.com"
            try:
                c2, d2 = cloud._alibaba_rpc(conn, action, ver, h, region,
                                            {id_param: ident})
            except Exception as e:                            # noqa: BLE001
                return {"label": label, "rows": [],
                        "note": ("timed out" if "timed out" in str(e).lower()
                                 else str(e))}
            if c2 != 200:
                return {"label": label, "rows": [],
                        "note": cloud._ali_why(d2, c2)}
            try:
                return {"label": label, "rows": reader(d2), "note": ""}
            except Exception as e:                            # noqa: BLE001
                return {"label": label, "rows": [],
                        "note": f"unexpected shape ({type(e).__name__})"}

        out["extras"] += [got for got in
                          (_pmap(ask, extras, workers=min(4, len(extras))) or [])
                          if got]
    return out
