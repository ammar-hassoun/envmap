"""Cloud accounts: registered once, verified against the provider's own API.

WHAT "CONNECTED" MEANS HERE
    A connection is a set of credentials the portal has *proven* by asking the
    cloud who they belong to — AWS STS GetCallerIdentity, an Azure AD token
    grant, Alibaba's GetCallerIdentity. The status line shows the identity the
    cloud reported, so a pasted key for the wrong account is caught at Save,
    not during an incident.

WHAT IT DELIBERATELY IS NOT
    Not a multi-cloud management console. The portal registers and verifies
    accounts; what to *do* with them grows per need (and per provider) from
    here. Verification is also the riskiest thing to fake: a page that says
    "connected" without having asked the cloud is worse than no page.

NO SDKS, STATED PLAINLY
    Every check is a plain HTTPS request built with the standard library:
    - AWS: Signature V4 is HMAC-SHA256, implemented below (~40 lines).
    - Azure: the client-credentials grant is one form POST.
    - Alibaba: RPC-style HMAC-SHA1 signing, also stdlib.
    - Google Cloud: the exception. Its service accounts sign JWTs with RSA,
      which the standard library cannot do. The portal validates the pasted
      service-account JSON thoroughly (shape, key markers, expected fields)
      and says exactly that in the status — "stored, structure valid, not
      verified against Google". Anything stronger needs the `cryptography`
      package; the check function says so rather than pretending.
    Adding a provider is a PROVIDERS entry plus one check function.
"""
import base64
import datetime
import difflib
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import urlguard

TIMEOUT = 15

PROVIDERS = {
    "aws": {
        "label": "AWS",
        "icon": "🟧",
        "needs": ["key_id", "secret"],
        "fields": {"key_id": "Access key ID", "secret": "Secret access key",
                   "region": "Region id, e.g. eu-west-1 — resources are read "
                             "from this one, and you can switch on the page"},
        "auth": "IAM access key — a dedicated read-only user is enough",
        "note": "Read-only across EC2, EBS, VPC, ELB, RDS, ElastiCache, S3, "
                "ECR, Lambda, EKS and IAM, with cost history from Cost Explorer "
                "— ReadOnlyAccess covers all of it, and Cost Explorer also has "
                "to be switched on once in the Billing console. "
                "Verified with STS GetCallerIdentity, the canonical "
                "\"who am I\" call: it needs no permissions at all and returns "
                "the account and ARN these keys belong to.",
    },
    "azure": {
        "label": "Azure",
        "icon": "🔷",
        "needs": ["tenant", "key_id", "secret"],
        "fields": {"tenant": "Tenant ID", "key_id": "Application (client) ID",
                   "secret": "Client secret",
                   "region": "Subscription ID (optional)"},
        "auth": "App registration with a client secret",
        "note": "Verified by acquiring a management-plane token with the "
                "client-credentials grant; with a subscription ID it also "
                "confirms the app can see that subscription.",
    },
    "alibaba": {
        "label": "Alibaba Cloud",
        "icon": "🟠",
        "needs": ["key_id", "secret"],
        "fields": {"key_id": "AccessKey ID", "secret": "AccessKey Secret",
                   "region": "Region id, e.g. me-central-1 — a name like "
                             "\u201cSAU\u201d or \u201cRiyadh\u201d is resolved"},
        "auth": "RAM AccessKey — a dedicated read-only RAM user is enough",
        "note": "Verified with STS GetCallerIdentity against "
                "sts.aliyuncs.com, signed the RPC way (HMAC-SHA1).",
    },
    "gcp": {
        "label": "Google Cloud",
        "icon": "🔴",
        "needs": ["secret"],
        "fields": {"secret": "Service-account JSON (paste the whole file)",
                   "region": "Project ID (optional — read from the JSON)"},
        "auth": "service-account key file",
        "note": "Stored and structurally validated. Google's service accounts "
                "sign JWTs with RSA, which this portal's no-dependency rule "
                "cannot do — so the status says \"structure valid, not "
                "verified against Google\", and means it.",
    },
    "other": {
        "label": "Other cloud / API",
        "icon": "☁️",
        "needs": ["base_url"],
        "fields": {"base_url": "API endpoint URL", "key_id": "Username (optional)",
                   "secret": "Token / password (optional)"},
        "auth": "bearer token or basic auth",
        "note": "Any provider with an HTTP API — DigitalOcean, Hetzner, "
                "OpenStack Keystone… The check calls the endpoint with the "
                "credential and reports what came back.",
    },
}


class CloudError(Exception):
    pass


# A transient failure is not an answer. Firing twenty products at once earns the
# occasional reset or handshake timeout from the far end, and reporting that as
# "RDS could not be read" sends someone to check permissions on a working
# account. One retry, briefly delayed, turns nearly all of them into answers.
TRANSIENT = ("connection reset", "timed out", "timeout", "broken pipe",
             "connection refused", "temporarily unavailable", "eof occurred",
             # a name that would not resolve a second ago usually resolves now:
             # a laptop waking up, a VPN reconnecting, a flaky resolver
             "nodename nor servname", "name or service not known",
             "temporary failure in name resolution", "getaddrinfo")


def _get(url: str, headers: dict | None = None, data: bytes | None = None,
         tries: int = 2):
    last = None
    for attempt in range(max(1, tries)):
        req = urllib.request.Request(
            urlguard.check(url), data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.getcode(), r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            # an HTTP error IS an answer — the far end replied, so do not retry
            return e.code, e.read().decode(errors="replace")
        except Exception as e:                                # noqa: BLE001
            last = e
            if attempt + 1 >= tries or not any(
                    t in str(e).lower() for t in TRANSIENT):
                raise
            time.sleep(0.4 * (attempt + 1))
    raise last if last else RuntimeError("request failed")


# ── AWS: Signature V4, stdlib only ─────────────────────────────
def aws_signed(c: dict, service: str, region: str, method: str = "POST",
               path: str = "/", query: str = "", body: str = "",
               headers: dict | None = None, host: str = "") -> tuple[int, str]:
    """One signed request to any AWS API, whatever shape it takes.

    AWS speaks four dialects and the portal needs all of them: the query
    protocol with a form body (EC2, ELB, RDS, IAM), REST with JSON (Lambda,
    EKS), REST with XML (S3), and JSON-RPC with an X-Amz-Target header (Cost
    Explorer). They differ only in method, path and headers — the signature is
    the same four HMACs either way, so it is signed in one place rather than
    once per service.
    """
    region = (region or c.get("region") or "us-east-1").strip()
    host = host or f"{service}.{region}.amazonaws.com"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    stamp = now.strftime("%Y%m%d")

    send = {k.lower(): v for k, v in (headers or {}).items()}
    send["host"] = host
    send["x-amz-date"] = amz_date
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    if service == "s3":
        # S3 insists the payload hash is also a header, signed
        send["x-amz-content-sha256"] = payload_hash

    signed_names = ";".join(sorted(send))
    canonical_headers = "".join(f"{k}:{send[k]}\n" for k in sorted(send))
    canonical = "\n".join([method, path, query, canonical_headers,
                            signed_names, payload_hash])
    scope = f"{stamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                          hashlib.sha256(canonical.encode()).hexdigest()])

    def _h(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = _h(("AWS4" + c["secret"]).encode(), stamp)
    for part in (region, service, "aws4_request"):
        k = _h(k, part)
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()

    out = {k: v for k, v in (headers or {}).items()}
    out["X-Amz-Date"] = amz_date
    if service == "s3":
        out["X-Amz-Content-Sha256"] = payload_hash
    if c.get("session_token"):
        out["X-Amz-Security-Token"] = c["session_token"]
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={c['key_id']}/{scope}, "
                            f"SignedHeaders={signed_names}, Signature={sig}")
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return _get(url, headers=out, data=body.encode() if body else None)


def aws_call(c: dict, service: str, body: str, region: str = "") -> tuple[int, str]:
    """A signed POST to a query-protocol API (STS, EC2, ELB, RDS, IAM).

    Kept as its own name because most call sites are this shape, but it is one
    line over aws_signed now — there was a second copy of the signature before,
    and two copies of a signing routine is one too many.
    """
    region = (region or c.get("region") or "us-east-1").strip()
    host = (f"sts.{region}.amazonaws.com" if service == "sts"
            else f"{service}.{region}.amazonaws.com")
    return aws_signed(
        c, service, region, "POST", "/", "", body,
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        host=host)


def _aws_check(c: dict) -> tuple[bool, str]:
    code, text = aws_call(c, "sts", "Action=GetCallerIdentity&Version=2011-06-15")
    if code == 200 and "<Arn>" in text:
        arn = text.split("<Arn>")[1].split("</Arn>")[0]
        acct = text.split("<Account>")[1].split("</Account>")[0] \
            if "<Account>" in text else "?"
        return True, f"account {acct} — {arn}"
    if "SignatureDoesNotMatch" in text or "InvalidClientTokenId" in text:
        return False, "AWS refused the keys — check the ID and secret"
    return False, f"STS answered HTTP {code}"


# ── Azure: client-credentials grant ────────────────────────────
def _azure_check(c: dict) -> tuple[bool, str]:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": c["key_id"], "client_secret": c["secret"],
        "scope": "https://management.azure.com/.default"}).encode()
    code, text = _get(
        f"https://login.microsoftonline.com/"
        f"{urllib.parse.quote(c['tenant'])}/oauth2/v2.0/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body)
    if code != 200:
        try:
            why = json.loads(text).get("error_description", "").split("\n")[0]
        except json.JSONDecodeError:
            why = f"HTTP {code}"
        return False, f"Azure AD refused the credentials — {why[:160]}"
    token = json.loads(text).get("access_token", "")
    sub = (c.get("region") or "").strip()
    if not sub:
        return True, "Azure AD issued a management token for this app"
    code, text = _get(
        f"https://management.azure.com/subscriptions/"
        f"{urllib.parse.quote(sub)}?api-version=2022-12-01",
        headers={"Authorization": f"Bearer {token}"})
    if code == 200:
        name = json.loads(text).get("displayName", sub)
        return True, f"token issued, subscription “{name}” visible"
    return False, f"token issued, but subscription {sub} answered HTTP " \
                  f"{code} — grant the app Reader on it"


# ── Alibaba: RPC-style HMAC-SHA1 ───────────────────────────────
def _alibaba_check(c: dict) -> tuple[bool, str]:
    params = {
        "Action": "GetCallerIdentity", "Version": "2015-04-01",
        "Format": "JSON", "AccessKeyId": c["key_id"],
        "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0",
        "SignatureNonce": uuid.uuid4().hex,
        "Timestamp": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    def enc(s):
        return urllib.parse.quote(str(s), safe="~")
    canon = "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(params.items()))
    to_sign = "GET&%2F&" + enc(canon)
    sig = base64.b64encode(hmac.new((c["secret"] + "&").encode(),
                                    to_sign.encode(), hashlib.sha1)
                           .digest()).decode()
    code, text = _get("https://sts.aliyuncs.com/?" + canon
                      + "&Signature=" + enc(sig))
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return False, f"STS answered HTTP {code}, not JSON"
    if code == 200 and doc.get("AccountId"):
        return True, f"account {doc['AccountId']} — " \
                     f"{doc.get('Arn', doc.get('IdentityType', ''))}"
    return False, doc.get("Message", f"HTTP {code}")[:180]


# ── GCP: structural validation, honestly labelled ──────────────
def _gcp_check(c: dict) -> tuple[bool, str]:
    try:
        doc = json.loads(c["secret"])
    except json.JSONDecodeError:
        return False, "that is not JSON — paste the whole service-account file"
    missing = [k for k in ("type", "project_id", "private_key",
                           "client_email", "token_uri") if not doc.get(k)]
    if missing:
        return False, f"service-account JSON is missing: {', '.join(missing)}"
    if doc["type"] != "service_account":
        return False, f"this is a '{doc['type']}' credential, " \
                      "not a service account"
    if "BEGIN PRIVATE KEY" not in doc["private_key"]:
        return False, "the private_key field does not contain a key"
    return True, (f"ok: structure valid — {doc['client_email']} in project "
                  f"{doc['project_id']}. NOT verified against Google: "
                  "RSA signing needs a library this portal does not carry.")


def _other_check(c: dict) -> tuple[bool, str]:
    headers = {}
    if c.get("secret") and not c.get("key_id"):
        headers["Authorization"] = f"Bearer {c['secret']}"
    elif c.get("key_id"):
        cred = base64.b64encode(
            f"{c['key_id']}:{c.get('secret', '')}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"
    code, _ = _get(c["base_url"], headers=headers)
    if code < 400:
        return True, f"HTTP {code}"
    if code in (401, 403):
        return False, f"endpoint answers but refused the credential (HTTP {code})"
    return False, f"HTTP {code}"


CHECKS = {"aws": _aws_check, "azure": _azure_check,
          "alibaba": _alibaba_check, "gcp": _gcp_check, "other": _other_check}


def test(conn: dict) -> tuple[bool, str]:
    kind = conn.get("type", "")
    if kind not in CHECKS:
        return False, f"unknown provider '{kind}'"
    prov = PROVIDERS[kind]
    missing = [k for k in prov["needs"] if not (conn.get(k) or "").strip()]
    if missing:
        labels = prov["fields"]
        return False, "missing: " + ", ".join(labels.get(k, k) for k in missing)
    try:
        return CHECKS[kind](conn)
    except Exception as e:                                    # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


# ── inventory ──────────────────────────────────────────────────
# What each account actually contains, read live. Deliberately a *small*
# vocabulary — compute, storage, database, network, cluster — because the point
# is one comparable picture across four clouds, not a faithful mirror of each
# provider's console. A provider contributes whatever it can answer cheaply;
# what it cannot answer is absent and said to be absent, never invented.
INV_TTL = 180.0
_inv: dict = {}
_refreshing: set = set()


def _inv_key(conn: dict, region: str = "") -> tuple:
    """The cache key. In one place because it stopped being just the account id
    when regions arrived, and peek() was still using the old shape — so the hub
    page silently never found anything the warmer had collected."""
    return (conn.get("id") or conn.get("name", ""), region or "")


def _xml_all(text: str, tag: str) -> list[str]:
    """Every <tag>…</tag> body. AWS query APIs answer in XML and the shapes here
    are shallow, so this beats pulling in a parser for four fields."""
    out, needle, close = [], f"<{tag}>", f"</{tag}>"
    i = text.find(needle)
    while i >= 0:
        j = text.find(close, i)
        if j < 0:
            break
        out.append(text[i + len(needle):j])
        i = text.find(needle, j)
    return out


def _xml_one(text: str, tag: str) -> str:
    got = _xml_all(text, tag)
    return got[0] if got else ""


# ── AWS, the same shape as Alibaba ─────────────────────────────────────────
# The group keys are deliberately the ones the Alibaba sweep uses: "compute",
# "subnets", "secgroups", "buckets" and so on. Everything downstream — the tiles,
# the network diagram, the search index, CSV export, the deep pages, the action
# forms — keys off those, so AWS arrives with all of it working rather than
# needing a parallel set of pages.
#
# READ WITH A PARSER, NOT WITH string.find
#     The Alibaba side answers JSON and the older AWS code here sliced XML between
#     tags, which is fine for a flat document. EC2's is not flat: a reservation
#     holds instances, an instance holds a tagSet, and a tagSet holds <item>
#     elements — so slicing from "<item>" to the next "</item>" cut every instance
#     short at its first tag. ElementTree is in the standard library and knows
#     where an element ends.
def _aws_tree(text: str):
    """Parsed, with namespaces dropped so paths do not have to carry them.

    Every AWS XML response declares a namespace that includes the API version, so
    matching on qualified names would break the moment a version changed.
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.rsplit("}", 1)[1]
    return root


def _n(node, name: str) -> str:
    """The text of a named element: this one, or any below it.

    Checking the node itself matters more than it looks: S3 answers a bucket's
    region as <LocationConstraint>eu-west-1</LocationConstraint> and nothing else,
    so a descendants-only search reads it as empty and the bucket appears to have
    no region.
    """
    if node is None:
        return ""
    found = node if node.tag == name else node.find(f".//{name}")
    return (found.text or "").strip() if found is not None and found.text else ""


def _kids(node, name: str) -> list:
    return [] if node is None else node.findall(f".//{name}")


def _direct(node, name: str) -> list:
    """Only the immediate children with this name — needed where the same tag
    appears at two depths, as <item> does throughout EC2."""
    return [] if node is None else [el for el in node if el.tag == name]


def _aws_tags(node, want: str = "Name") -> str:
    for tagset in _kids(node, "tagSet"):
        for entry in _direct(tagset, "item"):
            if _n(entry, "key") == want:
                return _n(entry, "value")
    return ""


def _aws_rows_instances(text):
    root = _aws_tree(text)
    out = []
    for inst in _kids(root, "instancesSet"):
        for item in _direct(inst, "item"):
            iid = _n(item, "instanceId")
            if not iid:
                continue
            state = ""
            got = item.find("instanceState")
            if got is not None:
                state = _n(got, "name")
            place = item.find("placement")
            private, public = _n(item, "privateIpAddress"), _n(item, "ipAddress")
            out.append({
                "name": _aws_tags(item) or iid, "id": iid,
                "kind": _n(item, "instanceType"), "state": state,
                "extra": ", ".join(x for x in (private, public) if x),
                "zone": _n(place, "availabilityZone") if place is not None else ""})
    return out


def _aws_rows_volumes(text):
    root = _aws_tree(text)
    out = []
    for vset in _kids(root, "volumeSet") or [root]:
        for item in _direct(vset, "item"):
            vid = _n(item, "volumeId")
            if not vid:
                continue
            attached = ""
            for att in _kids(item, "attachmentSet"):
                attached = _n(att, "instanceId")
            out.append({"name": _aws_tags(item) or vid, "id": vid,
                        "kind": f"{_n(item, 'volumeType')} · "
                                f"{_n(item, 'size')} GiB",
                        "state": _n(item, "status"),
                        "extra": attached or "not attached",
                        "zone": _n(item, "availabilityZone")})
    return out


def _aws_rows_sgs(text):
    root = _aws_tree(text)
    out = []
    for info in _kids(root, "securityGroupInfo") or [root]:
        for item in _direct(info, "item"):
            gid = _n(item, "groupId")
            if not gid:
                continue
            out.append({"name": _n(item, "groupName") or gid, "id": gid,
                        "kind": "security group", "state": "",
                        "extra": _n(item, "vpcId"),
                        "zone": _n(item, "groupDescription")[:40]})
    return out


def _aws_rows_vpcs(text):
    root = _aws_tree(text)
    out = []
    for vset in _kids(root, "vpcSet") or [root]:
        for item in _direct(vset, "item"):
            vid = _n(item, "vpcId")
            if not vid:
                continue
            out.append({"name": _aws_tags(item) or vid, "id": vid,
                        "kind": _n(item, "cidrBlock"),
                        "state": _n(item, "state"),
                        "extra": ("default" if _n(item, "isDefault") == "true"
                                  else ""),
                        "zone": ""})
    return out


def _aws_rows_subnets(text):
    root = _aws_tree(text)
    out = []
    for sset in _kids(root, "subnetSet") or [root]:
        for item in _direct(sset, "item"):
            sid = _n(item, "subnetId")
            if not sid:
                continue
            out.append({"name": _aws_tags(item) or sid, "id": sid,
                        "kind": _n(item, "cidrBlock"),
                        "state": _n(item, "state"),
                        "extra": f"{_n(item, 'availableIpAddressCount')} free IPs "
                                 f"· {_n(item, 'vpcId')}",
                        "zone": _n(item, "availabilityZone")})
    return out


def _aws_rows_eips(text):
    root = _aws_tree(text)
    out = []
    for aset in _kids(root, "addressesSet") or [root]:
        for item in _direct(aset, "item"):
            ip = _n(item, "publicIp")
            if not ip:
                continue
            inst = _n(item, "instanceId")
            out.append({"name": _aws_tags(item) or ip,
                        "id": _n(item, "allocationId") or ip,
                        "kind": _n(item, "domain"), "state": "",
                        "extra": f"{ip} → {inst or 'unbound'}",
                        "zone": _n(item, "associationId")})
    return out


def _aws_rows_nat(text):
    root = _aws_tree(text)
    out = []
    for nset in _kids(root, "natGatewaySet") or [root]:
        for item in _direct(nset, "item"):
            nid = _n(item, "natGatewayId")
            if not nid:
                continue
            out.append({"name": _aws_tags(item) or nid, "id": nid,
                        "kind": _n(item, "connectivityType") or "public",
                        "state": _n(item, "state"),
                        "extra": _n(item, "vpcId"),
                        "zone": _n(item, "subnetId")})
    return out


def _aws_rows_routetables(text):
    root = _aws_tree(text)
    out = []
    for rset in _kids(root, "routeTableSet") or [root]:
        for item in _direct(rset, "item"):
            rid = _n(item, "routeTableId")
            if not rid:
                continue
            routes = sum(len(_direct(rs, "item")) for rs in _kids(item, "routeSet"))
            out.append({"name": _aws_tags(item) or rid, "id": rid,
                        "kind": "route table", "state": "",
                        "extra": f"{_n(item, 'vpcId')} · {routes} routes",
                        "zone": ""})
    return out


def _aws_rows_snapshots(text):
    root = _aws_tree(text)
    out = []
    for sset in _kids(root, "snapshotSet") or [root]:
        for item in _direct(sset, "item"):
            sid = _n(item, "snapshotId")
            if not sid:
                continue
            out.append({"name": _aws_tags(item) or sid, "id": sid,
                        "kind": f"{_n(item, 'volumeSize')} GiB",
                        "state": _n(item, "status"),
                        "extra": _n(item, "volumeId") or "source gone",
                        "zone": _n(item, "startTime")[:10]})
    return out


def _aws_rows_images(text):
    root = _aws_tree(text)
    out = []
    for iset in _kids(root, "imagesSet") or [root]:
        for item in _direct(iset, "item"):
            iid = _n(item, "imageId")
            if not iid:
                continue
            out.append({"name": _n(item, "name") or _aws_tags(item) or iid,
                        "id": iid,
                        "kind": f"{_n(item, 'architecture')} · "
                                f"{_n(item, 'rootDeviceType')}",
                        "state": _n(item, "imageState"),
                        "extra": _n(item, "description")[:50],
                        "zone": _n(item, "creationDate")[:10]})
    return out


def _aws_rows_keypairs(text):
    root = _aws_tree(text)
    out = []
    for kset in _kids(root, "keySet") or [root]:
        for item in _direct(kset, "item"):
            name = _n(item, "keyName")
            if name:
                out.append({"name": name, "id": name, "kind": "key pair",
                            "state": "",
                            "extra": _n(item, "keyFingerprint")[:32],
                            "zone": _n(item, "createTime")[:10]})
    return out


def _aws_rows_elbv2(text):
    root = _aws_tree(text)
    out = []
    for item in _kids(root, "member"):
        arn = _n(item, "LoadBalancerArn")
        if not arn:
            continue
        state = item.find("State")
        out.append({"name": _n(item, "LoadBalancerName") or arn, "id": arn,
                    "kind": f"{_n(item, 'Type').upper()} · {_n(item, 'Scheme')}",
                    "state": _n(state, "Code") if state is not None else "",
                    "extra": _n(item, "DNSName"), "zone": _n(item, "VpcId")})
    return out


def _aws_rows_rds(text):
    root = _aws_tree(text)
    out = []
    for item in _kids(root, "DBInstance"):
        ident = _n(item, "DBInstanceIdentifier")
        if not ident:
            continue
        endpoint = item.find("Endpoint")
        out.append({"name": ident, "id": ident,
                    "kind": f"{_n(item, 'Engine')} {_n(item, 'EngineVersion')} · "
                            f"{_n(item, 'DBInstanceClass')}",
                    "state": _n(item, "DBInstanceStatus"),
                    "extra": (_n(endpoint, "Address") if endpoint is not None
                              else ""),
                    "zone": _n(item, "AvailabilityZone")})
    return out


def _aws_rows_iam_users(text):
    root = _aws_tree(text)
    return [{"name": _n(m, "UserName"), "id": _n(m, "UserId"), "kind": "user",
             "state": "", "extra": _n(m, "Arn"),
             "zone": _n(m, "CreateDate")[:10]}
            for m in _kids(root, "member") if _n(m, "UserName")]


def _aws_rows_iam_roles(text):
    root = _aws_tree(text)
    return [{"name": _n(m, "RoleName"), "id": _n(m, "RoleId"), "kind": "role",
             "state": "", "extra": _n(m, "Description")[:60] or _n(m, "Arn"),
             "zone": _n(m, "CreateDate")[:10]}
            for m in _kids(root, "member") if _n(m, "RoleName")]


def _aws_rows_iam_policies(text):
    root = _aws_tree(text)
    return [{"name": _n(m, "PolicyName"), "id": _n(m, "PolicyId"),
             "kind": "customer managed", "state": "",
             "extra": f"attached to {_n(m, 'AttachmentCount') or '0'}",
             "zone": _n(m, "UpdateDate")[:10]}
            for m in _kids(root, "member") if _n(m, "PolicyName")]


def _aws_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _aws_rows_ecr(text):
    """Container repositories. ECR is JSON-RPC, not the query protocol — which is
    why it was missing: it could not be a row in a table that only spoke one
    dialect."""
    out = []
    for r in _aws_json(text).get("repositories") or []:
        name = r.get("repositoryName") or ""
        if not name:
            continue
        enc = (r.get("encryptionConfiguration") or {}).get("encryptionType", "")
        scan = (r.get("imageScanningConfiguration") or {}).get("scanOnPush")
        created = r.get("createdAt")
        when = ""
        if isinstance(created, (int, float)):
            when = datetime.datetime.fromtimestamp(
                created, datetime.timezone.utc).date().isoformat()
        out.append({
            "name": name, "id": name,
            "kind": f"{r.get('imageTagMutability', '')}"
                    + (f" · {enc}" if enc else ""),
            "state": "scan on push" if scan else "",
            "extra": r.get("repositoryUri", ""), "zone": when})
    out.sort(key=lambda r: r["name"])
    return out


def _aws_rows_lambda(text):
    out = []
    for f in _aws_json(text).get("Functions") or []:
        name = f.get("FunctionName") or ""
        if not name:
            continue
        out.append({"name": name, "id": name,
                    "kind": f"{f.get('Runtime', '')} · {f.get('MemorySize', '?')} MB",
                    "state": f.get("State", ""),
                    "extra": f"{f.get('Timeout', '?')}s timeout · "
                             f"{round((f.get('CodeSize') or 0) / 1048576, 1)} MB",
                    "zone": (f.get("LastModified") or "")[:10]})
    out.sort(key=lambda r: r["name"])
    return out


def _aws_rows_eks(text):
    return [{"name": name, "id": name, "kind": "Kubernetes", "state": "",
             "extra": "", "zone": ""}
            for name in _aws_json(text).get("clusters") or []]


def _aws_rows_elasticache(text):
    root = _aws_tree(text)
    out = []
    for item in _kids(root, "CacheCluster"):
        cid = _n(item, "CacheClusterId")
        if not cid:
            continue
        endpoint = item.find(".//ConfigurationEndpoint")
        out.append({"name": cid, "id": cid,
                    "kind": f"{_n(item, 'Engine')} {_n(item, 'EngineVersion')} · "
                            f"{_n(item, 'CacheNodeType')}",
                    "state": _n(item, "CacheClusterStatus"),
                    "extra": (_n(endpoint, "Address") if endpoint is not None
                              else ""),
                    "zone": _n(item, "PreferredAvailabilityZone")})
    return out


# (group key, label, icon, service, api version, action, extra params, reader,
#  protocol)
#
# Protocol matters because AWS does not have one. Most of these are the query
# protocol — a form body, XML back. ECR and Lambda and EKS are not, and leaving
# them out because the table only spoke one dialect is exactly why an account
# whose bill says "EC2 Container Registry" showed no registry at all.
# A "global" service carries its own host: IAM answers only at iam.amazonaws.com,
# and asking it in eu-west-1 fails in a way that looks like a permission problem.
AWS_PRODUCTS = [
    ("compute", "EC2 instances", "🖥", "ec2", "2016-11-15",
     "DescribeInstances", {}, _aws_rows_instances),
    ("disks", "EBS volumes", "💽", "ec2", "2016-11-15",
     "DescribeVolumes", {}, _aws_rows_volumes),
    ("secgroups", "Security groups", "🛡", "ec2", "2016-11-15",
     "DescribeSecurityGroups", {}, _aws_rows_sgs),
    ("vpcs", "VPCs", "🕸", "ec2", "2016-11-15", "DescribeVpcs", {},
     _aws_rows_vpcs),
    ("subnets", "Subnets", "🔀", "ec2", "2016-11-15", "DescribeSubnets", {},
     _aws_rows_subnets),
    ("eips", "Elastic IPs", "🌐", "ec2", "2016-11-15", "DescribeAddresses", {},
     _aws_rows_eips),
    ("nat", "NAT gateways", "↔", "ec2", "2016-11-15", "DescribeNatGateways", {},
     _aws_rows_nat),
    ("routetables", "Route tables", "🧭", "ec2", "2016-11-15",
     "DescribeRouteTables", {}, _aws_rows_routetables),
    ("snapshots", "Snapshots", "📸", "ec2", "2016-11-15", "DescribeSnapshots",
     {"Owner.1": "self", "MaxResults": "100"}, _aws_rows_snapshots),
    ("images", "AMIs (yours)", "💿", "ec2", "2016-11-15", "DescribeImages",
     {"Owner.1": "self"}, _aws_rows_images),
    ("keypairs", "Key pairs", "🔐", "ec2", "2016-11-15", "DescribeKeyPairs", {},
     _aws_rows_keypairs),
    ("clb", "Load balancers", "⚖", "elasticloadbalancing", "2015-12-01",
     "DescribeLoadBalancers", {}, _aws_rows_elbv2),
    ("rds", "RDS databases", "🗃", "rds", "2014-10-31", "DescribeDBInstances",
     {}, _aws_rows_rds),
    ("iam_users", "IAM users", "👤", "iam", "2010-05-08", "ListUsers", {},
     _aws_rows_iam_users),
    ("iam_roles", "IAM roles", "🎭", "iam", "2010-05-08", "ListRoles", {},
     _aws_rows_iam_roles),
    ("iam_policies", "IAM policies (yours)", "📜", "iam", "2010-05-08",
     "ListPolicies", {"Scope": "Local"}, _aws_rows_iam_policies),
    ("redis", "ElastiCache", "⚡", "elasticache", "2015-02-02",
     "DescribeCacheClusters", {}, _aws_rows_elasticache),
    # JSON-RPC and REST, which the query protocol cannot carry
    ("registry", "ECR repositories", "📦", "ecr", "2015-09-21",
     "DescribeRepositories", {}, _aws_rows_ecr,
     ("json", "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories")),
    ("functions", "Lambda functions", "λ", "lambda", "2015-03-31",
     "ListFunctions", {}, _aws_rows_lambda, ("rest", "/2015-03-31/functions")),
    ("k8s", "EKS clusters", "☸", "eks", "2017-11-01", "ListClusters", {},
     _aws_rows_eks, ("rest", "/clusters")),
]

# Services with one endpoint for the whole account, whatever region is on screen.
AWS_GLOBAL = {"iam": "iam.amazonaws.com", "s3": "s3.amazonaws.com",
              "ce": "ce.us-east-1.amazonaws.com"}

AWS_WORDS = {
    "compute": "ec2 instance instances vm vms server servers box",
    "disks": "ebs volume volumes disk disks storage",
    "secgroups": "sg security group groups firewall rules ingress port",
    "vpcs": "vpc vpcs network networks cidr",
    "subnets": "subnet subnets cidr zone az address",
    "eips": "eip elastic ip public address",
    "nat": "nat gateway natgw",
    "routetables": "route routes table routing",
    "snapshots": "snapshot snapshots backup",
    "images": "ami amis image images template",
    "keypairs": "key keypair keypairs ssh pem",
    "clb": "elb alb nlb load balancer balancers lb target",
    "rds": "rds database databases db postgres postgresql mysql aurora",
    "iam_users": "iam user users account identity people",
    "iam_roles": "iam role roles assume sts trust",
    "iam_policies": "iam policy policies permission permissions",
    "buckets": "s3 bucket buckets object storage static",
    "registry": "ecr acr registry repository repositories docker image container "
                "images push pull",
    "functions": "lambda function functions serverless",
    "k8s": "eks kubernetes cluster clusters k8s node group",
    "billing": "bill bills billing cost costs spend explorer invoice money",
}


def _merge_words() -> None:
    """Fold the AWS vocabulary into the shared one.

    The group keys are deliberately the same across providers, so the search box
    can have one table: "ecs" and "ec2" both lead to compute, "oss" and "s3" both
    to buckets.
    """
    for key, words in AWS_WORDS.items():
        SERVICE_WORDS[key] = (SERVICE_WORDS.get(key, "") + " " + words).strip()


# Resources addressed by name rather than by an opaque id: a bucket, an IAM or
# RAM user. Their APIs take the name, so the page has to use it as the identity.
NAME_KEYED = ("ram_users", "iam_users", "oss", "buckets")
BUCKET_KEYS = ("oss", "buckets")


def aws_regions(c: dict) -> list[dict]:
    """Regions this account can use, from EC2 itself. Never raises, for the same
    reason the Alibaba one does not: everything else depends on it."""
    key = ("aws", c.get("key_id", ""))
    now = time.time()
    if key in _ALI_REGIONS and now - _ALI_REGIONS[key][0] < _ALI_TTL:
        return _ALI_REGIONS[key][1]
    try:
        code, text = aws_call(c, "ec2", "Action=DescribeRegions&Version=2016-11-15",
                              c.get("region") or "us-east-1")
    except Exception:                                         # noqa: BLE001
        return _ALI_REGIONS.get(key, (0, []))[1]
    if code != 200:
        return _ALI_REGIONS.get(key, (0, []))[1]
    rows = []
    for item in _xml_all(_xml_one(text, "regionInfo") or text, "item"):
        rid = _xml_one(item, "regionName")
        if rid:
            rows.append({"id": rid, "name": rid,
                         "endpoint": _xml_one(item, "regionEndpoint")})
    if rows:
        _ALI_REGIONS[key] = (now, rows)
    return rows


def aws_buckets(c: dict) -> tuple[list, str]:
    """S3 buckets, account-wide. ListBuckets is global and answers XML."""
    try:
        code, text = aws_signed(c, "s3", "us-east-1", "GET", "/", "", "",
                                host=AWS_GLOBAL["s3"])
    except Exception as e:                                    # noqa: BLE001
        return [], f"S3 buckets: {e}"
    if code != 200:
        root = _aws_tree(text)
        why = (_n(root, "Message") if root is not None else "") or text.strip()[:160]
        if code == 403:
            why += " — the key needs s3:ListAllMyBuckets"
        return [], f"S3 buckets: HTTP {code} {why}"
    root = _aws_tree(text)
    rows = []
    for b in _kids(root, "Bucket"):
        name = _n(b, "Name")
        if name:
            rows.append({"name": name, "id": name, "kind": "bucket", "state": "",
                         "extra": "", "zone": _n(b, "CreationDate")[:10]})
    rows.sort(key=lambda r: r["name"])
    return rows, ""


def aws_bills(c: dict, months: int = 12, refresh: bool = False) -> dict:
    """Monthly cost by service, from Cost Explorer.

    Cost Explorer is a JSON API on one global endpoint, it charges per request,
    and a month that has closed never changes — so this is cached for an hour
    like the Alibaba one, and asks for the whole window in a single call rather
    than one per month.
    """
    key = ("aws-bills", c.get("key_id", ""), int(months))
    hit = _BILLS.get(key)
    if hit and not refresh:
        age = time.time() - hit[0]
        if age < _BILLS_TTL:
            return hit[1]
        return {**hit[1], "stale_for": round(age)}

    today = datetime.datetime.now(datetime.timezone.utc).date()
    start = (today.replace(day=1)
             - datetime.timedelta(days=31 * max(1, months - 1))).replace(day=1)
    body = json.dumps({
        "TimePeriod": {"Start": start.isoformat(), "End": today.isoformat()},
        "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"],
        "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}]})
    out = {"months": [], "series": [], "labels": [], "by_product": [],
           "currency": "", "total": 0.0, "notes": [], "balance": "",
           "host": AWS_GLOBAL["ce"], "stale_for": 0}
    try:
        code, text = aws_signed(
            c, "ce", "us-east-1", "POST", "/", "", body,
            {"Content-Type": "application/x-amz-json-1.1",
             "X-Amz-Target": "AWSInsightsIndexService.GetCostAndUsage"},
            host=AWS_GLOBAL["ce"])
    except Exception as e:                                    # noqa: BLE001
        out["notes"].append(f"Cost Explorer: {e}")
        return out
    if code != 200:
        why = text[:200]
        try:
            why = json.loads(text).get("Message") or json.loads(text).get("message") or why
        except json.JSONDecodeError:
            pass
        if code in (400, 403):
            why += (" — Cost Explorer needs ce:GetCostAndUsage, and it has to be "
                    "enabled once in the Billing console")
        out["notes"].append(f"Cost Explorer: HTTP {code} {why}")
        return out
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        out["notes"].append("Cost Explorer answered something that is not JSON")
        return out

    products: dict = {}
    for period in doc.get("ResultsByTime") or []:
        cycle = (period.get("TimePeriod") or {}).get("Start", "")[:7]
        rows, total = [], 0.0
        for group in period.get("Groups") or []:
            name = (group.get("Keys") or ["?"])[0]
            metric = (group.get("Metrics") or {}).get("UnblendedCost") or {}
            try:
                amount = float(metric.get("Amount") or 0)
            except (TypeError, ValueError):
                amount = 0.0
            # Cost Explorer returns tiny negatives for rounding and credits, and
            # "USD -0.0" on a dashboard reads as a bug rather than as zero
            if abs(amount) < 0.005:
                amount = 0.0
            out["currency"] = out["currency"] or metric.get("Unit", "")
            if amount == 0:
                continue
            total += amount
            products[name] = products.get(name, 0.0) + amount
            rows.append({"product": name, "code": "", "amount": round(amount, 2),
                         "kind": "on demand", "currency": metric.get("Unit", "")})
        rows.sort(key=lambda r: -r["amount"])
        out["months"].append({"cycle": cycle, "total": round(total, 2),
                              "rows": rows})
    out["months"].sort(key=lambda m: m["cycle"])
    out["labels"] = [m["cycle"] for m in out["months"]]
    out["series"] = [m["total"] for m in out["months"]]
    out["by_product"] = sorted(({"product": k, "amount": round(v, 2)}
                                for k, v in products.items()),
                               key=lambda r: -r["amount"])
    out["total"] = round(sum(out["series"]), 2)
    _BILLS[key] = (time.time(), out)
    return out


def _aws_exposure(c: dict, groups: list, region: str, notes: list) -> dict:
    """Security group rules open to 0.0.0.0/0, counted from what is already read.

    Cheaper than the Alibaba equivalent: DescribeSecurityGroups returns the rules
    inline, so no extra call per group is needed and nothing has to be capped.
    Egress to the world is normal and is not counted.
    """
    out = {"open_rules": 0, "open_groups": 0, "checked": 0, "total": 0,
           "capped": False, "worst": []}
    raw = _AWS_SG_XML.get((c.get("key_id", ""), region), "")
    root = _aws_tree(raw) if raw else None
    if root is None:
        return out
    for info in _kids(root, "securityGroupInfo") or [root]:
        for item in _direct(info, "item"):
            gid = _n(item, "groupId")
            if not gid:
                continue
            out["total"] += 1
            out["checked"] += 1
            opened = []
            for perms in _direct(item, "ipPermissions"):
                for perm in _direct(perms, "item"):
                    world = any(_n(r, "cidrIp") in ("0.0.0.0/0", "::/0")
                                for ranges in _direct(perm, "ipRanges")
                                for r in _direct(ranges, "item"))
                    if not world:
                        continue
                    proto = _n(perm, "ipProtocol")
                    frm, to = _n(perm, "fromPort"), _n(perm, "toPort")
                    ports = f"{frm}-{to}" if frm else "all"
                    opened.append(f"{_n(item, 'groupName') or gid}: "
                                  f"{'all' if proto == '-1' else proto}/{ports}")
            if opened:
                out["open_groups"] += 1
                out["open_rules"] += len(opened)
                out["worst"] += opened[:3]
    return out


# The security-group answer, kept so exposure can be counted without asking
# twice. Keyed by account and region, replaced on every sweep.
_AWS_SG_XML: dict = {}


def _aws_inventory(c: dict, region_want: str = "") -> dict:
    """Everything this account holds in one region, plus what is account-wide."""
    from .fleet import _pmap
    notes = []
    regions = aws_regions(c)
    want = (region_want or c.get("region") or "us-east-1").strip()
    rid = want
    if regions and not any(r["id"] == want for r in regions):
        near = difflib.get_close_matches(want, [r["id"] for r in regions], n=3,
                                         cutoff=0.5)
        return {"groups": [], "region": want, "regions": regions,
                "billing": {}, "security": {},
                "notes": [f"“{want}” is not a region this account can use. "
                          + (f"Closest: {', '.join(near)}." if near else "")]}

    def one(spec):
        key, label, icon, service, version, action, extra, reader = spec[:8]
        mode = spec[8] if len(spec) > 8 else ("query", "")
        host = AWS_GLOBAL.get(service, "")
        where = "us-east-1" if host else rid
        try:
            if mode[0] == "json":
                # JSON-RPC: the operation is a header, the body is the arguments
                code, text = aws_signed(
                    c, service, where, "POST", "/", "", json.dumps(extra or {}),
                    {"Content-Type": "application/x-amz-json-1.1",
                     "X-Amz-Target": mode[1]}, host=host)
            elif mode[0] == "rest":
                code, text = aws_signed(c, service, where, "GET", mode[1], "", "",
                                        host=host)
            else:
                params = {"Action": action, "Version": version, **extra}
                body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                                for k, v in params.items())
                code, text = aws_signed(
                    c, service, where, "POST", "/", "", body,
                    {"Content-Type":
                     "application/x-www-form-urlencoded; charset=utf-8"},
                    host=host)
        except Exception as e:                                # noqa: BLE001
            why = "timed out" if "timed out" in str(e).lower() else str(e)
            return (None, f"{label}: {why}")
        if code != 200:
            return (None, f"{label}: {_aws_why(text, code)}")
        if key == "secgroups":
            _AWS_SG_XML[(c.get("key_id", ""), rid)] = text
        try:
            rows = reader(text)
        except Exception as e:                                # noqa: BLE001
            return (None, f"{label}: unexpected shape ({type(e).__name__})")
        return ({"key": key, "label": label, "icon": icon, "rows": rows}, None)

    groups = []
    for got in _pmap(one, AWS_PRODUCTS, workers=6) or []:
        if not got:
            continue
        group, why = got
        if group:
            groups.append(group)
        elif why:
            notes.append(why)

    buckets, why = aws_buckets(c)
    if why:
        notes.append(why)
    else:
        groups.append({"key": "buckets", "label": "S3 buckets", "icon": "🪣",
                       "rows": buckets,
                       "columns": ["bucket", "kind", "", "", "created"]})

    security = _aws_exposure(c, groups, rid, notes)
    bills = aws_bills(c, 12)
    notes += bills.get("notes", [])
    billing = {"total": (f"{bills['currency']} {bills['series'][-1]}"
                         if bills.get("series") else ""),
               "month": bills["labels"][-1] if bills.get("labels") else "",
               "currency": bills.get("currency", ""), "balance": "",
               "rows": bills["months"][-1]["rows"] if bills.get("months") else [],
               "host": bills.get("host", "")}
    if billing["rows"]:
        groups.append({"key": "billing",
                       "label": f"Spend this month ({billing['month']})",
                       "icon": "💳", "rows": [
                           {"name": r["product"], "id": "", "kind": r["kind"],
                            "state": "", "extra": f"{r['currency']} {r['amount']}",
                            "zone": billing["month"]}
                           for r in billing["rows"]],
                       "columns": ["service", "pricing", "", "amount", "period"]})
    if regions:
        notes.append(f"Resources are per region — this is {rid}. "
                     f"{len(regions)} regions are available to this account; "
                     f"IAM, S3 and billing are account-wide.")
    return {"groups": groups, "notes": _collapse(notes), "region": rid,
            "regions": regions, "billing": billing, "security": security}


def _aws_why(text: str, code: int) -> str:
    """AWS's error, with the remedy it never includes.

    Read as XML or as JSON: the query protocol answers one and ECR, Lambda and
    Cost Explorer answer the other, and a message hidden in the wrong parser
    reads as a blank failure.
    """
    root = _aws_tree(text)
    why = (_n(root, "Message") if root is not None else "") or ""
    codename = _n(root, "Code") if root is not None else ""
    if not why:
        doc = _aws_json(text)
        why = str(doc.get("message") or doc.get("Message") or "")
        codename = codename or str(doc.get("__type") or "")
    why = why or text.strip()[:160]
    low = (why + codename).lower()
    if "unauthorizedoperation" in low or "accessdenied" in low or code == 403:
        why += " — this key's IAM policy does not allow that call"
    elif "optintequired" in low or "optinrequired" in low:
        why += " — that region or service is not enabled on the account"
    elif "invalidclienttokenid" in low:
        why += " — the access key id is unknown or has been deleted"
    elif "signaturedoesnotmatch" in low:
        why += " — the secret does not match the key id"
    return why


def _azure_inventory(c: dict) -> dict:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": c["key_id"],
        "client_secret": c["secret"],
        "scope": "https://management.azure.com/.default"}).encode()
    code, text = _get(f"https://login.microsoftonline.com/"
                      f"{urllib.parse.quote(c['tenant'])}/oauth2/v2.0/token",
                      {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if code != 200:
        raise CloudError("could not get a management token — re-test the account")
    token = json.loads(text).get("access_token", "")
    h = {"Authorization": f"Bearer {token}"}
    sub = (c.get("region") or "").strip()
    if not sub:
        code, text = _get("https://management.azure.com/subscriptions"
                          "?api-version=2022-12-01", h)
        subs = json.loads(text).get("value", []) if code == 200 else []
        if not subs:
            return {"groups": [], "region": "",
                    "notes": ["no subscription is visible to this app — give it "
                              "Reader on one, or set the subscription ID"]}
        sub = subs[0].get("subscriptionId", "")

    groups, notes = [], []
    # One ARM resources call, grouped by type: cheaper than one call per service
    # and it cannot go stale as Azure adds resource types.
    code, text = _get(f"https://management.azure.com/subscriptions/"
                      f"{urllib.parse.quote(sub)}/resources"
                      "?api-version=2022-12-01&$top=500", h)
    if code != 200:
        raise CloudError(f"ARM answered HTTP {code} for the resource list")
    buckets: dict = {}
    for r in json.loads(text).get("value", []):
        kind = r.get("type", "")
        key = {"Microsoft.Compute/virtualMachines": ("compute", "Virtual machines", "🖥"),
               "Microsoft.ContainerService/managedClusters": ("cluster", "AKS clusters", "☸"),
               "Microsoft.Storage/storageAccounts": ("storage", "Storage accounts", "🗄"),
               "Microsoft.Sql/servers": ("database", "SQL servers", "🗃"),
               "Microsoft.DBforPostgreSQL/flexibleServers": ("database", "PostgreSQL", "🗃"),
               "Microsoft.Network/publicIPAddresses": ("network", "Public IPs", "🌐"),
               }.get(kind)
        if not key:
            continue
        k, label, icon = key
        b = buckets.setdefault(k, {"key": k, "label": label, "icon": icon, "rows": []})
        b["rows"].append({"name": r.get("name", ""), "id": r.get("id", "")[-40:],
                           "kind": kind.split("/")[-1], "state": "",
                           "extra": (r.get("sku") or {}).get("name", ""),
                           "zone": r.get("location", "")})
    groups = list(buckets.values())
    notes.append("Resource types beyond compute, clusters, storage, databases "
                 "and public IPs exist in the subscription but are not shown.")
    return {"groups": groups, "notes": notes, "region": sub}


# Alibaba serves most regions from a region-specific endpoint, and refuses the
# central one with "The specified endpoint cant operate this region". The region
# list, and the endpoint for each, come from the API rather than from a table
# here: a new region appears without a code change, and an account that cannot
# see a region is told so in its own words.
_ALI_REGIONS: dict = {}
_ALI_TTL = 900


def _alibaba_rpc(c: dict, action: str, version: str, host: str,
                 region: str, extra: dict | None = None):
    params = {"Action": action, "Version": version, "Format": "JSON",
              "AccessKeyId": c["key_id"], "SignatureMethod": "HMAC-SHA1",
              "SignatureVersion": "1.0", "RegionId": region,
              "SignatureNonce": uuid.uuid4().hex,
              "Timestamp": datetime.datetime.now(datetime.timezone.utc)
              .strftime("%Y-%m-%dT%H:%M:%SZ"), **(extra or {})}

    def enc(v):
        return urllib.parse.quote(str(v), safe="~")
    canon = "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(params.items()))
    sig = base64.b64encode(hmac.new((c["secret"] + "&").encode(),
                                    ("GET&%2F&" + enc(canon)).encode(),
                                    hashlib.sha1).digest()).decode()
    code, text = _get(f"https://{host}/?{canon}&Signature={enc(sig)}")
    try:
        return code, json.loads(text)
    except json.JSONDecodeError:
        return code, {}


# The last region id that worked for an account. A blip on the region list must
# not lose the answer we already had: without it, a region written as a name —
# "SAU" — cannot be resolved, every product is then asked at a host built from
# that name, and twenty-two DNS failures are reported instead of one lost call.
_LAST_REGION: dict = {}


def alibaba_regions(c: dict) -> list[dict]:
    """[{id, name, endpoint}] as this account sees them, briefly cached.

    Never raises. It is one call that everything else depends on, so a failure
    here used to escape to the page as a bare URLError and read as "0 resources"
    — which says the account is empty, not that one request failed.
    """
    key = c.get("key_id", "")
    now = time.time()
    if key in _ALI_REGIONS and now - _ALI_REGIONS[key][0] < _ALI_TTL:
        return _ALI_REGIONS[key][1]
    try:
        code, doc = _alibaba_rpc(c, "DescribeRegions", "2014-05-26",
                                 "ecs.aliyuncs.com", "cn-hangzhou",
                                 {"AcceptLanguage": "en-US"})
    except Exception:                                         # noqa: BLE001
        return _ALI_REGIONS.get(key, (0, []))[1]
    rows = []
    if code == 200:
        for r in (doc.get("Regions") or {}).get("Region", []) or []:
            rows.append({"id": r.get("RegionId", ""),
                         "name": r.get("LocalName", ""),
                         "endpoint": r.get("RegionEndpoint", "")})
    if rows:
        _ALI_REGIONS[key] = (now, rows)
    return rows


def alibaba_resolve_region(want: str, regions: list[dict]) -> tuple[dict, str]:
    """(region, note) for whatever was typed in the settings box.

    An id is used as given. Anything else is matched against the names Alibaba
    itself publishes — its name for Riyadh is literally "SAU (Riyadh)", so "SAU"
    is a reasonable thing to have typed and resolving it beats refusing it.

    Matching is tiered, most specific first, because a loose rule is ambiguous
    on real data: Alibaba spells São Paulo "Sau Paulo", so "SAU" matches a word
    in both "SAU (Riyadh)" and "Brazil (Sau Paulo)". A region's name leads with
    its territory, so "starts with" separates them. When a tier matches more than
    one region nothing is guessed — the candidates are named and the caller is
    asked to be specific.

    The note always says what was matched, because quietly operating on a
    different region than the one written down is worse than an error.
    """
    want = (want or "").strip()
    if not regions:
        return ({"id": want or "cn-hangzhou", "name": "", "endpoint": ""}, "")
    for r in regions:                                   # an id, used as given
        if r["id"].lower() == want.lower():
            return r, ""
    q = want.lower()
    if not q:
        return (regions[0], f"no region set — using {regions[0]['id']}")

    def words(r):
        return [w for w in re.split(r"[^a-z0-9]+", r["name"].lower()) if w]

    tiers = [
        ("name begins with it", lambda r: words(r) and words(r)[0] == q),
        ("a whole word of the name", lambda r: q in words(r)),
        ("a word of the name starts with it",
         lambda r: any(w.startswith(q) for w in words(r))),
        ("part of the id", lambda r: q in r["id"].lower()),
    ]
    for _why, test in tiers:
        hits = [r for r in regions if test(r)]
        if len(hits) == 1:
            return hits[0], (f"“{want}” is not a region id — matched "
                             f"{hits[0]['id']} ({hits[0]['name']})")
        if len(hits) > 1:
            raise CloudError(
                f"“{want}” matches {len(hits)} of this account's regions: "
                + ", ".join(f"{r['id']} ({r['name']})" for r in hits[:6])
                + ". Use the region id.")
    near = difflib.get_close_matches(q, [r["id"] for r in regions], n=3, cutoff=0.5)
    byname = [r["id"] for r in regions
              if difflib.SequenceMatcher(None, q, r["name"].lower()).ratio() > 0.5]
    options = ", ".join(dict.fromkeys(near + byname)) or \
        ", ".join(r["id"] for r in regions[:6])
    raise CloudError(f"“{want}” is not one of this account's "
                     f"{len(regions)} regions. Closest: {options}.")


# Every product read for an Alibaba account, in one table.
#
# (group key, label, icon, product host prefix, API version, action, extra params,
#  the function that turns the answer into rows)
#
# Region-scoped products are called at <prefix>.<region>.aliyuncs.com — the same
# rule the endpoint fix established — while RAM, billing and resource groups are
# account-wide and have one host each. Adding a product is a row here plus a
# reader; nothing else in the file changes.
def _rows_ecs(doc):
    return [{"name": i.get("InstanceName") or i.get("InstanceId", ""),
             "id": i.get("InstanceId", ""), "kind": i.get("InstanceType", ""),
             "state": i.get("Status", ""),
             "extra": ", ".join((i.get("VpcAttributes") or {})
                                .get("PrivateIpAddress", {}).get("IpAddress", [])
                                + (i.get("PublicIpAddress") or {}).get("IpAddress", [])),
             "zone": i.get("ZoneId", "")}
            for i in (doc.get("Instances") or {}).get("Instance", [])]


def _rows_disks(doc):
    return [{"name": d.get("DiskName") or d.get("DiskId", ""),
             "id": d.get("DiskId", ""),
             "kind": f"{d.get('Category', '')} · {d.get('Size', '?')} GiB",
             "state": d.get("Status", ""),
             "extra": d.get("InstanceId") or "not attached",
             "zone": d.get("ZoneId", "")}
            for d in (doc.get("Disks") or {}).get("Disk", [])]


def _rows_sg(doc):
    return [{"name": g.get("SecurityGroupName") or g.get("SecurityGroupId", ""),
             "id": g.get("SecurityGroupId", ""),
             "kind": g.get("SecurityGroupType", "normal"), "state": "",
             "extra": g.get("VpcId", ""), "zone": g.get("Description", "")[:40]}
            for g in (doc.get("SecurityGroups") or {}).get("SecurityGroup", [])]


def _rows_vpc(doc):
    return [{"name": v.get("VpcName") or v.get("VpcId", ""),
             "id": v.get("VpcId", ""), "kind": v.get("CidrBlock", ""),
             "state": v.get("Status", ""),
             "extra": f"{len((v.get('VSwitchIds') or {}).get('VSwitchId', []))} subnets"
                      + (" · default" if v.get("IsDefault") else ""),
             "zone": v.get("RegionId", "")}
            for v in (doc.get("Vpcs") or {}).get("Vpc", [])]


def _rows_vswitch(doc):
    return [{"name": v.get("VSwitchName") or v.get("VSwitchId", ""),
             "id": v.get("VSwitchId", ""), "kind": v.get("CidrBlock", ""),
             "state": v.get("Status", ""),
             "extra": f"{v.get('AvailableIpAddressCount', '?')} free IPs · "
                      f"{v.get('VpcId', '')}",
             "zone": v.get("ZoneId", "")}
            for v in (doc.get("VSwitches") or {}).get("VSwitch", [])]


def _rows_eip(doc):
    return [{"name": e.get("Name") or e.get("IpAddress", ""),
             "id": e.get("AllocationId", ""),
             "kind": f"{e.get('Bandwidth', '?')} Mbps · {e.get('InternetChargeType', '')}",
             "state": e.get("Status", ""),
             "extra": f"{e.get('IpAddress', '')} → {e.get('InstanceId') or 'unbound'}",
             "zone": e.get("RegionId", "")}
            for e in (doc.get("EipAddresses") or {}).get("EipAddress", [])]


def _rows_nat(doc):
    return [{"name": n.get("Name") or n.get("NatGatewayId", ""),
             "id": n.get("NatGatewayId", ""), "kind": n.get("Spec") or n.get("NatType", ""),
             "state": n.get("Status", ""), "extra": n.get("VpcId", ""),
             "zone": n.get("RegionId", "")}
            for n in (doc.get("NatGateways") or {}).get("NatGateway", [])]


def _rows_slb(doc):
    return [{"name": b.get("LoadBalancerName") or b.get("LoadBalancerId", ""),
             "id": b.get("LoadBalancerId", ""),
             "kind": f"CLB · {b.get('AddressType', '')}",
             "state": b.get("LoadBalancerStatus", ""),
             "extra": b.get("Address", ""), "zone": b.get("MasterZoneId", "")}
            for b in (doc.get("LoadBalancers") or {}).get("LoadBalancer", [])]


def _rows_alb(doc):
    return [{"name": b.get("LoadBalancerName") or b.get("LoadBalancerId", ""),
             "id": b.get("LoadBalancerId", ""),
             "kind": f"ALB · {b.get('AddressType', '')}",
             "state": b.get("LoadBalancerStatus", ""),
             "extra": b.get("DNSName", ""), "zone": b.get("VpcId", "")}
            for b in (doc.get("LoadBalancers") or [])]


def _rows_rds(doc):
    return [{"name": d.get("DBInstanceDescription") or d.get("DBInstanceId", ""),
             "id": d.get("DBInstanceId", ""),
             "kind": f"{d.get('Engine', '')} {d.get('EngineVersion', '')} · "
                     f"{d.get('DBInstanceClass', '')}",
             "state": d.get("DBInstanceStatus", ""),
             "extra": f"{d.get('DBInstanceNetType', '')} · {d.get('VpcId', '')}",
             "zone": d.get("ZoneId", "")}
            for d in (doc.get("Items") or {}).get("DBInstance", [])]


def _rows_redis(doc):
    return [{"name": i.get("InstanceName") or i.get("InstanceId", ""),
             "id": i.get("InstanceId", ""),
             "kind": f"{i.get('InstanceClass', '')} · {i.get('Capacity', '?')} MB",
             "state": i.get("InstanceStatus", ""),
             "extra": i.get("ConnectionDomain", ""), "zone": i.get("ZoneId", "")}
            for i in (doc.get("Instances") or {}).get("KVStoreInstance", [])]


def _rows_ram_users(doc):
    return [{"name": u.get("UserName", ""), "id": u.get("UserId", ""),
             "kind": u.get("DisplayName", ""), "state": "",
             "extra": u.get("Email") or u.get("MobilePhone") or "",
             "zone": (u.get("CreateDate") or "")[:10]}
            for u in (doc.get("Users") or {}).get("User", [])]


def _rows_ram_roles(doc):
    return [{"name": r.get("RoleName", ""), "id": r.get("RoleId", ""),
             "kind": "role", "state": "",
             "extra": (r.get("Description") or "")[:60],
             "zone": (r.get("CreateDate") or "")[:10]}
            for r in (doc.get("Roles") or {}).get("Role", [])]


def _rows_ram_policies(doc):
    return [{"name": p.get("PolicyName", ""), "id": p.get("PolicyType", ""),
             "kind": p.get("PolicyType", ""), "state": "",
             "extra": (p.get("Description") or "")[:60],
             "zone": (p.get("UpdateDate") or p.get("CreateDate") or "")[:10]}
            for p in (doc.get("Policies") or {}).get("Policy", [])]


def _rows_groups(doc):
    return [{"name": g.get("DisplayName") or g.get("Name", ""),
             "id": g.get("Id", ""), "kind": g.get("Status", ""), "state": "",
             "extra": (g.get("Name") or ""), "zone": (g.get("CreateDate") or "")[:10]}
            for g in (doc.get("ResourceGroups") or {}).get("ResourceGroup", [])]


def _rows_snapshots(doc):
    return [{"name": s.get("SnapshotName") or s.get("SnapshotId", ""),
             "id": s.get("SnapshotId", ""),
             "kind": f"{s.get('SourceDiskType', '')} · {s.get('SourceDiskSize', '?')} GiB",
             "state": s.get("Status", ""),
             "extra": (s.get("SourceDiskId") or "source gone")
                      + (" · instant" if s.get("InstantAccess") else ""),
             "zone": (s.get("CreationTime") or "")[:10]}
            for s in (doc.get("Snapshots") or {}).get("Snapshot", [])]


def _rows_images(doc):
    return [{"name": i.get("ImageName") or i.get("ImageId", ""),
             "id": i.get("ImageId", ""),
             "kind": f"{i.get('OSName') or i.get('Platform', '')} · {i.get('Size', '?')} GiB",
             "state": i.get("Status", ""),
             "extra": i.get("Description", "")[:50] or i.get("ImageOwnerAlias", ""),
             "zone": (i.get("CreationTime") or "")[:10]}
            for i in (doc.get("Images") or {}).get("Image", [])]


def _rows_keypairs(doc):
    return [{"name": k.get("KeyPairName", ""), "id": k.get("KeyPairName", ""),
             "kind": "key pair", "state": "",
             "extra": k.get("KeyPairFingerPrint", "")[:32],
             "zone": (k.get("CreationTime") or "")[:10]}
            for k in (doc.get("KeyPairs") or {}).get("KeyPair", [])]


def _rows_routetables(doc):
    return [{"name": r.get("RouteTableName") or r.get("RouteTableId", ""),
             "id": r.get("RouteTableId", ""),
             "kind": r.get("RouteTableType", ""), "state": r.get("Status", ""),
             "extra": f"{r.get('VpcId', '')} · "
                      f"{len((r.get('VSwitchIds') or {}).get('VSwitchId', []))} subnets",
             "zone": (r.get("CreationTime") or "")[:10]}
            for r in (doc.get("RouterTableList") or {}).get("RouterTableListType", [])]


def _rows_vpn(doc):
    return [{"name": v.get("Name") or v.get("VpnGatewayId", ""),
             "id": v.get("VpnGatewayId", ""),
             "kind": f"{v.get('Spec', '')} · {v.get('BusinessStatus', '')}",
             "state": v.get("Status", ""),
             "extra": f"{v.get('InternetIp', '')} · {v.get('VpcId', '')}",
             "zone": (v.get("EndTime") and "expires "
                      + str(v.get("EndTime"))[:10]) or ""}
            for v in (doc.get("VpnGateways") or {}).get("VpnGateway", [])]


def _rows_nas(doc):
    return [{"name": f.get("Description") or f.get("FileSystemId", ""),
             "id": f.get("FileSystemId", ""),
             "kind": f"{f.get('ProtocolType', '')} · {f.get('StorageType', '')}",
             "state": f.get("Status", ""),
             "extra": f"{round(int(f.get('MeteredSize') or 0) / 1024**3, 2)} GiB used",
             "zone": f.get("ZoneId", "")}
            for f in (doc.get("FileSystems") or {}).get("FileSystem", [])]


def _rows_acr(doc):
    """Repositories in a Container Registry instance.

    Alibaba's registry is per instance and per region, so a namespace is only
    meaningful with the repository beside it — they are joined here the way the
    registry URL joins them.
    """
    out = []
    for r in doc.get("Repositories") or []:
        ns, name = r.get("RepoNamespaceName", ""), r.get("RepoName", "")
        full = f"{ns}/{name}" if ns else name
        if not full:
            continue
        out.append({"name": full, "id": r.get("RepoId", full),
                    "kind": f"{r.get('RepoType', '')} · "
                            f"{r.get('Summary', '')}".strip(" ·"),
                    "state": r.get("RepoStatus", ""),
                    "extra": r.get("InstanceId", ""),
                    "zone": (r.get("ModifiedTime") and
                             str(r.get("ModifiedTime"))[:10]) or ""})
    out.sort(key=lambda r: r["name"])
    return out


ALI_PRODUCTS = [
    ("compute", "ECS instances", "🖥", "ecs", "2014-05-26", "DescribeInstances",
     {"PageSize": "100"}, _rows_ecs),
    ("disks", "Disks", "💽", "ecs", "2014-05-26", "DescribeDisks",
     {"PageSize": "100"}, _rows_disks),
    ("secgroups", "Security groups", "🛡", "ecs", "2014-05-26",
     "DescribeSecurityGroups", {"PageSize": "100"}, _rows_sg),
    ("vpcs", "VPCs", "🕸", "vpc", "2016-04-28", "DescribeVpcs",
     {"PageSize": "50"}, _rows_vpc),
    ("subnets", "Subnets (VSwitches)", "🔀", "vpc", "2016-04-28",
     "DescribeVSwitches", {"PageSize": "50"}, _rows_vswitch),
    ("eips", "Elastic IPs", "🌐", "vpc", "2016-04-28", "DescribeEipAddresses",
     {"PageSize": "100"}, _rows_eip),
    ("nat", "NAT gateways", "↔", "vpc", "2016-04-28", "DescribeNatGateways",
     {"PageSize": "50"}, _rows_nat),
    ("clb", "Load balancers (CLB)", "⚖", "slb", "2014-05-15",
     "DescribeLoadBalancers", {"PageSize": "100"}, _rows_slb),
    ("alb", "Load balancers (ALB)", "⚖", "alb", "2020-06-16",
     "ListLoadBalancers", {"MaxResults": "100"}, _rows_alb),
    ("rds", "Databases (RDS)", "🗃", "rds", "2014-08-15", "DescribeDBInstances",
     {"PageSize": "100"}, _rows_rds),
    ("redis", "Redis (KVStore)", "⚡", "r-kvstore", "2015-01-01",
     "DescribeInstances", {"PageSize": "50"}, _rows_redis),
    ("snapshots", "Snapshots", "📸", "ecs", "2014-05-26", "DescribeSnapshots",
     {"PageSize": "100"}, _rows_snapshots),
    ("images", "Custom images", "💿", "ecs", "2014-05-26", "DescribeImages",
     {"PageSize": "100", "ImageOwnerAlias": "self"}, _rows_images),
    ("keypairs", "Key pairs", "🔐", "ecs", "2014-05-26", "DescribeKeyPairs",
     {"PageSize": "50"}, _rows_keypairs),
    ("routetables", "Route tables", "🧭", "vpc", "2016-04-28",
     "DescribeRouteTableList", {"PageSize": "50"}, _rows_routetables),
    ("vpn", "VPN gateways", "🔒", "vpc", "2016-04-28", "DescribeVpnGateways",
     {"PageSize": "50"}, _rows_vpn),
    ("nas", "NAS file systems", "🗂", "nas", "2017-06-26", "DescribeFileSystems",
     {"PageSize": "50"}, _rows_nas),
    # account-wide: one host, no region in it
    ("ram_users", "RAM users", "👤", "ram.aliyuncs.com", "2015-05-01",
     "ListUsers", {"MaxItems": "100"}, _rows_ram_users),
    ("ram_roles", "RAM roles", "🎭", "ram.aliyuncs.com", "2015-05-01",
     "ListRoles", {"MaxItems": "100"}, _rows_ram_roles),
    ("ram_policies", "RAM policies (custom)", "📜", "ram.aliyuncs.com",
     "2015-05-01", "ListPolicies", {"MaxItems": "100", "PolicyType": "Custom"},
     _rows_ram_policies),
    ("resource_groups", "Resource groups", "🗂",
     "resourcemanager.aliyuncs.com", "2020-03-31", "ListResourceGroups",
     {"PageSize": "50"}, _rows_groups),
]


# ── OSS, which does not speak RPC ──────────────────────────────────────────
# Object Storage signs like S3, not like the rest of Alibaba: an Authorization
# header over a canonicalised string, and XML back instead of JSON. That is why
# it was missing from the product table — it cannot be a row in it — so it gets
# its own reader.
def _oss_get(c: dict, host: str, bucket: str = "", query: str = "") -> tuple:
    """A signed OSS GET.

    The path and the signed resource are NOT the same string, which is the trap:
    with the bucket in the hostname the request path is "/", while the signature
    must still be computed over "/bucket/". Signing the path instead of the
    resource authenticates fine and then gets a 403 for the wrong thing.

    StringToSign = VERB \n Content-MD5 \n Content-Type \n Date \n
                   CanonicalizedOSSHeaders CanonicalizedResource
    """
    date = datetime.datetime.now(datetime.timezone.utc) \
        .strftime("%a, %d %b %Y %H:%M:%S GMT")
    canon = f"/{bucket}/" if bucket else "/"
    if query:
        canon += f"?{query}"
    to_sign = f"GET\n\n\n{date}\n{canon}"
    sig = base64.b64encode(hmac.new(c["secret"].encode(), to_sign.encode(),
                                    hashlib.sha1).digest()).decode()
    url = f"https://{host}/" + (f"?{query}" if query else "")
    return _get(url, {"Date": date,
                      "Authorization": f"OSS {c['key_id']}:{sig}"})


def _oss_text(node, tag: str) -> str:
    """The text of a child tag, whatever namespace OSS decided to use.

    OSS labels its XML with a namespace that names a region, so a fixed prefix
    would work in Hangzhou and nowhere else. Matching on the local name avoids
    caring.
    """
    for child in node:
        if child.tag.rsplit("}", 1)[-1] == tag:
            return (child.text or "").strip()
    return ""


def alibaba_buckets(c: dict, region: str) -> tuple[list, str]:
    """([rows], note). Buckets are listed account-wide, whatever region is asked.

    The service-level list returns every bucket the key can see, with the region
    each one lives in — which is more useful than filtering to the region on
    screen, since a bucket in the wrong region is exactly the thing you want to
    notice.
    """
    import xml.etree.ElementTree as ET
    host = f"oss-{region}.aliyuncs.com"
    try:
        code, text = _oss_get(c, host)
    except Exception as e:                                    # noqa: BLE001
        why = "timed out" if "timed out" in str(e).lower() else str(e)
        return [], f"OSS buckets: {why}"
    if code != 200:
        why = text.strip()
        # OSS answers XML errors too, and its <Message> is the readable part
        try:
            root = ET.fromstring(text)
            why = _oss_text(root, "Message") or why
        except ET.ParseError:
            pass
        if "AccessDenied" in text or code == 403:
            why += " — the key needs AliyunOSSReadOnlyAccess"
        return [], f"OSS buckets: HTTP {code} {why[:200]}"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [], f"OSS buckets: unreadable answer ({e})"
    rows = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "Bucket":
            continue
        name = _oss_text(node, "Name")
        if not name:
            continue
        loc = _oss_text(node, "Location").replace("oss-", "")
        rows.append({"name": name, "id": name,
                     "kind": _oss_text(node, "StorageClass") or "Standard",
                     "state": "",
                     "extra": _oss_text(node, "ExtranetEndpoint")
                              or f"oss-{loc}.aliyuncs.com",
                     "zone": loc})
    rows.sort(key=lambda r: r["name"])
    return rows, ""


def alibaba_bucket_detail(c: dict, bucket: str, region: str) -> dict:
    """Size, object count and settings for one bucket.

    Two calls: ?stat for what is in it, ?bucketInfo for how it is configured. The
    bucket has to be addressed at its own region's endpoint, so its location is
    read first and the calls follow it.
    """
    import xml.etree.ElementTree as ET
    fields, extras = [], []

    host = f"{bucket}.oss-{region}.aliyuncs.com"
    code, text = _oss_get(c, host, bucket, "location")
    if code == 200:
        try:
            loc = (ET.fromstring(text).text or "").strip()
            if loc:
                host = f"{bucket}.{loc}.aliyuncs.com"
                fields.append(("region", loc.replace("oss-", "")))
        except ET.ParseError:
            pass

    code, text = _oss_get(c, host, bucket, "stat")
    if code == 200:
        try:
            root = ET.fromstring(text)
            size = _oss_text(root, "Storage")
            gib = round(int(size) / 1024 ** 3, 2) if size.isdigit() else size
            fields += [("size (GiB)", gib),
                       ("objects", _oss_text(root, "ObjectCount")),
                       ("multipart uploads",
                        _oss_text(root, "MultipartUploadCount")),
                       ("standard storage (GiB)",
                        round(int(_oss_text(root, "StandardStorage") or 0)
                              / 1024 ** 3, 2))]
        except (ET.ParseError, ValueError):
            pass
    else:
        extras.append(f"stat: HTTP {code}")

    code, text = _oss_get(c, host, bucket, "bucketInfo")
    if code == 200:
        try:
            root = ET.fromstring(text)
            for node in root.iter():
                tag = node.tag.rsplit("}", 1)[-1]
                if tag == "Bucket":
                    for want, label in (("CreationDate", "created"),
                                        ("StorageClass", "storage class"),
                                        ("ExtranetEndpoint", "public endpoint"),
                                        ("IntranetEndpoint", "internal endpoint"),
                                        ("Versioning", "versioning"),
                                        ("DataRedundancyType", "redundancy"),
                                        ("BlockPublicAccess", "block public access")):
                        val = _oss_text(node, want)
                        if val:
                            fields.append((label, val))
                if tag == "AccessControlList":
                    grant = _oss_text(node, "Grant")
                    if grant:
                        fields.append(("ACL", grant))
        except ET.ParseError:
            pass
    else:
        extras.append(f"bucketInfo: HTTP {code}")
    return {"fields": fields, "notes": extras}


# How many ways in there are. A rule allowing 0.0.0.0/0 is the single most
# useful security fact about a cloud account, and it is not in any list call —
# it needs one describe per security group. Capped, because an estate with a
# hundred groups should not pay a hundred calls for a tile, and the cap is
# reported rather than hidden.
EXPOSURE_CAP = 12


# What each group is called elsewhere. Somebody who lives in the Alibaba console
# types "ecs", "slb" or "oss", not "ECS instances" or "Load balancers (CLB)", and
# a search that only matches the portal's own labels is a search that fails on
# the words people actually use.
SERVICE_WORDS = {
    "compute": "ecs instance instances vm vms server servers machine guest",
    "disks": "disk disks ebs volume volumes yundisk storage block",
    "snapshots": "snapshot snapshots backup image point-in-time",
    "images": "image images ami custom template",
    "keypairs": "key keypair keypairs ssh",
    "secgroups": "sg security group groups firewall rules acl port",
    "vpcs": "vpc vpcs network networks cidr",
    "subnets": "vswitch vsw subnet subnets cidr zone address",
    "routetables": "route routes routing table gateway",
    "eips": "eip eips elastic ip public address floating",
    "nat": "nat gateway snat dnat",
    "vpn": "vpn gateway ipsec tunnel ssl",
    "clb": "slb clb load balancer balancers lb listener",
    "alb": "alb application load balancer lb layer7",
    "rds": "rds database databases db postgres postgresql mysql sql apsaradb",
    "redis": "redis kvstore cache memcache memory",
    "nas": "nas nfs file filesystem share",
    "oss": "oss bucket buckets object storage s3 static",
    "ram_users": "ram iam user users account accounts identity people",
    "ram_roles": "ram iam role roles assume trust",
    "ram_policies": "ram iam policy policies permission permissions grant",
    "resource_groups": "resource group groups rg organisation organization",
    "billing": "bill bills billing spend cost costs invoice money expense",
}


_merge_words()          # both vocabularies exist by here


def _alibaba_exposure(c: dict, groups: list, region: str,
                      notes: list) -> dict:
    from .fleet import _pmap
    sgs = next((g["rows"] for g in groups if g["key"] == "secgroups"), [])
    out = {"open_rules": 0, "open_groups": 0, "checked": 0,
           "total": len(sgs), "capped": False, "worst": []}
    if not sgs:
        return out
    look = sgs[:EXPOSURE_CAP]
    out["capped"] = len(sgs) > EXPOSURE_CAP

    def one(sg):
        try:
            code, doc = _alibaba_rpc(c, "DescribeSecurityGroupAttribute",
                                     "2014-05-26",
                                     f"ecs.{region}.aliyuncs.com", region,
                                     {"SecurityGroupId": sg["id"]})
        except Exception:                                     # noqa: BLE001
            return None
        if code != 200:
            return None
        open_rules = []
        for p in (doc.get("Permissions") or {}).get("Permission", []) or []:
            if (p.get("Direction") or "ingress") != "ingress":
                continue
            if str(p.get("SourceCidrIp", "")) in ("0.0.0.0/0", "::/0") \
                    and (p.get("Policy") or "Accept").lower() == "accept":
                open_rules.append(
                    f"{sg.get('name', sg['id'])}: "
                    f"{(p.get('IpProtocol') or '').lower()}/"
                    f"{p.get('PortRange', '')}")
        return (sg, open_rules)

    for got in _pmap(one, look, workers=6) or []:
        if not got:
            continue
        sg, open_rules = got
        out["checked"] += 1
        if open_rules:
            out["open_groups"] += 1
            out["open_rules"] += len(open_rules)
            out["worst"] += open_rules[:3]
    if out["capped"]:
        notes.append(f"exposure checked on {out['checked']} of {out['total']} "
                     f"security groups — the rest were not asked about")
    return out


def _alibaba_billing(c: dict, notes: list) -> dict:
    """Balance and this month's spend by product, from the billing API.

    Its own function because it is not a resource list: the shape is money, the
    host is account-wide, and a permission failure here should not read as "you
    have no resources".
    """
    out = {"balance": "", "currency": "", "month": "", "total": "", "rows": [],
           "host": ""}
    # Which host this account is billed through — the same question alibaba_bills
    # asks, so it is asked in one place. There were two copies of this loop and
    # only one of them survived a name that would not resolve.
    host, doc, code = _bss_host(c)
    if not host:
        why = _ali_why(doc, code)
        if not any(t in why.lower() for t in TRANSIENT):
            why += " — billing needs AliyunBSSReadOnlyAccess on the key"
        notes.append("Billing: " + why)
        return out
    out["host"] = host
    d = doc.get("Data") or {}
    out["balance"] = d.get("AvailableAmount", "")
    out["currency"] = d.get("Currency", "")

    cycle = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    out["month"] = cycle
    try:
        code, doc = _alibaba_rpc(c, "QueryBillOverview", "2017-12-14", host,
                                 "cn-hangzhou", {"BillingCycle": cycle})
    except Exception as e:                                    # noqa: BLE001
        notes.append(f"Billing overview: {e}")
        return out
    if code == 200:
        data = doc.get("Data") or {}
        items = (data.get("Items") or {}).get("Item", []) or []
        total = 0.0
        for it in items:
            try:
                amount = float(it.get("PretaxAmount") or 0)
            except (TypeError, ValueError):
                amount = 0.0
            total += amount
            out["rows"].append({
                "name": it.get("ProductName") or it.get("ProductCode", ""),
                "id": it.get("ProductCode", ""),
                "kind": it.get("SubscriptionType", ""),
                "state": "",
                "extra": f"{it.get('Currency', out['currency'])} "
                         f"{it.get('PretaxAmount', '0')}",
                "zone": it.get("BillingDate", "") or cycle})
        out["rows"].sort(key=lambda r: -float((r["extra"].split() or ["0", "0"])[-1]
                                              or 0))
        out["total"] = f"{out['currency'] or ''} {round(total, 2)}".strip()
    else:
        notes.append("Billing overview: " + _ali_why(doc, code))
    return out


def _bss_host(c: dict) -> tuple[str, dict, int]:
    """The billing host this account answers on.

    An international account is billed through Singapore and answers "auth site
    failed." on the China host — an error about the site, not about permissions.
    Cached per key, since it never changes for an account.
    """
    key = ("bss", c.get("key_id", ""))
    now = time.time()
    if key in _ALI_REGIONS and now - _ALI_REGIONS[key][0] < _ALI_TTL:
        return _ALI_REGIONS[key][1], {}, 200
    doc, code = {}, 0
    for candidate in ("business.aliyuncs.com",
                      "business.ap-southeast-1.aliyuncs.com"):
        try:
            code, doc = _alibaba_rpc(c, "QueryAccountBalance", "2017-12-14",
                                     candidate, "cn-hangzhou")
        except Exception as e:                                # noqa: BLE001
            # billing is one part of the page, and it must not be the part that
            # takes the rest of it down
            doc, code = {"Message": str(e)}, 0
            continue
        if code == 200:
            _ALI_REGIONS[key] = (now, candidate)
            return candidate, doc, code
    return "", doc, code


# A bill for a closed month never changes, and the open one changes hourly at
# most, so an hour of cache costs nothing and saves twelve API calls per view.
_BILLS: dict = {}
_BILLS_TTL = 3600.0


def alibaba_registry(c: dict, region: str) -> tuple[list, str]:
    """([rows], note) for the container registry in one region.

    Two steps rather than one, because a repository belongs to an instance and
    ListRepository refuses to answer without one — which is why it could not be a
    row in the product table.
    """
    from .fleet import _pmap
    host = f"cr.{region}.aliyuncs.com"
    try:
        code, doc = _alibaba_rpc(c, "ListInstance", "2018-12-01", host, region, {})
    except Exception as e:                                    # noqa: BLE001
        why = "timed out" if "timed out" in str(e).lower() else str(e)
        return [], f"Container registry: {why}"
    if code != 200:
        return [], f"Container registry: {_ali_why(doc, code)}"
    instances = doc.get("Instances") or []
    if not instances:
        return [], ("no Container Registry instance in this region — the registry "
                    "is per region, so check the others if you expect one")

    def one(inst):
        iid = inst.get("InstanceId")
        if not iid:
            return []
        try:
            c2, d2 = _alibaba_rpc(c, "ListRepository", "2018-12-01", host, region,
                                  {"InstanceId": iid, "PageSize": "100"})
        except Exception:                                     # noqa: BLE001
            return []
        return _rows_acr(d2) if c2 == 200 else []

    rows = []
    for got in _pmap(one, instances, workers=min(4, len(instances))) or []:
        rows += got or []
    rows.sort(key=lambda r: r["name"])
    return rows, ""


def alibaba_bills(c: dict, months: int = 12, refresh: bool = False) -> dict:
    key = (c.get("key_id", ""), int(months))
    hit = _BILLS.get(key)
    if hit and not refresh:
        age = time.time() - hit[0]
        if age < _BILLS_TTL:
            return hit[1]
        # stale: hand over what we have and collect a new one behind the page
        import threading
        if key not in _refreshing:
            _refreshing.add(key)

            def run():
                try:
                    alibaba_bills(c, months, refresh=True)
                finally:
                    _refreshing.discard(key)
            threading.Thread(target=run, name="bills-revalidate",
                             daemon=True).start()
        return {**hit[1], "stale_for": round(age)}
    got = _alibaba_bills(c, months)
    got["stale_for"] = 0
    _BILLS[key] = (time.time(), got)
    return got


def _alibaba_bills(c: dict, months: int = 12) -> dict:
    """Every month's bill for the last `months`, by product.

    One call per month, in parallel. Returns the series for the trend, the
    per-product totals for the ranking, and the months themselves so a page can
    show any one of them in full — which is the difference between "this month
    costs USD 680" and "RDS doubled in May".
    """
    from .fleet import _pmap
    host, _doc, _code = _bss_host(c)
    out = {"host": host, "months": [], "series": [], "labels": [],
           "by_product": [], "currency": "", "total": 0.0, "notes": []}
    if not host:
        out["notes"].append("billing is not readable with this key — "
                            "AliyunBSSReadOnlyAccess is what it needs")
        return out

    today = datetime.datetime.now(datetime.timezone.utc).date()
    cycles = []
    y, m = today.year, today.month
    for _ in range(max(1, months)):
        cycles.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    cycles.reverse()

    def one(cycle):
        try:
            code, doc = _alibaba_rpc(c, "QueryBillOverview", "2017-12-14", host,
                                     "cn-hangzhou", {"BillingCycle": cycle})
        except Exception as e:                                # noqa: BLE001
            return (cycle, None, str(e))
        if code != 200:
            return (cycle, None, _ali_why(doc, code))
        items = ((doc.get("Data") or {}).get("Items") or {}).get("Item", []) or []
        return (cycle, items, "")

    products: dict = {}
    for got in _pmap(one, cycles, workers=6) or []:
        if not got:
            continue
        cycle, items, why = got
        if items is None:
            out["notes"].append(f"{cycle}: {why}")
            continue
        total = 0.0
        rows = []
        for it in items:
            try:
                amount = float(it.get("PretaxAmount") or 0)
            except (TypeError, ValueError):
                amount = 0.0
            name = it.get("ProductName") or it.get("ProductCode", "?")
            total += amount
            products[name] = products.get(name, 0.0) + amount
            out["currency"] = out["currency"] or it.get("Currency", "")
            rows.append({"product": name, "code": it.get("ProductCode", ""),
                         "amount": round(amount, 2),
                         "kind": it.get("SubscriptionType", ""),
                         "currency": it.get("Currency", "")})
        rows.sort(key=lambda r: -r["amount"])
        out["months"].append({"cycle": cycle, "total": round(total, 2),
                              "rows": rows})
    out["months"].sort(key=lambda x: x["cycle"])
    out["labels"] = [x["cycle"] for x in out["months"]]
    out["series"] = [x["total"] for x in out["months"]]
    out["by_product"] = sorted(({"product": k, "amount": round(v, 2)}
                                for k, v in products.items()),
                               key=lambda r: -r["amount"])
    out["total"] = round(sum(out["series"]), 2)
    return out


# ── payment and settlement ─────────────────────────────────────────────────
# WHAT CAN AND CANNOT BE DONE HERE, HONESTLY
#     Neither AWS nor Alibaba Cloud exposes payment instruments through an API.
#     There is no call to list a card, add a bank account or remove one — those
#     live only in each provider's own billing console, behind that console's own
#     re-authentication. So the portal reads everything about money that IS
#     available — balance, what is outstanding, what has settled and when — and
#     links straight to the page where a card is changed.
#
#     It will also never type a card number, an IBAN or a CVV into anything on
#     someone's behalf, which is a rule rather than a limitation.
PAYMENT_CONSOLES = {
    "alibaba": [
        ("Billing overview", "https://billing.console.aliyun.com/",
         "balance, payment methods, invoices and settlement"),
    ],
    "aws": [
        ("Billing overview",
         "https://us-east-1.console.aws.amazon.com/billing/home",
         "bills, payment preferences and what is outstanding"),
    ],
}


def payments(conn: dict) -> dict:
    """What the provider will say about money: balance, outstanding, settlement.

    Deliberately not "payment methods" — see the note above. The consoles are
    linked instead, because that is where the card actually lives.
    """
    kind = conn.get("type", "")
    out = {"provider": kind, "balance": "", "currency": "", "credit": "",
           "outstanding": 0.0, "settled": 0.0, "rows": [], "notes": [],
           "consoles": PAYMENT_CONSOLES.get(kind, []),
           "manageable": False}
    if kind == "alibaba":
        host, doc, code = _bss_host(conn)
        if not host:
            out["notes"].append("billing is not readable with this key — it needs "
                                "AliyunBSSReadOnlyAccess")
            return out
        d = doc.get("Data") or {}
        out["balance"] = d.get("AvailableAmount", "")
        out["currency"] = d.get("Currency", "")
        out["credit"] = d.get("CreditAmount", "")
        cycle = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        try:
            code, doc = _alibaba_rpc(conn, "QuerySettleBill", "2017-12-14", host,
                                     "cn-hangzhou",
                                     {"BillingCycle": cycle, "PageSize": "100"})
        except Exception as e:                                # noqa: BLE001
            out["notes"].append(f"settlement: {e}")
            return out
        if code != 200:
            out["notes"].append("settlement: " + _ali_why(doc, code))
            return out
        for it in ((doc.get("Data") or {}).get("Items") or {}).get("Item", []) or []:
            try:
                paid = float(it.get("PaymentAmount") or 0)
                owed = float(it.get("OutstandingAmount") or 0)
            except (TypeError, ValueError):
                paid, owed = 0.0, 0.0
            if not paid and not owed:
                continue
            out["settled"] += paid
            out["outstanding"] += owed
            out["rows"].append({
                "product": it.get("ProductName") or it.get("ProductCode", ""),
                "status": it.get("Status", ""), "paid": round(paid, 2),
                "outstanding": round(owed, 2),
                "when": (it.get("PaymentTime") or "")[:16],
                "currency": it.get("Currency", out["currency"]),
                "method": it.get("PaymentCurrency") or ""})
        out["rows"].sort(key=lambda r: -r["outstanding"])
        out["settled"] = round(out["settled"], 2)
        out["outstanding"] = round(out["outstanding"], 2)
        out["month"] = cycle
    elif kind == "aws":
        got = aws_bills(conn, 2)
        out["currency"] = got.get("currency", "")
        out["month"] = got["labels"][-1] if got.get("labels") else ""
        out["settled"] = got["series"][-1] if got.get("series") else 0.0
        out["notes"] += got.get("notes", [])
        out["notes"].append(
            "AWS publishes cost through Cost Explorer but nothing about payment: "
            "there is no API for a card, a bank account, or what is outstanding. "
            "Those are in the billing console, linked below.")
    else:
        out["notes"].append(f"the portal cannot read billing for "
                            f"{kind or 'this provider'}")
    return out


def _ali_why(doc: dict, code: int) -> str:
    """Alibaba's message, with the remedy it never includes."""
    why = doc.get("Message", f"HTTP {code}")
    name = str(doc.get("Code", ""))
    low = why.lower()
    if "does not open" in low or "not opened" in low or "not activated" in low:
        why += (" — this product is not enabled on the account, which is not a "
                "permission problem: enable it in the console if you want it")
    elif "not authorized" in low or name.startswith("Forbidden") or code == 403:
        why += (" — this access key's RAM user lacks read permission for that "
                "product")
    elif "InvalidAccessKeyId" in name:
        why += " — the access key id is unknown or disabled"
    elif "endpoint" in low:
        why += " — wrong endpoint for this region"
    return why


def _collapse(notes: list) -> list:
    """Fold notes that share one cause into one line.

    When the network is down every product fails the same way, and twenty-two
    copies of the same URLError bury the one sentence worth reading. The products
    are still named, because "which ones" is a fair question.
    """
    shared = [("a host name would not resolve — DNS or connectivity",
               ("nodename nor servname", "name or service not known",
                "getaddrinfo", "name resolution")),
              ("the connection timed out", ("timed out", "timeout")),
              ("the connection was refused or reset",
               ("connection refused", "connection reset", "broken pipe"))]
    out, folded = [], {}
    for note in notes:
        low = note.lower()
        for label, needles in shared:
            if any(n in low for n in needles):
                folded.setdefault(label, []).append(note.split(":", 1)[0])
                break
        else:
            out.append(note)
    for label, who in folded.items():
        if len(who) == 1:
            out.append(f"{who[0]}: {label}")
        else:
            names = ", ".join(who[:4]) + (f" and {len(who) - 4} more"
                                          if len(who) > 4 else "")
            out.append(f"{len(who)} products could not be read — {label} "
                       f"({names})")
    return out


def _looks_like_region(value: str) -> bool:
    """Is this an Alibaba region id rather than somebody's name for a place?

    Ids are lower case with a dash: me-central-1, cn-hangzhou, ap-southeast-1.
    "SAU" and "Riyadh" are not, and cannot be turned into a host name.
    """
    return bool(re.fullmatch(r"[a-z]{2,3}-[a-z0-9-]+", str(value or "")))


def _alibaba_inventory(c: dict, region_want: str = "") -> dict:
    """Everything this account holds in one region, plus what is account-wide.

    Products are read in parallel and fail independently: one product without
    permission must not blank the page, and its own note says which and why.
    """
    from .fleet import _pmap
    notes = []
    regions = alibaba_regions(c)
    want = region_want or c.get("region", "")
    try:
        region, note = alibaba_resolve_region(want, regions)
    except CloudError as e:
        return {"groups": [], "notes": [str(e)], "region": want,
                "regions": regions, "billing": {}, "security": {}}
    if note:
        notes.append(note)
    rid = region["id"]

    if note and _looks_like_region(rid) and c.get("id"):
        # Resolve a name to an id once, and keep it. Working it out needs the
        # region list, so a page load during a DNS blip could not do it — and
        # since it was only remembered in memory, a restart lost it and the
        # account read as empty. Written back, the guesswork happens once ever.
        try:
            from . import store
            store.update_conn("cloud", c.get("pid", ""), c["id"], region=rid)
            c["region"] = rid
            notes[-1] += " — saved, so it does not have to be worked out again"
        except Exception:                                     # noqa: BLE001
            pass

    if not regions:
        # The list could not be read. A region already known to work is better
        # than a guess; a value that is not id-shaped cannot be used at all, and
        # asking twenty-two products at a host built from it produces twenty-two
        # identical DNS errors and no information.
        remembered = _LAST_REGION.get(c.get("key_id", ""))
        if remembered and not _looks_like_region(rid):
            notes.append(f"the region list could not be read — using "
                         f"{remembered}, which worked last time")
            rid = remembered
            region = {"id": rid, "name": "", "endpoint": ""}
        elif not _looks_like_region(rid):
            return {"groups": [], "region": rid, "regions": [],
                    "billing": {}, "security": {},
                    "notes": [f"the region list could not be read, and “{rid}” is "
                              f"a name rather than a region id, so nothing could "
                              f"be asked. Check that ecs.aliyuncs.com is "
                              f"reachable, or set the region to an id such as "
                              f"me-central-1."]}
        else:
            notes.append("the region list could not be read — carrying on with "
                         f"{rid}")
    else:
        _LAST_REGION[c.get("key_id", "")] = rid
    if _looks_like_region(c.get("region", "")):
        # a stored id is itself a memory of what works, and survives a restart
        _LAST_REGION.setdefault(c.get("key_id", ""), c["region"])

    def one(spec):
        try:
            return _one_product(c, spec, region, rid)
        except CloudError as e:
            return (None, f"{spec[1]}: {e}")
        except Exception as e:                                # noqa: BLE001
            # _pmap turns an exception into None, and the loop below skipped
            # None — so a product that timed out vanished from the page with
            # nothing said about it. RAM disappeared exactly this way.
            why = "timed out" if "timed out" in str(e).lower() else f"{type(e).__name__}: {e}"
            return (None, f"{spec[1]}: {why}")

    def _one_product(c, spec, region, rid):
        key, label, icon, host, version, action, extra, reader = spec
        # an account-wide product carries its own host; a regional one is built
        # from the endpoint this region actually publishes
        if "." in host:
            endpoint = host
        elif host == "ecs":
            endpoint = region.get("endpoint") or f"ecs.{rid}.aliyuncs.com"
        else:
            endpoint = f"{host}.{rid}.aliyuncs.com"
        code, doc = _alibaba_rpc(c, action, version, endpoint, rid, extra)
        if code != 200:
            return (None, f"{label}: {_ali_why(doc, code)}")
        try:
            rows = reader(doc)
        except Exception as e:                                # noqa: BLE001
            return (None, f"{label}: unexpected shape ({type(e).__name__})")
        return ({"key": key, "label": label, "icon": icon, "rows": rows}, None)

    groups = []
    # six at a time, not twenty: the far end resets connections under a burst,
    # and a retried product is slower than a product that answered first time
    for got in _pmap(one, ALI_PRODUCTS, workers=6) or []:
        if not got:
            continue
        group, why = got
        if group:
            groups.append(group)
        elif why:
            notes.append(why)

    repos, why = alibaba_registry(c, rid)
    if why:
        notes.append(why)
    if not why or repos:
        groups.append({"key": "registry", "label": "Container registry",
                       "icon": "📦", "rows": repos,
                       "columns": ["repository", "type", "status", "instance",
                                   "changed"]})

    buckets, why = alibaba_buckets(c, rid)
    if why:
        notes.append(why)
    else:
        groups.append({"key": "oss", "label": "OSS buckets", "icon": "🪣",
                       "rows": buckets,
                       "columns": ["bucket", "storage class", "", "endpoint",
                                   "region"]})

    security = _alibaba_exposure(c, groups, rid, notes)
    billing = _alibaba_billing(c, notes)
    if billing.get("rows"):
        groups.append({"key": "billing", "label": f"Spend this month ({billing['month']})",
                       "icon": "💳", "rows": billing["rows"],
                       "columns": ["product", "subscription", "", "amount",
                                   "period"]})
    if regions:
        notes.append(f"Resources are per region — this is {rid}. "
                     f"{len(regions)} regions are available to this account; "
                     f"RAM, billing and resource groups are account-wide.")
    # folded at the very end, so a shared cause covers the products, the buckets
    # and the billing call rather than only the products
    return {"groups": groups, "notes": _collapse(notes), "region": rid,
            "regions": regions, "billing": billing, "security": security}


def _other_inventory(c: dict) -> dict:
    code, text = _get(c["base_url"], {"Authorization": f"Bearer {c['secret']}"}
                      if c.get("secret") and not c.get("key_id") else {})
    return {"groups": [], "region": "",
            "notes": [f"Generic endpoint: HTTP {code}. The portal has no schema "
                      "for this provider, so it reports reachability only — the "
                      "account is registered and verified, not inventoried."]}


def _gcp_inventory(c: dict) -> dict:
    try:
        doc = json.loads(c.get("secret") or "{}")
    except json.JSONDecodeError:
        doc = {}
    return {"groups": [], "region": doc.get("project_id", ""),
            "notes": ["Google Cloud is registered but not inventoried: calling "
                      "its APIs needs an RSA-signed JWT, which the standard "
                      "library cannot produce. Everything else about this "
                      "account is stored and validated."]}


INVENTORY = {"aws": _aws_inventory, "azure": _azure_inventory,
             "alibaba": _alibaba_inventory, "gcp": _gcp_inventory,
             "other": _other_inventory}


# The hub must never wait on a cloud API. Same lesson as the log stores: a
# dashboard showing slightly-old numbers instantly beats fresh numbers slowly,
# and four accounts × two API calls × a slow region is a page nobody opens
# twice. So a daemon warmer owns the fetching and peek() reads cache only.
WARM_EVERY = 150.0
_warm_started = False
_warm_lock = __import__("threading").Lock()


def warm_start() -> None:
    global _warm_started
    import threading
    with _warm_lock:
        if _warm_started:
            return
        _warm_started = True
    threading.Thread(target=_warm_loop, name="cloud-warmer", daemon=True).start()


def _warm_loop() -> None:
    import time as _t
    from . import store
    while True:
        try:
            conns = store.all_cloud()
        except Exception:                                     # noqa: BLE001
            conns = []
        for c in conns:
            try:
                inventory(c)
            except Exception:                                 # noqa: BLE001
                pass
            if c.get("type") == "alibaba":
                # the spend trend as well: a restarted process loses the cache,
                # and nobody should meet "collecting…" because of a deploy
                try:
                    alibaba_bills(c, 12)
                except Exception:                             # noqa: BLE001
                    pass
        _t.sleep(WARM_EVERY)


def warm_now() -> None:
    """One forced pass, off-thread — the Refresh button."""
    import threading
    from . import store

    def run():
        for c in store.all_cloud():
            try:
                inventory(c, refresh=True)
            except Exception:                                 # noqa: BLE001
                pass
    threading.Thread(target=run, name="cloud-refresh", daemon=True).start()


def bills(conn: dict, months: int = 12, refresh: bool = False) -> dict:
    """Monthly cost for whichever provider this account is.

    One entry point so the pages do not each have to know which reader belongs
    to which provider — the bills page called the Alibaba one for every account,
    which meant an AWS account had a bills page with no months in it.
    """
    kind = conn.get("type")
    if kind == "aws":
        return aws_bills(conn, months, refresh)
    if kind == "alibaba":
        return alibaba_bills(conn, months, refresh)
    return {"months": [], "series": [], "labels": [], "by_product": [],
            "currency": "", "total": 0.0, "stale_for": 0,
            "notes": [f"the portal cannot read bills for {kind or 'this provider'} "
                      f"yet — AWS and Alibaba Cloud are implemented"]}


def bills_peek(conn: dict, months: int = 12) -> dict | None:
    """The cached bills, kicking a collection off if there are none yet.

    The account page wants a spend trend but must not wait a second and a half
    for twelve months of API calls. So it asks for what is already known, and the
    chart appears on the next view.
    """
    key = (("aws-bills", conn.get("key_id", ""), int(months))
           if conn.get("type") == "aws"
           else (conn.get("key_id", ""), int(months)))
    hit = _BILLS.get(key)
    if hit:
        return hit[1]
    import threading
    if key not in _refreshing:
        _refreshing.add(key)

        def run():
            try:
                bills(conn, months, refresh=True)
            except Exception:                                 # noqa: BLE001
                pass
            finally:
                _refreshing.discard(key)
        threading.Thread(target=run, name="bills-warm", daemon=True).start()
    return None


def peek(conn: dict, region: str = "") -> dict | None:
    """The cached inventory, or None if the warmer has not reached it yet.
    Never touches the network, so the hub cannot be slow."""
    hit = _inv.get(_inv_key(conn, region))
    return hit[1] if hit else None


def _readable_failure(e: Exception) -> str:
    """A failed collection, in words rather than in exception spelling."""
    text = str(e).lower()
    if any(t in text for t in ("nodename nor servname", "name or service not known",
                              "getaddrinfo", "name resolution")):
        return ("this account could not be reached: a host name would not "
                "resolve. That is DNS or connectivity, not the account — the "
                "last known contents are shown if there are any.")
    if "timed out" in text or "timeout" in text:
        return ("this account could not be read in time — Alibaba was slow or "
                "unreachable. The last known contents are shown if there are any.")
    if "certificate" in text:
        return f"the TLS certificate was refused: {e}"
    return f"this account could not be read — {type(e).__name__}: {e}"


def inventory(conn: dict, refresh: bool = False, region: str = "") -> dict:
    """{groups: [{key,label,icon,rows:[…]}], notes: [...], region, error}

    `region` overrides the account's configured one for this look only, which is
    what the region switcher on the page uses — cloud resources are per region and
    an account with work in three of them should not need three connections.
    """
    key = _inv_key(conn, region)
    hit = _inv.get(key)
    fresh = hit and time.time() - hit[0] < INV_TTL
    if hit and not refresh and fresh:
        return hit[1]
    if hit and not refresh:
        # Stale, but present: hand it over now and collect a new one behind the
        # page. Twenty products across a slow link is seconds of waiting, and
        # nobody wants to watch that to see a count that changes hourly. The age
        # travels with it so the page can say how old it is.
        _revalidate(conn, region)
        return {**hit[1], "stale_for": round(time.time() - hit[0])}
    fn = INVENTORY.get(conn.get("type"))
    if not fn:
        got = {"groups": [], "notes": [], "region": "",
               "error": f"unknown provider '{conn.get('type')}'"}
    else:
        try:
            # only the providers whose resources are region-scoped take one
            # both region-scoped providers take an override; the others do not
            got = ({**fn(conn, region), "error": ""}
                   if region and fn in (_alibaba_inventory, _aws_inventory)
                   else {**fn(conn), "error": ""})
        except CloudError as e:
            got = {"groups": [], "notes": [], "region": "", "error": str(e)}
        except Exception as e:                                # noqa: BLE001
            # "URLError: <urlopen error [Errno 8] nodename nor servname
            # provided>" next to "0 resources" reads as an empty account. Say
            # what failed, in words, and keep whatever was known before.
            got = {"groups": [], "notes": [], "region": "",
                   "error": _readable_failure(e)}
            stale = _inv.get(key)
            if stale:
                got = {**stale[1], "error": _readable_failure(e),
                       "stale_for": round(time.time() - stale[0])}
    got["total"] = sum(len(g["rows"]) for g in got["groups"])
    got["stale_for"] = 0
    previous = _inv.get(key)
    if not got["total"] and previous and previous[1].get("total"):
        # A collection that came back with nothing, when the last one had
        # contents, is far more likely to be a failed collection than an emptied
        # account — and "0 resources" is a much worse lie than stale numbers. The
        # notes explaining the failure are carried over so it is not a silent
        # substitution.
        kept = {**previous[1], "notes": got["notes"] + previous[1].get("notes", []),
                "stale_for": round(time.time() - previous[0]),
                "error": got.get("error", "")}
        _inv[key] = (previous[0], kept)
        return kept
    _inv[key] = (time.time(), got)
    return got


def _revalidate(conn: dict, region: str) -> None:
    """Collect a fresh inventory off-thread, once per key at a time."""
    import threading
    key = _inv_key(conn, region)
    if key in _refreshing:
        return
    _refreshing.add(key)

    def run():
        try:
            inventory(conn, refresh=True, region=region)
        except Exception:                                     # noqa: BLE001
            pass
        finally:
            _refreshing.discard(key)
    threading.Thread(target=run, name="cloud-revalidate", daemon=True).start()


def invalidate() -> None:
    _inv.clear()
    _BILLS.clear()
