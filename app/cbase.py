"""Couchbase management, over the REST API rather than the SDK.

WHY REST AND NOT THE SDK
    The official SDK is a C++ extension. Everything else this image needs ships
    as a pure or manylinux wheel and the container has no compiler, which is a
    property worth keeping for one integration. Couchbase's own administration
    interface is HTTP on 8091 and the query service is HTTP on 8093, so there is
    nothing the SDK would give us here that a JSON call does not — and the
    cluster manager API is the more stable of the two across versions.

WHY VERSION DETECTION IS THE FIRST THING IT DOES
    Couchbase changed shape twice in ways that matter to this file:

      5.0  introduced cluster-wide RBAC users. Before it, a bucket carried its
           own SASL password and /settings/rbac/users does not exist.
      7.0  introduced scopes and collections. Before it, a bucket is flat.

    The estate this was written for runs 4.6.4, which has neither. Writing to
    the current documentation would have produced a collection browser that
    404s and a users tab that renders an empty table — and an empty table is
    the failure worth avoiding, because it reads as "no users exist" rather
    than "this server cannot answer that". Anything unavailable says so and
    says why, in the same way the Wazuh reader does for 4.8 vulnerabilities.

CREDENTIALS
    Nothing is stored. A server is registered by host and port; whoever opens
    the console types their own Couchbase account, it is held in memory for
    that session and never written to disk. This mirrors dbconn exactly, and
    for the same reason: the audit trail on the server names a real person.

    That also means this module never sees a credential it can persist, so
    there is nothing here for secretbox to encrypt.

READ AND WRITE
    Reads are always allowed. Creating a bucket is a write and needs the
    console switched into write mode first, which is its own audited action.
    Flush and delete are deliberately absent — see `bucket_create`.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import urlguard
# BOOT is shared rather than generated again here. It answers one question —
# "did the process that issued this ticket restart" — and that is a property of
# the process, not of an engine. Two stamps would mean two ways to be wrong
# about it, and the session only carries one.
from .dbconn import BOOT, DBError, FRESH, IDLE, TIMEOUT, label, port_of

__all__ = ["DBError", "label", "test", "connect", "open_console", "console",
           "session", "session_of", "set_write", "close_console", "BOOT",
           "Console"]

QUERY_PORT = 8093           # the N1QL/SQL++ service, separate from 8091
QUERY_TIMEOUT = 75          # a statement, in seconds
MAX_ROWS = 500              # rows handed to a browser

# What each generation can answer. Checked by name so the reason can be shown.
NEEDS_5 = "cluster-wide users arrived in Couchbase 5.0"
NEEDS_7 = "scopes and collections arrived in Couchbase 7.0"


# ── talking to the cluster ─────────────────────────────────────
def _req(host: str, port: int, path: str, creds: dict | None,
         data: dict | None = None, method: str = "",
         timeout: int = TIMEOUT) -> tuple[int, str]:
    """One call. Returns (status, body) and raises only on transport failure.

    A non-2xx is returned rather than raised because Couchbase puts the useful
    part in the body — "RAM quota specified is too large" comes back as a 400
    with a field-by-field explanation, and turning that into a bare HTTPError
    would throw away the only thing worth showing the operator.
    """
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    # The guard is called here, in plain sight, rather than inside a URL helper.
    # tests/test_urlguard.py reads the source and wants it within sight of the
    # Request — and it is right to: a reader cannot tell that a URL built three
    # calls away was checked, which is how an unguarded fetch survives review.
    req = urllib.request.Request(
        urlguard.check(f"http://{host}:{port}{path}"), data=body,
        # `data is not None`, not `data` — an empty form is still a POST. Written
        # as a truth test, stopRebalance (which takes no fields) went out as a
        # GET and came back 404, which reads as "this cluster cannot stop a
        # rebalance" rather than "the portal asked in the wrong verb".
        method=method or ("POST" if data is not None else "GET"))
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if creds and creds.get("user"):
        import base64
        raw = f"{creds['user']}:{creds.get('password', '')}".encode()
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise DBError(f"cannot reach {host}:{port} — "
                      f"{getattr(e.reason, 'strerror', None) or e.reason}") from e
    except socket.timeout as e:
        raise DBError(f"no answer from {host}:{port} within {timeout}s") from e


def _explain(status: int, body: str, what: str, user: str = "") -> str:
    """Couchbase's own words where it has any, and a plain sentence where not.

    `user` is threaded in only to keep a refusal accurate: "that account is not
    permitted" is the right sentence for a real account with too few roles, and
    the wrong one when nothing was sent at all.
    """
    detail = ""
    try:
        doc = json.loads(body)
        if isinstance(doc, dict):
            errs = doc.get("errors")
            if isinstance(errs, dict):
                detail = "; ".join(f"{k}: {v}" for k, v in errs.items())
            elif isinstance(errs, list):
                detail = "; ".join(str(e.get("msg") or e) for e in errs)
            detail = detail or str(doc.get("_") or doc.get("reason") or "")
        elif isinstance(doc, list) and doc:
            detail = "; ".join(str(x) for x in doc)
    except ValueError:
        detail = body.strip()[:300]
    if status in (401, 403) and not user:
        return (f"this cluster requires an account to {what}, and this console "
                f"holds none. Open it again with a Couchbase account that has "
                f"the Cluster Admin or Read-Only Admin role.")
    if status == 401:
        return (f"Couchbase rejected the credentials for this session. Open the "
                f"console again with an account that has the Cluster Admin or "
                f"Read-Only Admin role.")
    if status == 403:
        return (f"{user} is authenticated but not permitted to {what}. "
                f"{detail}".strip())
    if status == 404:
        return f"this cluster has no endpoint for {what} — {detail or 'not found'}"
    return f"{what} failed ({status})" + (f" — {detail}" if detail else "")


def _json(host: str, port: int, path: str, creds: dict | None, what: str,
          timeout: int = TIMEOUT):
    status, body = _req(host, port, path, creds, timeout=timeout)
    if status >= 300:
        raise DBError(_explain(status, body, what,
                               (creds or {}).get("user", "")))
    try:
        return json.loads(body)
    except ValueError as e:
        raise DBError(f"{what}: the server did not answer with JSON") from e


# ── version ────────────────────────────────────────────────────
def _version_of(doc: dict, pool: dict | None = None) -> tuple[str, tuple[int, int]]:
    """The cluster's version as text, and as (major, minor) for comparisons.

    /pools gives implementationVersion like "4.6.4-4590-enterprise"; a node
    gives the same in `version`. Either can be missing on a partly initialised
    cluster, and an unparsable version must not stop the page rendering — it
    degrades to (0, 0), which simply means "assume nothing newer works".
    """
    raw = str(doc.get("implementationVersion")
              or ((pool or {}).get("nodes") or [{}])[0].get("version") or "")
    parts = raw.split("-")[0].split(".")
    try:
        return raw, (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return raw, (0, 0)


# ── reachability, with no credentials ──────────────────────────
def probe(host: str, port: int) -> tuple[str, bool]:
    """Is something at this address Couchbase. Returns (note, answered_openly).

    THIS DELIBERATELY DOES NOT AUTHENTICATE, AND A 401 IS A PASS.
        The settings page has no credentials to offer — none are stored, by
        design — so the only question it can ask is the same one the PostgreSQL
        and MySQL probes ask: did the port answer, and did it answer as the
        thing we expect. A cluster that refuses to describe itself without an
        account has answered both, and is working exactly as it should.

        The first version raised on 401, which reported a correctly secured
        production cluster as "failed" and then told the operator to "open the
        console again" — advice from the console's own error path, on a button
        that never opens one. Meanwhile a cluster that hands its topology to
        anonymous callers passed. The test was rewarding the misconfiguration
        and failing the hardened server.

        So the anonymous case is now the one that gets remarked on, because
        being able to read a cluster's name, version and bucket inventory
        without an account is worth knowing about.
    """
    status, body = _req(host, port, "/pools", None)
    if status in (401, 403):
        return ("Couchbase, and it requires an account before it will describe "
                "itself. Nothing more can be read from here without one, which "
                "is correct — the version, buckets and the rest are read at the "
                "console with your own credentials", False)
    if status >= 300:
        raise DBError(_explain(status, body, "read the cluster version"))
    try:
        doc = json.loads(body)
    except ValueError:
        raise DBError("that port answered, but not as Couchbase") from None
    if not isinstance(doc, dict) or "pools" not in doc:
        raise DBError("that port answered, but not as Couchbase")
    raw, _ = _version_of(doc)
    edition = "Enterprise" if doc.get("isEnterprise") else "Community"
    pools = ", ".join(p.get("name", "?") for p in (doc.get("pools") or []))
    if not pools:
        return (f"Couchbase {raw or '?'} {edition}, but no cluster has been "
                f"provisioned on it yet", True)
    return f"Couchbase {raw or '?'} {edition}, cluster '{pools}'", True


def test(conn: dict) -> tuple[bool, str]:
    host = (conn.get("host") or "").strip()
    port = port_of(conn)
    if not host:
        return False, "no host"
    try:
        note, open_to_anyone = probe(host, port)
    except DBError as e:
        return False, str(e)
    except Exception as e:                                     # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    if not open_to_anyone:
        return True, f"reachable — {note}."
    # Said plainly, because it is a finding and not a convenience: everything in
    # that note was read with no credentials at all.
    return True, (f"reachable — {note}. Note that it answered all of that "
                  f"WITHOUT any credentials, so its version, node names and "
                  f"bucket inventory are readable by anyone who can reach this "
                  f"port. Credentials are still asked for at the console.")


# ── proving credentials before they are kept ───────────────────
class _Probe:
    """Closeable, so the open route can prove credentials with the same
    `contextlib.closing(engine.connect(...))` it uses for a SQL server."""

    def close(self) -> None:
        return None


def connect(conn: dict, creds: dict, database: str = "") -> _Probe:
    """Prove the account works and has enough rights to be useful.

    /pools/default is the cheapest call that actually requires authorisation on
    a secured cluster. Holding a password that turns out to be wrong, and only
    discovering it on the first real request, leaves a useless secret in memory
    and blames the wrong thing.

    A caveat worth stating: some clusters — including the 4.6 one this was
    written against — serve /pools/default to anonymous callers, so a successful
    open does not by itself prove the credentials are good. The first
    administrative call will say so if they are not.
    """
    host = (conn.get("host") or "").strip()
    port = port_of(conn)
    if not host:
        raise DBError("no host")
    status, body = _req(host, port, "/pools/default", creds)
    if status == 401:
        raise DBError("Couchbase rejected that username or password")
    if status >= 300:
        raise DBError(_explain(status, body, "read the cluster",
                               creds.get("user", "")))
    return _Probe()


# ── one operator, one cluster ──────────────────────────────────
class Console:
    """Mirrors dbconn.Console's lifecycle so the routes need not care which
    engine they hold: same ticket, same idle expiry, same write toggle.

    There are no pooled connections to manage — every call is an HTTP request —
    so what the lock guards here is the cache, not a cursor.
    """

    def __init__(self, cid: str, uid: str, user: str, password: str,
                 server: dict):
        self.cid, self.uid, self.user = cid, uid, user
        self._password = password
        self.server = dict(server)
        self.write = False
        self.opened = self.used = time.time()
        self.history: list[dict] = []
        self._lock = threading.RLock()
        self._cache: dict[str, tuple[float, object]] = {}

    # ── plumbing ───────────────────────────────────────────────
    @property
    def creds(self) -> dict:
        return {"user": self.user, "password": self._password}

    @property
    def host(self) -> str:
        return (self.server.get("host") or "").strip()

    @property
    def port(self) -> int:
        return port_of(self.server)

    @property
    def qport(self) -> int:
        try:
            p = int(str(self.server.get("query_port") or "").strip())
        except ValueError:
            p = 0
        return p or QUERY_PORT

    def close(self) -> None:
        with self._lock:
            self._cache.clear()
            self._password = ""

    def open_connections(self) -> int:
        return 0            # HTTP, nothing held open — shown as such in the UI

    def _touch(self) -> None:
        self.used = time.time()

    def _cached(self, key: str, make, fresh: float = FRESH, force: bool = False):
        with self._lock:
            self._touch()
            hit = self._cache.get(key)
            if hit and not force and time.time() - hit[0] < fresh:
                return hit[1]
            out = make()
            self._cache[key] = (time.time(), out)
            return out

    def forget(self, prefix: str = "") -> None:
        with self._lock:
            for k in [k for k in self._cache if not prefix or k.startswith(prefix)]:
                self._cache.pop(k, None)

    def _get(self, path: str, what: str, timeout: int = TIMEOUT):
        return _json(self.host, self.port, path, self.creds, what, timeout)

    def _need_write(self, what: str) -> None:
        if not self.write:
            raise DBError(f"this console is read-only — switch it to write mode "
                          f"before you {what}")

    # ── version, and what this cluster can be asked ────────────
    def version(self, force: bool = False) -> dict:
        return self._cached("version", self._version, fresh=300, force=force)

    def _version(self) -> dict:
        pools = self._get("/pools", "read the cluster version")
        pool: dict = {}
        try:
            pool = self._get("/pools/default", "read the cluster")
        except DBError:
            pass                       # unprovisioned; the version still shows
        raw, tup = _version_of(pools, pool)
        return {"text": raw, "tuple": tup,
                "enterprise": bool(pools.get("isEnterprise")),
                "has_rbac": tup >= (5, 0), "has_collections": tup >= (7, 0)}

    # ── overview ───────────────────────────────────────────────
    def overview(self, force: bool = False) -> dict:
        return self._cached("overview", self._overview, force=force)

    def _overview(self) -> dict:
        pool = self._get("/pools/default", "read the cluster")
        ver = self.version()
        ram = (pool.get("storageTotals") or {}).get("ram") or {}
        hdd = (pool.get("storageTotals") or {}).get("hdd") or {}
        nodes = [self._node(n) for n in (pool.get("nodes") or [])]
        # A cluster mid-rebalance, or with a node down, is the thing an operator
        # opened this page to find out. It goes at the top, not in a tab.
        warn = [str(a) for a in (pool.get("alerts") or [])][:6]
        down = [n["hostname"] for n in nodes if n["status"] != "healthy"]
        if down:
            warn.insert(0, f"{len(down)} node(s) not healthy: {', '.join(down)}")
        return {
            "name": pool.get("clusterName") or "",
            "version": ver["text"], "enterprise": ver["enterprise"],
            "nodes": nodes,
            "rebalance": pool.get("rebalanceStatus") or "none",
            "buckets_max": pool.get("maxBucketCount") or 0,
            "quota_mb": pool.get("memoryQuota") or 0,
            "index_quota_mb": pool.get("indexMemoryQuota") or 0,
            "fts_quota_mb": pool.get("ftsMemoryQuota") or 0,
            "ram": {"total": ram.get("total") or 0,
                    "used": ram.get("used") or 0,
                    "quota_total": ram.get("quotaTotal") or 0,
                    "quota_used": ram.get("quotaUsed") or 0,
                    "by_data": ram.get("usedByData") or 0},
            "hdd": {"total": hdd.get("total") or 0,
                    "used": hdd.get("used") or 0,
                    "free": hdd.get("free") or 0,
                    "by_data": hdd.get("usedByData") or 0},
            "services": sorted({s for n in nodes for s in n["services"]}),
            "alerts": warn,
        }

    @staticmethod
    def _node(n: dict) -> dict:
        stats = n.get("interestingStats") or {}
        sys = n.get("systemStats") or {}
        return {
            "hostname": n.get("hostname") or "?",
            # The cluster's own name for this node. A rebalance is asked for by
            # otpNode, never by hostname, and sending the wrong set is how a
            # node gets ejected by accident — so it is carried, not derived.
            "otp": n.get("otpNode") or "",
            "status": n.get("status") or "unknown",
            "membership": n.get("clusterMembership") or "",
            "version": (n.get("version") or "").split("-")[0],
            "os": n.get("os") or "",
            "services": sorted(n.get("services") or []),
            "this": bool(n.get("thisNode")),
            "uptime": _uptime(n.get("uptime")),
            "ram_total": n.get("memoryTotal") or 0,
            "ram_free": n.get("memoryFree") or 0,
            "cpu": round(float(sys.get("cpu_utilization_rate") or 0), 1),
            # Named "docs", not "items": a template reaching for `node.items`
            # gets the dict's own .items method instead of this value, and the
            # only symptom is a format error a long way from the cause.
            "docs": stats.get("curr_items") or 0,
            "docs_replica": stats.get("vb_replica_curr_items") or 0,
            "ops": stats.get("ops") or 0,
            "disk": stats.get("couch_docs_actual_disk_size") or 0,
        }

    # ── buckets ────────────────────────────────────────────────
    def buckets(self, force: bool = False) -> list[dict]:
        return self._cached("buckets", self._buckets, force=force)

    def _buckets(self) -> list[dict]:
        doc = self._get("/pools/default/buckets?skipMap=true",
                        "list the buckets")
        if not isinstance(doc, list):
            raise DBError("the bucket list did not come back as a list")
        out = []
        for b in doc:
            st = b.get("basicStats") or {}
            quota = (b.get("quota") or {}).get("ram") or 0
            ctl = b.get("controllers") or {}
            out.append({
                "name": b.get("name") or "?",
                "type": b.get("bucketType") or "",
                "quota": quota,
                "quota_pct": round(float(st.get("quotaPercentUsed") or 0), 1),
                "docs": st.get("itemCount") or 0,   # see _node
                "ops": round(float(st.get("opsPerSec") or 0), 1),
                "disk": st.get("diskUsed") or 0,
                "data": st.get("dataUsed") or 0,
                "mem": st.get("memUsed") or 0,
                "fetches": st.get("diskFetches") or 0,
                "replicas": b.get("replicaNumber", 0),
                "eviction": b.get("evictionPolicy") or "",
                "conflict": b.get("conflictResolutionType") or "",
                "threads": b.get("threadsNumber") or 0,
                "nodes": len(b.get("nodes") or []),
                # 4.x reports a bucket's own SASL auth; 5.0+ uses cluster RBAC.
                # Shown because "no bucket password" on an exposed cluster is a
                # finding, not a detail.
                "auth": b.get("authType") or "",
                "sasl_set": bool(b.get("saslPassword")),
                "can_flush": "doFlush" in ctl,
            })
        return sorted(out, key=lambda r: r["name"])

    def bucket(self, name: str) -> dict:
        one = self._get(f"/pools/default/buckets/{urllib.parse.quote(name)}",
                        f"read bucket {name}")
        st = one.get("basicStats") or {}
        return {"name": one.get("name"), "raw_stats": st,
                "type": one.get("bucketType"),
                "compaction": one.get("autoCompactionSettings") or {},
                "capabilities": sorted(one.get("bucketCapabilities") or [])}

    def bucket_create(self, name: str, ram_mb: int, replicas: int = 1,
                      btype: str = "membase", eviction: str = "",
                      flush: bool = False) -> str:
        """Create a bucket. The one write this console offers, and why.

        Flush and delete are not implemented. Both destroy data outright, and a
        portal that can reach every cluster in an estate is the worst possible
        place to put a one-click version of them — the blast radius is a whole
        bucket and the undo is a restore. Couchbase's own console asks for the
        bucket name to be typed and is where they belong. Creating is additive,
        reversible by deleting there, and is what an operator actually wants
        from here.

        The payload differs by generation: before 5.0 a bucket carries its own
        SASL authentication and `authType` is mandatory, so it is sent only for
        those. Sending it to 7.x is not an error but it is dead weight, and
        sending nothing to 4.6 is rejected.
        """
        self._need_write("create a bucket")
        name = (name or "").strip()
        if not name:
            raise DBError("a bucket needs a name")
        try:
            ram_mb = int(ram_mb)
        except (TypeError, ValueError):
            raise DBError("the RAM quota must be a whole number of MB") from None
        if ram_mb < 100:
            # Couchbase enforces 100 too, but its message is less clear and this
            # saves a round trip on an obvious typo.
            raise DBError("Couchbase requires at least 100 MB per bucket")
        data = {"name": name, "ramQuotaMB": str(ram_mb),
                "bucketType": btype or "membase",
                "replicaNumber": str(int(replicas)),
                "flushEnabled": "1" if flush else "0"}
        if eviction:
            data["evictionPolicy"] = eviction
        if not self.version()["has_rbac"]:
            data["authType"] = "sasl"
            data["saslPassword"] = ""
        status, body = _req(self.host, self.port, "/pools/default/buckets",
                            self.creds, data=data)
        if status >= 300:
            raise DBError(_explain(status, body, f"create bucket {name}",
                                   self.user))
        self.forget("buckets")
        self.forget("overview")
        return (f"bucket {name} created — {ram_mb} MB, "
                f"{replicas} replica(s). Couchbase warms it up in the background.")

    # ── rebalance ──────────────────────────────────────────────
    def rebalance(self, force: bool = False) -> dict:
        # Short cache: while one is running this is the progress bar, and a
        # twenty-second-old percentage is worse than none.
        return self._cached("rebalance", self._rebalance, fresh=5, force=force)

    def _rebalance(self) -> dict:
        """Whether one is running, and whether one is needed.

        Those are different questions and only the second is easy to miss. A
        node that has been added but not yet rebalanced into the cluster, or one
        that was failed over, holds no data and serves nothing — the cluster is
        smaller than it looks and nothing says so until somebody opens the
        Couchbase console. Couchbase marks both in clusterMembership.
        """
        pool = self._get("/pools/default", "read the cluster")
        nodes = [self._node(n) for n in (pool.get("nodes") or [])]
        try:
            tasks = self._get("/pools/default/tasks", "read the cluster tasks")
        except DBError:
            tasks = []
        task = next((t for t in (tasks if isinstance(tasks, list) else [])
                     if t.get("type") == "rebalance"), {})
        pending = [n for n in nodes
                   if n["membership"] in ("inactiveAdded", "inactiveFailed")]
        running = (str(task.get("status") or "") == "running"
                   or str(pool.get("rebalanceStatus") or "") == "running")
        per_node = {}
        for otp, v in (task.get("perNode") or {}).items():
            per_node[otp] = round(float((v or {}).get("progress") or 0), 1)
        return {
            "status": pool.get("rebalanceStatus") or "none",
            "running": running,
            "progress": round(float(task.get("progress") or 0), 1),
            "per_node": per_node,
            # inactiveAdded: added, holds nothing yet. inactiveFailed: failed
            # over, its data is on the replicas until a rebalance settles it.
            "pending": [{"host": n["hostname"], "why": n["membership"]}
                        for n in pending],
            "needed": bool(pending),
            "known": [n["otp"] for n in nodes if n["otp"]],
            "nodes": len(nodes),
        }

    def rebalance_start(self) -> str:
        """Redistribute data across the nodes the cluster already knows about.

        ejectedNodes is sent EMPTY, deliberately and always. The same endpoint
        removes nodes when that list is populated, and a rebalance that ejects
        is a different and much more consequential operation than one that
        redistributes — it is how a cluster loses a node by accident. This
        console cannot express it. Removing a node stays in Couchbase's own
        console, where the node being ejected is named on screen.

        knownNodes must be every node, by otpNode. Couchbase treats a node
        missing from that list as one to eject, so an incomplete list is the
        dangerous input, which is why this refuses when the cluster did not
        report identifiers for all of them.
        """
        self._need_write("rebalance the cluster")
        info = self.rebalance(force=True)
        if info["running"]:
            raise DBError("a rebalance is already running on this cluster")
        known = info["known"]
        if not known or len(known) != info["nodes"]:
            raise DBError(
                f"the cluster reported identifiers for {len(known)} of its "
                f"{info['nodes']} nodes. A rebalance sent with an incomplete "
                f"node list would eject the missing ones, so it has not been "
                f"sent. Use Couchbase's own console for this cluster.")
        status, body = _req(self.host, self.port, "/controller/rebalance",
                            self.creds,
                            data={"knownNodes": ",".join(known),
                                  "ejectedNodes": ""})
        if status >= 300:
            raise DBError(_explain(status, body, "start a rebalance", self.user))
        self.forget()
        return (f"rebalance started across {len(known)} node(s), ejecting none. "
                f"It runs in the background — Refresh to follow the progress.")

    def rebalance_stop(self) -> str:
        """Stop one in flight. Safe: Couchbase leaves the cluster consistent and
        the rebalance can be started again, it just has more left to do."""
        self._need_write("stop a rebalance")
        status, body = _req(self.host, self.port, "/controller/stopRebalance",
                            self.creds, data={})
        if status >= 300:
            raise DBError(_explain(status, body, "stop the rebalance", self.user))
        self.forget()
        return ("rebalance stopped. The cluster is consistent; whatever had not "
                "moved yet still needs a rebalance.")

    # ── one bucket, in detail ──────────────────────────────────
    def bucket_detail(self, name: str) -> dict:
        """Everything about one bucket, including its scopes and collections."""
        one = self._get(f"/pools/default/buckets/{urllib.parse.quote(name)}",
                        f"read bucket {name}")
        if not isinstance(one, dict):
            # one bucket is an object and the collection is a list; a list here
            # means the request was answered by something else entirely.
            raise DBError(f"the cluster did not describe bucket {name} as a "
                          f"single bucket")
        st = one.get("basicStats") or {}
        comp = one.get("autoCompactionSettings")
        quota = (one.get("quota") or {}).get("ram") or 0
        return {
            "name": one.get("name") or name,
            "type": one.get("bucketType") or "",
            "quota": quota,
            "quota_pct": round(float(st.get("quotaPercentUsed") or 0), 1),
            "docs": st.get("itemCount") or 0,
            "ops": round(float(st.get("opsPerSec") or 0), 1),
            "disk": st.get("diskUsed") or 0,
            "data": st.get("dataUsed") or 0,
            "mem": st.get("memUsed") or 0,
            "fetches": st.get("diskFetches") or 0,
            "replicas": one.get("replicaNumber", 0),
            "replica_index": bool(one.get("replicaIndex")),
            "eviction": one.get("evictionPolicy") or "",
            "conflict": one.get("conflictResolutionType") or "",
            "threads": one.get("threadsNumber") or 0,
            "nodes": len(one.get("nodes") or []),
            "auth": one.get("authType") or "",
            "sasl_set": bool(one.get("saslPassword")),
            "durability": one.get("durabilityMinLevel") or "",
            "storage": one.get("storageBackend") or "",
            "ttl": one.get("maxTTL") or 0,
            "compression": one.get("compressionMode") or "",
            # False means "the server decides", not "never" — worth the
            # distinction because a bucket inheriting the cluster setting looks
            # identical to one with compaction switched off.
            "compaction": comp if isinstance(comp, dict) else None,
            "capabilities": sorted(one.get("bucketCapabilities") or []),
            "collections": self.collections(name),
        }

    # ── scopes and collections, 7.0 and later ──────────────────
    def collections(self, bucket: str) -> dict:
        ver = self.version()
        if not ver["has_collections"]:
            # Not an empty list: an empty list says "this bucket has none".
            return {"supported": False, "why": NEEDS_7,
                    "version": ver["text"], "scopes": []}
        try:
            doc = self._get(f"/pools/default/buckets/{urllib.parse.quote(bucket)}"
                            f"/scopes", f"list the scopes in {bucket}")
        except DBError as e:
            # A refusal is not "no scopes". Same rule as everywhere else here.
            return {"supported": True, "why": str(e), "version": ver["text"],
                    "scopes": []}
        scopes = []
        for s in (doc.get("scopes") or []):
            cols = []
            for c in (s.get("collections") or []):
                cols.append({"name": c.get("name") or "",
                             # 0 means "inherit the bucket's", not "never
                             # expire" — shown as such in the template.
                             "ttl": c.get("maxTTL") or 0,
                             "history": bool(c.get("history"))})
            scopes.append({"name": s.get("name") or "",
                           "collections": sorted(cols, key=lambda c: c["name"]),
                           "count": len(cols)})
        # _default exists on every 7.x bucket and is rarely what anyone came to
        # see, so it sorts last rather than being hidden — hiding it would make
        # a bucket that only has the default scope look like it failed to load.
        scopes.sort(key=lambda s: (s["name"].startswith("_"), s["name"]))
        return {"supported": True, "why": "", "version": ver["text"],
                "scopes": scopes,
                "total": sum(s["count"] for s in scopes)}

    # ── XDCR ───────────────────────────────────────────────────
    def xdcr(self, force: bool = False) -> dict:
        return self._cached("xdcr", self._xdcr, force=force)

    def _xdcr(self) -> dict:
        """Remote clusters, and the replications running to them.

        Two calls, because Couchbase keeps them apart: the remote cluster is a
        registered reference, and a replication is a task. A reference with no
        replication is a common and confusing state — a target was set up and
        nothing was ever pointed at it — so it is shown rather than hidden.

        Both endpoints need administrative rights. A 403 here is reported as
        such instead of an empty page, because "no replications" and "you may
        not see the replications" are opposite conclusions.
        """
        out: dict = {"remotes": [], "replications": [], "note": ""}
        try:
            remotes = self._get("/pools/default/remoteClusters",
                                "list the remote clusters")
        except DBError as e:
            out["note"] = str(e)
            return out
        for r in (remotes if isinstance(remotes, list) else []):
            if r.get("deleted"):
                continue
            out["remotes"].append({
                "name": r.get("name") or "?",
                "hostname": r.get("hostname") or "",
                "username": r.get("username") or "",
                "uuid": r.get("uuid") or "",
                "secure": bool(r.get("demandEncryption")
                               or r.get("secureType") not in (None, "none")),
            })
        try:
            tasks = self._get("/pools/default/tasks", "read the cluster tasks")
        except DBError as e:
            out["note"] = out["note"] or str(e)
            return out
        by_uuid = {r["uuid"]: r["name"] for r in out["remotes"]}
        for t in (tasks if isinstance(tasks, list) else []):
            if t.get("type") != "xdcr":
                continue
            # id is "<remoteUUID>/<source>/<target>" on every version that has
            # XDCR v2, which is everything from 2.x onward.
            ident = str(t.get("id") or "")
            ruuid = ident.split("/")[0] if "/" in ident else ""
            errs = [str(e) for e in (t.get("errors") or [])][:3]
            out["replications"].append({
                "source": t.get("source") or "",
                "target": str(t.get("target") or "").rsplit("/", 1)[-1],
                "remote": by_uuid.get(ruuid, ruuid[:8] or "?"),
                "status": t.get("status") or "unknown",
                "continuous": bool(t.get("continuous", True)),
                "changes_left": t.get("changesLeft") or 0,
                "docs_written": t.get("docsWritten") or 0,
                "errors": errs,
                "paused": str(t.get("status")) == "paused",
            })
        if out["remotes"] and not out["replications"]:
            out["note"] = ("a remote cluster is registered but nothing is "
                           "replicating to it")
        elif not out["remotes"]:
            out["note"] = "no remote cluster is registered, so XDCR is not set up"
        return out

    # ── indexes ────────────────────────────────────────────────
    def indexes(self, force: bool = False) -> dict:
        return self._cached("indexes", self._indexes, force=force)

    def _indexes(self) -> dict:
        """/indexStatus is cluster-wide and needs no query service to be up.

        Asking system:indexes over N1QL would be the other route, but it fails
        when the query service is down — which is exactly when an operator is
        looking at this page.
        """
        try:
            doc = self._get("/indexStatus", "read the index status")
        except DBError as e:
            return {"rows": [], "note": str(e)}
        rows = []
        for i in (doc.get("indexes") or []):
            rows.append({
                "name": i.get("index") or "?",
                "bucket": i.get("bucket") or "",
                "scope": i.get("scope") or "",
                "collection": i.get("collection") or "",
                "status": i.get("status") or "",
                "progress": i.get("progress") or 0,
                "hosts": ", ".join(i.get("hosts") or []),
                "definition": i.get("definition") or "",
                "replica": i.get("replicaId") or 0,
            })
        rows.sort(key=lambda r: (r["bucket"], r["name"]))
        note = "" if rows else "the cluster reports no secondary indexes"
        return {"rows": rows, "note": note}

    # ── users ──────────────────────────────────────────────────
    def users(self, force: bool = False) -> dict:
        return self._cached("users", self._users, fresh=120, force=force)

    def _users(self) -> dict:
        ver = self.version()
        if not ver["has_rbac"]:
            return {"supported": False, "why": NEEDS_5,
                    "version": ver["text"], "rows": []}
        try:
            doc = self._get("/settings/rbac/users", "list the users")
        except DBError as e:
            return {"supported": True, "why": str(e), "version": ver["text"],
                    "rows": []}
        rows = []
        for u in (doc if isinstance(doc, list) else []):
            rows.append({
                "id": u.get("id") or "?",
                "name": u.get("name") or "",
                "domain": u.get("domain") or "",
                "roles": sorted({(r.get("role") or "")
                                 + (f"[{r['bucket_name']}]"
                                    if r.get("bucket_name") else "")
                                 for r in (u.get("roles") or [])}),
            })
        return {"supported": True, "why": "", "version": ver["text"],
                "rows": sorted(rows, key=lambda r: r["id"])}

    def roles(self, force: bool = False) -> dict:
        """The roles this cluster will accept, so they can be picked not guessed.

        Couchbase rejects an unknown role with a message naming only the field,
        and the role names are not guessable — `bucket_full_access` versus
        `bucket_admin`, `data_reader` scoped per bucket. Offering the cluster's
        own catalogue is the difference between a form that works first time and
        one that fails with "roles: invalid".
        """
        return self._cached("roles", self._roles, fresh=600, force=force)

    def _roles(self) -> dict:
        ver = self.version()
        if not ver["has_rbac"]:
            return {"supported": False, "why": NEEDS_5, "rows": []}
        try:
            doc = self._get("/settings/rbac/roles", "list the available roles")
        except DBError as e:
            return {"supported": True, "why": str(e), "rows": []}
        rows = []
        for r in (doc if isinstance(doc, list) else []):
            role = r.get("role") or ""
            if not role:
                continue
            rows.append({
                "role": role,
                "name": r.get("name") or role,
                "desc": r.get("desc") or "",
                # A role carrying bucket_name in the catalogue is one that MUST
                # be qualified when assigned — role[bucket] — and assigning it
                # bare is rejected. The form needs to know which those are.
                "scoped": "bucket_name" in r,
            })
        seen, out = set(), []
        for r in sorted(rows, key=lambda x: x["role"]):
            if r["role"] in seen:
                continue                      # catalogues repeat scoped roles
            seen.add(r["role"])
            out.append(r)
        return {"supported": True, "why": "", "rows": out}

    def user_save(self, uid: str, name: str, roles: str, password: str = "",
                  new: bool = False) -> str:
        """Create or change a local Couchbase account.

        Local only. External accounts live in the directory this cluster is
        wired to, and pretending to manage those from here would write a local
        account that shadows a real one.

        The password is never stored, logged or echoed back. It goes into this
        one request and nothing else holds it — the caller must not put it in an
        audit line either, which is why this returns a message that does not
        contain it.
        """
        self._need_write("change a Couchbase account")
        ver = self.version()
        if not ver["has_rbac"]:
            raise DBError(f"this cluster is {ver['text']}, and {NEEDS_5}. "
                          f"Accounts here are per bucket and are not managed "
                          f"through this endpoint.")
        uid = (uid or "").strip()
        roles = ",".join(p.strip() for p in (roles or "").split(",") if p.strip())
        if not uid:
            raise DBError("an account needs a username")
        if not roles:
            raise DBError("an account with no roles can sign in and do nothing "
                          "— pick at least one role")
        if new and not password:
            raise DBError("a new local account needs a password")
        data = {"roles": roles, "name": (name or "").strip()}
        if password:
            data["password"] = password
        status, body = _req(
            self.host, self.port,
            f"/settings/rbac/users/local/{urllib.parse.quote(uid)}",
            self.creds, data=data, method="PUT")
        if status >= 300:
            raise DBError(_explain(status, body,
                                   f"save the account {uid}", self.user))
        self.forget("users")
        did = "created" if new else "updated"
        return (f"account {uid} {did} with role(s) {roles}"
                + (" and a new password" if password and not new else ""))

    # ── SQL++ / N1QL ───────────────────────────────────────────
    def query(self, statement: str, limit: int = MAX_ROWS) -> dict:
        """Run one statement against the query service.

        Read-only unless the console is in write mode. Couchbase enforces that
        itself when asked — `readonly=true` makes the service refuse anything
        that mutates, which is a far better guarantee than inspecting the
        statement here and guessing.
        """
        statement = (statement or "").strip().rstrip(";")
        if not statement:
            raise DBError("nothing to run")
        data = {"statement": statement, "pretty": "false",
                "timeout": f"{QUERY_TIMEOUT}s"}
        if not self.write:
            data["readonly"] = "true"
        began = time.time()
        try:
            status, body = _req(self.host, self.qport, "/query/service",
                                self.creds, data=data, timeout=QUERY_TIMEOUT + 5)
        except DBError as e:
            # The query service is a separate port and is often the one that is
            # not reachable, so name it rather than saying "the cluster".
            raise DBError(f"{e} — this is the query service on "
                          f"{self.host}:{self.qport}, not the admin port") from e
        took = time.time() - began
        try:
            doc = json.loads(body)
        except ValueError:
            raise DBError(_explain(status, body, "run the statement",
                                   self.user)) from None
        errs = doc.get("errors") or []
        if errs:
            first = errs[0] if isinstance(errs[0], dict) else {"msg": str(errs[0])}
            msg = str(first.get("msg") or first)
            code = first.get("code")
            if code == 13014 or status == 401:
                msg = ("Couchbase rejected the credentials for the query "
                       "service. The same account must exist there too.")
            elif "readonly" in msg.lower() and not self.write:
                msg = ("that statement changes data and this console is "
                       "read-only — switch it to write mode first")
            out = {"ok": False, "error": msg, "code": code, "rows": [],
                   "columns": [], "took": took, "count": 0, "truncated": False}
            self._remember(statement, out)
            return out
        rows = doc.get("results") or []
        truncated = len(rows) > limit
        rows = rows[:limit]
        # A projection can differ row to row, so the column set is the union in
        # first-seen order rather than the first row's keys.
        cols: list[str] = []
        for r in rows:
            if isinstance(r, dict):
                for k in r:
                    if k not in cols:
                        cols.append(k)
        metrics = doc.get("metrics") or {}
        out = {"ok": True, "error": "", "rows": rows, "columns": cols,
               "count": metrics.get("resultCount", len(rows)),
               "elapsed": metrics.get("elapsedTime") or "",
               "mutations": metrics.get("mutationCount") or 0,
               "took": took, "truncated": truncated,
               "status": doc.get("status") or ""}
        self._remember(statement, out)
        return out

    def _remember(self, statement: str, out: dict) -> None:
        with self._lock:
            self.history.insert(0, {
                "sql": statement, "at": time.time(),
                "ok": bool(out.get("ok")),
                "rows": len(out.get("rows") or []),
                "took": round(out.get("took") or 0, 3),
                "error": out.get("error") or ""})
            del self.history[40:]


def _uptime(seconds) -> str:
    try:
        s = int(float(seconds or 0))
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    d, rem = divmod(s, 86400)
    h, m = divmod(rem // 60, 60)
    if d:
        return f"{d}d {h}h"
    return f"{h}h {m}m" if h else f"{m}m"


# ── the console registry ───────────────────────────────────────
# Deliberately a copy of dbconn's rather than a shared one: the two hold
# different objects, and a single registry keyed only by ticket would let a
# Couchbase ticket resolve to a SQL console if a server's type ever changed
# under it. The duplication is a dozen lines and removes that class of bug.
import secrets                                                 # noqa: E402

_consoles: dict[str, Console] = {}
_reg_lock = threading.Lock()


def _reap() -> None:
    now = time.time()
    for ticket, con in list(_consoles.items()):
        if now - con.used > IDLE:
            con.close()
            _consoles.pop(ticket, None)


def open_console(cid: str, uid: str, user: str, password: str,
                 server: dict) -> str:
    ticket = secrets.token_urlsafe(24)
    with _reg_lock:
        _reap()
        _consoles[ticket] = Console(cid, uid, user, password, server)
    return ticket


def console(ticket: str, cid: str, uid: str) -> Console | None:
    with _reg_lock:
        _reap()
        con = _consoles.get(ticket or "")
        # The ticket alone is not enough: it must also be this user's console
        # for this server, so a ticket leaking into another session is inert.
        if not con or con.cid != cid or con.uid != uid:
            return None
        con._touch()
        return con


def session_of(con: Console | None) -> dict:
    if not con:
        return {}
    return {"user": con.user, "write": con.write, "opened": con.opened,
            "used": con.used, "held": con.open_connections(),
            "history": list(con.history)}


def session(ticket: str, cid: str, uid: str) -> dict | None:
    con = console(ticket, cid, uid)
    return session_of(con) if con else None


def set_write(ticket: str, on: bool) -> None:
    with _reg_lock:
        con = _consoles.get(ticket or "")
        if con:
            con.write = bool(on)


def close_console(ticket: str) -> None:
    with _reg_lock:
        con = _consoles.pop(ticket or "", None)
    if con:
        con.close()


def invalidate() -> None:
    with _reg_lock:
        for con in _consoles.values():
            con.forget()
