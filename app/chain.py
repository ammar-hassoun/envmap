"""What runs on each server, from the rack to the pod.

A server's BMC (Server hardware), the hypervisor host installed on it
(Hypervisors), the VMs on that host, the Kubernetes nodes those VMs are
(Clusters), and the pods on them — five things EnvMap already reads from four
places, joined here so one page can say what a power button takes down with
it. Asked for on 25 November 2026: "for each server, what runs on it".

HOW THE LAYERS ARE JOINED — BY IDENTITY, NOT BY NAME
    server ↔ host   The SMBIOS UUID a BMC reports (Redfish `UUID`) is the one
                    the hypervisor reports for the box it runs on
                    (`hardware.systemInfo.uuid`); failing that, the service
                    tag or serial (a Dell ESXi host reports its service tag as
                    its serial). On 24 November 2026 all eight dev ESXi hosts
                    matched their iDRACs both ways — and every one of them was
                    called localhost.localdomain, so a name would have joined
                    nothing.
    VM ↔ node       A VM's SMBIOS UUID (vSphere `config.uuid`, Proxmox
                    `smbios1`) is the `systemUUID` its kernel gives the node —
                    under VMware with the first three groups byte-swapped,
                    because SMBIOS stores them little-endian and vSphere prints
                    them big-endian. 27 of the 47 dev nodes matched only that
                    way; their generated node names shared nothing with their
                    VMs' names.
    server ↔ node   A Kubernetes node on bare metal reports the server's own
                    UUID: the chain skips the hypervisor.
    Weaker clues come after every UUID has been settled, and only one to one:
    the node's address is the VM's guest address; the names agree. Never
    between two machines whose UUIDs differ — on 24 November 2026 a VM and a
    node in another cluster shared the name talos-worker02 and were two
    machines, as their UUIDs said.

WHAT IS NEVER GUESSED
    A wrong arrow is worse than a missing one here: a power button's warning
    trusts it. So nothing depends on the order things are read in, and:
    - two Kubernetes nodes that claim one VM (a stale node object left behind
      by a re-join, or a kubelet that reports somebody else's UUID) link
      nothing, unless exactly one of them is Ready — the warning names both;
    - two VMs with one UUID on one connection (a copied VM) link nothing
      unless exactly one of them runs;
    - the same machine seen twice — a VM through a vCenter and through its own
      host, a server whose BMC was added twice — is one machine, counted once;
    - a link set by hand remembers the identity it was set for, and stops
      applying when the VM or host behind that id is a different one (Proxmox
      reuses VM ids).

WHO SEES WHAT
    Every layer through its own area and its connection's project, exactly as
    its own page would: a person who may open Server hardware but not Clusters
    sees that a VM is a Kubernetes node and how many pods it holds, never
    which cluster or what the node is called. Even "still reading" and "could
    not read" name only what the person may see.

COST
    Everything here is a read the pages already make and cache (bmc.read,
    virt.read, cluster.everywhere), plus a small identity read for a vCenter
    or Proxmox (virt.identities). Gathered together under one deadline, kept a
    minute like the pages they come from, and joined once per answer rather
    than once per page view.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.parse

from . import bmc, cluster, gather, rbac, store, virt

_gatherer = gather.Gatherer("chain", ttl=60.0, hard=900.0, first_paint=2.5,
                            workers=16)

# placeholders vendors print where no serial was programmed
_NO_SERIAL = {"", "0", "NONE", "N/A", "NA", "NOTSPECIFIED", "NOTAVAILABLE",
              "TOBEFILLEDBYO.E.M.", "SYSTEMSERIALNUMBER", "DEFAULTSTRING",
              "123456789", "0123456789", "CHASSISSERIALNUMBER", "VMWARE"}
# UUIDs boards ship with when nobody programmed one: shared by thousands of
# machines, so they identify none of them
_NO_UUID = {"03000200040005000006000700080009", "00020003000400050006000700080009"}
_GENERIC_NAMES = {"", "localhost", "localhost.localdomain", "unknown", "none",
                  "minwinpc", "debian", "ubuntu", "talos"}


# ── identity ───────────────────────────────────────────────────
def uuid_keys(value) -> set:
    """Both byte orders of an SMBIOS UUID as 32 lowercase hex digits, or an
    empty set for a missing, placeholder, all-zero or all-F one. Takes a
    providerID such as vsphere://<uuid> too."""
    raw = str(value or "").lower().rsplit("/", 1)[-1]
    h = re.sub(r"[^0-9a-f]", "", raw)
    if len(h) != 32 or len(set(h)) == 1:
        return set()
    b = bytes.fromhex(h)
    swapped = (b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:]).hex()
    if h in _NO_UUID or swapped in _NO_UUID:
        return set()
    return {h, swapped}


def serial_key(value) -> str:
    s = re.sub(r"\s+", "", str(value or "")).upper()
    return "" if s in _NO_SERIAL or len(s) < 4 else s


def name_key(value) -> str:
    """A machine name to compare: lower case, first label, never one of the
    names every machine is called before somebody names it."""
    s = str(value or "").strip().lower()
    if s in _GENERIC_NAMES:
        return ""
    s = s.split(".", 1)[0]
    return "" if s in _GENERIC_NAMES or len(s) < 3 else s


def _fp(uuids: set, serial: str = "") -> str:
    """What a link set by hand remembers about the thing it was set on."""
    return min(uuids) if uuids else serial


def _one_machine(items: list) -> bool:
    """Whether several records are the same machine: all carry the same
    non-empty identity."""
    ids = {frozenset(i["_uuids"]) for i in items}
    return len(ids) == 1 and bool(next(iter(ids)))


# ── reading ────────────────────────────────────────────────────
def _server(conn: dict) -> dict:
    return bmc.read(conn, detail=False)


def _hypervisor(conn: dict) -> dict:
    return {"data": virt.read(conn), "ident": virt.identities(conn)}


def _nodes():
    return cluster.everywhere("nodes")


def _pods():
    return cluster.everywhere("pods")


def _jobs(bmcs: list, virts: list) -> list:
    # labelled by key, not by name: what is still being read, or could not
    # be, is named later through each person's own view (`_sources`)
    jobs = [(f"bmc:{c['id']}", f"bmc:{c['id']}", (lambda c=c: _server(c))) for c in bmcs]
    jobs += [(f"virt:{c['id']}", f"virt:{c['id']}", (lambda c=c: _hypervisor(c)))
             for c in virts]
    jobs += [("nodes", "nodes", _nodes), ("pods", "pods", _pods)]
    return jobs


def invalidate() -> None:
    _gatherer.invalidate()
    _memo.clear()


def refresh_soon() -> None:
    """A Refresh pressed on a page: the next look collects afresh — through
    the same deadline and the same shared collection as any other, so a
    Refresh pressed many times reads each source once, not once per press.
    Not more often than every ten seconds."""
    for key, hit in list(_gatherer._cache.items()):
        if time.monotonic() - hit["at"] > 10:
            _gatherer._cache.pop(key, None)
    _memo.clear()


def _key(bmcs: list, virts: list) -> str:
    sig = hashlib.sha1("|".join(sorted(
        [f"b{c['id']}{c.get('base_url')}" for c in bmcs]
        + [f"v{c['id']}{c.get('base_url')}" for c in virts])).encode()).hexdigest()[:12]
    return f"estate:{sig}"


_memo: dict = {}
_memo_guard = threading.Lock()


def _late() -> list:
    """(cluster id, name) the fleet has not read yet, for nodes or pods."""
    out = {}
    for part in ("nodes", "pods"):
        for cid, name in cluster._PENDING.get(part) or []:
            out[cid] = name
    return sorted(out.items())


def graph() -> dict:
    """The whole estate, joined. Not filtered: every view below filters it for
    the person asking. Waits at most the gatherer's first paint."""
    bmcs, virts = store.all_bmc(), virt.store_all()
    key = _key(bmcs, virts)
    got = _gatherer.gather(key, _jobs(bmcs, virts))
    pending = list(got.get("pending") or [])
    failed = {}
    for e in got.get("errors") or []:
        src, _sep, why = str(e).partition(": ")
        failed[src] = why[:200]
    late = _late()
    if pending or late:
        # an answer with holes is served, never kept as if whole: the next
        # look collects behind the reader instead of waiting a minute
        hit = _gatherer._cache.get(key)
        if hit:
            hit["at"] = min(hit["at"], time.monotonic() - _gatherer.ttl)
    return _joined(got["parts"], pending, failed, late, bmcs, virts)


def _joined(parts, pending, failed, late, bmcs, virts) -> dict:
    """_join once per answer: pages and warnings ask many times a minute."""
    links = store.estate_links()
    sig = (id(parts), json.dumps(links, sort_keys=True), tuple(pending),
           tuple(sorted(failed)), tuple(late),
           tuple(sorted((c["id"], c.get("pid") or "", c.get("name", "")) for c in bmcs + virts)))
    with _memo_guard:
        hit = _memo.get("g")
        if hit and hit[0] == sig:
            return hit[1]
    g = _join(parts, pending, bmcs, virts, failed=failed, late=late, links=links)
    with _memo_guard:
        _memo["g"] = (sig, g)
    return g


_peeking = threading.Event()


def peek() -> dict | None:
    """The last joined estate without waiting for anything, or None when
    there is none yet — for pages that show the chain on the side (the server
    list, node tables) and must not be slowed by it. A missing or old answer
    starts one fresh collection behind the caller, never one per page view."""
    bmcs, virts = store.all_bmc(), virt.store_all()
    key = _key(bmcs, virts)
    hit = _gatherer._cache.get(key)
    if (not hit or time.monotonic() - hit["at"] > _gatherer.ttl) and not _peeking.is_set():
        _peeking.set()
        threading.Thread(target=_quiet_graph, name="chain-peek", daemon=True).start()
    if not hit:
        return None
    return _joined(hit["parts"], [], {}, _late(), bmcs, virts)


def _quiet_graph() -> None:
    try:
        graph()
    except Exception:                                         # noqa: BLE001
        pass
    finally:
        _peeking.clear()


def _q(v) -> str:
    return urllib.parse.quote(str(v or ""), safe="")


def _hand(entry) -> tuple:
    """A stored link set by hand: (target, the identity it was set for)."""
    if isinstance(entry, dict):
        return str(entry.get("to") or ""), str(entry.get("fp") or "")
    return str(entry or ""), ""


# ── joining ────────────────────────────────────────────────────
def _join(parts: dict, pending: list, bmcs: list, virts: list, failed: dict | None = None,
          late: list | None = None, links: dict | None = None) -> dict:
    manual = links if links is not None else store.estate_links()
    servers, hosts, vms, nodes = {}, {}, {}, {}

    for c in bmcs:
        info = parts.get(f"bmc:{c['id']}")
        i = info or {}
        servers[c["id"]] = {
            "key": c["id"], "id": c["id"], "name": c.get("name", ""),
            "pid": c.get("pid") or "", "read": info is not None,
            "model": " ".join(x for x in (i.get("vendor"), i.get("model")) if x),
            "serial": i.get("sku") or i.get("serial") or "",
            "uuid": i.get("uuid", ""), "power": i.get("power", ""),
            "health": i.get("health", ""), "ok": i.get("ok", True),
            # the OS its own agent reported to the BMC: shown, never joined on
            "os": i.get("os", ""), "hostname": i.get("hostname", ""),
            "os_hypervisor": bmc.is_hypervisor_os(i.get("os", "")),
            "bmc_word": bmc.agent(i.get("vendor", ""))[0],
            "os_agent": bmc.agent(i.get("vendor", ""))[1],
            "href": f"/bmc?device={_q(c['id'])}",
            "_uuids": uuid_keys(i.get("uuid")),
            "_serials": {k for k in (serial_key(i.get("serial")), serial_key(i.get("sku"))) if k},
            "_name": name_key(i.get("hostname")),
        }

    for c in virts:
        got = parts.get(f"virt:{c['id']}")
        if not got:
            continue
        data, ident = got["data"], got.get("ident") or {}
        ih, iv = ident.get("hosts") or {}, ident.get("vms") or {}
        kind = data.get("kind", "")
        hlist = data.get("hosts") or []
        single = len(hlist) == 1
        for x in hlist:
            idn = ih.get(x["name"], {})
            hkey = f"{c['id']}|{x['name']}"
            label = c.get("name", "") if single and not name_key(x["name"]) else x["name"]
            if kind == "ESXi":
                href = f"/virt/host?c={_q(c['id'])}"
            elif kind == "Proxmox":
                href = f"/virt/host?c={_q(c['id'])}&node={_q(x['name'])}"
            else:
                href = f"/virt?q={_q(x['name'])}"
            uu = uuid_keys(x.get("uuid") or idn.get("uuid"))
            serial = x.get("serial") or idn.get("serial") or ""
            hosts[hkey] = {
                "key": hkey, "conn": c["id"], "conn_name": c.get("name", ""),
                "pid": c.get("pid") or "", "name": x["name"], "label": label,
                "kind": kind, "state": x.get("state", ""),
                "cpu_pct": x.get("cpu_pct"), "mem_pct": x.get("mem_pct"),
                "model": " ".join(v for v in (x.get("vendor") or idn.get("vendor"),
                                              x.get("model") or idn.get("model")) if v),
                "serial": serial, "href": href, "vms": [],
                # a vCenter lists its VMs without their host: which host runs
                # which comes from its identity read, and without it the
                # host's VMs are not known — never "none"
                "vms_known": kind != "vSphere" or bool(iv),
                "_uuids": uu, "_serial": serial_key(serial), "_name": name_key(x["name"]),
                "_fp": _fp(uu, serial_key(serial)),
            }
        for g in data.get("guests") or []:
            idg = iv.get(g["id"]) or iv.get(str(g["id"])) or {}
            hname = g.get("host") or idg.get("host") or ""
            hkey = (f"{c['id']}|{hname}" if hname
                    else (f"{c['id']}|{hlist[0]['name']}" if single else ""))
            vkey = f"{c['id']}|{g['id']}"
            state = g.get("state", "")
            running = state.lower() in ("running", "on", "poweredon")
            kind_q = "lxc" if g.get("kind") == "container" else "qemu"
            uu = uuid_keys(g.get("uuid") or idg.get("uuid"))
            vms[vkey] = {
                "key": vkey, "conn": c["id"], "conn_name": c.get("name", ""),
                "pid": c.get("pid") or "", "id": g["id"], "name": g.get("name", ""),
                "kind": g.get("kind", "VM"), "state": state, "running": running,
                "host": hkey if hkey in hosts else "",
                "href": (f"/virt/vm?c={_q(c['id'])}&vm={_q(g['id'])}"
                         + (f"&node={_q(hname)}&kind={kind_q}" if kind == "Proxmox" else ""))
                if kind in ("ESXi", "Proxmox") else f"/virt?q={_q(g.get('name', ''))}",
                "_uuids": uu, "_fp": _fp(uu),
                "_ip": (g.get("ip") or idg.get("ip") or "") if running else "",
                "_names": {n for n in (name_key(g.get("name")),
                                       name_key(g.get("guest_host") or idg.get("guest_host"))) if n},
            }
            if vms[vkey]["host"]:
                hosts[vms[vkey]["host"]]["vms"].append(vkey)

    for grp in parts.get("nodes") or []:
        for n in grp.get("nodes") or []:
            nkey = f"{grp['cid']}|{n['name']}"
            nodes[nkey] = {
                "key": nkey, "cid": grp["cid"], "pid": grp.get("pid", ""),
                "cluster": grp.get("cluster", grp["cid"]), "project": grp.get("project", ""),
                "name": n["name"], "ready": bool(n.get("ready")),
                "roles": n.get("roles") or [], "ip": n.get("ip", ""),
                "pods": 0, "bad": 0,
                "href": (f"/clusters?project={_q(grp.get('pid', ''))}&cluster={_q(grp['cid'])}"
                         f"&tab=pods&node={_q(n['name'])}"),
                "_uuids": uuid_keys(n.get("uuid")) | uuid_keys(n.get("provider_id")),
                "_ips": set(n.get("ips") or ([n["ip"]] if n.get("ip") else [])),
                "_names": {k for k in (name_key(n["name"]), name_key(n.get("hostname"))) if k},
            }
    for grp in parts.get("pods") or []:
        for p in grp.get("pods") or []:
            nd = nodes.get(f"{grp['cid']}|{p.get('node', '')}")
            if nd:
                nd["pods"] += 1
                if p.get("problem"):
                    nd["bad"] += 1

    notes: dict = {}                    # key -> a sentence about how it was linked

    # ── server ↔ host ──
    host_servers: dict = {}
    host_how: dict = {}
    by_uuid: dict = {}
    for s in servers.values():
        for u in s["_uuids"]:
            by_uuid.setdefault(u, []).append(s["key"])
    hand_hosts = manual.get("hosts") or {}
    for h in hosts.values():
        if h["key"] in hand_hosts:
            to, fp = _hand(hand_hosts[h["key"]])
            if fp and h["_fp"] and fp != h["_fp"]:
                notes[h["key"]] = ("a link set by hand no longer applies: this connection "
                                   "now reaches a different host")
            elif to in servers:
                host_servers[h["key"]], host_how[h["key"]] = [to], "set by hand"
                continue
            else:
                host_servers[h["key"]] = []
                host_how[h["key"]] = ("set by hand: not linked" if not to
                                      else "set by hand to a server that is gone")
                continue
        # two different hardware UUIDs are two machines, whatever else agrees:
        # the weaker clues only join a pair where one side has none
        loose = [s for s in servers.values() if not (h["_uuids"] and s["_uuids"])]
        tried = [
            ("hardware UUID", list(dict.fromkeys(k for u in h["_uuids"] for k in by_uuid.get(u, [])))),
            ("service tag", [s["key"] for s in loose if h["_serial"] and h["_serial"] in s["_serials"]]),
            ("host name", [s["key"] for s in loose if h["_name"] and h["_name"] == s["_name"]]),
        ]
        host_servers[h["key"]], host_how[h["key"]] = [], ""
        for how, cands in tried:
            if len(cands) == 1 or (cands and _one_machine([servers[k] for k in cands])):
                # one server, or one server whose BMC was added twice
                host_servers[h["key"]], host_how[h["key"]] = cands, how
                break
            if cands:
                host_how[h["key"]] = f"its {how} matches more than one server"
                break

    # ── VM ↔ node ──
    vm_node: dict = {}                   # vm key -> node key
    vm_how: dict = {}
    doubt: dict = {}                     # vm key -> [node keys] it could be
    hand_vms = manual.get("vms") or {}
    hand_targets: dict = {}
    for vk, entry in hand_vms.items():
        v = vms.get(vk)
        if not v:
            continue
        to, fp = _hand(entry)
        if fp and v["_fp"] and fp != v["_fp"]:
            notes[vk] = "a link set by hand no longer applies: this id is now a different VM"
            continue
        if to in nodes:
            vm_node[vk], vm_how[vk] = to, "set by hand"
            hand_targets.setdefault(to, []).append(vk)
        else:
            vm_how[vk] = "set by hand: not linked" if not to else "set by hand to a node that is gone"
    decided = set(vm_how)                # VMs whose answer is already given by hand
    taken = set(hand_targets)

    # every UUID claim first, from both sides, so nothing depends on order
    vm_by_uuid: dict = {}
    for v in vms.values():
        if v["key"] not in decided:
            for u in v["_uuids"]:
                vm_by_uuid.setdefault(u, []).append(v["key"])
    claims: dict = {}                    # vm key -> [node keys claiming it]
    node_cands: dict = {}                # node key -> [vm keys it claims]
    for n in nodes.values():
        if n["key"] in taken:
            continue
        cands = list(dict.fromkeys(k for u in n["_uuids"] for k in vm_by_uuid.get(u, [])))
        if cands:
            node_cands[n["key"]] = cands
            for k in cands:
                claims.setdefault(k, []).append(n["key"])
    for vk, ns in claims.items():
        if len(ns) == 1:
            vm_node[vk], vm_how[vk] = ns[0], "hardware UUID"
            continue
        ready = [k for k in ns if nodes[k]["ready"]]
        if len(ready) == 1:
            # a re-joined node leaves its old object behind, NotReady
            vm_node[vk], vm_how[vk] = ready[0], "hardware UUID"
            notes[vk] = ("another Kubernetes node object that is not Ready reports the "
                         "same hardware UUID")
        else:
            doubt[vk] = ns
            vm_how[vk] = f"its hardware UUID is reported by {len(ns)} Kubernetes nodes"
    # one node, several VMs: the same VM through several connections is one
    # machine; two copies of a VM on one connection are not
    node_vms: dict = {k: list(v) for k, v in hand_targets.items()}
    for nk in node_cands:
        mine = [vk for vk in node_cands[nk] if vm_node.get(vk) == nk]
        if not mine:
            continue
        per_conn: dict = {}
        for vk in mine:
            per_conn.setdefault(vms[vk]["conn"], []).append(vk)
        keep = []
        for conn_id, vks in per_conn.items():
            if len(vks) == 1:
                keep += vks
                continue
            running = [vk for vk in vks if vms[vk]["running"]]
            if len(running) == 1:
                keep += running
                for vk in vks:
                    if vk not in running:
                        vm_node.pop(vk, None)
                        vm_how[vk] = "a copy of a running VM with the same hardware UUID"
            else:
                for vk in vks:
                    vm_node.pop(vk, None)
                    doubt[vk] = [nk]
                    vm_how[vk] = "another VM on this connection has the same hardware UUID"
        if keep:
            node_vms[nk] = sorted(keep, key=lambda k: (not vms[k]["running"], k))

    # bare metal: a node reporting a server's own UUID
    server_nodes: dict = {}
    linked_nodes = set(node_vms) | {k for ks in doubt.values() for k in ks}
    srv_uuid = by_uuid
    for n in nodes.values():
        if n["key"] in linked_nodes or n["key"] in node_cands:
            continue
        cands = list(dict.fromkeys(k for u in n["_uuids"] for k in srv_uuid.get(u, [])))
        if cands and (len(cands) == 1 or _one_machine([servers[k] for k in cands])):
            for sk in cands:
                server_nodes.setdefault(sk, []).append(n["key"])
            linked_nodes.add(n["key"])

    # weaker clues last, and only one to one, from both sides
    free_nodes = [n for n in nodes.values() if n["key"] not in linked_nodes and n["key"] not in taken]
    free_vms = {vk for vk in vms if vk not in vm_how}
    by_ip: dict = {}
    by_name: dict = {}
    for vk in free_vms:
        v = vms[vk]
        if v["_ip"]:
            by_ip.setdefault(v["_ip"], []).append(vk)
        for nm in v["_names"]:
            by_name.setdefault(nm, []).append(vk)
    for how, index, fields in (("address", by_ip, "_ips"), ("name", by_name, "_names")):
        pairs = []
        for n in free_nodes:
            cands = {vk for key in n[fields] for vk in index.get(key, [])
                     if vk in free_vms and not (vms[vk]["_uuids"] and n["_uuids"])}
            pairs += [(n["key"], vk) for vk in cands]
        per_n: dict = {}
        per_v: dict = {}
        for nk, vk in pairs:
            per_n[nk] = per_n.get(nk, 0) + 1
            per_v[vk] = per_v.get(vk, 0) + 1
        for nk, vk in pairs:
            if per_n[nk] == 1 and per_v[vk] == 1:
                vm_node[vk], vm_how[vk] = nk, how
                node_vms[nk] = [vk]
                free_vms.discard(vk)
        free_nodes = [n for n in free_nodes if n["key"] not in node_vms]

    server_hosts: dict = {}
    for hk, sks in host_servers.items():
        for sk in sks:
            server_hosts.setdefault(sk, []).append(hk)
    return {"servers": servers, "hosts": hosts, "vms": vms, "nodes": nodes,
            "host_servers": host_servers, "host_how": host_how,
            "server_hosts": server_hosts, "vm_node": vm_node, "vm_how": vm_how,
            "doubt": doubt, "node_vms": node_vms, "server_nodes": server_nodes,
            "notes": notes, "pending": list(pending), "failed": dict(failed or {}),
            "late": list(late or [])}


# ── who may see what ───────────────────────────────────────────
class _Lens:
    """One person's view: which layers, which projects, which clusters."""

    def __init__(self, user):
        self.user = user
        self.bmc = rbac.may_area(user, "bmc")
        self.virt = rbac.may_area(user, "virt")
        self.k8s = rbac.may_area(user, "clusters")
        self.clusters = rbac.visible_clusters(user) if self.k8s else set()
        self.link = rbac.may_area(user, "settings")

    def server(self, s) -> bool:
        return bool(s) and self.bmc and rbac.may_project(self.user, s["pid"], "bmc")

    def hyp(self, x) -> bool:
        return bool(x) and self.virt and rbac.may_project(self.user, x["pid"], "virt")

    def node(self, n) -> bool:
        return bool(n) and self.k8s and (self.clusters is None or n["cid"] in self.clusters)

    def cluster_id(self, cid: str) -> bool:
        return self.k8s and (self.clusters is None or cid in self.clusters)


def _pub(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def _sources(g: dict, lens: _Lens) -> dict:
    """What is still being read and what could not be read, named only where
    this person may see it: {"pending": [names], "failed": [names],
    "hidden": count of the rest}."""
    conns = {f"bmc:{c['id']}": ("bmc", c) for c in store.all_bmc()}
    conns.update({f"virt:{c['id']}": ("virt", c) for c in virt.store_all()})
    hidden = 0

    def name(src: str) -> str:
        nonlocal hidden
        kind, c = conns.get(src, ("", None))
        if kind == "bmc" and lens.server({"pid": c.get("pid") or ""}):
            return c.get("name", "")
        if kind == "virt" and lens.hyp({"pid": c.get("pid") or ""}):
            return c.get("name", "")
        if src in ("nodes", "pods"):
            return "" if not lens.k8s else "Kubernetes clusters"
        hidden += 1
        return ""
    pending = [n for n in (name(s) for s in g["pending"]) if n]
    for cid, cname in g["late"]:
        if lens.cluster_id(cid):
            pending.append(cname)
        else:
            hidden += 1
    failed = [n for n in (name(s) for s in g["failed"]) if n]
    return {"pending": list(dict.fromkeys(pending)), "failed": list(dict.fromkeys(failed)),
            "hidden": hidden}


def _node_view(g: dict, lens: _Lens, nkey: str) -> dict:
    n = g["nodes"].get(nkey)
    if not n:
        return {}
    if lens.node(n):
        return _pub(n)
    # that it is a node, and how much rides on it, is the point of the chain;
    # which cluster and what it is called belong to the Clusters area
    return {"hidden": True, "ready": n["ready"], "pods": n["pods"], "bad": n["bad"]}


def _server_of(g: dict, lens: _Lens, hkey: str) -> tuple:
    """(the first server under this host the person may see, whether there
    is one they may not)."""
    sks = g["host_servers"].get(hkey) or []
    for sk in sks:
        if lens.server(g["servers"][sk]):
            return g["servers"][sk], False
    return None, bool(sks)


def _machine(v: dict) -> str:
    """One VM, however many connections show it."""
    return min(v["_uuids"]) if v["_uuids"] else v["key"]


def _vm_row(g: dict, lens: _Lens, vk: str) -> dict:
    v = g["vms"][vk]
    nk = g["vm_node"].get(vk)
    row = {**_pub(v), "node": _node_view(g, lens, nk) if nk else {},
           "node_how": g["vm_how"].get(vk, ""), "note": g["notes"].get(vk, "")}
    if vk in g["doubt"]:
        row["doubt"] = [_node_view(g, lens, k) for k in g["doubt"][vk]]
    return row


# ── views ──────────────────────────────────────────────────────
def for_server(user, server_id: str, g: dict | None = None) -> dict:
    """The chain under one server, for its "Runs here" tab."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    s = g["servers"].get(server_id)
    if not s or not lens.server(s):
        return {}
    hosts_out, hidden_hosts = [], 0
    machines: dict = {}
    node_keys: set = set()
    for hk in g["server_hosts"].get(server_id, []):
        h = g["hosts"][hk]
        if not lens.hyp(h):
            hidden_hosts += 1
            continue
        rows = [_vm_row(g, lens, vk) for vk in h["vms"]]
        rows.sort(key=lambda r: (not (r["node"] or r.get("doubt")), not r["running"],
                                 r["name"].lower()))
        for vk in h["vms"]:
            v = g["vms"][vk]
            machines.setdefault(_machine(v), v["running"])
            if g["vm_node"].get(vk):
                node_keys.add(g["vm_node"][vk])
        hosts_out.append({**_pub(h), "how": g["host_how"].get(hk, ""), "vms": rows,
                          "note": g["notes"].get(hk, ""),
                          "running": sum(1 for r in rows if r["running"]),
                          "nodes": sum(1 for r in rows if r["node"])})
    metal = [_node_view(g, lens, nk) for nk in g["server_nodes"].get(server_id, [])]
    node_keys |= set(g["server_nodes"].get(server_id, []))
    nodes = [g["nodes"][k] for k in node_keys]
    out = {"server": _pub(s), "hosts": hosts_out, "hidden_hosts": hidden_hosts,
           "metal": metal, "sources": _sources(g, lens), "can_link": lens.link and lens.virt}
    if lens.link and lens.virt:
        # the hosts no server claims yet, to link here by hand
        out["choices"] = sorted(
            ({"key": h["key"], "label": f"{h['label']} · {h['conn_name']}"
              if h["label"] != h["conn_name"] else h["label"]}
             for h in g["hosts"].values()
             if lens.hyp(h) and not g["host_servers"].get(h["key"])),
            key=lambda x: x["label"].lower())
    out["totals"] = {
        # each machine once: a VM seen through a vCenter and through its own
        # host is one VM, a node is one node
        "hosts": len(hosts_out) + hidden_hosts,
        "vms": len(machines), "running": sum(1 for r in machines.values() if r),
        "nodes": len(node_keys),
        "pods": sum(n["pods"] for n in nodes), "bad": sum(n["bad"] for n in nodes),
    }
    out["why_none"] = "" if (hosts_out or hidden_hosts or metal) else _why_none(g, s, lens)
    return out


def _why_none(g: dict, s: dict, lens: _Lens) -> str:
    """Why nothing is linked under a server, in terms somebody can act on,
    counting only what this person may see."""
    if not s["read"]:
        return "EnvMap could not read this server's BMC, so it does not know its identity yet."
    n_hosts = sum(1 for h in g["hosts"].values() if lens.hyp(h))
    n_nodes = sum(1 for n in g["nodes"].values() if lens.node(n))
    ids = " and ".join(x for x in (
        f"hardware UUID {s['uuid']}" if s["uuid"] else "",
        f"service tag {s['serial']}" if s["serial"] else "") if x)
    if not n_hosts and not n_nodes:
        why = ("No hypervisor and no Kubernetes cluster you may open is connected to EnvMap, "
               "so there is nothing to find on this server.")
    else:
        why = (f"None of the {n_hosts} hypervisor host{'s' if n_hosts != 1 else ''} and "
               f"{n_nodes} Kubernetes node{'s' if n_nodes != 1 else ''} you may see reports this "
               f"server's {ids or 'identity'}. If it runs a hypervisor, connect it in "
               "Settings → Hypervisors, or link it here by hand.")
    if not s.get("os"):
        why += (f" The {s.get('bmc_word') or 'BMC'} does not report an operating system either"
                + (f": it does once {s['os_agent']} runs on the host." if s.get("os_agent") else "."))
    return why


def summary_for_servers(user, g: dict | None = None) -> dict:
    """{server id: "ESXi · 12 VMs · 5 nodes"} for the server list: what the
    Runs here tab would count, as far as this person may see."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    out = {}
    for sid, s in g["servers"].items():
        if not lens.server(s):
            continue
        all_hosts = g["server_hosts"].get(sid, [])
        hs = [h for h in all_hosts if lens.hyp(g["hosts"][h])]
        machines = {_machine(g["vms"][vk]) for h in hs for vk in g["hosts"][h]["vms"]}
        nodes = {g["vm_node"][vk] for h in hs for vk in g["hosts"][h]["vms"] if g["vm_node"].get(vk)} \
            | set(g["server_nodes"].get(sid, []))
        bits = []
        if hs:
            bits.append(" + ".join(sorted({g["hosts"][h]["kind"] for h in hs})))
            bits.append(f"{len(machines)} VM{'s' if len(machines) != 1 else ''}")
        elif all_hosts:
            bits.append(f"{len(all_hosts)} host{'s' if len(all_hosts) != 1 else ''}")
        if nodes:
            bits.append(f"{len(nodes)} node{'s' if len(nodes) != 1 else ''}")
        out[sid] = " · ".join(bits)
    return out


def why_empty(user, g: dict | None = None) -> dict:
    """{server id: {"text", "sub", "os"}} for each server whose Runs cell
    would otherwise be a bare dash, which people read as "broken".

    The operating system its BMC reports comes first ("os": True; "sub" is
    its host name, or "not connected" for a hypervisor EnvMap could read):
    that is what runs there, as far as anything tells. Without one, a few
    words on why nothing is known. The Runs here tab says the whole of it;
    this is the part that fits in a cell. An empty summary is empty for
    everybody (it counts hosts and nodes the person may not open), so the
    reason is about the estate, not the person."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    found = summary_for_servers(user, g)
    connected = bool(virt.store_all())
    out = {}
    for sid, s in g["servers"].items():
        if not lens.server(s) or found.get(sid):
            continue
        if s.get("os"):
            out[sid] = {"text": s["os"], "os": True,
                        "sub": "not connected" if s.get("os_hypervisor")
                        else s.get("hostname", "")}
            continue
        out[sid] = {"os": False, "sub": "",
                    "text": "BMC not read yet" if not s["read"] else
                    "no hypervisor matches" if connected else
                    "no hypervisor connected"}
    return out


def _host_key(g: dict, conn_id: str, host_name: str) -> str:
    """The host a page means: the one named, or — only on a connection with
    exactly one host, a standalone ESXi whose page names none — that one."""
    hk = f"{conn_id}|{host_name}"
    if hk in g["hosts"]:
        return hk
    mine = [x["key"] for x in g["hosts"].values() if x["conn"] == conn_id]
    return mine[0] if len(mine) == 1 and not host_name else ""


def for_host(user, conn_id: str, host_name: str, g: dict | None = None) -> dict:
    """A hypervisor host's server, for its page."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    hk = _host_key(g, conn_id, host_name)
    h = g["hosts"].get(hk)
    if not h or not lens.hyp(h):
        return {}
    s, hidden = _server_of(g, lens, hk)
    nodes = {g["vm_node"][v] for v in h["vms"] if g["vm_node"].get(v)}
    out = {"host": _pub(h), "how": g["host_how"].get(hk, ""), "note": g["notes"].get(hk, ""),
           "server": _pub(s) if s else {}, "server_hidden": hidden and not s,
           "nodes": len(nodes), "can_link": lens.link and lens.bmc}
    if lens.link and lens.bmc:
        out["choices"] = sorted(({"key": x["key"], "label": x["name"]}
                                 for x in g["servers"].values() if lens.server(x)),
                                key=lambda x: x["label"].lower())
    return out


def for_vm(user, conn_id: str, vm_id: str, g: dict | None = None) -> dict:
    """A VM's host, server and Kubernetes node, for its page."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    vk = f"{conn_id}|{vm_id}"
    v = g["vms"].get(vk)
    if not v or not lens.hyp(v):
        return {}
    h = g["hosts"].get(v["host"]) if v["host"] else None
    s, _hidden = _server_of(g, lens, h["key"]) if h else (None, False)
    row = _vm_row(g, lens, vk)
    out = {"vm": _pub(v), "host": _pub(h) if h else {}, "server": _pub(s) if s else {},
           "node": row["node"], "node_how": row["node_how"], "note": row["note"],
           "doubt": row.get("doubt") or [], "can_link": lens.link and lens.k8s}
    if lens.link and lens.k8s:
        claimed = set(g["vm_node"].values())
        out["choices"] = sorted(({"key": n["key"], "label": f"{n['name']} · {n['cluster']}"}
                                 for n in g["nodes"].values()
                                 if lens.node(n) and n["key"] not in claimed),
                                key=lambda x: x["label"].lower())
    return out


def for_nodes(user, cid: str | None = None, g: dict | None = None) -> dict:
    """{(cid, node name): {vm, host, server}} for the node tables: where each
    node runs, as far as this person may see."""
    g = g if g is not None else graph()
    lens = _Lens(user)
    out = {}
    for nk, n in g["nodes"].items():
        if cid and n["cid"] != cid:
            continue
        vks = g["node_vms"].get(nk) or []
        v = g["vms"].get(vks[0]) if vks else None
        if v:
            h = g["hosts"].get(v["host"]) if v["host"] else None
            s, _hidden = _server_of(g, lens, h["key"]) if h else (None, False)
            out[(n["cid"], n["name"])] = {
                "vm": _pub(v) if lens.hyp(v) else {},
                "host": _pub(h) if h and lens.hyp(h) else {},
                "server": _pub(s) if s else {}, "how": g["vm_how"].get(v["key"], "")}
            continue
        sk = next((sid for sid, ns in g["server_nodes"].items() if nk in ns), None)
        s = g["servers"].get(sk) if sk else None
        if s:
            out[(n["cid"], n["name"])] = {"vm": {}, "host": {}, "how": "hardware UUID",
                                          "server": _pub(s) if lens.server(s) else {}}
    return out


# ── what an action takes down with it ──────────────────────────
def _count(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _nodes_phrase(g: dict, lens: _Lens, nkeys) -> str:
    nkeys = sorted(set(nkeys))
    if not nkeys:
        return ""
    pods = sum(g["nodes"][k]["pods"] for k in nkeys)
    by_cluster: dict = {}
    hidden = 0
    for k in nkeys:
        n = g["nodes"][k]
        if lens.node(n):
            by_cluster[n["cluster"]] = by_cluster.get(n["cluster"], 0) + 1
        else:
            hidden += 1
    where = ", ".join(f"{c}: {k}" for c, k in sorted(by_cluster.items()))
    if hidden:
        where = (where + ", " if where else "") + f"{hidden} in clusters you cannot open"
    return (f"{_count(len(nkeys), 'Kubernetes node')} ({where})"
            + (f" carrying {_count(pods, 'pod')}" if pods else ""))


def _doubt_phrase(g: dict, lens: _Lens, vks) -> str:
    vks = [vk for vk in vks if vk in g["doubt"]]
    if not vks:
        return ""
    names = []
    for vk in vks:
        for nk in g["doubt"][vk]:
            n = g["nodes"][nk]
            names.append(f"{n['name']} of {n['cluster']}" if lens.node(n) else "a node you cannot open")
    return ("EnvMap could not tell which Kubernetes node "
            + ("this VM is" if len(vks) == 1 else f"{len(vks)} of these VMs are")
            + " — it could be " + " or ".join(dict.fromkeys(names)) + ".")


def _tail(g: dict, lens: _Lens) -> str:
    src = _sources(g, lens)
    out = ""
    if src["failed"]:
        out += " EnvMap could not read " + ", ".join(src["failed"][:4]) + ", so this may not be all."
    if src["pending"]:
        out += (" EnvMap was still reading " + ", ".join(src["pending"][:4])
                + (" and more" if len(src["pending"]) > 4 else "") + ", so there may be more.")
    return out


def _host_phrase(g: dict, lens: _Lens, hk: str) -> tuple:
    """(a phrase for one host, the node keys under it, the VMs in doubt)."""
    h = g["hosts"][hk]
    if not lens.hyp(h):
        return "a hypervisor host in a connection your roles do not open", [], []
    if not h["vms_known"]:
        return f"{h['kind']} host {h['label']}, with VMs EnvMap could not read", [], []
    running = [v for v in h["vms"] if g["vms"][v]["running"]]
    machines = {_machine(g["vms"][v]) for v in running}
    nkeys = [g["vm_node"][v] for v in running if g["vm_node"].get(v)]
    return (f"{h['kind']} host {h['label']} with {_count(len(machines), 'running VM')}",
            nkeys, [v for v in running if v in g["doubt"]])


def impact_server(user, server_id: str, g: dict | None = None) -> str:
    g = g if g is not None else graph()
    lens = _Lens(user)
    s = g["servers"].get(server_id)
    if not s or not lens.server(s):
        return ""
    parts, nkeys, doubtful = [], [], []
    for hk in g["server_hosts"].get(server_id, []):
        phrase, nks, dv = _host_phrase(g, lens, hk)
        parts.append(phrase)
        nkeys += nks
        doubtful += dv
    nkeys += g["server_nodes"].get(server_id, [])
    np = _nodes_phrase(g, lens, nkeys)
    if not parts and not np:
        tail = _tail(g, lens)
        return ("EnvMap found nothing running on this server." + tail) if tail else ""
    text = "Running on this server: " + "; ".join(parts + ([np] if np else [])) + "."
    dp = _doubt_phrase(g, lens, doubtful)
    return text + (" " + dp if dp else "") + _tail(g, lens)


def impact_host(user, conn_id: str, host_name: str, g: dict | None = None) -> str:
    g = g if g is not None else graph()
    lens = _Lens(user)
    hk = _host_key(g, conn_id, host_name)
    h = g["hosts"].get(hk)
    if not h or not lens.hyp(h):
        return ""
    if not h["vms_known"]:
        return "EnvMap could not read which VMs run on this host."
    running = [v for v in h["vms"] if g["vms"][v]["running"]]
    if not running:
        return ""
    machines = {_machine(g["vms"][v]) for v in running}
    nkeys = [g["vm_node"][v] for v in running if g["vm_node"].get(v)]
    np = _nodes_phrase(g, lens, nkeys)
    dp = _doubt_phrase(g, lens, running)
    return (f"Running on this host: {_count(len(machines), 'VM')}"
            + (f", of them {np}" if np else "") + "." + (" " + dp if dp else "") + _tail(g, lens))


def impact_vm(user, conn_id: str, vm_id: str, g: dict | None = None) -> str:
    g = g if g is not None else graph()
    lens = _Lens(user)
    v = g["vms"].get(f"{conn_id}|{vm_id}")
    if not v or not lens.hyp(v):
        return ""
    if v["key"] in g["doubt"]:
        return _doubt_phrase(g, lens, [v["key"]])
    nk = g["vm_node"].get(v["key"])
    if not nk:
        return ""
    n = g["nodes"][nk]
    pods = f", carrying {_count(n['pods'], 'pod')}" if n["pods"] else ""
    if lens.node(n):
        return (f"This VM is the Kubernetes node {n['name']} of {n['cluster']}{pods}; "
                "the node goes down with it.")
    return f"This VM is a Kubernetes node{pods}; the node goes down with it."


# ── links set by hand ──────────────────────────────────────────
_link_guard = threading.Lock()


def set_link(g: dict, kind: str, key: str, target: str | None) -> tuple:
    """Set (target), mark not linked (""), or clear (None) a link by hand.
    kind "hosts": host key → server id; "vms": VM key → node key. Stores the
    identity of the host or VM it was set on, so it stops applying when that
    id comes to mean another machine. Returns (the stored entry before, after)."""
    with _link_guard:
        before = store.estate_links()[kind].get(key)
        if target is None:
            store.set_estate_link(kind, key, None)
            after = None
        else:
            src = (g["hosts"] if kind == "hosts" else g["vms"]).get(key) or {}
            after = {"to": target, "fp": src.get("_fp", "")}
            store.set_estate_link(kind, key, after)
    _memo.clear()
    return before, after


def hand_linked_to(g: dict, node_key: str) -> list:
    """The VMs already linked by hand to this node."""
    return [vk for vk, entry in (store.estate_links().get("vms") or {}).items()
            if _hand(entry)[0] == node_key]
