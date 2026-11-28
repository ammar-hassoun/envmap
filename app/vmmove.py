"""EnvMap Move: a running Linux VM moved to another hypervisor, or to another
host of the same one, without stopping it, in one click.

HOW A MOVE GOES
    1. Checks, before anything is created: both connections allow management
       and the person holds Administer on both; the source is a running Linux
       VM whose guest agent (Proxmox) or VMware Tools (ESXi) answers; the guest
       is x86-64, offers the kernel's snapshot device and is not locked down;
       its disks, cards and firmware can be built on the target, which has the
       memory and the space.
    2. The target VM is created stopped, in the source's image (moveside): the
       same processors, memory, firmware and disk layout, blank disks of the
       same sizes, the source's network cards with their own addresses, a
       transfer card, and this move's receiver CD (moveiso) to start from.
    3. The source gets a transfer card too, added while it runs, with an
       address of its own (link-local by default: nothing on the network is
       asked for an address), and the engine is copied into the guest.
    4. The target starts; its receiver waits on its transfer card.
    5. `envmove send` starts in the guest. The disks are copied while the
       system runs, then its memory; it freezes for the last changes, the
       picture crosses and the system resumes on the target. Before anything
       there runs again it tells the copy it left (frozen, waiting) to power
       off (envmove/core/core.c, tellold).
    6. EnvMap sees the source power off: the move is done. It takes the CD and
       the transfer card out of the new VM, gives it its own disk to start from
       and the source's name, and keeps the old VM, renamed and powered off,
       until someone deletes it.

    If it does not finish: before the freeze the guest simply carries on, and
    EnvMap removes what it built. After the freeze the system is waiting,
    frozen, for a verdict; the receiver tells it to carry on whenever the
    target starts again without the system having arrived, which is what
    "Bring it back" does (restart the target). Every way out ends with exactly
    one copy running.

WHAT IS STORED
    The job (data/moves/<id>.json, 0600): what was asked, every step with its
    time, and what was built, so a move EnvMap was restarted in the middle of
    can still be finished or undone. Never the guest's sign-in (ESXi): it is
    held in memory for the move's run and nowhere else. The tokens the guest
    and the receiver answer to are stored: they are worth nothing once the
    move has ended, and are needed until then.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from . import moveiso, moveside, rbac, virt, virtops
from .paths import DATA
from .virt import VirtError

MOVES = DATA / "moves"
# The verdict port is on the moving guest: below the kernel's range for
# outgoing connections (32768-60999), so no connection of the guest's own
# holds it by chance. The engine opens it before anything freezes.
RX_PORT, BOOT_PORT, VERDICT_PORT = 8000, 8100, 7470
PIDFILE = "/run/envmove.pid"
LOG = "/var/log/envmove.log"
ENGINE = "/usr/local/sbin/envmove"
FROZEN_LIMIT = 15 * 60          # frozen this long without arriving: stuck, the person decides
AT_ONCE = 3
DONE = ("done", "undone", "failed")
_lock = threading.Lock()
_jlocks: dict = {}              # job id -> its lock: one writer at a time
_running: dict = {}             # job id -> thread
_secrets: dict = {}             # job id -> {"user", "password"} for an ESXi guest, memory only


class MoveError(VirtError):
    """Something the person must hear, in words."""


# ── jobs on disk ───────────────────────────────────────────────
def _path(jid: str) -> Path:
    if not re.match(r"^[a-z0-9]{12}$", jid or ""):
        raise MoveError("unknown move")
    return MOVES / f"{jid}.json"


def load(jid: str) -> dict | None:
    try:
        return json.loads(_path(jid).read_text())
    except (OSError, ValueError, MoveError):
        return None


def _jlock(jid: str) -> threading.RLock:
    with _lock:
        return _jlocks.setdefault(jid, threading.RLock())


# what the watcher keeps in its own copy and writes as it is; everything else
# (the log, the state, a decision) is merged into the latest record on disk
OWN = ("built", "logpos", "result")


def update(job: dict, change) -> dict:
    """Apply `change(latest)` to the latest record of this move under its lock,
    save it, and make the caller's copy the result. A decision made in the
    page and the watcher's own steps never overwrite each other."""
    with _jlock(job["id"]):
        cur = load(job["id"]) or dict(job)
        for k in OWN:
            if k in job:
                cur[k] = job[k]
        change(cur)
        save(cur)
        job.clear()
        job.update(cur)
    return job


def save(job: dict) -> None:
    MOVES.mkdir(parents=True, exist_ok=True)
    p = _path(job["id"])
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(job, f)
    os.replace(tmp, p)


def all_jobs() -> list[dict]:
    out = []
    for p in sorted(MOVES.glob("*.json")) if MOVES.exists() else []:
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, ValueError):
            continue
    return sorted(out, key=lambda j: j.get("created", 0), reverse=True)


def public(job: dict) -> dict:
    """The job as the page sees it: never a token."""
    j = {k: v for k, v in job.items() if k != "tokens"}
    j["running"] = job["id"] in _running
    return j


def say(job: dict, text: str, kind: str = "step") -> None:
    def add(cur):
        cur.setdefault("log", []).append({"t": time.time(), "kind": kind, "text": str(text)[:2000]})
        cur["log"] = cur["log"][-1500:]
    update(job, add)


def phase(job: dict, state: str, text: str = "") -> None:
    def change(cur):
        cur["state"] = state
        cur.setdefault("times", {})[state] = time.time()
        if text:
            cur.setdefault("log", []).append({"t": time.time(), "kind": "step", "text": str(text)[:2000]})
            cur["log"] = cur["log"][-1500:]
    update(job, change)
    if state in DONE or state == "stuck":
        _audit_outcome(job, state, text)


def _audit_outcome(job: dict, state: str, text: str) -> None:
    """How a move ended, in the audit trail, under the name of whoever started it."""
    try:
        from . import auth
        auth.audit((job.get("by") or {}).get("email") or "envmap",
                   f"virt_vm_move_{state}",
                   f"{job['src']['conn_name']}/{job['src']['name']} -> {job['dst']['conn_name']}",
                   f"move {job['id']}: {text}"[:400])
    except Exception:                                       # noqa: BLE001
        pass


# ── sides ──────────────────────────────────────────────────────
def side(conn: dict, where: str = "", vm=None, guest: dict | None = None):
    f = virtops.flavor(conn)
    if f == "proxmox":
        return moveside.Pve(conn, where, vm)
    if f == "esxi":
        g = guest or {}
        return moveside.Esxi(conn, str(vm) if vm not in (None, "") else None,
                             g.get("user", ""), g.get("password", ""))
    raise MoveError("moves are between standalone ESXi hosts and Proxmox; "
                    "this connection is neither, or is not answering")


def may_move(user, src_conn: dict, dst_conn: dict) -> str:
    """"" when this person may move between these two connections, else why not."""
    for c, what in ((src_conn, "the VM's"), (dst_conn, "the target's")):
        why = virtops.manage_why(c) or virtops.may_why(user, "admin", c.get("pid") or "")
        if why:
            return f"{what} connection {c.get('name', '')}: {why}"
    return ""


# ── what the guest must offer ──────────────────────────────────
GUEST_CHECK = r"""
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
echo "uid=$(id -u)"
[ -c /dev/snapshot ] && echo snapshot=1 || echo snapshot=0
echo "lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null | tr -d '\n')"
[ -f /boot/vmlinuz-$(uname -r) ] && echo kernelfile=1 || echo kernelfile=0
echo "mkrx=$(command -v dracut || command -v mkinitramfs)"
echo "iptool=$(command -v ip)"
echo "gzip=$(command -v gzip)"
echo "nm=$(command -v nmcli)"
echo "os=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "selinux=$(id -Z 2>/dev/null)"
for s in $(findmnt -rn -o SOURCE 2>/dev/null | sort -u); do
  case "$s" in /dev/mapper/*|/dev/dm-*) echo "mount=dm $s";; /dev/*) echo "mount=plain $s";; esac
done
echo "root=$(findmnt -rn -o SOURCE /)"
swapon --show=NAME --noheadings 2>/dev/null | sed 's/^/swap=/'
r=$(ip -4 route show default 2>/dev/null | head -1)
echo "defroute=$r"
[ -f /run/envmove.pid ] && kill -0 "$(cat /run/envmove.pid)" 2>/dev/null && echo busy=1 || echo busy=0
"""


def parse_kv(text: str) -> dict:
    out: dict = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return {k: v if k in ("mount", "swap") else v[-1] for k, v in out.items()}


def guest_problems(g: dict, cross: bool) -> list[str]:
    why = []
    if g.get("arch") != "x86_64":
        why.append(f"the guest is {g.get('arch') or 'not answering'}; moves are for x86-64 Linux")
    if g.get("uid") != "0":
        why.append("the guest commands do not run as root (ESXi: sign in as root, or as a user with sudo without a password)")
    if g.get("snapshot") != "1":
        why.append("the guest's kernel offers no /dev/snapshot (built without hibernation support)")
    if "[none]" not in (g.get("lockdown") or "[none]"):
        why.append(f"the guest's kernel is locked down ({g.get('lockdown')}), which forbids taking its memory")
    if g.get("kernelfile") != "1":
        why.append(f"the running kernel is not at /boot/vmlinuz-{g.get('kernel', '?')}")
    if not g.get("mkrx"):
        why.append("the guest has neither dracut nor mkinitramfs to build the receiver from its own kernel")
    if not g.get("iptool"):
        why.append("the guest has no ip command (iproute2)")
    if not g.get("gzip"):
        why.append("the guest has no gzip")
    if "virt_qemu_ga" in (g.get("selinux") or ""):
        why.append("SELinux confines what the guest agent runs: allow it for the move with "
                   "setsebool -P virt_qemu_ga_run_unconfined on (and off again after)")
    if g.get("busy") == "1":
        why.append("a move is already running in this guest")
    if cross:
        plain = [m.split(" ", 1)[1] for m in g.get("mount", []) if m.startswith("plain ")]
        root = g.get("root", "")
        if not (root.startswith("/dev/mapper/") or root.startswith("/dev/dm-")):
            why.append(f"across hypervisors the disk controllers change type, and the root filesystem "
                       f"({root or '?'}) must then be on LVM; a plain partition is not supported yet")
        elif plain:
            pass                    # plain mounts beside an LVM root (like /boot) are taken off and put back
    return why


# ── the plan ───────────────────────────────────────────────────
def transfer_addresses(form: dict) -> dict:
    """Link-local by default: a /30 chosen at random, away from the
    169.254.169.0/24 some systems route for metadata."""
    mode = form.get("transfer_mode") or "auto"
    if mode == "auto":
        a = secrets.choice([x for x in range(1, 255) if x != 169])
        b = secrets.randbelow(63) * 4
        return {"mode": "auto", "src_ip": f"169.254.{a}.{b + 1}", "dst_ip": f"169.254.{a}.{b + 2}",
                "prefix": 30, "src_gw": "", "dst_gw": ""}
    out = {"mode": "routed"}
    for k in ("src", "dst"):
        try:
            iface = ipaddress.IPv4Interface(str(form.get(f"{k}_cidr", "")).strip())
        except ValueError:
            raise MoveError(f"the {'VM' if k == 'src' else 'new VM'}'s transfer address is IP/BITS, like 10.20.0.5/24") from None
        gw = str(form.get(f"{k}_gw", "")).strip()
        if gw:
            try:
                ipaddress.IPv4Address(gw)
            except ValueError:
                raise MoveError("a gateway is an IPv4 address") from None
        out[f"{k}_ip"], out[f"{k}_prefix"], out[f"{k}_gw"] = str(iface.ip), iface.network.prefixlen, gw
    out["prefix"] = out["dst_prefix"]
    return out


def check(user, form: dict) -> dict:
    """Everything that can be known before anything is created. Returns the
    plan ({"ok", "problems", "notes", "src", "dst", ...}); nothing changes."""
    problems, notes = [], []
    src_conn = virtops.find_conn(str(form.get("c", "")))
    dst_conn = virtops.find_conn(str(form.get("to", "")))
    if not src_conn or not dst_conn:
        raise MoveError("unknown connection")
    why = may_move(user, src_conn, dst_conn)
    if why:
        raise MoveError(why)
    ok, why = moveiso.parts()
    if not ok:
        raise MoveError(why)
    guest = {"user": str(form.get("guest_user", "")).strip(), "password": str(form.get("guest_password", ""))}
    src = side(src_conn, str(form.get("node", "")), str(form.get("vm", "")), guest)
    facts = src.facts()
    if facts["power"] != "running":
        problems.append("the VM is not running: a stopped VM is moved as a copy of its disks, not by EnvMap Move")
    problems += facts["blockers"]
    if src.flavor == "proxmox":
        try:
            if src.ha_managed():
                problems.append("Proxmox HA manages this VM: when the old copy powers itself off at the end, HA "
                                "would start it again from its old disks. Take it out of HA for the move "
                                "(Datacenter → HA)")
        except VirtError as e:
            notes.append(f"whether Proxmox HA manages this VM could not be read: {e}")
    dst_where = str(form.get("dst_node", "")) if virtops.flavor(dst_conn) == "proxmox" else ""
    dst = side(dst_conn, dst_where)
    same_vm = (src_conn["id"] == dst_conn["id"] and virtops.flavor(dst_conn) == "esxi")
    if same_vm:
        problems.append("the source and the target are the same ESXi host")
    cross = virtops.flavor(src_conn) != virtops.flavor(dst_conn)
    # the guest
    g = {}
    if not src.agent_ok():
        problems.append("the guest agent is not answering: Proxmox needs qemu-guest-agent running in the guest and "
                        "the agent option on" if src.flavor == "proxmox" else
                        "VMware Tools are not running in the guest")
    else:
        try:
            code, out = src.exec(GUEST_CHECK, 60)
            g = parse_kv(out)
            problems += guest_problems(g, cross)
        except VirtError as e:
            if "disabled" in str(e).lower() or "not allowed" in str(e).lower():
                problems.append("the guest agent does not run commands or write files: on RHEL, Alma and Rocky "
                                "allow guest-exec, guest-exec-status and guest-file-* in /etc/sysconfig/qemu-ga "
                                f"and restart qemu-guest-agent ({e})")
            else:
                problems.append(f"the guest could not be asked: {e}")
    # the target
    try:
        room = dst.room()
        if room["free_mb"] and room["free_mb"] < facts["memory_mb"] + 512:
            problems.append(f"the target has {room['free_mb']} MB of memory free; the VM needs {facts['memory_mb']} MB")
    except VirtError as e:
        notes.append(f"the target's free memory could not be read: {e}")
    ch = dst.choices()
    store = str(form.get("storage", "")).strip()
    st = next((s for s in ch["storages"] if s["name"] == store), None)
    if not st:
        problems.append("choose where the new VM's disks go")
    else:
        need = sum(d["bytes"] for d in facts["disks"]) / 1024 ** 3
        if st.get("free_gib") is not None and st["free_gib"] < need + 1:
            problems.append(f"{store} has {st['free_gib']} GiB free; the disks need {need:.1f} GiB")
    if dst.flavor == "proxmox":
        iso_store = str(form.get("iso_storage", "")).strip() or next(
            (s["name"] for s in ch.get("iso_storages", [])), "")
        if not iso_store:
            problems.append("the target node has no storage that holds ISO images (for the receiver CD)")
    else:
        iso_store = store
    nets = []
    for i, n in enumerate(facts["nics"]):
        net = str(form.get(f"net{i}", "")).strip()
        vlan = str(form.get(f"vlan{i}", "")).strip()
        if net not in ch["networks"]:
            problems.append(f"choose the network for card {i + 1} ({n['mac']})")
        if vlan and not (vlan.isdigit() and 1 <= int(vlan) <= 4094):
            problems.append(f"card {i + 1}: a VLAN tag between 1 and 4094")
        nets.append({"network": net, "vlan": vlan if dst.flavor == "proxmox" else ""})
    if not facts["nics"]:
        problems.append("the VM has no network card")
    tr = transfer_addresses(form)
    first = facts["nics"][0] if facts["nics"] else {"network": "", "vlan": ""}
    if form.get("src_tnet"):
        src_net, src_vlan = str(form["src_tnet"]), str(form.get("src_tvlan") or "").strip()
    else:
        src_net, src_vlan = str(first["network"] or ""), str(first.get("vlan") or "")
    if form.get("dst_tnet"):
        dst_net, dst_vlan = str(form["dst_tnet"]), str(form.get("dst_tvlan") or "").strip()
    else:
        dst_net, dst_vlan = (nets[0]["network"], nets[0]["vlan"]) if nets else ("", "")
    if src.flavor != "proxmox":
        src_vlan = ""
    if dst.flavor != "proxmox":
        dst_vlan = ""
    for what, v in (("the VM's transfer card", src_vlan), ("the new VM's transfer card", dst_vlan)):
        if v and not (v.isdigit() and 1 <= int(v) <= 4094):
            problems.append(f"{what}: a VLAN tag between 1 and 4094")
    tr.update(src_net=src_net, src_vlan=src_vlan, dst_net=dst_net, dst_vlan=dst_vlan,
              src_mac=moveside.new_mac(src.flavor), dst_mac=moveside.new_mac(dst.flavor))
    if tr["dst_net"] not in ch["networks"]:
        problems.append("choose the network the new VM's transfer card goes on")
    if form.get("src_tnet"):
        try:
            if tr["src_net"] not in src.choices()["networks"]:
                problems.append("the VM's transfer network is not one of its hypervisor's networks")
        except VirtError as e:
            problems.append(f"the VM's networks could not be read: {e}")
    if cross:
        notes.append("across hypervisors: the disk controllers change type, so the storage is re-pointed on arrival")
    if facts["firmware"] == "efi":
        notes.append("UEFI: the new VM starts with its own firmware settings; it boots from its disk's standard boot file after a restart")
    if cross and src.flavor == "proxmox":
        notes.append("Proxmox to ESXi: the system shows it has arrived through VMware Tools, which a system that "
                     "started on Proxmox may not run; then you confirm it on the new VM's console")
    name = facts["name"]
    return {"ok": not problems, "problems": problems, "notes": notes,
            "src": {"conn": src_conn["id"], "conn_name": src_conn.get("name", ""), "flavor": src.flavor,
                    "node": str(form.get("node", "")), "vm": str(form.get("vm", "")), "name": name,
                    "cpus": facts["cpus"], "memory_mb": facts["memory_mb"], "firmware": facts["firmware"],
                    "disks": [{"key": str(d["key"]), "gib": d["gib"]} for d in facts["disks"]],
                    "nics": [{"key": str(n["key"]), "mac": n["mac"], "network": n["network"]} for n in facts["nics"]],
                    "os": g.get("os", ""), "kernel": g.get("kernel", ""),
                    "production": bool(src_conn.get("production"))},
            "dst": {"conn": dst_conn["id"], "conn_name": dst_conn.get("name", ""), "flavor": dst.flavor,
                    "node": dst_where, "storage": store, "iso_storage": iso_store, "nets": nets,
                    "production": bool(dst_conn.get("production"))},
            "transfer": tr, "cross": cross, "facts": facts}


def confirm_name(plan: dict, confirm: str) -> None:
    if plan["src"]["production"] or plan["dst"]["production"]:
        name = (plan["src"]["name"] or "").strip()
        if not name:
            raise MoveError("a production hypervisor is involved, and the VM's name could not be read to confirm it")
        if (confirm or "").strip() != name:
            raise MoveError(f"a production hypervisor is involved: type {name} to confirm")


# ── starting one ───────────────────────────────────────────────
def start(user, form: dict) -> dict:
    """Check again, then start the move in the background. Returns the job."""
    plan = check(user, form)
    if not plan["ok"]:
        raise MoveError("; ".join(plan["problems"]))
    confirm_name(plan, str(form.get("confirm", "")))
    with _lock:
        if len(_running) >= AT_ONCE:
            raise MoveError(f"{AT_ONCE} moves are running already; start this one when one has finished")
        for j in all_jobs():
            if j.get("state") not in DONE and j["src"]["conn"] == plan["src"]["conn"] \
                    and j["src"]["vm"] == plan["src"]["vm"]:
                raise MoveError("this VM is being moved already")
        jid = secrets.token_hex(6)
        job = {"id": jid, "created": time.time(), "state": "starting",
               "by": {"id": (user or {}).get("id", ""), "email": (user or {}).get("email", ""),
                      "name": (user or {}).get("name") or (user or {}).get("email", "")},
               "src": plan["src"], "dst": plan["dst"], "transfer": plan["transfer"], "cross": plan["cross"],
               "built": {}, "times": {"starting": time.time()}, "log": [],
               "tokens": {"boot": secrets.token_urlsafe(24), "verdict": secrets.token_urlsafe(24)}}
        if plan["src"]["flavor"] == "esxi":
            _secrets[jid] = {"user": str(form.get("guest_user", "")).strip(),
                             "password": str(form.get("guest_password", ""))}
        save(job)
        t = threading.Thread(target=_run, args=(jid, plan["facts"]), daemon=True, name=f"move-{jid}")
        _running[jid] = t
    t.start()
    return job


def _sides(job: dict):
    sc, dc = virtops.find_conn(job["src"]["conn"]), virtops.find_conn(job["dst"]["conn"])
    if not sc or not dc:
        raise MoveError("a connection of this move was deleted")
    src = side(sc, job["src"]["node"], job["src"]["vm"], _secrets.get(job["id"]))
    dst = side(dc, job["dst"]["node"], job["built"].get("vm"))
    return src, dst


def _run(jid: str, facts: dict) -> None:
    job = load(jid)
    try:
        _prepare(job, facts)
        _move(job)
    except Exception as e:                                 # noqa: BLE001
        job = load(jid) or job
        say(job, f"stopped: {e}", "error")
        _after_failure(job, str(e))
    finally:
        with _lock:
            _running.pop(jid, None)
            if (load(jid) or {}).get("state") in DONE:
                _secrets.pop(jid, None)


def _prepare(job: dict, facts: dict) -> None:
    src, dst = _sides(job)
    tr, tok = job["transfer"], job["tokens"]
    name = job["src"]["name"]
    phase(job, "preparing", f"preparing: {job['src']['name']} on {job['src']['conn_name']} "
                            f"→ {job['dst']['conn_name']}" + (f" ({job['dst']['node']})" if job["dst"]["node"] else ""))
    # the receiver CD, made for this move
    settings = {"ip": f"{tr['dst_ip']}/{tr.get('dst_prefix', tr['prefix'])}", "gw": tr.get("dst_gw", ""),
                "mac": tr["dst_mac"], "port": BOOT_PORT, "token": tok["boot"],
                "verdict": f"{tr['src_ip']}:{VERDICT_PORT}", "vtoken": tok["verdict"]}
    iso = moveiso.receiver_iso(settings)
    iso_name = f"envmove-{job['id']}.iso"
    say(job, f"receiver CD written ({len(iso) >> 20} MiB); uploading it to {job['dst']['iso_storage']}")
    job["built"]["iso"] = dst.upload_iso(job["dst"]["iso_storage"], iso_name, iso)
    update(job, lambda c: None)
    # the new VM
    new_name = f"{name}-moving"[:60]
    if dst.flavor == "proxmox":
        spec, where = moveside.pve_spec(facts, facts["flavor"], name=re.sub(r"[^A-Za-z0-9.-]", "-", new_name),
                                        storage=job["dst"]["storage"], nets=job["dst"]["nets"],
                                        transfer=tr, iso=job["built"]["iso"])
        job["built"]["vm"] = dst.create(spec)
        job["built"].update(cd=where["cd"], tcard=where["transfer"], boot=where["boot"], onboot=where["onboot"])
    else:
        cfg = moveside.esxi_spec(facts, name=new_name, datastore=job["dst"]["storage"],
                                 nets=job["dst"]["nets"], transfer=tr, iso=job["built"]["iso"])
        job["built"]["vm"] = dst.create(cfg)
        keys = dst.device_keys()
        job["built"].update(cd=(keys["cdroms"] or [""])[0], tcard=keys["nics"].get(tr["dst_mac"], ""))
    update(job, lambda c: None)
    say(job, f"new VM {new_name} created ({job['built']['vm']}), stopped, with blank disks of the same sizes")
    # the source's transfer card, and the engine in the guest
    job["built"]["scard"] = src.add_card(tr["src_mac"], tr["src_net"], tr.get("src_vlan", ""))
    update(job, lambda c: None)
    say(job, f"transfer card added to the running VM ({tr['src_mac']}, network {tr['src_net']}"
             + (f", VLAN {tr['src_vlan']}" if tr.get("src_vlan") else "") + ")")
    data, digest = moveside.gz(moveiso.engine())
    src.put("/tmp/envmove.gz", data)
    code, out = src.exec(f"gzip -dc /tmp/envmove.gz > {ENGINE}.new && rm -f /tmp/envmove.gz && chmod 755 {ENGINE}.new "
                         f"&& mv -f {ENGINE}.new {ENGINE} && (restorecon {ENGINE} 2>/dev/null; true) && sha256sum {ENGINE}", 120)
    if code or digest not in out:
        raise MoveError(f"the engine did not arrive whole in the guest: {out[-200:]}")
    say(job, f"engine copied into the guest ({ENGINE}, sha256 {digest[:12]}…)")
    route = ""
    if tr.get("src_gw"):
        route = f"ip route replace {tr['dst_ip']}/32 via {tr['src_gw']} dev $x; "
    pfx = tr.get("src_prefix", tr["prefix"])
    script = (f"x=''; for i in $(seq 1 60); do x=$(grep -l -i -x {tr['src_mac']} /sys/class/net/*/address 2>/dev/null | head -1 | cut -d/ -f5); "
              f"[ -n \"$x\" ] && break; sleep 1; done; [ -n \"$x\" ] || {{ echo 'the transfer card did not appear in the guest'; exit 1; }}; "
              f"command -v nmcli >/dev/null && nmcli dev set $x managed no 2>/dev/null; "
              f"sysctl -qw net.ipv6.conf.$x.disable_ipv6=1 2>/dev/null; ip link set dev $x up && "
              f"ip addr replace {tr['src_ip']}/{pfx} dev $x && {route}"
              # the move's own card is let through the guest's firewall, for this run only: once frozen,
              # the system is told everything through it (the engine checks it answers before freezing)
              f"{{ if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then "
              f"firewall-cmd --zone=trusted --change-interface=$x >/dev/null 2>&1; fi; "
              f"iptables -C INPUT -i $x -j ACCEPT 2>/dev/null || iptables -I INPUT -i $x -j ACCEPT 2>/dev/null; "
              f"nft list table inet filter >/dev/null 2>&1 && nft insert rule inet filter input iifname $x accept 2>/dev/null; "
              f"true; }} && echo card=$x")
    code, out = src.exec(script, 120)
    if code:
        raise MoveError(f"the transfer card could not be set up in the guest: {out[-300:]}")
    say(job, f"transfer card set up in the guest: {parse_kv(out).get('card', '?')} {tr['src_ip']}/{pfx}")
    dst.start()
    say(job, "new VM started: its receiver waits on the transfer card")


def _send_command(job: dict) -> str:
    tr, tok = job["transfer"], job["tokens"]
    after = f"{tr['dst_mac']}={tr['dst_ip']}/{tr.get('dst_prefix', tr['prefix'])}" + (f",{tr['dst_gw']}" if tr.get("dst_gw") else "")
    args = [ENGINE, "send", "-to", f"{tr['dst_ip']}:{RX_PORT}", "-boot", f"{tr['dst_ip']}:{BOOT_PORT}",
            "-copy", "-ahead", "-via", tr["src_mac"], "-after", after, "-verdict", str(VERDICT_PORT)]
    args += ["-repoint"] if job.get("cross") else ["-keep", "auto"]
    # the tokens go in the environment, not on the command line every user of
    # the guest can read; the engine's own process id goes in a file
    env = (f"ENVMOVE_BOOTTOKEN={moveside.sh_quote(tok['boot'])} "
           f"ENVMOVE_VERDICTTOKEN={moveside.sh_quote(tok['verdict'])} ")
    return ("cd /; umask 077; : > " + LOG + "; " + env + "setsid nohup " + " ".join(moveside.sh_quote(a) for a in args)
            + f" < /dev/null >> {LOG} 2>&1 & echo $! > {PIDFILE}")


def _move(job: dict) -> None:
    src, dst = _sides(job)
    phase(job, "copying", "starting the move in the guest")
    code, out = src.exec(_send_command(job), 60)
    if code:
        raise MoveError(f"the move did not start in the guest: {out[-300:]}")
    watch(job, src, dst)


def _read_log(src, job: dict) -> str | None:
    """New lines of the engine's log, or None when the guest does not answer."""
    pos = int(job.get("logpos") or 0)
    try:
        code, out = src.exec(f"tail -c +{pos + 1} {LOG} 2>/dev/null | head -c 12000", 20)
    except VirtError:
        return None
    if code:
        return ""
    if out:
        job["logpos"] = pos + len(out.encode())
        update(job, lambda c: None)
        for line in out.splitlines():
            if line.strip():
                say(job, line, "guest")
    return out


def watch(job: dict, src, dst) -> None:
    """Follows the move to its end: the engine's log while the guest answers,
    then the two VMs. A hypervisor or guest that does not answer, for whatever
    reason, is waited out: it is never taken for an answer."""
    text, quiet, errors, last_dst = "", 0, 0, 0.0
    can_read = not (src.flavor == "esxi" and not getattr(src, "user", ""))
    while True:
        job = load(job["id"]) or job
        state = job.get("state")
        if state in DONE:
            return
        try:
            if state == "finishing":
                return _arrived(job, src, dst)
            if state in ("copying", "frozen") and src.status() == "stopped":
                # the moved system powers the old copy off once it runs; but a
                # VM can stop for other reasons, so the new VM must show it
                if _shows_system(dst, 180):
                    say(job, "the old copy is off and the new VM's guest agent answers")
                    return _arrived(job, src, dst)
                phase(job, "stuck", "the VM powered off, but the new VM does not show the system (its guest agent "
                                    "or VMware Tools do not answer): look at the new VM's console; if the system "
                                    "runs there, keep it there")
                continue
            if state == "copying":
                got = _read_log(src, job) if can_read else None
                if got is None:
                    quiet += 1
                else:
                    quiet = 0
                    text += got
                if "THAWED" in text or ("envmove:" in text and "WAITING" not in text
                                        and _engine_running(src) is False):
                    _after_failure(job, "the move did not happen; the VM carries on where it was", thawed=True)
                    return
                if quiet >= 2 and not src.agent_ok():
                    phase(job, "frozen", "the VM stopped answering: it is frozen while its memory crosses to the new VM")
                time.sleep(2)
            elif state in ("frozen", "stuck"):
                if time.time() - last_dst > 8:
                    last_dst = time.time()
                    if dst.agent_ok():
                        # only the moved system has a guest agent there: the receiver has none
                        if src.status() != "stopped":
                            say(job, "the new VM's guest agent answers: the system runs there; powering the old "
                                     "copy off (it was waiting for that)")
                            src.stop()
                        return _arrived(job, src, dst)
                if can_read and src.agent_ok():
                    got = _read_log(src, job) or ""
                    text += got
                    if "THAWED" in text or ("envmove:" in text and _engine_running(src) is False):
                        _after_failure(job, "the VM came back where it was (thawed): the move was undone", thawed=True)
                        return
                    if state == "frozen" and _engine_running(src) and "WAITING" not in text:
                        phase(job, "copying", "the VM answers again: it was busy, not frozen; the move goes on")
                        quiet = 0
                        continue
                if state == "frozen" and time.time() - job["times"].get("frozen", time.time()) > FROZEN_LIMIT:
                    phase(job, "stuck", "frozen for more than 15 minutes without arriving: look at the new VM's "
                                        "console, then bring the VM back, or keep it on the new VM if it runs there")
                time.sleep(1 if state == "frozen" else 3)
            else:
                return
            errors = 0
        except Exception as e:                                  # noqa: BLE001
            errors += 1
            if errors in (1, 10, 60):
                say(job, f"a hypervisor or the guest did not answer ({type(e).__name__}: {str(e)[:200]}); "
                         "still watching", "error")
            if errors >= 120 and state in ("copying", "frozen"):
                phase(job, "stuck", "the hypervisors have not answered for minutes: decide once they do")
            time.sleep(5)


def _shows_system(dst, limit: float) -> bool:
    """Whether the new VM's guest agent (or VMware Tools) answers within
    `limit` seconds: only the moved system has one there."""
    t0 = time.time()
    while time.time() - t0 < limit:
        try:
            if dst.agent_ok():
                return True
        except Exception:                                      # noqa: BLE001
            pass
        time.sleep(5)
    return False


def _engine_running(src):
    """True or False from the engine's own process id; None when the guest
    cannot be asked (then nobody may conclude it stopped)."""
    try:
        code, _ = src.exec(f'[ -f {PIDFILE} ] && kill -0 "$(cat {PIDFILE})" 2>/dev/null', 20)
        return code == 0
    except Exception:                                          # noqa: BLE001
        return None


def _arrived(job: dict, src, dst) -> None:
    """The old copy is off: the system runs on the new VM. Make it an ordinary
    VM there, and keep the old one, renamed and stopped."""
    if job["state"] != "finishing":
        phase(job, "finishing", "the old copy powered off: the system runs on the new VM")
    b, name = job["built"], job["src"]["name"]
    stamp = time.strftime("%Y%m%d")
    steps = []
    if dst.flavor == "proxmox":
        upd = {b["cd"]: "none,media=cdrom", "boot": b.get("boot") or "order=scsi0"}
        if b.get("onboot"):
            upd["onboot"] = b["onboot"]
        steps.append(("the receiver CD taken out, the disk made the start device", lambda: dst.set(upd)))
        steps.append(("the new VM's transfer card removed", lambda: dst.remove_card(b["tcard"])))
        steps.append((f"the new VM named {name}", lambda: dst.set({"name": re.sub(r"[^A-Za-z0-9.-]", "-", name)})))
    else:
        steps.append(("the receiver CD taken out", lambda: dst._wait(moveside.E.cd_set(dst.es, dst.moid, int(b["cd"]), ""))
                      if b.get("cd") else None))
        steps.append(("the new VM's transfer card removed", lambda: dst.remove_card(b["tcard"]) if b.get("tcard") else None))
        steps.append(("the disk made the start device", lambda: dst.boot_disk_first()))
        steps.append((f"the new VM named {name}", lambda: dst.rename(name)))
    old = f"{name}-left-{stamp}"
    if src.flavor == "proxmox":
        steps.append(("the old VM's transfer card removed", lambda: src.remove_card(b.get("scard", ""))))
        steps.append((f"the old VM renamed {old} and kept from starting with its host",
                      lambda: src.set({"name": re.sub(r"[^A-Za-z0-9.-]", "-", old), "onboot": 0})))
    else:
        steps.append(("the old VM's transfer card removed", lambda: src.remove_card(b["scard"]) if b.get("scard") else None))
        steps.append((f"the old VM renamed {old}", lambda: src.rename(old)))
    # a backstop for anything that starts the old VM again (a host restart, an
    # autostart list, a person): its cards come up disconnected
    steps.append(("the old VM's network cards disconnected", lambda: src.disconnect_cards()))
    steps.append(("the receiver CD deleted", lambda: dst.delete_iso(b["iso"]) if b.get("iso") else None))
    left = []
    for what, fn in steps:
        try:
            fn()
            say(job, what)
        except Exception as e:                                # noqa: BLE001
            left.append(f"{what}: {e}")
            say(job, f"not done — {what}: {e}", "error")
    t = job.get("times", {})
    if t.get("frozen") and t.get("finishing"):
        job["result"] = {"frozen_to_seen_s": round(t["finishing"] - t["frozen"], 1)}
        update(job, lambda c: None)
    try:
        if dst.agent_ok():
            _, out = dst.exec(f"grep -E 'disks: |memory: |OLD COPY|ARRIVED|network: ' {LOG} | tail -20", 20)
            for line in out.splitlines():
                say(job, line, "guest")
    except Exception:                                        # noqa: BLE001
        pass
    phase(job, "done", "moved" + ("; some tidying is left: " + "; ".join(left) if left else ""))
    virt.forget(virtops.find_conn(job["src"]["conn"]) or {})
    virt.forget(virtops.find_conn(job["dst"]["conn"]) or {})


def _after_failure(job: dict, why: str, thawed: bool = False) -> None:
    """The system still runs where it was (or never stopped): remove what was
    built for the move. `thawed`: the guest was seen answering again, so the
    system is certainly not on the new VM."""
    job = load(job["id"]) or job
    state = job.get("state")
    if state in DONE:
        say(job, f"after the end: {why}", "error")
        return
    if not thawed and state not in ("starting", "preparing"):
        # once the engine runs, the system may be frozen, on its way or on the
        # new VM: nothing is taken away until the guest is seen running again
        if state != "stuck":
            phase(job, "stuck", f"{why}. Nothing was removed: look at the two VMs, then bring the VM back or "
                                "keep it on the new one")
        else:
            say(job, why, "error")
        return
    say(job, why, "error")
    try:
        src, dst = _sides(job)
    except VirtError as e:
        phase(job, "failed", f"could not tidy up: {e}")
        return
    b = job.get("built", {})
    if b.get("vm"):
        try:
            dst.destroy()
            say(job, "the new VM deleted")
        except Exception as e:                                # noqa: BLE001
            say(job, f"the new VM could not be deleted: {e}", "error")
    if b.get("iso"):
        try:
            dst.delete_iso(b["iso"])
            say(job, "the receiver CD deleted")
        except Exception as e:                                # noqa: BLE001
            say(job, f"the receiver CD could not be deleted: {e}", "error")
    if b.get("scard"):
        try:
            src.remove_card(b["scard"])
            say(job, "the transfer card taken out of the VM")
        except Exception as e:                                # noqa: BLE001
            say(job, f"the transfer card could not be taken out: {e}", "error")
    phase(job, "undone" if job.get("times", {}).get("copying") else "failed",
          "nothing changed for the VM: it runs where it was")


# ── the person's decisions while frozen ────────────────────────
def _decide_gate(user, job: dict, confirm: str):
    if not job or job.get("state") not in ("frozen", "stuck"):
        raise MoveError("this move is not waiting for a decision")
    sc, dc = virtops.find_conn(job["src"]["conn"]), virtops.find_conn(job["dst"]["conn"])
    if not sc or not dc:
        raise MoveError("a connection of this move was deleted")
    why = may_move(user, sc, dc)
    if why:
        raise MoveError(why)
    if job["src"].get("production") or job["dst"].get("production"):
        name = (job["src"].get("name") or "").strip()
        if not name or (confirm or "").strip() != name:
            raise MoveError(f"a production hypervisor is involved: type {name or 'the VM name'} to confirm")
    return _sides(job)


def bring_back(user, jid: str, confirm: str = "") -> dict:
    """Restart the new VM: its receiver finds the system still waiting and
    tells it to carry on where it was. Refused when the system already runs
    on the new VM, or the other decision was taken."""
    job = load(jid)
    with _jlock(jid):
        job = load(jid)
        src, dst = _decide_gate(user, job, confirm)
        if (job.get("decision") or {}).get("what") == "keep":
            raise MoveError("it was decided to keep it on the new VM")
        if src.status() == "stopped":
            raise MoveError("the old copy is off: the system runs on the new VM")
        if dst.agent_ok():
            raise MoveError("the new VM's guest agent answers: the system runs there, and restarting it would lose "
                            "what it did since")
        if src.agent_ok():
            raise MoveError("the VM answers where it was: it is not frozen")
        update(job, lambda c: c.update(decision={"what": "back", "by": job_by(user), "t": time.time()}))
        say(job, f"bring it back: {job_by(user)} restarted the new VM, whose receiver tells the VM to carry on "
                 "where it was")
        if dst.status() == "running":
            dst.reset()
        else:
            dst.start()
        phase(job, "frozen")
    _resume(job)
    return job


def keep_new(user, jid: str, confirm: str = "") -> dict:
    """The system runs on the new VM but the old copy was not reached: power
    the old copy off from its hypervisor, which is what it was waiting for.
    Refused while the old copy answers (it is not frozen), or after "bring it
    back"."""
    with _jlock(jid):
        job = load(jid)
        src, dst = _decide_gate(user, job, confirm)
        if (job.get("decision") or {}).get("what") == "back":
            raise MoveError("it was decided to bring it back; wait for that to finish")
        if src.status() != "stopped":
            if src.agent_ok():
                raise MoveError("the VM answers where it was: it is running, not frozen, and is not powered off")
            update(job, lambda c: c.update(decision={"what": "keep", "by": job_by(user), "t": time.time()}))
            say(job, f"keep it on the new VM: {job_by(user)} powered the old copy off")
            src.stop()
        else:
            update(job, lambda c: c.update(decision={"what": "keep", "by": job_by(user), "t": time.time()}))
            say(job, f"keep it on the new VM: {job_by(user)} confirmed the system runs there")
        phase(job, "finishing")
    _resume(job)
    return job


def job_by(user) -> str:
    return (user or {}).get("name") or (user or {}).get("email") or "someone"


def _resume(job: dict) -> None:
    with _lock:
        if job["id"] in _running:
            return
        t = threading.Thread(target=_watch_again, args=(job["id"],), daemon=True, name=f"move-{job['id']}")
        _running[job["id"]] = t
    t.start()


def _watch_again(jid: str) -> None:
    job = load(jid)
    try:
        src, dst = _sides(job)
        watch(job, src, dst)
    except Exception as e:                                     # noqa: BLE001
        job = load(jid) or job
        say(job, f"watching stopped: {e}", "error")
    finally:
        with _lock:
            _running.pop(jid, None)


def resume_all() -> None:
    """At start: a move that was being watched when EnvMap stopped is watched
    again (the guest went on with it meanwhile). One that was still being
    prepared is undone."""
    for job in all_jobs():
        if job.get("state") in DONE:
            continue
        if job.get("state") in ("starting", "preparing"):
            say(job, "EnvMap restarted while the move was being prepared", "error")
            _after_failure(job, "the move was not started")
            continue
        if job["src"]["flavor"] == "esxi":
            say(job, "EnvMap restarted: the guest's sign-in is gone, so the move is followed through the VMs alone", "error")
        _resume(job)


def visible(user, job: dict) -> bool:
    """A move is shown to whoever may see both connections."""
    for cid in (job["src"]["conn"], job["dst"]["conn"]):
        c = virtops.find_conn(cid)
        if not c or not rbac.may_project(user, c.get("pid") or "", "virt"):
            return False
    return True
