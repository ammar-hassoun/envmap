"""EnvMap Move for a VM that is powered off.

A running VM moves itself (vmmove): its own system copies its disks and its
memory and carries on on the new VM. A VM that is off has no system to do
that, and it needs none: only its disks have to cross. EnvMap does not start
the VM to copy them. It makes the new VM, powered off, and two small helper
machines of its own (coldside), one on each host:

    old host   VM (off) ── its disks ──► giver ═══ transfer network ═══►
    new host   taker ──► the new VM's blank disks ──► read back, every byte

When both helpers say that every disk was read back from the new host's
storage and is the same, the helpers are removed, the new VM takes the VM's
name, and the old VM is kept: renamed, its cards disconnected.

WHAT CAN BE RELIED ON
    The VM is never changed before the copy is confirmed. So every way out
    before that is the same one: remove the helpers, the CDs and the new VM,
    and the VM is where it was, powered off, as if nothing had been tried.
    There is no "stuck" here and nothing for a person to decide.

    Neither VM is started by EnvMap, the old one or the new one. The new VM
    is powered off when the move is done, as the old one was.

    "Done" is read from the helpers while they run. A helper that is off,
    gone, or silent has confirmed nothing, and the move is undone.

    The VM must not run while its disks are read. ESXi holds the disks'
    locks for the helper, so the VM cannot start. Proxmox has no such lock,
    so at the end the node's task list is asked whether the VM was started
    since the move began; if it was, the copy is thrown away.
"""
from __future__ import annotations

import re
import threading
import time

from . import coldside, moveiso, virt, virtops, vmmove
from .virt import VirtError
from .vmmove import MoveError

POLL = 4
STALL = 20 * 60          # nothing moved for this long: given up, undone
UNHEARD = 10 * 60        # a helper that runs and cannot be heard for this long: the same
APART = 5 * 60           # both helpers run and have not found each other for this long: the same
OLD, NEW = "the helper on the old host", "the helper on the new host"


def _iso_names(jid: str) -> tuple[str, str]:
    return f"envmove-{jid}0.iso", f"envmove-{jid}1.iso"       # the taker's, the giver's


def _helpers(job: dict, src, dst):
    b = job.get("built") or {}
    return coldside.helper(src, b.get("giver")), coldside.helper(dst, b.get("taker"))


def _where(d: dict) -> str:
    return d.get("volume") or d.get("file") or ""


def run(job: dict, facts: dict) -> None:
    prepare(job, facts)
    watch(job)


def prepare(job: dict, facts: dict) -> None:
    src, dst = vmmove._sides(job)
    tr, b, jid, name = job["transfer"], job["built"], job["id"], job["src"]["name"]
    keep = lambda: vmmove.update(job, lambda c: None)       # noqa: E731
    sizes = [int(d["bytes"]) for d in facts["disks"]]
    vmmove.phase(job, "preparing", f"preparing: {name} (powered off) on {job['src']['conn_name']} → "
                                   f"{job['dst']['conn_name']}" + (f" ({job['dst']['node']})" if job["dst"]["node"] else ""))
    if src.status() != "stopped":
        raise MoveError("the VM is no longer powered off")
    # the new VM: built, and left powered off
    on_esxi = dst.flavor == "esxi"
    new_name = name if on_esxi else f"{name}-moving"[:60]
    plan = None
    if getattr(dst, "road", "") == "shell":
        # written down before any of it is made, so it can be undone from the record
        plan = dst.plan_build(facts, name=new_name, datastore=job["dst"]["storage"])
        b["making"] = plan
        keep()
    b.update(coldside.target(dst, facts, name=new_name, storage=job["dst"]["storage"], nets=job["dst"]["nets"], plan=plan))
    keep()
    vmmove.say(job, f"new VM {new_name} created ({b['vm']}), powered off, with blank disks of the same sizes. "
                    "EnvMap does not start it")
    # the two CDs: the same helper, told which side it is on and where its disks are
    tok = job["tokens"]["cold"]
    take = {"role": "take", "ip": f"{tr['dst_ip']}/{tr.get('dst_prefix', tr['prefix'])}", "gw": tr.get("dst_gw", ""),
            "mac": "", "port": vmmove.BOOT_PORT, "token": tok, "disks": coldside.slots(dst.flavor, sizes)}
    give = {"role": "give", "ip": f"{tr['src_ip']}/{tr.get('src_prefix', tr['prefix'])}", "gw": tr.get("src_gw", ""),
            "mac": "", "port": vmmove.BOOT_PORT, "token": tok, "to": f"{tr['dst_ip']}:{vmmove.BOOT_PORT}",
            "disks": coldside.slots(src.flavor, sizes)}
    take_iso, give_iso = _iso_names(jid)
    data = moveiso.receiver_iso(take)
    b["iso"] = dst.upload_iso(job["dst"]["iso_storage"], take_iso, data)
    keep()
    b["src_iso"] = src.upload_iso(job["src"]["iso_storage"], give_iso, moveiso.receiver_iso(give))
    keep()
    vmmove.say(job, f"the helpers' CDs written ({len(data) >> 20} MiB each) and uploaded: {b['iso']} and {b['src_iso']}")
    # the taker first: it waits for the giver
    gh, th = _helpers(job, src, dst)
    b["taker"] = th.plan(coldside.helper_name(jid, "take"), job["dst"]["storage"])
    keep()
    b["taker"] = th.make(b["taker"], iso=b["iso"], net=tr["dst_net"], vlan=tr.get("dst_vlan", ""), mac=tr["dst_mac"],
                         disks=b["wheres"], places=take["disks"], readonly=False)
    keep()
    th.start()
    vmmove.say(job, f"{NEW} made and started ({b['taker']['name']}, {b['taker']['vm']}): it holds the new VM's "
                    f"{len(sizes)} disk{'s' if len(sizes) != 1 else ''} and waits on the transfer network ({tr['dst_net']})")
    b["giver"] = gh.plan(coldside.helper_name(jid, "give"), job["src"].get("helper_store", ""))
    keep()
    b["giver"] = gh.make(b["giver"], iso=b["src_iso"], net=tr["src_net"], vlan=tr.get("src_vlan", ""), mac=tr["src_mac"],
                         disks=[_where(d) for d in facts["disks"]], places=give["disks"], readonly=True)
    keep()
    if src.status() != "stopped":
        raise MoveError("the VM was started while the move was being prepared")
    gh.start()
    vmmove.say(job, f"{OLD} made and started ({b['giver']['name']}, {b['giver']['vm']}): it holds the VM's disks "
                    "to read them. The VM itself stays powered off")


def _same_digests(ts: dict, gs: dict, n: int) -> list[str]:
    a, g = list(ts.get("digests") or []), list(gs.get("digests") or [])
    if len(a) != n or len(g) != n or not all(a) or a != g:
        raise MoveError("the two helpers say done but do not name the same digest for every disk "
                        f"(old host {g}, new host {a}): the copy is not kept")
    return a


def watch(job: dict) -> None:
    src, dst = vmmove._sides(job)
    gh, th = _helpers(job, src, dst)
    n = len(job["built"].get("wheres") or [])
    if job.get("state") != "copying":
        vmmove.phase(job, "copying", "the two helpers are starting from their CDs")
    t0 = moved = time.time()
    heard = {OLD: 0.0, NEW: 0.0}
    sig, shown, told = None, set(), ""
    both, met = 0.0, False                # when both were first heard; whether they ever found each other
    while True:
        cur = vmmove.load(job["id"]) or job
        if cur.get("cancel"):
            raise MoveError(f"stopped by {cur['cancel']}")
        ts, ttail = th.says()
        gs, gtail = gh.says()
        now = time.time()
        for label, s, tail in ((NEW, ts, ttail), (OLD, gs, gtail)):
            if not s:
                continue
            heard[label] = now
            for line in tail.splitlines():
                if (label, line) not in shown:
                    shown.add((label, line))
                    vmmove.say(job, f"{label}: {line}", "guest")
            if s.get("state") == "failed":
                raise MoveError(f"{label} stopped: {s.get('why') or 'it did not say why'}")
        if ts and gs and ts.get("state") == "done" and gs.get("state") == "done":
            digests = _same_digests(ts, gs, n)
            vmmove.update(job, lambda c: c.update(progress={"state": "done", "disk": n, "disks": n,
                                                            "done": ts.get("total", 0), "total": ts.get("total", 0),
                                                            "sent": gs.get("sent", 0), "checked": ts.get("checked", 0),
                                                            "digests": digests}))
            break
        if ts and gs and not both:
            both = now
        met = met or any((s or {}).get("state") in ("copying", "checking") for s in (ts, gs))
        if both and not met and now - both > APART:
            tr = job["transfer"]
            raise MoveError(f"the two helpers run and have not found each other for {APART // 60} minutes. The one on the "
                            f"old host is on {tr.get('src_net') or 'its network'}, the one on the new host on "
                            f"{tr.get('dst_net') or 'its network'}, and those two do not reach each other. Choose networks "
                            "that do under Transfer network, in the full form")
        # a helper that is off has said nothing
        for label, h in ((NEW, th), (OLD, gh)):
            p = h.power()
            if p != "running":
                raise MoveError(f"{label} is {'gone' if not p else 'no longer running'}, and the copy had not been confirmed")
            if now - max(heard[label], t0) > UNHEARD:
                raise MoveError(f"{label} runs but could not be heard for {UNHEARD // 60} minutes. Look at its console "
                                "on the host; EnvMap reads a helper through the guest agent's port on Proxmox and "
                                "through its serial console's file on ESXi")
        lead = ts or gs or {}
        step = ""
        if ts and ts.get("state") == "checking":
            step = f"disk {ts.get('disk', 0)} of {n}: reading the new disk back"
        elif lead.get("state") == "copying":
            step = f"disk {lead.get('disk', 0)} of {n}: copying"
        elif lead:
            step = "the helpers are finding each other"
        new = (ts or {}).get("state"), (gs or {}).get("state"), (gs or {}).get("done"), (ts or {}).get("done"), (ts or {}).get("checked")
        if new != sig:
            sig, moved = new, now
            vmmove.update(job, lambda c: c.update(progress={
                "state": lead.get("state", ""), "step": step, "disk": lead.get("disk", 0), "disks": n,
                "done": (gs or ts or {}).get("done", 0), "total": (gs or ts or {}).get("total", 0),
                "sent": (gs or {}).get("sent", 0), "checked": (ts or {}).get("checked", 0),
                "breaks": (gs or {}).get("breaks", 0)}))
        elif now - moved > STALL:
            raise MoveError(f"nothing moved for {STALL // 60} minutes (the helpers say: old host "
                            f"{(gs or {}).get('state', 'nothing')}, new host {(ts or {}).get('state', 'nothing')})")
        if step and step != told:
            told = step
            vmmove.say(job, step)
        time.sleep(POLL)
    finish(job)


def finish(job: dict) -> None:
    src, dst = vmmove._sides(job)
    b, name = job["built"], job["src"]["name"]
    if job.get("state") != "finishing":
        vmmove.phase(job, "finishing", "both helpers confirm: every disk was read back from the new host's storage "
                                       "and is the same as the original")
    # the copy is of a disk that held still only if the VM did not run meanwhile
    if src.status() != "stopped":
        raise MoveError("the VM was started while its disks were being read: the copy may be of a disk that "
                        "changed under it, so it is not kept")
    if src.flavor == "proxmox":
        started = coldside.pve_started_since(src, job.get("created") or 0)
        if started:
            raise MoveError("the VM was started and stopped again while its disks were being read: the copy may be "
                            "of a disk that changed under it, so it is not kept")
        if started is None:
            vmmove.say(job, "whether the VM was started during the copy could not be read from the node's task "
                            "list; it is powered off now", "error")
    gh, th = _helpers(job, src, dst)
    stamp = time.strftime("%Y%m%d")
    old = f"{name}-left-{stamp}"
    steps = [(f"{OLD} removed; the VM's disks were only read", gh.drop),
             (f"{NEW} removed", th.drop),
             ("the helper's CD deleted from the old host", lambda: src.delete_iso(b["src_iso"]) if b.get("src_iso") else None),
             ("the helper's CD deleted from the new host", lambda: dst.delete_iso(b["iso"]) if b.get("iso") else None)]
    if dst.flavor == "proxmox":
        upd = {"name": re.sub(r"[^A-Za-z0-9.-]", "-", name)}
        if b.get("onboot"):
            upd["onboot"] = b["onboot"]
        steps.append((f"the new VM named {name}", lambda: dst.set(upd)))
    elif b.get("making"):
        steps.append(("the new VM's folder is its own now", lambda: dst.settle(b["making"])))
    if src.flavor == "proxmox":
        steps.append((f"the old VM renamed {old} and kept from starting with its host",
                      lambda: src.set({"name": re.sub(r"[^A-Za-z0-9.-]", "-", old), "onboot": 0})))
    else:
        steps.append((f"the old VM renamed {old}", lambda: src.rename(old)))
    # whatever starts the old VM again (a host restart, an autostart list, a
    # person) finds it off the network: two VMs with one address is the harm
    steps.append(("the old VM's network cards disconnected", src.disconnect_cards))
    left = []
    for what, fn in steps:
        try:
            did = fn()
            vmmove.say(job, did if isinstance(did, str) and did and "removed" not in what else what)
        except Exception as e:                                # noqa: BLE001
            left.append(f"{what.split(';')[0]}: {e}")
            vmmove.say(job, f"not done — {what.split(';')[0]}: {e}", "error")
    vmmove.phase(job, "done", "moved, and powered off as it was: start it on the new host when you want it"
                 + ("; some tidying is left: " + "; ".join(left) if left else ""))
    virt.forget(virtops.find_conn(job["src"]["conn"]) or {})
    virt.forget(virtops.find_conn(job["dst"]["conn"]) or {})


def after_failure(job: dict, why: str) -> None:
    """Before the copy was confirmed, nothing of the VM was changed: take
    away what was made for the move."""
    job = vmmove.load(job["id"]) or job
    if job.get("state") in vmmove.DONE:
        vmmove.say(job, f"after the end: {why}", "error")
        return
    vmmove.say(job, why, "error")
    try:
        src, dst = vmmove._sides(job)
    except VirtError as e:
        vmmove.phase(job, "failed", f"could not tidy up: {e}")
        return
    b = job.get("built") or {}
    left = []
    held = False                         # something of EnvMap's may still hold the new VM's disks
    for label, side_, rec in ((OLD, src, b.get("giver")), (NEW, dst, b.get("taker"))):
        if not rec:
            continue
        try:
            vmmove.say(job, f"{label}: {coldside.helper(side_, rec).drop()}")
        except Exception as e:                                # noqa: BLE001
            left.append(f"{label} is still there")
            held = held or label == NEW
            vmmove.say(job, f"{label} could not be removed: {e}", "error")
    if held:
        left.append("the new VM is still there")
        vmmove.say(job, "the new VM was left: its helper still holds its disks", "error")
    else:
        try:
            if b.get("making") and getattr(dst, "road", "") == "shell":
                vmmove.say(job, dst.unmake(b["making"], b.get("vm") if b.get("vmx") else ""))
            elif b.get("vm"):
                if dst.exists():
                    dst.destroy()
                    vmmove.say(job, "the new VM deleted")
                else:
                    vmmove.say(job, "the new VM was already gone")
        except Exception as e:                                # noqa: BLE001
            left.append("the new VM is still there")
            vmmove.say(job, f"the new VM could not be taken away: {e}", "error")
    for side_, key, where in ((dst, "iso", "new"), (src, "src_iso", "old")):
        if not b.get(key):
            continue
        try:
            vmmove.say(job, side_.delete_iso(b[key]) or f"the helper's CD deleted from the {where} host")
        except Exception as e:                                # noqa: BLE001
            left.append(f"the helper's CD on the {where} host")
            vmmove.say(job, f"the helper's CD on the {where} host could not be deleted: {e}", "error")
    vmmove.phase(job, "failed" if left else "undone",
                 "nothing changed for the VM: it is powered off where it was"
                 + ("; left for you to remove: " + ", ".join(left) if left else ""))
    virt.forget(virtops.find_conn(job["dst"]["conn"]) or {})


def cancel(user, jid: str) -> dict:
    """Stop a powered-off move that is still copying. It is undone like any
    other way out: the VM was never changed."""
    job = vmmove.load(jid)
    if not job or job.get("mode") != "off":
        raise MoveError("unknown move")
    sc, dc = virtops.find_conn(job["src"]["conn"]), virtops.find_conn(job["dst"]["conn"])
    why = vmmove.may_move(user, sc or {}, dc or {}) if sc and dc else "a connection of this move was deleted"
    if why:
        raise MoveError(why)
    if job.get("state") not in ("starting", "preparing", "copying"):
        raise MoveError("this move is past the point where stopping it means anything")
    who = vmmove.job_by(user)
    vmmove.update(job, lambda c: c.update(cancel=who))
    vmmove.say(job, f"{who} asked to stop the move")
    return job


def again(jid: str) -> None:
    """After EnvMap restarted: the helpers went on meanwhile, so listen again."""
    job = vmmove.load(jid)
    try:
        if job.get("state") == "finishing":
            finish(job)
        else:
            watch(job)
    except Exception as e:                                     # noqa: BLE001
        job = vmmove.load(jid) or job
        vmmove.say(job, f"stopped: {e}", "error")
        after_failure(job, str(e))


def resume(job: dict) -> None:
    with vmmove._lock:
        if job["id"] in vmmove._running:
            return
        t = threading.Thread(target=_again, args=(job["id"],), daemon=True, name=f"move-{job['id']}")
        vmmove._running[job["id"]] = t
    t.start()


def _again(jid: str) -> None:
    try:
        again(jid)
    finally:
        with vmmove._lock:
            vmmove._running.pop(jid, None)
