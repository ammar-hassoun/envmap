"""Provision: a guided "new VM" flow on top of the Terraform engine.

WHAT THIS IS
    The Terraform page runs hand-written stacks. This is the wizard on top of it:
    pick an OS image, one or more destination Proxmox nodes, resources and a
    static network, and it GENERATES a Terraform stack (HCL + tfvars) which the
    same engine then runs — same runs, same apply-gate, same prod-confirm, same
    audit. Nothing here provisions directly; it writes the `.tf` that
    `terraform.start()` executes. A provisioned stack is an ordinary stack.

WHY A LIVE PROXMOX CLIENT (proxmox.py, below)
    The wizard shows real choices — which nodes exist, which datastores hold
    images vs disks, which bridges a node has, and whether the chosen OS image is
    already uploaded. A full `terraform plan` for each of those is slow; a
    read-only Proxmox API GET is instant. So this module carries a tiny read-only
    Proxmox client that reuses an existing stack's sealed credential (unsealed in
    process, never shown, never written to disk) to answer those questions.

THE OS CATALOG (no DHCP, no console — the whole point)
    Each OS knows how it installs on Proxmox and how it takes a STATIC network
    with no DHCP and no F3-at-the-console step:
      - AlmaLinux 10 / 8 → a cloud image (qcow2) + cloud-init: Proxmox sets the
        hostname, static IP, user and SSH key at first boot.
      - Talos       → a nocloud disk image + a machine-config carried on a config
        drive; the node self-configures its static network locally at boot, then
        the siderolabs/talos provider bootstraps and returns a kubeconfig.

THE SAFETY POSTURE IS THE ENGINE'S
    Creating from the wizard only writes a stack; nothing changes until someone
    runs it, and apply/destroy still need `allow_apply` on and (for prod) the
    stack name typed. The credential is never re-entered and never unsealed to
    the browser — a generated stack simply reuses the connection stack's sealed
    credential, copied ciphertext-to-ciphertext.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

import httpx

from . import db, secretbox, terraform
from .ansible import Refused, new_keypair

# ── caps / validation ──────────────────────────────────────────
NAME_OK = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")   # a hostname label
MAX_VMS = 32                       # one wizard run's VM count ceiling
HTTP_TIMEOUT = 12.0


# ── post-provision Ansible: the chosen playbook + the private key we baked ──
# A fresh VM gets a generated PUBLIC key planted in it (cloud-init / kickstart);
# the matching PRIVATE key is sealed here, keyed by the stack, so the run route
# can configure the VM the moment it is reachable. Kept OUT of spec_json (which
# the edit-in-wizard page reads back) so a private key never rides into a page.
def _pa_migrate(c) -> None:
    c.execute("""CREATE TABLE IF NOT EXISTS provision_ansible (
        sid TEXT PRIMARY KEY, pb_id TEXT, key_sealed TEXT, os_user TEXT, created TEXT)""")
    # additive: the ad-hoc run's id once it starts, so the stack page can reopen
    # the log and the record survives a restart
    cols = [r[1] for r in c.execute("PRAGMA table_info(provision_ansible)").fetchall()]
    if "run_id" not in cols:
        c.execute("ALTER TABLE provision_ansible ADD COLUMN run_id TEXT DEFAULT ''")


db.register(_pa_migrate)


def set_ansible(sid: str, pb_id: str, private_key: str, os_user: str) -> None:
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO provision_ansible "
                  "(sid, pb_id, key_sealed, os_user, created) VALUES (?,?,?,?,?)",
                  (sid, pb_id, secretbox.seal(private_key), os_user,
                   time.strftime("%Y-%m-%d %H:%M:%S")))


def ansible_for(sid: str) -> dict | None:
    """The stack's post-provision Ansible config with the private key UNSEALED —
    for the run route only, never a page."""
    rows = db.q("SELECT pb_id, key_sealed, os_user FROM provision_ansible WHERE sid=?", (sid,))
    if not rows:
        return None
    r = dict(rows[0])
    return {"pb_id": r["pb_id"], "os_user": r["os_user"],
            "private_key": secretbox.unseal(r["key_sealed"]) if r.get("key_sealed") else ""}


def set_ansible_run(sid: str, run_id: str) -> None:
    with db.tx() as c:
        c.execute("UPDATE provision_ansible SET run_id=? WHERE sid=?", (run_id, sid))


def ansible_run_id(sid: str) -> str:
    rows = db.q("SELECT run_id FROM provision_ansible WHERE sid=?", (sid,))
    return (rows[0]["run_id"] if rows and rows[0]["run_id"] else "")


# ── the post-provision playbook, run SERVER-SIDE so closing the wizard cannot
# abort it. A daemon per stack waits for the apply to finish and the VMs to
# answer on SSH, then starts the ad-hoc run; its live phase is readable so the
# wizard (if still open) and the stack page can show what is happening. #
_POST: dict = {}
_POST_LOCK = threading.Lock()


def post_ansible_status(sid: str) -> dict:
    """Where the background run is up to: phase ∈ waiting_apply | waiting_ssh |
    running | done | failed, plus run_id (once started) and host/error. Falls back
    to the persisted run_id so a finished run is still linkable after a restart."""
    with _POST_LOCK:
        st = dict(_POST.get(sid) or {})
    if not st:
        rid = ansible_run_id(sid)
        if rid:
            return {"phase": "running", "run_id": rid, "host": "", "error": ""}
    return st


def _post_set(sid: str, **kw) -> None:
    with _POST_LOCK:
        _POST.setdefault(sid, {}).update(kw)


def arm_post_ansible(sid: str, apply_run_id: str, who: str) -> bool:
    """Start (once) the background worker for a stack that has a playbook attached.
    Returns False when there is nothing to arm or it is already running."""
    cfg = ansible_for(sid)
    if not cfg or not cfg.get("private_key"):
        return False
    with _POST_LOCK:
        cur = _POST.get(sid)
        if cur and cur.get("phase") not in ("failed", "done"):
            return False                      # already in flight
        _POST[sid] = {"phase": "waiting_apply", "run_id": "", "host": "",
                      "error": "", "at": time.time()}
    threading.Thread(target=_post_ansible_worker,
                     args=(sid, apply_run_id, who, cfg), daemon=True).start()
    return True


def _post_ansible_worker(sid: str, apply_run_id: str, who: str, cfg: dict) -> None:
    from . import ansible
    try:
        # 1) wait for the apply run to finish; a failed apply means no VMs to
        #    configure. A manual retry passes no run id and skips straight to SSH.
        for _ in range(2400):                 # ceiling ~80 min at 2s
            if not apply_run_id:
                break
            r = terraform.run(apply_run_id)
            if r and r.get("done"):
                if r.get("status") != "ok":
                    _post_set(sid, phase="failed",
                              error=f"apply {r.get('status')} — playbook skipped")
                    return
                break
            time.sleep(2)
        # 2) the VM IPs from the stored spec
        spec = stored_spec(sid) or {}
        hosts = [{"name": n.get("hostname") or ip, "address": ip, "ssh_user": cfg["os_user"]}
                 for n in (spec.get("nodes") or [])
                 if (ip := (n.get("ip") or "").split("/")[0].strip())]
        if not hosts:
            _post_set(sid, phase="failed", error="this stack has no VM IPs to run against")
            return
        # 3) wait for every VM to answer on SSH (the install takes minutes)
        _post_set(sid, phase="waiting_ssh")
        deadline = time.time() + 40 * 60
        while time.time() < deadline:
            pending = [h["address"] for h in hosts if not vm_ssh_ready(h["address"])]
            if not pending:
                break
            _post_set(sid, host=pending[0])
            time.sleep(8)
        else:
            _post_set(sid, phase="failed",
                      error="the VM(s) never answered on SSH within 40 min")
            return
        # 4) start the ad-hoc run — its own daemon carries it to completion and it
        #    is followable/reopenable at /ansible/run/<id>.json
        _post_set(sid, phase="running")
        run_id = ansible.run_adhoc(
            cfg["pb_id"], spec.get("stack_name") or "provisioned", hosts,
            cfg["private_key"], who, True, cfg["os_user"],
            ansible.config()["allow_real"])
        set_ansible_run(sid, run_id)
        _post_set(sid, phase="running", run_id=run_id)
    except ansible.Refused as e:              # noqa: F841
        _post_set(sid, phase="failed", error=str(e))
    except Exception as e:                     # noqa: BLE001
        _post_set(sid, phase="failed", error=str(e)[:200])


def vm_ssh_ready(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    """Can we open a TCP connection to the VM's SSH port yet? A fresh ISO install
    is not reachable for minutes after apply returns; the run route polls this."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ══ the read-only Proxmox client ════════════════════════════════
class ProxmoxError(RuntimeError):
    """A Proxmox API call failed — surfaced to the wizard, never swallowed."""


class Proxmox:
    """A minimal, read-only Proxmox VE client. GETs only; it lists what the
    wizard needs to offer real choices. Auth is either an API token (a header)
    or username/password (a login ticket used as a cookie). It is built from a
    connection stack's unsealed credential and lives no longer than one call
    batch — the secret never leaves this process."""

    def __init__(self, endpoint: str, *, token: str = "", username: str = "",
                 password: str = "", insecure: bool = False):
        self.base = endpoint.rstrip("/")
        if not self.base.endswith("/api2/json"):
            self.base += "/api2/json"
        self.token, self.username, self.password = token, username, password
        verify: bool | ssl.SSLContext = not insecure
        headers = {}
        if token:
            headers["Authorization"] = f"PVEAPIToken={token}"
        self._c = httpx.Client(base_url=self.base, verify=verify,
                               timeout=HTTP_TIMEOUT, headers=headers)
        self._logged_in = bool(token)

    # -- lifecycle ------------------------------------------------
    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> "Proxmox":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- auth -----------------------------------------------------
    def _login(self) -> None:
        if self._logged_in:
            return
        if not (self.username and self.password):
            raise ProxmoxError("this connection has neither an API token nor a "
                               "username/password — cannot reach Proxmox")
        try:
            r = self._c.post("/access/ticket",
                             data={"username": self.username, "password": self.password})
            r.raise_for_status()
            d = r.json()["data"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise ProxmoxError(f"Proxmox login failed: {_httperr(e)}") from e
        if not d or not d.get("ticket"):
            raise ProxmoxError("Proxmox rejected the username/password")
        self._c.cookies.set("PVEAuthCookie", d["ticket"])
        # ticket (cookie) auth requires this header on every modifying call
        # (POST/PUT/DELETE) — token auth does not, which is why it was missing
        if d.get("CSRFPreventionToken"):
            self._c.headers["CSRFPreventionToken"] = d["CSRFPreventionToken"]
        self._logged_in = True

    def _get(self, path: str) -> list | dict:
        self._login()
        try:
            r = self._c.get(path)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"GET {path} failed: {_httperr(e)}") from e
        return (r.json() or {}).get("data")

    # -- reads the wizard uses ------------------------------------
    def version(self) -> str:
        d = self._get("/version") or {}
        return d.get("version", "") if isinstance(d, dict) else ""

    def nodes(self) -> list[dict]:
        out = []
        for n in (self._get("/nodes") or []):
            out.append({
                "node": n.get("node", ""),
                "online": (n.get("status") == "online"),
                "cpu": n.get("maxcpu") or 0,
                "mem_gb": round((n.get("maxmem") or 0) / 1024 ** 3, 1),
                "mem_used_gb": round((n.get("mem") or 0) / 1024 ** 3, 1),
            })
        return sorted(out, key=lambda x: x["node"])

    @staticmethod
    def _noderow(node, status, maxcpu, cpu, maxmem, mem, maxdisk, disk, uptime) -> dict:
        maxcpu, cpu = int(maxcpu or 0), float(cpu or 0)
        maxmem, mem = int(maxmem or 0), int(mem or 0)
        maxdisk, disk = int(maxdisk or 0), int(disk or 0)
        gb = lambda b: round(b / 1024 ** 3, 1)
        return {
            "node": node, "online": status == "online",
            "cpu_cores": maxcpu, "cpu_pct": round(cpu * 100, 1),
            "mem_gb": gb(maxmem), "mem_used_gb": gb(mem), "mem_free_gb": gb(maxmem - mem),
            "mem_pct": round(mem / maxmem * 100) if maxmem else 0,
            "disk_gb": gb(maxdisk), "disk_used_gb": gb(disk), "disk_free_gb": gb(maxdisk - disk),
            "disk_pct": round(disk / maxdisk * 100) if maxdisk else 0,
            "uptime": int(uptime or 0),
        }

    def nodes_detail(self) -> list[dict]:
        """Every node with its live CPU / RAM / root-disk usage. Works for a real
        cluster (one `/cluster/resources` call) AND a standalone host: if cluster
        resources come back empty it falls back to `/nodes` + each node's
        `/status`, so an un-clustered Proxmox lists its single host all the same."""
        res = self._get("/cluster/resources?type=node") or []
        if res:
            return sorted((self._noderow(
                r.get("node"), r.get("status"), r.get("maxcpu"), r.get("cpu"),
                r.get("maxmem"), r.get("mem"), r.get("maxdisk"), r.get("disk"),
                r.get("uptime")) for r in res), key=lambda x: x["node"])
        out = []
        for n in (self._get("/nodes") or []):
            node = n.get("node")
            try:
                st = self._get(f"/nodes/{node}/status") or {}
            except ProxmoxError:
                st = {}
            mem, root = st.get("memory") or {}, st.get("rootfs") or {}
            out.append(self._noderow(
                node, n.get("status"), (st.get("cpuinfo") or {}).get("cpus"),
                st.get("cpu"), mem.get("total"), mem.get("used"),
                root.get("total"), root.get("used"), st.get("uptime")))
        return sorted(out, key=lambda x: x["node"])

    def storages(self, node: str) -> list[dict]:
        out = []
        for s in (self._get(f"/nodes/{node}/storage") or []):
            out.append({
                "id": s.get("storage", ""),
                "type": s.get("type", ""),
                "content": (s.get("content") or "").split(","),
                "free_gb": round((s.get("avail") or 0) / 1024 ** 3, 1),
                "total_gb": round((s.get("total") or 0) / 1024 ** 3, 1),
                "active": bool(s.get("active", 1)),
            })
        return sorted(out, key=lambda x: x["id"])

    def storage_status(self, node: str, storage: str) -> dict:
        """Capacity of one datastore on a node — total / used / free. Feeds the
        'remaining disk space' on the Images tab."""
        d = self._get(f"/nodes/{node}/storage/{storage}/status") or {}
        total, used, avail = int(d.get("total") or 0), int(d.get("used") or 0), int(d.get("avail") or 0)
        gb = lambda b: round(b / 1024 ** 3, 1)
        return {"total_gb": gb(total), "used_gb": gb(used), "free_gb": gb(avail),
                "used_pct": round(used / total * 100) if total else 0}

    def bridges(self, node: str) -> list[dict]:
        out = []
        for b in (self._get(f"/nodes/{node}/network") or []):
            if b.get("type") not in ("bridge", "OVSBridge"):
                continue
            out.append({
                "iface": b.get("iface", ""),
                "active": bool(b.get("active", 0)),
                "cidr": b.get("cidr", "") or "",
                "comments": (b.get("comments") or "").strip(),
            })
        return sorted(out, key=lambda x: x["iface"])

    def content(self, node: str, storage: str) -> list[dict]:
        """Files in a datastore — ISOs, imported disk images, templates. Feeds the
        wizard's image picker and the 'is the OS image already there?' check.

        The default content listing does NOT reliably include the `import` content
        type (Proxmox surfaces it under its own filter), so it is requested
        explicitly and merged — otherwise a disk image dropped into import content
        is invisible to the portal even while the GUI's Import tab lists it."""
        by_volid: dict[str, dict] = {}

        def _add(items) -> None:
            for f in (items or []):
                volid = f.get("volid", "")                # e.g. local:iso/foo.iso
                if not volid:
                    continue
                by_volid[volid] = {
                    "volid": volid,
                    "name": volid.split("/", 1)[1] if "/" in volid else volid,
                    "content": f.get("content", ""),
                    "size_gb": round((f.get("size") or 0) / 1024 ** 3, 2),
                }

        _add(self._get(f"/nodes/{node}/storage/{storage}/content"))
        try:                                              # import content, asked for by name
            _add(self._get(f"/nodes/{node}/storage/{storage}/content?content=import"))
        except ProxmoxError:
            pass                                          # older storage/version without it
        return list(by_volid.values())

    def cluster_vms(self) -> list[dict]:
        """Every VM/CT the cluster knows, in ONE call — `/cluster/resources` is a
        single request per Proxmox (not one per node), so the inventory page stays
        fast even on a busy cluster."""
        out = []
        for r in (self._get("/cluster/resources?type=vm") or []):
            tags = (r.get("tags") or "").replace(",", ";")
            out.append({
                "vmid": r.get("vmid"),
                "name": r.get("name") or "",
                "node": r.get("node") or "",
                "kind": r.get("type") or "qemu",          # qemu | lxc
                "status": r.get("status") or "",           # running | stopped
                "template": bool(r.get("template")),
                "cores": int(r.get("maxcpu") or 0),
                "mem_gb": round((r.get("maxmem") or 0) / 1024 ** 3, 1),
                "disk_gb": round((r.get("maxdisk") or 0) / 1024 ** 3, 1),
                "uptime": int(r.get("uptime") or 0),
                "tags": [t for t in tags.split(";") if t.strip()],
                "pool": r.get("pool") or "",
            })
        return out

    def vm_action(self, node: str, vmid: int, action: str) -> str:
        """Change a VM's power state: start / shutdown (ACPI) / stop (pull the
        plug) / reboot. Returns the Proxmox task id (a UPID)."""
        self._login()
        try:
            r = self._c.post(f"/nodes/{node}/qemu/{vmid}/status/{action}")
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"{action} on VM {vmid} failed: {_httperr(e)}") from e
        return (r.json() or {}).get("data", "")

    def destroy_vm(self, node: str, vmid: int) -> str:
        """Delete a VM and its disks. Proxmox refuses a RUNNING VM (the caller
        disables the button until it is stopped). `purge` also removes it from
        backup/replication jobs; `destroy-unreferenced-disks` sweeps stray disks.
        Returns the task id (a UPID)."""
        self._login()
        try:
            r = self._c.delete(f"/nodes/{node}/qemu/{vmid}",
                               params={"purge": 1, "destroy-unreferenced-disks": 1})
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"delete VM {vmid} failed: {_httperr(e)}") from e
        return (r.json() or {}).get("data", "")

    def vm_config(self, node: str, vmid: int) -> dict:
        """A VM's DEFINED hardware — cores, memory, disks, NICs, boot, os, tags.
        This is the pending/desired config (what a boot applies), which is exactly
        what a hardware editor shows and changes."""
        return self._get(f"/nodes/{node}/qemu/{vmid}/config") or {}

    def vm_status(self, node: str, vmid: int) -> dict:
        """Live status — running/stopped, uptime, current cpu/mem use."""
        return self._get(f"/nodes/{node}/qemu/{vmid}/status/current") or {}

    def set_vm_config(self, node: str, vmid: int, params: dict) -> None:
        """Write a VM's hardware config. Proxmox applies most fields at once;
        cores/memory land as PENDING on a RUNNING VM without hotplug and take
        effect on the next boot (no error either way). Writes only `params`."""
        self._login()
        try:
            r = self._c.post(f"/nodes/{node}/qemu/{vmid}/config", data=params)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"update VM {vmid} failed: {_httperr(e)}") from e

    def vncproxy(self, node: str, vmid: int) -> dict:
        """Open a VNC proxy session for a VM in websocket mode. Returns the
        one-time ticket (the RFB password) and the port the vncwebsocket uses."""
        self._login()
        try:
            r = self._c.post(f"/nodes/{node}/qemu/{vmid}/vncproxy",
                             data={"websocket": 1})
            r.raise_for_status()
            d = (r.json() or {}).get("data") or {}
        except (httpx.HTTPError, ValueError) as e:
            raise ProxmoxError(f"console for VM {vmid} failed: {_httperr(e)}") from e
        if not d.get("ticket") or not d.get("port"):
            raise ProxmoxError("Proxmox did not return a console ticket")
        return {"ticket": d["ticket"], "port": d["port"], "cert": d.get("cert", "")}

    def node_guests(self, node: str) -> list[dict]:
        """The VMs and containers on ONE node — for the expanded host view. Uses
        the per-node endpoints, so it works on a standalone host too."""
        out = []
        for kind, path in (("qemu", f"/nodes/{node}/qemu"), ("lxc", f"/nodes/{node}/lxc")):
            try:
                for g in (self._get(path) or []):
                    out.append({
                        "vmid": g.get("vmid"), "name": g.get("name") or "",
                        "status": g.get("status") or "", "kind": kind,
                        "cores": int(g.get("cpus") or 0),
                        "mem_gb": round((g.get("maxmem") or 0) / 1024 ** 3, 1),
                        "disk_gb": round((g.get("maxdisk") or 0) / 1024 ** 3, 1),
                    })
            except ProxmoxError:
                pass
        return sorted(out, key=lambda v: v["vmid"] or 0)

    def upload(self, node: str, storage: str, name: str, path: str,
               content: str = "iso", on_progress=None) -> str:
        """Push a local file onto a node's datastore over 8006 — the same endpoint
        the UI 'Upload' button uses. `content` is the Proxmox content type: `iso`
        for an installer/staged image, `import` for a file a VM disk will
        `import_from` (a disk import source must be import/images content, never
        iso). Proxmox's importer runs qemu-img at import time and detects the real
        qcow2/raw format, so the bytes — not the extension — decide the format.

        `on_progress(sent, total)` is called as the body streams out, so a caller
        can show a live figure. A big image is legitimately slow, so there is no
        total cap — but a single socket write that blocks past the write timeout
        means the far side stopped reading (a stalled VPN), which becomes a clean
        error in ~2 min instead of an endless hang."""
        self._login()
        try:
            total = os.path.getsize(path)
        except OSError:
            total = 0
        timeout = httpx.Timeout(120.0, connect=15.0)
        try:
            with open(path, "rb") as fh:
                src = _UploadReader(fh, total, on_progress) if on_progress else fh
                r = self._c.post(
                    f"/nodes/{node}/storage/{storage}/upload",
                    data={"content": content},
                    files={"filename": (name, src, "application/octet-stream")},
                    timeout=timeout)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"upload to {storage} on {node} failed: {_httperr(e)}") from e
        except OSError as e:
            raise ProxmoxError(f"could not read {path}: {e}") from e
        return (r.json() or {}).get("data", "")

    def delete_content(self, node: str, storage: str, volid: str) -> None:
        """Remove a datastore volume (used to clean up the staging probe)."""
        from urllib.parse import quote
        self._login()
        try:
            r = self._c.delete(
                f"/nodes/{node}/storage/{storage}/content/{quote(volid, safe='')}")
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise ProxmoxError(f"delete {volid} failed: {_httperr(e)}") from e


class _UploadReader:
    """Wraps a binary file so an upload can report bytes-sent. httpx reads it in
    chunks to stream the multipart body; each read advances the counter and calls
    back. seek/tell proxy through so httpx can still size the body — and a seek
    back to the start (which httpx does after sizing) resets the counter, so the
    figure a caller sees starts at zero when the real transfer begins."""
    def __init__(self, fh, total, cb):
        self._fh, self._total, self._cb, self._sent = fh, total, cb, 0

    def read(self, size=-1):
        chunk = self._fh.read(size)
        if chunk:
            self._sent += len(chunk)
            try:
                self._cb(self._sent, self._total)
            except Exception:                     # progress must never break the upload
                pass
        return chunk

    def seek(self, offset, whence=0):
        if offset == 0 and whence == 0:
            self._sent = 0
        return self._fh.seek(offset, whence)

    def tell(self):
        return self._fh.tell()

    def __iter__(self):
        return iter(self._fh)


def _httperr(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (401, 403):
            return f"{code} — the credential was rejected (check the token/password and its permissions)"
        return f"HTTP {code}"
    if isinstance(e, httpx.ConnectError):
        return "could not connect (endpoint/firewall?)"
    if isinstance(e, httpx.TimeoutException):
        return "timed out"
    return f"{type(e).__name__}: {e}"


# ══ connections (an existing stack's Proxmox credential) ═════════
def connections() -> list[dict]:
    """Terraform stacks that carry a Proxmox credential — the wizard borrows one
    as the 'where do I connect' handle, so nothing is re-entered."""
    out = []
    for s in terraform.stacks():
        if s.get("provider", "").startswith("proxmox") and s.get("has_creds"):
            out.append({"id": s["id"], "name": s["name"],
                        "project_name": s.get("project_name", ""),
                        "region_name": s.get("region_name", "")})
    return out


def _creds_of(connection_sid: str) -> dict:
    """Unseal a connection stack's credential into a dict of KEY→value. Stays in
    this process; never returned to a page."""
    raw = terraform._stack_raw(connection_sid) or {}
    sealed = raw.get("creds_sealed") or ""
    if not sealed:
        raise Refused("that connection has no stored Proxmox credential")
    out = {}
    for line in (secretbox.unseal(sealed) or "").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def client_for(connection_sid: str) -> Proxmox:
    """A live Proxmox client from a connection stack's sealed credential."""
    c = _creds_of(connection_sid)
    endpoint = c.get("PROXMOX_VE_ENDPOINT") or c.get("PM_API_URL") or ""
    if not endpoint:
        raise Refused("that connection has no PROXMOX_VE_ENDPOINT")
    insecure = (c.get("PROXMOX_VE_INSECURE", "") or "").lower() in ("1", "true", "yes")
    return Proxmox(endpoint,
                   token=c.get("PROXMOX_VE_API_TOKEN", ""),
                   username=c.get("PROXMOX_VE_USERNAME", ""),
                   password=c.get("PROXMOX_VE_PASSWORD", ""),
                   insecure=insecure)


def _proxmox_connections() -> list[dict]:
    """Every stack that is a Proxmox connection (has a credential) — the source
    for both the wizard's connection list and the inventory's cluster loop."""
    return [s for s in terraform.stacks()
            if s.get("provider", "").startswith("proxmox") and s.get("has_creds")]


# ── the VM inventory (EC2-style: every VM the clusters report) ──
# A cluster does not carry the portal's env per VM, so env is derived from a VM's
# Proxmox tag when one looks like an environment, else it falls back to the
# connection stack's env. Tags are shown verbatim too (like EC2 tags).
_ENV_TAGS = {
    "prod": "prod", "production": "prod",
    "preprod": "preprod", "pre-prod": "preprod", "pre_prod": "preprod",
    "stage": "staging", "staging": "staging",
    "uat": "uat", "qa": "qa",
    "dev": "dev", "development": "dev",
    "test": "test", "testing": "test", "sandbox": "sandbox",
}


def _env_from(tags: list[str], fallback: str) -> str:
    for t in tags:
        got = _ENV_TAGS.get(t.strip().lower())
        if got:
            return got
    return (fallback or "").strip().lower()


def _managed_names() -> dict[str, dict]:
    """VM names a portal stack declares, so the inventory can flag which VMs the
    portal manages (like "launched by this template"). A cheap scan of stored HCL
    for `name = "…"`; a heuristic, but the generated VM HCL always uses that form."""
    out: dict[str, dict] = {}
    for s in terraform.stacks():
        raw = terraform._stack_raw(s["id"]) or {}
        for m in re.finditer(r'name\s*=\s*"([^"]+)"', raw.get("body") or ""):
            out.setdefault(m.group(1), {"stack_id": s["id"], "stack_name": s["name"]})
    return out


def _is_generated(s: dict) -> bool:
    """A wizard-made VM stack, not a hand-made connection: it either carries a
    saved spec, or was stamped with the `Provisioned:` note by create() (the note
    covers stacks made before spec_json existed)."""
    return bool(s.get("has_spec")) or (s.get("notes") or "").startswith("Provisioned:")


def _dedupe_by_endpoint(conns: list[dict]) -> list[dict]:
    """Collapse connection stacks that point at the SAME Proxmox to one — every
    wizard-generated VM stack copies the connection's credential, so a cluster
    would otherwise be queried (and its VMs listed) once per stack. The
    representative is a real connection over a generated VM stack, so the cluster
    shows a meaningful name, not a VM's."""
    by_ep: dict[str, dict] = {}
    for s in conns:
        try:
            cd = _creds_of(s["id"])
            ep = (cd.get("PROXMOX_VE_ENDPOINT") or cd.get("PM_API_URL") or "").strip().rstrip("/")
        except (Refused, ProxmoxError):
            ep = ""
        key = ep or s["id"]
        cur = by_ep.get(key)
        if cur is None or (_is_generated(cur) and not _is_generated(s)):
            by_ep[key] = s
    return list(by_ep.values())


def clusters() -> list[dict]:
    """Distinct Proxmox clusters (deduped by endpoint) — for pickers that mean
    'which cluster' rather than 'which credential stack'. Carries each cluster's
    region so the Images tab can honour the region filter."""
    return [{"id": s["id"], "name": s["name"], "rgid": s.get("rgn_id", ""),
             "region": s.get("region_name", "") or ""}
            for s in _dedupe_by_endpoint(_proxmox_connections())]


# ── add a Proxmox host / cluster as a connection ───────────────
def _norm_endpoint(ep: str) -> str:
    """Normalise a Proxmox endpoint to the base URL both bpg and the read client
    want: an https scheme, a port (8006 by default), no trailing slash and no
    `/api2/json` (the clients add that themselves)."""
    from urllib.parse import urlparse
    ep = (ep or "").strip()
    if not ep:
        return ""
    if not ep.startswith(("http://", "https://")):
        ep = "https://" + ep
    ep = ep.rstrip("/")
    if ep.endswith("/api2/json"):
        ep = ep[: -len("/api2/json")]
    p = urlparse(ep)
    host = p.hostname or ""
    if not host:
        return ""
    port = p.port or 8006
    return f"{p.scheme}://{host}:{port}"


def _client_from_spec(spec: dict) -> Proxmox:
    endpoint = _norm_endpoint(spec.get("endpoint", ""))
    if not endpoint:
        raise Refused("the Proxmox endpoint is required (e.g. https://10.0.0.5:8006)")
    token = (spec.get("api_token") or "").strip()
    user = (spec.get("username") or "").strip()
    pw = spec.get("password") or ""
    if not token and not (user and pw):
        raise Refused("provide an API token, or a username and password")
    return Proxmox(endpoint, token=token, username=user, password=pw,
                   insecure=bool(spec.get("insecure")))


def test_connection(spec: dict) -> dict:
    """Try the entered credentials against Proxmox WITHOUT saving them — the
    'Test' button on the add-host wizard. Returns the version + node list."""
    with _client_from_spec(spec) as px:
        version = px.version()
        nodes = px.nodes_detail()
    return {"version": version, "nodes": len(nodes),
            "node_names": [n["node"] for n in nodes],
            "cluster": len(nodes) > 1}


def add_host(spec: dict, who: str) -> str:
    """Register a Proxmox host/cluster as a connection — a tiny stack that holds
    only the sealed credential and a `provider "proxmox" {}` block, exactly like a
    hand-made connection. Every other tab then sees the new cluster. Credentials
    are sealed by save_stack; they never come back to a page."""
    name = (spec.get("name") or "").strip()
    if not name:
        raise Refused("give the host a name")
    endpoint = _norm_endpoint(spec.get("endpoint", ""))
    if not endpoint:
        raise Refused("the Proxmox endpoint is required")
    token = (spec.get("api_token") or "").strip()
    user = (spec.get("username") or "").strip()
    pw = spec.get("password") or ""
    if not token and not (user and pw):
        raise Refused("provide an API token, or a username and password")
    lines = [f"PROXMOX_VE_ENDPOINT={endpoint}",
             f"PROXMOX_VE_INSECURE={'true' if spec.get('insecure') else 'false'}"]
    if token:
        lines.append(f"PROXMOX_VE_API_TOKEN={token}")
    if user:
        lines.append(f"PROXMOX_VE_USERNAME={user}")
    if pw:
        lines.append(f"PROXMOX_VE_PASSWORD={pw}")
    fields = {
        "name": name, "provider": "proxmox", "body": 'provider "proxmox" {}',
        "creds": "\n".join(lines), "env": (spec.get("env") or "").strip(),
        "pid": (spec.get("pid") or "").strip(), "rgid": (spec.get("rgid") or "").strip(),
        "notes": (spec.get("notes") or "").strip() or "Proxmox connection (added from Hosts)",
    }
    return terraform.save_stack("", fields, who)


def add_hosts(specs: list, who: str) -> list[dict]:
    """Save SEVERAL standalone Proxmox hosts in one submission. A spec carrying a
    `sid` EDITS that connection (used when the edit modal is in standalone mode —
    the first row is the connection being edited); a spec without one ADDS a new
    connection. They typically share the caller-set region + env. Partial success
    is fine: a rejected row is reported, the rest still land."""
    out = []
    for sp in specs or []:
        name = (sp.get("name") or "").strip()
        sid = (sp.get("sid") or "").strip()
        try:
            if sid:
                edit_host(sid, sp, who)
                out.append({"name": name, "ok": True, "sid": sid, "edited": True})
            else:
                out.append({"name": name, "ok": True, "sid": add_host(sp, who)})
        except Refused as e:
            out.append({"name": name or "(unnamed)", "ok": False, "error": str(e)})
    return out


def inventory(connection: str = "") -> dict:
    """Every VM across every Proxmox connection (or just one), annotated with the
    portal's project / region / env and whether a stack manages it. One
    `/cluster/resources` call per connection; a connection that cannot be reached
    is reported in `errors`, never fatal — the rest of the fleet still lists."""
    managed = _managed_names()
    conns = _proxmox_connections()
    if connection:
        conns = [s for s in conns if s["id"] == connection]
    conns = _dedupe_by_endpoint(conns)     # many stacks may point at one cluster
    vms: list[dict] = []
    errors: list[dict] = []
    for s in conns:
        try:
            with client_for(s["id"]) as px:
                found = px.cluster_vms()
        except (Refused, ProxmoxError) as e:
            errors.append({"connection": s["name"], "sid": s["id"], "error": str(e)})
            continue
        from . import pam
        for v in found:
            env = _env_from(v["tags"], s.get("env", ""))
            v.update({
                "connection": s["name"], "connection_id": s["id"],
                "project": s.get("project_name", "") or "—",
                "pid": s.get("proj_id", ""),
                "region": s.get("region_name", "") or "—",
                "rgid": s.get("rgn_id", ""),
                "env": env, "env_label": pam.env_label(env),
                "env_tone": pam.env_tone(env), "is_prod": env == "prod",
                "managed_by": managed.get(v["name"]),
            })
            vms.append(v)
    vms.sort(key=lambda v: (v["connection"], str(v["node"]),
                            v["vmid"] or 0))
    return {"vms": vms, "errors": errors, "counts": _inv_counts(vms),
            "connections": [{"id": s["id"], "name": s["name"]} for s in conns]}


def hosts(connection: str = "") -> dict:
    """Every Proxmox NODE across every connection, with live CPU / RAM / disk and
    the VMs it runs — the Hosts overview, and the source the wizard uses to show
    what each node has free. Works for clusters and standalone hosts alike; a
    connection that cannot be reached is reported, not fatal."""
    conns = _dedupe_by_endpoint(_proxmox_connections())
    if connection:
        conns = [s for s in conns if s["id"] == connection]
    out, errors = [], []
    from . import pam
    for s in conns:
        try:
            with client_for(s["id"]) as px:
                nodes = px.nodes_detail()
                vms = px.cluster_vms()
        except (Refused, ProxmoxError) as e:
            # carry the sid so the UI can offer edit/remove on a connection that
            # never authenticated (a 401 host has no nodes, so it appears ONLY
            # here — without the sid there was no way to fix or remove it).
            errors.append({"connection": s["name"], "sid": s["id"], "error": str(e)})
            continue
        per_node: dict[str, int] = {}
        for v in vms:
            per_node[v["node"]] = per_node.get(v["node"], 0) + 1
        env = (s.get("env", "") or "")
        for n in nodes:
            n.update({
                "connection": s["name"], "connection_id": s["id"],
                "project": s.get("project_name", "") or "—", "pid": s.get("proj_id", ""),
                "region": s.get("region_name", "") or "—", "rgid": s.get("rgn_id", ""),
                "env": env, "env_label": pam.env_label(env), "env_tone": pam.env_tone(env),
                "vms": per_node.get(n["node"], 0),
                "cluster": s["name"], "is_cluster": len(nodes) > 1,
            })
            out.append(n)
    out.sort(key=lambda n: (n["connection"], n["node"]))
    return {"hosts": out, "errors": errors, "counts": _host_counts(out),
            "connections": [{"id": s["id"], "name": s["name"]} for s in conns]}


def host_detail(connection: str, node: str) -> dict:
    """One node's guests and ALL its datastores (with usage) — loaded when a host
    is expanded on the Hosts tab."""
    with client_for(connection) as px:
        vms = px.node_guests(node)
        stores = []
        for s in px.storages(node):
            total, free = s.get("total_gb", 0), s.get("free_gb", 0)
            s["used_gb"] = round(max(0.0, total - free), 1)
            s["used_pct"] = round((total - free) / total * 100) if total else 0
            stores.append(s)
    return {"node": node, "vms": vms, "storages": stores}


def remove_connection(sid: str) -> bool:
    """Remove a Proxmox connection (a whole cluster/host) FROM THE PORTAL — the
    connection stack is deleted; the Proxmox itself is never touched. Provisioned
    VM stacks keep their own copied credential and still run."""
    raw = terraform._stack_raw(sid)
    if not raw:
        raise Refused("that connection is already gone")
    if not (raw.get("provider", "") or "").startswith("proxmox"):
        raise Refused("that is not a Proxmox connection")
    return terraform.delete_stack(sid)


def host_get(sid: str) -> dict:
    """The non-secret fields of a Proxmox connection, to PRE-FILL the edit form.
    The credential itself is never returned — only which KIND of auth it uses, so
    the form can show the right fields; the token/password stay sealed."""
    raw = terraform._stack_raw(sid)
    if not raw or not (raw.get("provider", "") or "").startswith("proxmox"):
        raise Refused("that is not a Proxmox connection")
    try:
        c = _creds_of(sid)
    except Refused:
        c = {}
    return {
        "sid": sid, "name": raw.get("name", ""),
        "endpoint": c.get("PROXMOX_VE_ENDPOINT", ""),
        "insecure": (c.get("PROXMOX_VE_INSECURE", "") or "").lower() in ("1", "true", "yes"),
        "auth": "token" if c.get("PROXMOX_VE_API_TOKEN") else "pass",
        "username": c.get("PROXMOX_VE_USERNAME", ""),   # an identifier, not the secret
        "has_cred": bool(c.get("PROXMOX_VE_API_TOKEN") or c.get("PROXMOX_VE_PASSWORD")),
        "env": raw.get("env", ""), "pid": raw.get("proj_id", ""), "rgid": raw.get("rgn_id", ""),
    }


def edit_host(sid: str, spec: dict, who: str) -> str:
    """Update a Proxmox connection's endpoint / placement / credential. The
    credential blob carries the endpoint too, so it is always rebuilt — but the
    token/password are only replaced when the form supplies a new one; left blank,
    the stored credential is kept (you cannot see it to retype it). The endpoint
    and insecure flag can still be changed on their own."""
    raw = terraform._stack_raw(sid)
    if not raw or not (raw.get("provider", "") or "").startswith("proxmox"):
        raise Refused("that is not a Proxmox connection")
    try:
        cur = _creds_of(sid)
    except Refused:
        cur = {}
    name = (spec.get("name") or "").strip() or raw.get("name", "")
    endpoint = _norm_endpoint(spec.get("endpoint", "")) or cur.get("PROXMOX_VE_ENDPOINT", "")
    if not endpoint:
        raise Refused("the Proxmox endpoint is required")
    token = (spec.get("api_token") or "").strip()
    user = (spec.get("username") or "").strip()
    pw = spec.get("password") or ""
    if not (token or (user and pw)):        # no new credential — keep the stored one
        token = cur.get("PROXMOX_VE_API_TOKEN", "")
        user = cur.get("PROXMOX_VE_USERNAME", "")
        pw = cur.get("PROXMOX_VE_PASSWORD", "")
    if not token and not (user and pw):
        raise Refused("provide an API token, or a username and password")
    lines = [f"PROXMOX_VE_ENDPOINT={endpoint}",
             f"PROXMOX_VE_INSECURE={'true' if spec.get('insecure') else 'false'}"]
    if token:
        lines.append(f"PROXMOX_VE_API_TOKEN={token}")
    if user:
        lines.append(f"PROXMOX_VE_USERNAME={user}")
    if pw:
        lines.append(f"PROXMOX_VE_PASSWORD={pw}")
    fields = {
        "name": name, "provider": "proxmox",
        "body": raw.get("body") or 'provider "proxmox" {}',
        "creds": "\n".join(lines), "env": (spec.get("env") or raw.get("env") or "").strip(),
        "pid": (spec.get("pid") or raw.get("proj_id") or "").strip(),
        "rgid": (spec.get("rgid") or raw.get("rgn_id") or "").strip(),
        "notes": raw.get("notes") or "Proxmox connection",
    }
    return terraform.save_stack(sid, fields, who)


def _host_counts(hs: list[dict]) -> dict:
    online = [h for h in hs if h["online"]]
    return {
        "nodes": len(hs), "online": len(online),
        "vcpu": sum(h["cpu_cores"] for h in hs),
        "mem_gb": round(sum(h["mem_gb"] for h in hs)),
        "mem_free_gb": round(sum(h["mem_free_gb"] for h in online)),
        "disk_free_gb": round(sum(h["disk_free_gb"] for h in online)),
        "vms": sum(h["vms"] for h in hs),
    }


def _inv_counts(vms: list[dict]) -> dict:
    running = sum(1 for v in vms if v["status"] == "running")
    return {
        "total": len(vms),
        "running": running,
        "stopped": sum(1 for v in vms if v["status"] == "stopped"),
        "templates": sum(1 for v in vms if v["template"]),
        "managed": sum(1 for v in vms if v["managed_by"]),
        "unmanaged": sum(1 for v in vms if not v["managed_by"] and not v["template"]),
    }


# ── VM power actions ───────────────────────────────────────────
VM_ACTIONS = {"start", "shutdown", "reboot", "stop"}


def vm_action(connection: str, node: str, vmid, action: str) -> str:
    """Start / shutdown / reboot / stop, or DELETE, one VM on its cluster. All
    disruptive — the route gates it on the escalating permission + the apply switch,
    confirms it in the UI, and audits it. `delete` needs the VM already stopped
    (Proxmox refuses a running one; the UI disables the button until then). Returns
    the Proxmox task id."""
    if action != "delete" and action not in VM_ACTIONS:
        raise Refused(f"unknown VM action {action!r}")
    try:
        vmid = int(vmid)
    except (TypeError, ValueError):
        raise Refused("a VM id is required")
    with client_for(connection) as px:
        return px.destroy_vm(node, vmid) if action == "delete" else px.vm_action(node, vmid, action)


# ── VM hardware detail + edit ──────────────────────────────────
_DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide|nvme)\d+$")
_NET_KEY = re.compile(r"^net\d+$")
# a VM name is a hostname label; a tag is Proxmox's own charset (lowercased)
_VM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_TAG_STRIP = re.compile(r"[^a-z0-9_.+-]")


def _size_gb(spec: str) -> float:
    """GB from a Proxmox disk spec's `size=` token (40G / 512M / 1T / 20480)."""
    m = re.search(r"(?:^|,)size=([0-9.]+)([KMGT]?)", spec)
    if not m:
        return 0.0
    n = float(m.group(1))
    mult = {"K": 1 / 1024 ** 2, "M": 1 / 1024, "G": 1, "T": 1024}.get(m.group(2) or "G", 1)
    return round(n * mult, 1)


def _shape_vm(node: str, vmid: int, cfg: dict, st: dict) -> dict:
    """Proxmox's flat qemu config + live status → a normalized VM detail dict."""
    def opts(s: str) -> dict:                       # "a=b,c=d" → {"a":"b","c":"d"}
        return dict(p.split("=", 1) for p in str(s).split(",") if "=" in p)
    disks, nics = [], []
    for k, raw in cfg.items():
        val = str(raw)
        if _DISK_KEY.match(k) and "media=cdrom" not in val:
            disks.append({"id": k, "storage": val.split(":", 1)[0].split(",")[0],
                          "size_gb": _size_gb(val)})
        elif _NET_KEY.match(k):
            model = val.split("=", 1)[0]
            o = opts(val)
            nics.append({"id": k, "model": model, "mac": o.get(model, ""),
                         "bridge": o.get("bridge", ""), "vlan": o.get("tag", ""),
                         "firewall": o.get("firewall", "0") == "1"})
    disks.sort(key=lambda d: d["id"])
    nics.sort(key=lambda n: n["id"])
    agent = str(cfg.get("agent") or "")
    cores = int(cfg.get("cores") or 1)
    sockets = int(cfg.get("sockets") or 1)
    balloon = cfg.get("balloon")
    return {
        "vmid": vmid, "node": node,
        "name": cfg.get("name") or st.get("name") or "",
        "status": st.get("status") or "", "kind": "qemu",
        "uptime": int(st.get("uptime") or 0),
        "cpu_pct": round(float(st.get("cpu") or 0) * 100, 1),
        "mem_used_gb": round(int(st.get("mem") or 0) / 1024 ** 3, 2),
        "mem_max_gb": round(int(st.get("maxmem") or 0) / 1024 ** 3, 2),
        "cores": cores, "sockets": sockets, "vcpus": cores * sockets,
        "cpu_type": cfg.get("cpu") or "kvm64",
        "memory_mb": int(cfg.get("memory") or 0),
        "balloon_mb": int(balloon) if str(balloon or "").isdigit() else None,
        "ostype": cfg.get("ostype") or "",
        "agent_on": agent.startswith("1") or "enabled=1" in agent,
        "boot": cfg.get("boot") or "", "onboot": str(cfg.get("onboot") or "0") == "1",
        "description": cfg.get("description") or "",
        "tags": [t for t in re.split(r"[;,]", str(cfg.get("tags") or "")) if t.strip()],
        "disks": disks, "nics": nics,
    }


def vm_detail(connection: str, node: str, vmid) -> dict:
    """A VM's full hardware config + live status, read live from Proxmox. Read-only."""
    vmid = int(vmid)
    with client_for(connection) as px:
        cfg = px.vm_config(node, vmid)
        st = px.vm_status(node, vmid)
    return _shape_vm(node, vmid, cfg, st)


def _as_int(v, what: str, lo: int, hi: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise Refused(f"{what} must be a whole number")
    if not (lo <= n <= hi):
        raise Refused(f"{what} must be between {lo} and {hi}")
    return n


# what a hardware edit may touch — CPU/RAM/identity. Disks and NICs stay read-only
# here (resizing a disk is a separate, irreversible operation).
def vm_edit(connection: str, node: str, vmid, changes: dict) -> dict:
    """Validate then apply a VM hardware/identity change. Disruptive — the route
    gates it exactly like a power action (escalating permission + apply switch +
    audit). Returns the fields actually written."""
    vmid = int(vmid)
    params: dict = {}
    if "cores" in changes:
        params["cores"] = _as_int(changes["cores"], "vCPU cores", 1, 512)
    if "sockets" in changes:
        params["sockets"] = _as_int(changes["sockets"], "CPU sockets", 1, 8)
    if "memory_mb" in changes:
        params["memory"] = _as_int(changes["memory_mb"], "memory (MB)", 16, 4 * 1024 * 1024)
    if "name" in changes:
        name = str(changes["name"] or "").strip()
        if name and not _VM_NAME.match(name):
            raise Refused("a VM name is letters, digits, . - _ up to 63 characters")
        if name:
            params["name"] = name
    if "description" in changes:
        params["description"] = str(changes["description"] or "")[:8000]
    if "tags" in changes:
        tags = changes["tags"]
        if isinstance(tags, str):
            tags = re.split(r"[;,\s]+", tags)
        clean = [_TAG_STRIP.sub("", str(t).lower().strip()) for t in (tags or [])]
        params["tags"] = ";".join(t for t in clean if t)
    if not params:
        raise Refused("no editable field was provided")
    with client_for(connection) as px:
        px.set_vm_config(node, vmid, params)
    return {"changed": sorted(params)}


# ── VM console (noVNC over a relayed Proxmox vncwebsocket) ──────
# The browser can neither reach Proxmox :8006 nor hold the sealed credential, so
# the portal relays: it calls vncproxy server-side, then pipes the RFB stream from
# Proxmox's vncwebsocket to a vendored noVNC client. A short-lived session id hands
# the browser only the per-VNC ticket (seconds-long, not the account credential).
_CONSOLE: dict = {}
_CONSOLE_LOCK = threading.Lock()
_CONSOLE_TTL = 120


def console_open(connection: str, node: str, vmid) -> dict:
    """Start a console session: vncproxy (server-side, sealed credential) and stash
    the ticket/port under a one-time session id the browser opens the relay with."""
    vmid = int(vmid)
    with client_for(connection) as px:
        d = px.vncproxy(node, vmid)
    sess = uuid.uuid4().hex
    now = time.time()
    with _CONSOLE_LOCK:
        for k in [k for k, v in _CONSOLE.items() if now - v["at"] > _CONSOLE_TTL]:
            _CONSOLE.pop(k, None)                       # prune sessions never used
        _CONSOLE[sess] = {"connection": connection, "node": node, "vmid": vmid,
                          "port": d["port"], "ticket": d["ticket"], "at": now}
    return {"session": sess, "ticket": d["ticket"]}


def console_take(session: str) -> dict | None:
    """Consume a console session — single use, and expired ones are refused."""
    with _CONSOLE_LOCK:
        info = _CONSOLE.pop(session, None)
    if not info or time.time() - info["at"] > _CONSOLE_TTL:
        return None
    return info


def console_upstream(info: dict) -> dict:
    """What the relay needs to open Proxmox's vncwebsocket for a taken session: the
    wss URL, the auth header (a PVEAuthCookie from a password login, else the API
    token), and whether to skip TLS verification. Runs in a worker thread."""
    from urllib.parse import quote, urlparse
    creds = _creds_of(info["connection"])
    endpoint = (creds.get("PROXMOX_VE_ENDPOINT") or creds.get("PM_API_URL") or "").strip()
    insecure = (creds.get("PROXMOX_VE_INSECURE", "") or "").lower() in ("1", "true", "yes")
    header: dict = {}
    px = client_for(info["connection"])
    try:
        px._login()
        cookie = px._c.cookies.get("PVEAuthCookie")
        if cookie:
            header["Cookie"] = f"PVEAuthCookie={cookie}"
        elif creds.get("PROXMOX_VE_API_TOKEN"):
            header["Authorization"] = f"PVEAPIToken={creds['PROXMOX_VE_API_TOKEN']}"
    finally:
        px.close()
    p = urlparse(endpoint if endpoint.startswith(("http://", "https://")) else "https://" + endpoint)
    host = p.netloc or p.path
    url = (f"wss://{host}/api2/json/nodes/{info['node']}/qemu/{info['vmid']}"
           f"/vncwebsocket?port={info['port']}&vncticket={quote(str(info['ticket']), safe='')}")
    return {"url": url, "headers": header, "insecure": insecure}


# ── per-host ISO / image inventory (the Images subtab) ─────────
def host_images(connection: str, storage: str = "local") -> list[dict]:
    """The ISO / import images on each node of a cluster, plus that datastore's
    remaining space — so the Images tab shows what is uploaded where, and how much
    room is left. Reads the nodes CONCURRENTLY (each is 2 slow round-trips over the
    link; sequentially that is N×2, in parallel it is ~2). A node that cannot be
    read is reported, not fatal."""
    from concurrent.futures import ThreadPoolExecutor
    with client_for(connection) as px:
        nodes = px.nodes()          # also logs in once, so the parallel reads share the cookie
        if not nodes:
            return []

        def one(n: dict) -> dict:
            node = n["node"]
            row = {"node": node, "online": n["online"], "storage": storage,
                   "images": [], "capacity": None, "error": ""}
            if not n["online"]:
                return row
            try:
                row["images"] = sorted(
                    (f for f in px.content(node, storage)
                     if f.get("content") in ("iso", "import")),
                    key=lambda x: x["name"])
                row["capacity"] = px.storage_status(node, storage)
            except ProxmoxError as e:
                row["error"] = str(e)
            return row

        with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as ex:
            return list(ex.map(one, nodes))


def delete_iso(connection: str, node: str, storage: str, volid: str) -> None:
    """Remove one ISO / imported image from a node's datastore. The routes gate
    this on the provisioning area and the UI confirms it — it is destructive."""
    volid = (volid or "").strip()
    if not volid:
        raise Refused("which image?")
    if not volid.startswith(f"{storage}:"):
        raise Refused("that image is not on this datastore")
    with client_for(connection) as px:
        px.delete_content(node, storage, volid)


_UPLOAD_EXT = {
    "iso": (r"\.(iso|img)$", ".iso / .img"),
    "import": (r"\.(raw|img|qcow2|vmdk)$", ".raw / .img / .qcow2 / .vmdk"),
    "vztmpl": (r"\.(tar\.gz|tgz|tar\.xz|tar\.zst)$", ".tar.gz / .tar.xz / .tar.zst"),
}


def upload_iso(connection: str, node: str, storage: str, name: str, path: str,
               content: str = "iso") -> str:
    """Push a file the user picked from their device onto a node's datastore, via
    the portal (the nodes are air-gapped; the portal has the file). `content` is
    the Proxmox content type — `iso` (ISO/installer), `import` (a disk image a VM
    will import_from) or `vztmpl` (a container template). Big files are a slow
    transfer over 8006 — the caller streams it to a temp file first."""
    content = (content or "iso").strip()
    if content not in _UPLOAD_EXT:
        raise Refused("content type must be iso, import or vztmpl")
    pat, hint = _UPLOAD_EXT[content]
    if not re.search(pat, name or "", re.I):
        raise Refused(f"a {content} upload must be {hint} (got {name!r})")
    name = os.path.basename(name)
    with client_for(connection) as px:
        return px.upload(node, storage, name, path, content=content)


# ── quick-launch recipes (a preset spec + which fields to ask) ──
# Each recipe fixes the OS, install method and resources, so a launch asks only
# the variables: where (connection + node), the image, the static network, and
# the login. `create()` then generates the stack exactly as the full wizard does.
# `quick` marks the few shown on the Overview's Quick-launch strip; the full set
# (every entry here) always appears in the "Provision a VM" chooser.
PRESETS = [
    {"key": "alma10", "os": "almalinux-10", "method": "iso", "quick": True,
     "label": "AlmaLinux 10", "blurb": "minimal ISO · unattended kickstart",
     "icon": "server", "cores": 2, "mem_mb": 4096, "disk_gb": 40},
    {"key": "alma8", "os": "almalinux-8", "method": "iso", "quick": True,
     "label": "AlmaLinux 8", "blurb": "minimal ISO · unattended kickstart",
     "icon": "server", "cores": 2, "mem_mb": 4096, "disk_gb": 40},
    # cloud-image distros — the host downloads the qcow2 once, then cloud-init sets
    # the static network + login (no ISO, no console). Air-gapped hosts stage it.
    {"key": "ubuntu2404", "os": "ubuntu-24.04", "method": "cloud",
     "label": "Ubuntu 24.04 LTS", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "ubuntu2204", "os": "ubuntu-22.04", "method": "cloud",
     "label": "Ubuntu 22.04 LTS", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "debian12", "os": "debian-12", "method": "cloud",
     "label": "Debian 12", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "rocky9", "os": "rocky-9", "method": "cloud",
     "label": "Rocky Linux 9", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "centos10", "os": "centos-10", "method": "cloud",
     "label": "CentOS Stream 10", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "centos9", "os": "centos-9", "method": "cloud",
     "label": "CentOS Stream 9", "blurb": "cloud image · cloud-init",
     "icon": "server", "cores": 2, "mem_mb": 2048, "disk_gb": 20},
    {"key": "alpine321", "os": "alpine-3.21", "method": "cloud",
     "label": "Alpine Linux 3.21", "blurb": "cloud image · tiny",
     "icon": "server", "cores": 1, "mem_mb": 1024, "disk_gb": 8},
    {"key": "talos", "os": "talos", "method": "cloud", "quick": True,
     "label": "Talos node", "blurb": "nocloud image · machine-config drive",
     "icon": "boxes", "cores": 4, "mem_mb": 4096, "disk_gb": 20},
]


def presets() -> list[dict]:
    # carry the OS family so the wizard can offer the install methods that family
    # actually supports (RHEL-family = ISO+kickstart OR cloud image; the rest = cloud).
    return [{**p, "family": CATALOG[p["os"]]["family"]} for p in PRESETS]


# families whose ISO installs unattended via an Anaconda kickstart (the ISO method);
# everything else is cloud-image only in this wizard.
KICKSTART_FAMILIES = {"almalinux", "centos", "rocky"}


def methods_for(os_key: str) -> list[str]:
    """The install methods offered for an OS — 'cloud' always, plus 'iso' for the
    RHEL family (Anaconda kickstart). Talos has its own wizard."""
    fam = (CATALOG.get(os_key) or {}).get("family", "")
    return (["cloud", "iso"] if fam in KICKSTART_FAMILIES else ["cloud"])


def preset(key: str) -> dict | None:
    return next((dict(p) for p in PRESETS if p["key"] == key), None)


# ══ the OS catalog ══════════════════════════════════════════════
# Each entry says how the OS is installed unattended with a static address.
#   kind        : how the image is used — "cloud" (qcow2 + cloud-init) or
#                 "nocloud" (Talos raw disk image + machine-config drive).
#   url         : where to fetch it (download-into-Proxmox), {ver}/{schematic}
#                 filled from the spec for Talos.
#   file_name   : the name it lands under in the datastore (also the presence key).
#   content     : the Proxmox datastore content type it downloads as.
#   decompress  : xz for Talos' .raw.xz, else "".
#   disk_gb/cores/mem_mb : sensible defaults for that OS.
CATALOG: dict[str, dict] = {
    "almalinux-10": {
        "label": "AlmaLinux 10", "kind": "cloud", "family": "almalinux",
        "url": "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/"
               "AlmaLinux-10-GenericCloud-latest.x86_64.qcow2",
        "file_name": "almalinux-10-cloudimg-amd64.img",
        "content": "iso", "decompress": "",
        "cloud_user": "almalinux",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "almalinux-8": {
        "label": "AlmaLinux 8", "kind": "cloud", "family": "almalinux",
        "url": "https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/"
               "AlmaLinux-8-GenericCloud-latest.x86_64.qcow2",
        "file_name": "almalinux-8-cloudimg-amd64.img",
        "content": "iso", "decompress": "",
        "cloud_user": "almalinux",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    # ── cloud-image distros (cloud-init) ── downloaded as `.img` into `iso`
    # content (the proven pattern: import content 400s a `.img`, but `iso` accepts
    # it and bpg's `import_from = local:iso/*.img` works — qemu-img detects the real
    # qcow2 at import). cloud_user is the image's default login for cloud-init.
    "ubuntu-24.04": {
        "label": "Ubuntu 24.04 LTS", "kind": "cloud", "family": "ubuntu",
        "url": "https://cloud-images.ubuntu.com/releases/24.04/release/"
               "ubuntu-24.04-server-cloudimg-amd64.img",
        "file_name": "ubuntu-24.04-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "ubuntu",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "ubuntu-22.04": {
        "label": "Ubuntu 22.04 LTS", "kind": "cloud", "family": "ubuntu",
        "url": "https://cloud-images.ubuntu.com/releases/22.04/release/"
               "ubuntu-22.04-server-cloudimg-amd64.img",
        "file_name": "ubuntu-22.04-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "ubuntu",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "debian-12": {
        "label": "Debian 12", "kind": "cloud", "family": "debian",
        "url": "https://cloud.debian.org/images/cloud/bookworm/latest/"
               "debian-12-genericcloud-amd64.qcow2",
        "file_name": "debian-12-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "debian",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "rocky-9": {
        "label": "Rocky Linux 9", "kind": "cloud", "family": "rocky",
        "url": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/"
               "Rocky-9-GenericCloud-Base.latest.x86_64.qcow2",
        "file_name": "rocky-9-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "rocky",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "centos-10": {
        "label": "CentOS Stream 10", "kind": "cloud", "family": "centos",
        "url": "https://cloud.centos.org/centos/10-stream/x86_64/images/"
               "CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2",
        "file_name": "centos-stream-10-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "cloud-user",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "centos-9": {
        "label": "CentOS Stream 9", "kind": "cloud", "family": "centos",
        "url": "https://cloud.centos.org/centos/9-stream/x86_64/images/"
               "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2",
        "file_name": "centos-stream-9-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "cloud-user",
        "disk_gb": 20, "cores": 2, "mem_mb": 2048,
    },
    "alpine-3.21": {
        "label": "Alpine Linux 3.21", "kind": "cloud", "family": "alpine",
        # Alpine cloud images are versioned to the patch (no `latest` symlink);
        # bump this when 3.21.x moves. The bios-cloudinit variant boots on Proxmox.
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/"
               "generic_alpine-3.21.3-x86_64-bios-cloudinit-r0.qcow2",
        "file_name": "alpine-3.21-cloudimg-amd64.img",
        "content": "iso", "decompress": "", "cloud_user": "alpine",
        "disk_gb": 8, "cores": 1, "mem_mb": 1024,
    },
    "talos": {
        "label": "Talos Linux", "kind": "nocloud", "family": "talos",
        # {schematic} and {ver} come from the spec; the bare (no-extension)
        # schematic is the default, overridable for custom Image Factory builds.
        # zstd, not the default .raw.xz — bpg's download_file decompresses
        # gz/lzo/zst/bz2 but NOT xz; the factory serves .raw.zst on demand.
        "url": "https://factory.talos.dev/image/{schematic}/{ver}/nocloud-amd64.raw.zst",
        "file_name": "talos-{ver}-nocloud-amd64.raw",   # after zstd decompression
        "content": "import", "decompress": "zst",
        "schematic": "376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba",
        "disk_gb": 20, "cores": 2, "mem_mb": 4096,
    },
}


def os_choices() -> list[dict]:
    return [{"key": k, "label": v["label"], "family": v["family"],
             "kind": v["kind"], "disk_gb": v["disk_gb"], "cores": v["cores"],
             "mem_mb": v["mem_mb"], "needs_version": v["family"] == "talos"}
            for k, v in CATALOG.items()]


def image_file_name(os_key: str, ver: str = "") -> str:
    o = CATALOG[os_key]
    return o["file_name"].format(ver=(ver or "").lstrip("v"))


def image_status(connection_sid: str, node: str, storage: str,
                 os_key: str, ver: str = "") -> dict:
    """Is the chosen OS image already in the datastore? Answers the wizard's
    'check image' button. Never fails the page — returns why if it could not
    look."""
    if os_key not in CATALOG:
        return {"ok": False, "error": "unknown image"}
    want = image_file_name(os_key, ver)
    try:
        with client_for(connection_sid) as px:
            files = px.content(node, storage)
    except (Refused, ProxmoxError) as e:
        return {"ok": False, "error": str(e), "want": want}
    present = any(f["name"].endswith(want) or want in f["name"] for f in files)
    return {"ok": True, "present": present, "want": want,
            "storage": storage, "node": node,
            "downloadable": True,   # every catalog image has a URL we can fetch
            "url": CATALOG[os_key]["url"]}


def datastore_images(connection: str, node: str, storage: str) -> list[dict]:
    """Existing files on a node's datastore that can serve as a VM image — the
    source for the wizard's 'pick an existing image' dropdown. No transfer."""
    with client_for(connection) as px:
        files = px.content(node, storage)
    out = [{"volid": f["volid"], "name": f["name"], "size_gb": f.get("size_gb", 0),
            "content": f.get("content", "")}
           for f in files if f.get("content") in ("iso", "import", "vztmpl")]
    return sorted(out, key=lambda x: x["name"])


def image_source_url(os_key: str, ver: str = "") -> str:
    """The public URL to fetch an OS image from — for the 'download to my device'
    helper (the browser downloads it; the portal stores nothing)."""
    cat = CATALOG.get(os_key) or {}
    url = cat.get("url", "")
    if os_key == "talos":
        v = ("v" + ver.lstrip("v")) if ver else "v1.13.8"
        url = url.format(schematic=cat.get("schematic", ""), ver=v)
    return url


# ══ staging: EnvMap fetches an image and pushes it onto the node(s) ══
# The nodes are air-gapped, but EnvMap has the internet AND reaches Proxmox on
# 8006 — so EnvMap downloads the image once and uploads it to each node's iso
# datastore over the API (no node egress, no SSH). Runs on a background thread; a
# small in-memory job dict is polled by the wizard.
_STAGE: dict = {}
_STAGE_LOCK = threading.Lock()


def staged_name(os_key: str, ver: str = "") -> str:
    """The filename a staged image lands under — an `.img` in iso content, which
    bpg imports regardless of the true qcow2/raw format."""
    base = image_file_name(os_key, ver)
    return re.sub(r"\.(raw|qcow2|img)$", "", base) + ".img"


def staged_volid(img_ds: str, os_key: str, ver: str = "") -> str:
    return f"{img_ds}:iso/{staged_name(os_key, ver)}"


def _stage_set(job: str, **kw) -> None:
    with _STAGE_LOCK:
        if job in _STAGE:
            _STAGE[job].update(kw)


def stage_status(job: str) -> dict | None:
    with _STAGE_LOCK:
        return dict(_STAGE[job]) if job in _STAGE else None


def stage_probe(connection: str, node: str, storage: str) -> dict:
    """A tiny, self-cleaning check of what the 8006 upload API accepts on this
    cluster. Tests two paths: `iso` (the image-staging path) and `import` (the
    content the OEMDRV kickstart disk needs — a disk's import_from source must be
    import/images content, never iso). For `import` it tries the extensions
    Proxmox might whitelist and reports which one takes, so the caller can pick
    the right one. Uploads a few-KB dummy for each, confirms it lists, deletes it —
    leaves nothing behind. Runs in the portal so the credential stays sealed."""
    tag = uuid.uuid4().hex[:8]
    out: dict = {"ok": True, "iso": None, "import": {}}
    tmp = None
    try:
        tmp = tempfile.mkdtemp(prefix="envmap-probe-")

        with client_for(connection) as px:
            # sweep any leftovers from an earlier failed probe (either content)
            swept = 0
            for f in px.content(node, storage):
                if "envmap-probe-" in (f.get("name") or ""):
                    try:
                        px.delete_content(node, storage, f["volid"])
                        swept += 1
                    except ProxmoxError:
                        pass
            out["swept"] = swept

            def _try(content: str, ext: str) -> dict:
                name = f"envmap-probe-{tag}{ext}"
                p = os.path.join(tmp, name)
                with open(p, "wb") as fh:
                    fh.write(b"\0" * 4096)
                r = {"uploaded": False, "listed": False, "deleted": False}
                try:
                    px.upload(node, storage, name, p, content=content)
                    r["uploaded"] = True
                    r["listed"] = any((f.get("name") or "").endswith(name)
                                      for f in px.content(node, storage))
                    try:
                        px.delete_content(node, storage, f"{storage}:{content}/{name}")
                        r["deleted"] = True
                    except ProxmoxError as e:
                        r["delete_error"] = str(e)
                except ProxmoxError as e:
                    r["error"] = str(e)
                return r

            out["iso"] = _try("iso", ".img")
            for ext in (".raw", ".img", ".qcow2"):
                out["import"][ext] = _try("import", ext)
    except (Refused, ProxmoxError, OSError) as e:
        return {"ok": False, "error": str(e)}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return out


def stage_start(connection: str, nodes: list, os_key: str, ver: str,
                img_ds: str, who: str) -> str:
    if os_key not in CATALOG:
        raise Refused("unknown image")
    if not nodes:
        raise Refused("no nodes to stage to")
    job = "stg-" + uuid.uuid4().hex[:10]
    with _STAGE_LOCK:
        _STAGE[job] = {"status": "running", "pct": 0, "msg": "starting…",
                       "volid": staged_volid(img_ds, os_key, ver), "by": who}
    threading.Thread(target=_stage_run, daemon=True,
                     args=(job, connection, list(nodes), os_key, ver, img_ds)).start()
    return job


def _download(url: str, path: str, job: str, label: str = "downloading") -> None:
    with httpx.stream("GET", url, follow_redirects=True,
                      timeout=httpx.Timeout(120.0, connect=15.0)) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length") or 0)
        done = mark = 0
        step = max(4 * 1024 * 1024, (total // 100) or 1)   # report ~every 1%
        with open(path, "wb") as fh:
            for chunk in r.iter_bytes(1024 * 256):
                fh.write(chunk)
                done += len(chunk)
                if not total or (done - mark < step and done < total):
                    continue
                mark = done
                _stage_set(job, pct=int(done * 80 / total),        # download ≤ 80%
                           msg=f"{label} · {done // (1024*1024)}/{total // (1024*1024)} MB")


def _stage_run(job, connection, nodes, os_key, ver, img_ds) -> None:
    cat = CATALOG.get(os_key) or {}
    url = cat.get("url", "")
    if os_key == "talos":
        v = ("v" + ver.lstrip("v")) if ver else ver
        url = url.format(schematic=cat.get("schematic", ""), ver=v)
    name = staged_name(os_key, ver)
    tmp = None
    try:
        tmp = tempfile.mkdtemp(prefix="envmap-stage-")
        img = os.path.join(tmp, name)
        label = f"downloading {cat.get('label', os_key)}"
        _stage_set(job, msg=label + "…")
        if cat.get("decompress") == "zst":
            comp = img + ".zst"
            _download(url, comp, job, label)
            _stage_set(job, msg="decompressing…", pct=85)
            subprocess.run(["zstd", "-d", "-f", comp, "-o", img],
                           check=True, capture_output=True)
            os.remove(comp)
        else:
            _download(url, img, job, label)
        total_mb = max(1, os.path.getsize(img) // (1024 * 1024))
        n = len(nodes)
        with client_for(connection) as px:
            for i, node in enumerate(nodes, 1):
                already = any(f["name"].endswith(name) for f in px.content(node, img_ds))
                if already:
                    _stage_set(job, pct=int(85 + i * 15 / n),
                               msg=f"{node}: already present ({i}/{n})")
                    continue
                base = 85 + (i - 1) * 15 / n         # this node's slice of the 85→100 band
                _stage_set(job, pct=int(base),
                           msg=f"uploading {total_mb} MB to {node} ({i}/{n})…")
                mark = {"at": -1}
                def cb(sent, tot, _node=node, _i=i, _base=base):
                    step = max(8 * 1024 * 1024, (tot // 100) or 1)   # report ~every 1%
                    if sent - mark["at"] < step and sent < tot:
                        return
                    mark["at"] = sent
                    pct = int(_base + 15 / n * (sent / tot if tot else 0))
                    _stage_set(job, pct=min(99, pct),
                               msg=f"uploading to {_node} ({_i}/{n}) · "
                                   f"{sent // (1024*1024)}/{tot // (1024*1024)} MB")
                px.upload(node, img_ds, name, img, content="iso", on_progress=cb)
        _stage_set(job, status="ok", pct=100,
                   msg=f"staged {name} to {n} node(s)")
    except (Refused, ProxmoxError, OSError, subprocess.SubprocessError) as e:
        _stage_set(job, status="failed", msg=str(e))
    finally:
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ══ the generator: a spec → a Terraform stack ═══════════════════
def _v(name: str, val) -> str:
    return f'  {name} = "{val}"'


def _validate(spec: dict) -> dict:
    """Shape + sanity check a wizard spec. Raises Refused with a plain message so
    the wizard can show exactly what is wrong. Normalises each VM's target
    connection — its own, or the spec-level default — so a run can span more than
    one Proxmox."""
    os_key = spec.get("os")
    if os_key not in CATALOG:
        raise Refused("pick an operating system")
    cat = CATALOG[os_key]
    default_conn = (spec.get("connection") or "").strip()

    nodes = spec.get("nodes") or []
    if not nodes:
        raise Refused("add at least one VM")
    if len(nodes) > MAX_VMS:
        raise Refused(f"one run is capped at {MAX_VMS} VMs")

    seen_names, seen_ips = set(), set()
    for i, n in enumerate(nodes, 1):
        host = (n.get("hostname") or "").strip().lower()
        if not NAME_OK.match(host):
            raise Refused(f"VM #{i}: {host!r} is not a valid hostname "
                          "(lower-case letters, digits, dashes)")
        if host in seen_names:
            raise Refused(f"two VMs both named {host!r}")
        seen_names.add(host)
        conn = (n.get("connection") or default_conn).strip()
        if not conn:
            raise Refused(f"{host}: choose a Proxmox connection")
        n["connection"] = conn
        if not (n.get("node") or "").strip():
            raise Refused(f"{host}: choose a destination node")
        try:
            ip = ipaddress.ip_interface(n.get("ip") or "")
        except ValueError:
            raise Refused(f"{host}: {n.get('ip')!r} is not an IP/CIDR like 10.0.0.5/24")
        if str(ip) in seen_ips:
            raise Refused(f"two VMs share the address {ip}")
        seen_ips.add(str(ip))
        n["hostname"], n["ip"] = host, str(ip)

    if not _conns(spec):
        raise Refused("pick a Proxmox connection")
    # network is validated per-VM: a VM's own gateway/dns override the spec-level
    # ones, so only the OS login is truly shared (the full wizard leaves the node
    # fields empty and everything falls back to the spec).
    for n in nodes:
        net = _net_of(spec, n)
        try:
            ipaddress.ip_address(net["gateway"])
        except ValueError:
            raise Refused(f"{n['hostname']}: the gateway {net['gateway']!r} is not a valid IP address")
        for d in net["dns"]:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                raise Refused(f"{n['hostname']}: {d!r} is not a valid DNS server address")

    if cat["family"] == "talos":
        if not (spec.get("talos_version") or "").strip():
            raise Refused("Talos needs a version, e.g. v1.13.8")
        for key, label in (("pod_cidr", "pod"), ("svc_cidr", "service")):
            v = (spec.get(key) or "").strip()
            if v:
                try:
                    ipaddress.ip_network(v, strict=False)
                except ValueError:
                    raise Refused(f"the {label} CIDR {v!r} is not a valid network like 10.244.0.0/16")
        vip = (spec.get("vip") or "").strip()
        if vip:
            try:
                ipaddress.ip_address(vip)
            except ValueError:
                raise Refused(f"the control-plane VIP {vip!r} is not a valid IP address")
        if (spec.get("talos_method") or "").strip() == "iso" and not (spec.get("image_volid") or "").strip():
            raise Refused("the metal-ISO install needs a Talos ISO already on the host")
    return spec


def _conns(spec: dict) -> list[str]:
    """The distinct Proxmox connections a spec targets, in first-seen order."""
    out: list[str] = []
    for n in spec.get("nodes") or []:
        c = (n.get("connection") or spec.get("connection") or "").strip()
        if c and c not in out:
            out.append(c)
    return out


def _alias_map(spec: dict) -> dict:
    """sid -> provider alias, ONLY when more than one Proxmox is in play. An empty
    map means the single default `provider "proxmox" {}` — the proven one-Proxmox
    path stays byte-for-byte the same."""
    cs = _conns(spec)
    return {sid: f"c{i + 1}" for i, sid in enumerate(cs)} if len(cs) > 1 else {}


def _provider_defs(aliases: dict) -> list[str]:
    """The provider block(s). One default provider for a single Proxmox (reads
    PROXMOX_VE_* env, as always); one aliased provider per connection — fed by
    TF_VAR variables that `create()` fills from each connection's sealed
    credential — when a run spans several."""
    if not aliases:
        return ['provider "proxmox" {}', ""]
    L: list[str] = []
    for a in aliases.values():
        p = f"pve_{a}"
        L += [f'variable "{p}_endpoint" {{ type = string }}',
              f'variable "{p}_insecure" {{ type = bool }}',
              f'variable "{p}_username" {{ type = string }}',
              f'variable "{p}_api_token" {{',
              "  type      = string", "  sensitive = true", "}",
              f'variable "{p}_password" {{',
              "  type      = string", "  sensitive = true", "}"]
    L.append("")
    for a in aliases.values():
        p = f"pve_{a}"
        L += ['provider "proxmox" {',
              f'  alias     = "{a}"',
              f"  endpoint  = var.{p}_endpoint",
              f"  insecure  = var.{p}_insecure",
              f'  api_token = var.{p}_api_token != "" ? var.{p}_api_token : null',
              f'  username  = var.{p}_username != "" ? var.{p}_username : null',
              f'  password  = var.{p}_password != "" ? var.{p}_password : null',
              "}"]
    L.append("")
    return L


def _img_id(aliases: dict, sid: str, node: str) -> str:
    """Image-download resource id, unique per (connection, node)."""
    pre = (aliases[sid] + "_") if aliases else ""
    return f"img_{pre}{_id(node)}"


# ══ ISO + kickstart (unattended install of the installer ISO) ══
def _hash_password(pw: str) -> str:
    """A SHA-512 crypt hash for cloud-init / kickstart. Python's `crypt` module is
    gone in 3.13+, so shell out to openssl with the password on STDIN (never argv,
    so it can't leak into the process list)."""
    if not pw:
        return ""
    try:
        r = subprocess.run(["openssl", "passwd", "-6", "-stdin"],
                           input=pw.encode(), capture_output=True, check=True)
        return r.stdout.decode().strip()
    except (OSError, subprocess.SubprocessError) as e:
        raise Refused(f"could not hash the OS password: {e}")


def _net_of(spec: dict, n: dict) -> dict:
    """The effective network for a VM — its own values override the spec-level
    ones, so a run can put each VM on a different network (only the OS login is
    truly shared). The full wizard leaves the node fields empty and everything
    falls back to the spec, so its behaviour is unchanged."""
    return {
        "gateway": (n.get("gateway") or spec.get("gateway") or "").strip(),
        "dns": n.get("dns") or spec.get("dns") or [],
        "bridge": (n.get("bridge") or spec.get("bridge") or "vmbr0").strip(),
        "vlan": str(n.get("vlan") or spec.get("vlan") or "").strip(),
    }


def _kickstart(spec: dict, n: dict, pwhash: str) -> str:
    """An Anaconda kickstart that installs the ISO unattended with a STATIC
    network — the RHEL-family equivalent of cloud-init. Delivered on an OEMDRV
    disk, so no network is needed to fetch it."""
    ip = ipaddress.ip_interface(n["ip"])
    mask = str(ip.network.netmask)
    net = _net_of(spec, n)
    dns = ",".join(net["dns"])
    user = (spec.get("os_user") or "").strip()
    sshkey = (spec.get("ssh_key") or "").strip()
    L = ["# generated by EnvMap — unattended install", "text",
         "lang en_US.UTF-8", "keyboard us", "timezone UTC --utc",
         f"network --bootproto=static --ip={ip.ip} --netmask={mask} "
         f"--gateway={net['gateway']} --nameserver={dns} "
         f"--hostname={n['hostname']} --device=link --activate --onboot=on",
         "firewall --enabled --service=ssh", "selinux --enforcing",
         "ignoredisk --only-use=sda",       # never touch the OEMDRV disk (sdb)
         "bootloader --location=mbr --boot-drive=sda",
         "clearpart --all --initlabel --drives=sda",
         "autopart --type=lvm",
         f"rootpw --iscrypted {pwhash}" if pwhash else "rootpw --lock"]
    if user and user != "root":
        line = f"user --name={user} --groups=wheel"
        if pwhash:
            line += f" --iscrypted --password={pwhash}"
        L.append(line)
    if sshkey:
        L.append(f'sshkey --username={user or "root"} "{sshkey}"')
    post = ["%post --erroronfail",
            # enable the guest agent only if it actually made it onto the system
            "systemctl enable qemu-guest-agent 2>/dev/null || true"]
    if spec.get("ansible_playbook") and user and user != "root":
        # passwordless sudo for the provisioning user, so an Ansible playbook's
        # `become` works with no sudo password — the SSH key is already baked in,
        # this closes the loop for hands-off post-provision configuration.
        post.append(f'echo "{user} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-{user}')
        post.append(f'chmod 0440 /etc/sudoers.d/90-{user}')
    post += ["%end", ""]
    L += ["reboot", "",
          # --ignoremissing: never stop at Anaconda's interactive "some packages
          # are missing, continue? (yes/no)" prompt — that hangs an unattended
          # install forever. qemu-guest-agent is NOT on the AlmaLinux minimal ISO
          # and an air-gapped node cannot fetch it, so it is best-effort here.
          "%packages --ignoremissing", "@^minimal-environment", "openssh-server",
          "qemu-guest-agent", "%end", ""] + post
    return "\n".join(L)


def _build_oemdrv(ks_text: str) -> str:
    """Build a tiny ISO labelled OEMDRV holding ks.cfg — Anaconda auto-loads a
    kickstart from an OEMDRV-labelled volume, so the install needs no network.
    Returns the ISO path; raises Refused if no ISO builder is available."""
    d = tempfile.mkdtemp(prefix="oemdrv-")
    src = os.path.join(d, "src")
    os.mkdir(src)
    with open(os.path.join(src, "ks.cfg"), "w") as fh:
        fh.write(ks_text)
    out = os.path.join(d, "oemdrv.iso")
    for cmd in (["xorriso", "-as", "mkisofs", "-V", "OEMDRV", "-o", out, src],
                ["genisoimage", "-V", "OEMDRV", "-r", "-o", out, src],
                ["mkisofs", "-V", "OEMDRV", "-r", "-o", out, src],
                ["hdiutil", "makehybrid", "-iso", "-joliet",
                 "-default-volume-name", "OEMDRV", "-o", out, src]):
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            return out
        except subprocess.SubprocessError:
            continue
    raise Refused("no ISO builder on the portal (need xorriso, genisoimage or "
                  "mkisofs) to make the kickstart OEMDRV disk")


def generate(spec: dict) -> dict:
    """Turn a validated spec into {body, tfvars}. Dispatches on OS family and, for
    a cloud OS, on the install method (cloud-init clone vs ISO + kickstart)."""
    spec = _validate(spec)
    aliases = _alias_map(spec)
    fam = CATALOG[spec["os"]]["family"]
    if fam == "talos":
        return _gen_talos(spec, aliases)
    if (spec.get("method") or "cloud") == "iso":
        return _gen_iso(spec, aliases)
    return _gen_cloud(spec, aliases)


def _gen_cloud(spec: dict, aliases: dict) -> dict:
    """AlmaLinux (and any cloud-image OS): download the qcow2 once per (Proxmox,
    node), then one VM per row with a static cloud-init network. No DHCP, no
    console. With `aliases` set, every resource is pinned to its Proxmox."""
    cat = CATALOG[spec["os"]]
    disk_ds = spec.get("disk_datastore") or "local-lvm"
    img_ds = spec.get("image_datastore") or "local"
    cores = int(spec.get("cores") or cat["cores"])
    mem = int(spec.get("mem_mb") or cat["mem_mb"])
    disk_gb = int(spec.get("disk_gb") or cat["disk_gb"])
    ssh_key = (spec.get("ssh_key") or "").strip()
    pwhash = _hash_password(spec.get("os_password", ""))   # once; a SHA-512 hash, not plaintext
    nodes = spec["nodes"]
    url = (spec.get("image_url") or "").strip() or cat["url"]
    present = bool(spec.get("image_present"))       # already uploaded → no download
    # default matches where the download/stage lands: iso content, `.img` file_name
    volid = (spec.get("image_volid") or "").strip() or f"{img_ds}:iso/{cat['file_name']}"

    def imp(sid, node):
        return (f'"{volid}"' if present
                else f"proxmox_virtual_environment_download_file.{_img_id(aliases, sid, node)}.id")

    L: list[str] = []
    L.append("terraform {")
    L.append('  required_providers { proxmox = { source = "bpg/proxmox", version = "~> 0.60" } }')
    L.append("}")
    L += _provider_defs(aliases)
    if present:
        L.append(f'# {cat["label"]}: image already uploaded — cloned from {volid} (no download).')
        L.append("")
    else:
        L.append(f'# {cat["label"]} cloud image — downloaded once per node, then cloned to each VM.')
    for sid, node in ([] if present else sorted({(n["connection"], n["node"]) for n in nodes})):
        L.append(f'resource "proxmox_virtual_environment_download_file" "{_img_id(aliases, sid, node)}" {{')
        if aliases:
            L.append(f"  provider     = proxmox.{aliases[sid]}")
        L.append(f'  content_type = "{cat["content"]}"')
        L.append(f'  datastore_id = "{img_ds}"')
        L.append(f'  node_name    = "{node}"')
        L.append(f'  url          = "{url}"')
        L.append(f'  file_name    = "{cat["file_name"]}"')
        L.append("  overwrite    = false")
        L.append("}")
        L.append("")

    for n in nodes:
        rid = _id(n["hostname"])
        addr = n["ip"]
        vcores = int(n.get("cores") or cores)
        vmem = int(n.get("mem_mb") or mem)
        vdisk = int(n.get("disk_gb") or disk_gb)
        L.append(f'resource "proxmox_virtual_environment_vm" "{rid}" {{')
        if aliases:
            L.append(f"  provider  = proxmox.{aliases[n['connection']]}")
        L.append(f'  name      = "{n["hostname"]}"')
        L.append(f'  node_name = "{n["node"]}"')
        L.append("  agent { enabled = true }")
        L.append("  cpu {")
        L.append(f"    cores = {vcores}")
        L.append('    type  = "host"')
        L.append("  }")
        L.append(f"  memory {{ dedicated = {vmem} }}")
        L.append("  disk {")
        L.append(f'    datastore_id = "{disk_ds}"')
        L.append(f'    import_from  = {imp(n["connection"], n["node"])}')
        L.append('    interface    = "scsi0"')
        L.append(f"    size         = {vdisk}")
        L.append("  }")
        net = _net_of(spec, n)
        L.append("  network_device {")
        L.append(f'    bridge  = "{net["bridge"]}"')
        if net["vlan"]:
            L.append(f"    vlan_id = {net['vlan']}")
        L.append("  }")
        L.append("  initialization {")
        L.append("    ip_config {")
        L.append("      ipv4 {")
        L.append(f'        address = "{addr}"')
        L.append(f'        gateway = "{net["gateway"]}"')
        L.append("      }")
        L.append("    }")
        if net["dns"]:
            servers = ", ".join(f'"{d}"' for d in net["dns"])
            L.append(f"    dns {{ servers = [{servers}] }}")
        if ssh_key or spec.get("os_user") or pwhash:
            L.append("    user_account {")
            L.append(f'      username = "{spec.get("os_user") or cat["cloud_user"]}"')
            if pwhash:
                # cipassword — a SHA-512 hash so the clear password never lands in the
                # stored HCL body; recent Proxmox/cloud-init accept the hashed form.
                L.append(f'      password = "{pwhash}"')
            if ssh_key:
                L.append(f'      keys     = ["{ssh_key}"]')
            L.append("    }")
        L.append("  }")
        L.append("}")
        L.append("")
        L.append(f'output "{rid}_ip" {{ value = "{addr}" }}')
        L.append("")
    return {"body": "\n".join(L), "tfvars": ""}


def _gen_talos(spec: dict, aliases: dict) -> dict:
    """Talos: a nocloud disk image whose per-node machine-config (static network,
    hostname, install disk) is delivered LOCALLY on a config drive — so the node
    brings up its static IP at first boot with no DHCP and no console. The talos
    provider then bootstraps over that now-reachable static IP and returns a
    kubeconfig. No laptop talosctl, no over-the-network config-apply, one run.
    One cluster can span several Proxmox (each VM pinned to its provider); the
    Talos resources talk to node IPs, so they are Proxmox-agnostic.

    The config drive needs a datastore with the `snippets` content type enabled
    (the machine-config is written there as cloud-init user-data)."""
    cat = CATALOG[spec["os"]]
    ver = spec["talos_version"].strip()
    if not ver.startswith("v"):
        ver = "v" + ver
    schematic = (spec.get("talos_schematic") or cat["schematic"]).strip()
    k8s = (spec.get("k8s_version") or "").strip()
    disk_ds = spec.get("disk_datastore") or "local-lvm"
    img_ds = spec.get("image_datastore") or "local"
    snip_ds = spec.get("snippet_datastore") or img_ds     # must allow `snippets`
    pod_cidr = (spec.get("pod_cidr") or "").strip()       # cluster.network.podSubnets
    svc_cidr = (spec.get("svc_cidr") or "").strip()       # cluster.network.serviceSubnets
    vip = (spec.get("vip") or "").strip()                 # control-plane shared VIP
    ntp = [s.strip() for s in (spec.get("ntp_servers") or []) if s.strip()]  # machine.time.servers
    cores = int(spec.get("cores") or cat["cores"])
    mem = int(spec.get("mem_mb") or cat["mem_mb"])
    disk_gb = int(spec.get("disk_gb") or cat["disk_gb"])
    nodes = spec["nodes"]
    controlplanes = [n for n in nodes if n.get("role", "controlplane") == "controlplane"]
    if not controlplanes:
        raise Refused("a Talos cluster needs at least one control-plane node")
    # the API endpoint is the VIP when set (HA control plane), else the first CP
    endpoint_ip = (vip or spec.get("cp_endpoint") or controlplanes[0]["ip"]).split("/")[0]
    url = (spec.get("image_url") or "").strip() or cat["url"].format(schematic=schematic, ver=ver)
    present = bool(spec.get("image_present"))       # already uploaded → no download
    volid = (spec.get("image_volid") or "").strip() or f"{img_ds}:import/{image_file_name(spec['os'], ver)}"
    install_disk = spec.get("install_disk") or "/dev/sda"
    # EXPERIMENTAL metal-ISO path: boot the Talos ISO already on the host and apply
    # the machine-config over the network (talos_machine_configuration_apply). It
    # needs the node reachable in maintenance mode (DHCP) — the default nocloud path
    # needs neither DHCP nor console. `volid` is the ISO for this path.
    metal = (spec.get("talos_method") or "").strip() == "iso"
    if metal:
        present = True                              # ISO is on the host; never download

    def _prov(sid, pad=""):
        return [f"  provider{pad} = proxmox.{aliases[sid]}"] if aliases else []

    def imp(sid, node):
        return (f'"{volid}"' if present
                else f"proxmox_virtual_environment_download_file.{_img_id(aliases, sid, node)}.id")

    L: list[str] = []
    L.append("terraform {")
    L.append("  required_providers {")
    L.append('    proxmox = { source = "bpg/proxmox",       version = "~> 0.60" }')
    L.append('    talos   = { source = "siderolabs/talos",  version = "~> 0.6" }')
    L.append("  }")
    L.append("}")
    L += _provider_defs(aliases)
    if metal:
        L.append(f'# Talos {ver} (metal ISO, experimental): boots {volid}; config applied over the network.')
        L.append("")
    elif present:
        L.append(f'# Talos {ver}: image already uploaded — cloned from {volid} (no download).')
        L.append("")
    else:
        L.append(f'# Talos {ver} nocloud image — downloaded (and zstd-decompressed) per node.')
    for sid, node in ([] if present else sorted({(n["connection"], n["node"]) for n in nodes})):
        L.append(f'resource "proxmox_virtual_environment_download_file" "{_img_id(aliases, sid, node)}" {{')
        L += _prov(sid, "               ")
        L.append(f'  content_type            = "{cat["content"]}"')
        L.append(f'  datastore_id            = "{img_ds}"')
        L.append(f'  node_name               = "{node}"')
        L.append(f'  url                     = "{url}"')
        L.append(f'  file_name               = "{image_file_name(spec["os"], ver)}"')
        L.append(f'  decompression_algorithm = "{cat["decompress"]}"')
        L.append("  overwrite               = false")
        L.append("}")
        L.append("")

    # Talos PKI + machine config
    L.append('resource "talos_machine_secrets" "this" {}')
    L.append("")
    L.append('data "talos_client_configuration" "this" {')
    L.append('  cluster_name         = "%s"' % (spec.get("cluster_name") or "talos"))
    L.append("  client_configuration = talos_machine_secrets.this.client_configuration")
    L.append(f'  endpoints            = ["{endpoint_ip}"]')
    L.append("}")
    L.append("")

    # one VM per node — machine-config delivered LOCALLY on a nocloud config drive
    for n in nodes:
        rid = _id(n["hostname"])
        role = n.get("role", "controlplane")
        addr = n["ip"]
        vcores = int(n.get("cores") or cores)
        vmem = int(n.get("mem_mb") or mem)
        vdisk = int(n.get("disk_gb") or disk_gb)
        net = _net_of(spec, n)
        # per-node machine config: static network + hostname + install disk
        L.append(f'data "talos_machine_configuration" "{rid}" {{')
        L.append('  cluster_name     = "%s"' % (spec.get("cluster_name") or "talos"))
        L.append(f'  cluster_endpoint = "https://{endpoint_ip}:6443"')
        L.append(f'  machine_type     = "{role}"')
        L.append("  machine_secrets  = talos_machine_secrets.this.machine_secrets")
        if k8s:
            L.append(f'  kubernetes_version = "{k8s}"')
        L.append("  config_patches   = [yamlencode({")
        L.append("    machine = {")
        L.append('      install = { disk = "%s" }' % install_disk)
        L.append("      network = {")
        # nocloud gets its hostname from the config drive's meta-data (the VM name),
        # so ALSO setting it here fails Talos validation ("static hostname is already
        # set in v1alpha1 config"). Set it in the config only for the metal path,
        # which has no cloud-init meta-data to supply it.
        if metal:
            L.append(f'        hostname   = "{n["hostname"]}"')
        L.append("        interfaces = [{")
        L.append('          interface = "eth0"')
        L.append(f'          addresses = ["{addr}"]')
        L.append(f'          routes    = [{{ network = "0.0.0.0/0", gateway = "{net["gateway"]}" }}]')
        if vip and role == "controlplane":     # shared API VIP, control-plane only
            L.append(f'          vip       = {{ ip = "{vip}" }}')
        L.append("        }]")
        if net["dns"]:
            servers = ", ".join(f'"{d}"' for d in net["dns"])
            L.append(f"        nameservers = [{servers}]")
        L.append("      }")
        # NTP: replace Talos's public defaults with the given servers so an
        # air-gapped node syncs time from something it can actually reach (no NTP
        # → certs never validate → the cluster never bootstraps).
        if ntp:
            ntps = ", ".join(f'"{s}"' for s in ntp)
            L.append(f"      time = {{ servers = [{ntps}] }}")
        L.append("    }")
        # cluster-wide pod / service CIDRs — patched into EVERY node's config so
        # control-plane and worker agree (the values you'd hand-edit into each file).
        if pod_cidr or svc_cidr:
            L.append("    cluster = {")
            L.append("      network = {")
            if pod_cidr:
                L.append(f'        podSubnets     = ["{pod_cidr}"]')
            if svc_cidr:
                L.append(f'        serviceSubnets = ["{svc_cidr}"]')
            L.append("      }")
            L.append("    }")
        L.append("  })]")
        L.append("}")
        L.append("")
        if metal:
            # EXPERIMENTAL: boot the ISO, blank install disk, no config drive; the
            # config is pushed over the network once the node is up in maintenance
            # mode. `naddr` assumes the node is reachable at its intended IP then
            # (e.g. a DHCP reservation) — surfaced to the user as a requirement.
            naddr = addr.split("/")[0]
            L.append(f'resource "proxmox_virtual_environment_vm" "{rid}" {{')
            L += _prov(n["connection"])
            L.append(f'  name       = "{n["hostname"]}"')
            L.append(f'  node_name  = "{n["node"]}"')
            L.append("  agent { enabled = false }")
            L.append('  boot_order = ["scsi0", "ide2"]')
            L.append("  cpu {")
            L.append(f"    cores = {vcores}")
            L.append('    type  = "host"')
            L.append("  }")
            L.append(f"  memory {{ dedicated = {vmem} }}")
            L.append('  operating_system { type = "l26" }')
            L.append("  cdrom {")
            L.append(f'    file_id   = "{volid}"')
            L.append('    interface = "ide2"')
            L.append("  }")
            L.append("  disk {")
            L.append(f'    datastore_id = "{disk_ds}"')
            L.append('    interface    = "scsi0"')
            L.append(f"    size         = {vdisk}")
            L.append("  }")
            L.append("  network_device {")
            L.append(f'    bridge  = "{net["bridge"]}"')
            if net["vlan"]:
                L.append(f"    vlan_id = {net['vlan']}")
            L.append("  }")
            L.append("}")
            L.append("")
            L.append(f'resource "talos_machine_configuration_apply" "{rid}" {{')
            L.append("  client_configuration        = talos_machine_secrets.this.client_configuration")
            L.append(f"  machine_configuration_input = data.talos_machine_configuration.{rid}.machine_configuration")
            L.append(f'  node                        = "{naddr}"')
            L.append(f'  endpoint                    = "{naddr}"')
            L.append(f"  depends_on                  = [proxmox_virtual_environment_vm.{rid}]")
            L.append("}")
            L.append("")
            continue
        # write that config as the node's nocloud user-data (a snippet)
        L.append(f'resource "proxmox_virtual_environment_file" "cfg_{rid}" {{')
        L += _prov(n["connection"])
        L.append('  content_type = "snippets"')
        L.append(f'  datastore_id = "{snip_ds}"')
        L.append(f'  node_name    = "{n["node"]}"')
        L.append("  source_raw {")
        L.append(f"    data      = data.talos_machine_configuration.{rid}.machine_configuration")
        L.append(f'    file_name = "talos-{n["hostname"]}.yaml"')
        L.append("  }")
        L.append("}")
        L.append("")
        # the VM: the nocloud image as its disk + the config drive carrying the
        # machine-config as user-data, plus a static cloud-init address so the
        # interface is up with no DHCP even before Talos applies its own network.
        L.append(f'resource "proxmox_virtual_environment_vm" "{rid}" {{')
        L += _prov(n["connection"])
        L.append(f'  name      = "{n["hostname"]}"')
        L.append(f'  node_name = "{n["node"]}"')
        L.append("  cpu {")
        L.append(f"    cores = {vcores}")
        L.append('    type  = "host"')
        L.append("  }")
        L.append(f"  memory {{ dedicated = {vmem} }}")
        L.append('  operating_system { type = "l26" }')
        L.append("  disk {")
        L.append(f'    datastore_id = "{disk_ds}"')
        L.append(f'    import_from  = {imp(n["connection"], n["node"])}')
        L.append('    interface    = "scsi0"')
        L.append(f"    size         = {vdisk}")
        L.append("  }")
        L.append("  network_device {")
        L.append(f'    bridge  = "{net["bridge"]}"')
        if net["vlan"]:
            L.append(f"    vlan_id = {net['vlan']}")
        L.append("  }")
        L.append("  initialization {")
        L.append(f'    datastore_id      = "{disk_ds}"')
        L.append(f"    user_data_file_id = proxmox_virtual_environment_file.cfg_{rid}.id")
        L.append("    ip_config {")
        L.append("      ipv4 {")
        L.append(f'        address = "{addr}"')
        L.append(f'        gateway = "{net["gateway"]}"')
        L.append("      }")
        L.append("    }")
        if net["dns"]:
            servers = ", ".join(f'"{d}"' for d in net["dns"])
            L.append(f"    dns {{ servers = [{servers}] }}")
        L.append("  }")
        L.append("}")
        L.append("")

    cp = _id(controlplanes[0]["hostname"])
    cp_ip = controlplanes[0]["ip"].split("/")[0]
    L.append('resource "talos_machine_bootstrap" "this" {')
    L.append("  client_configuration = talos_machine_secrets.this.client_configuration")
    L.append(f'  node                 = "{cp_ip}"')
    L.append("  # waits for the CP to be configured; the provider retries until its API answers")
    _cp_dep = f"talos_machine_configuration_apply.{cp}" if metal else f"proxmox_virtual_environment_vm.{cp}"
    L.append(f"  depends_on           = [{_cp_dep}]")
    L.append("}")
    L.append("")
    L.append('resource "talos_cluster_kubeconfig" "this" {')
    L.append("  client_configuration = talos_machine_secrets.this.client_configuration")
    L.append(f'  node                 = "{cp_ip}"')
    L.append("  depends_on           = [talos_machine_bootstrap.this]")
    L.append("}")
    L.append("")
    L.append('output "talosconfig" {')
    L.append("  value     = data.talos_client_configuration.this.talos_config")
    L.append("  sensitive = true")
    L.append("}")
    L.append('output "kubeconfig" {')
    L.append("  value     = talos_cluster_kubeconfig.this.kubeconfig_raw")
    L.append("  sensitive = true")
    L.append("}")
    return {"body": "\n".join(L), "tfvars": ""}


def _gen_iso(spec: dict, aliases: dict) -> dict:
    """AlmaLinux (and any RHEL-family ISO): boot the installer ISO onto an empty
    disk, with a per-VM OEMDRV disk carrying the kickstart, so Anaconda installs
    unattended with a static network — no cloud image, no internet. The install
    ISO is the one picked from the datastore; create() builds + uploads each VM's
    OEMDRV and fills in its volume id."""
    cat = CATALOG[spec["os"]]
    disk_ds = spec.get("disk_datastore") or "local-lvm"
    img_ds = spec.get("image_datastore") or "local"
    cores = int(spec.get("cores") or cat["cores"])
    mem = int(spec.get("mem_mb") or cat["mem_mb"])
    disk_gb = int(spec.get("disk_gb") or cat["disk_gb"])
    install_iso = (spec.get("image_volid") or "").strip()
    nodes = spec["nodes"]

    L: list[str] = []
    L.append("terraform {")
    L.append('  required_providers { proxmox = { source = "bpg/proxmox", version = "~> 0.60" } }')
    L.append("}")
    L += _provider_defs(aliases)
    L.append(f'# {cat["label"]} — unattended install from {install_iso} via kickstart (OEMDRV).')
    L.append("")
    for n in nodes:
        rid = _id(n["hostname"])
        vcores = int(n.get("cores") or cores)
        vmem = int(n.get("mem_mb") or mem)
        vdisk = int(n.get("disk_gb") or disk_gb)
        oemdrv = n.get("_oemdrv_volid") or f"{img_ds}:import/oemdrv-{rid}.raw"
        L.append(f'resource "proxmox_virtual_environment_vm" "{rid}" {{')
        if aliases:
            L.append(f"  provider  = proxmox.{aliases[n['connection']]}")
        L.append(f'  name      = "{n["hostname"]}"')
        L.append(f'  node_name = "{n["node"]}"')
        L.append('  operating_system { type = "l26" }')
        # No guest agent to wait for. bpg blocks VM creation on the agent when it
        # is enabled, but the unattended installer may not carry qemu-guest-agent
        # (absent from the minimal ISO, and the node is air-gapped). Terraform's
        # job is done once the VM is provisioned + started; the OS install then
        # runs to completion on its own inside the guest.
        L.append("  agent { enabled = false }")
        L.append("  cpu {")
        L.append(f"    cores = {vcores}")
        L.append('    type  = "host"')
        L.append("  }")
        L.append(f"  memory {{ dedicated = {vmem} }}")
        L.append("  disk {")
        L.append(f'    datastore_id = "{disk_ds}"')
        L.append('    interface    = "scsi0"')
        L.append(f"    size         = {vdisk}")
        L.append("  }")
        L.append("  cdrom {")            # the installer ISO (bpg allows only one cdrom)
        L.append(f'    file_id   = "{install_iso}"')
        L.append('    interface = "ide2"')
        L.append("  }")
        L.append("  disk {")             # the kickstart, on an OEMDRV-labelled disk
        L.append(f'    datastore_id = "{disk_ds}"')
        L.append(f'    import_from  = "{oemdrv}"')
        L.append('    interface    = "scsi1"')
        L.append("    size         = 1")
        L.append("  }")
        net = _net_of(spec, n)
        L.append("  network_device {")
        L.append(f'    bridge  = "{net["bridge"]}"')
        if net["vlan"]:
            L.append(f"    vlan_id = {net['vlan']}")
        L.append("  }")
        # disk first: a blank scsi0 isn't bootable so the firmware falls through to
        # the installer CD for the unattended install, but once Anaconda has written
        # the OS the disk boots and the CD is never reached again — CD-first would
        # re-launch the installer on every reboot (an endless reinstall loop).
        L.append('  boot_order = ["scsi0", "ide2"]')
        L.append("}")
        L.append("")
    return {"body": "\n".join(L), "tfvars": ""}


def _id(s: str) -> str:
    """A Terraform resource identifier from a hostname/node — letters, digits and
    underscores, never starting with a digit."""
    out = re.sub(r"[^A-Za-z0-9_]", "_", s or "")
    return ("n_" + out) if not out or out[0].isdigit() else out


# ══ create: spec → a real stack (reusing the connections' creds) ══
def _spec_for_store(spec: dict) -> str:
    """The wizard answers to persist for 'Edit in wizard' — WITHOUT the OS
    password (a secret never lands in the DB in the clear; it is re-entered on an
    edit) and without the internal OEMDRV volume ids that staging adds."""
    keep = {k: v for k, v in spec.items() if k not in ("os_password", "stack_id")}
    keep["nodes"] = [{k: v for k, v in (n or {}).items() if not k.startswith("_")}
                     for n in spec.get("nodes", [])]
    return json.dumps(keep, separators=(",", ":"))


def stored_spec(sid: str) -> dict | None:
    """The persisted wizard spec for a stack, or None if it was not wizard-made
    (or was since hand-edited away). Used to pre-fill the wizard for an edit."""
    st = terraform.stack(sid) or {}
    raw = st.get("spec_json") or ""
    if not raw:
        return None
    try:
        spec = json.loads(raw)
    except (ValueError, TypeError):
        return None
    spec["stack_id"] = sid                     # so a re-save edits in place
    spec["stack_name"] = st.get("name", "")
    return spec


def _stage_oemdrv(spec: dict) -> None:
    """For the ISO method: build each VM's kickstart, wrap it in an OEMDRV ISO,
    and upload it (a few hundred KB — no slow-link problem) to that VM's node, so
    the installer finds its answer file locally. Fills n['_oemdrv_volid']."""
    pwhash = _hash_password(spec.get("os_password", ""))
    img_ds = spec.get("image_datastore") or "local"
    clients: dict = {}
    try:
        for n in spec["nodes"]:
            sid = n["connection"]
            px = clients.get(sid) or clients.setdefault(sid, client_for(sid))
            # a disk's import_from source must be `import`/`images` content, not
            # `iso` — so upload the OEMDRV into the datastore's import area. The
            # import content type whitelists `.raw` (not `.img`, which it 400s);
            # the OEMDRV bytes are a raw ISO9660 image, so `.raw` is honest.
            name = f"oemdrv-{_id(n['hostname'])}.raw"
            volid = f"{img_ds}:import/{name}"
            iso = _build_oemdrv(_kickstart(spec, n, pwhash))
            try:
                # re-generating a stack for the same host re-uploads this file;
                # Proxmox refuses an upload that already exists, so clear it first
                try:
                    px.delete_content(n["node"], img_ds, volid)
                except ProxmoxError:
                    pass
                try:
                    px.upload(n["node"], img_ds, name, iso, content="import")
                except ProxmoxError as e:
                    # the kickstart rides an OEMDRV disk imported from `import`
                    # content — a type stock Proxmox does not enable on `local`.
                    # Lead with the real Proxmox error, then name that requirement
                    # so a content-type rejection is actionable rather than opaque.
                    raise Refused(
                        f"couldn't stage the kickstart on '{img_ds}' ({n['node']}): {e}. "
                        f"The unattended install delivers its answer file on the "
                        f"datastore's 'import' content; if that was rejected, enable "
                        f"Import on '{img_ds}' under Datacenter → Storage (Proxmox "
                        f"8.2+), or choose a datastore that has it.") from e
            finally:
                shutil.rmtree(os.path.dirname(iso), ignore_errors=True)
            n["_oemdrv_volid"] = volid
    finally:
        for px in clients.values():
            px.close()


def create(spec: dict, who: str) -> str:
    """Generate and persist a stack from the wizard spec. For a SINGLE Proxmox the
    connection's sealed credential is copied ciphertext-to-ciphertext (never
    unsealed). For SEVERAL, each connection's credential is unsealed in-process
    and re-sealed as per-alias `TF_VAR_*` variables that the aliased providers
    read — the secrets are never returned to a page or written in the clear.
    Returns the new stack id."""
    spec = _validate(spec)                     # normalise connections + hostnames
    # post-provision Ansible: bake a fresh PUBLIC key into the VM (so it is
    # key-reachable at boot) and keep the private half to run the playbook with.
    # Must happen BEFORE _stage_oemdrv/generate, which read spec["ssh_key"].
    ansible_priv, pb_id = "", (spec.get("ansible_playbook") or "").strip()
    if pb_id:
        from .ansible import playbook as _pb
        if not _pb(pb_id):
            raise Refused("the chosen Ansible playbook no longer exists")
        ansible_priv, pub = new_keypair()
        spec["ssh_key"] = pub                  # planted via cloud-init / kickstart
    if (spec.get("method") or "cloud") == "iso" and CATALOG[spec["os"]]["family"] != "talos":
        _stage_oemdrv(spec)                    # build + upload each VM's kickstart
    gen = generate(spec)                       # validates + normalises connections
    conns = _conns(spec)
    aliases = _alias_map(spec)
    primary = terraform._stack_raw(conns[0])
    if not primary:
        raise Refused("that Proxmox connection is gone")

    name = (spec.get("stack_name") or "").strip()
    if not name:
        first = spec["nodes"][0]["hostname"]
        name = f"{CATALOG[spec['os']]['family']}-{first}"
    fields = {
        "name": name,
        "provider": "proxmox",
        "body": gen["body"],
        "tfvars": gen["tfvars"],
        "notes": (spec.get("notes")
                  or f"Provisioned: {CATALOG[spec['os']]['label']} · "
                     f"{len(spec['nodes'])} VM(s)"
                     + (f" across {len(conns)} Proxmox" if len(conns) > 1 else "")),
        "env": (spec.get("env") or "").strip(),
        "pid": primary.get("proj_id", ""),
        "rgid": primary.get("rgn_id", ""),
        "spec_json": _spec_for_store(spec),   # so it can be re-edited in the wizard
    }
    if spec.get("is_prod"):
        fields["is_prod"] = "1"
    # an existing id means "edit in wizard": regenerate this stack in place rather
    # than making a new one (save_stack UPDATEs when the id exists).
    sid = terraform.save_stack((spec.get("stack_id") or "").strip(), fields, who)

    if not aliases:
        # one Proxmox: copy the sealed credential verbatim, never unsealed
        sealed = primary.get("creds_sealed") or ""
    else:
        # several Proxmox: unseal each connection, re-key its credential to the
        # alias's TF_VAR_* names, and seal the merged block
        lines: list[str] = []
        for csid, a in aliases.items():
            if not terraform._stack_raw(csid):
                raise Refused("one of the Proxmox connections is gone")
            cd = _creds_of(csid)
            insec = "true" if (cd.get("PROXMOX_VE_INSECURE", "").lower()
                               in ("1", "true", "yes")) else "false"
            p = f"pve_{a}"
            lines += [f"TF_VAR_{p}_endpoint={cd.get('PROXMOX_VE_ENDPOINT', '')}",
                      f"TF_VAR_{p}_insecure={insec}",
                      f"TF_VAR_{p}_api_token={cd.get('PROXMOX_VE_API_TOKEN', '')}",
                      f"TF_VAR_{p}_username={cd.get('PROXMOX_VE_USERNAME', '')}",
                      f"TF_VAR_{p}_password={cd.get('PROXMOX_VE_PASSWORD', '')}"]
        sealed = secretbox.seal("\n".join(lines))

    with db.tx() as c:
        c.execute("UPDATE tf_stacks SET creds_sealed = ? WHERE id = ?", (sealed, sid))
    if pb_id and ansible_priv:
        set_ansible(sid, pb_id, ansible_priv, (spec.get("os_user") or "").strip())
    return sid
