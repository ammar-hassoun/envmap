#!/usr/bin/env python3
"""Provision: the "new VM" wizard that GENERATES a Terraform stack.

WHY THIS EXISTS
    The wizard never provisions directly — it turns a spec into a `.tf` stack the
    Terraform engine then runs. The load-bearing facts:

      1. **The generated HCL is correct and static-networked.** AlmaLinux uses a
         cloud-image + cloud-init static IP; Talos uses a nocloud image whose
         machine-config is delivered on a config drive (a snippet as user-data) —
         never the over-the-network `talos_machine_configuration_apply`, which
         would need a not-yet-reachable node (the no-DHCP chicken-and-egg).
      2. **The Talos image is pulled as zstd**, because bpg's download_file cannot
         decompress the factory's default xz.
      3. **A spec is validated, not trusted** — hostnames, unique names/addresses,
         IP/CIDR, gateway, DNS, and Talos needing a version + a control-plane.
      4. **One run can span several Proxmox.** When the VMs target more than one
         connection, the stack gets ALIASED providers (one per Proxmox) and every
         resource is pinned to its own; a single-Proxmox run stays byte-identical
         to the default-provider path.
      5. **Credentials are never exposed.** One Proxmox → the sealed credential is
         copied ciphertext-to-ciphertext. Several → each is unsealed in-process
         and re-sealed as per-alias `TF_VAR_*`, never in the HCL or a page.

    ./.venv/bin/python tests/test_provision.py
"""
from __future__ import annotations

import copy
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("prov-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import db, provision, secretbox, terraform as tf      # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def _raises(what: str, fn) -> None:
    try:
        fn()
        check(f"{what} — it was ALLOWED", False)
    except provision.Refused:
        pass


# _validate stamps each node with its connection, so hand every call a FRESH copy.
_ALMA = {
    "os": "almalinux-10", "connection": "ts-x", "bridge": "vmbr0",
    "gateway": "10.0.10.1", "dns": ["10.0.10.196", "10.0.10.197"],
    "ssh_key": "ssh-ed25519 AAAAKEY user@lab",
    "nodes": [{"hostname": "alma-1", "node": "pve01", "ip": "10.0.10.60/24"}],
}
_TALOS = {
    "os": "talos", "connection": "ts-x", "bridge": "vmbr0",
    "talos_version": "1.13.8", "cluster_name": "lab", "snippet_datastore": "local",
    "gateway": "10.0.10.1", "dns": ["10.0.10.196"],
    "nodes": [{"hostname": "talos-cp-1", "node": "pve01",
               "ip": "10.0.10.70/24", "role": "controlplane"}],
}


def A(**kw):
    return {**copy.deepcopy(_ALMA), **kw}


def T(**kw):
    return {**copy.deepcopy(_TALOS), **kw}


def main() -> int:
    print("the catalog offers AlmaLinux + the cloud distros + Talos; Talos alone needs a version")
    keys = {c["key"] for c in provision.os_choices()}
    check("AlmaLinux and Talos present", {"almalinux-10", "almalinux-8", "talos"} <= keys)
    nv = {c["key"]: c["needs_version"] for c in provision.os_choices()}
    check("only Talos needs a version", nv["talos"] and not nv["almalinux-10"])

    print("AlmaLinux generates a cloud-init static-IP VM, no xz anywhere")
    a = provision.generate(A())["body"]
    check("downloads the cloud image into iso content (accepts a .img; import 400s it)",
          'proxmox_virtual_environment_download_file' in a and 'content_type = "iso"' in a)
    check("static cloud-init address, gateway and dns",
          'address = "10.0.10.60/24"' in a and 'gateway = "10.0.10.1"' in a
          and '"10.0.10.196"' in a)
    check("the login key rides in cloud-init", 'user_account' in a and 'AAAAKEY' in a)
    check("no xz, no talos in a cloud image", 'xz' not in a and 'talos' not in a)

    print("Talos delivers config on a drive (nocloud), not over the network")
    t = provision.generate(T())["body"]
    check("pulls the zstd image, decompresses zst",
          'nocloud-amd64.raw.zst' in t and 'decompression_algorithm = "zst"' in t)
    check("writes the machine-config as a snippet (user-data)",
          'content_type = "snippets"' in t
          and 'data.talos_machine_configuration.talos_cp_1.machine_configuration' in t)
    check("the VM carries that config drive",
          'user_data_file_id = proxmox_virtual_environment_file.cfg_talos_cp_1.id' in t)
    check("NO over-the-network apply (the chicken-and-egg)",
          'talos_machine_configuration_apply' not in t)
    check("it bootstraps and yields a kubeconfig",
          'talos_machine_bootstrap' in t and 'talos_cluster_kubeconfig' in t)
    check("the static network patch is in the config (nocloud: no hostname — the "
          "config drive sets it; see the NTP/hostname test below)",
          'addresses = ["10.0.10.70/24"]' in t and 'hostname   =' not in t)

    print("a spec is validated, not trusted")
    _raises("no OS", lambda: provision.generate(A(os="")))
    _raises("no connection", lambda: provision.generate(A(connection="")))
    _raises("no VMs", lambda: provision.generate(A(nodes=[])))
    _raises("a bad hostname", lambda: provision.generate(
        A(nodes=[{"hostname": "Bad Host", "node": "pve01", "ip": "10.0.0.5/24"}])))
    _raises("a node with no destination", lambda: provision.generate(
        A(nodes=[{"hostname": "a1", "node": "", "ip": "10.0.0.5/24"}])))
    _raises("a malformed address", lambda: provision.generate(
        A(nodes=[{"hostname": "a1", "node": "pve01", "ip": "not-an-ip"}])))
    _raises("two VMs with the same address", lambda: provision.generate(A(nodes=[
        {"hostname": "a1", "node": "pve01", "ip": "10.0.0.5/24"},
        {"hostname": "a2", "node": "pve01", "ip": "10.0.0.5/24"}])))
    _raises("a bad gateway", lambda: provision.generate(A(gateway="nope")))
    _raises("Talos without a version", lambda: provision.generate(T(talos_version="")))
    _raises("a Talos cluster with no control-plane", lambda: provision.generate(
        T(nodes=[{"hostname": "w1", "node": "pve01", "ip": "10.0.0.9/24", "role": "worker"}])))

    print("image file names and resource ids are derived safely")
    check("Talos image name carries the version",
          provision.image_file_name("talos", "1.13.8") == "talos-1.13.8-nocloud-amd64.raw")
    check("a resource id never starts with a digit", provision._id("1-cp")[0] == "n")
    check("a hostname becomes a legal id", provision._id("alma-1") == "alma_1")

    print("a single Proxmox stays on the default provider (unchanged path)")
    s1 = provision.generate(A())["body"]
    check("default provider, no aliases", 'provider "proxmox" {}' in s1 and "alias" not in s1)
    check("image id is bare per-node", "img_pve01" in s1 and "img_c1_" not in s1)

    print("several Proxmox in ONE run → aliased providers, per-VM pinning")
    multi = A(nodes=[
        {"hostname": "ke-1", "node": "pve01", "ip": "10.0.10.60/24", "connection": "ts-KE"},
        {"hostname": "ke-2", "node": "pve02", "ip": "10.0.10.61/24", "connection": "ts-KE"},
        {"hostname": "tz-1", "node": "pve01", "ip": "10.0.20.60/24", "connection": "ts-TZ"},
    ])
    del multi["connection"]
    mb = provision.generate(multi)["body"]
    check("one aliased provider per Proxmox", mb.count("alias     =") == 2 and 'provider "proxmox" {}' not in mb)
    check("each Proxmox has its own credential variables",
          'variable "pve_c1_endpoint"' in mb and 'variable "pve_c2_api_token"' in mb)
    check("every VM is pinned to its Proxmox",
          "provider  = proxmox.c1" in mb and "provider  = proxmox.c2" in mb)
    check("image downloads are per (Proxmox, node)",
          "img_c1_pve01" in mb and "img_c1_pve02" in mb and "img_c2_pve01" in mb)

    print("image source: override URL, or skip the download for an air-gapped node")
    over = provision.generate(A(image_url="https://mirror.local/alma.qcow2"))["body"]
    check("an override URL replaces the public one",
          "https://mirror.local/alma.qcow2" in over and "download_file" in over)
    pre = provision.generate(A(image_present=True))["body"]
    check("skip-download emits NO download resource",
          "proxmox_virtual_environment_download_file" not in pre)
    check("the VM clones the pre-uploaded volume (iso content, .img)",
          'import_from  = "local:iso/almalinux-10-cloudimg-amd64.img"' in pre)
    pre2 = provision.generate(A(image_present=True, image_volid="local:import/x.img"))["body"]
    check("an explicit volume id is honoured", 'import_from  = "local:import/x.img"' in pre2)

    print("ISO + kickstart: unattended install from an existing ISO")
    ib = provision.generate({"os": "almalinux-10", "method": "iso", "connection": "x",
        "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "os_user": "ammar", "ssh_key": "ssh-ed25519 K",
        "image_volid": "local:iso/alma.iso",
        "nodes": [{"hostname": "a1", "node": "pve01", "ip": "10.0.0.5/24"}]})["body"]
    # the OEMDRV disk imports from `import` content as a `.raw` — Proxmox rejects
    # an `iso`-content volid as a disk import source (needs images/import), and
    # its import upload 400s a `.img`, so both the content and the extension matter.
    check("one cdrom (installer) + OEMDRV as an import/.raw disk, no clone/download",
          ib.count("cdrom {") == 1 and 'import_from  = "local:import/oemdrv-a1.raw"' in ib
          and "boot_order" in ib and "download_file" not in ib and "import_from  = proxmox" not in ib)
    # the guest agent is disabled for the ISO method: bpg blocks VM creation on
    # the agent, and the installer may not carry qemu-guest-agent (air-gapped
    # minimal ISO) — so waiting for it would hang, then fail, the apply.
    check("ISO VM does not wait on a guest agent", "agent { enabled = false }" in ib)
    ks = provision._kickstart({"gateway": "10.0.0.1", "dns": ["1.1.1.1", "1.0.0.1"],
        "os_user": "ammar", "ssh_key": "ssh-ed25519 K"},
        {"hostname": "a1", "ip": "10.0.0.5/24"}, "$6$abc$def")
    check("kickstart: static net, only-use sda, user + key, hashed root",
          "--bootproto=static --ip=10.0.0.5 --netmask=255.255.255.0" in ks
          and "ignoredisk --only-use=sda" in ks and "user --name=ammar" in ks
          and 'sshkey --username=ammar "ssh-ed25519 K"' in ks
          and "rootpw --iscrypted $6$abc$def" in ks)
    # a missing package must never open Anaconda's interactive continue-prompt —
    # that hangs an unattended install; --ignoremissing skips it silently.
    check("kickstart tolerates missing packages (no interactive prompt)",
          "%packages --ignoremissing" in ks)
    check("the password hashes to sha512-crypt", provision._hash_password("x").startswith("$6$"))
    check("method dispatch: cloud clones, iso installs",
          "import_from" in provision.generate({"os": "almalinux-10", "connection": "x",
              "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "image_present": True,
              "image_volid": "local:iso/x.img",
              "nodes": [{"hostname": "a1", "node": "pve01", "ip": "10.0.0.5/24"}]})["body"])

    print("create() copies one credential verbatim, merges several into TF_VARs")
    connA = tf.save_stack("", {"name": "pve-ke", "provider": "proxmox", "env": "prod",
        "body": 'provider "proxmox" {}', "creds":
        "PROXMOX_VE_ENDPOINT=https://10.0.10.11:8006/\nPROXMOX_VE_API_TOKEN=root@pam!p=SEK-A"}, "adm")
    connB = tf.save_stack("", {"name": "pve-tz", "provider": "proxmox", "env": "prod",
        "body": 'provider "proxmox" {}', "creds":
        "PROXMOX_VE_ENDPOINT=https://10.0.30.11:8006/\nPROXMOX_VE_API_TOKEN=root@pam!p=SEK-B"}, "adm")

    # single: verbatim ciphertext copy
    sid1 = provision.create(A(connection=connA, stack_name="one-pve"), "adm")
    row1 = db.q("SELECT body, creds_sealed FROM tf_stacks WHERE id=?", (sid1,))[0]
    src = db.q("SELECT creds_sealed FROM tf_stacks WHERE id=?", (connA,))[0]["creds_sealed"]
    check("one Proxmox → default provider + verbatim credential",
          'provider "proxmox" {}' in row1["body"] and row1["creds_sealed"] == src)
    check("the secret never lands in the HCL", "SEK-A" not in row1["body"])

    # several: merged TF_VAR credentials, sealed
    sid2 = provision.create(A(nodes=[
        {"hostname": "ke-1", "node": "pve01", "ip": "10.0.10.60/24", "connection": connA},
        {"hostname": "tz-1", "node": "pve01", "ip": "10.0.30.60/24", "connection": connB},
    ], stack_name="two-pve"), "adm")
    row2 = db.q("SELECT body, creds_sealed FROM tf_stacks WHERE id=?", (sid2,))[0]
    merged = secretbox.unseal(row2["creds_sealed"])
    check("both Proxmox endpoints are keyed by alias in TF_VARs",
          "TF_VAR_pve_c1_endpoint=https://10.0.10.11:8006/" in merged
          and "TF_VAR_pve_c2_endpoint=https://10.0.30.11:8006/" in merged)
    check("both tokens are carried, but only in the sealed block",
          "SEK-A" in merged and "SEK-B" in merged
          and "SEK-A" not in row2["body"] and secretbox.sealed(row2["creds_sealed"]))
    check("the stack view still hides the credential",
          "creds_sealed" not in (tf.stack(sid2) or {}) and tf.stack(sid2)["has_creds"])

    print("quick-launch recipes + inventory helpers")
    rk = {p["key"] for p in provision.presets()}
    check("the core recipes exist, each fixing os + method + resources",
          {"alma10", "alma8", "talos"} <= rk
          and all(p.get("os") and p.get("method") and p.get("cores") for p in provision.presets()))
    check("env is read from a VM tag, else it falls back to the connection env",
          provision._env_from(["web", "prod"], "dev") == "prod"
          and provision._env_from(["web"], "preprod") == "preprod"
          and provision._env_from([], "") == "")
    check("a Provisioned note (or a saved spec) marks a generated stack",
          provision._is_generated({"notes": "Provisioned: AlmaLinux 10 · 1 VM(s)"})
          and provision._is_generated({"has_spec": True})
          and not provision._is_generated({"notes": "the KE cluster"}))

    print("cluster_vms normalises one API call; dedupe collapses a shared cluster")
    px = provision.Proxmox("https://x:8006/", token="t", insecure=True)
    px._get = lambda path: [
        {"vmid": 100, "name": "app-1", "node": "pve01", "type": "qemu", "status": "running",
         "maxcpu": 4, "maxmem": 8 * 1024**3, "maxdisk": 40 * 1024**3, "uptime": 99,
         "tags": "prod;web", "pool": "app"},
        {"vmid": 101, "name": "ct-1", "node": "pve02", "type": "lxc", "status": "stopped",
         "maxcpu": 1, "maxmem": 512 * 1024**2, "maxdisk": 8 * 1024**3, "template": 0}]
    fleet = px.cluster_vms()
    check("cluster_vms parses one call into normalised VMs",
          len(fleet) == 2 and fleet[0]["cores"] == 4 and fleet[0]["mem_gb"] == 8.0
          and fleet[0]["tags"] == ["prod", "web"] and fleet[1]["kind"] == "lxc")
    saved = provision._creds_of
    provision._creds_of = lambda sid: {"PROXMOX_VE_ENDPOINT":
        {"a": "https://10.0.0.1:8006/", "b": "https://10.0.0.1:8006",
         "c": "https://10.0.0.2:8006/"}[sid]}
    try:
        reps = provision._dedupe_by_endpoint([
            {"id": "a", "name": "gen", "has_spec": True, "notes": "Provisioned: x"},
            {"id": "b", "name": "real-conn", "has_spec": False, "notes": "the cluster"},
            {"id": "c", "name": "other", "has_spec": False, "notes": ""}])
        by = {r["id"]: r["name"] for r in reps}
        check("stacks sharing an endpoint collapse to one; a different endpoint stays",
              len(reps) == 2 and "c" in by)
        check("the real connection wins the name over a generated stack", by.get("b") == "real-conn")
    finally:
        provision._creds_of = saved

    print("nodes_detail reads a cluster in one call, falls back for a standalone host")
    pxn = provision.Proxmox("https://x:8006/", token="t", insecure=True)
    pxn._get = lambda p: ([{"node": "pve01", "status": "online", "maxcpu": 40, "cpu": 0.1,
        "maxmem": 270 * 1024**3, "mem": 54 * 1024**3, "maxdisk": 100 * 1024**3,
        "disk": 6 * 1024**3, "uptime": 99}] if p == "/cluster/resources?type=node" else [])
    nd = pxn.nodes_detail()
    check("a cluster node is parsed with live cpu / mem / disk",
          len(nd) == 1 and nd[0]["cpu_cores"] == 40 and nd[0]["cpu_pct"] == 10.0
          and nd[0]["mem_pct"] == 20 and nd[0]["disk_free_gb"] == 94.0)

    def _standalone(p):
        if p == "/cluster/resources?type=node":
            return []                                  # a lone host: no cluster resources
        if p == "/nodes":
            return [{"node": "solo", "status": "online"}]
        if p == "/nodes/solo/status":
            return {"cpuinfo": {"cpus": 8}, "cpu": 0.5,
                    "memory": {"total": 16 * 1024**3, "used": 8 * 1024**3},
                    "rootfs": {"total": 200 * 1024**3, "used": 50 * 1024**3}, "uptime": 5}
        return []
    pxn._get = _standalone
    nd2 = pxn.nodes_detail()
    check("a standalone host lists via /nodes + /status",
          len(nd2) == 1 and nd2[0]["node"] == "solo" and nd2[0]["cpu_cores"] == 8
          and nd2[0]["cpu_pct"] == 50.0 and nd2[0]["mem_pct"] == 50 and nd2[0]["disk_free_gb"] == 150.0)
    counts = provision._host_counts([
        {"online": True, "cpu_cores": 40, "mem_gb": 250, "mem_free_gb": 200, "disk_free_gb": 80, "vms": 4},
        {"online": False, "cpu_cores": 40, "mem_gb": 250, "mem_free_gb": 200, "disk_free_gb": 80, "vms": 1}])
    check("host counts total cores over all, free only over online",
          counts["nodes"] == 2 and counts["online"] == 1 and counts["vcpu"] == 80
          and counts["mem_free_gb"] == 200 and counts["vms"] == 5)

    print("a wizard stack remembers its spec and edits in place (no HCL)")
    sidE = provision.create(A(connection=connA, stack_name="edit-me",
                              os_user="ammar", os_password="p@ssw0rd"), "adm")
    raw = db.q("SELECT spec_json FROM tf_stacks WHERE id=?", (sidE,))[0]["spec_json"]
    check("the spec is persisted WITHOUT the OS password",
          raw and "p@ssw0rd" not in raw)
    back = provision.stored_spec(sidE)
    check("stored_spec round-trips, carries the stack id, drops the password",
          back and back["stack_id"] == sidE and back["os_user"] == "ammar"
          and "os_password" not in back)
    before = db.q("SELECT COUNT(*) AS n FROM tf_stacks")[0]["n"]
    sidE2 = provision.create({**back, "cores": 8}, "adm")
    after = db.q("SELECT COUNT(*) AS n FROM tf_stacks")[0]["n"]
    check("re-saving the spec edits the SAME stack, not a new one",
          sidE2 == sidE and after == before)
    stored = provision._spec_for_store(A(os_password="s3cret",
        nodes=[{"hostname": "a1", "node": "pve01", "ip": "10.0.0.5/24",
                "_oemdrv_volid": "local:import/x.raw"}]))
    check("_spec_for_store strips the password and the internal OEMDRV key",
          "s3cret" not in stored and "_oemdrv_volid" not in stored and "a1" in stored)

    print("add-host: endpoint normalises, a sealed connection stack is created")
    check("endpoint normalises to base https with :8006 and no /api2/json",
          provision._norm_endpoint("10.0.0.5") == "https://10.0.0.5:8006"
          and provision._norm_endpoint("https://pve:8006/api2/json/") == "https://pve:8006")
    hid = provision.add_host({"name": "pve-new", "endpoint": "10.9.9.9",
        "api_token": "root@pam!portal=SEK-TOK", "insecure": True}, "adm")
    hrow = db.q("SELECT provider, body, creds_sealed FROM tf_stacks WHERE id=?", (hid,))[0]
    check("add_host makes a proxmox connection stack; the token never lands in the body",
          hrow["provider"] == "proxmox" and 'provider "proxmox" {}' in hrow["body"]
          and hrow["creds_sealed"] and "SEK-TOK" not in hrow["body"])
    merged = secretbox.unseal(hrow["creds_sealed"])
    check("the sealed block carries the normalised endpoint + token + insecure",
          "PROXMOX_VE_ENDPOINT=https://10.9.9.9:8006" in merged
          and "PROXMOX_VE_API_TOKEN=root@pam!portal=SEK-TOK" in merged
          and "PROXMOX_VE_INSECURE=true" in merged)
    check("the new host now shows up as a cluster/connection",
          any(c["id"] == hid for c in provision.clusters()))
    _raises("add_host with no credential is refused",
            lambda: provision.add_host({"name": "x", "endpoint": "1.2.3.4"}, "adm"))
    _raises("add_host with no endpoint is refused",
            lambda: provision.add_host({"name": "x", "api_token": "t"}, "adm"))
    _raises("delete_iso refuses a volid that is not on the datastore",
            lambda: provision.delete_iso("ts-x", "pve01", "local", "other:iso/x.iso"))

    print("host detail lists a node's guests; a connection can be removed from the portal")
    pxg = provision.Proxmox("https://x:8006/", token="t", insecure=True)
    pxg._get = lambda p: ([{"vmid": 100, "name": "a", "status": "running", "cpus": 4,
        "maxmem": 8 * 1024**3, "maxdisk": 40 * 1024**3}] if p.endswith("/qemu")
        else [{"vmid": 101, "name": "ct", "status": "stopped", "cpus": 1,
        "maxmem": 512 * 1024**2, "maxdisk": 8 * 1024**3}] if p.endswith("/lxc") else [])
    g = pxg.node_guests("pve01")
    check("node_guests lists qemu + lxc for a node",
          len(g) == 2 and g[0]["kind"] == "qemu" and g[0]["cores"] == 4 and g[1]["kind"] == "lxc")
    rid = provision.add_host({"name": "pve-rm", "endpoint": "10.7.7.7", "api_token": "root@pam!x=Y"}, "adm")
    check("remove_connection deletes the connection stack (portal only)",
          provision.remove_connection(rid) and not tf._stack_raw(rid))
    _raises("remove_connection on a vanished stack is refused",
            lambda: provision.remove_connection(rid))
    nid = tf.save_stack("", {"name": "aws-thing", "provider": "aws", "body": "# x"}, "adm")
    _raises("remove_connection refuses a non-Proxmox stack",
            lambda: provision.remove_connection(nid))

    print("console: a one-time session is minted (vncproxy) and consumed single-use")
    saved_cf = provision.client_for

    class _FakePx:
        def vncproxy(self, node, vmid):
            return {"ticket": "VNC-TICKET", "port": 5901}
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    provision.client_for = lambda sid: _FakePx()
    try:
        o = provision.console_open("ts-x", "pve01", 116)
        check("console_open returns a session id + the RFB ticket",
              o.get("session") and o["ticket"] == "VNC-TICKET")
        took = provision.console_take(o["session"])
        check("console_take consumes the session once, then it is gone",
              took and took["port"] == 5901 and provision.console_take(o["session"]) is None)
    finally:
        provision.client_for = saved_cf

    print("per-node network: a VM's own gateway / vlan / dns override the shared default")
    pn = provision.generate({"os": "almalinux-10", "method": "iso", "connection": "x",
        "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "os_user": "a", "bridge": "vmbr0", "vlan": "10",
        "image_volid": "local:iso/x.iso", "nodes": [
            {"hostname": "a1", "node": "pve01", "ip": "10.0.0.5/24"},
            {"hostname": "a2", "node": "pve02", "ip": "10.9.9.5/24",
             "gateway": "10.9.9.1", "vlan": "99", "dns": ["9.9.9.9"]}]})["body"]
    ks2 = provision._kickstart({"gateway": "10.0.0.1", "dns": ["1.1.1.1"], "os_user": "a"},
        {"hostname": "a2", "ip": "10.9.9.5/24", "gateway": "10.9.9.1", "dns": ["9.9.9.9"]}, "")
    check("a2 carries its own vlan while a1 keeps the shared one",
          "vlan_id = 99" in pn and "vlan_id = 10" in pn)
    check("a2's kickstart uses its own gateway + dns",
          "--gateway=10.9.9.1" in ks2 and "--nameserver=9.9.9.9" in ks2)

    print("Talos cluster CIDRs: pod + service subnets patched into every node's config")
    tz = provision.generate(T(pod_cidr="10.240.0.0/14", svc_cidr="10.100.0.0/16", nodes=[
        {"hostname": "cp1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"},
        {"hostname": "w1", "node": "pve02", "ip": "10.0.0.11/24", "role": "worker"}]))["body"]
    check("both control-plane and worker configs carry the pod + service CIDRs",
          tz.count('podSubnets     = ["10.240.0.0/14"]') == 2
          and tz.count('serviceSubnets = ["10.100.0.0/16"]') == 2)
    _raises("a malformed pod CIDR is refused", lambda: provision.generate(T(pod_cidr="not-a-cidr")))

    print("Talos VIP: shared control-plane address on CP nodes only, and it is the endpoint")
    tv = provision.generate(T(vip="10.0.0.9", nodes=[
        {"hostname": "cp1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"},
        {"hostname": "w1", "node": "pve02", "ip": "10.0.0.11/24", "role": "worker"}]))["body"]
    check("the VIP is attached to the control-plane interface, exactly once",
          tv.count('vip       = { ip = "10.0.0.9" }') == 1)
    check("the cluster API endpoint and talos endpoints use the VIP, not a node IP",
          'cluster_endpoint = "https://10.0.0.9:6443"' in tv
          and 'endpoints            = ["10.0.0.9"]' in tv)
    check("the kubeconfig is still fetched from a real control-plane node, not the VIP",
          'talos_cluster_kubeconfig' in tv and 'node                 = "10.0.0.10"' in tv)
    check("no VIP set → no vip block, endpoint falls back to the first control-plane",
          'vip       = {' not in tz and 'cluster_endpoint = "https://10.0.0.10:6443"' in tz)
    _raises("a malformed VIP is refused", lambda: provision.generate(T(vip="not-an-ip")))

    print("Talos image: a staged / on-host volid skips the node download and imports from it")
    ti = provision.generate(T(image_present=True,
        image_volid="local:iso/talos-1.13.8-nocloud-amd64.img", nodes=[
        {"hostname": "cp1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"},
        {"hostname": "w1", "node": "pve02", "ip": "10.0.0.11/24", "role": "worker"}]))["body"]
    check("no download_file resource is generated when the image is already present",
          "proxmox_virtual_environment_download_file" not in ti)
    check("every node imports its disk from the provided volid",
          ti.count('import_from  = "local:iso/talos-1.13.8-nocloud-amd64.img"') == 2)
    check("the default (no volid) still generates the per-node download",
          "proxmox_virtual_environment_download_file" in tz)

    print("Talos metal ISO (experimental): boots the ISO + applies config over the network")
    tmi = provision.generate(T(talos_method="iso", image_present=True,
        image_volid="local:iso/talos-metal-amd64.iso", nodes=[
        {"hostname": "talos-cp-1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"},
        {"hostname": "talos-w-1", "node": "pve02", "ip": "10.0.0.11/24", "role": "worker"}]))["body"]
    check("the ISO is booted as a cdrom, no image download",
          'file_id   = "local:iso/talos-metal-amd64.iso"' in tmi
          and "proxmox_virtual_environment_download_file" not in tmi)
    check("no nocloud config drive on the metal path",
          "proxmox_virtual_environment_file" not in tmi and "user_data_file_id" not in tmi)
    check("config is applied over the network, once per node, to the node's own IP",
          tmi.count('resource "talos_machine_configuration_apply"') == 2
          and 'endpoint                    = "10.0.0.10"' in tmi)
    check("bootstrap waits for the control-plane's config-apply, not just the VM",
          "depends_on           = [talos_machine_configuration_apply.talos_cp_1]" in tmi)
    _raises("metal ISO without an ISO volid is refused",
            lambda: provision.generate(T(talos_method="iso", nodes=[
                {"hostname": "c", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"}])))

    print("Talos NTP + hostname handling (nocloud vs metal)")
    tn = provision.generate(T(ntp_servers=["10.0.10.196", "10.0.10.197"], nodes=[
        {"hostname": "cp1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane"}]))["body"]
    check("NTP servers are patched into machine.time.servers",
          'time = { servers = ["10.0.10.196", "10.0.10.197"] }' in tn)
    check("no NTP given → no machine.time block", "time = {" not in tz)
    check("nocloud OMITS machine.network.hostname (the config drive sets it, else "
          "Talos rejects the duplicate)", "hostname   =" not in tn)
    check("metal DOES set the hostname (no cloud-init meta-data to supply it)",
          'hostname   = "talos-cp-1"' in tmi)

    print("Talos per-node resources: each node gets its own vCPU / RAM / disk")
    tres = provision.generate(T(nodes=[
        {"hostname": "cp1", "node": "pve01", "ip": "10.0.0.10/24", "role": "controlplane",
         "cores": 8, "mem_mb": 8192, "disk_gb": 50},
        {"hostname": "w1", "node": "pve02", "ip": "10.0.0.11/24", "role": "worker",
         "cores": 2, "mem_mb": 2048, "disk_gb": 20}]))["body"]
    check("the control-plane node's resources are honoured",
          "cores = 8" in tres and "dedicated = 8192" in tres and "= 50" in tres)
    check("the worker node's own (different) resources are honoured",
          "cores = 2" in tres and "dedicated = 2048" in tres and "= 20" in tres)

    print("image upload: content type + extension are validated before the transfer")
    _raises("an unknown content type is refused",
            lambda: provision.upload_iso("x", "n", "local", "a.iso", "/tmp/x", "bogus"))
    _raises("an ISO upload rejects a .raw file",
            lambda: provision.upload_iso("x", "n", "local", "disk.raw", "/tmp/x", "iso"))
    _raises("an import upload rejects a .iso file",
            lambda: provision.upload_iso("x", "n", "local", "cd.iso", "/tmp/x", "import"))

    print("post-provision Ansible: kickstart plants the key + NOPASSWD sudo when a playbook is chosen")
    _kn = {"hostname": "web1", "node": "pve01", "ip": "10.0.0.5/24"}
    ks_no = provision._kickstart({"os_user": "ammar", "ssh_key": "ssh-ed25519 KEY",
        "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "bridge": "vmbr0"}, dict(_kn), "")
    check("no playbook → no passwordless sudoers", "NOPASSWD" not in ks_no)
    ks_yes = provision._kickstart({"os_user": "ammar", "ssh_key": "ssh-ed25519 KEY",
        "ansible_playbook": "pb-x", "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "bridge": "vmbr0"},
        dict(_kn), "")
    check("the SSH public key is planted for the user",
          'sshkey --username=ammar "ssh-ed25519 KEY"' in ks_yes)
    check("a playbook adds NOPASSWD sudo for the user",
          "ammar ALL=(ALL) NOPASSWD:ALL" in ks_yes and "/etc/sudoers.d/90-ammar" in ks_yes)

    print("iso method: a rejected OEMDRV upload becomes a clean Refused, not a bare ProxmoxError")
    # the route only turns Refused/ProxmoxError into JSON — a ProxmoxError escaping
    # create() used to reach the browser as an HTML 500 the JS `.json()` couldn't
    # parse ("Unexpected token '<'"). Stub the client so the upload is rejected.
    class _RejectPx:
        def delete_content(self, *a, **k): pass
        def upload(self, *a, **k): raise provision.ProxmoxError("upload to local on pve01 failed: HTTP 400")
        def close(self): pass
    _orig_client_for, _orig_build = provision.client_for, provision._build_oemdrv
    provision.client_for = lambda sid: _RejectPx()
    # isolate the UPLOAD failure — don't depend on an ISO builder being installed
    import tempfile
    def _fake_build(_ks):
        p = os.path.join(tempfile.mkdtemp(prefix="oemdrv-t-"), "oemdrv.iso")
        open(p, "wb").close()
        return p
    provision._build_oemdrv = _fake_build
    try:
        _isospec = A(connection=connA, method="iso", stack_name="iso-vm",
                     image_datastore="local", os_user="ammar", os_password="pw")
        try:
            provision.create(_isospec, "adm")
            check("a rejected upload raises (not a silent success)", False)
        except provision.Refused as e:
            check("the OEMDRV failure is a Refused carrying the real error + datastore",
                  "HTTP 400" in str(e) and "local" in str(e) and "import" in str(e).lower())
        except provision.ProxmoxError:
            check("a ProxmoxError must be wrapped as Refused so the route can JSON it", False)
    finally:
        provision.client_for, provision._build_oemdrv = _orig_client_for, _orig_build

    print("post-provision Ansible: the private key is stored sealed, keyed by the stack")
    provision.set_ansible("ts-antest", "pb-x", "PRIVATE-KEY-DATA", "ammar")
    got = provision.ansible_for("ts-antest")
    check("ansible_for returns the playbook, user and unsealed key",
          got and got["pb_id"] == "pb-x" and got["os_user"] == "ammar"
          and got["private_key"] == "PRIVATE-KEY-DATA")
    _araw = db.q("SELECT key_sealed FROM provision_ansible WHERE sid=?", ("ts-antest",))[0]["key_sealed"]
    check("the stored key is sealed at rest, no plaintext",
          secretbox.sealed(_araw) and "PRIVATE-KEY-DATA" not in _araw)

    print("VM actions: 'delete' routes to destroy_vm, a power verb to vm_action, unknown is refused")
    _raises("an unknown VM action is refused before any client is opened",
            lambda: provision.vm_action("c", "pve01", 7, "nuke"))
    _acalls = []
    class _ActPx:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def destroy_vm(self, node, vmid): _acalls.append(("destroy", node, vmid)); return "UPID:del"
        def vm_action(self, node, vmid, action): _acalls.append((action, node, vmid)); return "UPID:act"
    _oc = provision.client_for
    provision.client_for = lambda c: _ActPx()
    try:
        check("delete routes to destroy_vm",
              provision.vm_action("c", "pve01", 7, "delete") == "UPID:del" and _acalls[-1] == ("destroy", "pve01", 7))
        check("a power verb still routes to vm_action",
              provision.vm_action("c", "pve01", 7, "shutdown") == "UPID:act" and _acalls[-1] == ("shutdown", "pve01", 7))
    finally:
        provision.client_for = _oc

    print("OS catalog: cloud-image distros (Ubuntu/Debian/Alpine/CentOS/Rocky) generate a download + cloud-init")
    _oskeys = {c["key"] for c in provision.os_choices()}
    check("the new cloud distros are in the catalog",
          {"ubuntu-24.04", "ubuntu-22.04", "debian-12", "alpine-3.21", "centos-10", "rocky-9"} <= _oskeys)
    _pkeys = {p["key"] for p in provision.presets()}
    check("each has a quick-launch preset", {"ubuntu2404", "debian12", "alpine321", "centos10", "rocky9"} <= _pkeys)
    _cloud = provision.generate({"os": "ubuntu-24.04", "method": "cloud", "connection": "c", "bridge": "vmbr0",
        "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "os_user": "ammar", "os_password": "Cl0ud!pw",
        "cores": 2, "mem_mb": 2048, "disk_gb": 20,
        "nodes": [{"hostname": "ubu1", "node": "pve01", "ip": "10.0.0.9/24"}]})["body"]
    check("a cloud OS downloads the image (no ISO needed)",
          "proxmox_virtual_environment_download_file" in _cloud and "ubuntu-24.04-cloudimg-amd64.img" in _cloud)
    check("cloud-init sets the user and a static address",
          'username = "ammar"' in _cloud and 'address = "10.0.0.9/24"' in _cloud)
    check("the OS password is a SHA-512 hash, never plaintext in the body",
          'password = "$6$' in _cloud and "Cl0ud!pw" not in _cloud)
    check("RHEL family offers ISO+kickstart AND cloud; the rest cloud-only",
          provision.methods_for("almalinux-10") == ["cloud", "iso"]
          and provision.methods_for("centos-10") == ["cloud", "iso"]
          and provision.methods_for("ubuntu-24.04") == ["cloud"]
          and provision.methods_for("alpine-3.21") == ["cloud"])
    check("presets carry their OS family so the wizard can offer the right methods",
          all(p.get("family") for p in provision.presets()))

    print("recipe wizard: per-VM resources reach the HCL (editable per VM, not a fixed size)")
    _mix = provision.generate({"os": "almalinux-10", "method": "iso", "connection": "c", "bridge": "vmbr0",
        "gateway": "10.0.0.1", "dns": ["1.1.1.1"], "cores": 2, "mem_mb": 4096, "disk_gb": 40,
        "nodes": [{"hostname": "m1", "node": "pve01", "ip": "10.0.0.5/24", "cores": 2, "mem_mb": 4096, "disk_gb": 40},
                  {"hostname": "m2", "node": "pve01", "ip": "10.0.0.6/24", "cores": 8, "mem_mb": 16384, "disk_gb": 120}]})["body"]
    check("per-VM CPU differs in the HCL", "cores = 2" in _mix and "cores = 8" in _mix)
    check("per-VM RAM + disk differ in the HCL", "dedicated = 16384" in _mix and "size         = 120" in _mix)

    print("upload progress: the reader counts bytes sent, and a seek(0) resets the tally")
    import io
    seen = []
    rd = provision._UploadReader(io.BytesIO(b"abcdefghij"), 10, lambda s, t: seen.append((s, t)))
    rd.read(4); rd.read(4)
    check("bytes-sent accumulates across reads", seen[-1] == (8, 10))
    rd.seek(0)                               # httpx seeks back to the start after sizing
    rd.read(3)
    check("a seek to the start resets the tally so progress begins at zero",
          seen[-1] == (3, 10))

    print("VM detail: Proxmox config + status normalize to a hardware dict")
    _cfg = {"name": "web", "cores": 2, "sockets": 1, "memory": 4096, "balloon": 2048,
            "cpu": "host", "ostype": "l26", "agent": "enabled=1", "onboot": 1,
            "tags": "prod;ke", "description": "worker",
            "scsi0": "local-lvm:vm-9-disk-0,size=40G,ssd=1", "scsi1": "local-lvm:vm-9-disk-1,size=1T",
            "ide2": "local:iso/x.iso,media=cdrom",
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10,firewall=1"}
    _st = {"status": "running", "uptime": 3600, "cpu": 0.05, "mem": 2 * 1024 ** 3, "maxmem": 4 * 1024 ** 3}
    _d = provision._shape_vm("pve01", 9, _cfg, _st)
    check("cores/sockets/memory + live cpu/mem parsed",
          _d["cores"] == 2 and _d["vcpus"] == 2 and _d["memory_mb"] == 4096
          and _d["cpu_pct"] == 5.0 and _d["mem_used_gb"] == 2.0 and _d["balloon_mb"] == 2048)
    check("disks parsed (1T→1024GB) and the cdrom is NOT a disk",
          [x["size_gb"] for x in _d["disks"]] == [40.0, 1024.0]
          and all(x["id"] != "ide2" for x in _d["disks"]))
    check("nic parsed with bridge/vlan/mac/firewall",
          _d["nics"][0]["bridge"] == "vmbr0" and _d["nics"][0]["vlan"] == "10"
          and _d["nics"][0]["firewall"] is True and _d["nics"][0]["mac"] == "AA:BB:CC:DD:EE:FF")
    check("agent + tags + onboot parsed",
          _d["agent_on"] is True and _d["tags"] == ["prod", "ke"] and _d["onboot"] is True)

    print("VM edit: only editable fields, validated, then written via set_vm_config")
    _edits = []
    class _EditPx:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def set_vm_config(self, node, vmid, params): _edits.append((node, vmid, params))
    _oc = provision.client_for
    provision.client_for = lambda c: _EditPx()
    try:
        _r = provision.vm_edit("c", "pve01", 9,
                               {"cores": 4, "memory_mb": 8192, "name": "web-1", "tags": ["Prod", "K E!"]})
        check("valid edit writes the mapped Proxmox params (GB→memory, tags cleaned)",
              _edits[-1][2] == {"cores": 4, "memory": 8192, "name": "web-1", "tags": "prod;ke"}
              and _r["changed"] == ["cores", "memory", "name", "tags"])
        _raises("zero cores refused", lambda: provision.vm_edit("c", "p", 9, {"cores": 0}))
        _raises("over-max cores refused", lambda: provision.vm_edit("c", "p", 9, {"cores": 9999}))
        _raises("tiny memory refused", lambda: provision.vm_edit("c", "p", 9, {"memory_mb": 8}))
        _raises("a bad VM name refused", lambda: provision.vm_edit("c", "p", 9, {"name": "-nope"}))
        _raises("no editable field refused", lambda: provision.vm_edit("c", "p", 9, {"foo": 1}))
    finally:
        provision.client_for = _oc

    print("post-provision Ansible is armed + driven SERVER-SIDE (survives the wizard closing)")
    import time as _t
    from app import ansible as _ans
    _save = (provision.ansible_for, provision.stored_spec, provision.terraform.run,
             provision.vm_ssh_ready, provision.set_ansible_run, _ans.run_adhoc, _ans.config)
    provision.ansible_for = lambda sid: {"pb_id": "pb1", "private_key": "KEY", "os_user": "ops"}
    provision.stored_spec = lambda sid: {"stack_name": "prov", "nodes": [{"hostname": "h1", "ip": "10.0.0.9/24"}]}
    provision.terraform.run = lambda rid, since=0: {"done": True, "status": "ok"}
    provision.vm_ssh_ready = lambda ip, port=22, timeout=3.0: True
    provision.set_ansible_run = lambda sid, rid: None
    _ans.run_adhoc = lambda *a, **k: "run-TST"
    _ans.config = lambda: {"allow_real": True}

    def _await(sid, want):   # poll the background worker's phase, briefly
        for _ in range(60):
            s = provision.post_ansible_status(sid)
            if s.get("run_id") or s.get("phase") in want:
                return s
            _t.sleep(0.05)
        return provision.post_ansible_status(sid)
    try:
        provision._POST.clear()
        check("arm starts the worker", provision.arm_post_ansible("ts-pa", "apply-1", "who") is True)
        check("the worker drives itself to the ad-hoc run (no client needed)",
              _await("ts-pa", ("failed",)).get("run_id") == "run-TST")
        check("arming again while it runs is a no-op",
              provision.arm_post_ansible("ts-pa", "apply-1", "who") is False)
        provision._POST.clear()
        provision.terraform.run = lambda rid, since=0: {"done": True, "status": "failed"}
        provision.arm_post_ansible("ts-pa2", "apply-2", "who")
        check("a failed apply skips the playbook",
              _await("ts-pa2", ("failed", "done", "running")).get("phase") == "failed")
    finally:
        (provision.ansible_for, provision.stored_spec, provision.terraform.run,
         provision.vm_ssh_ready, provision.set_ansible_run, _ans.run_adhoc, _ans.config) = _save

    print("editing a Proxmox connection keeps the sealed credential unless retyped")
    sid = provision.add_host({"name": "pve-edit-test", "endpoint": "https://10.0.0.9:8006",
                              "api_token": "root@pam!t=ORIGINAL", "insecure": True,
                              "env": "dev"}, "tester@x")
    g = provision.host_get(sid)
    check("host_get returns endpoint + auth kind and NEVER the token",
          g["endpoint"] == "https://10.0.0.9:8006" and g["auth"] == "token"
          and "ORIGINAL" not in repr(g))
    provision.edit_host(sid, {"sid": sid, "name": "pve-edit-test",
                              "endpoint": "https://10.0.0.20:8006"}, "tester@x")
    c = provision._creds_of(sid)
    check("editing the endpoint with a blank credential keeps the stored token",
          c["PROXMOX_VE_ENDPOINT"] == "https://10.0.0.20:8006"
          and c["PROXMOX_VE_API_TOKEN"] == "root@pam!t=ORIGINAL")
    provision.edit_host(sid, {"sid": sid, "name": "pve-edit-test",
                              "endpoint": "https://10.0.0.20:8006",
                              "api_token": "root@pam!t=REPLACED"}, "tester@x")
    check("a retyped token replaces the stored one",
          provision._creds_of(sid)["PROXMOX_VE_API_TOKEN"] == "root@pam!t=REPLACED")
    _raises("edit_host refuses an unknown stack",
            lambda: provision.edit_host("nope-xxx",
                    {"name": "x", "endpoint": "https://y:8006"}, "t"))

    print("adding several standalone hosts at once — partial failure is reported, not fatal")
    res = provision.add_hosts([
        {"name": "pve-a", "endpoint": "https://10.0.1.1:8006", "api_token": "root@pam!t=a", "env": "dev"},
        {"name": "pve-b", "endpoint": "", "api_token": "root@pam!t=b", "env": "dev"},   # bad: no endpoint
        {"name": "pve-c", "endpoint": "https://10.0.1.3:8006", "api_token": "root@pam!t=c", "env": "dev"},
    ], "tester@x")
    check("two good hosts land, the bad one is reported — the batch is not lost",
          sum(1 for r in res if r["ok"]) == 2 and sum(1 for r in res if not r["ok"]) == 1)
    check("each good host is its own sealed connection",
          all(provision._creds_of(r["sid"])["PROXMOX_VE_ENDPOINT"]
              for r in res if r["ok"]))

    print("a batch mixes edit (row carries a sid) and add (no sid) in one save")
    existing = next(r["sid"] for r in res if r["ok"])          # reuse pve-a from above
    mixed = provision.add_hosts([
        {"sid": existing, "name": "pve-a", "endpoint": "https://10.9.9.9:8006"},   # EDIT: no cred → keep
        {"name": "pve-new", "endpoint": "https://10.0.2.9:8006", "api_token": "root@pam!t=n", "env": "dev"},  # ADD
    ], "tester@x")
    check("the sid row edits (kept its token, moved endpoint) and is flagged edited",
          mixed[0]["ok"] and mixed[0].get("edited")
          and provision._creds_of(existing)["PROXMOX_VE_ENDPOINT"] == "https://10.9.9.9:8006"
          and provision._creds_of(existing)["PROXMOX_VE_API_TOKEN"] == "root@pam!t=a")
    check("the no-sid row adds a brand-new connection",
          mixed[1]["ok"] and not mixed[1].get("edited") and mixed[1]["sid"] != existing)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
