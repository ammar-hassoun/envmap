#!/usr/bin/env python3
"""Terraform: stacks, the sealed provider credential, the run gating and output.

WHY THIS EXISTS
    The Terraform page runs `.tf` against a provider with a stored credential —
    the same trust an Ansible playbook carries. The load-bearing facts:

      1. **The credential is sealed and never shown.** A stack's secret is sealed
         at rest, dropped from every page context, and injected only as run-time
         environment variables.
      2. **apply/destroy are gated twice.** Off by default (allow_apply), and a
         production stack needs its name typed — checked before a terraform
         binary is even required, so the gate is provable here.
      3. **Reading is separate from running.** `terraform` reads the stacks and
         output; `init/plan/apply/destroy` need the escalating `terraform_apply`.
      4. The run row is created before the process, streamed, and finished once.

    ./.venv/bin/python tests/test_terraform.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["PORTAL_SCHEDULER"] = "0"
import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("tf-")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import db, secretbox, terraform as tf                # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def main() -> int:
    print("a stack seals the credential and never shows it")
    sid = tf.save_stack("", {"name": "ke-web", "provider": "proxmox",
        "body": 'resource "null_resource" "x" {}',
        "tfvars": 'node = "pve-01"', "env": "staging",
        "creds": "PROXMOX_VE_ENDPOINT=https://pve:8006/\n"
                 "PROXMOX_VE_API_TOKEN=root@pam!p=SEKRET"}, "adm")
    s = tf.stack(sid)
    check("the view carries no sealed credential", "creds_sealed" not in s)
    check("it knows the provider, env and has-creds",
          s["provider"] == "proxmox" and s["env_label"] == "Staging"
          and s["env_tone"] == "warn" and s["has_creds"] is True)
    raw = db.q("SELECT creds_sealed FROM tf_stacks WHERE id=?", (sid,))[0]["creds_sealed"]
    check("the credential is sealed at rest, no token in the row",
          secretbox.sealed(raw) and "SEKRET" not in raw)
    check("a blank credential on edit keeps the stored one",
          (tf.save_stack(sid, {"name": "ke-web", "provider": "proxmox",
                               "body": "x", "creds": ""}, "adm"),
           db.q("SELECT creds_sealed FROM tf_stacks WHERE id=?", (sid,))[0]["creds_sealed"] == raw)[1])

    print("the credential block is validated, not trusted")
    _raises("a KEY without a value", lambda: tf._clean_creds("PROXMOX_TOKEN"))
    _raises("a lowercase env name", lambda: tf._clean_creds("token=abc"))
    check("a good block passes",
          tf._clean_creds("A=1\n# comment\nB_C=2 3") == "A=1\nB_C=2 3")

    print("a production environment turns the confirm on by itself")
    ps = tf.save_stack("", {"name": "ke-prod", "provider": "proxmox",
        "body": "x", "env": "production", "creds": ""}, "adm")
    check("env=production makes the stack production",
          tf.stack(ps)["is_prod"] == 1)

    print("the argv is a list, and apply carries -auto-approve")
    check("init/plan/apply/destroy build the right commands",
          "init" in tf.argv_for("init", "/wd")
          and "-auto-approve" not in tf.argv_for("plan", "/wd")
          and "-auto-approve" in tf.argv_for("apply", "/wd")
          and "destroy" in tf.argv_for("destroy", "/wd")
          and "-no-color" in tf.argv_for("plan", "/wd"))

    print("apply and destroy are gated twice, before a binary is even needed")
    _raises("apply with the switch off", lambda: tf.start(sid, "apply", "adm",
            allow_apply=False))
    _raises("destroy with the switch off", lambda: tf.start(sid, "destroy", "adm",
            allow_apply=False))
    _raises("prod apply without the typed name", lambda: tf.start(ps, "apply",
            "adm", allow_apply=True, confirm="wrong"))
    _raises("an unknown action", lambda: tf.start(sid, "nonsense", "adm"))

    print("the run row is created, appended, and finished once")
    db.run("INSERT INTO tf_runs (id, stack_id, stack_name, action, status, "
           "started, by) VALUES (?,?,?,?,?,?,?)",
           ("tr-t1", sid, "ke-web", "plan", tf.STATUS_RUNNING, tf._now(), "adm"))
    tf._append("tr-t1", "Refreshing...\n")
    got = tf.run("tr-t1")
    check("run() returns the text and 'not done' while running",
          got["text"] == "Refreshing...\n" and not got["done"])
    got2 = tf.run("tr-t1", since=got["at"])
    check("run(since=…) returns only the new bytes", got2["text"] == "")
    tf._finish("tr-t1", 0, tf._resources(
        "Apply complete! Resources: 3 added, 1 changed, 0 destroyed."))
    done = tf.run("tr-t1")
    check("finishing sets done + ok", done["done"] and done["status"] == "ok")
    row = db.q("SELECT resources FROM tf_runs WHERE id='tr-t1'")[0]
    check("terraform's own change summary is parsed",
          '"added": 3' in row["resources"] and '"changed": 1' in row["resources"])
    check("a plan summary parses too",
          '"add": 2' in tf._resources("Plan: 2 to add, 0 to change, 1 to destroy."))

    print("a Talos stack advertises its kubeconfig; read_outputs guards on state")
    tid = tf.save_stack("", {"name": "talos-lab", "provider": "proxmox",
        "body": 'resource "talos_cluster_kubeconfig" "this" {}', "creds": ""}, "adm")
    check("the single-stack view flags a Talos kubeconfig stack",
          tf.stack(tid)["has_kube"] is True)
    flags = {r["id"]: r["has_kube"] for r in tf.stacks()}
    check("the list view flags the Talos stack and clears a plain one",
          flags.get(tid) is True and flags.get(sid) is False)
    check("read_outputs is empty until the cluster has state",
          tf.read_outputs(tid) == {})

    print("deleting a stack removes its working directory")
    wd = tf._workdir(sid)
    os.makedirs(wd, exist_ok=True)
    open(os.path.join(wd, "terraform.tfstate"), "w").close()
    tf.delete_stack(sid)
    check("the stack and its state directory are gone",
          tf.stack(sid) is None and not os.path.isdir(wd))

    routes()
    image_ships_an_engine()
    print("OK" if not bad else f"{bad} FAILED")
    return bad


def _raises(what: str, fn) -> None:
    try:
        fn()
        check(f"{what} — it was ALLOWED", False)
    except tf.Refused:
        pass


def routes() -> None:
    print("through the routes: reading is separate from running")
    from fastapi.testclient import TestClient

    from app import auth, main, rbac

    def enrol(email, pw, role):
        uid = auth.create_user(email, "N", pw, role=role)
        db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0 WHERE id=?",
               ("TESTSECRET", uid))
        return uid

    def login(c, e, p):
        c.post("/login", data={"email": e, "password": p}, follow_redirects=False)
        c.post("/mfa", data={"code": auth._totp_at(
            "TESTSECRET", int(time.time() // auth.TOTP_STEP))}, follow_redirects=False)

    enrol("boss@t", "Admin-Pass-Word-42", "admin")
    ruid = enrol("reader@t", "Reader-Pass-Word-42", "viewer")
    rid = rbac.save("", "tf reader", "", ["terraform"], [], [], [])   # read, not apply
    rbac.set_for_user(ruid, [rid])

    boss = TestClient(main.app); boss.__enter__(); login(boss, "boss@t", "Admin-Pass-Word-42")
    reader = TestClient(main.app); reader.__enter__(); login(reader, "reader@t", "Reader-Pass-Word-42")

    r = boss.get("/terraform")
    check(f"an admin sees the Terraform page ({r.status_code})",
          r.status_code == 200 and "Terraform" in r.text and "Stacks" in r.text)
    r = boss.get("/settings/terraform")
    check("settings renders with the runner state",
          r.status_code == 200 and "apply" in r.text)
    r = boss.post("/terraform/stack/save", data={"sid": "", "name": "RT Stack",
        "provider": "proxmox", "body": 'resource "null_resource" "x" {}',
        "env": "staging", "creds": "A=1"}, follow_redirects=False)
    check("an admin can save a stack", r.status_code == 303
          and "/terraform/stacks/" in r.headers.get("location", ""))
    r = boss.get("/terraform?sec=stacks")
    check("no secret is on the page", "TESTSECRET" not in r.text and "RT Stack" in r.text)

    # a reader (terraform area, not terraform_apply) reads but cannot run
    r = reader.get("/terraform")
    check(f"a reader may read the page ({r.status_code})", r.status_code == 200)
    r = reader.post("/terraform/run", data={"sid": "x", "action": "plan"},
                    follow_redirects=False)
    check("a reader cannot run terraform (needs terraform_apply)",
          r.status_code == 403)
    # the Talos config download rides the same apply gate and 404s until applied
    r = reader.get("/provision/cluster/download?sid=x&which=kubeconfig")
    check("a reader cannot download a cluster config (needs terraform_apply)",
          r.status_code == 403)
    r = boss.get("/provision/cluster/download?sid=x&which=bogus")
    check("an unknown config file is refused", r.status_code == 400)
    r = boss.get("/provision/cluster/download?sid=x&which=talosconfig")
    check("the config download 404s until the cluster is applied",
          r.status_code == 404)
    # settings save toggles the switch, audited
    r = boss.post("/settings/terraform", data={"allow_apply": "1", "parallelism": "20"},
                  follow_redirects=False)
    check("saving settings turns apply on", r.status_code == 303
          and tf.config()["allow_apply"] is True and tf.config()["parallelism"] == 20)


def image_ships_an_engine() -> None:
    """The provisioning page must work out of the box.

    It did not: a fresh install opened Infrastructure Provisioning to a red
    banner saying no terraform or tofu binary was on PATH, and stacks could be
    written but never run. The engine is part of what this product does, so it
    belongs in the image the way kubectl and git do.

    Shipped as OPENTOFU rather than HashiCorp Terraform on purpose: Terraform
    has been BUSL-1.1 since v1.6 and this image is redistributed to customers
    who run it themselves. OpenTofu is MPL-2.0 and a drop-in.

    Checked against the Dockerfile rather than by running anything, because
    the suite runs on a developer's laptop where the binary may be present for
    reasons that have nothing to do with the image.
    """
    print("the image ships a provisioning engine, so the banner never shows")
    root = pathlib.Path(__file__).resolve().parent.parent
    dockerfile = (root / "Dockerfile").read_text()
    check("the image fetches OpenTofu", "opentofu/opentofu/releases" in dockerfile)
    check("pinned to a version, not 'latest'",
          re.search(r"ARG TOFU_VERSION=\d+\.\d+\.\d+", dockerfile) is not None)
    # It is handed provider credentials and told to change infrastructure, so
    # "it downloaded without erroring" is not the bar. kubectl is verified the
    # same way; kubeseal, for the record, is not.
    check("and checksum-verified against the release's own SHA256SUMS",
          "SHA256SUMS" in dockerfile and "sha256sum -c -" in dockerfile)
    check("MPL-2.0 asks that the licence travel with the binary",
          "opentofu-LICENSE" in dockerfile)

    # THE ANSIBLE TRAP, in a new costume: a binary that is in the image and not
    # on PORTAL_TOOL_PATH is a binary the portal reports as missing, and nothing
    # outside a container reproduces it.
    dest = re.search(r"COPY --from=tools ([^\n]*?)/out/tofu[^\n]*? (/\S+)",
                     dockerfile)
    check("tofu is copied into the image", dest is not None)
    tool_path = re.search(r'PORTAL_TOOL_PATH="([^"]+)"', dockerfile)
    check("the image sets a tool path", tool_path is not None)
    if dest and tool_path:
        where = dest.group(2).rstrip("/")
        dirs = tool_path.group(1).split(":")
        check(f"and {where} is on it, or the portal cannot find what it ships "
              f"({dirs})", where in dirs)

    print("and the resolver actually looks for what the image ships")
    # Shipping `tofu` only helps if tool() considers that name. This is the
    # link between the two halves and the one that would silently not hold.
    src = (root / "app" / "terraform.py").read_text()
    check("tool() falls back to tofu when PORTAL_TERRAFORM is unset",
          '"terraform", "tofu"' in src)
    check("and an install naming its own binary still wins",
          "env.TERRAFORM != " in src)


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
