"""Seal secret values with kubeseal for a specific cluster.

The sealing certificate can be pasted into the cluster's settings (preferred —
works with no cluster connectivity), or fetched from the cluster's
sealed-secrets controller as a fallback.
"""
import subprocess
from pathlib import Path

from .env import KUBESEAL
from . import store

# Upstream defaults for the sealed-secrets chart, used only when a cluster does
# not say otherwise. The controller's real name depends on the Helm release name
# chosen at install time, so any cluster can override both in its settings.
CONTROLLER_NAMESPACES = ["kube-system", "sealed-secrets"]
CONTROLLER_NAMES = ["sealed-secrets-controller", "sealed-secrets"]


def _candidates(cluster: dict) -> list[tuple[str, str]]:
    """(namespace, name) pairs to try, the cluster's own setting first."""
    ns = (cluster.get("sealing_namespace") or "").strip()
    name = (cluster.get("sealing_controller") or "").strip()
    out = []
    if ns and name:
        out.append((ns, name))
    elif name:
        out += [(n, name) for n in CONTROLLER_NAMESPACES]
    elif ns:
        out += [(ns, n) for n in CONTROLLER_NAMES]
    out += [(n, c) for n in CONTROLLER_NAMESPACES for c in CONTROLLER_NAMES
            if (n, c) not in out]
    return out


class SealingError(Exception):
    pass


def fetch_cert(cluster: dict) -> str:
    """Pull the public sealing cert from the cluster (fallback path)."""
    if not cluster.get("kubeconfig_file") or not cluster.get("context"):
        raise SealingError("paste a sealing certificate, or add a kubeconfig so "
                           "it can be fetched from the cluster")
    errors = []
    for ns, name in _candidates(cluster):
        r = subprocess.run(
            [KUBESEAL, "--fetch-cert",
             "--kubeconfig", cluster["kubeconfig_file"],
             "--context", cluster["context"],
             "--controller-namespace", ns, "--controller-name", name],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and "BEGIN CERTIFICATE" in r.stdout:
            return r.stdout
        errors.append(f"{ns}/{name}: {r.stderr.strip()[:100]}")
    raise SealingError(
        "could not fetch the sealing certificate. If your controller uses a "
        "different Helm release name, set it on the cluster, or paste the "
        "certificate directly. Tried — " + " | ".join(errors))


def cert_path(pid: str, cluster: dict) -> str:
    if cluster.get("cert_file") and Path(cluster["cert_file"]).exists():
        return cluster["cert_file"]
    pem = fetch_cert(cluster)
    store.write_cluster_files(pid, cluster["id"], sealing_cert=pem)
    refreshed = store.get_cluster(pid, cluster["id"]) or {}
    if not refreshed.get("cert_file"):
        raise SealingError("failed to store the fetched sealing certificate")
    return refreshed["cert_file"]


def seal_value(pid: str, cluster: dict, namespace: str, secret_name: str,
               value: str) -> str:
    if not namespace or not secret_name:
        raise SealingError("values file has no namespace/secretName to seal against")
    r = subprocess.run(
        [KUBESEAL, "--raw", "--scope", "strict",
         "--namespace", namespace, "--name", secret_name,
         "--cert", cert_path(pid, cluster), "--from-file", "/dev/stdin"],
        input=value, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise SealingError(f"kubeseal failed: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def validate_cert(pem: str) -> tuple[bool, str]:
    if "BEGIN CERTIFICATE" not in pem:
        return False, "that does not look like a PEM certificate"
    r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-enddate"],
                       input=pem, capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, r.stderr.strip()[:200] or "openssl rejected the certificate"
    return True, " ".join(r.stdout.split())
