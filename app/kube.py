"""Read-only cluster queries using a cluster's stored kubeconfig."""
import json
import subprocess
import time
from datetime import datetime, timezone

from .env import KUBECTL


def base_args(cluster: dict) -> list[str] | None:
    """The prefix every cluster read shares: which binary, which file, which
    context. The binary is named by the deployment (PORTAL_KUBECTL) because an
    image may ship it anywhere."""
    kc, ctx = cluster.get("kubeconfig_file"), cluster.get("context")
    if not kc or not ctx:
        return None
    return [KUBECTL, "--kubeconfig", kc, "--context", ctx]


# ── reachability, remembered briefly ───────────────────────────
# An unreachable cluster must cost one short probe, not a stack of full-length
# kubectl timeouts: a page reads a dozen resources, and 12 × 20s of waiting on a
# dead endpoint reads as the whole portal hanging. So the first caller pays for
# one quick `kubectl version` and everyone reuses the verdict for CHECK_TTL
# seconds — including the negative verdict, which is the one that matters.
CHECK_TTL = 30.0
_alive: dict = {}


def reachable(cluster: dict) -> tuple[bool, str]:
    """(True, "") when the API server answers, else (False, why) — cached."""
    key = f"{cluster.get('kubeconfig_file')}::{cluster.get('context')}"
    hit = _alive.get(key)
    if hit and time.time() - hit[0] < CHECK_TTL:
        return hit[1], hit[2]
    base = base_args(cluster)
    if not base:
        got = (False, "this cluster has no kubeconfig or context set")
    else:
        try:
            r = subprocess.run(base + ["version", "-o", "json",
                                       "--request-timeout=4s"],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                got = (True, "")
            else:
                got = (False, r.stderr.strip()[:220] or "kubectl failed")
        except subprocess.TimeoutExpired:
            got = (False, "no response from the API server within 8s")
        except Exception as e:                                # noqa: BLE001
            got = (False, f"{type(e).__name__}: {e}")
    _alive[key] = (time.time(), got[0], got[1])
    return got


def forget(cluster: dict) -> None:
    """Drop the cached verdict — call after editing a cluster's kubeconfig, so
    a fixed cluster is not still reported down for another CHECK_TTL."""
    _alive.pop(f"{cluster.get('kubeconfig_file')}::{cluster.get('context')}",
               None)


def contexts_of(content: str) -> list[str]:
    """List contexts in a pasted kubeconfig by asking kubectl."""
    import tempfile
    from pathlib import Path
    if "clusters" not in content or "contexts" not in content:
        raise ValueError("this does not look like a kubeconfig file")
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(content)
        tmp = fh.name
    try:
        r = subprocess.run([KUBECTL, "config", "get-contexts", "-o", "name",
                            "--kubeconfig", tmp],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            raise ValueError(r.stderr.strip()[:250] or "kubectl rejected the file")
        ctxs = sorted(c for c in r.stdout.split() if c)
        if not ctxs:
            raise ValueError("no contexts found")
        return ctxs
    finally:
        Path(tmp).unlink(missing_ok=True)


def current_context_of(content: str) -> str:
    """The kubeconfig's own `current-context`, or "" if it names none. Lets the
    cluster form take just a kubeconfig — the file already says which context it
    is for, so a person should not have to retype it."""
    import tempfile
    from pathlib import Path
    if "clusters" not in content or "contexts" not in content:
        return ""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(content)
        tmp = fh.name
    try:
        r = subprocess.run([KUBECTL, "config", "current-context",
                            "--kubeconfig", tmp],
                           capture_output=True, text=True, timeout=20)
        # rc != 0 is "no current-context set" — not an error, just nothing to use
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:                                         # noqa: BLE001
        return ""
    finally:
        Path(tmp).unlink(missing_ok=True)


def resolve_context(content: str, wanted: str = "") -> tuple[str, str]:
    """Pick the context for a pasted kubeconfig: an explicit choice if given and
    valid, else the file's current-context, else the sole context. Returns
    (context, error) — error is set only when the file is unusable or genuinely
    ambiguous (several contexts, none current, none chosen)."""
    try:
        ctxs = contexts_of(content)
    except ValueError as e:
        return "", str(e)
    if wanted:
        if wanted not in ctxs:
            return "", (f"context '{wanted}' is not in this kubeconfig "
                        f"({', '.join(ctxs)})")
        return wanted, ""
    cur = current_context_of(content)
    if cur and cur in ctxs:
        return cur, ""
    if len(ctxs) == 1:
        return ctxs[0], ""
    return "", ("this kubeconfig has several contexts and sets no "
                f"current-context — set current-context in the file, or pick one: "
                f"{', '.join(ctxs)}")


def test_cluster(cluster: dict) -> tuple[bool, str]:
    args = base_args(cluster)
    if not args:
        return False, "kubeconfig or context missing"
    # This runs while a person is holding a submitted form, so a dead endpoint
    # must answer in seconds, and as a verdict — never as an exception: the
    # cluster is saved either way, and "saved but unreachable" is a status,
    # not a server error.
    #
    # It is also always an *explicit* probe — someone adding a cluster or
    # pressing Test — so the cached verdict is dropped first: "still down" from
    # a cache is the wrong answer to a person who just fixed the network.
    forget(cluster)
    ok, why = reachable(cluster)
    if not ok:
        return False, why
    try:
        r = subprocess.run(args + ["get", "nodes", "-o", "json",
                                   "--request-timeout=8s"],
                           capture_output=True, text=True, timeout=12)
    except subprocess.TimeoutExpired:
        return False, "the API server answered a version probe but listing " \
                      "nodes timed out after 12s"
    if r.returncode != 0:
        return False, r.stderr.strip()[:220]
    try:
        items = json.loads(r.stdout).get("items", [])
    except json.JSONDecodeError:
        return False, "unexpected kubectl output"
    ready = sum(1 for n in items
                for c in n.get("status", {}).get("conditions", [])
                if c["type"] == "Ready" and c["status"] == "True")
    return True, f"connected — {ready}/{len(items)} nodes ready"


def _age(ts: str) -> str:
    try:
        d = datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if d.days:
            return f"{d.days}d"
        h = d.seconds // 3600
        return f"{h}h" if h else f"{d.seconds // 60}m"
    except Exception:
        return "?"


def get_pods(cluster: dict, namespaces: list[str]) -> dict:
    args = base_args(cluster)
    if not args:
        return {"pods": [], "error": "this cluster has no kubeconfig/context set"}
    ok, why = reachable(cluster)
    if not ok:
        return {"pods": [], "error": why}
    pods, errors = [], []
    for ns in namespaces:
        try:
            r = subprocess.run(args + ["get", "pods", "-n", ns, "-o", "json",
                                       "--request-timeout=10s"],
                               capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            errors.append(f"{ns}: timed out after 15s")
            continue
        if r.returncode != 0:
            errors.append(f"{ns}: {r.stderr.strip()[:150]}")
            continue
        try:
            items = json.loads(r.stdout).get("items", [])
        except json.JSONDecodeError:
            errors.append(f"{ns}: bad kubectl output")
            continue
        for it in items:
            meta, status = it["metadata"], it.get("status", {})
            cs = status.get("containerStatuses", []) or []
            ready = sum(1 for c in cs if c.get("ready"))
            phase = status.get("phase", "Unknown")
            reason = next((w["reason"] for c in cs
                           if (w := (c.get("state") or {}).get("waiting"))
                           and w.get("reason")), "")
            if meta.get("deletionTimestamp"):
                phase = "Terminating"
            healthy = (phase == "Running" and ready == len(cs) and not reason) \
                or phase == "Succeeded"
            pods.append({"namespace": ns, "name": meta["name"],
                         "ready": f"{ready}/{len(cs)}",
                         "status": reason or phase,
                         "restarts": sum(c.get("restartCount", 0) for c in cs),
                         "age": _age(meta.get("creationTimestamp", "")),
                         "healthy": healthy})
    return {"pods": pods, "error": " | ".join(errors) if errors else None}
