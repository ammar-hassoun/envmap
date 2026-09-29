"""Live pod log streaming via `kubectl logs -f`, exposed as Server-Sent Events.

WHY THE LINES ARE BATCHED
    One SSE frame per line is fine for a quiet pod and hopeless for a busy one.
    A container replaying a few thousand lines on attach produced a few thousand
    frames, each with its own event name, its own JSON envelope and its own trip
    through the browser's event loop — and the page spent longer parsing frames
    than kubectl spent producing them.

    So a reader thread fills a ring buffer and the generator drains it in
    batches. The window is small enough to be imperceptible on a quiet pod (the
    line still lands inside a tenth of a second) and turns a burst of two
    thousand lines into a handful of frames instead of two thousand.

WHY A RING BUFFER AND NOT A QUEUE
    A bounded queue applies backpressure, which sounds right and is wrong here:
    kubectl's pipe fills, kubectl blocks, and the log the operator is watching
    stops moving because their browser was busy. A deque with a maxlen drops the
    OLDEST lines instead, which is the correct thing to lose in a log tail —
    nobody scrolled back three thousand lines during a burst, and the recent
    ones are the reason the window is open.
"""
import collections
import json
import subprocess
import threading
import time

from .kube import base_args

# How long to let a burst gather before sending it. Chosen to be under the
# threshold where a person perceives a log as lagging, while still collapsing a
# replay of thousands of lines into a few frames.
BATCH_WINDOW = 0.08
MAX_BATCH = 500            # lines in one frame
BUFFER = 20000             # lines held for a slow reader before the oldest go
KEEPALIVE = 20             # seconds of silence before a comment frame


def containers_of(cluster: dict, namespace: str, pod: str) -> list[str]:
    args = base_args(cluster)
    if not args:
        return []
    r = subprocess.run(
        args + ["get", "pod", pod, "-n", namespace, "-o",
                "jsonpath={range .spec.containers[*]}{.name}{'\\n'}{end}",
                "--request-timeout=10s"],
        capture_output=True, text=True, timeout=20)
    return [c for c in r.stdout.split() if c] if r.returncode == 0 else []


def snapshot(cluster: dict, namespace: str, pod: str, container: str = "",
             tail: int = 300, previous: bool = False) -> str:
    args = base_args(cluster)
    if not args:
        return "cluster has no kubeconfig/context configured"
    cmd = args + ["logs", pod, "-n", namespace, f"--tail={tail}",
                  "--timestamps", "--request-timeout=20s"]
    if container:
        cmd += ["-c", container]
    if previous:
        cmd.append("--previous")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    return r.stdout or r.stderr or "(no output)"


def stream(cluster: dict, namespace: str, pod: str, container: str = "",
           tail: int = 200, previous: bool = False):
    """Generator yielding SSE frames from a follow-mode log tail.

    Each `log` frame carries a LIST of lines, not one line — see the note at the
    top of this module.
    """
    args = base_args(cluster)
    if not args:
        yield sse("error", "cluster has no kubeconfig/context configured")
        return
    cmd = args + ["logs", pod, "-n", namespace, "-f", f"--tail={tail}",
                  "--timestamps"]
    if container:
        cmd += ["-c", container]
    if previous:
        cmd.append("--previous")

    # stderr kept SEPARATE, not folded into stdout. Merged, kubectl's "unable to
    # retrieve container logs for containerd://…" arrived as though the pod had
    # logged it — so the window showed a failure as content, the stream ended,
    # the browser reconnected, and the same line appeared again every few
    # seconds for as long as the window stayed open. One dead pod, one kubectl
    # run per retry, for ever.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    buf: collections.deque = collections.deque(maxlen=BUFFER)
    errs: list = []
    woke = threading.Event()
    ended = threading.Event()

    def pump():
        """Read as fast as kubectl produces, independent of the browser."""
        try:
            for line in proc.stdout:
                buf.append(line.rstrip("\n"))
                # is_set() is an attribute read; set() takes the condition lock
                # and notifies. A 2000-line replay was paying 2000 lock/notify
                # pairs to produce four frames.
                if not woke.is_set():
                    woke.set()
        except Exception:                                      # noqa: BLE001
            pass          # the process going away is the normal way this ends
        finally:
            ended.set()
            woke.set()

    def pump_err():
        """Drained on its own thread so a chatty stderr cannot block kubectl."""
        try:
            for line in proc.stderr:
                errs.append(line.rstrip("\n"))
        except Exception:                                      # noqa: BLE001
            pass

    reader = threading.Thread(target=pump, name="logstream", daemon=True)
    reader.start()
    errreader = threading.Thread(target=pump_err, name="logstream-err",
                                 daemon=True)
    errreader.start()

    try:
        while True:
            if not buf:
                if ended.is_set():
                    break
                # No lines and none arriving: hold the connection open so a
                # proxy does not decide the request is finished.
                if not woke.wait(KEEPALIVE):
                    yield ": keepalive\n\n"
                    continue
                woke.clear()
                continue
            # Give the rest of the burst a moment to land so it goes out in
            # one frame rather than five hundred — but not when a full frame is
            # already waiting. Sleeping before each chunk of a replay spent
            # 320ms doing nothing to deliver lines that were already in memory.
            if len(buf) < MAX_BATCH:
                time.sleep(BATCH_WINDOW)
            batch = []
            while buf and len(batch) < MAX_BATCH:
                batch.append(buf.popleft())
            if batch:
                yield sse("log", batch)
        # kubectl has finished. Whether that is an ending or a failure decides
        # whether the browser should try again, so it is said explicitly — an
        # EventSource reconnects on its own otherwise, and a pod whose logs can
        # never be fetched becomes a retry loop nobody asked for.
        # wait(), not poll(): stdout reaching EOF does not mean the process has
        # been reaped, and poll() answers None for one that is merely finishing
        # — which read as success and sent the browser back to retry.
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rc = None
        errreader.join(timeout=2)      # let the reason arrive before quoting it
        if rc:
            why = " ".join(x for x in errs if x.strip()) or (
                f"kubectl exited {rc} without saying why")
            yield sse("fatal", why)
        else:
            yield sse("end", "the log stream ended — the pod is gone or "
                              "stopped writing")
    except GeneratorExit:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
