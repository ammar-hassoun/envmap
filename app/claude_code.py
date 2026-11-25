"""Claude Code for the doctor, fetched by the portal where nobody installed it.

WHY THIS EXISTS
    The 3D view's doctor runs through Claude Code (`doctor_cli`) for people
    whose Claude is a subscription and who have no API key. On a laptop Claude
    Code is simply there. In a cluster it is not: the image does not carry it
    (it is Anthropic's software, under Anthropic's terms, and 360 MB), so dev
    answered every call with "the doctor is thinking" for ever (22 November
    2026). An installation that switches this on (`PORTAL_DOCTOR_CLI_FETCH`,
    the chart's `portal.doctorClaudeCode`) has the portal fetch it itself,
    from Anthropic's own release server, the first time somebody calls.

WHAT IS TRUSTED
    Only Anthropic's release server, the same one Anthropic's installer uses
    (`downloads.claude.ai/claude-code-releases`): the stable version it names,
    that version's manifest, and the binary checked against the manifest's
    SHA-256 and size before it is ever made executable. A binary that does not
    match is deleted, never run.

WHERE IT IS KEPT
    On the data volume (`DATA/claude-code/<version>/claude`), so it is fetched
    once per version rather than at every pod start, and the root filesystem
    can stay read-only. A newer stable release is not fetched by itself: the
    one that works keeps working until the volume is cleared.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import threading
import urllib.request
from pathlib import Path

from . import env, urlguard

BASE = "https://downloads.claude.ai/claude-code-releases"
TIMEOUT = 30
log = logging.getLogger(__name__)
_guard = threading.Lock()
_state = {"state": "idle", "why": "", "got": 0, "size": 0, "version": ""}


def home() -> Path:
    return env.DATA_DIR / "claude-code"


def plat() -> str:
    m = platform.machine().lower()
    return "linux-arm64" if m in ("aarch64", "arm64") else "linux-x64"


def path() -> str:
    """The newest verified copy on the volume, or "" when there is none."""
    got = sorted((p for p in home().glob("*/claude") if os.access(p, os.X_OK)),
                 key=lambda p: [int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", p.parent.name)])
    return str(got[-1]) if got else ""


def status() -> dict:
    with _guard:
        return dict(_state)


def fetch() -> dict:
    """Start fetching when there is nothing to run and nothing under way, and
    say where it stands. Never waits: a call from the view returns at once."""
    with _guard:
        before = dict(_state)
        if path():
            _state.update(state="ready", why="")
        elif _state["state"] != "fetching":
            _state.update(state="fetching", why="", got=0, size=0, version="")
            threading.Thread(target=_fetch, name="claude-code-fetch", daemon=True).start()
            if before["state"] == "failed":
                return before        # what went wrong last time is the news; the retry is under way
        return dict(_state)


def waiting(st: dict) -> str:
    """The sentence the view shows while there is no Claude Code to start."""
    if st.get("state") == "failed":
        return ("this portal could not fetch Claude Code from Anthropic (" + st.get("why", "")
                + "); it is trying again, so call again in a minute")
    done = f", {st['got'] * 100 // st['size']}% so far" if st.get("size") else ""
    return ("this portal is fetching Claude Code from Anthropic for the first time"
            + done + ": call again in a minute or two")


def _get(url: str) -> bytes:
    with urlguard.urlopen(urlguard.check(url), timeout=TIMEOUT) as r:
        return r.read()


def _fetch() -> None:
    part = None
    try:
        version = _get(f"{BASE}/stable").decode().strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", version):
            raise ValueError("the release server did not name a version")
        info = json.loads(_get(f"{BASE}/{version}/manifest.json"))["platforms"][plat()]
        want, size = str(info["checksum"]).lower(), int(info.get("size") or 0)
        if not re.fullmatch(r"[0-9a-f]{64}", want):
            raise ValueError("the manifest carries no checksum for this machine")
        with _guard:
            _state.update(version=version, size=size)
        dest = home() / version
        dest.mkdir(parents=True, exist_ok=True)
        part = dest / "claude.part"
        h, got = hashlib.sha256(), 0
        with urlguard.urlopen(urlguard.check(f"{BASE}/{version}/{plat()}/claude"), timeout=TIMEOUT) as r, \
                open(part, "wb") as out:
            while chunk := r.read(1 << 20):
                out.write(chunk)
                h.update(chunk)
                got += len(chunk)
                with _guard:
                    _state["got"] = got
        if h.hexdigest() != want or (size and got != size):
            raise ValueError("the download did not match Anthropic's checksum, so it was thrown away")
        os.chmod(part, 0o755)
        os.replace(part, dest / "claude")
        part = None
        with _guard:
            _state.update(state="ready", why="")
        log.info("claude code %s fetched for the doctor", version)
    except Exception as e:                       # noqa: BLE001 - said in the view, and retried on the next call
        with _guard:
            _state.update(state="failed", why=str(e)[:160] or type(e).__name__)
        log.warning("claude code could not be fetched: %s", e)
    finally:
        if part is not None:
            try:
                part.unlink()
            except OSError:
                pass
