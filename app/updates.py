"""Is there a newer release, and where would it come from.

    Two channels, and neither is required: a chart index or release
    feed at PORTAL_UPDATE_URL, or nothing at all. An installation
    that configures neither is told so plainly rather than being
    told it is up to date, because those are different answers.
    """
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request

from . import env
from . import urlguard

# Checked at most this often. A release is a rare event and this is a network
# call on somebody else's machine; hourly is already generous.
EVERY = 6 * 3600
TIMEOUT = 8

_lock = threading.Lock()
_state: dict = {"at": 0.0, "latest": "", "error": "", "checked": False}

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-.]([0-9A-Za-z.-]+))?$")


def url() -> str:
    return env.UPDATE_URL


def parse(text: str) -> str:
    """The newest version in a Helm index or a JSON manifest, or "".

    The index is read with a regex rather than a YAML parser: the portal has no
    YAML dependency, the shape here is two well-known keys, and a chart index
    that cannot be read must degrade to "no idea" rather than to a traceback.
    """
    text = (text or "").strip()
    if not text:
        return ""
    if text.startswith("{"):
        try:
            got = json.loads(text)
        except json.JSONDecodeError:
            return ""
        for key in ("version", "latest", "tag_name"):
            value = str(got.get(key) or "").lstrip("v")
            if _SEMVER.match(value):
                return value
        return ""
    # a Helm index lists every published version; the newest is the one we want
    found = [m.group(1) for m in re.finditer(r"^\s+version:\s*v?([^\s#]+)",
                                             text, re.M)]
    ranked = [v for v in found if _SEMVER.match(v)]
    return max(ranked, key=key_of) if ranked else ""


def key_of(version: str) -> tuple:
    """Sort key. A pre-release sorts below the release it leads to.

    0.2.0-rc1 must come before 0.2.0, or a customer on the release would be
    told to "upgrade" to the candidate it superseded.
    """
    m = _SEMVER.match((version or "").lstrip("v"))
    if not m:
        return (-1, 0, 0, 0, "")
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def newer(latest: str, current: str) -> bool:
    if not latest or not current:
        return False
    return key_of(latest) > key_of(current)


def _fetch() -> tuple[str, str]:
    target = url()
    if not target:
        return "", ""
    req = urllib.request.Request(urlguard.check(target), headers={
        "User-Agent": f"config-portal/{env.VERSION}",
        "Accept": "application/json, text/yaml, */*"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(512_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return "", f"the update feed answered {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return "", f"could not reach the update feed: {e}"
    got = parse(body)
    if not got:
        return "", "the update feed carried no version this portal could read"
    return got, ""


def check(force: bool = False) -> dict:
    """What we know about the newest release. Never raises, never blocks long.

    Cached: a page render must not wait on somebody else's web server, and the
    answer changes a few times a year.
    """
    if not url():
        return {"configured": False, "current": env.VERSION, "latest": "",
                "available": False, "error": "", "checked": False, "age": None}
    with _lock:
        stale = force or (time.time() - _state["at"]) > EVERY
        if stale:
            latest, error = _fetch()
            _state.update({"at": time.time(), "checked": True,
                           "latest": latest or _state["latest"], "error": error})
        s = dict(_state)
    return {"configured": True, "current": env.VERSION, "latest": s["latest"],
            "available": newer(s["latest"], env.VERSION),
            "error": s["error"], "checked": s["checked"],
            "age": int(time.time() - s["at"]) if s["at"] else None}


def peek() -> dict:
    """Cache only — for a page that must not make a network call to render."""
    if not url():
        return {"configured": False, "available": False, "latest": "",
                "current": env.VERSION, "error": "", "checked": False,
                "age": None}
    with _lock:
        s = dict(_state)
    return {"configured": True, "current": env.VERSION, "latest": s["latest"],
            "available": newer(s["latest"], env.VERSION), "error": s["error"],
            "checked": s["checked"],
            "age": int(time.time() - s["at"]) if s["at"] else None}


def refresh_soon() -> None:
    """Warm the cache off the request path."""
    if not url():
        return
    threading.Thread(target=check, kwargs={"force": True},
                     name="update-check", daemon=True).start()
