"""A recorded WEB session — a browser in the cluster, watched through guacd.

WHY THIS EXISTS
    guacd speaks RDP, VNC and SSH. It does not speak HTTP, so a web
    application cannot become a watchable, recorded session on its own: the
    only way to record *somebody using a web app* with this machinery is for a
    BROWSER that guacd can see to be the thing using it.

    Reported as "I added a web application to PAM but I cannot see a live
    session, and I cannot see the recording for it" — and before this the
    honest answer was that a web target was a bookmark with an audit line.

    Everything downstream is reused unchanged. To guacd a seat is an ordinary
    VNC target, so the `.guac` recording, the Active tab, watch/end and the
    replay player all work without knowing that a web target exists.

ONE POD PER SESSION, and that is a security property rather than tidiness.
    Two people sharing one browser share its cookies, so the second would
    inherit the first's authenticated session — in a privileged-access tool
    that is the whole game, not an edge case. A seat's pod starts empty and is
    deleted when the session ends: nothing is carried between sessions and
    nothing is left behind. It is also why there is no pool.

THE IMAGE CONTRACT, and why this product does not build the image.
    A seat needs two things from its image: a VNC server for guacd to render,
    and a way to be told which URL to open. A Selenium standalone image offers
    both — VNC on 5900 and WebDriver on 4444 — and is maintained by somebody
    else, which is worth a great deal in a commercial image that runs in
    somebody else's cluster. Shipping our own browser image would mean a
    second artefact to build, sign, publish and re-patch for every browser CVE
    for ever. So the image, its two ports and its VNC password are
    CONFIGURATION: the next customer will have their own approved browser.

REACHED BY PORT-FORWARD, deliberately.
    guacd runs as a sidecar in the portal's own pod and therefore shares the
    portal's network namespace — so a `kubectl port-forward` started by this
    module is reachable by guacd at 127.0.0.1. That is what makes the browser
    cluster a CHOICE: the pod does not have to live in the portal's own
    cluster, or on a pod network the portal could route to. The cost is worth
    stating plainly rather than discovering: the VNC stream goes through the
    API server.

    (`kmanage` refuses `port-forward` as a verb somebody may TYPE, for the
    good reason that it holds a connection open and belongs on their own
    machine. This is not that: it is the portal holding a connection open for
    the length of a session it is already managing, the same shape as the SSH
    ControlMaster behind file transfer.)

WHAT HAPPENS IF THE PORTAL DIES MID-SESSION
    The pod carries `activeDeadlineSeconds`, so it stops on its own even if
    nothing ever calls `close()`. `sweep()` removes what it finds anyway,
    because a stopped pod still occupies a name and a line in `kubectl get`.
"""
from __future__ import annotations

import contextlib
import json
import queue
import re
import secrets
import shutil
import subprocess
import threading
import time

import httpx

from . import kube

# One shape, so `close()` can only ever delete a pod this module created — the
# same guard `kmanage.netshoot_stop` applies for the same reason.
POD_RE = re.compile(r"^pam-web-[0-9a-f]{8}$")
LABELS = {"app.kubernetes.io/managed-by": "devops-envmap",
          "envmap.tech/component": "pam-web-seat"}
# A SPARE is a seat that is already running and belongs to nobody yet. The
# label is how a claim is made visible to every replica and to an operator
# with kubectl: `spare=yes` is free to take, anything else is somebody's
# session. Claiming FLIPS the label — it never reuses a pod that has been
# claimed before, so the one-pod-per-session isolation is untouched.
SPARE_LABEL = "envmap.tech/spare"
# The screen a seat was built with, so a claim can tell whether a waiting spare
# is the right shape for the person claiming it.
SCREEN_LABEL = "envmap.tech/screen"
MIN_SCREEN, MAX_SCREEN = 320, 3840
# THE SIZE THE LAST PERSON ACTUALLY HAD. A spare is built before anybody has
# asked for it, so it has to guess a screen -- and a spare of the wrong shape
# is not a saving, it is a pod nobody can use. Remembered here so the pool
# converges on the size this install is really being read at. In memory only:
# on a restart the pool starts from the configured default and the first click
# corrects it, which is a cold start once rather than a setting to maintain.
_screen_seen: tuple = ()
URL_OK = re.compile(r"(?i)^https?://[^\s<>\"']+$")
NS_OK = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# A BARE HOST NAME. These become `--host-resolver-rules` exclusions and are
# resolved for the egress policy, so anything carrying a scheme, a port, a
# path or a space is a rule that would not mean what it looks like.
HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,252}[a-z0-9])?$")

APPLY_TIMEOUT = 25
READY_TIMEOUT = 120          # a browser image is large; the first pull is slow
FORWARD_TIMEOUT = 20
DRIVER_TIMEOUT = 60
PAGE_TIMEOUT = 20            # how long a target page may take to settle
FAREWELL_TIMEOUT = 5         # showing the sign-off must never hold a teardown
FAREWELL_SETTLE = 0.7        # long enough for guacd to record one frame
READY_POLL = 3               # how often the pod is asked how it is getting on
NUDGE_EVERY = 4              # re-issue a navigation that has not committed
DELETE_TIMEOUT = 15


class Refused(Exception):
    """Said in words a person can act on, never a stack trace."""


def _clusters() -> dict:
    """{cid: cluster} across every project — a seat names one cluster by id and
    nothing else knows which project it sits under."""
    from . import store
    out = {}
    for pid, p in (store.projects() or {}).items():
        for cid, c in (p.get("clusters") or {}).items():
            out[cid] = dict(c, id=cid, pid=pid)
    return out


def cluster_options() -> list:
    """What the settings page offers — every cluster the portal could run a
    browser in, each saying whether it actually can."""
    from . import kmanage
    out = []
    for cid, c in sorted(_clusters().items(), key=lambda kv: kv[1].get("name", "")):
        out.append({"id": cid, "name": c.get("name") or cid,
                    "pid": c.get("pid", ""),
                    "why": "" if kube.base_args(c) and kmanage.writable(c)
                           else ("no kubeconfig or context set"
                                 if not kube.base_args(c)
                                 else "management is not enabled for it")})
    return out


def why_unavailable(cfg: dict) -> str:
    """"" when a seat can be opened, else the reason in words.

    Asked BEFORE a button is offered, so the catalogue can disable the action
    with the reason in its title rather than failing after the click — the
    house rule for an inapplicable action.
    """
    from . import kmanage
    if not cfg.get("web_browser"):
        return ("recorded web sessions are switched off — an administrator "
                "turns them on in Settings → Privileged Access")
    if not shutil.which(kube.KUBECTL):
        return f"{kube.KUBECTL} is not installed in this image"
    cid = str(cfg.get("web_cluster") or "").strip()
    if not cid:
        return ("no cluster is chosen to run browsers in — set one in "
                "Settings → Privileged Access")
    c = _clusters().get(cid)
    if not c:
        return "the cluster chosen to run browsers in is no longer registered"
    if not kube.base_args(c):
        return f"{c.get('name') or cid} has no kubeconfig or context set"
    if not kmanage.writable(c):
        # A seat is a pod, and a pod is a write. Reuse the one sentence that
        # already says where the tick lives rather than inventing a ninth.
        return kmanage.read_only_why(
            f"a browser for a web session has to be created in "
            f"{c.get('name') or cid}")
    if not NS_OK.match(str(cfg.get("web_namespace") or "")):
        return "the namespace for browser pods is not a valid namespace name"
    # PORTS THAT NOTHING COULD ANSWER, refused before a pod is built rather
    # than discovered as a readiness probe that never passes. A customer ran
    # for days with both of these set to 1 — collapsed there by a settings
    # save, not typed — so every seat was probed on port 1, every browser
    # "never became ready", and no page in the product said anything was
    # wrong. The portal was building a pod it could have known was
    # unreachable.
    #
    # Below 1024 is the test because these are ports INSIDE the seat, bound by
    # a container that does not run as root: a Selenium image cannot listen
    # there whatever the number says. They are properties of the image rather
    # than preferences, which is why a wrong one is a fault and not a choice.
    for key, label, usual in (("web_driver_port", "WebDriver", 4444),
                              ("web_vnc_port", "VNC", 5900)):
        port = int(cfg.get(key) or 0)
        if port < 1024:
            # NAME THE FIELD, not the page. The first version of this sent
            # somebody to "Settings → Privileged Access" while they were
            # already on it, looking straight at the box, and they had to ask
            # where the option was. A direction is only useful from where the
            # reader is standing.
            return (f"the {label} port for browsers is set to {port}, which "
                    f"nothing in the browser image listens on — a seat would "
                    f"never become ready. Put {usual} in the “ports & "
                    f"password” row under Recorded web sessions")
    # THE TOPOLOGY HAS TO ADD UP. guacd renders the seat by connecting to it,
    # so a guacd that is not this pod's sidecar cannot be pointed at
    # 127.0.0.1 — that is its own loopback, and the seat lives on the
    # portal's. Refused in words here rather than surfacing later as "the
    # browser did not answer", which names the wrong thing entirely.
    from . import pam
    if not pam.guacd_is_local(cfg.get("guacd_host")) \
            and not str(cfg.get("web_seat_host") or "").strip():
        return (f"guacd runs at {cfg['guacd_host']}, not as this portal's "
                "sidecar, so it cannot reach a browser at 127.0.0.1 — set "
                "\"how guacd reaches this portal\" in Settings → Privileged "
                "Access to an address that answers there")
    return ""


def remember_screen(w, h) -> None:
    """Note the screen a real console just asked for, for the spare pool."""
    global _screen_seen
    # JUDGED HERE, not inferred from what screen_of falls back to. It used to
    # read a junk size as "" by passing zero defaults and checking the result
    # was truthy -- and once the seat's size was clamped to a floor, that
    # fallback stopped being zero and garbage began teaching the pool a
    # 320x320 pool. A sentinel that another function is free to change is not
    # a check.
    try:
        w, h = int(w or 0), int(h or 0)
    except (TypeError, ValueError):
        return
    if (MIN_SCREEN <= w <= MAX_SCREEN and MIN_SCREEN <= h <= MAX_SCREEN):
        _screen_seen = (_even(w), _even(h))


def wanted_screen(cfg: dict) -> tuple:
    """The screen a spare should be built with."""
    return _screen_seen or (int(cfg["rdp_width"]), int(cfg["rdp_height"]))


def _even(n: int) -> int:
    """Down to an even number of pixels, never below the floor.

    A pane is whatever height a browser window happens to be, and a seat asked
    for an ODD one gets a framebuffer with an odd dimension. Observed on a
    customer's session: a desktop of 1728x829 whose VNC link then died with
    guacd reporting "Error handling message from VNC server" -- and odd
    dimensions are a long-standing sore point in the encoders underneath, since
    several of them work in 2x2 blocks. This is not proof that it was the
    cause, and it is not offered as one; it is one pixel of height against a
    class of failure that is expensive to diagnose and free to avoid.
    """
    return max(MIN_SCREEN, n - (n % 2))


def screen_of(cfg: dict, size=None) -> tuple:
    """The seat's screen, in pixels: the CLIENT's when one is known.

    WHY IT IS THE CLIENT'S AND NOT A SETTING. The seat used to render at a
    configured size shared with RDP, and the console then scaled that image
    into whatever pane the person actually had. Two things went wrong and only
    one of them looks like scaling: the picture was resampled, AND the page
    computed its own responsive layout for a viewport nobody was looking at.
    Reported as "the dimensions look so bad, it is not the same as when I
    connect directly using my device browser" — which is exactly right, because
    it was not the same: a 1280x800 page shrunk to 85% inside a 1410x679 pane.

    Matching the client makes the scale exactly 1: pixel for pixel, and the
    application lays itself out for the size it is being read at.

    Bounded, because this arrives from a browser: a screen is a screen, and a
    seat asked for 30000 pixels of framebuffer is a way to spend a node's
    memory rather than a way to see a page.
    """
    try:
        w, h = int((size or (0, 0))[0] or 0), int((size or (0, 0))[1] or 0)
    except (TypeError, ValueError, IndexError):
        w = h = 0
    if not (MIN_SCREEN <= w <= MAX_SCREEN and MIN_SCREEN <= h <= MAX_SCREEN):
        return (_even(int(cfg["rdp_width"])), _even(int(cfg["rdp_height"])))
    return (_even(w), _even(h))


def manifest(name: str, cfg: dict, sid: str = "", spare: bool = False,
             size=None) -> dict:
    """The seat's pod.

    Locked down as far as a browser allows and no further — a browser needs to
    write (its profile, its cache) and Chromium's own sandbox needs
    `/dev/shm`, so `readOnlyRootFilesystem` and a tiny shm are the two things
    NOT claimed here. Saying which is honest; pretending otherwise would mean
    a pod that starts and then fails in a way nobody can read.
    """
    ttl = int(cfg["web_ttl"])
    shm = str(cfg.get("web_shm_mb") or 512)
    scr = screen_of(cfg, size)
    return {
        "apiVersion": "v1", "kind": "Pod",
        # The session id is a LABEL, so `kubectl get pods -l
        # envmap.tech/session=<id>` answers "which browser is that recording"
        # — the question an operator asks when a seat is still up and nobody
        # knows whose it is.
        "metadata": {"name": name, "namespace": cfg["web_namespace"],
                     "labels": dict(LABELS, **{"envmap.tech/seat": name},
                                    **{SCREEN_LABEL: f"{scr[0]}x{scr[1]}"},
                                    **({"envmap.tech/session": sid} if sid
                                       else {}),
                                    **({SPARE_LABEL: "yes"} if spare else {}))},
        "spec": {
            # SPREAD, softly. Three of nine nodes had the image and a seat had
            # no scheduling hint at all, so a spare MISS landed on a cold node
            # two times in three and paid the whole pull. Spreading the pool
            # puts the image on more nodes over time; `ScheduleAnyway` because
            # a seat that will not schedule is worse than one that is slow.
            "topologySpreadConstraints": [{
                "maxSkew": 1,
                "topologyKey": "kubernetes.io/hostname",
                "whenUnsatisfiable": "ScheduleAnyway",
                "labelSelector": {"matchLabels": dict(LABELS)},
            }],
            "restartPolicy": "Never",
            # THE BACKSTOP, and the reason a leaked seat is not a leaked
            # browser: even if the portal is killed between opening a session
            # and closing it, the pod stops by itself.
            "activeDeadlineSeconds": ttl,
            "terminationGracePeriodSeconds": 2,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "containers": [{
                "name": "browser", "image": cfg["web_image"],
                "imagePullPolicy": "IfNotPresent",
                "env": [
                    {"name": "SE_VNC_PASSWORD", "value": cfg["web_vnc_password"]},
                    {"name": "SE_SCREEN_WIDTH", "value": str(scr[0])},
                    {"name": "SE_SCREEN_HEIGHT", "value": str(scr[1])},
                    # A seat is watched, not shared: nothing else may queue a
                    # browser on it while somebody is looking at it.
                    {"name": "SE_NODE_MAX_SESSIONS", "value": "1"},
                    {"name": "SE_NODE_OVERRIDE_MAX_SESSIONS", "value": "true"},
                ],
                "ports": [
                    {"name": "vnc", "containerPort": int(cfg["web_vnc_port"])},
                    {"name": "driver", "containerPort": int(cfg["web_driver_port"])},
                ],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": cfg.get("web_cpu_req") or "200m",
                                 "memory": cfg.get("web_mem_req") or "768Mi"},
                    "limits": {"cpu": cfg.get("web_cpu_lim") or "2",
                               "memory": cfg.get("web_mem_lim") or "2Gi"},
                },
                # READY MUST MEAN "SELENIUM IS LISTENING", not "the container
                # is running". Without this, `kubectl wait
                # --for=condition=Ready` returns the moment the process
                # starts, while the JVM still needs tens of seconds to bind
                # 4444 — so everything after it raced a browser that was not
                # there yet, and whether it worked depended on how fast the
                # node was. The grid's own /status is the authority on this,
                # and it is the same endpoint wait_driver polls.
                "readinessProbe": {
                    "httpGet": {"path": "/status",
                                "port": int(cfg["web_driver_port"])},
                    "initialDelaySeconds": 2,
                    "periodSeconds": 2,
                    "failureThreshold": 60,
                },
                "volumeMounts": [
                    {"name": "shm", "mountPath": "/dev/shm"},
                    # OVER THE VENDOR'S LOGO. `start-vnc.sh` in the browser
                    # image runs `fbsetbg -u Esetroot -c
                    # /usr/share/images/fluxbox/ubuntu-light.png`, and that
                    # file is the Selenium Grid mark -- visible for the second
                    # before the browser covers it, and again if a session
                    # drops. `subPath` replaces the one file and leaves the
                    # rest of the image alone; such a mount is read-only
                    # always, which is all that is wanted here.
                    {"name": "brand", "mountPath": WALL_PATH,
                     "subPath": "wall.png", "readOnly": True},
                ],
            }],
            # WRITTEN BY AN INIT CONTAINER, not carried in a ConfigMap. A
            # ConfigMap would be a second object to create, update and delete
            # alongside every seat, and one more thing to leak when a pod dies
            # in a way the portal does not see -- which has already happened
            # once, to the NetworkPolicies. This travels inside the pod and
            # goes when the pod goes. The SAME IMAGE as the browser, so there
            # is nothing extra to pull.
            "initContainers": [{
                "name": "brand",
                "image": cfg["web_image"],
                "imagePullPolicy": "IfNotPresent",
                "command": ["sh", "-c",
                            "printf %s \"$WALL_B64\" | base64 -d > /brand/wall.png"],
                "env": [{"name": "WALL_B64", "value": wallpaper_b64()}],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "500m", "memory": "128Mi"}},
                "volumeMounts": [{"name": "brand", "mountPath": "/brand"}],
            }],
            "volumes": [
                {"name": "shm", "emptyDir": {
                    "medium": "Memory", "sizeLimit": f"{shm}Mi"}},
                {"name": "brand", "emptyDir": {"sizeLimit": "1Mi"}},
            ],
        },
    }


def _run(argv: list, timeout: int, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin or None, capture_output=True,
                          text=True, timeout=timeout)


# ANY bind address, not just loopback. `--address 0.0.0.0` (which forward()
# itself passes whenever the seat is dialled at something other than
# 127.0.0.1) makes kubectl print "Forwarding from 0.0.0.0:<port> -> 5900" —
# which the loopback-only pattern could not match, so the seat never learned
# its ports and open_seat hung. The default path prints four lines, two of
# them loopback, which is why the shipped sidecar arrangement worked and this
# was invisible until the escape hatch was used.
_FWD_LINE = re.compile(r"Forwarding from \S+:(\d+) -> (\d+)")


# THE SEAT'S OWN GROUND, drawn here rather than shipped as a file. The browser
# image paints its VENDOR'S logo on the desktop -- `start-vnc.sh` runs
# `fbsetbg -u Esetroot -c /usr/share/images/fluxbox/ubuntu-light.png`, and that
# file is the Selenium Grid mark. It shows for the second before the browser
# covers it, it shows again if a session drops, and it was reported both times:
# somebody else's branding on the inside of this product.
#
# WHY IT IS GENERATED. Drawing a logo needs a raster library and a font, and
# Pillow is not a declared dependency of this product -- adding one to paint a
# background is the wrong trade. But a PNG is a container around zlib, and both
# are in the standard library, so the mark this product already draws in SVG
# can be drawn again in pixels with no dependency at all: a ground, a rounded
# square with the same gradient, and the two rhombi. No text, because text is
# the part that would need a font.
_wallpaper_cache: dict = {}
WALL_PX = 512                 # generous for a scaled background, small to encode
WALL_PATH = "/usr/share/images/fluxbox/ubuntu-light.png"


def wallpaper_png(mark: bool = True) -> bytes:
    """The seat desktop's background, as PNG bytes. Computed once."""
    import struct                                            # noqa: PLC0415
    import zlib                                              # noqa: PLC0415
    if mark in _wallpaper_cache:
        return _wallpaper_cache[mark]
    n = WALL_PX
    bg = (0x0d, 0x11, 0x17)                       # the product's own ground
    a, b = (0x5b, 0x8d, 0xef), (0x8b, 0x6c, 0xf5)  # the mark's gradient stops
    # The mark occupies the middle third, on the 24-unit grid its SVG uses.
    side = n // 3
    x0 = y0 = (n - side) // 2
    unit = side / 24.0
    radius = 6 * unit                              # rx="6" on a 24-wide square
    rows = []
    for y in range(n):
        row = bytearray()
        for x in range(n):
            r, g, bl = bg
            if mark and x0 <= x < x0 + side and y0 <= y < y0 + side:
                # local coordinates on the 24x24 grid
                lx, ly = (x - x0) / unit, (y - y0) / unit
                px, py = x - x0, y - y0
                # rounded corners: outside the corner circle is ground
                cx = radius if px < radius else (side - radius
                                                 if px > side - radius else px)
                cy = radius if py < radius else (side - radius
                                                 if py > side - radius else py)
                inside = ((px - cx) ** 2 + (py - cy) ** 2) <= radius ** 2
                if inside:
                    t = (lx + ly) / 48.0           # x1,y1 -> x2,y2 diagonal
                    r = int(a[0] + (b[0] - a[0]) * t)
                    g = int(a[1] + (b[1] - a[1]) * t)
                    bl = int(a[2] + (b[2] - a[2]) * t)
                    # the two stacked rhombi, the lower one at half opacity
                    for cyc, alpha in ((7.6, 1.0), (16.6, 0.5)):
                        if abs(lx - 12) / 9.0 + abs(ly - cyc) / 4.2 <= 1.0:
                            r = int(r + (255 - r) * alpha)
                            g = int(g + (255 - g) * alpha)
                            bl = int(bl + (255 - bl) * alpha)
                            break
            row += bytes((r, g, bl))
        rows.append(bytes(row))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xffffffff))

    raw = b"".join(b"\x00" + r for r in rows)      # filter type 0 per scanline
    out = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    _wallpaper_cache[mark] = out
    return out


def wallpaper_b64() -> str:
    """The desktop background, base64, for the init container to decode."""
    import base64                                            # noqa: PLC0415
    return base64.b64encode(wallpaper_png(True)).decode("ascii")


def brand_page(name: str, site: str = "", mark: bool = True) -> str:
    """A `data:` URL showing the install's own name, for the seat to end on.

    WHY THE BROWSER AND NOT THE WALLPAPER. Reported after watching a recording
    back: the last thing on it was the Selenium Grid desktop, which is this
    product's plumbing captioning somebody's audit evidence — the same
    objection as the automation bar. The seat's wallpaper is a file in its
    image (`/usr/share/images/fluxbox/ubuntu-light.png`, which that image
    overwrites with its own logo), so it COULD be replaced by mounting over
    it — but drawing a name into a PNG needs a raster library and a font, and
    Pillow is not a declared dependency of this product. Adding one to caption
    a desktop is the wrong trade.

    The seat already has a renderer with every font it needs: the browser
    guacd is pointed at. So the last thing the session shows is a page, which
    also makes it BRAND-AWARE for free — a customer who has renamed this
    install sees their name, not ours, exactly as every other surface does.

    A `data:` URL because a seat cannot reach the portal: its egress policy
    allows the target and DNS, and `--host-resolver-rules` makes every other
    host unresolvable. Nothing is fetched, so nothing has to be allowed.

    NO ORGANISATION NAME. This used to print the brand's SUBTITLE under the
    product name, and on a real install that subtitle is a COMPANY — so the
    last frame of somebody's audit evidence carried one. Reported on sight,
    and correctly: a recording is a record of what an operator did, not a
    place to sign the work. The line below it is kept because it says
    something about the RECORDING; the subtitle said something about whoever
    runs the portal.

    `site` replaces it and is empty for now: the product's own address will go
    there once there is a page to point at, which is a URL about the software
    rather than a name about a company. Until then the seat signs off with the
    install's own name and nothing else.
    """
    import html
    import urllib.parse as _u
    # The mark follows the same rule it does everywhere: it appears only when
    # the install is not wearing somebody else's name. Our logo over a
    # customer's name would be worse than no logo at all.
    logo = ("""<svg viewBox="0 0 24 24" width="112" height="112">
      <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#5b8def"/>
      <stop offset="1" stop-color="#8b6cf5"/></linearGradient></defs>
      <rect width="24" height="24" rx="6" fill="url(#g)"/>
      <path d="M12 3.4 21 7.6 12 11.8 3 7.6Z" fill="#fff"/>
      <path d="M12 12.4 21 16.6 12 20.8 3 16.6Z" fill="#fff" opacity=".5"/>
      </svg>""" if mark else "")
    doc = (
        "<!doctype html><meta charset=utf-8><title>" + html.escape(name)
        + "</title><style>html,body{height:100%;margin:0}"
        "body{background:#0d1117;color:#e6edf7;display:flex;"
        "align-items:center;justify-content:center;"
        "font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
        ".w{text-align:center}"
        ".n{margin:22px 0 0;font-size:34px;font-weight:650;letter-spacing:-.4px}"
        ".o{margin:6px 0 0;font-size:14px;color:#7d8ba0}"
        ".e{margin:26px 0 0;font-size:12.5px;color:#7d8ba0}</style>"
        '<div class="w">' + logo
        + '<div class="n">' + html.escape(name) + "</div>"
        + ('<div class="o">' + html.escape(site) + "</div>" if site else "")
        + '<div class="e">this session has ended and the recording is closed</div>'
        + "</div>")
    return "data:text/html;charset=utf-8," + _u.quote(doc, safe="")


_notes: dict = {}
_notes_lock = threading.Lock()


def note(sid: str, text: str) -> None:
    """Record what the seat is doing, for the person watching a blank pane.

    The console could only ever say "starting a browser in the cluster…" and
    then guess at a cause, because the seat is built on a worker thread while
    the socket is held open somewhere else and nothing carried a word between
    them. A dict and a lock carry it: the builder writes, the relay's
    keepalive reads and sends it on.

    Kept small and dropped with the session — this is a progress line, not a
    log, and a note nobody is waiting for is one nobody should be keeping.
    """
    if not sid:
        return
    with _notes_lock:
        _notes[sid] = (text or "")[:400]


def progress(sid: str) -> str:
    """The seat's latest note, or "" — read by the relay while it waits."""
    with _notes_lock:
        return _notes.get(sid, "")


def forget(sid: str) -> None:
    with _notes_lock:
        _notes.pop(sid, None)


class Seat:
    """One browser, alive for the length of one session.

    Holds three things that must be released together — the pod, the
    port-forward and the WebDriver session — which is why it is an object and
    not three return values.
    """

    def __init__(self, cluster: dict, cfg: dict, name: str, sid: str = "",
                 also=(), size=None):
        self.cluster, self.cfg, self.name, self.sid = cluster, cfg, name, sid
        self.also = tuple(also or ())
        self.size = size
        self.namespace = cfg["web_namespace"]
        self.proc: subprocess.Popen | None = None
        self.ports: dict = {}
        self.driver_session = ""
        self._closed = False
        self._lock = threading.Lock()

    # ── what the relay needs ──────────────────────────────────
    @property
    def vnc_host(self) -> str:
        """The address GUACD should dial to reach this seat.

        127.0.0.1 is correct for the shipped topology and only that one —
        guacd as a sidecar shares this pod's network namespace, so the
        port-forward below is its loopback too. A guacd running anywhere else
        would dial its OWN loopback and find nothing, which is why this is
        configurable and why `why_unavailable` refuses that combination rather
        than letting it fail as "the browser did not answer".
        """
        return str(self.cfg.get("web_seat_host") or "").strip() or "127.0.0.1"

    @property
    def vnc_port(self) -> int:
        return int(self.ports.get(int(self.cfg["web_vnc_port"]), 0))

    @property
    def vnc_password(self) -> str:
        return str(self.cfg["web_vnc_password"])

    # ── lifecycle ─────────────────────────────────────────────
    def _base(self) -> list:
        base = kube.base_args(self.cluster)
        if not base:
            raise Refused("that cluster has no kubeconfig or context set")
        return base

    def create(self) -> None:
        body = json.dumps(manifest(self.name, self.cfg, self.sid,
                                   size=self.size))
        try:
            r = _run(self._base() + ["apply", "-f", "-"], APPLY_TIMEOUT, body)
        except subprocess.TimeoutExpired:
            raise Refused("the cluster did not answer in time")
        if r.returncode != 0:
            from . import kmanage
            said = (r.stderr or "").strip()[:300]
            why = kmanage.why_refused(self.cluster, self.namespace, "create")
            raise Refused(f"the browser could not be started: {said}"
                          + (f" — {why}" if why else ""))

    def trouble(self) -> str:
        """What the CLUSTER says is wrong with this pod, or "".

        WHY THIS EXISTS. The console said "starting a browser in the
        cluster… 16s" and then, at 30s, asserted that the image was being
        pulled — a guess, and on a customer's install usually the wrong one.
        Every failure this feature has had away from our own cluster was
        something Kubernetes could have said outright: the image cannot be
        pulled from that registry, no node will schedule it, the namespace
        has a policy that rejects the pod. We were inferring from here what
        the API server was willing to state.

        So it is asked. `waiting.reason` on the container status is
        `ImagePullBackOff` / `ErrImagePull` / `CreateContainerConfigError`
        and friends; an unscheduled pod has no container status at all and
        its reason is on the pod's conditions instead. The message is
        whatever THAT says, never a sentence composed here about a cause
        nobody checked.
        """
        try:
            r = _run(self._base() + ["get", "pod", self.name,
                                     "-n", self.namespace, "-o", "json"],
                     DELETE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return "the cluster did not answer when asked about the pod"
        if r.returncode != 0:
            # "I COULD NOT ASK" IS NOT "NOTHING IS WRONG", and conflating them
            # is what produced the worst message this feature has sent: a
            # customer watched a pod that was up and serving while the console
            # said the browser never became ready and the cluster reported
            # nothing wrong. Both halves were false, and the reason was that
            # the read itself had failed — a namespace the credential cannot
            # list, RBAC that allows create and not get. Silence about a
            # failed question is worse than no question.
            said = (r.stderr or r.stdout or "").strip()
            return ("this portal cannot read that pod's status, so it cannot "
                    "tell whether the browser started: "
                    + (said[:200] or "the cluster gave no reason"))
        try:
            pod = json.loads(r.stdout or "{}")
        except ValueError:
            return ""
        st = pod.get("status") or {}
        for cs in (st.get("containerStatuses") or []):
            wait = (cs.get("state") or {}).get("waiting") or {}
            why = (wait.get("message") or "").strip()
            reason = (wait.get("reason") or "").strip()
            # Running and ContainerCreating are not trouble; everything else
            # a container waits on is worth repeating verbatim.
            if reason and reason not in ("ContainerCreating", "PodInitializing"):
                # A CRASH LOOP NAMES WHAT KILLED IT. `CrashLoopBackOff` says
                # the container keeps dying and not why; `OOMKilled` and the
                # exit code are on the PREVIOUS state, and they are the
                # actionable half — "give it more memory" versus "read the
                # logs" are different jobs.
                last = ((cs.get("lastState") or {}).get("terminated") or {})
                end = ""
                if last.get("reason") or last.get("exitCode") is not None:
                    end = (f" (last: {last.get('reason') or 'exited'}"
                           + (f", exit {last['exitCode']}"
                              if last.get("exitCode") is not None else "")
                           + f", restarted {cs.get('restartCount', 0)} times)")
                return (f"{reason}: {why}{end}" if why
                        else f"{reason}{end}")[:300]
        # No container status yet means it has not been scheduled — and the
        # reason for that is on the conditions, not on the container.
        for cond in (st.get("conditions") or []):
            if cond.get("type") == "PodScheduled" and cond.get("status") == "False":
                return (f"{cond.get('reason') or 'not scheduled'}: "
                        f"{cond.get('message') or ''}").strip()[:300]
        # A CONTAINER THAT IS RUNNING AND NEVER READY has its reason in none of
        # the places above, and that is the case a customer actually hit: the
        # console waited the whole budget and then said the cluster reported
        # nothing wrong, which was true of the two things it had looked at and
        # useless to the person waiting. A failing readiness probe is an
        # EVENT, and a container that keeps dying leaves its reason in
        # `lastState`, not in `waiting`.
        for cs in (st.get("containerStatuses") or []):
            last = ((cs.get("lastState") or {}).get("terminated") or {})
            if last.get("reason"):
                return (f"the browser keeps stopping — {last['reason']}"
                        + (f" (exit {last['exitCode']})"
                           if last.get("exitCode") is not None else "")
                        + f", restarted {cs.get('restartCount', 0)} times")[:300]
        if (ev := self._last_warning()):
            return ev + self._last_log()
        # Still nothing: say what it IS doing, which at least distinguishes
        # "not scheduled" from "running and silent".
        phase = st.get("phase") or "unknown"
        ready = [c for c in (st.get("containerStatuses") or [])
                 if not c.get("ready")]
        if phase == "Running" and ready:
            return ("the browser is running but has not answered its readiness "
                    "check — it may need longer, or more memory than this "
                    "namespace allows it") + self._last_log()
        return ""

    def _last_log(self) -> str:
        """The container's own last words, appended to a probe failure.

        "connection refused" says the browser is not listening and not why.
        The container has usually said why — out of memory, a bad flag, a
        display that would not start — and it is the next thing a person
        would look at, so the portal looks instead of making them. Best
        effort and prefixed, so an empty log costs nothing.
        """
        try:
            r = _run(self._base() + ["logs", self.name, "-n", self.namespace,
                                     "--tail=3"], DELETE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return ""
        if r.returncode != 0:
            return ""
        said = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        return (" — it last said: " + said[-1][:160]) if said else ""

    def _last_warning(self) -> str:
        """The pod's most recent Warning event, verbatim.

        This is where `Unhealthy: Readiness probe failed: …`, `FailedMount`
        and the quota refusals live — none of which appear on the pod's own
        status, and all of which are the actual answer to "why is it not
        ready". Read separately because it is a second API call and is only
        worth making once the cheap places have come back empty.
        """
        try:
            r = _run(self._base() + [
                "get", "events", "-n", self.namespace,
                "--field-selector",
                f"involvedObject.name={self.name},type=Warning",
                "-o", "jsonpath={range .items[*]}{.reason}|{.message}{\"\\n\"}{end}"],
                DELETE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return ""
        if r.returncode != 0:
            return ""
        lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
        if not lines:
            return ""
        reason, _, msg = lines[-1].partition("|")
        return f"{reason.strip()}: {msg.strip()}"[:300]

    def wait_ready(self) -> None:
        # From CONFIG, not the module constant: a 1.5GB pull on a slow link
        # was seen still running at 268s, and a fixed 120s made that a failure
        # instead of a wait.
        budget = int(self.cfg.get("web_ready_timeout") or READY_TIMEOUT)
        # POLLED, not one long `kubectl wait`. Waiting blind for ten minutes
        # and then reporting "timed out waiting for the condition" is the
        # least useful thing this could do with the time — and it is what it
        # did. Polling costs one cheap call every few seconds and lets the
        # pod's own reason be reported the moment the cluster knows it, both
        # to the person waiting and in the refusal.
        end = time.monotonic() + budget
        note(self.sid, "asking the cluster for a browser")
        while time.monotonic() < end:
            try:
                r = _run(self._base() + ["get", "pod", self.name, "-n",
                                         self.namespace, "-o",
                                         "jsonpath={.status.conditions"
                                         "[?(@.type=='Ready')].status}"],
                         DELETE_TIMEOUT)
            except subprocess.TimeoutExpired:
                r = None
            if r is not None and r.returncode == 0 and (r.stdout or "").strip() == "True":
                return
            # A READ THAT FAILED IS NOT A POD THAT IS NOT READY. Polling on
            # blindly turned an unreadable pod into a ten-minute wait and then
            # a sentence that said the opposite of the truth.
            if r is not None and r.returncode != 0:
                raise Refused(
                    "this portal cannot read the browser pod's status: "
                    + ((r.stderr or r.stdout or "").strip()[:200]
                       or "the cluster gave no reason"))
            if (bad := self.trouble()):
                # A pull that is BACKING OFF will not fix itself inside this
                # budget, and making somebody watch a spinner for ten minutes
                # for an answer the cluster already has is the failure this
                # whole change is about.
                if "BackOff" in bad or "Unschedulable" in bad:
                    raise Refused(f"the cluster will not start the browser — {bad}")
                note(self.sid, bad)
            time.sleep(READY_POLL)
        raise Refused("the browser did not become ready in time"
                      + (f" — {bad}" if (bad := self.trouble()) else
                         ". The cluster reported nothing wrong with the pod, so"
                         " it is starting slowly rather than failing"))

    def forward(self) -> None:
        """One port-forward for both ports, with the LOCAL ports chosen by the
        kernel (`:port`) and read back from kubectl's own output.

        Picking a local port ourselves would be a race against every other
        session on this pod; kubectl says which it got, so that is what is
        believed.
        """
        vnc, drv = int(self.cfg["web_vnc_port"]), int(self.cfg["web_driver_port"])
        argv = self._base() + ["port-forward", f"pod/{self.name}",
                               "-n", self.namespace, f":{vnc}", f":{drv}"]
        # kubectl binds 127.0.0.1 by default, which is what the sidecar wants.
        # When guacd is told to dial the portal by some other address, the
        # listener has to exist on an interface that answers there — otherwise
        # the seat opens and guacd cannot reach it, and the failure arrives as
        # a timeout with nothing naming the cause.
        if self.vnc_host != "127.0.0.1":
            argv += ["--address", "0.0.0.0"]
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        # PUMPED BY A THREAD, because `readline()` on a live pipe blocks with
        # no deadline: when nothing more is printed — which is exactly what
        # happens if the lines do not parse — the `while … < deadline` test is
        # never re-evaluated and FORWARD_TIMEOUT can never fire. That did not
        # merely hang the click: it held an anyio worker thread for ever, and
        # enough clicks would stall every threadpool call in the portal. Same
        # shape as the sftp session's own pump in pam.py, for the same reason.
        lines: queue.Queue = queue.Queue()

        def pump(stream) -> None:
            try:
                for ln in iter(stream.readline, ""):
                    lines.put(ln)
            except Exception:                                   # noqa: BLE001
                pass
            finally:
                lines.put(None)

        threading.Thread(target=pump, args=(self.proc.stdout,),
                         daemon=True).start()
        got, deadline = {}, time.monotonic() + FORWARD_TIMEOUT
        while len(got) < 2:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() if self.proc.stderr else "")[:250]
                raise Refused(f"the connection to the browser failed: {err.strip()}")
            try:
                line = lines.get(timeout=min(left, 0.5))
            except queue.Empty:
                continue
            if line is None:                       # the pipe closed
                break
            if (m := _FWD_LINE.search(line)):
                got[int(m.group(2))] = int(m.group(1))
        if len(got) < 2:
            raise Refused("the connection to the browser did not open in time "
                          f"(got {len(got)} of 2 ports)")
        self.ports = got

    def _driver(self) -> str:
        return f"http://127.0.0.1:{self.ports[int(self.cfg['web_driver_port'])]}"

    def wait_driver(self) -> None:
        """Wait for the browser's WebDriver to actually LISTEN.

        `kubectl wait --for=condition=Ready` returns as soon as the container
        is running, and the manifest carries no readinessProbe — but Selenium
        needs several more seconds to bind its port. A port-forward to a port
        nothing is listening on is REFUSED immediately, not slowly, so the
        single POST that used to follow failed fast and deleted the pod. That
        read as flakiness rather than as a missing wait, because whether it
        happened depended on how quickly the node started the container.
        """
        end = time.monotonic() + DRIVER_TIMEOUT
        last = ""
        while time.monotonic() < end:
            try:
                with httpx.Client(timeout=5) as h:
                    r = h.get(f"{self._driver()}/status")
                    if r.status_code < 400 and (r.json().get("value") or {}).get("ready"):
                        return
                    last = f"not ready yet ({r.status_code})"
            except httpx.HTTPError as e:                        # noqa: PERF203
                last = type(e).__name__
            time.sleep(0.5)
        # Say whether the tunnel itself died, because "ConnectError" alone
        # cannot tell "the browser is slow" from "the port-forward is gone".
        tun = ""
        if self.proc is not None and self.proc.poll() is not None:
            err = ""
            with contextlib.suppress(Exception):
                err = (self.proc.stderr.read() or "")[:200].strip()
            tun = f"; the connection to it had already closed ({err or 'no output'})"
        raise Refused("the browser never became ready to accept a session"
                      + (f" — last: {last}" if last else "") + tun)

    def open_url(self, url: str) -> None:
        """Start a browser on the seat and point it at the target.

        This is the step that makes the image contract worth it: a browser
        appears on the VNC display because WebDriver was asked for one, and it
        is looking at the URL because WebDriver was told to. No image-specific
        entrypoint, no baked-in homepage, no start-up file to mount.

        THE SESSION OPENS ON about:blank AND THE TARGET IS A SEPARATE
        NAVIGATION, and that split is the whole fix for a seat that failed
        with "the browser did not answer: ReadTimeout" on a real target. The
        session used to be created with `--app=<target>`, which makes the
        target's page load part of session creation; with the default
        `pageLoadStrategy` that POST does not return until the page fires
        `load`, and a PWA with a service worker and a long-lived connection
        never does. Measured against a real one: session creation 1.3s on
        about:blank in every single run, and the browser demonstrably ON the
        page — the URL and the page title both read back in 0.0s — while the
        old code was still waiting to be told it had loaded.

        `--app=about:blank` rather than dropping `--app`: the window TYPE is
        decided when the window is created, so the app window with no omnibox
        has to be asked for before the navigation, not after. Confinement is
        unchanged.
        """
        if not URL_OK.match(url or "") or not _host_of(url):
            raise Refused("that target has no usable http(s) address")
        self.wait_driver()
        wait = int(self.cfg.get("web_page_timeout") or PAGE_TIMEOUT)
        body = {"capabilities": {"alwaysMatch": {
            # A window, not a headless run — the whole point is that there is
            # something on the display for guacd to render and record.
            "browserName": self.cfg.get("web_browser_name") or "chrome",
            # `none` HANDS THE SEAT OVER AS SOON AS THE BROWSER STARTS ON
            # THE TARGET, which is what a browser does for everybody else:
            # you watch the page arrive. `eager` was tried first and cost the
            # whole timeout — 22.7s of a 22.7s open — because the measured
            # target fires neither `load` NOR DOMContentLoaded inside it, so
            # waiting for either is waiting for something that never comes on
            # a page that is already rendered.
            "pageLoadStrategy": "none",
            # Still bounded, because `none` only shortens the happy path.
            "timeouts": {"pageLoad": wait * 1000},
            # KIOSK, AND AN APP WINDOW. Reported: "from the browser I can
            # see the URL tab where I can open google.com and it works fine".
            # A seat is supposed to be a controlled path to ONE application;
            # a browser with an omnibox is an unrestricted browser running
            # inside somebody's cluster. `--app=` opens a window with no
            # address bar, tab strip or navigation UI, and `--kiosk` takes
            # the window furniture with it.
            #
            # Say plainly what this is and is not: it removes the UI, not the
            # capability. Keyboard shortcuts, a link on the page, or a
            # redirect can still leave the target. The CONTROL is the egress
            # NetworkPolicy; this is the part that stops it being an
            # invitation.
            "goog:chromeOptions": {"args": [
                "--kiosk",
                "--app=about:blank",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate,TabHoverCards",
                "--disable-dev-shm-usage",
                # EVERY OTHER HOST FAILS TO RESOLVE, INSTANTLY. Measured: the
                # target's login page sat on its own spinner for ever because
                # it pulls a tag manager from a third party, and a packet the
                # NetworkPolicy DROPS is not a refusal — the browser waits out
                # a TCP connect timeout, so the app's bootstrap waited too.
                # Nine seconds in, the DOM had not moved and the one pending
                # request was that third party.
                #
                # This is not the confinement — the NetworkPolicy is, and it
                # still catches a request made to a literal address, which
                # this flag cannot see. It is the same rule stated where the
                # browser can act on it, so denial arrives as an error the
                # page can handle rather than as silence it waits on.
                # EVERY NAME THE TARGET'S PAGE MAY USE, not just the one
                # in the address bar. A page is rarely one host: the measured
                # application pulls its API from a second name on the SAME
                # SERVER — already allowed by the egress policy, because it
                # resolves to the same address — and only this rule refused
                # it. So the landing page rendered and signing in could not
                # work, and nothing in the seat could say why.
                "--host-resolver-rules=MAP * ~NOTFOUND"
                + "".join(f", EXCLUDE {h}"
                          for h in [_host_of(url)] + also_hosts(self.also)),
            ],
            # NO "Chrome is being controlled by automated test software".
            # Reported from a real session, and it is worth more than tidiness:
            # the bar eats ~45px off the top of every seat, it invites the
            # person to press its ✕ (which is the one control that could close
            # the window they are working in), and it describes the plumbing
            # rather than the session. WebDriver is how the seat is pointed at
            # the target — that is an implementation detail of this product,
            # not something to caption somebody's screen with.
            #
            # `--disable-infobars` is the flag people reach for and it has
            # done nothing for years; the bar is driven by the
            # `enable-automation` switch, so the switch is what has to go.
            "excludeSwitches": ["enable-automation"]},
        }}}
        try:
            with httpx.Client(timeout=DRIVER_TIMEOUT) as h:
                r = h.post(f"{self._driver()}/session", json=body)
                if r.status_code >= 400:
                    raise Refused("the browser refused to start a session: "
                                  + r.text[:200])
                doc = r.json().get("value") or {}
                self.driver_session = str(doc.get("sessionId") or "")
                if not self.driver_session:
                    raise Refused("the browser did not return a session")
                me = f"{self._driver()}/session/{self.driver_session}"
                # A NAVIGATION TIMEOUT IS NOT A VERDICT ON THE SEAT, and
                # treating it as one is what refused a working session: the
                # measured case answered 500 after the pageLoad timeout with
                # the page loaded, rendered and titled behind it. An app that
                # keeps a connection open has not failed to open, it has
                # failed to say it finished — so the outcome is decided by
                # asking the browser WHERE IT IS, not by how the navigation
                # returned.
                with contextlib.suppress(httpx.HTTPError):
                    h.post(f"{me}/url", json={"url": url},
                           timeout=wait + DRIVER_TIMEOUT)
                # POLLED, because with `none` the navigation returns before
                # the address has changed. A fixed sleep would be a guess in
                # both directions at once: too short refuses a working seat,
                # too long is the wait this whole change exists to remove.
                # RETRIED WHILE IT HAS NOT COMMITTED, because the first
                # attempt can be made before the cluster is ready to carry it.
                # A CLAIMED SPARE is a RUNNING pod whose egress policy was
                # just changed underneath it — from DNS-only, which is what a
                # spare waits on, to one naming this target — and a CNI does
                # not necessarily program that before the browser's first
                # packet. A dropped packet is not a refused one: Chrome shows
                # an error page for a refusal, and hangs for ever on a drop,
                # which is why the symptom is a blank page rather than an
                # error. Chrome does not retry a hung navigation, so this
                # does.
                #
                # A fresh seat never had this problem — it is created with the
                # right policy already on it — which is exactly the kind of
                # difference that only appears on somebody else's cluster.
                want, where, end = _host_of(url), "", time.monotonic() + wait
                nudged = time.monotonic()
                while True:
                    # NEVER LET ONE POLL SPEND THE WHOLE BUDGET. `GET /url` is
                    # itself a WebDriver command, so while the renderer is busy
                    # loading, it QUEUES — it does not answer "still loading",
                    # it answers nothing until the page lets go. Measured on a
                    # customer's target: 0.08s to issue the navigation, then
                    # four consecutive reads that each blocked the full client
                    # timeout before one finally returned the address.
                    #
                    # With a per-read timeout of DRIVER_TIMEOUT (60s) against a
                    # budget of `wait` (20s by default), the first read blocked
                    # for sixty seconds and the deadline below — checked only
                    # AFTER it returned — was long gone. The seat was refused
                    # after exactly ONE look, and the refusal said "not reached
                    # after 20s", blaming the settle time or the seat's
                    # network. Both were wrong: the browser did arrive. The
                    # poll ate the time the page was supposed to get.
                    left = end - time.monotonic()
                    with contextlib.suppress(httpx.HTTPError, ValueError):
                        w = h.get(f"{me}/url",
                                  timeout=max(1.0, min(DRIVER_TIMEOUT, left)))
                        if w.status_code < 400:
                            where = str((w.json() or {}).get("value") or "")
                    if _host_of(where) == want:
                        break
                    if time.monotonic() - nudged >= NUDGE_EVERY:
                        nudged = time.monotonic()
                        with contextlib.suppress(httpx.HTTPError):
                            h.post(f"{me}/url", json={"url": url},
                                   timeout=max(1.0, end - time.monotonic()))
                    if time.monotonic() >= end:
                        # SAY WHAT TO DO, not merely what is true. "the
                        # browser is on nothing" is accurate and leaves the
                        # reader nowhere: still on about:blank means the page
                        # had not begun to arrive, which is either too short a
                        # settle time or a target the SEAT cannot reach — and
                        # the seat's network is not the portal's, which is the
                        # part people do not think of. Both are named, with
                        # the number that was actually used.
                        # `about:blank` is the blank page, not somewhere
                        # else: it has no host, so treating it as a
                        # destination would report "went to about:blank" for
                        # a page that simply had not begun to arrive.
                        seen = _host_of(where)
                        if not seen and where and not where.startswith(
                                ("about:", "data:", "chrome:")):
                            seen = where[:60]
                        # A SEAT IS REFUSED FOR GOING SOMEWHERE ELSE, NOT FOR
                        # BEING SLOW TO SAY WHERE IT WENT. Those are different
                        # facts and only the first one is a verdict.
                        if seen and seen != want:
                            raise Refused(
                                f"the browser went to {seen} instead of {want}")
                        # NOT ARRIVED IS NOT THE SAME AS NOT WORKING, and
                        # refusing here threw away working seats. The
                        # navigation was issued and accepted (`POST /url`
                        # returns in hundredths of a second under
                        # `pageLoadStrategy: none`); all that has not happened
                        # is that the browser has not yet answered a question
                        # about itself. On a slow target it answers a minute
                        # later, having been on the right page the whole time.
                        #
                        # Handing over anyway is what the strategy was chosen
                        # for in the first place: you watch the page arrive,
                        # the way you do in your own browser. It does NOT
                        # loosen confinement — the control is the egress
                        # NetworkPolicy and the resolver rule, neither of which
                        # this check enforces — so the only thing given up is a
                        # confirmation, and that is said out loud rather than
                        # being quietly assumed.
                        # THE GUIDANCE IS NOT LOST, IT STOPS BEING A VERDICT.
                        # Reported from a customer install: "the browser is on
                        # nothing, not <host>" — true, and it left the reader
                        # nowhere. Still blank is either too short a settle
                        # time or a target the SEAT cannot reach, and the
                        # seat's network is not the portal's, which is the part
                        # nobody thinks of. Both are still named, with the
                        # number actually in force; they are now said to
                        # somebody who HAS their seat and can see the screen
                        # for themselves.
                        note(self.sid,
                             f"still opening {want} — connecting anyway. If it "
                             f"stays blank, either raise “allow a page this "
                             f"long to settle” (it is {wait}s) or check that a "
                             f"pod in this browser cluster can reach {want}: "
                             f"the seat resolves and connects on its own, not "
                             f"through this portal")
                        break
                    time.sleep(0.2)
        except httpx.HTTPError as e:
            raise Refused(f"the browser did not answer: {type(e).__name__}")

    def farewell(self, name: str, site: str = "", mark: bool = True) -> None:
        """Show the install's own name, so the recording does not end on
        somebody else's product.

        Called BEFORE the guacd stream is closed, or there is nothing left to
        record it onto — the relay shuts its guacd socket first and guacd
        stops writing the file at that point. Bounded and suppressed
        throughout: a session that has already finished must not be held open
        by its own sign-off, and failing to draw a logo is not a reason to
        leave a browser logged in to a production application.
        """
        if not self.driver_session or not self.ports:
            return
        with contextlib.suppress(Exception):
            with httpx.Client(timeout=FAREWELL_TIMEOUT) as h:
                h.post(f"{self._driver()}/session/{self.driver_session}/url",
                       json={"url": brand_page(name, site, mark)})
            # One beat, so guacd sees the frame and puts it on the recording.
            time.sleep(FAREWELL_SETTLE)

    def close(self) -> None:
        """Release all three, in the order that leaves nothing behind.

        Every step is best-effort and none may raise: this runs in a session's
        teardown, and a browser left running because its WebDriver session
        would not close politely is the worst outcome available.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self.driver_session and self.ports:
            try:
                with httpx.Client(timeout=8) as h:
                    h.delete(f"{self._driver()}/session/{self.driver_session}")
            except Exception:                                   # noqa: BLE001
                pass
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:                                   # noqa: BLE001
                with __import__("contextlib").suppress(Exception):
                    self.proc.kill()
        try:
            delete(self.cluster, self.namespace, self.name)
        except Exception:                                       # noqa: BLE001
            pass
        with contextlib.suppress(Exception):
            drop_policy(self.cluster, self.namespace, self.name)


def delete(cluster: dict, namespace: str, name: str) -> bool:
    """Remove one seat's pod — and ONLY a pod this module named."""
    if not POD_RE.match(name or ""):
        raise Refused("that is not a browser pod this portal started")
    base = kube.base_args(cluster)
    if not base:
        return False
    try:
        r = _run(base + ["delete", "pod", name, "-n", namespace,
                         "--ignore-not-found", "--wait=false"], DELETE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0


def _host_of(url: str) -> str:
    """The hostname alone, folded, for comparing where a browser ended up.

    A redirect to another PATH on the target is the application doing its job
    (`/login` sending somebody to `/dashboard`); a different HOST is the seat
    having left the application it was confined to. Only the second is worth
    refusing, so only the host is compared.
    """
    import urllib.parse as _u
    with contextlib.suppress(ValueError):
        return (_u.urlsplit(url).hostname or "").strip().lower()
    return ""


def also_hosts(also) -> list:
    """The extra hostnames a target's page needs, cleaned.

    WHY A TARGET IS MORE THAN ONE HOST. Measured on a customer's application:
    the page it opens on pulls from three names, not one — the target itself,
    an API on the SAME SERVER under a different name, and an object store.
    The API's address was already allowed by the egress policy, because it
    resolves to the same address as the target; what refused it was
    `--host-resolver-rules`, which excluded exactly one NAME. So the landing
    page rendered and signing in could not work, and nothing in the seat could
    say why.

    Names only, never addresses with schemes or paths: these are used as
    resolver-rule exclusions and resolved for the policy, and anything else is
    a way of writing a rule that does not mean what it looks like.
    """
    out: list = []
    for raw in (also or ()):
        host = str(raw or "").strip().lower().rstrip(".")
        if HOST_OK.match(host) and host not in out:
            out.append(host)
    return out[:20]


def target_ips(url: str, also=()) -> list:
    """Every address the target's host resolves to, for the egress policy.

    Resolved by the PORTAL, once, at seat-open time — not by the browser,
    which is the thing being constrained. A host that resolves to several
    addresses gets all of them; a policy naming one of a round-robin set is a
    session that works four times out of five.
    """
    import socket as _s
    import urllib.parse as _u
    host = (_u.urlsplit(url).hostname or "").strip()
    if not host:
        return []
    found: set = set()
    for h in [host] + also_hosts(also):
        try:
            got = _s.getaddrinfo(h, None)
        except OSError:
            # AN EXTRA HOST THAT DOES NOT RESOLVE IS NOT A REASON TO REFUSE A
            # SEAT: it is one asset the page will do without. The TARGET's own
            # failure to resolve is still fatal, and is checked by the caller
            # on the empty result.
            if h == host:
                return []
            continue
        found.update(a[4][0] for a in got
                     if a[0] in (_s.AF_INET, _s.AF_INET6))
    return sorted(found)


def serving_pods(cluster: dict, ips: list) -> list:
    """The cluster's OWN Services answering on `ips`, as egress peers.

    WHY AN ipBlock IS NOT ENOUGH, and it cost a customer a working console.
    Their target was served by the ingress of the very cluster the seat runs
    in — `traefik/traefik-public`, a LoadBalancer whose external address is
    the address the target's name resolves to. That is not an exotic
    arrangement, it is the most ordinary one there is: the application and
    this portal live in the same cluster.

    A packet from the seat to that address never leaves as "world" traffic.
    The load balancer hairpins it straight back in, so by the time the policy
    engine sees it the destination identity is a POD, not the CIDR that was
    allowed — and a CIDR rule cannot match a pod identity. Under a default
    deny that is a silent DROP, which is why the browser showed
    ERR_CONNECTION_TIMED_OUT rather than a refusal, and why every layer
    underneath looked healthy: the pod ran, the policy was applied exactly as
    written, DNS resolved, and the application answered fine from anywhere
    else in the cluster.

    Measured, same seat and same confinement, one extra rule the only change:
    196 characters of a Chrome error page, frozen for 90 seconds, became the
    application's own page in five.

    THIS DOES NOT WIDEN CONFINEMENT TO THE CLUSTER. The peer is one Service's
    backing pods, in that Service's namespace, on that Service's ports — the
    same application the ipBlock already named, reached by the path it is
    actually served on. Read-only and soft: a cluster this portal cannot list
    Services in simply gets the ipBlock rule it got before.
    """
    if not ips:
        return []
    try:
        r = _kubectl(cluster, ["get", "svc", "-A", "-o", "json"], APPLY_TIMEOUT)
    except (subprocess.TimeoutExpired, Refused):
        return []
    if r.returncode != 0:
        return []
    try:
        items = (json.loads(r.stdout or "{}") or {}).get("items") or []
    except ValueError:
        return []
    want, out = set(ips), []
    for svc in items:
        spec = svc.get("spec") or {}
        selector = spec.get("selector") or {}
        # A Service with no selector has no pods to name — its endpoints are
        # managed by hand, and there is nothing here to allow.
        if not selector:
            continue
        mine = {str(spec.get("clusterIP") or "")}
        mine.update(str(x) for x in (spec.get("externalIPs") or []))
        for ing in ((svc.get("status") or {}).get("loadBalancer") or {}
                    ).get("ingress") or []:
            mine.add(str(ing.get("ip") or ""))
        if not (mine & want):
            continue
        # The port the POD listens on, which is not always the port the
        # Service is published on: a NetworkPolicy peer is the pod.
        ports = []
        for prt in spec.get("ports") or []:
            if str(prt.get("protocol") or "TCP").upper() != "TCP":
                continue
            tgt = prt.get("targetPort")
            ports.append(tgt if tgt not in (None, "") else prt.get("port"))
        out.append({"namespace": str((svc.get("metadata") or {}).get(
            "namespace") or ""), "selector": selector,
            "ports": [x for x in ports if x not in (None, "")]})
    return out


def egress_policy(name: str, cfg: dict, url: str, ips: list,
                  serving: tuple = ()) -> dict:
    """A NetworkPolicy that lets ONE seat reach ONE application, and DNS.

    This is the actual control, and the reason a seat is worth its weight:
    without it the browser pod can reach every service in the cluster, the
    node's metadata endpoint, and the internet — so an operator holding
    `pam_connect` on one harmless target would have a browser inside the
    cluster with none of those restrictions. Kiosk mode hides the address bar;
    this is what makes the address bar's absence mean something.

    Egress only. Ingress is not restricted because the port-forward reaches
    the pod through the kubelet, and closing it would break the session
    without closing anything an attacker wanted.
    """
    import urllib.parse as _u
    port = _u.urlsplit(url).port or (443 if url.lower().startswith("https") else 80)
    to = [{"ipBlock": {"cidr": f"{ip}/{'128' if ':' in ip else '32'}"}}
          for ip in ips]
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": cfg["web_namespace"],
                     "labels": dict(LABELS, **{"envmap.tech/seat": name})},
        "spec": {
            "podSelector": {"matchLabels": {"envmap.tech/seat": name}},
            "policyTypes": ["Egress"],
            "egress": [
                # DNS ON PORT 53 TO ANYWHERE, and the destination is
                # deliberately unrestricted. This used to name the
                # `kube-system` namespace, which is where CoreDNS lives and
                # which is wrong on a great many real clusters:
                #
                #   * NodeLocal DNSCache intercepts DNS to the kube-dns
                #     ClusterIP with iptables and answers from a LINK-LOCAL
                #     address on the NODE (169.254.20.10). The node is not a
                #     pod in any namespace, so a namespace selector cannot
                #     match it and every lookup is dropped. Found on a
                #     customer's cluster, where the seat became Ready — the
                #     grid binds locally and needs no DNS — and then sat on a
                #     blank page because the browser could not resolve the one
                #     host it was allowed to visit.
                #   * a cluster may run DNS outside kube-system, or forward to
                #     a resolver on the VPC.
                #
                # WHAT THIS DOES NOT WIDEN: the browser still cannot FETCH
                # anything but the target — TCP egress below is the single
                # address list — and `--host-resolver-rules` already refuses
                # to resolve any host but that one. Being able to ask a
                # question of a resolver is not being able to reach a service,
                # and a confinement that only works on our own cluster is not
                # a confinement.
                {"ports": [{"protocol": "UDP", "port": 53},
                           {"protocol": "TCP", "port": 53}]},
                # and the application itself, on its own port. Nothing else.
                {"to": to, "ports": [{"protocol": "TCP", "port": int(port)}]},
            ] + [
                # ...and the same application by the path it is actually
                # served on, when that is this cluster's own ingress. See
                # serving_pods: the ipBlock above cannot match a hairpinned
                # packet, whose destination identity is a pod.
                {"to": [{"namespaceSelector": {"matchLabels": {
                            "kubernetes.io/metadata.name": svc["namespace"]}},
                         "podSelector": {"matchLabels": svc["selector"]}}],
                 "ports": [{"protocol": "TCP", "port": prt}
                           for prt in svc["ports"]]}
                for svc in serving
                # PORTS ARE MANDATORY ON THIS PEER, and the `if` is why.
                # A NetworkPolicy rule with no `ports` allows EVERY port to
                # the pods it selects -- so a Service whose targetPort could
                # not be read (a named port resolved on the pod, an odd
                # spec) silently turned "the application, on its own port"
                # into "every port on the ingress controller". That is the
                # confinement widening itself exactly when it knows least,
                # and the seat is what it is confining. Omitting the peer
                # instead costs a hairpinned request through this cluster's
                # own ingress -- a session that fails visibly, which is the
                # direction this control is required to fail in.
                if svc.get("namespace") and svc.get("selector")
                and svc.get("ports")
            ],
        },
    }


def _kubectl(cluster: dict, args: list, timeout: int) -> subprocess.CompletedProcess:
    base = kube.base_args(cluster)
    if not base:
        raise Refused("that cluster has no kubeconfig or context set")
    return _run(base + args, timeout)


def _apply(cluster: dict, doc: dict, timeout: int = APPLY_TIMEOUT) -> bool:
    base = kube.base_args(cluster)
    if not base:
        return False
    try:
        r = _run(base + ["apply", "-f", "-"], timeout, json.dumps(doc))
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0


def lock_egress(cluster: dict, cfg: dict, name: str, url: str,
                also=()) -> str:
    """Confine one seat to one application. "" on success, else why not.

    Applied at OPEN/CLAIM time rather than at creation, because a spare does
    not know its target yet — a spare is created with the DNS-only policy
    below, so it is never unrestricted even while it waits.
    """
    ips = target_ips(url, also)
    if not ips:
        return (f"the target's host could not be resolved, so the browser "
                f"cannot be confined to it — refusing rather than opening an "
                f"unrestricted browser in {cluster.get('name') or 'the cluster'}")
    serving = serving_pods(cluster, ips)
    if not _apply(cluster, egress_policy(name, cfg, url, ips,
                                         tuple(serving))):
        return ("the egress policy for the browser could not be applied — "
                "refusing rather than opening an unrestricted browser")
    return ""


def idle_policy(name: str, cfg: dict) -> dict:
    """DNS only. What a SPARE gets while it waits for somebody: it has no
    target yet, and a browser sitting unrestricted in a cluster is the thing
    this whole mechanism exists to avoid."""
    doc = egress_policy(name, cfg, "https://127.0.0.1:443/", [])
    doc["spec"]["egress"] = [doc["spec"]["egress"][0]]      # keep DNS, drop the rest
    return doc


def drop_policy(cluster: dict, ns: str, name: str) -> None:
    base = kube.base_args(cluster)
    if not base or not POD_RE.match(name or ""):
        return
    with contextlib.suppress(Exception):
        _run(base + ["delete", "networkpolicy", name, "-n", ns,
                     "--ignore-not-found", "--wait=false"], DELETE_TIMEOUT)


def spares(cfg: dict) -> list:
    """Every unclaimed seat, with the resourceVersion a claim needs.

    READY only: an unclaimed pod still pulling its image is not a spare, it is
    a promise, and handing it out would reintroduce the wait it exists to
    remove.
    """
    cluster = _clusters().get(str(cfg.get("web_cluster") or "").strip())
    if not cluster or not kube.base_args(cluster):
        return []
    ns = str(cfg.get("web_namespace") or "")
    if not NS_OK.match(ns):
        return []
    sel = f"{SPARE_LABEL}=yes,envmap.tech/component=pam-web-seat"
    try:
        r = _kubectl(cluster, ["get", "pods", "-n", ns, "-l", sel,
                               "-o", "json"], DELETE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return []
    if r.returncode != 0:
        return []
    try:
        items = (json.loads(r.stdout or "{}") or {}).get("items") or []
    except ValueError:
        return []
    out = []
    for pod in items:
        meta, status = pod.get("metadata") or {}, pod.get("status") or {}
        name = str(meta.get("name") or "")
        if not POD_RE.match(name):
            continue
        phase = str(status.get("phase") or "")
        cs = status.get("containerStatuses") or [{}]
        out.append({"name": name,
                    "rv": str(meta.get("resourceVersion") or ""),
                    "phase": phase,
                    "ready": phase == "Running" and bool(cs[0].get("ready")),
                    # READ AS JSON, not as columns. A space-separated jsonpath
                    # drops a field that is empty and every column after it
                    # shifts left -- which on the reaping path once lined a
                    # live session up to be deleted. A spare created before
                    # this label existed has no screen, and that is exactly
                    # the row that would have shifted.
                    "screen": str((meta.get("labels") or {}).get(
                        SCREEN_LABEL) or ""),
                    # A pod that has STOPPED is not a spare and never will be
                    # again: a spare carries the same activeDeadlineSeconds as
                    # a session, so one that waited longer than the deadline is
                    # Failed. That corpse was still counted, so the pool
                    # believed it was full and a real click paid the cold start
                    # it was meant to avoid -- measured, and reported as still
                    # very slow.
                    "dead": phase in ("Failed", "Succeeded")})
    return out


def ensure_spares(cfg: dict) -> dict:
    """Top the spare pool up to `web_spares`, creating what is missing.

    Called from the warmer's periodic pass and again right after a claim, so
    the pod somebody just took is replaced while they are using it. Does
    nothing at all when the feature is off or the pool size is zero — a
    browser running in somebody's cluster because they upgraded is not
    acceptable.
    """
    want = int(cfg.get("web_spares") or 0)
    if why_unavailable(cfg):
        return {"have": 0, "made": 0, "want": want}
    all_spares = spares(cfg)
    # RETIRE THE ONES NOBODY CAN USE. A spare's screen is fixed when its pod is
    # created, so once the pool learns the size this install is really read at,
    # the ones built for the old guess are waste: they count towards `want`, so
    # without this the pool stays full of pods no claim will ever take and every
    # click pays the cold start the pool exists to avoid.
    keep_scr = "%dx%d" % wanted_screen(cfg)
    if want > 0:
        stale = [sp for sp in all_spares
                 if not sp["dead"] and sp.get("screen") != keep_scr]
        for sp in stale:
            with contextlib.suppress(Exception):
                delete(_clusters()[str(cfg["web_cluster"]).strip()],
                       cfg["web_namespace"], sp["name"])
                drop_policy(_clusters()[str(cfg["web_cluster"]).strip()],
                            cfg["web_namespace"], sp["name"])
        if stale:
            all_spares = [sp for sp in all_spares if sp not in stale]
    # SETTING THE POOL TO ZERO MUST DRAIN IT, not abandon it. It used to
    # return here whenever `want` was 0, so turning the pool off stranded
    # every spare already running until its own deadline killed it — each one
    # holding a memory request and a pod slot the whole time. Found on a
    # cluster that was FULL: turning the pool off to free room did the
    # opposite, and the fresh seat that replaced the claim could not be
    # scheduled at all ("0/2 nodes are available: 1 Insufficient memory, 1 Too
    # many pods"). Off has to mean off NOW, or the setting cannot be used to
    # recover from the situation it is most needed in.
    cluster = _clusters()[str(cfg["web_cluster"]).strip()]
    ns = cfg["web_namespace"]
    # Clear the corpses FIRST, or they are counted as pool and nothing is
    # ever replaced.
    reaped = 0
    for dead in [sp for sp in all_spares if sp["dead"]]:
        with contextlib.suppress(Exception):
            delete(cluster, ns, dead["name"])
            drop_policy(cluster, ns, dead["name"])
        reaped += 1
    have = [sp for sp in all_spares if not sp["dead"]]
    # Surplus above `want` goes too — which for want=0 is all of them. Only
    # UNCLAIMED spares are touched: `spares()` selects `spare=yes`, so a pod
    # somebody is using is never in this list.
    for extra in have[want:]:
        with contextlib.suppress(Exception):
            delete(cluster, ns, extra["name"])
            drop_policy(cluster, ns, extra["name"])
        reaped += 1
    have = have[:want]
    made = 0
    for _ in range(max(0, want - len(have))):
        seat = Seat(cluster, cfg, f"pam-web-{secrets.token_hex(4)}", "")
        # DNS-only while it waits, so a spare is never an unrestricted
        # browser sitting in somebody's cluster.
        _apply(cluster, idle_policy(seat.name, cfg))
        body = json.dumps(manifest(seat.name, cfg, "", spare=True,
                                   size=wanted_screen(cfg)))
        # `apply` reads the manifest from stdin, which _kubectl does not pass.
        base = kube.base_args(cluster)
        try:
            r = _run(base + ["apply", "-f", "-"], APPLY_TIMEOUT, body)
        except subprocess.TimeoutExpired:
            break
        if r.returncode != 0:
            break
        made += 1
    return {"have": len(have), "made": made, "want": want, "reaped": reaped}


def claim_spare(cfg: dict, url: str, sid: str, also=(),
                size=None) -> Seat | None:
    """Take a ready spare and make it this session's seat, or None.

    The claim is a LABEL FLIP with `--resource-version`, which is optimistic
    concurrency: if another session took the same pod between the list and the
    flip, kubectl refuses and this tries the next one. Without that, two
    sessions could share one browser — which is the whole thing the
    one-pod-per-session rule exists to prevent, so it may not be left to luck.
    """
    if not int(cfg.get("web_spares") or 0):
        return None
    cluster = _clusters().get(str(cfg.get("web_cluster") or "").strip())
    if not cluster:
        return None
    # A SPARE OF THE WRONG SHAPE IS NOT A SAVING. Claiming it would put the
    # person back where they started: a page laid out for a screen they do not
    # have, resampled to fit the one they do. Better to pay the cold start once
    # and then have a pool that fits -- ensure_spares retires the wrong ones,
    # so this corrects itself after the first click rather than every time.
    want_scr = "%dx%d" % screen_of(cfg, size)
    for cand in [s for s in spares(cfg)
                 if s["ready"] and s.get("screen") == want_scr]:
        try:
            r = _kubectl(cluster, ["label", "pod", cand["name"],
                                   "-n", cfg["web_namespace"],
                                   f"{SPARE_LABEL}=taken",
                                   f"envmap.tech/session={sid or 'unnamed'}",
                                   "--overwrite",
                                   f"--resource-version={cand['rv']}"],
                         DELETE_TIMEOUT)
        except subprocess.TimeoutExpired:
            continue
        if r.returncode != 0:
            continue                      # somebody else won it; try the next
        seat = Seat(cluster, cfg, cand["name"], sid, also, size)
        try:
            # CONFINE IT BEFORE IT CAN GO ANYWHERE. The spare has been sitting
            # on the DNS-only policy; this replaces it with one naming this
            # target, and it happens before the browser is told the URL.
            if (why := lock_egress(cluster, cfg, seat.name, url, also)):
                raise Refused(why)
            seat.forward()
            seat.open_url(url)
        except BaseException:
            seat.close()
            raise
        return seat
    return None


def open_seat(cfg: dict, url: str, sid: str = "", also=(),
              size=None) -> Seat:
    """A ready browser looking at `url`, or `Refused` saying which step failed.

    The steps are separate and named because they fail differently and a
    person can only act on one of them: the cluster refused the pod, the image
    never became ready, the connection did not open, the browser would not
    load the page.
    """
    if (why := why_unavailable(cfg)):
        raise Refused(why)
    # A WARM SPARE FIRST. Creating the pod here means paying for the image
    # pull with somebody watching a blank pane: measured on a real cluster,
    # 36.9s cold and 4.3s warm. A spare is already Running and already has the
    # image, so claiming one is a label flip and a port-forward. It is never a
    # pod that has served before — the claim flips it OUT of the pool and it
    # is deleted at the end — so nothing about the isolation changes.
    claimed = claim_spare(cfg, url, sid, also, size)
    if claimed is not None:
        return claimed
    cluster = _clusters()[str(cfg["web_cluster"]).strip()]
    seat = Seat(cluster, cfg, f"pam-web-{secrets.token_hex(4)}", sid, also,
                size)
    step = "confining the browser"
    try:
        # The policy goes on BEFORE the pod, so there is no instant in which
        # the browser exists without it.
        if (why := lock_egress(cluster, cfg, seat.name, url, also)):
            raise Refused(why)
        step = "creating the browser pod"
        seat.create()
        step = "waiting for the browser pod to be ready"
        seat.wait_ready()
        step = "opening a connection to the browser"
        seat.forward()
        step = "telling the browser to open the target"
        seat.open_url(url)
    except Refused as e:
        seat.close()
        # NAME THE STEP. "the browser never became ready" and "the egress
        # policy could not be applied" fail at different places and are fixed
        # in different places, and a reader who only sees the sentence cannot
        # tell how far it got.
        raise Refused(f"{e} (while {step})") from None
    except BaseException:
        # Half a seat is worse than none: a pod that was created and then
        # abandoned would sit there rendering nothing until its deadline.
        seat.close()
        raise
    return seat


def reap_orphans(cfg: dict, live: set) -> list:
    """Delete seat pods that no live session owns, and their policies.

    THE GAP THIS CLOSES: `ensure_spares` only ever reaped pods labelled
    `spare=yes`, so a seat that had been CLAIMED (`spare=taken`) or created
    directly (no spare label at all) was never collected once its session
    ended — observed on a real cluster as three seat pods where there should
    have been one, each holding its memory request until
    `activeDeadlineSeconds` finally stopped it and left a corpse behind.

    `live` is the set of session ids the portal currently believes are open.
    A pod naming a session that is not in it is finished; a pod naming no
    session and holding no spare label was created for a session that never
    got as far as being registered. Both are rubbish.

    The deadline is still the backstop — this is the tidying that makes the
    backstop rare rather than routine.
    """
    cluster = _clusters().get(str(cfg.get("web_cluster") or "").strip())
    ns = str(cfg.get("web_namespace") or "")
    if not cluster or not kube.base_args(cluster) or not NS_OK.match(ns):
        return []
    sel = "envmap.tech/component=pam-web-seat"
    try:
        # READ AS JSON, NOT AS A jsonpath TEMPLATE, and the reason is a
        # bug this function shipped with. jsonpath emits an ABSENT label as
        # an empty field, and `.split()` collapses runs of whitespace — so a
        # seat created directly, which carries a session but no spare label,
        # came back as two fields and its SESSION ID was read as the spare
        # label. It then looked like a pod naming no session at all, which is
        # this function's definition of rubbish: it would have deleted the
        # browser somebody was using, mid-session.
        #
        # A separator does not fix it either: `|` is a jsonpath operator and
        # the template is refused outright ("unterminated quoted string").
        # A structured read has no delimiter to get wrong, and this walks a
        # handful of pods on a warmer pass, so the extra bytes cost nothing.
        r = _kubectl(cluster, ["get", "pods", "-n", ns, "-l", sel,
                              "-o", "json"], DELETE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return []
    # A FAILED LISTING IS NOT AN EMPTY CLUSTER, and conflating the two here
    # deleted the egress policy of every LIVE seat. kubectl writes nothing to
    # stdout when it fails, so `json.loads("{}")` gave `items = []` with no
    # exception -- `alive` was then empty, and the orphan sweep below, whose
    # own listing had succeeded, found every policy unclaimed and dropped it.
    # The browsers kept running, unconfined, inside the customer's cluster.
    # RBAC on the namespace, an unreachable API server or a renamed namespace
    # are all enough, and this runs on a repeating warmer pass. The policy
    # listing already checked its return code; the pod listing did not.
    if r.returncode != 0:
        return []
    try:
        items = (json.loads(r.stdout or "{}") or {}).get("items") or []
    except ValueError:
        return []
    gone = []
    for pod in items:
        meta = (pod or {}).get("metadata") or {}
        labels = meta.get("labels") or {}
        name = str(meta.get("name") or "")
        spare = str(labels.get(SPARE_LABEL) or "")
        sess = str(labels.get("envmap.tech/session") or "")
        if not POD_RE.match(name):
            continue
        if spare == "yes":
            continue                     # a spare waiting for somebody
        if sess and sess in live:
            continue                     # somebody is using it right now
        with contextlib.suppress(Exception):
            delete(cluster, ns, name)
            drop_policy(cluster, ns, name)
        gone.append(name)
    # ORPHANED POLICIES OUTLIVE THEIR PODS, and nothing was collecting them.
    # `drop_policy` runs when the PORTAL deletes a seat — but a pod that dies
    # of its own `activeDeadlineSeconds` is never deleted by us, so its
    # NetworkPolicy stayed for ever. Found on a customer's cluster holding one
    # from twenty hours earlier, and they accumulate one per seat that ever
    # timed out. Harmless individually and unbounded in aggregate, which is
    # the worst shape for a leak: nothing ever fails because of it.
    try:
        r = _kubectl(cluster, ["get", "networkpolicy", "-n", ns, "-o",
                               "jsonpath={range .items[*]}{.metadata.name}"
                               "{\"\\n\"}{end}"], DELETE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return gone
    if r.returncode != 0:
        return gone
    alive = {(pod.get("metadata") or {}).get("name") for pod in items}
    for pol in (r.stdout or "").splitlines():
        pol = pol.strip()
        # Only ours, by the name shape this module creates, and only when no
        # pod of that name is left.
        if POD_RE.match(pol) and pol not in alive:
            with contextlib.suppress(Exception):
                drop_policy(cluster, ns, pol)
            gone.append(pol)
    return gone


def sweep(cfg: dict) -> list:
    """Every seat pod still in the browser namespace, and remove them.

    Not the primary guard — `activeDeadlineSeconds` is, because it works when
    the portal is not running. This is for the restart case, where a pod is
    stopped but still occupying a name and a line in `kubectl get`.
    """
    cid = str(cfg.get("web_cluster") or "").strip()
    cluster = _clusters().get(cid)
    if not cluster or not kube.base_args(cluster):
        return []
    ns = str(cfg.get("web_namespace") or "")
    if not NS_OK.match(ns):
        return []
    sel = ",".join(f"{k}={v}" for k, v in LABELS.items())
    try:
        r = _run(kube.base_args(cluster)
                 + ["get", "pods", "-n", ns, "-l", sel,
                    "-o", "jsonpath={.items[*].metadata.name}"], DELETE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return []
    names = [n for n in (r.stdout or "").split() if POD_RE.match(n)]
    for n in names:
        delete(cluster, ns, n)
        drop_policy(cluster, ns, n)
    return names
