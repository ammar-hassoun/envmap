"""Privileged Access — a catalogue of targets, brokered credentials, and a
recording of every live session.

WHAT THIS IS FOR
    One place that answers three questions a bastion answers: what can be
    reached, who may open a live door to it, and what happened once they were
    in. A **target** is a machine or app and the protocol to reach it — SSH, RDP,
    VNC, a web app, a database. Its **credential is brokered**: the vault holds
    the key or password, sealed at rest, and hands it to the transport at connect
    time; the person never sees it. Every session is **recorded** — the screen,
    replayable, and (for SSH) the commands — and every connect, refusal and
    command is audited.

WHY IT IS ITS OWN MODULE, NOT PART OF ANSIBLE
    The recording began life inside Ansible, recording SSH terminals on inventory
    hosts. But recording a session is not an Ansible idea, and a PAM reaches more
    than hosts a playbook runs against. The recording primitives
    (`kmanage.SessionCast`, `pty_audit_line`, the `Recording` accumulator) only
    ever consumed "screen bytes" and "finished command lines", so they lift out
    unchanged; what is new here is the target catalogue, the credential broker,
    and — for RDP/VNC — the Guacamole gateway.

THE TRANSPORTS, AND WHAT RECORDS THEM
    * **SSH** — a pty running `ssh`, the same machinery the cluster pod terminal
      uses, recorded as an asciinema cast (`rec_kind='asciinema'`).
    * **RDP / VNC** — a relay to `guacd` (Apache Guacamole's daemon), which
      renders the desktop to the browser and writes its own session recording
      (`rec_kind='guac'`). guacd is a sidecar; without it, those targets say so.
    * **Web app / database** — CATALOGUED AND OPENED, and that is all. The
      browser goes straight to the application; the portal is not in the path,
      so there is no live session, no recording, and nothing is injected into
      the request — a stored credential on such a target is held and unused.
      `/pam/targets/{id}/launch` audits the open and redirects, which is the
      only thing the portal can honestly contribute without a proxy. A
      recorded web proxy and a query console are a later phase. This used to
      read "launched with the brokered credential", which was not true of any
      code path and is what produced "I added a web application but I cannot
      see a live session or a recording for it".

    A recording is always a FILE indexed by a row: the `pam_sessions` row carries
    `rec_kind` and `rec_rel` (a path relative to DATA), so the replay page picks
    the right player and a stored path can never point outside the data volume.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import queue
import re
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from . import db, env, secretbox, store
# Shared portal machinery — the SSH pty scratch, the password askpass, the
# project/region helpers and the relative-time words all already exist in the
# Ansible module, which keeps its own host terminal. Reused rather than copied.
from . import ansible
from .ansible import (Refused, _askpass, _dur_words, _placed, _term_scratch,
                      ago, drop_session_dir, place_of)
from .paths import DATA

# Recordings (the casts and the guac files) are files, not database rows: a
# recording is written a line at a time for the length of a session, and the row
# beside it is only the index and the command transcript.
SESSIONS = DATA / "pam-sessions"

# What a target may be. SSH/RDP/VNC are the live, recorded protocols — `live`
# is what the page counts and what produces a session and a recording. http(s)
# and the databases are catalogued and OPENED: the browser goes straight to
# them, so there is no session and no recording, and the open is audited
# instead. A recorded proxy / query console is a later phase.
PROTOCOLS = {
    "ssh":      {"label": "SSH",        "port": 22,   "live": True,  "guac": False},
    "rdp":      {"label": "RDP",        "port": 3389, "live": True,  "guac": True},
    "vnc":      {"label": "VNC",        "port": 5900, "live": True,  "guac": True},
    "https":    {"label": "Web (HTTPS)", "port": 443, "live": False, "guac": False},
    "http":     {"label": "Web (HTTP)",  "port": 80,  "live": False, "guac": False},
    "postgres": {"label": "PostgreSQL", "port": 5432, "live": False, "guac": False},
    "mysql":    {"label": "MySQL",      "port": 3306, "live": False, "guac": False},
}
GUAC_PROTOCOLS = tuple(k for k, v in PROTOCOLS.items() if v["guac"])


def enabled() -> bool:
    """Whether Privileged Access is switched on for this installation.

    OFF by default, and toggled from **Settings → Privileged Access** — it was
    an environment variable (`PORTAL_PAM`) and was moved into the portal on
    request, because an installation switch that needs a redeploy to flip is
    not a switch the person running the portal owns.

    The whole PAM — this module, its routes, templates and tests — stays in the
    tree, and while this is off every entry point (the sidebar link, the
    Ansible shell button, the `/pam` routes themselves) vanishes from the
    running product. **Settings → Privileged Access is the one thing that does
    NOT vanish**, because the switch has to be reachable to be switched: a page
    that hides the only way to turn itself back on is a one-way door.

    See CLAUDE.md → "Privileged Access is a switch in Settings".
    """
    return config()["enabled"]


# The environment a target lives in. Free-form (the portal's environments are
# discovered folder names, not a fixed enum), but a known label gets a tidy
# display name and a colour so prod stands apart from staging at a glance; an
# unknown label shows as typed, in a neutral tone. Prod-class labels also switch
# on the typed-name safeguard automatically. The vocabulary mirrors the generic
# software-lifecycle families config.py already uses for env icons.
ENV_META = {
    "production":     ("Production",  "danger"),
    "prod":           ("Production",  "danger"),
    "pre-production": ("Pre-prod",    "warn"),
    "preproduction":  ("Pre-prod",    "warn"),
    "preprod":        ("Pre-prod",    "warn"),
    "staging":        ("Staging",     "warn"),
    "stage":          ("Staging",     "warn"),
    "uat":            ("UAT",         "warn"),
    "qa":             ("QA",          "accent"),
    "test":           ("Test",        "accent"),
    "testing":        ("Test",        "accent"),
    "development":    ("Development", "ok"),
    "dev":            ("Development", "ok"),
    "sandbox":        ("Sandbox",     "ok"),
    "dr":             ("DR",          "accent"),
}
PROD_ENVS = {"production", "prod"}
ENV_SUGGEST = ["production", "pre-production", "staging", "uat", "qa", "test",
               "development", "dr"]


def env_norm(env: str) -> str:
    return (env or "").strip().lower()[:40]


def env_label(env: str) -> str:
    """The tidy display name for an environment — the known label, or the raw
    value as typed, or '' when there is none."""
    e = env_norm(env)
    if not e:
        return ""
    return ENV_META.get(e, ((env or "").strip()[:40], ""))[0]


def env_tone(env: str) -> str:
    """The colour tone for an environment badge: danger|warn|accent|ok|muted."""
    return ENV_META.get(env_norm(env), ("", "muted"))[1] or "muted"


def env_is_prod(env: str) -> bool:
    """Whether an environment is production-class — used to switch the typed-name
    safeguard on by default when a target is placed in prod."""
    return env_norm(env) in PROD_ENVS

# A target name and an address become arguments to ssh or parameters to guacd, so
# they are checked rather than trusted — the same discipline the Ansible host
# terminal uses (a smuggled `-o ProxyCommand=…` in an address is a remote command
# execution, not a broken connection).
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
ADDR_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,253}$")

STATUS_RUNNING = "running"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    return db.connect()


def _migrate(c: sqlite3.Connection) -> None:
    """Two tables — the catalogue and the sessions — created then extended
    additively, plus a one-time carry-forward of the SSH recordings that were
    made while this feature lived inside Ansible.
    """
    # A target: what to reach, how, and the credential to reach it with. The
    # credential is sealed (secretbox), exactly as an Ansible group's key is —
    # `secret_sealed` is never returned to a browser. `extra` is protocol detail
    # as JSON (RDP domain/security/ignore-cert, screen size, a web URL, a db
    # name) so a new protocol needs no new column.
    c.execute("""CREATE TABLE IF NOT EXISTS pam_targets (
        id TEXT PRIMARY KEY, name TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'ssh', address TEXT, port INTEGER,
        proj_id TEXT DEFAULT '', rgn_id TEXT DEFAULT '',
        tags TEXT DEFAULT '', is_prod INTEGER DEFAULT 0,
        env TEXT DEFAULT '',
        hostname TEXT DEFAULT '',            -- the machine's own name; address may be an IP
        label TEXT DEFAULT '',               -- what people call it, free text
        username TEXT DEFAULT '',
        auth_kind TEXT DEFAULT '',           -- key | password | none
        secret_sealed TEXT DEFAULT '',       -- the key or password, via secretbox
        extra TEXT DEFAULT '',               -- JSON, protocol-specific
        asset_id TEXT DEFAULT '', notes TEXT DEFAULT '',
        created TEXT, updated TEXT, created_by TEXT, updated_by TEXT)""")
    # A recording of one live session on one target. The screen lives in a file
    # under DATA pointed at by `rec_rel`; `rec_kind` says which player reads it
    # (an xterm for an asciinema cast, the Guacamole player for a guac file).
    # `source` remembers where the session was opened from (pam | ansible) so the
    # SSH recordings inherited from the Ansible page are distinguishable.
    c.execute("""CREATE TABLE IF NOT EXISTS pam_sessions (
        id TEXT PRIMARY KEY, target_id TEXT DEFAULT '',
        target_name TEXT DEFAULT '', protocol TEXT DEFAULT 'ssh',
        who TEXT, address TEXT DEFAULT '',
        proj_id TEXT DEFAULT '', rgn_id TEXT DEFAULT '',
        started TEXT, ended TEXT, seconds INTEGER DEFAULT 0,
        out_bytes INTEGER DEFAULT 0, cmd_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'closed', ip TEXT DEFAULT '',
        rec_kind TEXT DEFAULT '', rec_rel TEXT DEFAULT '',
        commands TEXT DEFAULT '', source TEXT DEFAULT 'pam',
        sha256 TEXT DEFAULT '', reason TEXT DEFAULT '',
        ticket TEXT DEFAULT '', session_time TEXT DEFAULT '')""")

    # Carry forward the SSH recordings already made under Ansible. INSERT OR
    # IGNORE keeps it idempotent — the ids are preserved, so a second migration
    # run copies nothing new — and the cast files are left where they are
    # (rec_rel still resolves against DATA), only indexed here.
    try:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(ansible_sessions)")}
    except sqlite3.OperationalError:
        cols = set()
    if {"id", "cast_rel", "group_name"} <= cols:
        c.execute("""INSERT OR IGNORE INTO pam_sessions
            (id, target_id, target_name, protocol, who, address, proj_id,
             rgn_id, started, ended, seconds, out_bytes, cmd_count, status, ip,
             rec_kind, rec_rel, commands, source)
            SELECT id, '', group_name, 'ssh', who, host, proj_id, rgn_id,
             started, ended, seconds, out_bytes, cmd_count, status, ip,
             CASE WHEN cast_rel != '' THEN 'asciinema' ELSE '' END,
             cast_rel, commands, 'ansible'
            FROM ansible_sessions""")

    # Additive columns for databases created before these features (the CREATE
    # above already has them for fresh ones): the recording's integrity checksum
    # and the operator's stated reason for the session.
    have = {r["name"] for r in c.execute("PRAGMA table_info(pam_sessions)")}
    for col in ("sha256", "reason", "ticket", "session_time"):
        if col not in have:
            c.execute(f"ALTER TABLE pam_sessions ADD COLUMN {col} TEXT DEFAULT ''")
    thave = {r["name"] for r in c.execute("PRAGMA table_info(pam_targets)")}
    if "env" not in thave:
        c.execute("ALTER TABLE pam_targets ADD COLUMN env TEXT DEFAULT ''")
    for col in ("hostname", "label"):
        if col not in thave:
            c.execute(f"ALTER TABLE pam_targets ADD COLUMN {col} TEXT DEFAULT ''")
    shave = {r["name"] for r in c.execute("PRAGMA table_info(pam_sessions)")}
    if "rec_trimmed" not in shave:
        # WHEN a retention policy removed the screen. Without this a trimmed
        # recording is indistinguishable from a lost or deleted one, and
        # `session_integrity` would report it as 'missing' — which in this
        # product means somebody may have tampered with the evidence. A policy
        # doing its job must not look like an incident.
        c.execute("ALTER TABLE pam_sessions ADD COLUMN rec_trimmed TEXT DEFAULT ''")

    for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_pam_tgt_place "
            "ON pam_targets(proj_id, rgn_id)",
            "CREATE INDEX IF NOT EXISTS idx_pam_sess_who ON pam_sessions(who)",
            "CREATE INDEX IF NOT EXISTS idx_pam_sess_at ON pam_sessions(started)",
            "CREATE INDEX IF NOT EXISTS idx_pam_sess_tgt "
            "ON pam_sessions(target_id)"):
        c.execute(stmt)


db.register(_migrate)


# ── the installation's own settings ────────────────────────────
# `allow_connect` is off until somebody turns it on — the same posture as
# Ansible's `allow_real` and a cluster's "allow management". A PAM that has just
# been given a catalogue can be READ (see the targets, review the recordings)
# without one mis-click opening a live root shell on production.
# `enabled` is the master switch and it lives HERE, in the database, like every
# other piece of configuration in this portal — not in the environment. Its
# default is read from PORTAL_PAM so an installation that was switched on by the
# env var keeps Privileged Access after upgrading to this version; the moment
# somebody uses the toggle in Settings, the stored choice wins for good. That
# ordering is the whole compatibility story: the env var seeds, it never
# overrides, so the switch on the page is never the one that does nothing.
DEFAULTS = {"enabled": (os.environ.get("PORTAL_PAM", "") or "").strip().lower()
            in ("1", "true", "yes", "on"),
            "allow_connect": False, "record_sessions": True,
            "guacd_host": "127.0.0.1", "guacd_port": 4822,
            "rdp_width": 1280, "rdp_height": 800,
            # COLOUR PER PIXEL, for an operator on a link that cannot carry
            # the picture. MEASURED through guacd against a real page scrolling
            # at 1600x900, mean bytes per scroll:
            #
            #   24-bit  342 KiB    the default, and what every install has
            #   16-bit  281 KiB    -18%, thousands of colours, mild banding
            #    8-bit  107 KiB    -69%, 256 colours, plainly degraded
            #
            # So this is a real lever and a modest one: 18% at a quality most
            # people would accept, 69% at a quality most would not. Worth
            # having for somebody on a thin link, and worth being honest that
            # it is not what makes a session feel local.
            #
            # EMPTY BY DEFAULT, which means "do not send the parameter", which
            # means guacd keeps doing exactly what it does today. A setting
            # that silently degraded everybody's colour to make a graph look
            # better would be the wrong way round: this is here for the person
            # who has measured their own link and decided.
            "guac_color_depth": "",
            # session governance — a real PAM does not just record, it constrains
            "require_reason": "prod",     # off | prod | always
            "idle_timeout": 1800,         # seconds with no input before close; 0 off
            "max_duration": 0,            # hard cap on a session's length; 0 off
            "max_concurrent": 0,          # live sessions one person may hold; 0 off
            # A RECORDED WEB SESSION — a browser in the cluster, one pod per
            # session, rendered and recorded by the same guacd the RDP/VNC
            # targets use. Off by default: it creates pods in somebody's
            # cluster and pulls a browser image, neither of which should start
            # happening because the portal was upgraded. See app/webseat.py
            # for why the image is configuration rather than something this
            # product builds and ships.
            "web_browser": False,
            "web_image": "selenium/standalone-chromium:latest",
            "web_browser_name": "chrome",
            "web_cluster": "",            # which registered cluster runs them
            "web_namespace": "default",
            "web_vnc_port": 5900,
            "web_driver_port": 4444,
            "web_vnc_password": "secret",  # the image's own default
            # WHERE GUACD SHOULD DIAL THE SEAT. Blank means 127.0.0.1, which
            # is right for the shipped topology and ONLY that one: guacd as a
            # sidecar shares the portal's network namespace, so the portal's
            # port-forward is guacd's loopback too. `guacd_host` is
            # configurable, though — a guacd running anywhere else would dial
            # ITS own loopback and find nothing, so that case has to name an
            # address guacd can reach the PORTAL at.
            "web_seat_host": "",
            "web_ttl": 3600,               # activeDeadlineSeconds on the pod
            "web_shm_mb": 512,
            "web_cpu_req": "200m", "web_mem_req": "768Mi",
            "web_cpu_lim": "2", "web_mem_lim": "2Gi",
            # RETENTION. A recording is the biggest thing this feature
            # produces and nothing trimmed it: an asciinema cast is ~6
            # bytes/second, a guac recording about 9,000 — so the day web or
            # RDP sessions are used in earnest they fill the volume that also
            # holds the git checkouts and the Terraform state. 0 means keep
            # for ever, which stays the default because deleting somebody's
            # evidence must be a choice they made.
            # HOW MANY BROWSERS TO KEEP WARM. A seat created on demand costs
            # the image pull with somebody watching: 36.9s cold, 4.3s warm,
            # measured. One spare makes the common click about two seconds.
            # It only ever runs when recorded web sessions are ON, so nobody
            # gets an idle browser in their cluster by upgrading.
            "web_spares": 1,
            # HOW LONG A BROWSER MAY TAKE TO BECOME READY. 120s was hard-coded
            # and it is not enough: a ~1.5GB image on a slow link was observed
            # still pulling at 268 seconds, so the old constant turned a slow
            # pull into a guaranteed FAILURE rather than a wait. Configurable
            # because pull speed is a property of somebody's cluster and
            # registry, not of this product.
            "web_ready_timeout": 600,
            # HOW LONG A TARGET PAGE MAY TAKE TO SETTLE. Not a failure
            # deadline — the seat is handed over on where the browser ACTUALLY
            # IS, not on the page admitting it finished — so this only bounds
            # how long the navigation is given before that is checked. A real
            # PWA never fires the event at all, which is exactly why the
            # answer cannot come from waiting longer.
            "web_page_timeout": 20,
            # THE GATEWAY'S OWN IMAGE, for the one-click that adds it. Named
            # rather than hardcoded because a sidecar that cannot be pulled
            # stops the WHOLE POD, not just itself — so a mirrored or
            # air-gapped install has to be able to point this at their own
            # registry before pressing the button. It mirrors the chart's
            # default; the two are pinned together by tests/test_chart.py.
            "guacd_image": "guacamole/guacd:1.5.5",
            "keep_days": 0,               # trim recordings older than this
            "keep_mb": 0}                 # cap the whole store at this size

REASON_MODES = ("off", "prod", "always")


def config() -> dict:
    got = {**DEFAULTS, **(store._setting("pam") or {})}
    got["enabled"] = bool(got.get("enabled"))
    got["allow_connect"] = bool(got.get("allow_connect"))
    got["record_sessions"] = bool(got.get("record_sessions"))
    got["guacd_host"] = str(got.get("guacd_host") or "127.0.0.1").strip()
    if got.get("require_reason") not in REASON_MODES:
        got["require_reason"] = "prod"
    got["web_browser"] = bool(got.get("web_browser"))
    for txt in ("web_image", "web_browser_name", "web_cluster", "web_namespace",
                "guacd_image", "guac_color_depth",
                "web_vnc_password", "web_cpu_req", "web_mem_req",
                "web_cpu_lim", "web_mem_lim"):
        got[txt] = str(got.get(txt) or DEFAULTS[txt]).strip() or DEFAULTS[txt]
    # Blank is meaningful here (it MEANS the sidecar), so it is not filled in
    # from the defaults like the others.
    got["web_seat_host"] = str(got.get("web_seat_host") or "").strip()
    for num, low, high in (("guacd_port", 1, 65535),
                           ("rdp_width", 640, 3840), ("rdp_height", 480, 2160),
                           ("idle_timeout", 0, 86400), ("max_duration", 0, 86400),
                           ("max_concurrent", 0, 100),
                           ("web_vnc_port", 1, 65535),
                           ("web_driver_port", 1, 65535),
                           # A seat that never times out is a browser left
                           # logged in to a production application for ever,
                           # so zero is deliberately not allowed here.
                           ("web_ttl", 300, 86400), ("web_shm_mb", 64, 4096),
                           ("keep_days", 0, 3650), ("keep_mb", 0, 1024 * 1024),
                           ("web_spares", 0, 8),
                           ("web_ready_timeout", 60, 3600),
                           ("web_page_timeout", 5, 300)):
        try:
            # A BLANK FALLS BACK TO THE DEFAULT, never to the floor. `or 0`
            # sent an absent value to zero and the clamp then raised it to the
            # minimum — so "nothing was supplied" and "the smallest legal
            # value" became the same thing, which is how a port became 1.
            raw = got.get(num)
            if raw is None or (isinstance(raw, str) and not raw.strip()):
                raw = DEFAULTS[num]
            got[num] = max(low, min(high, int(raw)))
        except (TypeError, ValueError):
            got[num] = DEFAULTS[num]
    return got


def reason_required(is_prod) -> bool:
    """Whether a session on this target must carry a stated reason: never in
    'off', always on production in 'prod', on every target in 'always'."""
    mode = config().get("require_reason", "prod")
    return mode == "always" or (mode == "prod" and bool(is_prod))


# HOW LONG THE SESSION IS FOR, as a list to choose from rather than a box to
# type in. It was free text, so it took "asap", "30 min", "half an hour" and
# "" -- and typed prose cannot bound anything, which is why the field did not
# do what its name said. These are minutes, and the label is generated from
# them, so what is stored is always something this code wrote.
SESSION_TIMES = ((15, "15 minutes"), (30, "30 minutes"), (60, "1 hour"),
                 (120, "2 hours"), (240, "4 hours"), (480, "8 hours"))
_SESSION_BY_LABEL = {label: mins for mins, label in SESSION_TIMES}


def session_cap_seconds(session_time: str) -> int:
    """The declared session length in seconds, or 0 when there is none.

    WHY THIS MATTERS AND DID NOT EXIST. The declared time was recorded on the
    row and folded into one audit line, and nothing anywhere read it back --
    so an operator who said "30 minutes" on a production target got a session
    bounded only by the install-wide maximum, which on most installs is
    nothing at all. Reported as "I don't think it is really working", which was
    exactly right: it was a note, not a limit.

    Only labels this module generates are recognised, and an older row with
    somebody's typed prose in it simply yields 0 -- the install-wide limit then
    applies, which is the behaviour that row was created under anyway.
    """
    return _SESSION_BY_LABEL.get((session_time or "").strip(), 0) * 60


def justification(ticket: str, session_time: str, summary: str) -> dict | None:
    """The three-part justification a governed connection must carry: a ticket
    URL, the expected session time, and a summary of the work. All three are
    mandatory; the ticket must be an http(s) URL, not free text. Returns the
    cleaned parts, or None if any is missing or the ticket is not a URL — the
    caller turns None into a refusal."""
    ticket = (ticket or "").strip()
    stime = (session_time or "").strip()
    # CHOSEN, not typed: anything that is not one of the offered lengths is
    # treated as nothing given, so the gate asks again rather than storing a
    # string no limit can be derived from.
    if stime and stime not in _SESSION_BY_LABEL:
        stime = ""
    summary = (summary or "").strip()
    if (not ticket.lower().startswith(("http://", "https://")) or len(ticket) < 10
            or not stime or len(summary) < 4):
        return None
    return {"ticket": ticket[:400], "session_time": stime[:80],
            "summary": summary[:300]}


def concurrent_for(who: str) -> int:
    """How many live sessions this person already holds in this worker — the
    input to the concurrent-session cap."""
    with _active_lock:
        return sum(1 for v in _active.values() if v.get("who") == who)


def save_config(**fields) -> None:
    """Write the settings. A field not supplied KEEPS ITS CURRENT VALUE.

    It used to fall back to `DEFAULTS`, which was a quiet trap the moment
    `enabled` joined them: any caller saving a subset — the governance fields,
    say — would have switched Privileged Access off as a side effect, because
    the default is off. Preserving is the only safe direction for a partial
    write.

    The settings FORM is unaffected either way: an unchecked checkbox sends
    nothing, so every boolean on the page is passed explicitly as
    `bool(f.get(...))` and a box cleared on purpose still clears.
    """
    now = config()
    # A FIELD GIVEN AS `None` IS A FIELD NOT GIVEN. The route reads the form
    # with `f.get(...)`, so a control missing from the POST arrives here as
    # None with its key PRESENT — which sailed past the "absent keeps its
    # value" rule above and was then normalised to 0 and clamped UP to the
    # setting's floor.
    #
    # Found on a customer install where every numeric web setting sat exactly
    # on its minimum — ports at 1, spares at 0, timeouts at their floors. A
    # readiness probe was therefore being made against port 1, which nothing
    # answers, so every browser they opened "never became ready". One save
    # that omitted those inputs did all of it, silently, and nothing on the
    # page ever looked wrong.
    given = {k: v for k, v in fields.items()
             if v is not None and not (isinstance(v, str) and not v.strip()
                                       and isinstance(DEFAULTS.get(k), int)
                                       and not isinstance(DEFAULTS.get(k), bool))}
    store._set_setting("pam", {k: given.get(k, now[k]) for k in DEFAULTS})


def guacd_reachable() -> bool:
    """Whether the guacd sidecar is answering — for the honest 'no gateway'
    state on RDP/VNC targets. A cheap TCP connect, not a Guacamole handshake."""
    cfg = config()
    try:
        with socket.create_connection((cfg["guacd_host"], cfg["guacd_port"]), 1):
            return True
    except OSError:
        return False


def _key_text(raw: str) -> str:
    """DEFERS to `ansible.key_text`, which is the one definition.

    The same field is filled on two forms — a target here, a host group in
    Ansible — and a normaliser written twice is one of them drifting. Same
    reason `_label` defers.
    """
    return ansible.key_text(raw)


def guacd_why() -> str:
    """"" when guacd answers, else a sentence naming what to DO about it.

    ONE definition, used by the catalogue row's disabled button and by the
    settings page, because a reason written twice is one of them going stale.

    It exists because "the gateway is not reachable" is true and useless. The
    default arrangement is a sidecar in this very pod, so the address is
    loopback and the only way it is absent is that the chart did not deploy
    it — which is a Helm value, not something a person can find from the
    portal. Somebody spent an evening concluding the feature was broken; the
    fix was one line they had no way of knowing about.
    """
    if guacd_reachable():
        return ""
    cfg = config()
    where = f"{cfg['guacd_host']}:{cfg['guacd_port']}"
    if guacd_is_local(cfg["guacd_host"]):
        # ASK THE DEPLOYMENT RATHER THAN GUESS. This used to assert that the
        # chart had not deployed it and to name a Helm value — advice that
        # became wrong the day `guacd.enabled` became true by default, and a
        # customer sent a screenshot of an install being told to set a value
        # that was already its default. The three cases need different
        # actions, and only one of them is the one that sentence described.
        from . import selfupdate
        seen = selfupdate.gateway_state()
        if seen.get("how") == "present":
            return (f"the gateway (guacd) is not answering at {where}, but its "
                    "container IS in this deployment — so it is starting, or "
                    "failing to start. Its logs say which. SSH targets do not "
                    "need it.")
        if seen.get("how") == "absent":
            return (f"the gateway (guacd) is not answering at {where}, and "
                    "there is no gateway container in this deployment. It "
                    "ships enabled by default, so this is an older chart or an "
                    "install with `guacd.enabled: false`. SSH targets do not "
                    "need it.")
        return (f"the gateway (guacd) is not answering at {where}. It ships as "
                "a sidecar alongside the portal and is enabled by default, so "
                "on a normal install this means the chart did not deploy it: "
                "check `guacd.enabled` in the Helm values and upgrade. SSH "
                "targets do not need it.")
    return (f"the gateway (guacd) is not answering at {where}, which is where "
            "Settings → Privileged Access points it. Check that it is running "
            "and reachable from this portal. SSH targets do not need it.")


# ── the target catalogue + credential broker ───────────────────
def _extra(target: dict) -> dict:
    try:
        return json.loads(target.get("extra") or "{}")
    except (ValueError, TypeError):
        return {}


def _asset_facts(rows: list) -> dict:
    """{asset_id: {"hostname", "label"}} for the rows that name an asset.

    One query for the list. Returns {} when nothing names an asset, so the
    common case costs nothing at all.
    """
    # `dict(r)` first: these rows arrive as a MIX of `sqlite3.Row` (from the
    # pam_targets query) and plain dicts (inventory-derived targets), and a
    # Row has no `.get` -- it raises IndexError on a column it does not carry.
    # `_target_view` converts each row, but only inside its own loop, and this
    # runs before it because the whole point is one query for the list.
    ids = [aid for aid in ((dict(r).get("asset_id") or "").strip()
                           for r in rows) if aid]
    if not ids:
        return {}
    from . import assets                                      # noqa: PLC0415
    # Only the hostname. There is deliberately no label here: `assets` has no
    # `label` column (COLUMNS at assets.py:45), and a field this returned that
    # nothing could fill would be the same defect as the asset_id it exists to
    # fix -- a declared thing with no writer.
    return {aid: {"hostname": (a.get("hostname") or "").strip()}
            for aid, a in assets.many(ids).items()}


def _target_view(rows: list) -> list:
    """Attach the display fields a page needs, and NEVER the secret.

    `secret_sealed` is dropped here rather than trusted not to be rendered — a
    credential that is not in the template context cannot leak into a page.
    """
    out = []
    cfg = config()
    # ONE QUERY FOR THE WHOLE LIST, not a get() per row -- this runs on every
    # Privileged Access page load, and `assets.many` exists for exactly this
    # (the same reason `ansible._asset_facts` batches it).
    facts = _asset_facts(rows)
    for r in rows:
        r = dict(r)
        r.pop("secret_sealed", None)
        r["pid"], r["rgid"] = r.get("proj_id", ""), r.get("rgn_id", "")
        r.setdefault("source", "pam")
        r["editable"] = r["source"] == "pam"        # inventory hosts edit in Ansible
        r["proto_label"] = PROTOCOLS.get(r.get("protocol", ""), {}).get(
            "label", r.get("protocol", ""))
        r["web"] = r.get("protocol") in ("http", "https")
        # A web target's protocol is live-capable only because a browser can be
        # run for it, so the SWITCH is what decides — not the protocol table.
        # A cluster that cannot actually take the pod is a reason the button is
        # disabled with the reason in its title, not a reason the protocol is
        # incapable; keeping those apart is what stops the tile and the row
        # from disagreeing.
        r["is_live"] = bool(PROTOCOLS.get(r.get("protocol", ""), {}).get("live")
                            or (r["web"] and cfg["web_browser"]))
        r["needs_guac"] = bool(
            PROTOCOLS.get(r.get("protocol", ""), {}).get("guac")
            or (r["web"] and cfg["web_browser"]))
        r["has_secret"] = bool(r.get("auth_kind")) and r.get("auth_kind") != "none"
        r["extra_d"] = _extra(r)
        # THE HOSTNAME DEFERS TO THE ASSET, because `pam_targets.asset_id` was
        # a column with a writer (save_target) and NO READER anywhere in the
        # tree -- a declared link nothing consulted, which is the same defect
        # the inventory-host hostname resolution was built to fix. A target
        # linked to an asset showed a blank hostname cell while the asset
        # inventory knew the machine's name.
        #
        # A TYPED hostname wins: somebody put it there on this form, about
        # this target. The asset only fills a blank.
        #
        # THE ADDRESS IS NEVER TOUCHED. A hostname column that silently
        # changed what a session connects to would be the worst possible place
        # in this product for a surprise, so this is display only -- exactly
        # the rule `ansible.inventory_targets` follows.
        r.setdefault("hostname", "")
        fact = facts.get(r.get("asset_id") or "") or {}
        if not (r.get("hostname") or "").strip() and fact.get("hostname"):
            r["hostname"] = fact["hostname"]
            r["hostname_from"] = "asset"
        else:
            r["hostname_from"] = "typed" if r.get("hostname") else ""
        r.setdefault("label", "")
        r["env_label"] = env_label(r.get("env", ""))
        r["env_tone"] = env_tone(r.get("env", ""))
        out.append(r)
    return _placed(out)


def targets(pid: str = "", rgid: str = "", protocol: str = "", env: str = "",
            include_inventory: bool = True) -> list:
    """The catalogue: targets entered here PLUS every Ansible inventory host, so
    a host is never entered twice. Filtered by place / protocol / environment.
    Secrets are never included."""
    clauses, args = [], []
    if pid:
        clauses.append("proj_id = ?"); args.append(pid)
    if rgid:
        clauses.append("rgn_id = ?"); args.append(rgid)
    if protocol:
        clauses.append("protocol = ?"); args.append(protocol)
    if env:
        clauses.append("env = ?"); args.append(env_norm(env))
    sql = "SELECT * FROM pam_targets"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY name COLLATE NOCASE"
    rows = _target_view(_conn().execute(sql, tuple(args)).fetchall())
    if include_inventory and protocol in ("", "ssh"):
        derived = ansible.inventory_targets()
        if pid:
            derived = [d for d in derived if d.get("proj_id") == pid]
        if rgid:
            derived = [d for d in derived if d.get("rgn_id") == rgid]
        if env:
            derived = [d for d in derived if env_norm(d.get("env")) == env_norm(env)]
        rows += _target_view(derived)
    return rows


def target(tid: str) -> dict | None:
    """One target, WITHOUT the secret — for pages. Resolves an entered target or
    an Ansible inventory host (id `ah-…`). Use `_target_raw`/`inventory_of` to
    connect."""
    row = _target_raw(tid)
    if row:
        return _target_view([row])[0]
    for d in ansible.inventory_targets():
        if d["id"] == tid:
            return _target_view([d])[0]
    return None


def inventory_of(tid: str) -> dict | None:
    """The Ansible group + host behind a derived target id, or None."""
    for d in ansible.inventory_targets():
        if d["id"] == tid:
            g = ansible.group(d["group_id"])
            if g:
                return {"group": g, "host": d["name"], "target": d}
    return None


def _target_raw(tid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM pam_targets WHERE id = ?",
                        (tid,)).fetchone()
    return dict(r) if r else None


def target_secret(tid: str) -> str:
    """The unsealed credential — only ever called inside a connect handler."""
    r = _target_raw(tid)
    if not r or not r.get("secret_sealed"):
        return ""
    return secretbox.unseal(r["secret_sealed"])


def _label(v) -> str:
    """What a target's label may be — deferred to `ansible._label` rather than
    re-derived, because the same field is typed on two pages (a target here, an
    inventory host there) and two definitions is one of them drifting."""
    return ansible._label(v)


def save_target(tid: str, fields: dict, who: str) -> str:
    """Create or update a target. The credential is sealed; a blank secret on an
    update KEEPS the stored one (so editing a target does not require re-typing
    the password), and auth_kind='none' or a sentinel clears it."""
    name = (fields.get("name") or "").strip()
    if not NAME_OK.match(name):
        raise Refused("a target needs a name — letters, digits, space, dot, "
                      "dash, underscore")
    protocol = (fields.get("protocol") or "ssh").strip().lower()
    if protocol not in PROTOCOLS:
        raise Refused(f"{protocol!r} is not a protocol this understands")
    address = (fields.get("address") or "").strip()
    if not ADDR_OK.match(address):
        raise Refused(f"the address {address!r} is not one that can be reached "
                      "safely — a host name or IP, no spaces or flags")
    pid, rgid = place_of(fields)
    try:
        port = int(fields.get("port") or 0) or PROTOCOLS[protocol]["port"]
    except (TypeError, ValueError):
        port = PROTOCOLS[protocol]["port"]
    if not 1 <= port <= 65535:
        raise Refused("the port must be between 1 and 65535")
    auth_kind = (fields.get("auth_kind") or "none").strip()
    if auth_kind not in ("key", "password", "none"):
        auth_kind = "none"
    extra = _clean_extra(protocol, fields)

    now, existing = _now(), _target_raw(tid) if tid else None
    tid = tid or ("pt-" + uuid.uuid4().hex[:12])
    # A blank secret on edit means "leave it": editing a target's port should not
    # wipe its stored key. A real new secret reseals; auth_kind none clears.
    # THE KEY COMES FROM ITS OWN FIELD, and this is the whole reason SSH key
    # targets never worked. The form used to copy the textarea into the
    # PASSWORD input on submit — and an `<input>` runs a value sanitisation
    # that STRIPS every CR and LF, so the key left the browser as one long
    # line and no amount of repair here could put the breaks back. Every
    # newline fix that came before this was mending damage that had already
    # happened upstream of the request.
    raw_secret = ((fields.get("secret_key") if auth_kind == "key"
                   else fields.get("secret")) or "")
    if auth_kind == "none":
        sealed = ""
    elif raw_secret:
        # AN SSH KEY IS NORMALISED AND THEN VALIDATED, and neither half was
        # happening. A customer's key was accepted here and failed at connect
        # time with ssh's own `error in libcrypto` / `Permission denied
        # (publickey)`, while the same key worked from their shell — because
        # this form stored whatever it was given. The Ansible group form has
        # asked ssh about a key since the day a mangled paste took out a whole
        # run; a target's key deserves the same answer at the same moment.
        if auth_kind == "key":
            raw_secret = _key_text(raw_secret)
            got = ansible.read_key(raw_secret)
            if not got["ok"]:
                raise Refused(got["why"] or "ssh will not load that key")
        sealed = secretbox.seal(raw_secret)
    else:
        sealed = (existing or {}).get("secret_sealed", "")

    hostname = (fields.get("hostname") or "").strip()
    # Held to the same shape as an address, because that is what it is — a name
    # something will be asked to resolve. A label is the field for prose.
    if hostname and not ADDR_OK.match(hostname):
        raise Refused(f"the host name {hostname!r} is not one a resolver would "
                      "accept — letters, digits, dots and dashes")
    env = env_norm(fields.get("env"))
    # A production-class environment switches the typed-name safeguard on by
    # itself, so classifying a target as prod cannot silently skip the confirm.
    row = dict(id=tid, name=name, protocol=protocol, address=address, port=port,
               proj_id=pid, rgn_id=rgid, tags=(fields.get("tags") or "").strip(),
               is_prod=1 if (fields.get("is_prod") or env_is_prod(env)) else 0,
               env=env, hostname=hostname,
               label=_label(fields.get("label")),
               username=(fields.get("username") or "").strip(),
               auth_kind=auth_kind, secret_sealed=sealed,
               extra=json.dumps(extra), asset_id=(fields.get("asset_id") or ""),
               notes=(fields.get("notes") or "").strip())
    with db.tx() as c:
        if existing:
            row.update(updated=now, updated_by=who)
            sets = ", ".join(f"{k} = ?" for k in row if k != "id")
            c.execute(f"UPDATE pam_targets SET {sets} WHERE id = ?",
                      (*[v for k, v in row.items() if k != "id"], tid))
        else:
            row.update(created=now, updated=now, created_by=who, updated_by=who)
            keys = ", ".join(row)
            c.execute(f"INSERT INTO pam_targets ({keys}) "
                      f"VALUES ({', '.join('?' for _ in row)})",
                      tuple(row.values()))
    return tid


WEB_URL_OK = re.compile(r"(?i)^https?://[^\s<>\"']+$")


def _web_url(v) -> str:
    """A web target's URL — http and https ONLY.

    NOT a cosmetic check. This value is rendered as a link and handed to a
    redirect, and storing `javascript:alert(document.domain)` here came back
    as a clickable `href` on the catalogue page for every reader of it —
    verified by storing it and reading the rendered row, not by reading the
    rule. There is no CSP in front of this product, so that href executes: the
    boundary crossed is "can add a target" to "runs script in an admin's
    session". It is exactly the case the 3 September scan predicted when it
    disproved the same shape on the BMC page — that one is saved by a fetch
    through `urlguard` standing in front of the render, and this page has no
    fetch in front of it.

    Refused rather than silently rewritten: somebody who typed a scheme meant
    it, and quietly turning it into something else is how a target ends up
    pointing somewhere nobody chose.
    """
    url = str(v or "").strip()[:500]
    if not url:
        return ""
    if not WEB_URL_OK.match(url):
        raise Refused("a web target's URL has to start with http:// or "
                      "https:// — that is the address the button opens")
    return url


def web_url(t: dict) -> str:
    """Where a web target's `open` actually goes — the stored URL, or the
    address it was catalogued with. Checked AGAIN here rather than trusted:
    rows stored before the scheme was validated are still in the database, and
    this is the one place they are turned back into a link."""
    url = ((t.get("extra_d") or {}).get("url") or "").strip()
    if not url:
        port = t.get("port") or PROTOCOLS.get(t.get("protocol") or "", {}).get("port")
        host = t.get("address") or ""
        tail = "" if not port or port in (80, 443) else f":{port}"
        url = f"{t.get('protocol') or 'https'}://{host}{tail}"
    return url if WEB_URL_OK.match(url) else ""


def web_also(t: dict) -> list:
    """The extra hostnames a web target's page is allowed to use."""
    return list((t.get("extra_d") or {}).get("also") or [])


def _clean_extra(protocol: str, fields: dict) -> dict:
    """The protocol-specific knobs, taken only from the fields that protocol
    uses — so a stray RDP field cannot ride along on an SSH target."""
    extra: dict = {}
    if protocol == "rdp":
        if fields.get("domain"):
            extra["domain"] = str(fields["domain"]).strip()[:120]
        extra["security"] = (fields.get("security") or "any").strip()
        extra["ignore_cert"] = bool(fields.get("ignore_cert"))
    if protocol in ("http", "https"):
        extra["url"] = _web_url(fields.get("url"))
        # THE OTHER NAMES THE PAGE NEEDS. A web target is rarely one host: the
        # measured application pulls its API from a second name on the same
        # server and its images from an object store. Those are the names the
        # seat's browser is allowed to resolve, and whose addresses join its
        # egress policy — so the confinement follows the application instead
        # of the address bar. A textarea, one per line, because that is how
        # people paste a list.
        extra["also"] = [h for h in re.split(r"[\s,]+",
                                             str(fields.get("also") or ""))
                         if h][:20]
    if protocol in ("postgres", "mysql"):
        extra["database"] = (fields.get("database") or "").strip()[:120]
    return extra


def delete_target(tid: str) -> bool:
    with db.tx() as c:
        gone = c.execute("DELETE FROM pam_targets WHERE id = ?", (tid,)).rowcount
    return bool(gone)


def target_facets() -> dict:
    """Distinct protocols and environments present (entered targets plus Ansible
    inventory hosts), for the catalogue filter dropdowns."""
    rows = _conn().execute("SELECT DISTINCT protocol FROM pam_targets").fetchall()
    envs = {env_norm(r["env"]) for r in
            _conn().execute("SELECT DISTINCT env FROM pam_targets").fetchall()
            if env_norm(r["env"])}
    envs |= {env_norm(d.get("env")) for d in ansible.inventory_targets()
             if env_norm(d.get("env"))}
    return {"protocols": sorted(r["protocol"] for r in rows if r["protocol"]),
            "envs": sorted(envs)}


# ── SSH: a pty running ssh, the credential brokered ────────────
SSH_TIMEOUT = 20
_USER_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def ssh_shell(target: dict, rows: int = 24, cols: int = 100):
    """A pty running `ssh` into an SSH target, authenticated by the target's own
    brokered credential — a key or a password the person never sees.

    The same `_Pty(raw_master=False)` the Ansible host terminal uses (so the
    newline fix carries), and the same space-free scratch dir for the key and
    known_hosts. The password path uses ssh's SSH_ASKPASS hook rather than the
    command line, exactly as the key-install flow does — a password in argv is a
    password every process on the box can read.
    """
    from . import kmanage
    if not target:
        raise Refused("that target is gone")
    if target.get("protocol") != "ssh":
        raise Refused("this target is not reached over SSH")
    addr = (target.get("address") or "").strip()
    user = (target.get("username") or "").strip()
    if not ADDR_OK.match(addr):
        raise Refused(f"the address {addr!r} is not one ssh will take safely")
    if user and not _USER_OK.match(user):
        raise Refused(f"the username {user!r} is not one ssh will take safely")
    try:
        port = int(target.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    work = _term_scratch()
    try:
        opts, penv = _ssh_auth(target, work)
        penv["TERM"] = "xterm-256color"
        argv = ([env.SSH, "-tt"] + opts + ["-p", str(port)]
                + [f"{user}@{addr}" if user else addr])
        term = kmanage._Pty(argv, rows, cols, raw_master=False, env=penv)
    except Exception:
        drop_session_dir(work)
        raise
    term.workdir = work
    return term


def _ssh_auth(target: dict, work: str) -> tuple[list, dict]:
    """The ssh options and environment that carry a target's brokered credential.

    Lifted out of `ssh_shell` when file transfer arrived, because the SECOND
    caller was the moment this had to stop being written once. A key parsed one
    way for the terminal and another for a transfer is two credential paths to
    keep in step, and the one that drifted would be the one nobody tested — the
    same lesson `_read_kubeconfig` records for cluster registration.

    Neither the key nor the password ever reaches argv: the key is a 0600 file
    in the session's own scratch directory, the password goes through ssh's
    SSH_ASKPASS hook. A password in argv is a password every process on the box
    can read.

    THE PORT IS NOT HERE, and that is deliberate: `ssh` spells it `-p` and
    `sftp` spells it `-P`, so a shared list carrying one of them makes the
    other caller fail with a usage error that names neither the port nor the
    flag ("[-X sftp_option] destination", found by running it). Each caller
    adds its own.
    """
    auth = target.get("auth_kind") or "none"
    penv = {"PATH": env.TOOL_PATH, "HOME": work}
    known = os.path.join(work, "known_hosts")
    opts = ["-o", f"ConnectTimeout={SSH_TIMEOUT}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known}"]
    if auth == "key":
        keyfile = os.path.join(work, "id_key")
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            key = secretbox.unseal(target.get("secret_sealed") or "")
            fh.write(key if key.endswith("\n") else key + "\n")
        opts += ["-i", keyfile, "-o", "IdentitiesOnly=yes",
                 "-o", "BatchMode=yes",
                 "-o", "PreferredAuthentications=publickey"]
    elif auth == "password":
        password = secretbox.unseal(target.get("secret_sealed") or "")
        opts += ["-o", "PubkeyAuthentication=no",
                 "-o", "PreferredAuthentications=password,"
                       "keyboard-interactive",
                 "-o", "NumberOfPasswordPrompts=1", "-o", "BatchMode=no"]
        penv.update(SSH_ASKPASS=_askpass(work, password),
                    SSH_ASKPASS_REQUIRE="force",
                    DISPLAY=os.environ.get("DISPLAY", ":0"))
    else:
        # No credential: host-based or agent auth. Never falls to a prompt.
        opts += ["-o", "BatchMode=yes"]
    return opts, penv


# ── file transfer over the session's own credential ───────────
# WHY SFTP AND NOT A SECOND IDEA OF AUTHENTICATION
#     `sftp` is the ssh binary's own subsystem, so it takes the identical
#     options _ssh_auth builds — the same key file, the same askpass, the same
#     known_hosts. A library client (paramiko and friends) would re-implement
#     key parsing, password auth and host-key policy as a SECOND credential
#     path, and the day the two disagreed would be the day one of them was
#     untested. There is one credential path and two subsystems on it.
#
# WHAT THIS DOES AND DOES NOT GRANT
#     Nothing new. The person opening this already holds an interactive shell
#     on the target through the same brokered credential — they can `cat` any
#     file on the box. So the boundary is unchanged and it is the one
#     `pam_connect` plus the per-target scope already answer.
#
#     What transfer DOES change is the evidence. A file leaving a production
#     host is exactly the event a PAM exists to record, and it is invisible to
#     the session recording: a download is not terminal output, so the cast
#     never sees it. Every transfer is therefore audited by name, direction and
#     size, and written into the session's command transcript as well.
MAX_UPLOAD = 256 * 1024 * 1024      # per file; a portal is not a file server
# ── one SSH connection, reused for every transfer ─────────────
# WHY THIS EXISTS
#     Each sftp call was a whole new SSH connection: TCP, key exchange, auth,
#     then teardown. On localhost that is ~46ms and invisible; across a VPN the
#     handshake is about six round trips, so every click into a directory cost
#     the better part of a second and the window felt broken. Reported as
#     "loading the files is too slow".
#
#     ssh already solves this — ControlMaster keeps the authenticated connection
#     open and later invocations ride it, skipping the handshake entirely. The
#     socket has to OUTLIVE one call, so the directory holding it is stable per
#     target rather than a fresh mkdtemp; `ControlPersist` then closes the
#     master on its own shortly after the last transfer, so nothing is left
#     holding a session open.
#
#     It also fixes a second thing: known_hosts lives there now instead of being
#     thrown away with the scratch, so ssh stops re-accepting the host key —
#     and stops printing "Permanently added…" — on every single call.
CONTROL_PERSIST = 90                # seconds the shared connection lingers
_homes: dict = {}                   # tid -> its stable ssh directory
_homes_lock = threading.Lock()
LIST_CAP = 2000                     # rows returned from one directory
SFTP_TIMEOUT = 300                  # seconds for one transfer


def _sftp_quote(path: str) -> str:
    """One path, as sftp's batch parser will read it back.

    THE INJECTION THAT MATTERS. `sftp -b` reads one command per LINE, so a
    newline inside a path is not a quoting problem, it is a second command —
    and the batch runs with the target's credential. Newlines and control
    characters are refused outright rather than escaped, because there is no
    legitimate remote path containing them and "escaped correctly" is a claim
    that has to stay true through every future edit.

    Everything else is double-quoted, with backslashes and double quotes
    themselves backslash-escaped — which is what OpenSSH's own tokeniser undoes.
    """
    path = str(path or "")
    if not path:
        raise Refused("no path was given")
    if len(path) > 4096:
        raise Refused("that path is too long")
    bad = [c for c in path if ord(c) < 0x20 or ord(c) == 0x7F]
    if bad:
        raise Refused("a path cannot contain a newline or a control character")
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sftp_home(tid: str) -> str:
    """The stable directory holding this target's known_hosts and its shared
    connection socket.

    Short and outside the data directory for the reason `control_path_dir`
    records: ssh refuses a ControlPath over about 104 bytes BEFORE it dials
    anything, and a data directory with a real name in it blows that on its
    own. Created 0700 by mkdtemp, which refuses to reuse an existing path.
    """
    with _homes_lock:
        got = _homes.get(tid)
        if got and os.path.isdir(got):
            return got
        got = ansible.control_path_dir(str(DATA))
        _homes[tid] = got
        return got


def drop_sftp_home(tid: str) -> None:
    """Close the kept-open sftp, the shared connection, and forget the
    directory. Called when a session ends: the transfer surface goes with it,
    so nothing behind it should outlive it either."""
    drop_sftp_session(tid)
    with _homes_lock:
        got = _homes.pop(tid, None)
        _master_seen.pop(tid, None)
    if not got:
        return
    # Ask the master to go rather than waiting out ControlPersist: the transfer
    # surface ends with the session, and so should the connection behind it.
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run([env.SSH, "-O", "exit", "-o",
                        f"ControlPath={os.path.join(got, 'm')}", "x"],
                       capture_output=True, timeout=5,
                       env={"PATH": env.TOOL_PATH})
    drop_session_dir(got)


def _sftp_argv(tid: str, work: str) -> tuple[list, dict]:
    """The sftp command for a target, native OR from the Ansible inventory.

    Takes an ID, never a target dict, for the reason `pam.target()` exists: the
    page-safe view has the credential stripped out of it, so a caller holding
    one and passing it here got "Permission denied (publickey)" from a target
    whose key is stored and fine. Found by running it. Resolving the row inside
    the module means a route physically cannot hand this a redacted target.

    Two credential paths, exactly the two `open_ssh` dispatches between:
      * a native target authenticates with its own sealed key or password
        through `_ssh_auth`;
      * an inventory host authenticates with its GROUP's key, and its options
        come from `ansible.host_shell_argv` TRANSLATED rather than rebuilt —
        that function owns the shape-checking that stops a smuggled
        `-o ProxyCommand=` in an inventory address, and writing a second copy
        of it here is how one of the two would come to miss something.
    """
    row = _target_raw(tid)
    if row:
        if row.get("protocol") != "ssh":
            raise Refused("file transfer needs an SSH target")
        addr = (row.get("address") or "").strip()
        user = (row.get("username") or "").strip()
        if not ADDR_OK.match(addr):
            raise Refused(f"the address {addr!r} is not one sftp will take "
                          f"safely")
        if user and not _USER_OK.match(user):
            raise Refused(f"the username {user!r} is not one sftp will take "
                          f"safely")
        try:
            port = int(row.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        opts, penv = _ssh_auth(row, work)
        dest = f"{user}@{addr}" if user else addr
        # Opened here, while the key file in `work` still exists: ssh -f reads
        # the credential and authenticates BEFORE it forks, so the scratch can
        # be dropped straight afterwards as it always was.
        _ensure_master(tid, dest, port,
                       opts + ["-o", f"UserKnownHostsFile="
                                     f"{os.path.join(_sftp_home(tid), 'known_hosts')}"],
                       penv)
        return ([env.SFTP] + _shared(tid) + opts + ["-P", str(port), "-b", "-"]
                + [dest]), penv

    inv = inventory_of(tid)
    if not inv:
        raise Refused("that target is gone")
    g = inv["group"]
    if g.get("key_sealed"):
        keyfile = os.path.join(work, "id_key")
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            text = secretbox.unseal(g["key_sealed"])
            fh.write(text if text.endswith("\n") else text + "\n")
    elif g.get("key_path"):
        keyfile = g["key_path"]
    else:
        raise Refused("this host's group has no key — set one up on its page, "
                      "and then files can move over it")
    known = os.path.join(work, "known_hosts")
    ssh_argv = ansible.host_shell_argv(g, inv["host"], keyfile, known)
    # Translate rather than rebuild: same options, different binary, and the
    # port flag renamed. Asserted rather than assumed — if that function ever
    # stops passing exactly one `-p`, this must fail loudly instead of running
    # sftp against the wrong port.
    if ssh_argv.count("-p") != 1:
        raise Refused("the inventory ssh command changed shape; file transfer "
                      "needs updating alongside it")
    body = [a for a in ssh_argv[1:] if a != "-tt"]
    body = ["-P" if a == "-p" else a for a in body]
    dest = body.pop()                                  # user@address, last
    iport = "22"
    if "-P" in body:
        iport = body[body.index("-P") + 1]
    ssh_opts = [a for a in ssh_argv[1:] if a != "-tt"]
    ssh_opts = ssh_opts[:-1]                           # drop user@address
    _ensure_master(tid, dest, iport, ssh_opts,
                   {"PATH": env.TOOL_PATH, "HOME": work})
    return ([env.SFTP] + _shared(tid) + body + ["-b", "-", dest],
            {"PATH": env.TOOL_PATH, "HOME": work})


def _shared(tid: str) -> list:
    """The options that let a transfer ride the already-authenticated connection.

    `ControlMaster=no` on purpose: sftp must USE a master, never try to be one.
    Measured by hand — `sftp -o ControlMaster=auto -o ControlPersist=90` leaves
    NO socket behind, because sftp runs ssh as its own transport and that ssh
    cannot daemonise while it is holding sftp's pipes. So the master is opened
    separately by `_ensure_master`, and this only points at its socket. With the
    socket absent these options are harmless: ssh opens an ordinary connection,
    which is exactly the old behaviour rather than a failure.

    known_hosts moves here too, out of the per-call scratch, so the host key is
    accepted ONCE instead of on every call — which is also what printed
    "Permanently added…" every time.
    """
    home = _sftp_home(tid)
    return ["-o", "ControlMaster=no",
            "-o", f"ControlPath={os.path.join(home, 'm')}",
            "-o", f"UserKnownHostsFile={os.path.join(home, 'known_hosts')}"]


# When each target's master was last confirmed up. `ssh -O check` is a whole
# process spawn, and it was running on EVERY listing — so browsing a tree paid
# for two processes per directory instead of one. Re-checking is cheap to skip:
# with `ControlMaster=no` a socket that has gone stale costs the transfer one
# ordinary handshake, not a failure, so being briefly wrong is a slow click and
# never a broken one.
_MASTER_RECHECK = 30.0
_master_seen: dict = {}


def _master_alive(tid: str, dest: str, port: int) -> bool:
    fresh = time.time() - _master_seen.get(tid, 0.0)
    if fresh < _MASTER_RECHECK:
        return True
    sock = os.path.join(_sftp_home(tid), "m")
    if not os.path.exists(sock):
        return False
    try:
        got = subprocess.run(
            [env.SSH, "-O", "check", "-o", f"ControlPath={sock}",
             "-p", str(port), dest],
            capture_output=True, text=True, timeout=5,
            env={"PATH": env.TOOL_PATH})
        if got.returncode == 0:
            _master_seen[tid] = time.time()
            return True
        return False
    except (OSError, subprocess.SubprocessError):
        return False


def _ensure_master(tid: str, dest: str, port: int, opts: list,
                   penv: dict) -> None:
    """Open the shared connection if it is not already up.

    `-M -f -N`: become the master, fork into the background once
    authenticated, run no command. ControlPersist then closes it on its own
    after CONTROL_PERSIST seconds of no clients, so nothing keeps a connection
    to somebody's production host open because a window was left open.

    Failure here is DELIBERATELY silent. The master is an optimisation; if it
    cannot be opened, every transfer still works by connecting on its own, and
    turning a slow path into a broken one would be the worse trade.
    """
    home = _sftp_home(tid)
    with _homes_lock:
        pass                        # serialise nothing but the home lookup
    if _master_alive(tid, dest, port):
        return
    try:
        subprocess.run(
            [env.SSH, "-M", "-f", "-N",
             "-o", f"ControlPath={os.path.join(home, 'm')}",
             "-o", f"ControlPersist={CONTROL_PERSIST}"]
            + opts + ["-p", str(port), dest],
            capture_output=True, text=True, timeout=SSH_TIMEOUT + 5, env=penv)
        if os.path.exists(os.path.join(home, "m")):
            _master_seen[tid] = time.time()
    except (OSError, subprocess.SubprocessError):
        pass


# ── ONE sftp session, kept open ───────────────────────────────
# WHY, WITH THE NUMBERS
#     Measured against a host with 40ms each way — a realistic VPN, which is
#     the thing localhost cannot show and the reason this was "fixed" twice
#     while still being slow. Per directory listing:
#
#         no shared connection            1.04s
#         riding a shared connection      0.62s
#         ...of which SESSION SETUP       0.29s   <- half of it
#         one kept-open session           0.26s
#
#     Sharing the connection removed the handshake; it did NOT remove opening a
#     new sftp session (channel + SFTP protocol INIT) for every click. That is
#     three or four round trips before a single command is sent, every time.
#
#     So the session is opened once and fed commands. The commands themselves
#     were never the cost — cd + pwd + ls -l measured within 10ms of `quit`
#     alone — but they are trimmed anyway: an absolute path needs no `cd` and
#     no `pwd`.
#
# THE TWO THINGS THAT MAKE IT SURVIVABLE
#     * every command is prefixed `-`, which is sftp's own "do not abort the
#       batch on an error". Without it the FIRST bad path — a directory that
#       does not exist, a permission denied — kills the session and every
#       later click reconnects. Found by trying it: the pipe broke on call two.
#     * the terminator is `version`, which sftp answers LOCALLY. A marker that
#       costs a round trip would give back a third of what this saves.
_SFTP_END = "SFTP protocol version"
_sessions: dict = {}
_sessions_lock = threading.Lock()


class _Sftp:
    """One long-lived `sftp` process, fed commands under a lock.

    Output is read by a thread into a queue: a blocking readline on a process
    that has decided to say nothing is a hung request, and this has to be able
    to give up and respawn rather than hold a worker for ever.
    """

    def __init__(self, argv: list, penv: dict, work: str):
        self.argv, self.penv = argv, penv
        # THE SESSION OWNS ITS SCRATCH. The first version dropped it right
        # after Popen returned, on the reasoning that "sftp authenticates
        # before it accepts a command" — which is true of sftp and irrelevant
        # to Popen, which returns as soon as the process EXISTS. So the key
        # file was deleted out from under it and every session came back
        # "Identity file … not accessible". Found by measuring; the timings
        # looked right while nothing worked.
        self.work = work
        self.lock = threading.Lock()
        self.proc = None
        self.q: queue.Queue = queue.Queue()

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1, env=self.penv)

        def pump(fh, q):
            try:
                for line in fh:
                    q.put(line.rstrip("\n"))
            except Exception:                                  # noqa: BLE001
                pass
            finally:
                q.put(None)                                    # it ended

        threading.Thread(target=pump, args=(self.proc.stdout, self.q),
                         daemon=True).start()

    def alive(self) -> bool:
        return bool(self.proc) and self.proc.poll() is None

    def close(self) -> None:
        if not self.proc:
            return
        with contextlib.suppress(Exception):
            self.proc.stdin.write("quit\n")
            self.proc.stdin.flush()
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=2)
        with contextlib.suppress(Exception):
            self.proc.kill()
        self.proc = None
        if self.work:
            drop_session_dir(self.work)
            self.work = ""

    def send(self, lines: list, timeout: float) -> tuple:
        """Run these commands and return (out, timed_out)."""
        if not self.alive():
            self.start()
        # Drain anything left over — the banner on a fresh session, or the tail
        # of a request that timed out. Mixing it into the next answer is how a
        # listing ends up with somebody else's error in it.
        while True:
            try:
                self.q.get_nowait()
            except queue.Empty:
                break
        self.proc.stdin.write("".join(f"-{c}\n" for c in lines) + "version\n")
        self.proc.stdin.flush()
        out, deadline = [], time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return "\n".join(out), True
            try:
                line = self.q.get(timeout=left)
            except queue.Empty:
                return "\n".join(out), True
            if line is None:                                   # process gone
                return "\n".join(out), False
            if _SFTP_END in line:
                return "\n".join(out), False
            out.append(line)


def _session(tid: str):
    """This target's kept-open sftp, started if it is not running."""
    with _sessions_lock:
        got = _sessions.get(tid)
    if got and got.alive():
        return got
    work = _term_scratch()
    try:
        argv, penv = _sftp_argv(tid, work)
        argv = argv[:1] + ["-o", "LogLevel=ERROR"] + argv[1:]
        ses = _Sftp(argv, penv, work)
        ses.start()
    except Exception:
        drop_session_dir(work)
        raise
    with _sessions_lock:
        old = _sessions.get(tid)
        if old and old is not ses:
            old.close()
        _sessions[tid] = ses
    return ses


def drop_sftp_session(tid: str) -> None:
    with _sessions_lock:
        got = _sessions.pop(tid, None)
    if got:
        got.close()


def _sftp_talk(tid: str, lines: list, timeout: int = SFTP_TIMEOUT) -> tuple:
    """Run sftp commands on the kept-open session. -> (out, err)

    `err` is a sentence when the output carries a failure sftp recognises, and
    "" otherwise: with every command `-` prefixed the process no longer exits
    non-zero, so the OUTPUT is the only place a failure is reported.
    """
    ses = _session(tid)
    with ses.lock:
        out, timed = ses.send(lines, timeout)
        if timed:
            # A session that stopped answering is not one to keep. Drop it so
            # the next request gets a fresh one rather than the same silence.
            ses.close()
            drop_sftp_session(tid)
            return out, f"it did not answer within {timeout}s"
    return out, _sftp_fail(out)


# mode, links, owner, group, size, then the DATE AS THREE FIELDS, then the
# name. The date has to be matched exactly rather than as ".+?" — non-greedy,
# it gave up after "Sep" and the name came back as "3 10:44 subdir", which is
# what the first run against a real host printed. A name may contain spaces, so
# it is whatever is left.
#
# The link count is `\S+`, not `\d+`: OpenSSH's own sftp-server reports it as
# `?` (seen on Alpine), so requiring a digit made EVERY row fall through to the
# name-only fallback — which looked like a parser that worked, because a row
# still appeared for every file.
_LS = re.compile(r"^([dlrwxsSt+-]{10})\s+\S+\s+(\S+)\s+(\S+)\s+"
                 r"(\d+)\s+(\S+\s+\d+\s+\S+)\s+(.*)$")


def sftp_list(tid: str, path: str = ".") -> dict:
    """One directory on the target. -> {"path", "rows", "error", "truncated"}

    `ls -l` is parsed rather than `ls -1` because the page needs the size and
    whether a row is a directory; a name is not enough to know what clicking it
    should do. A line that does not parse is kept as a name-only row instead of
    being dropped — a file the portal cannot describe is still a file somebody
    may need.
    """
    # An ABSOLUTE path needs neither: `ls -l <path>` answers on its own, and
    # `pwd` only exists to resolve a relative one. Two commands saved on every
    # click but the first.
    if path.startswith("/"):
        out, err = _sftp_talk(tid, [f"ls -l {_sftp_quote(path)}"], timeout=60)
    else:
        out, err = _sftp_talk(tid, [f"cd {_sftp_quote(path)}", "pwd", "ls -l"],
                              timeout=60)
    if err:
        return {"path": path, "rows": [], "truncated": False, "unreadable": 0,
                "error": err}
    here, rows, unreadable = path, [], 0
    for line in out.splitlines():
        line = line.rstrip()
        if not line or line.startswith("sftp>") or line.startswith("total "):
            continue
        if line.startswith("Remote working directory:"):
            here = line.split(":", 1)[1].strip()
            continue
        m = _LS.match(line)
        if not m:
            # COUNTED, never invented. A line this cannot describe used to
            # become a name-only row, which is how an ssh notice arrived as a
            # file; saying "one entry could not be read" is honest, and a row
            # made out of a sentence is not.
            unreadable += 1
            continue
        mode, owner, group, size, when, name = m.groups()
        # `ls -l <path>` prints FULL paths; `cd <path>` then `ls -l` prints
        # bare names. Dropping the cd to save two round trips therefore
        # changed the shape of the answer, and the listing came back reading
        # "/usr/share/nginx/html/assets" in the name column.
        head = (here.rstrip("/") + "/") if here != "/" else "/"
        if name.startswith(head):
            name = name[len(head):]
        name = name.rstrip("/")
        if not name or name in (".", ".."):
            continue
        rows.append({"name": name, "dir": mode.startswith("d"),
                     "link": mode.startswith("l"), "mode": mode,
                     "owner": owner, "group": group,
                     "size": int(size), "when": when.strip()})
    rows.sort(key=lambda r: (not r["dir"], r["name"].lower()))
    return {"path": here, "rows": rows[:LIST_CAP], "error": "",
            "unreadable": unreadable, "truncated": len(rows) > LIST_CAP}


def sftp_fetch(tid: str, remote: str, into: str) -> tuple:
    """Copy one remote file to a LOCAL path the portal chose. -> (ok, error)

    The caller names the local file — never the browser. A client-supplied
    local path is a write anywhere the portal can reach, and it buys nothing:
    the download is streamed back and deleted either way.
    """
    out, err = _sftp_talk(tid, [f"get -p {_sftp_quote(remote)} "
                                f"{_sftp_quote(into)}"])
    if not err and not os.path.exists(into):
        return False, "the file did not arrive — it may be a directory"
    return (not err), err


def sftp_send(tid: str, local: str, remote_dir: str, name: str) -> tuple:
    """Copy one local file into a remote DIRECTORY. -> (ok, error)

    The destination is a directory plus a name rather than one joined path, so
    a name carrying `../` cannot climb out of where the person is looking. The
    name is checked to be a single segment for the same reason.
    """
    name = (name or "").strip().replace("\\", "/").split("/")[-1]
    if not name or name in (".", ".."):
        raise Refused("that file has no usable name")
    dest = (remote_dir.rstrip("/") or "") + "/" + name
    # Confirmed rather than inferred. With `-` prefixed commands the process
    # exit code says nothing, so the destination is read back in the SAME
    # batch — one extra round trip on the same session, and a definite answer
    # instead of "no error phrase appeared".
    out, err = _sftp_talk(tid, [f"put {_sftp_quote(local)} {_sftp_quote(dest)}",
                                f"ls -l {_sftp_quote(dest)}"])
    if err:
        return False, err
    landed = any(_LS.match(l.rstrip()) for l in out.splitlines()
                 if not l.startswith("sftp>"))
    return (True, "") if landed else (False, "the file did not appear on the "
                                             "target")


def term_scratch() -> str:
    """A private, space-free working directory for one transfer.

    Public because the transfer ROUTES need one to stage a file in, and a route
    reaching for `_term_scratch` would be a route reaching past the module's own
    surface. Same directory discipline as a session's: a path with no spaces in
    it (ssh's UserKnownHostsFile is a space-separated LIST) and dropped when the
    transfer is done.
    """
    return _term_scratch()


def sftp_stat(tid: str, path: str) -> dict:
    """One remote path's own row. -> {"size", "dir", "error"}

    Asked before a download so a file bigger than the portal will hold is
    refused BEFORE it starts filling the disk the recordings live on, rather
    than after.
    """
    out, err = _sftp_talk(tid, [f"ls -l {_sftp_quote(path)}"], timeout=60)
    if err:
        return {"size": 0, "dir": False, "error": err}
    for line in out.splitlines():
        m = _LS.match(line.rstrip())
        if m:
            return {"size": int(m.group(4)),
                    "dir": line.startswith("d"), "error": ""}
    return {"size": 0, "dir": False, "error": ""}


def live_session_of(who: str, tid: str) -> str:
    """The id of this person's own live session on this target, or "".

    WHY FILE TRANSFER HANGS OFF THIS
        Opening a session is where the gates are: the connect permission, the
        installation switch, a justification when one is required, and a
        production target's name typed out. A transfer endpoint that re-asked
        all of that would be a second copy of every one of them — and asking
        somebody to type a production host's name once per FILE is not a gate,
        it is a reason to stop using the portal.

        So a transfer is something you do INSIDE a session you already hold. It
        inherits every gate the session passed, it is bounded by the session's
        own idle timeout and duration cap, and when the session ends the
        transfer surface ends with it. It also means the person is present:
        there is no background credential to borrow.
    """
    who = (who or "").strip().lower()
    if not who or not tid:
        return ""
    with _active_lock:
        for sid, v in _active.items():
            if (v.get("target_id") == tid
                    and (v.get("who") or "").strip().lower() == who):
                return sid
    return ""


# sftp's own failure vocabulary. Matched STRICTLY, with no fallback, because
# this decides WHETHER a command failed rather than explaining one already known
# to have. `_sftp_why` ends with "or else the last line", which is right when
# the exit code already said it went wrong and catastrophic here: every
# successful listing reported its last file as the error, and every transfer
# came back failed. Found by measuring against a real host — the timings looked
# perfect while nothing worked.
_FAILED = ("permission denied", "no such file", "not found",
           "not a regular file", "couldn't", "can't ", "failure",
           "connection refused", "connection closed", "connection reset",
           "host key verification failed", "timeout", "timed out",
           "is not a directory", "invalid", "denied", "broken pipe",
           "too many", "quota", "read-only file system", "no space left")


def _sftp_fail(out: str) -> str:
    """The failure sftp reported, or "" when it reported none."""
    for line in (out or "").splitlines():
        line = line.strip()
        if not line or line.startswith("sftp>"):
            continue                       # an echoed command is not a verdict
        low = line.lower()
        if any(p in low for p in _FAILED):
            return line[:240]
    return ""


def _sftp_why(out: str, err: str = "") -> str:
    """The one line of sftp's output worth showing somebody.

    Its failures arrive as a wall in which the useful sentence is rarely the
    last line — "Permission denied", "No such file or directory" and
    "not a regular file" are what a person can act on, so they win over the
    generic connection noise around them.
    """
    # An ECHOED COMMAND is never an explanation. With `-b -` sftp writes every
    # command it runs to stdout as "sftp> ls -l …", and those lines are the
    # LAST thing in the output — so the fallback below happily reported the
    # command back to the person as the reason it failed.
    lines = [l.strip() for l in ((err or "") + "\n" + (out or "")).splitlines()
             if l.strip() and not l.strip().startswith("sftp>")]
    for want in ("Permission denied", "No such file", "not found",
                 "not a regular file", "Failure", "Connection refused",
                 "Connection closed", "Host key verification failed",
                 "Timeout", "denied", "Invalid", "Couldn't"):
        for line in lines:
            if want.lower() in line.lower():
                return line[:240]
    return (lines[-1][:240] if lines else "the transfer failed")


def ssh_meta(tid: str) -> dict | None:
    """The facts a connect handler gates on, for a native OR inventory SSH
    target — so the terminal is the same door whichever the id came from."""
    row = _target_raw(tid)
    if row:
        if row.get("protocol") != "ssh":
            return None
        return {"name": row["name"], "address": row.get("address", ""),
                "is_prod": bool(row.get("is_prod")),
                "pid": row.get("proj_id", ""), "rgid": row.get("rgn_id", ""),
                "source": "pam"}
    inv = inventory_of(tid)
    if inv:
        d = inv["target"]
        return {"name": d["name"], "address": d["address"],
                "is_prod": bool(d["is_prod"]), "pid": d["proj_id"],
                "rgid": d["rgn_id"], "source": "ansible"}
    return None


def open_ssh(tid: str, rows: int = 24, cols: int = 100):
    """A pty on an SSH target, native or from the Ansible inventory. An inventory
    host reuses ansible.host_shell so it authenticates with the group's key,
    exactly as the Ansible page did — one code path for the credential, two
    front doors to it."""
    row = _target_raw(tid)
    if row:
        return ssh_shell(row, rows, cols)
    inv = inventory_of(tid)
    if inv:
        return ansible.host_shell(inv["group"], inv["host"], rows, cols)
    raise Refused("that SSH target is gone")


# ── session recording, protocol-agnostic ───────────────────────
# Moved out of Ansible and generalised: the accumulator takes screen bytes and
# finished command lines (SSH), or nothing at all while guacd writes its own
# recording (RDP/VNC). `rec_kind` on the row is what the replay page reads to
# choose a player.
def _file_sha256(path: str) -> str:
    """The SHA-256 of a file, or '' if it cannot be read — a checksum failure
    must never take down the session it is only observing."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class Recording:
    """Accumulates one session's recording + command transcript, then files it.

    Driven by the transport handler. For an asciinema recording it owns a
    `SessionCast` that `output`/`resize` feed; for a guac recording it owns no
    cast (guacd writes the file) and only carries the metadata and, on finish,
    indexes the file guacd wrote. Any write error is swallowed — a recording is
    evidence, not a gate on the session.
    """

    def __init__(self, sid: str, cast, meta: dict):
        self.id = sid
        self.cast = cast
        self.meta = meta               # protocol/target_id/who/address/... + rec_kind
        self.started = _now()
        self._start = time.time()
        self.commands: list[str] = []
        self._filed = False

    def output(self, text: str) -> None:
        if self.cast:
            try:
                self.cast.output(text)
            except Exception:                                   # noqa: BLE001
                self.cast = None

    def resize(self, rows: int, cols: int) -> None:
        if self.cast:
            try:
                self.cast.resize(rows, cols)
            except Exception:                                   # noqa: BLE001
                self.cast = None

    def commands_typed(self, lines) -> None:
        self.commands.extend(lines)

    def finish(self, status: str = "closed") -> None:
        if self._filed:
            return
        self._filed = True
        secs = int(round(time.time() - self._start))
        rec_rel, out_bytes = "", 0
        if self.cast:                                           # asciinema
            try:
                self.cast.close()
                out_bytes = self.cast.out_bytes
                rec_rel = os.path.relpath(self.cast.path, str(DATA))
            except Exception:                                   # noqa: BLE001
                rec_rel = ""
        elif self.meta.get("rec_kind") == "guac":
            guac = SESSIONS / self.id      # guacd was told to write exactly this
            if guac.is_file():
                rec_rel = os.path.relpath(str(guac), str(DATA))
                out_bytes = guac.stat().st_size
            else:
                self.meta["rec_kind"] = ""     # nothing was written; do not lie
        # A checksum of the recording as it was filed, so a later change to the
        # file on disk is provable — the evidence can be shown to be the evidence.
        sha = _file_sha256(os.path.join(str(DATA), rec_rel)) if rec_rel else ""
        m = self.meta
        try:
            with db.tx() as c:
                c.execute("""INSERT INTO pam_sessions
                    (id, target_id, target_name, protocol, who, address,
                     proj_id, rgn_id, started, ended, seconds, out_bytes,
                     cmd_count, status, ip, rec_kind, rec_rel, commands, source,
                     sha256, reason, ticket, session_time)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (self.id, m.get("target_id", ""), m.get("target_name", ""),
                     m.get("protocol", ""), m.get("who", ""),
                     m.get("address", ""), m.get("pid", ""), m.get("rgid", ""),
                     self.started, _now(), secs, out_bytes, len(self.commands),
                     status, m.get("ip", ""), m.get("rec_kind", ""), rec_rel,
                     "\n".join(self.commands), m.get("source", "pam"),
                     sha, (m.get("reason") or "")[:300],
                     (m.get("ticket") or "")[:400],
                     (m.get("session_time") or "")[:80]))
        except Exception:                                       # noqa: BLE001
            pass


def start_recording(who: str, ip: str, *, protocol: str = "ssh",
                    target_id: str = "", target_name: str = "", address: str = "",
                    pid: str = "", rgid: str = "", source: str = "pam",
                    rec_kind: str = "asciinema", rows: int = 24, cols: int = 100,
                    reason: str = "", ticket: str = "", session_time: str = "",
                    sid: str = "") -> Recording | None:
    """A Recording for one session, or None when recording is off.

    `rec_kind='asciinema'` opens a cast the SSH transport feeds; `'guac'` opens
    no cast — the caller passes the returned id to guacd as its recording name
    and guacd writes the file. None means recording is off; every transport
    drives a real recorder and a None the same way.
    """
    if not config().get("record_sessions", True):
        return None
    from . import kmanage
    sid = sid or ("ps-" + uuid.uuid4().hex[:12])
    meta = dict(protocol=protocol, target_id=target_id, target_name=target_name,
                who=who, address=address, pid=pid, rgid=rgid, source=source,
                rec_kind=rec_kind, ip=ip, reason=reason, ticket=ticket,
                session_time=session_time)
    cast = None
    try:
        SESSIONS.mkdir(parents=True, exist_ok=True)
        # 0770, not 0700: when guacd runs as a sidecar it writes RDP/VNC
        # recordings into this same directory, and it does so as a different user
        # sharing the pod's fsGroup — group write is what lets it. In a single-
        # tenant portal pod the only group members are the pod's own containers.
        os.chmod(SESSIONS, 0o770)
        if rec_kind == "asciinema":
            cast = kmanage.SessionCast(
                str(SESSIONS / f"{sid}.cast"), rows, cols,
                meta={"target": target_name, "who": who, "protocol": protocol})
    except Exception:                                           # noqa: BLE001
        cast = None
    return Recording(sid, cast, meta)


def _session_rows(where: str = "", args: tuple = ()) -> list:
    sql = ("SELECT id, target_id, target_name, protocol, who, address, "
           "proj_id AS pid, rgn_id AS rgid, started, ended, seconds, out_bytes, "
           "cmd_count, status, ip, rec_kind, rec_rel, source, sha256, reason, "
           "ticket, session_time FROM pam_sessions")
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY started DESC LIMIT 1000"
    rows = _placed([dict(r) for r in _conn().execute(sql, args).fetchall()])
    for r in rows:
        r["ago"] = ago(r.get("started"))
        r["took"] = _dur_words(int(r.get("seconds") or 0))
        r["proto_label"] = PROTOCOLS.get(r.get("protocol", ""), {}).get(
            "label", r.get("protocol", ""))
    return rows


def sessions(pid: str = "", rgid: str = "", who: str = "", protocol: str = "",
             target_id: str = "", visible=None) -> list:
    """Recorded sessions, newest first, filtered by place / user / protocol.

    `visible` is the per-device scope: a set of target ids the reader may see, or
    None for every target. A recording is scoped by the target it was of, so a
    person granted App A sees App A's sessions and no others — a session whose
    target they cannot see (or one with no resolvable target) is not theirs."""
    clauses, args = [], []
    for col, val in (("proj_id", pid), ("rgn_id", rgid), ("who", who),
                     ("protocol", protocol), ("target_id", target_id)):
        if val:
            clauses.append(f"{col} = ?"); args.append(val)
    rows = _session_rows(" AND ".join(clauses), tuple(args))
    if visible is not None:
        rows = [r for r in rows if r.get("target_id") in visible]
    return rows


def session(sid: str) -> dict | None:
    r = _conn().execute("SELECT * FROM pam_sessions WHERE id = ?",
                        (sid,)).fetchone()
    return dict(r) if r else None


def session_rec_path(sid: str) -> str | None:
    """The absolute path to a session's recording, if it is still on disk.

    Resolved against DATA and checked to be inside it, so a stored path can
    never be walked outside the data directory."""
    row = session(sid)
    if not row or not row.get("rec_rel"):
        return None
    base = os.path.realpath(str(DATA))
    full = os.path.realpath(os.path.join(base, row["rec_rel"]))
    if full != base and not full.startswith(base + os.sep):
        return None
    return full if os.path.isfile(full) else None


def session_integrity(sid: str) -> dict:
    """Whether a recording is byte-for-byte what was filed. Recomputes the
    file's SHA-256 and compares it to the checksum stored when the session
    ended. `state` is one of: 'verified' (matches), 'tampered' (differs),
    'expired' (a retention policy removed it, and WHEN), 'missing' (the file is
    gone with no explanation) or 'none' (no checksum — an unrecorded session or
    one from before integrity checksums existed).

    'expired' exists because without it a retention policy doing its job is
    indistinguishable from evidence going astray, and 'missing' in this product
    means the second thing.
    """
    row = session(sid)
    stored = (row or {}).get("sha256") or ""
    if not row or not stored:
        return {"state": "none", "stored": "", "current": ""}
    path = session_rec_path(sid)
    if not path:
        if (row.get("rec_trimmed") or ""):
            return {"state": "expired", "stored": stored, "current": "",
                    "when": row["rec_trimmed"]}
        return {"state": "missing", "stored": stored, "current": ""}
    cur = _file_sha256(path)
    return {"state": "verified" if cur == stored else "tampered",
            "stored": stored, "current": cur}


def store_bytes() -> int:
    """How much disk the recordings occupy right now."""
    if not SESSIONS.exists():
        return 0
    return sum(f.stat().st_size for f in SESSIONS.iterdir() if f.is_file())


def trim_recordings(days: int = -1, cap_mb: int = -1) -> dict:
    """Apply the retention policy: remove recording FILES, keep the ROWS.

    The row is the audit record — who reached what, when, under which ticket —
    and it costs a few hundred bytes. The file is the screen, and it is what
    grows without bound. Deleting the row to save space would throw away the
    evidence and keep the expensive part, so a trimmed session stays in the
    list saying its recording expired on a date.

    Oldest first for the size cap, because the newest recording is the one
    somebody is most likely to want.
    """
    cfg = config()
    days = cfg["keep_days"] if days < 0 else days
    cap = (cfg["keep_mb"] if cap_mb < 0 else cap_mb) * 1024 * 1024
    if not days and not cap:
        return {"by_age": 0, "by_size": 0, "freed": 0, "kept": store_bytes()}

    rows = [r for r in sessions() if (r.get("rec_rel") or "")]
    rows.sort(key=lambda r: r.get("started") or "")
    now, freed, by_age, by_size = _now(), 0, 0, 0

    def drop(row) -> int:
        nonlocal freed
        path = session_rec_path(row["id"])
        size = 0
        if path:
            try:
                size = os.path.getsize(path)
                os.remove(path)
            except OSError:
                size = 0
        with db.tx() as c:
            c.execute("UPDATE pam_sessions SET rec_rel = '', rec_trimmed = ? "
                      "WHERE id = ?", (now, row["id"]))
        freed += size
        return size

    if days:
        # THE SAME SHAPE `_now()` writes, offset included. These are compared
        # as STRINGS, so a cutoff without the "+00:00" is only accidentally
        # right — it sorts correctly against a stored value until the prefixes
        # match, and then does not. Build it the way the rows were built.
        cut = (_dt.datetime.now(_dt.UTC)
               - _dt.timedelta(days=days)).isoformat(timespec="seconds")
        for r in list(rows):
            if (r.get("started") or "") < cut:
                drop(r); by_age += 1; rows.remove(r)
    if cap:
        while store_bytes() > cap and rows:
            drop(rows.pop(0)); by_size += 1
    return {"by_age": by_age, "by_size": by_size, "freed": freed,
            "kept": store_bytes()}


def delete_session(sid: str) -> bool:
    path = session_rec_path(sid)
    with db.tx() as c:
        gone = c.execute("DELETE FROM pam_sessions WHERE id = ?", (sid,)).rowcount
    if path:
        try:
            os.remove(path)
        except OSError:
            pass
    return bool(gone)


def clear_sessions(pid: str = "", rgid: str = "", who: str = "",
                   protocol: str = "", visible=None) -> int:
    rows = sessions(pid, rgid, who, protocol, visible=visible)
    for r in rows:
        delete_session(r["id"])
    return len(rows)


def session_commands_text(sid: str) -> str | None:
    """One session's commands, as a plain-text transcript with a header.

    Only SSH sessions have commands; an RDP/VNC session says so rather than
    returning an empty file that reads like a bug."""
    row = session(sid)
    if not row:
        return None
    lines = [
        f"# session {row['id']}  ({PROTOCOLS.get(row['protocol'], {}).get('label', row['protocol'])})",
        f"# target  {row['target_name'] or row['address']}",
        f"# user    {row['who']}",
        f"# from    {row['started']}  to  {row['ended']}"
        f"  ({row.get('seconds', 0)}s)",
        "",
    ]
    if row.get("protocol") not in ("ssh",):
        lines.append("(a graphical session — no commands; watch the recording)")
    else:
        body = (row.get("commands") or "").strip()
        lines.append(body or "(no commands were finished in this session)")
    return "\n".join(lines) + "\n"


def session_transcript_text(sid: str) -> str | None:
    """The whole session as text — the prompts, the commands AND their output,
    exactly what was on the screen — rebuilt from the recording's output stream.

    SSH (asciinema) only; an RDP/VNC session is graphical and has no text form.
    ANSI colour and cursor codes are stripped so it reads as a plain typescript;
    it stays output-only, so a password typed at a no-echo prompt is not in it,
    the same as the live screen never showed it."""
    row = session(sid)
    if not row or row.get("rec_kind") != "asciinema":
        return None
    path = session_rec_path(sid)
    if not path:
        return None
    from . import kmanage
    chunks = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.readline()                       # the asciinema v2 header line
            for line in fh:
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if len(ev) >= 3 and ev[1] == "o":   # an output event
                    chunks.append(ev[2])
    except OSError:
        return None
    text = kmanage._ANSI.sub("", "".join(chunks))
    return text.replace("\r\n", "\n").replace("\r", "")


def commands_for(who: str = "", protocol: str = "", pid: str = "",
                 rgid: str = "", visible=None) -> str:
    """Every command a user finished on the SSH targets, newest session first."""
    rows = sessions(pid=pid, rgid=rgid, who=who, protocol=protocol or "ssh",
                    visible=visible)
    who_label = who or "all users"
    out = [f"# commands by {who_label} on the SSH targets",
           f"# {len(rows)} session(s), newest first", ""]
    total = 0
    for r in rows:
        cmds = (session(r["id"]).get("commands") or "").strip()
        n = len([x for x in cmds.splitlines() if x.strip()]) if cmds else 0
        total += n
        out.append(f"── {r['started']}  {r['who']}@{r['target_name'] or r['address']}"
                   f"  ({n} command(s), session {r['id']})")
        out.append(cmds if cmds else "(none)")
        out.append("")
    out.insert(2, f"# {total} command(s) in total")
    return "\n".join(out) + "\n"


def session_facets(pid: str = "", rgid: str = "", visible=None) -> dict:
    rows = sessions(pid, rgid, visible=visible)
    return {"users": sorted({r["who"] for r in rows if r.get("who")}),
            "protocols": sorted({r["protocol"] for r in rows if r.get("protocol")})}


def sessions_stats(pid: str = "", rgid: str = "", who: str = "",
                   protocol: str = "", visible=None) -> dict:
    rows = sessions(pid, rgid, who, protocol, visible=visible)
    return {
        "count": len(rows),
        "seconds": sum(int(r.get("seconds") or 0) for r in rows),
        "commands": sum(int(r.get("cmd_count") or 0) for r in rows),
        "users": len({r["who"] for r in rows if r.get("who")}),
        "targets": len({r.get("target_name") or r.get("address")
                        for r in rows if r.get("target_name") or r.get("address")}),
    }


def summary() -> dict:
    c = _conn()
    one = lambda q: (c.execute(q).fetchone() or [0])[0]          # noqa: E731
    inv = len(ansible.inventory_targets())      # inventory hosts are targets too
    entered = one("SELECT COUNT(*) FROM pam_targets")
    return {
        "targets": entered + inv,
        "live": one("SELECT COUNT(*) FROM pam_targets WHERE protocol IN "
                    "('ssh','rdp','vnc')") + inv,     # inventory hosts are SSH
        "sessions": one("SELECT COUNT(*) FROM pam_sessions"),
    }


# ── active (live) sessions — for the console view and the kill switch ──
# A live session registers here on connect and drops on close. The value holds
# just enough to show a row and to end it: a callable that tears the transport
# down. Kept in memory because a live session is a live process in THIS worker;
# a session on another replica is that replica's to end.
_active: dict = {}
_active_lock = threading.Lock()


def register_active(sid: str, info: dict, closer) -> None:
    with _active_lock:
        _active[sid] = {**info, "closer": closer, "since": time.time()}


def set_guac_id(sid: str, connid: str) -> None:
    """Remember guacd's own id for a live graphical session.

    THIS IS WHAT MAKES A DESKTOP SESSION WATCHABLE. guacd lets a second client
    attach to a connection it is already running — `select $<id>` instead of
    `select vnc` — and that second client is handed the same display stream.
    Verified against a live seat: the joiner received 840,433 bytes of the same
    screen the primary got 840,529 of, one second behind it.

    Without the id there is nothing to join, so it is captured out of the
    `ready` instruction as the session opens rather than reconstructed later.
    """
    if not sid or not connid:
        return
    with _active_lock:
        if sid in _active:
            _active[sid]["guac_id"] = connid


def guac_id_of(sid: str) -> str:
    """guacd's connection id for a live session, or "" if there is none."""
    with _active_lock:
        return str((_active.get(sid) or {}).get("guac_id") or "")



def drop_active(sid: str) -> None:
    with _active_lock:
        gone = _active.pop(sid, None)
        tid = (gone or {}).get("target_id") or ""
        # Only when this was the LAST session on that target: two people on one
        # box share the connection behind their transfers, and closing it under
        # the other one would turn their next click into a reconnect.
        still = any(v.get("target_id") == tid for v in _active.values())
    if tid and not still:
        drop_sftp_home(tid)


def active_sessions(visible=None) -> list:
    """The live sessions in this worker. `visible` is the per-device scope — a
    set of target ids the reader may see, or None for all — so a scoped operator
    watches (and can kill) only the live sessions on their own targets."""
    with _active_lock:
        out = []
        for sid, v in _active.items():
            if visible is not None and v.get("target_id") not in visible:
                continue
            # `closer` is a callable and `cast` is a filesystem path — neither
            # belongs on a page. Whether the session can be WATCHED does.
            row = {k: v[k] for k in v if k not in ("closer", "cast")}
            row["watchable"] = bool(v.get("cast"))
            # A GRAPHICAL SESSION IS WATCHABLE TOO, by a different mechanism.
            # `watchable` means "there is an asciinema cast to tail"; this
            # means "guacd is running a connection a second viewer can join".
            # They are kept apart because the two open different windows, and
            # collapsing them would offer an SSH tail for a desktop.
            row["shadowable"] = bool(v.get("guac_id"))
            row["id"] = sid
            row["seconds"] = int(time.time() - v["since"])
            row["took"] = _dur_words(row["seconds"])
            row["proto_label"] = PROTOCOLS.get(row.get("protocol", ""), {}).get(
                "label", row.get("protocol", ""))
            out.append(row)
    return sorted(out, key=lambda r: r["since"], reverse=True)


def live_cast(sid: str) -> str:
    """The recording file a live session is writing, if it can be watched.

    SSH only, and deliberately: its `SessionCast` is a line-buffered asciinema
    file, so the frames are on disk the moment they are written and tailing it
    IS watching the session. An RDP/VNC recording is written by guacd in its own
    format for its own player; there is no equivalent tail, so those sessions
    report unwatchable rather than offering a control that does nothing.

    Returns "" when the session is not live here, is not watchable, or its path
    has escaped DATA — the same containment rule `session_rec_path` applies,
    because this reads a file named by a session record.
    """
    with _active_lock:
        v = _active.get(sid)
    path = (v or {}).get("cast") or ""
    if not path:
        return ""
    try:
        full = os.path.realpath(path)
        if os.path.commonpath([full, os.path.realpath(str(DATA))]) != \
                os.path.realpath(str(DATA)):
            return ""
    except (ValueError, OSError):
        return ""
    return full if os.path.exists(full) else ""


def active_target(sid: str) -> str | None:
    """The target id of a live session, or None if it is not live here — used to
    scope the kill switch to the operator's own targets."""
    with _active_lock:
        v = _active.get(sid)
    return v.get("target_id") if v else None


def kill_active(sid: str) -> bool:
    """End a live session now. Returns whether one was there to end."""
    with _active_lock:
        v = _active.get(sid)
    if not v:
        return False
    try:
        v["closer"]()
    except Exception:                                           # noqa: BLE001
        pass
    return True


# ── Guacamole (RDP/VNC) protocol helpers ───────────────────────
# guacd speaks a simple instruction format: LEN.VALUE,LEN.VALUE,…; where LEN is
# the UTF-16 code-unit length of VALUE. The portal is the small server-side relay
# the Guacamole Java webapp usually is: it selects the protocol, answers guacd's
# argument list with the target's brokered parameters, and then pipes the display
# stream to the browser's guacamole-common-js client. The framing is
# length-computed, never string-concatenated from user text — a password can hold
# any character without breaking it, the same discipline as building an argv.
def guac_instr(*elems: str) -> bytes:
    """One guacd instruction from its elements."""
    def n(s: str) -> int:
        return len(s.encode("utf-16-le")) // 2
    return (",".join(f"{n(e)}.{e}" for e in elems) + ";").encode("utf-8")


def guac_params(target: dict, width: int = 0, height: int = 0) -> tuple[str, dict]:
    """(protocol, params) for guacd, filled from the target and its brokered
    credential. RDP/VNC only; the password is unsealed here and goes no further
    than guacd."""
    protocol = target.get("protocol")
    if protocol not in GUAC_PROTOCOLS:
        raise Refused("this target is not reached over RDP or VNC")
    cfg = config()
    w = max(640, min(int(width or cfg["rdp_width"]), 3840))
    h = max(480, min(int(height or cfg["rdp_height"]), 2160))
    w, h = w - (w % 2), h - (h % 2)
    extra = _extra(target)
    params = {"hostname": target.get("address", ""),
              "port": str(target.get("port") or PROTOCOLS[protocol]["port"]),
              "width": str(w), "height": str(h), "dpi": "96"}
    # THE SAME TRADE, on the same terms, for a real desktop: absent unless
    # somebody has chosen a depth, so every existing install is unaffected.
    if str(cfg.get("guac_color_depth") or "").strip():
        params["color-depth"] = str(cfg["guac_color_depth"]).strip()
    if target.get("username"):
        params["username"] = target["username"]
    secret = secretbox.unseal(target.get("secret_sealed") or "")
    if secret:
        params["password"] = secret
    if protocol == "rdp":
        if extra.get("domain"):
            params["domain"] = extra["domain"]
        if extra.get("security") and extra["security"] != "any":
            params["security"] = extra["security"]
        if extra.get("ignore_cert"):
            params["ignore-cert"] = "true"
        params["resize-method"] = "display-update"
    return protocol, params


LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]", "")


def guacd_is_local(host=None) -> bool:
    """Whether guacd shares this process's loopback — i.e. runs as the sidecar
    the chart ships. It is what decides whether a seat can be offered at
    127.0.0.1, so it is asked rather than assumed.

    Takes the host so the caller can ask about the configuration IT is
    holding. The first version read `config()` regardless of what it was
    given, which made `webseat.why_unavailable(cfg)` not a function of its own
    argument — the settings page could then disagree with the socket about the
    very thing it was rendering.
    """
    if host is None:
        host = config()["guacd_host"]
    return str(host).strip().lower() in LOOPBACK


def guac_web_params(seat, width: int = 0, height: int = 0) -> tuple[str, dict]:
    """(vnc, params) pointing guacd at a SEAT rather than at the target.

    The application's own address never reaches guacd, and that is the shape
    of the whole feature: guacd renders a BROWSER, and the browser is the
    thing that visits the application. Which is also why a web target's stored
    credential is still brokered nowhere — nothing on this path can type it
    into a login form, and the last round of this was precisely about not
    claiming otherwise.
    """
    cfg = config()
    w = max(640, min(int(width or cfg["rdp_width"]), 3840))
    h = max(480, min(int(height or cfg["rdp_height"]), 2160))
    # EVEN, and the same rounding webseat.screen_of applies to the framebuffer
    # itself: guacd is told the size the desktop actually has, and the two
    # disagreeing by a pixel would be a scale nobody asked for.
    w, h = w - (w % 2), h - (h % 2)
    params = {"hostname": seat.vnc_host, "port": str(seat.vnc_port),
              "width": str(w), "height": str(h), "dpi": "96"}
    # Only when somebody has chosen one: an absent parameter leaves guacd's own
    # default alone, and that is the behaviour every existing install has.
    if str(cfg.get("guac_color_depth") or "").strip():
        params["color-depth"] = str(cfg["guac_color_depth"]).strip()
    if seat.vnc_password:
        params["password"] = seat.vnc_password
    return "vnc", params


def guac_recording_params(sid: str) -> dict:
    """The guacd knobs that make it write a replayable recording into our store,
    which pam.Recording.finish() then indexes. Keystrokes are excluded from the
    recording for the same reason the SSH cast is output-only — a password typed
    at a prompt must not sit in the file."""
    SESSIONS.mkdir(parents=True, exist_ok=True)
    try:
        # 0770, not 0700: when guacd runs as a sidecar it writes RDP/VNC
        # recordings into this same directory, and it does so as a different user
        # sharing the pod's fsGroup — group write is what lets it. In a single-
        # tenant portal pod the only group members are the pod's own containers.
        os.chmod(SESSIONS, 0o770)
    except OSError:
        pass
    return {"recording-path": str(SESSIONS), "recording-name": sid,
            "create-recording-path": "true", "recording-include-keys": "false"}


def guac_connect_values(arg_names: list, params: dict) -> list:
    """Values for the `connect` instruction — one per name guacd asked for, in
    the order it asked. The protocol VERSION element is echoed back; a name we do
    not set goes empty (guacd lists every knob it supports, most unused)."""
    return [a if a.startswith("VERSION_") else str(params.get(a, ""))
            for a in arg_names]


def guac_ops(text: str) -> list:
    """Split a guac message into (opcode, the instruction verbatim) pairs.

    Length-prefixed, so a ';' inside a value is NOT a boundary — the same rule
    `GuacFramer` applies, for the same reason: a password or a clipboard can
    contain the delimiter.

    This exists to filter what a JOINED viewer may send upstream. A read-only
    watcher's `sync` has to pass (it is guacd's flow control) and its mouse and
    keys must not, and getting either half wrong is bad in a different
    direction: drop `sync` and the stream stalls, keep `key` and somebody has
    a keyboard they were never granted. The instruction is passed on verbatim
    rather than re-encoded, so nothing can be altered in transit.
    """
    out: list = []
    i, n = 0, len(text)
    while i < n:
        start, elems = i, []
        while i < n:
            dot = text.find(".", i)
            if dot < 0:
                return out
            try:
                ln = int(text[i:dot])
            except ValueError:
                return out                  # not framed as expected; stop
            end = dot + 1 + ln
            if end >= n:
                return out                  # the value is not all here
            elems.append(text[dot + 1:end])
            i = end + 1
            if text[end] == ";":
                break
        if elems:
            out.append((elems[0], text[start:i]))
    return out


# What a JOINED viewer may send upstream. `sync` is guacd's flow control and
# carries no input, so it passes either way; everything else here is input and
# only somebody who has been granted control may send it.
GUAC_INPUT = ("mouse", "key", "clipboard", "size")


def guac_upstream(text: str, allow_input: bool) -> str:
    """What of a joined viewer's message may reach guacd.

    THE READ-ONLY GUARANTEE LIVES HERE, which is why it is a function and not
    three lines inside a socket handler: it is the one rule that decides
    whether a supervisor can type on somebody else's production machine, and a
    rule that cannot be called cannot be tested.

    Guacamole's protocol would happily accept mouse and key events from a
    second user on a connection — sharing is a first-class feature of it — so
    "read-only" is not a property of joining. It is this filter. Instructions
    are passed on VERBATIM rather than re-encoded, so nothing can be altered
    on the way through, and anything unrecognised is dropped rather than
    forwarded: a `disconnect` from a watcher would end somebody else's
    session.
    """
    keep = [raw for op, raw in guac_ops(text)
            if op == "sync" or (allow_input and op in GUAC_INPUT)]
    return "".join(keep)


class GuacFramer:
    """Re-frames guacd's byte stream onto whole-instruction boundaries.

    WHY THIS EXISTS
        guacamole-common-js's WebSocketTunnel parses each WebSocket MESSAGE on
        its own and errors ("Invalid array length") if a message ends in the
        middle of an instruction — it keeps no buffer across messages. guacd's
        TCP stream, read in fixed chunks, splits instructions wherever the read
        happened to land. So the relay must hold back a partial trailing
        instruction and only forward complete ones. Values are length-prefixed
        (LEN.VALUE), so a ';' inside a value is not a boundary — the length is.
    """

    def __init__(self):
        self.buf = ""

    def feed(self, text: str) -> str:
        """Add newly-arrived text; return the whole instructions now complete."""
        self.buf += text
        cut, i, n = 0, 0, len(self.buf)
        while i < n:
            dot = self.buf.find(".", i)
            if dot < 0:
                break                       # length digits not all here yet
            try:
                ln = int(self.buf[i:dot])
            except ValueError:
                # not a length — the stream is not framed as expected; hand the
                # buffer over rather than stalling, and let the client complain
                cut = n
                break
            end = dot + 1 + ln              # index just past the value
            if end >= n:
                break                       # value (or its separator) not here yet
            i = end + 1                     # step over the ',' or ';'
            if self.buf[end] == ";":
                cut = i                     # a complete instruction ends here
        out, self.buf = self.buf[:cut], self.buf[cut:]
        return out
